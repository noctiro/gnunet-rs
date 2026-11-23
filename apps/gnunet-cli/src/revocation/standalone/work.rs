//! One cancellable native worker, one Argon2 scratch area and durable public work.
use super::{
    Certificate, Result,
    native::clock::RuntimeClock,
    proof_file::{FileResult, ProofFile},
    pure::{self, Check, Miner, RevocationConfig, pow},
};
use gnunet_config::Configuration;
use gnunet_service_runtime::signals::Termination;
use std::{
    error::Error,
    future::{Future, poll_fn},
    io::{self, Write},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
    thread::{self, JoinHandle},
    time::Duration,
};
use tokio::sync::oneshot;

#[derive(Clone, Copy)]
pub(super) struct Policy {
    network: RevocationConfig,
    epochs: u32,
}
impl Policy {
    pub(super) fn read(config: &Configuration, epochs: u32) -> Result<Self> {
        let matching_bits = u32::try_from(config.get_number(b"revocation", b"WORKBITS")?)?;
        let epoch_duration = config.get_time(b"revocation", b"EPOCH_DURATION")?;
        if epochs == 0
            || epoch_duration == 0
            || matching_bits
                .checked_add(epochs)
                .is_none_or(|target| target > 512)
        {
            return Err("invalid revocation work policy or epoch count".into());
        }
        Ok(Self {
            network: RevocationConfig {
                matching_bits,
                epoch_duration,
            },
            epochs,
        })
    }

    pub(super) fn ttl(self) -> u64 {
        pure::DEFAULT_EPOCH_MICROS.saturating_mul(u64::from(self.epochs))
    }
}

pub(super) struct ReadyProof {
    pub(super) certificate: Certificate,
    pub(super) already_ready: bool,
}

struct Worker {
    cancel: Arc<AtomicBool>,
    result: oneshot::Receiver<FileResult<Option<ReadyProof>>>,
    thread: Option<JoinHandle<()>>,
}
impl Worker {
    fn start(
        certificate: Certificate,
        existing: bool,
        file: Option<ProofFile>,
        policy: Policy,
        clock: Arc<dyn RuntimeClock>,
    ) -> io::Result<Self> {
        let cancel = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&cancel);
        let (sender, result) = oneshot::channel();
        let thread = thread::Builder::new()
            .name("gnunet-revocation-pow".into())
            .spawn(move || {
                let actual = produce(
                    certificate,
                    existing,
                    file,
                    policy,
                    clock.as_ref(),
                    &stopping,
                );
                let _delivered = sender.send(actual);
            })?;
        Ok(Self {
            cancel,
            result,
            thread: Some(thread),
        })
    }

    fn join(&mut self) -> Result<()> {
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| "original revocation work thread panicked")?;
        }
        Ok(())
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        let _joined = self.join();
    }
}

pub(super) async fn prepare(
    seed: Certificate,
    existing: bool,
    file: Option<ProofFile>,
    policy: Policy,
    clock: Arc<dyn RuntimeClock>,
    signals: &mut Termination,
) -> Result<ReadyProof> {
    let mut worker = Worker::start(seed, existing, file, policy, clock)?;
    let mut stop = None;
    let received = poll_fn(|cx| {
        if let ready @ Poll::Ready(_) = Pin::new(&mut worker.result).poll(cx) {
            return ready;
        }
        if stop.is_none()
            && let Poll::Ready(result) = signals.poll_stop(cx)
        {
            worker.cancel.store(true, Ordering::Release);
            stop = Some(result);
        }
        Poll::Pending
    })
    .await;
    let joined = worker.join();
    let actual = received?.map_err(|error| error as Box<dyn Error>);
    joined?;
    match (actual, stop) {
        (Err(original), Some(Err(signal))) => {
            Err(format!("{original}; termination observer: {signal}").into())
        }
        (Err(original), _) => Err(original),
        (_, Some(Err(signal))) => Err(signal.into()),
        (Ok(None), _) | (_, Some(Ok(()))) => {
            writeln!(io::stderr().lock(), "Cancelling calculation.")?;
            Err("revocation proof calculation interrupted".into())
        }
        (Ok(Some(proof)), None) => Ok(proof),
    }
}

fn produce(
    seed: Certificate,
    existing: bool,
    mut file: Option<ProofFile>,
    policy: Policy,
    clock: &dyn RuntimeClock,
    stop: &AtomicBool,
) -> FileResult<Option<ReadyProof>> {
    let proof = seed.proof()?;
    if !proof.signature_valid()? {
        return Err("invalid signature on original revocation certificate".into());
    }
    let mut scratch = Vec::new();
    scratch.try_reserve_exact(pow::MEMORY_BLOCKS)?;
    scratch.resize_with(pow::MEMORY_BLOCKS, pow::Block::default);
    if existing {
        match ready(&seed, policy, clock, stop, &mut scratch)? {
            Some(true) => {
                return Ok(Some(ReadyProof {
                    certificate: seed,
                    already_ready: true,
                }));
            }
            Some(false) => writeln!(
                io::stderr().lock(),
                "Continuing calculation where left off..."
            )?,
            None => return Ok(None),
        }
    }
    if let Some(file) = &mut file {
        file.prepare_update()?;
    }
    writeln!(
        io::stderr().lock(),
        "Revocation certificate not ready, calculating proof of work"
    )?;
    let mut miner = if existing {
        Miner::resume(proof, 0, policy.network.matching_bits, policy.epochs)?
    } else {
        Miner::new(proof, 0, policy.network.matching_bits, policy.epochs)?
    };
    let mut since_save = 0;
    loop {
        if stop.load(Ordering::Acquire) {
            if let Some(file) = &mut file {
                file.save(&miner.checkpoint())?;
            }
            return Ok(None);
        }
        let progress = miner.step(&mut scratch)?;
        since_save += 1;
        if progress.ready {
            let certificate = Certificate::copy(miner.certificate()?);
            let current = ready(&certificate, policy, clock, stop, &mut scratch)?;
            if let Some(file) = &mut file {
                file.save(&certificate)?;
            }
            return match current {
                Some(true) => Ok(Some(ReadyProof {
                    certificate,
                    already_ready: false,
                })),
                Some(false) => Err(
                    "computed revocation certificate is outside its current acceptance lifetime"
                        .into(),
                ),
                None => Ok(None),
            };
        }
        if since_save == 128 {
            if let Some(file) = &mut file {
                file.save(&miner.checkpoint())?;
            }
            since_save = 0;
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn ready(
    certificate: &Certificate,
    policy: Policy,
    clock: &dyn RuntimeClock,
    stop: &AtomicBool,
    scratch: &mut [pow::Block],
) -> FileResult<Option<bool>> {
    let Some(mut check) = Check::new(certificate, policy.network)? else {
        return Ok(Some(false));
    };
    while check.completed_hashes() < pure::NONCES as u8 {
        if stop.load(Ordering::Acquire) {
            return Ok(None);
        }
        check.step(scratch)?;
    }
    let now = clock.sample()?.now.as_micros();
    Ok(Some(check.finish_at(now)?.is_some()))
}
