//! Public REVOCATION certificate work and original-MQ operations. Public work
//! files contain exactly372 bytes; no private key file is opened or imported.
use gnunet::{
    clients::{identity, revocation as native},
    crypto::{EddsaPrivateKey, gns::PkeySecret},
    gnsrecord::ZoneKey,
    revocation::{
        self as pure, Certificate, Check, Miner, MiningProgress, Proof, RevocationConfig, pow,
    },
};
use native::clock::{RuntimeClock, SystemClock};
use std::{
    error::Error,
    ffi::OsString,
    fs::{File, OpenOptions},
    future::{Future, poll_fn},
    io::{Read, Write},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    thread::{self, JoinHandle},
    time::Duration,
};
use tokio::{
    signal::unix::{Signal, SignalKind},
    time::Instant,
};
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, Box<dyn Error>>;
fn row(out: &mut impl Write, value: serde_json::Value) -> Result<()> {
    serde_json::to_writer(&mut *out, &value)?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}
fn public_file(path: &Path) -> Result<Certificate> {
    let mut file = File::open(path)?;
    let mut bytes = [0; pure::PROOF_BYTES];
    file.read_exact(&mut bytes)?;
    if file.read(&mut [0; 1])? != 0 {
        return Err("public certificate must contain exactly372 bytes".into());
    }
    Ok(Certificate::copy(Proof::parse(&bytes)?))
}
fn save_public(path: &Path, certificate: &Certificate) -> Result<()> {
    // Explicit new public output only. An existing file is never replaced.
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(certificate.bytes())?;
    file.sync_all()?;
    Ok(())
}
struct Options {
    timeout: Duration,
    hashes: u64,
    start: u64,
    epochs: u32,
    policy: RevocationConfig,
    io: usize,
}
fn options(args: &[OsString]) -> Result<Options> {
    let mut o = Options {
        timeout: Duration::from_secs(30),
        hashes: 1_000_000,
        start: 0,
        epochs: 1,
        policy: pure::DEFAULT_POLICY,
        io: 380,
    };
    let mut a = 0;
    while a < args.len() {
        let k = args[a].to_str().ok_or("option must be ASCII")?;
        let v = args
            .get(a + 1)
            .and_then(|x| x.to_str())
            .ok_or("missing option value")?;
        a += 2;
        match k {
            "--timeout-ms" => o.timeout = Duration::from_millis(v.parse()?),
            "--hash-limit" => o.hashes = v.parse()?,
            "--start" => o.start = v.parse()?,
            "--epochs" => o.epochs = v.parse()?,
            "--workbits" => o.policy.matching_bits = v.parse()?,
            "--epoch-ms" => {
                o.policy.epoch_duration = v
                    .parse::<u64>()?
                    .checked_mul(1000)
                    .ok_or("epoch overflow")?
            }
            "--io-slice-bytes" => o.io = v.parse()?,
            _ => return Err(format!("unknown revocation option {k}").into()),
        }
    }
    if o.timeout.is_zero()
        || o.timeout.as_micros() >= u128::from(u64::MAX)
        || Instant::now().checked_add(o.timeout).is_none()
        || o.hashes == 0
        || o.epochs == 0
        || o.policy.matching_bits >= 512
        || o.policy.epoch_duration == 0
        || o.io == 0
        || o.io > 65535
    {
        return Err("invalid finite revocation resource/deadline bound".into());
    }
    Ok(o)
}
fn until(clock: &dyn RuntimeClock, duration: Duration) -> Result<u64> {
    Ok(clock
        .sample()?
        .now
        .as_micros()
        .checked_add(u64::try_from(duration.as_micros())?)
        .filter(|n| *n < u64::MAX)
        .ok_or("deadline overflow")?)
}
async fn observe<T, E: Error + 'static>(
    future: impl Future<Output = std::result::Result<T, E>>,
    signal: Pin<&mut impl Future<Output = std::io::Result<()>>>,
) -> Result<Option<T>> {
    let mut future = std::pin::pin!(future);
    let mut signal = signal;
    poll_fn(|cx| {
        if let Poll::Ready(r) = signal.as_mut().poll(cx) {
            return Poll::Ready(r.map(|()| None).map_err(|e| Box::new(e) as Box<dyn Error>));
        }
        future
            .as_mut()
            .poll(cx)
            .map(|r| r.map(Some).map_err(|e| Box::new(e) as Box<dyn Error>))
    })
    .await
}
fn exposure(s: native::Submission) -> serde_json::Value {
    match s {
        native::Submission::Unsent => serde_json::json!({"kind":"unsent"}),
        native::Submission::Partial { bytes, total } => {
            serde_json::json!({"kind":"partial","bytes":bytes,"total":total})
        }
        native::Submission::Written { bytes } => {
            serde_json::json!({"kind":"whole-local-write","bytes":bytes})
        }
    }
}
async fn ipc(
    socket: PathBuf,
    query: Option<ZoneKey>,
    proof: Option<Certificate>,
    o: &Options,
    out: &mut impl Write,
) -> Result<()> {
    let source = native::EndpointSource::unix(socket);
    let deadline = until(source.clock().as_ref(), o.timeout)?;
    let d = native::Deadlines {
        send_until: deadline,
        until: deadline,
    };
    let domain = native::Instance::new();
    let limits = native::Limits {
        io_slice_bytes: o.io,
        ..Default::default()
    };
    let mut client = match (query, proof.as_ref()) {
        (Some(key), None) => native::Client::query(&domain, source, key, d, limits)?,
        (None, Some(cert)) => native::Client::revoke(&domain, source, cert.proof()?, d, limits)?,
        _ => return Err("invalid command".into()),
    };
    let hard = Instant::now()
        .checked_add(o.timeout)
        .ok_or("deadline overflow")?;
    let signal = tokio::signal::ctrl_c();
    let mut signal = std::pin::pin!(signal);
    let result=async{loop{let Some(progress)=observe(client.drive(Some(hard)),signal.as_mut()).await? else{
        let end=client.cancel().ok_or("original request already ended")?;
        row(out,serde_json::json!({"event":"revocation_local_end","job":end.job.diagnostic(),"submission":exposure(end.submission),"cause":format!("{:?}",end.cause),"revocation_outcome":"unknown-if-exposed"}))?;
        return Err("revocation canceled: original MQ physically closed, no remote cancel ACK".into())};
        match progress{
            native::Progress::Connected(epoch)=>row(out,serde_json::json!({"event":"revocation_connected","epoch":epoch.diagnostic()}))?,
            native::Progress::Queued(job,epoch)=>row(out,serde_json::json!({"event":"revocation_queued","job":job.diagnostic(),"epoch":epoch.diagnostic(),"local_only":true}))?,
            native::Progress::Submitted(job,epoch)=>row(out,serde_json::json!({"event":"revocation_written","job":job.diagnostic(),"epoch":epoch.diagnostic(),"service_response":false}))?,
            native::Progress::Reply(reply)=>{
                if reply.job!=client.job()||Some(reply.epoch)!=client.epoch(){return Err("reply belongs to a different original source".into())}
                match reply.response{
                    pure::ipc::Response::Query(raw)=>{row(out,serde_json::json!({"event":"revocation_query_result","raw":raw,"revoked":match raw{0=>Some(true),1=>Some(false),_=>None}}))?;if raw>1{return Err("unknown raw query status".into())}},
                    pure::ipc::Response::Revoke(raw)=>{row(out,serde_json::json!({"event":"revocation_result","raw":raw,"accepted":match raw{0=>Some(true),1=>Some(false),_=>None}}))?;if raw!=0{return Err(format!("service returned original REVOKE status {raw}").into())}}
                }return Ok(())
            },
            native::Progress::Ended(end)=>{row(out,serde_json::json!({"event":"revocation_local_end","job":end.job.diagnostic(),"submission":exposure(end.submission),"cause":format!("{:?}",end.cause),"revocation_outcome":"unknown-if-exposed"}))?;return Err("revocation original MQ ended without a service response".into())},
            native::Progress::Unavailable(e)=>return Err(e.into()),
            native::Progress::Retry(e,delay)=>row(out,serde_json::json!({"event":"revocation_preattach_retry","error":e.to_string(),"delay_us":delay.as_micros()}))?,
            native::Progress::WaitDeadline=>{let end=client.close();row(out,serde_json::json!({"event":"revocation_wait_deadline","submission":end.map(|e|exposure(e.submission)),"outcome":"inconclusive"}))?;return Err("original observation deadline elapsed".into())},
            native::Progress::Activity(..)=>{},native::Progress::Closed=>return Err("owner closed without original terminal event".into())
        }
    }}.await;
    // Writer/clock/signal/protocol errors also close before returning.
    let _end = client.close();
    result
}
/// One bounded explicit CPU worker; cancellation is checked between real hashes.
/// Drop joins the original worker, requiring actual CPU/OS progress. No detached
/// task, implicit key source, or per-candidate1MiB allocation exists.
struct Computation {
    cancel: Arc<AtomicBool>,
    receiver: tokio::sync::oneshot::Receiver<std::result::Result<Computed, String>>,
    thread: Option<JoinHandle<()>>,
}
struct MiningState {
    certificate: Box<Certificate>,
    progress: MiningProgress,
    search_after: u64,
    restoring: bool,
}
impl MiningState {
    fn observed(miner: &Miner) -> Self {
        Self {
            certificate: Box::new(miner.checkpoint()),
            progress: miner.progress(),
            search_after: miner.search_after(),
            restoring: miner.restoring(),
        }
    }
}
enum Computed {
    Verified { score: u32, checked_at: u64 },
    Mined(MiningState),
    Exhausted(MiningState),
    Interrupted { state: MiningState, cause: String },
}
impl Drop for Computation {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _joined = thread.join();
        }
    }
}
impl Computation {
    fn start(certificate: Certificate, mining: bool, o: &Options) -> Result<Self> {
        let clock = Arc::new(SystemClock);
        let until = until(clock.as_ref(), o.timeout)?;
        let hard = Instant::now()
            .checked_add(o.timeout)
            .ok_or("deadline overflow")?;
        let mut memory = Vec::new();
        memory.try_reserve_exact(pow::MEMORY_BLOCKS)?;
        memory.resize_with(pow::MEMORY_BLOCKS, pow::Block::default);
        let cancel = Arc::new(AtomicBool::new(false));
        let checking = cancel.clone();
        let (tx, receiver) = tokio::sync::oneshot::channel();
        let (policy, epochs, start, limit) = (o.policy, o.epochs, o.start, o.hashes);
        let thread = thread::Builder::new()
            .name("gnunet-cli-revocation-work".into())
            .spawn(move || {
                let guard = || -> std::result::Result<u64, String> {
                    if checking.load(Ordering::Acquire) {
                        return Err("original CPU job canceled".into());
                    }
                    if Instant::now() >= hard {
                        return Err("original CPU native deadline".into());
                    }
                    let now = clock.sample().map_err(|e| e.to_string())?.now.as_micros();
                    if now >= until {
                        return Err("original CPU logical deadline".into());
                    }
                    Ok(now)
                };
                let result = (|| -> std::result::Result<Computed, String> {
                    if mining {
                        let mut miner = Miner::resume(
                            certificate.proof().map_err(|e| e.to_string())?,
                            start,
                            policy.matching_bits,
                            epochs,
                        )
                        .map_err(|e| e.to_string())?;
                        if let Err(cause) = guard() {
                            return Ok(Computed::Interrupted {
                                state: MiningState::observed(&miner),
                                cause,
                            });
                        }
                        if !certificate
                            .proof()
                            .map_err(|e| e.to_string())?
                            .signature_valid()
                            .map_err(|e| e.to_string())?
                        {
                            return Err("original template signature invalid".into());
                        }
                        for _ in 0..limit {
                            if let Err(cause) = guard() {
                                return Ok(Computed::Interrupted {
                                    state: MiningState::observed(&miner),
                                    cause,
                                });
                            }
                            let progress = match miner.step(&mut memory) {
                                Ok(progress) => progress,
                                Err(error) => {
                                    return Ok(Computed::Interrupted {
                                        state: MiningState::observed(&miner),
                                        cause: error.to_string(),
                                    });
                                }
                            };
                            if let Err(cause) = guard() {
                                return Ok(Computed::Interrupted {
                                    state: MiningState::observed(&miner),
                                    cause,
                                });
                            }
                            if progress.ready {
                                return Ok(Computed::Mined(MiningState::observed(&miner)));
                            }
                        }
                        Ok(Computed::Exhausted(MiningState::observed(&miner)))
                    } else {
                        guard()?;
                        let mut check = Check::new(&certificate, policy)
                            .map_err(|e| e.to_string())?
                            .ok_or("invalid signature or nonce order")?;
                        while check.completed_hashes() < 32 {
                            guard()?;
                            check.step(&mut memory).map_err(|e| e.to_string())?;
                        }
                        let now = guard()?;
                        let checked = check
                            .finish_at(now)
                            .map_err(|e| e.to_string())?
                            .ok_or("work or lifetime rejected")?;
                        Ok(Computed::Verified {
                            score: checked.score(),
                            checked_at: checked.checked_at(),
                        })
                    }
                })();
                let _sent = tx.send(result);
            })?;
        Ok(Self {
            cancel,
            receiver,
            thread: Some(thread),
        })
    }
}
#[derive(Clone, Copy, Debug)]
enum WorkSignal {
    Interrupt,
    Terminate,
}
struct WorkSignals {
    interrupt: Signal,
    terminate: Signal,
}
impl WorkSignals {
    fn new() -> std::io::Result<Self> {
        Ok(Self {
            interrupt: tokio::signal::unix::signal(SignalKind::interrupt())?,
            terminate: tokio::signal::unix::signal(SignalKind::terminate())?,
        })
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<WorkSignal>> {
        for (source, signal) in [
            (&mut self.interrupt, WorkSignal::Interrupt),
            (&mut self.terminate, WorkSignal::Terminate),
        ] {
            match source.poll_recv(cx) {
                Poll::Ready(Some(())) => return Poll::Ready(Ok(signal)),
                Poll::Ready(None) => {
                    return Poll::Ready(Err(std::io::Error::other(format!(
                        "revocation CPU {signal:?} signal stream ended"
                    ))));
                }
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }
}
#[derive(Debug, Default)]
struct ComputationFailure {
    joined: bool,
    worker: Option<Box<dyn Error>>,
    cancellation: Option<Box<dyn Error>>,
    receive: Option<Box<dyn Error>>,
    join: Option<Box<dyn Error>>,
    save: Option<Box<dyn Error>>,
    output: Option<Box<dyn Error>>,
}
impl ComputationFailure {
    fn failed(&self) -> bool {
        !self.joined
            || self.worker.is_some()
            || self.cancellation.is_some()
            || self.receive.is_some()
            || self.join.is_some()
            || self.save.is_some()
            || self.output.is_some()
    }
    fn finish(self) -> Result<()> {
        if self.failed() {
            Err(Box::new(self))
        } else {
            Ok(())
        }
    }
}
impl std::fmt::Display for ComputationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "revocation CPU work: {self:?}")
    }
}
impl Error for ComputationFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.worker
            .as_deref()
            .or(self.cancellation.as_deref())
            .or(self.receive.as_deref())
            .or(self.join.as_deref())
            .or(self.save.as_deref())
            .or(self.output.as_deref())
    }
}
fn checkpoint(
    state: MiningState,
    target: Option<&Path>,
    event: &'static str,
    work_complete: bool,
    failures: &mut ComputationFailure,
    out: &mut impl Write,
) {
    // work_complete describes the actual mining result with clean join and no
    // observed stop; it was decided BEFORE this file/output attempt. It does
    // not assert file save, current proof lifetime or service acceptance.
    // Save/output errors remain independent even when actual work completed.
    // Incomplete work never receives a mined/verified/service-acceptance label.
    let saved = match target {
        Some(path) => match save_public(path, &state.certificate) {
            Ok(()) => true,
            Err(error) => {
                failures.save = Some(error);
                false
            }
        },
        None => {
            failures.save = Some("missing public mining output".into());
            false
        }
    };
    let output = row(
        out,
        serde_json::json!({
            "event": event,
            "hashes": state.progress.hashes,
            "score": state.progress.score,
            "work_target_reached": state.progress.ready,
            "complete": work_complete,
            "checkpoint_saved": saved,
            "public_certificate_bytes": 372,
            "search_after": state.search_after,
            "cursor_stored_in_certificate": false,
            "rechecking_carried_candidates": state.restoring,
            "cancel_requested": failures.cancellation.is_some(),
            "worker_joined": failures.joined,
            "service_accepted": false,
        }),
    );
    if let Err(error) = output {
        failures.output = Some(error);
    }
}
async fn compute(
    certificate: Certificate,
    target: Option<&Path>,
    o: &Options,
    out: &mut impl Write,
) -> Result<()> {
    // Register both real Unix stop streams before allocation/thread startup, so
    // a stop during that startup is retained for this original work owner.
    let mut signals = WorkSignals::new()?;
    let mut work = Computation::start(certificate, target.is_some(), o)?;
    let mut failures = ComputationFailure::default();
    let received = poll_fn(|cx| {
        // Preserve an already settled actual result before observing a new stop.
        // After a stop, await this SAME original worker's terminal channel;
        // requesting cancellation is not a checkpoint/completion receipt.
        if let Poll::Ready(result) = Pin::new(&mut work.receiver).poll(cx) {
            return Poll::Ready(result);
        }
        if failures.cancellation.is_none()
            && let Poll::Ready(result) = signals.poll(cx)
        {
            failures.cancellation = Some(match result {
                Ok(signal) => {
                    format!("original CPU work canceled by {signal:?} between hashes").into()
                }
                Err(error) => Box::new(error) as Box<dyn Error>,
            });
            work.cancel.store(true, Ordering::Release);
        }
        Poll::Pending
    })
    .await;
    // The actual result has been observed (or its original channel ended).
    // Join the one original thread before any new public output/file operation.
    // A native hash/OS scheduling boundary may still require real CPU progress.
    match work.thread.take() {
        Some(thread) => match thread.join() {
            Ok(()) => failures.joined = true,
            Err(_) => failures.join = Some("original CPU worker panicked before clean join".into()),
        },
        None => failures.join = Some("original CPU join owner missing".into()),
    }
    let completed = match received {
        Ok(Ok(completed)) => Some(completed),
        Ok(Err(error)) => {
            failures.worker = Some(error.into());
            None
        }
        Err(error) => {
            failures.receive = Some(Box::new(error));
            None
        }
    };
    match completed {
        Some(Computed::Verified { score, checked_at }) => {
            if let Err(error) = row(
                out,
                serde_json::json!({
                    "event":"revocation_checked", "score":score,
                    "checked_at_us":checked_at, "cancel_requested":failures.cancellation.is_some(),
                    "worker_joined":failures.joined, "service_accepted":false,
                }),
            ) {
                failures.output = Some(error);
            }
        }
        Some(Computed::Mined(state)) => {
            let complete = !failures.failed();
            checkpoint(
                state,
                target,
                if complete {
                    "revocation_mined"
                } else {
                    "revocation_work_stopped"
                },
                complete,
                &mut failures,
                out,
            );
        }
        Some(Computed::Exhausted(state)) => {
            failures.worker =
                Some("finite hash budget exhausted; public work remains incomplete".into());
            checkpoint(
                state,
                target,
                "revocation_work_limit",
                false,
                &mut failures,
                out,
            );
        }
        Some(Computed::Interrupted { state, cause }) => {
            failures.worker = Some(cause.into());
            checkpoint(
                state,
                target,
                "revocation_work_stopped",
                false,
                &mut failures,
                out,
            );
        }
        None => {}
    }
    failures.finish()
}
async fn prepare(
    socket: PathBuf,
    name: &[u8],
    output: &Path,
    o: &Options,
    out: &mut impl Write,
) -> Result<()> {
    // Explicit caller authorization to retrieve this named ego from the actual
    // native IDENTITY endpoint and sign purpose3. No private file is opened.
    let source = identity::EndpointSource::unix(socket);
    let clock = source.clock();
    let deadline = until(clock.as_ref(), o.timeout)?;
    let domain = identity::Instance::new();
    let mut lookup = identity::Lookup::exact(
        &domain,
        source,
        name,
        deadline,
        identity::Limits {
            reconnect: false,
            ..Default::default()
        },
    )?;
    let hard = Instant::now()
        .checked_add(o.timeout)
        .ok_or("deadline overflow")?;
    let signal = tokio::signal::ctrl_c();
    let mut signal = std::pin::pin!(signal);
    let result=async{loop{let Some(progress)=observe(lookup.drive(Some(hard)),signal.as_mut()).await? else{return Err("named ego signing canceled".into())};match progress{
        identity::LookupProgress::Finished{outcome:identity::LookupOutcome::Found(ego),..}=>{
            let public=ZoneKey::from_wire(&ego.public_key()?)?;let now=clock.sample()?.now.as_micros();
            if now>=deadline||Instant::now()>=hard{return Err("original signing deadline".into())}
            let timestamp=now.saturating_sub(pure::PREDATE_MICROS);let template=Certificate::from_parts(public,timestamp,o.policy.epoch_duration.saturating_mul(u64::from(o.epochs)),&[0;32],&[0;64]);
            let region=template.proof()?.signing_message();let mut raw=Zeroizing::new([0;32]);raw.copy_from_slice(&ego.secret().expose_serialized()[4..]);
            let signature=match ego.secret().key_type(){identity::KeyType::Ecdsa=>PkeySecret::from_bytes(*raw)?.sign(3,&[&region])?,identity::KeyType::Eddsa=>*EddsaPrivateKey::from_seed(*raw).sign(3,&region)?.as_bytes()};
            let prepared=Certificate::from_parts(public,timestamp,template.proof()?.ttl(),&[0;32],&signature);
            if clock.sample()?.now.as_micros()>=deadline||Instant::now()>=hard{return Err("original signing deadline elapsed before public output".into())}
            save_public(output,&prepared)?;return row(out,serde_json::json!({"event":"revocation_prepared","public_certificate_bytes":372,"timestamp_us":timestamp,"purpose":3,"pow_complete":false,"service_accepted":false}))
        },identity::LookupProgress::Finished{outcome,..}=>return Err(format!("original IDENTITY lookup failed: {outcome:?}").into()),identity::LookupProgress::Closed=>return Err("lookup closed".into()),identity::LookupProgress::Source(identity::Progress::WaitDeadline)=>return Err("original lookup deadline".into()),identity::LookupProgress::Source(_)=>{}
    }}}.await;
    let _closed = lookup.close();
    result
}
pub(super) fn run(args: &[OsString], out: &mut impl Write) -> Result<()> {
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        writeln!(
            out,
            "revocation query <UNIXPATH> <typed-public-base32> [options]\nrevocation revoke <UNIXPATH> <public-certificate> [options]\nrevocation prepare <IDENTITY-UNIXPATH> <ego> <new-public-template> [options]\nrevocation mine <public-signed-template-or-checkpoint> <new-public-output> [options]\nrevocation verify <public-certificate> [options]\nOptions: --timeout-ms N (default30000), --workbits N (22), --epoch-ms N (365d), --hash-limit N (1000000), --start N (0), --epochs N (1), --io-slice-bytes N (380). Mine rechecks each distinct carried nonce (at most32, counted in the hash budget) before continuing. Resume starts above max(--start,carried nonces); rejected-candidate history is not stored. Use the prior search_after diagnostic as --start to avoid repeating that history; counters never wrap. On budget/deadline/SIGINT/SIGTERM, mine waits for its actual worker result and join, then writes the last incomplete public checkpoint to the new output and exits with failure. The complete diagnostic describes uninterrupted joined mining work, while checkpoint_saved describes the independent file write/sync result. Public output is create-new and never replaces a file. Incomplete checkpoints require more work; work success is not current lifetime verification or service acceptance; exposed IPC loss is unknown. No private key file import."
        )?;
        return Ok(());
    }
    let action = args[0].to_str().ok_or("action must be ASCII")?;
    let count = match action {
        "query" | "revoke" | "mine" => 2,
        "verify" => 1,
        "prepare" => 3,
        _ => return Err("unknown revocation action".into()),
    };
    let operands = args.get(1..1 + count).ok_or("missing revocation operand")?;
    let o = options(&args[1 + count..])?;
    // Parse bounded public input before constructing native sources/workers.
    let certificate = match action {
        "revoke" => Some(public_file(Path::new(&operands[1]))?),
        "mine" | "verify" => Some(public_file(Path::new(&operands[0]))?),
        _ => None,
    };
    let key = if action == "query" {
        Some(ZoneKey::from_ztld(
            operands[1].to_str().ok_or("public key must be ASCII")?,
        )?)
    } else {
        None
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            match action {
                "query" | "revoke" => {
                    ipc(PathBuf::from(&operands[0]), key, certificate, &o, out).await
                }
                "verify" => compute(certificate.ok_or("missing certificate")?, None, &o, out).await,
                "mine" => {
                    compute(
                        certificate.ok_or("missing certificate")?,
                        Some(Path::new(&operands[1])),
                        &o,
                        out,
                    )
                    .await
                }
                "prepare" => {
                    prepare(
                        PathBuf::from(&operands[0]),
                        operands[1].as_os_str().as_bytes(),
                        Path::new(&operands[2]),
                        &o,
                        out,
                    )
                    .await
                }
                _ => Err("invalid command".into()),
            }
        })
}
