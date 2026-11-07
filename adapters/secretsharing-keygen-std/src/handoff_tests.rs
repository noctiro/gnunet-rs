//! Actual private Unix PILS source movement and retirement. This is a native
//! ownership regression, not a fabricated Round1 transcript or a DKG fixture.
#![cfg(unix)]
use crate::{Report, SigningSession};
use gnunet_pils::{
    HelloLimits, MasterKey, Profile, Service,
    client::{Completion, Identity, Inbound, Instance, KeyTarget, OperationId, Written},
};
use gnunet_pils_host::{
    Host, Limits as HostLimits,
    client::{self as pils, EndpointSource},
};
use gnunet_service_runtime::clock::{RuntimeClock, SystemClock};
use gnunet_types::Error as Fault;
use gnunet_wire::official::SignaturePurpose;
use std::{
    io,
    os::unix::{fs::DirBuilderExt, net::UnixListener},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
#[derive(Default)]
struct Counts {
    accepted: AtomicUsize,
    requests: AtomicUsize,
    closed: AtomicUsize,
}
struct Server {
    directory: Option<PathBuf>,
    stop: Arc<AtomicBool>,
    counts: Arc<Counts>,
    worker: Option<thread::JoinHandle<io::Result<()>>>,
}
impl Server {
    fn new() -> Result<Self> {
        let mut nonce = [0; 8];
        getrandom::fill(&mut nonce)?;
        let root = std::env::temp_dir();
        let directory = root.join(format!(
            "gs-pils-{}-{:016x}",
            std::process::id(),
            u64::from_be_bytes(nonce)
        ));
        let stop = Arc::new(AtomicBool::new(false));
        let counts = Arc::new(Counts::default());
        let mut server = Self {
            directory: None,
            stop,
            counts,
            worker: None,
        };
        std::fs::DirBuilder::new().mode(0o700).create(&directory)?;
        server.directory = Some(directory);
        // Establish the cleanup owner before socket/service preparation so
        // constructor refusal cannot leave its private directory behind.
        let listener = UnixListener::bind(server.path()?)?;
        let service = Service::<4096>::new(
            MasterKey::from_seed([17; 32]),
            Profile::Reference029,
            SystemClock.sample()?.now.as_micros(),
            hello(),
        )?;
        let mut host = Host::new(
            listener,
            service,
            HostLimits {
                clients: 2,
                receive_bytes: 65535,
                transmit_bytes: 262140,
                accepts_per_step: 2,
                address_bytes: 4096,
            },
        )?;
        let flag = server.stop.clone();
        let observed = server.counts.clone();
        let worker = thread::spawn(move || {
            let hard = Instant::now() + Duration::from_secs(30);
            while !flag.load(Ordering::SeqCst) {
                if Instant::now() >= hard {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "original native fixture bound",
                    ));
                }
                let progress = host.poll_once(
                    SystemClock
                        .sample()
                        .map_err(io::Error::other)?
                        .now
                        .as_micros(),
                )?;
                observed
                    .accepted
                    .fetch_add(progress.accepted, Ordering::SeqCst);
                observed
                    .requests
                    .fetch_add(progress.requests, Ordering::SeqCst);
                observed.closed.fetch_add(progress.closed, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(1));
            }
            Ok(())
        });
        server.worker = Some(worker);
        Ok(server)
    }
    fn path(&self) -> Result<PathBuf> {
        Ok(self.directory.as_ref().ok_or(Fault::Closed)?.join("socket"))
    }
    fn finish(&mut self) -> Result {
        self.stop.store(true, Ordering::SeqCst);
        self.worker
            .take()
            .ok_or(Fault::Closed)?
            .join()
            .map_err(|_| io::Error::other("native fixture panic"))??;
        if let Some(path) = &self.directory {
            std::fs::remove_dir_all(path)?;
            self.directory = None;
        }
        Ok(())
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _joined = worker.join();
        }
        if let Some(path) = self.directory.take() {
            let _removed = std::fs::remove_dir_all(path);
        }
    }
}
fn check(ok: bool) -> Result {
    if ok {
        Ok(())
    } else {
        Err("original source handoff invariant".into())
    }
}
fn hello() -> HelloLimits {
    HelloLimits {
        maximum_input_bytes: 65535,
        maximum_address_bytes: 4096,
        maximum_addresses: 32,
    }
}
async fn observed<'id>(
    client: &mut pils::Client<'id, 1>,
    deadline: tokio::time::Instant,
) -> Result<Identity<'id>> {
    for _ in 0..1024 {
        match client.drive(Some(deadline)).await? {
            pils::Progress::Inbound(Inbound::Identity { identity, .. }) => return Ok(identity),
            pils::Progress::Connected(_) | pils::Progress::Activity { .. } => {}
            _ => return Err("unexpected actual PILS identity event".into()),
        }
    }
    Err("bounded native identity event count".into())
}
async fn signature<'id>(
    client: &mut pils::Client<'id, 1>,
    identity: Identity<'id>,
    purpose: u32,
    deadline: tokio::time::Instant,
) -> Result<(OperationId<'id>, Written<'id>, Completion<'id>)> {
    let mut region = [0x41; 24];
    SignaturePurpose::new(purpose, 16)?.encode(&mut region)?;
    let operation = client.sign(&region, KeyTarget::Exact(identity))?;
    let mut written = None;
    let mut completed = None;
    for _ in 0..1024 {
        match client.drive(Some(deadline)).await? {
            pils::Progress::Written(receipt) if receipt.operation == operation => {
                written = Some(receipt)
            }
            pils::Progress::Inbound(Inbound::Complete(completion))
                if completion.operation() == operation =>
            {
                let Completion::Signature {
                    peer,
                    announced: Some(announced),
                    ..
                } = &completion
                else {
                    return Err("actual SIGN failed".into());
                };
                check(*peer == identity.peer() && announced.epoch() == identity.epoch())?;
                completed = Some(completion);
            }
            pils::Progress::Activity { .. } => {}
            _ => return Err("unexpected actual SIGN event".into()),
        }
        if written.is_some() && completed.is_some() {
            return Ok((
                operation,
                written.ok_or(Fault::NotReady)?,
                completed.ok_or(Fault::NotReady)?,
            ));
        }
    }
    Err("bounded native signature event count".into())
}
#[test]
fn original_native_signing_epoch_survives_owner_move_and_closes_once() -> Result {
    let mut server = Server::new()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let mut instance = Instance::new();
        let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
        let source = EndpointSource::unix_with_clock(server.path()?, clock).fixed_endpoint()?;
        let mut client = pils::Client::<1>::new(
            &mut instance,
            source,
            Profile::Reference029,
            pils::Limits {
                pending_operations: 1,
                ..pils::Limits::default()
            },
            hello(),
        )?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        let identity = observed(&mut client, deadline).await?;
        let epoch = client.epoch();
        let (first, written, completion) = signature(&mut client, identity, 21, deadline).await?;
        check(client.is_idle())?;
        let report = Report {
            identity: Some(identity),
            signature_operation: Some(first),
            signature_written: written.operation == first,
            signature_completion: Some(completion),
            ..Report::default()
        };
        // Test only the private native-source handoff primitive. No consensus
        // receipt, Round1 completion or CompletedRound1 is manufactured.
        let mut session = SigningSession::new(client, identity, report);
        check(session.client.epoch() == epoch && session.identity().epoch() == identity.epoch())?;
        let (second, _, _) = signature(&mut session.client, identity, 22, deadline).await?;
        check(second != first && session.client.epoch() == epoch && session.client.is_idle())?;
        let original = session.close().ok_or(Fault::NotReady)?;
        check(
            original.signature_operation == Some(first)
                && original.pils_idle
                && !original.signature_result_unknown
                && original.signature_completion.is_some(),
        )?;
        check(session.close().is_none() && session.client.epoch().is_none())?;
        while server.counts.closed.load(Ordering::SeqCst) == 0 {
            if tokio::time::Instant::now() >= deadline {
                return Err("native peer did not observe physical close".into());
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        check(
            server.counts.accepted.load(Ordering::SeqCst) == 1
                && server.counts.requests.load(Ordering::SeqCst) == 2
                && server.counts.closed.load(Ordering::SeqCst) == 1,
        )
    })?;
    server.finish()
}
