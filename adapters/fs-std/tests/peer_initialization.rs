//! Failed deferred peer construction retains and explicitly joins the real worker.
#![cfg(all(unix, feature = "server"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "The model asserts original error identity, real worker join and index lock release before Server drop."
)]
use gnunet_fs::service as pure;
use gnunet_fs_host::{
    index::{Index, Limits as IndexLimits},
    server::{
        Error, FailureScope, Limits, NoPeers, PeerShutdown, Ports, ProviderFailure, Server,
        UnixAccess,
        peers::Deferred,
        ports::{self, Lookup, LookupProgress, NoSigner, StorePort},
    },
};
type Failure = Box<dyn std::error::Error + Send + Sync>;
use gnunet_service_runtime::{
    clock::{RuntimeClock, SystemClock},
    service::{ServiceOptions, ShutdownMode},
};
use gnunet_types::Error as ProtocolError;
use std::{
    cell::Cell,
    fmt, fs,
    future::poll_fn,
    path::PathBuf,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Result<Self, Failure> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "gnrs-fs-peer-init-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory)?;
        Ok(Self(directory))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _removed = fs::remove_dir_all(&self.0);
    }
}

struct IdleStore {
    starts: Rc<Cell<usize>>,
    closed: Rc<Cell<bool>>,
}
impl StorePort for IdleStore {
    fn start(&mut self, _: Lookup) -> Result<(), ports::Error> {
        self.starts.set(self.starts.get() + 1);
        Err(ProtocolError::Unsupported.into())
    }
    fn poll(&mut self, _: &mut Context<'_>) -> Poll<Result<LookupProgress, ports::Error>> {
        Poll::Pending
    }
    fn close(&mut self) -> Result<(), ports::Error> {
        self.closed.set(true);
        Ok(())
    }
}

#[derive(Debug)]
struct FactoryRefusal {
    original: Arc<()>,
}
impl fmt::Display for FactoryRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("original controlled peer factory refusal")
    }
}
impl std::error::Error for FactoryRefusal {}

#[test]
fn failed_peer_factory_keeps_original_error_until_explicit_worker_join() -> Result<(), Failure> {
    let directory = Directory::new()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut instance = pure::Instance::new();
            let mut clients = [pure::ClientSlot::default(); 1];
            let mut seen = [[0; 64]; 1];
            let mut queries = [pure::QuerySlot::new(&mut seen)];
            let protocol = pure::Service::new(
                &mut instance,
                &mut clients,
                &mut queries,
                pure::Limits::default(),
            )?;
            let index_path = directory.0.join("index");
            let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
            let starts = Rc::new(Cell::new(0));
            let closed = Rc::new(Cell::new(false));
            let mut server = Server::new(
                protocol,
                Ports {
                    datastore: IdleStore {
                        starts: starts.clone(),
                        closed: closed.clone(),
                    },
                    signer: NoSigner,
                    peers: Deferred::<NoPeers>::new(),
                    index: Index::open(&index_path, IndexLimits::default())?,
                    clock: clock.clone(),
                },
                Limits {
                    clients: 1,
                    route_slots: 1,
                    index_queue: 2,
                    io_slice_bytes: 3,
                    rescan_interval: Duration::from_secs(3600),
                },
                ServiceOptions {
                    shutdown: ShutdownMode::Soft,
                    ..ServiceOptions::default()
                },
                UnixAccess {
                    match_uid: true,
                    match_gid: false,
                },
            )?;
            assert!(server.peer_router().get().is_none());
            assert!(!server.report().worker_quiesced);
            let original = Arc::new(());
            let mut weak_resolver = None;
            let mut admitted = None;
            let initialization = match server.initialize_peers(|resolver, actual_clock| {
                assert!(Arc::ptr_eq(&actual_clock, &clock));
                // This is the real sole worker's weak queue, with one actual
                // readonly job admitted before the factory's original refusal.
                admitted = Some(resolver.resolve([0; 64], [0; 72]).map_err(|error| {
                    let scope = if error.is_fatal() {
                        FailureScope::Service
                    } else {
                        FailureScope::Operation
                    };
                    ProviderFailure::new(Box::new(error), scope)
                })?);
                weak_resolver = Some(resolver);
                Err(ProviderFailure::operation(FactoryRefusal {
                    original: original.clone(),
                }))
            }) {
                Err(error) => error,
                Ok(()) => return Err("controlled factory failure was replaced by success".into()),
            };
            let Error::Route(cause) = initialization.as_ref() else {
                return Err("factory failure lost its original provider classification".into());
            };
            let refusal = cause
                .cause()
                .downcast_ref::<FactoryRefusal>()
                .ok_or("factory's concrete original error was replaced")?;
            assert!(Arc::ptr_eq(&refusal.original, &original));
            assert!(server.peer_router().get().is_none());
            assert!(!server.report().worker_quiesced);
            assert!(!closed.get());

            // Keep Server and both weak/public job handles alive across normal
            // shutdown. Dropping them cannot stand in for the original join.
            let report = server.shutdown(|_| {}).await;
            assert!(report.worker_quiesced);
            assert!(server.report().worker_quiesced);
            assert!(closed.get());
            assert_eq!(starts.get(), 0);
            assert_eq!(report.accepted, 0);
            assert_eq!(report.searches, 0);
            assert_eq!(report.peer_shutdown, Some(PeerShutdown::Quiesced));
            assert!(Arc::ptr_eq(
                report
                    .failure
                    .as_ref()
                    .ok_or("shutdown lost primary failure")?,
                &initialization,
            ));
            assert!(Arc::ptr_eq(
                report
                    .peer_failure
                    .as_ref()
                    .ok_or("shutdown lost peer failure")?,
                &initialization,
            ));
            let resolver = weak_resolver
                .as_ref()
                .ok_or("factory missed real resolver")?;
            match resolver.resolve([0; 64], [0; 72]) {
                Err(error) if matches!(error.as_ref(), Error::WorkerGone) => {}
                _ => return Err("weak resolver admitted work after the original join".into()),
            }
            let mut resolution = admitted
                .take()
                .ok_or("original worker job was not retained")?;
            let settled = poll_fn(|cx| resolution.poll(cx)).await;
            assert!(matches!(settled, Err(error) if matches!(error.as_ref(), Error::Index(_))));

            // Original WAL/index ownership has ended while Server is still
            // alive. The successful reopen follows explicit join, before Drop.
            let mut reopened = Index::open(&index_path, IndexLimits::default())?;
            assert!(reopened.entries()?.next().is_none());
            drop(reopened);
            drop(server);
            Ok::<_, Failure>(())
        })
        .await??;
        Ok::<_, Failure>(())
    })
}
