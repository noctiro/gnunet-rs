//! Actual original PUT uncertainty survives cooperative worker drain/restart.
//! The local native peer reads one official request and deliberately sends no
//! reply; it is a fault fixture, not original-C or P2P interoperability evidence.
#![cfg(all(unix, feature = "network"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Native worker test asserts original complete wire requests, unknown receipts and no replay"
)]

use gnunet_client_host::EndpointSource;
use gnunet_crypto::hash512;
use gnunet_datastore_host::Outcome as NativeOutcome;
use gnunet_fs_host::{
    Buffers, Control,
    durable::store,
    jobs::{
        self, Blocked, Event, Execution, Sources, State, Worker,
        catalog::{Catalog, Directory, Kind, Policy, Registration},
    },
    network::BlockOptions,
    publication::{Disposition, Limits, Phase, StopReason, Task},
};
use gnunet_service_runtime::clock::{RuntimeClock, SystemClock};
use gnunet_types::AbsoluteTime;
use gnunet_wire::official::datastore::Request;
use std::{
    fs::{self, File},
    io,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    net::{UnixListener, UnixStream},
    time::timeout,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const WAIT: Duration = Duration::from_secs(5);

struct Temporary(PathBuf);
impl Temporary {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "gnunet-jobs-native-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}

async fn frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).await?;
    let length = usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
    if length < 4 {
        return Err(io::Error::other("short original DATASTORE frame"));
    }
    let mut frame = vec![0; length];
    frame[..4].copy_from_slice(&prefix);
    stream.read_exact(&mut frame[4..]).await?;
    Ok(frame)
}

fn sources(
    fs_socket: PathBuf,
    ds_socket: PathBuf,
    clock: &Arc<dyn RuntimeClock>,
) -> Result<Sources, jobs::Error> {
    Sources::new(
        EndpointSource::unix_with_clock(fs_socket, clock.clone()),
        EndpointSource::unix_with_clock(ds_socket, clock.clone()),
    )
}

#[test]
fn original_quiet_put_is_drained_as_unknown_and_never_replayed_by_a_fresh_worker() -> TestResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let temporary = Temporary::new()?;
            let task_path = temporary.0.join("publication");
            let catalog_path = temporary.0.join("catalog");
            let input_path = temporary.0.join("input");
            let ds_socket = temporary.0.join("ds.sock");
            let fs_socket = temporary.0.join("unused-fs.sock");
            let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
            let now = clock.sample()?.now;
            fs::write(&input_path, b"actual prepared worker file")?;
            let task = Task::create_file(
                &task_path,
                &mut File::open(&input_path)?,
                &mut Buffers::new(),
                BlockOptions {
                    expiration: AbsoluteTime::from_micros(now.as_micros() + 60_000_000),
                    priority: 17,
                    anonymity: 2,
                    replication: 3,
                },
                Limits::default(),
                |_| Control::Continue,
            )?;
            let task_id = *task.task_id();
            assert_eq!(task.manifest().plan.puts.len(), 1);
            let expected = task.manifest().plan.puts[0];
            let mut catalog = Catalog::create(&catalog_path, Default::default())?;
            let entry = catalog.register(Registration {
                task_id,
                kind: Kind::Publication,
                task: Directory::capture(&task_path)?,
                output_parent: None,
                cache: None,
                graph: None,
                policy: Policy {
                    slice_us: 4_000_000,
                    quota: None,
                    repeat_delay_us: Some(1_000),
                },
            })?;
            drop(task);
            fs::remove_file(&input_path)?;
            let listener = UnixListener::bind(&ds_socket)?;
            let connections = AtomicUsize::new(0);
            let puts = AtomicUsize::new(0);
            let mut worker = Worker::new(
                catalog,
                sources(fs_socket.clone(), ds_socket.clone(), &clock)?,
                jobs::Options {
                    max_jobs: 1,
                    max_running: 1,
                    until: AbsoluteTime::from_micros(now.as_micros() + 4_500_000),
                    storage: store::Limits::default(),
                },
            )?;
            let stop = worker.stop_handle();
            let peer = async {
                let (mut stream, _) = listener.accept().await?;
                connections.fetch_add(1, Ordering::Relaxed);
                let bytes = frame(&mut stream).await?;
                let Request::Put(data) = Request::decode(&bytes)? else {
                    return Err("expected original full PUT before worker stop".into());
                };
                assert_eq!(data.kind, expected.kind);
                assert_eq!(data.key, &expected.key);
                assert_eq!(hash512(data.value), expected.payload.hash);
                assert_eq!(data.priority, 17);
                assert_eq!(data.anonymity, 2);
                assert_eq!(data.replication, 3);
                puts.fetch_add(1, Ordering::Relaxed);
                // The actual complete write is already exposed. Remain quiet;
                // only the original native owner can determine its uncertainty.
                stop.request();
                let mut extra = [0; 1];
                assert_eq!(stream.read(&mut extra).await?, 0);
                Ok::<_, Box<dyn std::error::Error>>(hash512(&bytes))
            };
            let drive = async {
                let mut original = None;
                while let Some(event) = worker.next().await? {
                    let Event::Settled(done) = event else {
                        return Err("first actual publication was skipped".into());
                    };
                    assert!(original.is_none());
                    assert_eq!(done.entry, entry);
                    assert_eq!(done.task_id, task_id);
                    assert!(done.scheduling_error.is_none());
                    assert!(done.state_error.is_none());
                    let Some(State::Publication(after)) = done.after else {
                        return Err("actual original task status was discarded".into());
                    };
                    assert_eq!(after.phase, Phase::Uncertain);
                    assert!(after.uncertain);
                    assert!(matches!(
                        after.pending.map(|pending| pending.disposition),
                        Some(Disposition::Unknown { .. })
                    ));
                    let Execution::Publication(Err(failure)) = done.execution else {
                        return Err(
                            "worker dropped or replaced the original publication failure".into(),
                        );
                    };
                    let native = failure
                        .native
                        .as_ref()
                        .ok_or("original native receipt was lost")?;
                    assert_eq!(native.outcome(), Some(NativeOutcome::Unknown));
                    assert!(native.response_bytes().is_none());
                    assert!(native.requested_cancel());
                    assert_eq!(failure.requested_stop, Some(StopReason::CallerPause));
                    original = Some(failure);
                }
                assert_eq!(worker.stats().started, 1);
                assert_eq!(worker.stats().settled, 1);
                assert_eq!(worker.stats().not_started, 0);
                assert_eq!(worker.stats().max_active, 1);
                Ok::<_, Box<dyn std::error::Error>>(original.ok_or("no drained original failure")?)
            };
            let (original, request_hash) =
                timeout(WAIT, async { tokio::try_join!(drive, peer) }).await??;
            assert_eq!(
                original
                    .native
                    .as_ref()
                    .ok_or("native result disappeared")?
                    .attempt()
                    .request_hash,
                request_hash
            );
            drop(worker);

            let task = Task::open(&task_path, store::Limits::default())?;
            let pending = task
                .status()
                .pending
                .ok_or("original unknown intent did not survive reopen")?;
            assert_eq!(pending.attempt.request_hash, request_hash);
            assert!(matches!(pending.disposition, Disposition::Unknown { .. }));
            assert_eq!(task.status().phase, Phase::Uncertain);
            assert_eq!(task.status().recorded.accepted, 0);
            drop(task);
            let catalog = Catalog::open(&catalog_path, Default::default())?;
            let now = clock.sample()?.now;
            let mut fresh = Worker::new(
                catalog,
                sources(fs_socket, ds_socket, &clock)?,
                jobs::Options {
                    max_jobs: 1,
                    max_running: 1,
                    until: AbsoluteTime::from_micros(now.as_micros() + 1_000_000),
                    storage: store::Limits::default(),
                },
            )?;
            let skipped = timeout(WAIT, fresh.next())
                .await??
                .ok_or("unknown was not inspected")?;
            assert!(matches!(
                skipped,
                Event::Skipped {
                    entry: original_entry,
                    reason: Blocked::PendingMutation,
                    state: State::Publication(status),
                } if original_entry == entry && status.uncertain
            ));
            assert!(timeout(WAIT, fresh.next()).await??.is_none());
            assert_eq!(fresh.stats().started, 0);
            assert_eq!(fresh.stats().settled, 0);
            assert_eq!(fresh.stats().skipped, 1);
            assert!(
                timeout(Duration::from_millis(50), listener.accept())
                    .await
                    .is_err()
            );
            assert_eq!(connections.load(Ordering::Relaxed), 1);
            assert_eq!(puts.load(Ordering::Relaxed), 1);
            // The retained native receipt remains genuine after the restart;
            // catalog repeat policy never turned it into replay permission.
            assert_eq!(
                original
                    .native
                    .as_ref()
                    .ok_or("lost original evidence")?
                    .outcome(),
                Some(NativeOutcome::Unknown)
            );
            Ok::<_, Box<dyn std::error::Error>>(())
        })
}
