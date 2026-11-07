//! Actual WAL, bounded storage worker, IPC credit and durable restart model.
#![cfg(unix)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "One focused actual worker/socket/restart model asserts original durable and wire observations"
)]
use gnunet_peerstore::{
    self as core, Envelope, Filter, Monitor, Record, Request, Response, Storage,
};
use gnunet_peerstore_host::{
    backend::{Limits as WalLimits, Wal},
    server::{Limits, Progress, Server},
    worker::Worker,
};
use gnunet_service_runtime::{
    clock::SystemClock,
    credentials::UnixAccess,
    service::{Listener, ServiceOptions},
};
use std::{
    error::Error,
    fs,
    future::{Future, poll_fn},
    io::Write,
    path::PathBuf,
    sync::Arc,
    task::Poll,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::Instant,
};
type Failure = Box<dyn Error + Send + Sync>;
struct Directory(PathBuf);
impl Directory {
    fn new() -> Result<Self, Failure> {
        let mut id = [0; 16];
        getrandom::fill(&mut id)?;
        let p = std::env::temp_dir().join(format!(
            "gnunet-peerstore-model-{:032x}",
            u128::from_be_bytes(id)
        ));
        fs::create_dir(&p)?;
        Ok(Self(p))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
fn record(value: &[u8], expiry: u64) -> Record<'_> {
    Record {
        peer: [4; 32],
        expiry,
        subsystem: Some(b"t"),
        key: Some(b"k"),
        value,
    }
}
async fn send(s: &mut TcpStream, r: Request<'_>) -> Result<(), Failure> {
    let mut bytes = [0; 512];
    let n = r.encode(&mut bytes)?;
    s.write_all(&bytes[..n]).await?;
    Ok(())
}
async fn frame(s: &mut TcpStream) -> Result<Vec<u8>, Failure> {
    let mut h = [0; 4];
    s.read_exact(&mut h).await?;
    let n = usize::from(u16::from_be_bytes([h[0], h[1]]));
    if n < 4 {
        return Err("short official frame".into());
    }
    let mut b = vec![0; n];
    b[..4].copy_from_slice(&h);
    s.read_exact(&mut b[4..]).await?;
    Ok(b)
}
async fn until<'id, 'slots, 'bytes, 'worker>(
    server: &mut Server<'id, 'slots, 'bytes, 'worker>,
    listeners: &[Listener<'_>],
    mut done: impl FnMut(&Server<'id, 'slots, 'bytes, 'worker>) -> bool,
) -> Result<(), Failure> {
    let end = Instant::now() + Duration::from_secs(3);
    while !done(server) {
        let p = poll_fn(|cx| {
            let driving = server.drive(listeners, Some(end), |_| {});
            let mut driving = std::pin::pin!(driving);
            Poll::Ready(driving.as_mut().poll(cx))
        })
        .await;
        match p {
            Poll::Pending => tokio::task::yield_now().await,
            Poll::Ready(Ok(Progress::WaitDeadline)) => {
                return Err("actual peerstore model deadline".into());
            }
            Poll::Ready(r) => {
                r?;
            }
        }
    }
    Ok(())
}
#[test]
fn actual_wal_worker_monitor_and_restart_keep_original_uid_and_result() -> Result<(), Failure> {
    let directory = Directory::new()?;
    let limits = WalLimits {
        records: 8,
        live_bytes: 4096,
        wal_bytes: 512 * 1024,
        checkpoint_bytes: 128,
    };
    let filter = Filter {
        peer: None,
        subsystem: Some(b"t"),
        key: Some(b"k"),
    };
    {
        let mut wal = Wal::open(&directory.0, limits)?;
        assert!(Wal::open(&directory.0, limits).is_err());
        assert_eq!(wal.store(record(b"a", 100), false)?, 1);
        assert_eq!(wal.store(record(b"b", 100), false)?, 2);
        assert_eq!(wal.store(record(b"c", 100), true)?, 3);
        assert_eq!(wal.records(), 1);
        assert_eq!(wal.expire(100)?, 0);
        assert_eq!(wal.expire(101)?, 1);
        assert_eq!(wal.sequence(), 4);
        assert_eq!(wal.store(record(b"d", u64::MAX), false)?, 5);
    }
    {
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(directory.0.join("records.wal"))?;
        file.write_all(b"torn")?;
        file.sync_all()?;
    }
    let wal = Wal::open(&directory.0, limits)?;
    assert_eq!(wal.recovered_tail(), 4);
    assert_eq!(
        wal.next(filter, 0)?
            .ok_or("missing committed row")?
            .sequence,
        5
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(8), async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let listeners = [Listener::Tcp(&listener)];
            let mut instance = core::Instance::new();
            let mut clients = [core::ClientSlot::new(); 2];
            let mut filters = [[0; 32]; 4];
            let mut operations = filters.each_mut().map(|b| core::OperationSlot::new(b));
            let mut bodies = [[0; 512]; 2];
            let mut messages = bodies.each_mut().map(|b| core::MessageSlot::new(b));
            let service = core::Service::new(
                &mut instance,
                &mut clients,
                &mut operations,
                &mut messages,
                core::Limits { record_bytes: 512 },
            )?;
            let mut worker = Worker::start(wal, 3)?;
            {
                let mut server = Server::new(
                    service,
                    &mut worker,
                    Limits {
                        clients: 2,
                        io_slice_bytes: 3,
                        maintenance_interval: Duration::from_secs(300),
                    },
                    ServiceOptions::default(),
                    UnixAccess::default(),
                    Arc::new(SystemClock),
                )?;
                let mut monitor = TcpStream::connect(listener.local_addr()?).await?;
                send(
                    &mut monitor,
                    Request::MonitorStart(Monitor {
                        rid: 77,
                        filter,
                        iterate_first: true,
                    }),
                )
                .await?;
                until(&mut server, &listeners, |s| s.report().written_frames >= 1).await?;
                let b = frame(&mut monitor).await?;
                let Response::Record(e) = Response::decode(&b)? else {
                    return Err("missing actual initial monitor record".into());
                };
                assert_eq!(e.rid, 0);
                assert_eq!(e.record.value, b"d");
                send(&mut monitor, Request::MonitorNext { limit: 1 }).await?;
                until(&mut server, &listeners, |s| s.report().written_frames >= 2).await?;
                assert_eq!(
                    Response::decode(&frame(&mut monitor).await?)?,
                    Response::MonitorSync
                );
                let mut writer = TcpStream::connect(listener.local_addr()?).await?;
                send(
                    &mut writer,
                    Request::Store(Envelope {
                        rid: 0x1122_3344,
                        options: 0,
                        reserved: 0,
                        record: record(b"fresh", u64::MAX),
                    }),
                )
                .await?;
                until(&mut server, &listeners, |s| s.report().written_frames >= 4).await?;
                assert_eq!(
                    Response::decode(&frame(&mut writer).await?)?,
                    Response::StoreResult {
                        rid: 0x1122_3344,
                        result: 1
                    }
                );
                let b = frame(&mut monitor).await?;
                let Response::Record(e) = Response::decode(&b)? else {
                    return Err("missing actual live monitor record".into());
                };
                assert_eq!(e.record.value, b"fresh");
                let stopped = server.shutdown(|_| {}).await;
                assert!(stopped.failure.is_none());
                let stopped_worker = stopped.worker.ok_or("worker join missing")?;
                assert!(stopped_worker.failure.is_none());
                assert_eq!(stopped_worker.sequence, 6);
                assert_eq!(stopped_worker.records, 2);
                assert_eq!(
                    stopped.report.storage_submitted,
                    stopped.report.storage_received
                );
                assert_eq!(stopped.report.accepted, 2);
                assert_eq!(stopped.report.closed, 2);
            }
            assert!(!worker.needs_join());
            Ok::<(), Failure>(())
        })
        .await??;
        Ok::<(), Failure>(())
    })?;
    let wal = Wal::open(&directory.0, limits)?;
    assert_eq!(wal.sequence(), 6);
    assert_eq!(wal.records(), 2);
    assert_eq!(
        wal.next(filter, 5)?
            .ok_or("missing actual committed fresh record")?
            .record
            .value,
        b"fresh"
    );
    Ok(())
}
