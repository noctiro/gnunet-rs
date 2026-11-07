//! Live configuration samples preserve original MQ, stream and callback authority.
#![expect(
    clippy::panic,
    reason = "Only test callbacks panic when an impossible or premature observation is delivered"
)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions establish live socket and original-operation invariants in fallible OS tests"
)]
#[path = "../../resolver-broker-std/tests/support/domain.rs"]
mod resolution_domain;
use gnunet_arm_core::{
    FrameSlot,
    client::{Client, ConnectionStatus, Event, Inbound, OperationSlot, StdioInheritance},
    monitor::Monitor,
    wire::ArmAbi,
};
use gnunet_arm_host::{
    ChildRegistry, ClientHost, Clock, LaunchLimits, Limits, LiveConfiguration, LocalLauncher,
    MonitorEvent, MonitorHost, Progress,
};
use gnunet_config::Configuration;
use std::{
    error::Error,
    io,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixListener},
    time::{Instant, timeout},
};
type Test = Result<(), Box<dyn Error>>;
static NEXT: AtomicU64 = AtomicU64::new(9000);
struct Dir(PathBuf);
impl Dir {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "arm-live-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}
fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
fn config(path: &std::path::Path) -> Result<Configuration, Box<dyn Error>> {
    let mut cfg = Configuration::new(Default::default());
    cfg.set_value(
        b"arm",
        b"UNIXPATH",
        Some(path.as_os_str().as_encoded_bytes()),
    )?;
    Ok(cfg)
}
async fn frame(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let len = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if !(4..=65535).contains(&len) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut data = vec![0; len];
    data[..4].copy_from_slice(&header);
    stream.read_exact(&mut data[4..]).await?;
    Ok(data)
}
#[test]
fn actual_monitor_cfg_update_then_eof_reports_one_unavailable_and_restore_does_not_retry() -> Test {
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        let dir = Dir::new()?;
        let path = dir.0.join("monitor.sock");
        let listener = UnixListener::bind(&path)?;
        let peer = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await?;
            assert_eq!(frame(&mut s).await?, b"\0\x04\0\x0e");
            s.write_all(b"\0\x0c\0\x0b\0\0\0\0arm\0").await?;
            s.shutdown().await?;
            assert!(
                timeout(Duration::from_millis(120), listener.accept())
                    .await
                    .is_err(),
                "configuration restoration must not invent a new retry"
            );
            Ok::<_, io::Error>(())
        });
        let cfg = config(&path)?;
        let live = LiveConfiguration::new(cfg.duplicate()?);
        let mut frames = [FrameSlot::EMPTY; 2];
        let mut pool = [0; 8];
        let core = Monitor::new(&mut frames, &mut pool, 1)?;
        let mut monitor = MonitorHost::start_live(
            core,
            live.clone(),
            domain.resolution(),
            Limits::default(),
            Clock::system()?,
            |_| panic!("initial creation must succeed"),
        )?;
        let mut statuses = 0;
        let mut unavailable = 0;
        let mut callback_error = None;
        let until = Instant::now() + Duration::from_secs(2);
        while unavailable == 0 {
            assert_ne!(
                monitor
                    .drive(Some(until), |event, port| {
                        let result = (|| -> Test {
                            match event {
                                MonitorEvent::Status(value) => {
                                    assert_eq!(value.service, b"arm");
                                    assert_eq!(value.status.0, 0);
                                    statuses += 1;
                                    let mut current = live.snapshot()?;
                                    current.set_value(b"arm", b"UNIXPATH", None)?;
                                    live.replace(current)?;
                                }
                                MonitorEvent::Unavailable(value) => {
                                    assert!(!value.initial);
                                    unavailable += 1;
                                    live.replace(cfg.duplicate()?)?;
                                }
                            }
                            Ok(())
                        })();
                        if let Err(error) = result {
                            callback_error = Some(error);
                            port.stop();
                        }
                    })
                    .await?,
                Progress::WaitDeadline
            );
            if callback_error.is_some() {
                break;
            }
        }
        if let Some(error) = callback_error {
            return Err(error);
        }
        assert_eq!((statuses, unavailable), (1, 1));
        assert!(monitor.take_endpoint_error().is_some());
        assert_eq!(
            monitor
                .drive(
                    Some(Instant::now() + Duration::from_millis(50)),
                    |_, _| panic!("update created implicit retry/callback")
                )
                .await?,
            Progress::WaitDeadline
        );
        monitor.stop();
        peer.await??;
        Ok(())
    })
}
#[test]
fn current_logical_mq_retries_new_unix_path_but_keeps_its_original_tcp_and_queued_id() -> Test {
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        let dir = Dir::new()?;
        let old = dir.0.join("absent.sock");
        let new = dir.0.join("new.sock");
        let unix = UnixListener::bind(&new)?;
        let replacement = TcpListener::bind("127.0.0.1:0").await?;
        let reservation = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        reservation.bind(&std::net::SocketAddr::from(([127, 0, 0, 1], 0)).into())?;
        let old_port = reservation
            .local_addr()?
            .as_socket()
            .ok_or("IPv4 address")?
            .port();
        let new_port = replacement.local_addr()?.port();
        let mut cfg = config(&old)?;
        cfg.set_number(b"arm", b"PORT", u64::from(old_port))?;
        cfg.set_value(b"arm", b"HOSTNAME", Some(b"127.0.0.1"))?;
        let live = LiveConfiguration::new(cfg.duplicate()?);
        let mut registry = ChildRegistry::new(2)?;
        let launcher = LocalLauncher::new(
            cfg.duplicate()?,
            PathBuf::from(env!("CARGO_BIN_EXE_gnunet-arm-spawn-helper")),
            LaunchLimits::default(),
            &mut registry,
        )?;
        let mut operations = [OperationSlot::EMPTY; 2];
        let mut slots = [FrameSlot::EMPTY; 4];
        let mut pool = [0; 128];
        let core = Client::new(&mut operations, &mut slots, &mut pool, 2, ArmAbi::U64Align8)?;
        let mut owner = ClientHost::connect_live(
            core,
            live.clone(),
            domain.resolution(),
            launcher,
            Limits::default(),
            Clock::system()?,
            |_| panic!(),
        )?;
        let original = owner.connection_epoch();
        let id = owner.request_service_list()?;
        // Before any attempt starts, replace TCP with a real listening endpoint. Native
        // CLIENT cached the old TCP when it created this original logical MQ.
        cfg.set_number(b"arm", b"PORT", u64::from(new_port))?;
        live.replace(cfg.duplicate()?)?;
        let until = Instant::now() + Duration::from_secs(7);
        loop {
            let progress = owner
                .drive(Some(until), |_, _| {
                    panic!("cached TCP was incorrectly refreshed")
                })
                .await?;
            if owner.take_io_error().is_some() {
                break;
            }
            assert_ne!(
                progress,
                Progress::WaitDeadline,
                "original TCP probe never reported a physical failure"
            );
        }
        assert!(owner.owns_operation(id));
        assert_eq!(owner.connection_epoch(), original);
        assert!(
            timeout(Duration::from_millis(5), replacement.accept())
                .await
                .is_err()
        );
        cfg.set_value(
            b"arm",
            b"UNIXPATH",
            Some(new.as_os_str().as_encoded_bytes()),
        )?;
        live.replace(cfg)?;
        let peer = tokio::spawn(async move {
            let (mut s, _) = unix.accept().await?;
            assert_eq!(frame(&mut s).await?, b"\0\x04\0\x0f");
            s.write_all(b"\0\x04\0\x0f").await?;
            let request = frame(&mut s).await?;
            assert_eq!(&request[8..16], &1u64.to_be_bytes());
            let mut response = vec![0; 24];
            response[..4].copy_from_slice(b"\0\x18\0\x0d");
            response[8..16].copy_from_slice(&1u64.to_be_bytes());
            s.write_all(&response).await?;
            assert_eq!(s.read(&mut [0]).await?, 0);
            Ok::<_, io::Error>(())
        });
        let mut complete = false;
        let until = Instant::now() + Duration::from_secs(8);
        while !complete {
            assert_ne!(
                owner
                    .drive(Some(until), |event, _| match event {
                        Inbound::List { operation, list } => {
                            assert_eq!(operation, id);
                            assert!(list.is_empty());
                            complete = true;
                        }
                        Inbound::Event(Event::Connection(ConnectionStatus::Connected)) => {}
                        _ => panic!("original operation changed"),
                    })
                    .await?,
                Progress::WaitDeadline
            );
        }
        assert_eq!(owner.connection_epoch(), original);
        owner.disconnect(|_, _| panic!("completed original callback repeated"))?;
        peer.await??;
        drop(reservation);
        assert!(
            timeout(Duration::from_millis(5), replacement.accept())
                .await
                .is_err()
        );
        Ok(())
    })
}

fn core<'a>(
    operations: &'a mut [OperationSlot],
    frames: &'a mut [FrameSlot],
    bytes: &'a mut [u8],
) -> Result<Client<'a>, Box<dyn Error>> {
    Ok(Client::new(
        operations,
        frames,
        bytes,
        NEXT.fetch_add(1, Ordering::Relaxed),
        ArmAbi::U64Align8,
    )?)
}
fn launcher<'r>(
    cfg: &Configuration,
    registry: &'r mut ChildRegistry,
) -> Result<LocalLauncher<'r>, Box<dyn Error>> {
    Ok(LocalLauncher::new(
        cfg.duplicate()?,
        PathBuf::from(env!("CARGO_BIN_EXE_gnunet-arm-spawn-helper")),
        LaunchLimits::default(),
        registry,
    )?)
}
#[test]
fn live_configuration_update_during_partial_tx_keeps_original_stream_and_every_frame_once() -> Test
{
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        use std::future::{Future, poll_fn};
        use tokio::sync::oneshot;
        let dir = Dir::new()?;
        let listener = UnixListener::bind(dir.0.join("partial.sock"))?;
        let (gate, wait) = oneshot::channel();
        let (done, mut completed) = oneshot::channel();
        let peer = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await?;
            assert_eq!(frame(&mut s).await?, b"\0\x04\0\x0f");
            s.write_all(b"\0\x04\0\x0f").await?;
            wait.await.map_err(io::Error::other)?;
            for index in 0..100usize {
                let f = frame(&mut s).await?;
                assert_eq!(f.len(), 65535);
                assert_eq!(&f[2..4], &8u16.to_be_bytes());
                assert_eq!(
                    &f[8..16],
                    &u64::try_from(index + 1)
                        .map_err(io::Error::other)?
                        .to_be_bytes()
                );
                assert_eq!(
                    f[16],
                    b'A' + u8::try_from(index % 26).map_err(io::Error::other)?
                );
                assert_eq!(
                    f[17],
                    b'A' + u8::try_from(index / 26).map_err(io::Error::other)?
                );
                assert!(f[18..f.len() - 1].iter().all(|b| *b == b'x'));
                assert_eq!(f.last(), Some(&0));
            }
            done.send(())
                .map_err(|_| io::Error::other("completed receiver"))?;
            assert_eq!(s.read(&mut [0]).await?, 0);
            Ok::<_, io::Error>(())
        });
        let cfg = config(&dir.0.join("partial.sock"))?;
        let live = LiveConfiguration::new(cfg.duplicate()?);
        let mut registry = ChildRegistry::new(4)?;
        let mut ops = [OperationSlot::EMPTY; 4];
        let mut slots = [FrameSlot::EMPTY; 128];
        let mut pool = vec![0; 8 * 1024 * 1024];
        let mut host = ClientHost::connect_live(
            core(&mut ops, &mut slots, &mut pool)?,
            live.clone(),
            domain.resolution(),
            launcher(&cfg, &mut registry)?,
            Limits {
                io_slice_bytes: 16384,
                ..Default::default()
            },
            Clock::system()?,
            |_| panic!(),
        )?;
        for index in 0..100usize {
            let mut name = vec![b'x'; 65518];
            name[0] = b'A' + u8::try_from(index % 26)?;
            name[1] = b'A' + u8::try_from(index / 26)?;
            let op = host.request_service_start(&name, StdioInheritance(0))?;
            host.operation_cancel(op)?;
        }
        let until = Instant::now() + Duration::from_secs(3);
        while !host.currently_up() {
            assert_ne!(
                host.drive(Some(until), |event, _| assert!(matches!(
                    event,
                    Inbound::Event(Event::Connection(ConnectionStatus::Connected))
                )))
                .await?,
                Progress::WaitDeadline
            );
        }
        let original = host.connection_epoch();
        let blocked = timeout(Duration::from_millis(20), async {
            loop {
                match host
                    .drive(None, |_, _| panic!("canceled operation callback"))
                    .await
                {
                    Ok(_) => {}
                    Err(e) => break Err::<(), _>(e),
                }
            }
        })
        .await;
        assert!(
            blocked.is_err(),
            "fixture did not reach real kernel backpressure"
        );
        assert_eq!(host.connection_epoch(), original);
        // Invalid future configuration cannot replace the currently blocked
        // original stream, partial TX cursor or queued callback-suppressed frames.
        live.replace(Configuration::new(Default::default()))?;
        gate.send(()).map_err(|_| "gate")?;
        loop {
            let mut step =
                Box::pin(host.drive(Some(until), |_, _| panic!("canceled operation callback")));
            let ready = poll_fn(|cx| {
                if let std::task::Poll::Ready(done) = std::pin::Pin::new(&mut completed).poll(cx) {
                    return std::task::Poll::Ready(done.map(|_| true).map_err(io::Error::other));
                }
                match step.as_mut().poll(cx) {
                    std::task::Poll::Ready(Ok(Progress::WaitDeadline)) => {
                        std::task::Poll::Ready(Err(io::Error::other("write budget")))
                    }
                    std::task::Poll::Ready(Ok(_)) => std::task::Poll::Ready(Ok(false)),
                    std::task::Poll::Ready(Err(e)) => {
                        std::task::Poll::Ready(Err(io::Error::other(e.to_string())))
                    }
                    std::task::Poll::Pending => std::task::Poll::Pending,
                }
            })
            .await?;
            if ready {
                break;
            }
        }
        assert_eq!(host.connection_epoch(), original);
        host.disconnect(|_, _| panic!("canceled callback on disconnect"))?;
        peer.await??;
        Ok(())
    })
}

#[test]
fn live_update_does_not_retarget_or_wake_an_original_polled_connection_attempt() -> Test {
    use gnunet_client_host::Endpoint;
    use std::{
        future::Future,
        pin::Pin,
        sync::Arc,
        task::{Context, Poll, Wake, Waker},
    };
    struct WakeCount(AtomicU64);
    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        let dir = Dir::new()?;
        let old = dir.0.join("attempt-old.sock");
        let new = dir.0.join("attempt-new.sock");
        let old_listener = UnixListener::bind(&old)?;
        let new_listener = UnixListener::bind(&new)?;
        let live = LiveConfiguration::new(config(&old)?);
        let endpoint = Endpoint::configuration_live(live.clone(), b"arm", domain.resolution())?;
        let mut original = endpoint.attempt(0);
        let wake_count = Arc::new(WakeCount(AtomicU64::new(0)));
        let waker = Waker::from(wake_count.clone());
        assert!(matches!(
            Pin::new(&mut original).poll(&mut Context::from_waker(&waker)),
            Poll::Pending
        ));
        let before = wake_count.0.load(Ordering::Relaxed);
        live.replace(config(&new)?)?;
        assert_eq!(
            wake_count.0.load(Ordering::Relaxed),
            before,
            "replace itself must not wake the attempt"
        );
        let connection = timeout(Duration::from_secs(2), original).await??;
        let (old_stream, _) = timeout(Duration::from_secs(2), old_listener.accept()).await??;
        assert!(
            timeout(Duration::from_millis(10), new_listener.accept())
                .await
                .is_err()
        );
        drop(connection);
        drop(old_stream);
        let next = timeout(Duration::from_secs(2), endpoint.attempt(2)).await??;
        let (new_stream, _) = timeout(Duration::from_secs(2), new_listener.accept()).await??;
        drop(next);
        drop(new_stream);
        Ok(())
    })
}
