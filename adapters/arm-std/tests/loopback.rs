//! Actual Unix/TCP control and monitor ownership across cancellation and EOF.
#![expect(
    clippy::panic,
    reason = "These test-only callbacks deliberately fail on unexpected invocation or result shape."
)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Actual socket assertions retain OS errors through Result"
)]
#[path = "../../resolver-broker-std/tests/support/domain.rs"]
mod resolution_domain;
use gnunet_arm_core::{
    FrameSlot,
    client::{Client, ConnectionStatus, Event, Inbound, OperationSlot, StdioInheritance},
    monitor::Monitor,
    wire::{ArmAbi, RequestStatus, ResultCode},
};
use gnunet_arm_host::{
    ChildRegistry, ClientHost, Clock, LaunchLimits, Limits, LocalLauncher, MonitorEvent,
    MonitorHost, Progress,
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
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixListener},
    time::{Instant, timeout},
};
type Test = Result<(), Box<dyn Error>>;
static NEXT: AtomicU64 = AtomicU64::new(1000);
struct Dir(PathBuf);
impl Dir {
    fn new() -> io::Result<Self> {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let p = PathBuf::from(format!("/tmp/gnunet-arm-host-{}-{n}", std::process::id()));
        std::fs::create_dir(&p)?;
        Ok(Self(p))
    }
    fn socket(&self) -> PathBuf {
        self.0.join("s")
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
fn core<'a>(
    ops: &'a mut [OperationSlot],
    slots: &'a mut [FrameSlot],
    bytes: &'a mut [u8],
) -> Result<Client<'a>, Box<dyn Error>> {
    Ok(Client::new(
        ops,
        slots,
        bytes,
        NEXT.fetch_add(1, Ordering::Relaxed),
        ArmAbi::U64Align8,
    )?)
}
async fn frame(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    let mut h = [0; 4];
    stream.read_exact(&mut h).await?;
    let size = usize::from(u16::from_be_bytes([h[0], h[1]]));
    if !(4..=65535).contains(&size) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut f = vec![0; size];
    f[..4].copy_from_slice(&h);
    stream.read_exact(&mut f[4..]).await?;
    Ok(f)
}
fn result(id: u64, code: u32) -> Vec<u8> {
    let mut f = vec![0; 24];
    f[..4].copy_from_slice(b"\0\x18\0\x0a");
    f[8..16].copy_from_slice(&id.to_be_bytes());
    f[16..20].copy_from_slice(&code.to_be_bytes());
    f
}
fn status(code: u32, name: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&u16::try_from(9 + name.len()).unwrap_or(0).to_be_bytes());
    f.extend_from_slice(&11u16.to_be_bytes());
    f.extend_from_slice(&code.to_be_bytes());
    f.extend_from_slice(name);
    f.push(0);
    f
}
#[test]
fn fragmented_unix_all_remote_requests_cancellation_and_list_borrow() -> Test {
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        let dir = Dir::new()?;
        let listener = UnixListener::bind(dir.socket())?;
        let peer = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await?;
            assert_eq!(frame(&mut s).await?, b"\0\x04\0\x0f");
            s.write_all(b"\0\x04\0\x0f").await?;
            let a = frame(&mut s).await?;
            let b = frame(&mut s).await?;
            let c = frame(&mut s).await?;
            assert_eq!(&a[2..4], &8u16.to_be_bytes());
            assert_eq!(&a[16..], b"svc\0");
            assert_eq!(&b[2..4], &9u16.to_be_bytes());
            assert_eq!(&b[16..], b"cancel\0");
            assert_eq!(&c[2..4], &12u16.to_be_bytes());
            let mut replies = result(1, 2);
            replies.extend(result(2, 0));
            let mut list = vec![0; 24];
            list[..4].copy_from_slice(b"\0\x18\0\x0d");
            list[8..16].copy_from_slice(&3u64.to_be_bytes());
            replies.extend(list);
            for byte in replies {
                s.write_all(&[byte]).await?;
            }
            let mut rest = [0];
            assert_eq!(s.read(&mut rest).await?, 0);
            Ok::<_, io::Error>(())
        });
        let cfg = config(&dir.socket())?;
        let mut registry = ChildRegistry::new(64)?;
        let mut ops = [OperationSlot::EMPTY; 8];
        let mut frames = [FrameSlot::EMPTY; 16];
        let mut pool = [0; 4096];
        let mut host = ClientHost::connect(
            core(&mut ops, &mut frames, &mut pool)?,
            cfg.duplicate()?,
            domain.resolution(),
            launcher(&cfg, &mut registry)?,
            Limits {
                io_slice_bytes: 1,
                ..Default::default()
            },
            Clock::system()?,
            |_| panic!("initial MQ failure"),
        )?;
        let start = host.request_service_start(b"svc", StdioInheritance(0xffff))?;
        let cancel = host.request_service_stop(b"cancel")?;
        host.operation_cancel(cancel)?;
        let list = host.request_service_list()?;
        let mut connected = 0;
        let mut got_start = false;
        let mut got_list = false;
        let until = Instant::now() + Duration::from_secs(3);
        while !got_start || !got_list {
            let p = host
                .drive(Some(until), |event, _| match event {
                    Inbound::Event(Event::Connection(ConnectionStatus::Connected)) => {
                        connected += 1
                    }
                    Inbound::Event(Event::Result {
                        operation,
                        status,
                        result,
                    }) => {
                        assert_eq!(operation, start);
                        assert_eq!(status, RequestStatus::SentOk);
                        assert_eq!(result, Some(ResultCode::STARTING));
                        got_start = true;
                    }
                    Inbound::List {
                        operation,
                        list: values,
                    } => {
                        assert_eq!(operation, list);
                        assert_eq!(values.len(), 0);
                        got_list = true;
                    }
                    e => panic!("unexpected {e:?}"),
                })
                .await?;
            assert_ne!(p, Progress::WaitDeadline);
        }
        assert_eq!(connected, 1);
        assert!(!host.owns_operation(start));
        assert!(!host.owns_operation(cancel));
        host.disconnect(|_, _| panic!("completed operations repeated"))?;
        peer.await??;
        Ok(())
    })
}
#[test]
fn tcp_monitor_raw_status_reconnect_and_stop_inside_callback() -> Test {
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let peer = tokio::spawn(async move {
            for i in 0..2 {
                let (mut s, _) = listener.accept().await?;
                assert_eq!(frame(&mut s).await?, b"\0\x04\0\x0e");
                let f = status(
                    if i == 0 { 0 } else { 0xabcdef01 },
                    if i == 0 { b"arm" } else { b"x\xff" },
                );
                for byte in f {
                    s.write_all(&[byte]).await?;
                }
                if i == 1 {
                    assert_eq!(s.read(&mut [0]).await?, 0);
                }
            }
            Ok::<_, io::Error>(())
        });
        let mut cfg = Configuration::new(Default::default());
        cfg.set_number(b"arm", b"PORT", u64::from(port))?;
        cfg.set_value(b"arm", b"HOSTNAME", Some(b"127.0.0.1"))?;
        let mut slots = [FrameSlot::EMPTY; 2];
        let mut pool = [0; 8];
        let core = Monitor::new(&mut slots, &mut pool, NEXT.fetch_add(1, Ordering::Relaxed))?;
        let mut monitor = MonitorHost::start(
            core,
            cfg,
            domain.resolution(),
            Limits {
                io_slice_bytes: 1,
                ..Default::default()
            },
            Clock::system()?,
            |_| panic!("initial monitor unavailable"),
        )?;
        let mut seen = Vec::new();
        let until = Instant::now() + Duration::from_secs(3);
        while seen.len() < 2 {
            assert_ne!(
                monitor
                    .drive(Some(until), |event, ctx| match event {
                        MonitorEvent::Status(status) => {
                            seen.push((status.status.0, status.service.to_vec()));
                            if seen.len() == 2 {
                                ctx.stop();
                            }
                        }
                        _ => panic!("unexpected unavailable"),
                    })
                    .await?,
                Progress::WaitDeadline
            );
        }
        assert_eq!(
            seen,
            [(0, b"arm".to_vec()), (0xabcdef01, b"x\xff".to_vec())]
        );
        assert!(monitor.is_closed());
        assert_eq!(
            monitor
                .drive(Some(until), |_, _| panic!("post-stop callback"))
                .await?,
            Progress::Closed
        );
        peer.await??;
        Ok(())
    })
}
#[test]
fn physical_eof_distinguishes_stopping_waiter_from_pending_stop() -> Test {
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        for stopping in [false, true] {
            let dir = Dir::new()?;
            let listener = UnixListener::bind(dir.socket())?;
            let peer = tokio::spawn(async move {
                let (mut s, _) = listener.accept().await?;
                frame(&mut s).await?;
                s.write_all(b"\0\x04\0\x0f").await?;
                let stop = frame(&mut s).await?;
                assert_eq!(&stop[16..], b"ARM\0");
                if stopping {
                    s.write_all(&result(1, 1)).await?;
                }
                drop(s);
                Ok::<_, io::Error>(())
            });
            let cfg = config(&dir.socket())?;
            let mut registry = ChildRegistry::new(64)?;
            let mut ops = [OperationSlot::EMPTY; 4];
            let mut slots = [FrameSlot::EMPTY; 8];
            let mut pool = [0; 1024];
            let mut host = ClientHost::connect(
                core(&mut ops, &mut slots, &mut pool)?,
                cfg.duplicate()?,
                domain.resolution(),
                launcher(&cfg, &mut registry)?,
                Limits::default(),
                Clock::system()?,
                |_| panic!(),
            )?;
            let op = host.request_service_stop(b"ARM")?;
            let mut events = Vec::new();
            let until = Instant::now() + Duration::from_secs(2);
            while !events.iter().any(|e| matches!(e, Event::Result { .. })) {
                assert_ne!(
                    host.drive(Some(until), |e, _| if let Inbound::Event(e) = e {
                        events.push(e)
                    })
                    .await?,
                    Progress::WaitDeadline
                );
            }
            let (_, status, code) = events
                .iter()
                .find_map(|e| {
                    if let Event::Result {
                        operation,
                        status,
                        result,
                    } = e
                    {
                        Some((*operation, *status, *result))
                    } else {
                        None
                    }
                })
                .ok_or("missing result")?;
            assert_eq!(
                events
                    .iter()
                    .filter(|e| matches!(e,Event::Result{operation,..} if *operation==op))
                    .count(),
                1
            );
            assert_eq!(
                (status, code),
                if stopping {
                    (RequestStatus::SentOk, Some(ResultCode::STOPPED))
                } else {
                    (RequestStatus::Disconnected, None)
                }
            );
            host.disconnect(|_, _| {})?;
            peer.await??;
        }
        Ok(())
    })
}
#[test]
fn bad_registered_frame_retires_one_epoch_without_replaying_operations() -> Test {
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        let dir = Dir::new()?;
        let listener = UnixListener::bind(dir.socket())?;
        let peer = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await?;
            frame(&mut first).await?;
            let list = frame(&mut first).await?;
            assert_eq!(&list[2..4], &12u16.to_be_bytes());
            first.write_all(b"\0\x05\0\x0fX").await?;
            assert_eq!(first.read(&mut [0]).await?, 0);
            drop(first);
            let (mut second, _) = listener.accept().await?;
            assert_eq!(frame(&mut second).await?, b"\0\x04\0\x0f");
            second.write_all(b"\0\x04\0\x0f").await?;
            let probe = timeout(Duration::from_millis(25), second.read(&mut [0])).await;
            assert!(probe.is_err(), "old list replayed");
            Ok::<_, io::Error>(())
        });
        let cfg = config(&dir.socket())?;
        let mut registry = ChildRegistry::new(64)?;
        let mut ops = [OperationSlot::EMPTY; 4];
        let mut slots = [FrameSlot::EMPTY; 8];
        let mut pool = [0; 1024];
        let mut host = ClientHost::connect(
            core(&mut ops, &mut slots, &mut pool)?,
            cfg.duplicate()?,
            domain.resolution(),
            launcher(&cfg, &mut registry)?,
            Limits::default(),
            Clock::system()?,
            |_| panic!(),
        )?;
        let op = host.request_service_list()?;
        let mut failed = 0;
        let mut connected = 0;
        let until = Instant::now() + Duration::from_secs(2);
        while connected == 0 {
            assert_ne!(
                host.drive(Some(until), |event, _| match event {
                    Inbound::Event(Event::ListDisconnected { operation }) => {
                        assert_eq!(operation, op);
                        failed += 1;
                    }
                    Inbound::Event(Event::Connection(ConnectionStatus::Connected)) =>
                        connected += 1,
                    _ => {}
                })
                .await?,
                Progress::WaitDeadline
            );
        }
        assert_eq!(failed, 1);
        peer.await??;
        host.disconnect(|_, _| {})?;
        Ok(())
    })
}
#[test]
fn invalid_initial_configuration_reports_each_original_unavailable_once() -> Test {
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        let cfg = Configuration::new(Default::default());
        let mut registry = ChildRegistry::new(64)?;
        let mut ops = [OperationSlot::EMPTY; 4];
        let mut slots = [FrameSlot::EMPTY; 4];
        let mut pool = [0; 32];
        let mut statuses = Vec::new();
        assert!(
            ClientHost::connect(
                core(&mut ops, &mut slots, &mut pool)?,
                cfg.duplicate()?,
                domain.resolution(),
                launcher(&cfg, &mut registry)?,
                Limits::default(),
                Clock::system()?,
                |s| statuses.push(s)
            )
            .is_err()
        );
        assert_eq!(statuses, [ConnectionStatus::Error]);
        let mut slots = [FrameSlot::EMPTY; 2];
        let mut pool = [0; 8];
        let core = Monitor::new(&mut slots, &mut pool, NEXT.fetch_add(1, Ordering::Relaxed))?;
        let mut unavailable = Vec::new();
        assert!(
            MonitorHost::start(
                core,
                cfg,
                domain.resolution(),
                Limits::default(),
                Clock::system()?,
                |e| { unavailable.push(e) }
            )
            .is_err()
        );
        assert_eq!(unavailable.len(), 1);
        assert!(unavailable[0].initial);
        Ok(())
    })
}
#[test]
fn unavailable_socket_retries_inside_original_mq_and_preserves_queued_list() -> Test {
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        let dir = Dir::new()?;
        let cfg = config(&dir.socket())?;
        let mut registry = ChildRegistry::new(64)?;
        let mut ops = [OperationSlot::EMPTY; 4];
        let mut slots = [FrameSlot::EMPTY; 8];
        let mut pool = [0; 1024];
        let mut host = ClientHost::connect(
            core(&mut ops, &mut slots, &mut pool)?,
            cfg.duplicate()?,
            domain.resolution(),
            launcher(&cfg, &mut registry)?,
            Limits::default(),
            Clock::system()?,
            |_| panic!(),
        )?;
        let original = host.connection_epoch();
        let id = host.request_service_list()?;
        let early = Instant::now() + Duration::from_millis(15);
        loop {
            if host
                .drive(Some(early), |_, _| {
                    panic!("socket retry fabricated callback")
                })
                .await?
                == Progress::WaitDeadline
            {
                break;
            }
        }
        assert_eq!(host.connection_epoch(), original);
        assert!(host.owns_operation(id));
        let listener = UnixListener::bind(dir.socket())?;
        let peer = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await?;
            assert_eq!(frame(&mut s).await?, b"\0\x04\0\x0f");
            let list = frame(&mut s).await?;
            assert_eq!(&list[2..4], &12u16.to_be_bytes());
            let mut reply = vec![0; 24];
            reply[..4].copy_from_slice(b"\0\x18\0\x0d");
            reply[8..16].copy_from_slice(&1u64.to_be_bytes());
            s.write_all(&reply).await?;
            assert_eq!(s.read(&mut [0]).await?, 0);
            Ok::<_, io::Error>(())
        });
        let mut complete = false;
        let until = Instant::now() + Duration::from_secs(2);
        while !complete {
            assert_ne!(
                host.drive(Some(until), |event, _| match event {
                    Inbound::List { operation, list } => {
                        assert_eq!(operation, id);
                        assert!(list.is_empty());
                        complete = true;
                    }
                    _ => panic!("unexpected retry callback"),
                })
                .await?,
                Progress::WaitDeadline
            );
        }
        assert_eq!(host.connection_epoch(), original);
        host.disconnect(|_, _| {})?;
        peer.await??;
        Ok(())
    })
}
#[test]
fn canceled_drive_under_real_socket_backpressure_keeps_every_original_byte_once() -> Test {
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        use std::future::{Future, poll_fn};
        use tokio::sync::oneshot;
        let dir = Dir::new()?;
        let listener = UnixListener::bind(dir.socket())?;
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
        let cfg = config(&dir.socket())?;
        let mut registry = ChildRegistry::new(4)?;
        let mut ops = [OperationSlot::EMPTY; 4];
        let mut slots = [FrameSlot::EMPTY; 128];
        let mut pool = vec![0; 8 * 1024 * 1024];
        let mut host = ClientHost::connect(
            core(&mut ops, &mut slots, &mut pool)?,
            cfg.duplicate()?,
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
fn list_reply(id: u64, count: u16, rows: &[u8], pool: &[u8]) -> Vec<u8> {
    let n = 24 + rows.len() + pool.len();
    let mut f = vec![0; 24];
    f[..2].copy_from_slice(&match u16::try_from(n) {
        Ok(n) => n.to_be_bytes(),
        Err(_) => panic!("bounded fixture overflow"),
    });
    f[2..4].copy_from_slice(&13u16.to_be_bytes());
    f[8..16].copy_from_slice(&id.to_be_bytes());
    f[16..18].copy_from_slice(&count.to_be_bytes());
    f.extend_from_slice(rows);
    f.extend_from_slice(pool);
    f
}
#[test]
fn malformed_list_rows_indices_nuls_prefix_and_result_retire_exact_original_mq() -> Test {
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        let mut name_index = vec![0; 28];
        name_index[..2].copy_from_slice(&2u16.to_be_bytes());
        let mut binary_index = vec![0; 28];
        binary_index[2..4].copy_from_slice(&2u16.to_be_bytes());
        let mut binary_nul = vec![0; 28];
        binary_nul[2..4].copy_from_slice(&1u16.to_be_bytes());
        let mut prefix = vec![0; 18];
        prefix[..4].copy_from_slice(b"\0\x12\0\x0d");
        prefix[8..16].copy_from_slice(&1u64.to_be_bytes());
        let mut short_result = vec![0; 20];
        short_result[..4].copy_from_slice(b"\0\x14\0\x0a");
        for bad in [
            list_reply(1, 1, &[], b""),
            list_reply(1, 1, &name_index, b"x\0"),
            list_reply(1, 1, &binary_index, b"x\0"),
            list_reply(1, 1, &[0; 28], b"x"),
            list_reply(1, 1, &binary_nul, b"\0x"),
            list_reply(1, 2, &[vec![0; 28], name_index.clone()].concat(), b"x\0"),
            list_reply(1, 2, &[vec![0; 28], binary_index.clone()].concat(), b"x\0"),
            prefix,
            short_result,
            vec![0, 3, 0, 13],
        ] {
            let dir = Dir::new()?;
            let listener = UnixListener::bind(dir.socket())?;
            let peer = tokio::spawn(async move {
                let (mut s, _) = listener.accept().await?;
                assert_eq!(frame(&mut s).await?, b"\0\x04\0\x0f");
                s.write_all(b"\0\x04\0\x0f").await?;
                assert_eq!(&frame(&mut s).await?[2..4], &12u16.to_be_bytes());
                s.write_all(&bad).await?;
                assert_eq!(s.read(&mut [0]).await?, 0);
                Ok::<_, io::Error>(())
            });
            let cfg = config(&dir.socket())?;
            let mut registry = ChildRegistry::new(2)?;
            let mut ops = [OperationSlot::EMPTY; 2];
            let mut slots = [FrameSlot::EMPTY; 4];
            let mut pool = [0; 128];
            let mut host = ClientHost::connect(
                core(&mut ops, &mut slots, &mut pool)?,
                cfg.duplicate()?,
                domain.resolution(),
                launcher(&cfg, &mut registry)?,
                Limits::default(),
                Clock::system()?,
                |_| panic!(),
            )?;
            let id = host.request_service_list()?;
            let mut callbacks = Vec::new();
            let until = Instant::now() + Duration::from_secs(2);
            while !callbacks
                .iter()
                .any(|event| matches!(event, Event::Connection(ConnectionStatus::Disconnected)))
            {
                assert_ne!(
                    host.drive(Some(until), |event, _| match event {
                        Inbound::Event(event) => callbacks.push(event),
                        Inbound::List { .. } => panic!("partially validated list exposed"),
                    })
                    .await?,
                    Progress::WaitDeadline
                );
            }
            let failures: Vec<_> = callbacks
                .iter()
                .filter(|event| !matches!(event, Event::Connection(ConnectionStatus::Connected)))
                .copied()
                .collect();
            assert_eq!(
                failures,
                [
                    Event::ListDisconnected { operation: id },
                    Event::Connection(ConnectionStatus::Disconnected)
                ]
            );
            assert!(!host.owns_operation(id));
            host.disconnect(|_, _| panic!("failure repeated"))?;
            peer.await??;
        }
        Ok(())
    })
}
#[test]
fn wrong_kind_unknown_ids_and_unregistered_frames_preserve_live_original_operation() -> Test {
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        for list_first in [true, false] {
            let dir = Dir::new()?;
            let listener = UnixListener::bind(dir.socket())?;
            let peer = tokio::spawn(async move {
                let (mut s, _) = listener.accept().await?;
                frame(&mut s).await?;
                s.write_all(b"\0\x04\0\x0f").await?;
                frame(&mut s).await?;
                frame(&mut s).await?;
                let mut response = if list_first {
                    result(1, 0xfeedbeef)
                } else {
                    list_reply(1, 0, &[], b"unused")
                };
                response.extend(result(999, 0));
                response.extend(list_reply(999, 0, &[], b""));
                response.extend(b"\0\x04\xfd\xe8\0\x04\0\x0b");
                response.extend(result(2, 0xdeadbeef));
                s.write_all(&response).await?;
                assert_eq!(s.read(&mut [0]).await?, 0);
                Ok::<_, io::Error>(())
            });
            let cfg = config(&dir.socket())?;
            let mut registry = ChildRegistry::new(2)?;
            let mut ops = [OperationSlot::EMPTY; 3];
            let mut slots = [FrameSlot::EMPTY; 8];
            let mut pool = [0; 256];
            let mut host = ClientHost::connect(
                core(&mut ops, &mut slots, &mut pool)?,
                cfg.duplicate()?,
                domain.resolution(),
                launcher(&cfg, &mut registry)?,
                Limits::default(),
                Clock::system()?,
                |_| panic!(),
            )?;
            let gone = if list_first {
                host.request_service_list()?
            } else {
                host.request_service_start(b"wrongkind", StdioInheritance(0))?
            };
            let live = host.request_service_stop(b"live")?;
            let mut seen = Vec::new();
            let until = Instant::now() + Duration::from_secs(2);
            while seen.is_empty() {
                assert_ne!(
                    host.drive(Some(until), |event, _| match event {
                        Inbound::Event(Event::Result {
                            operation,
                            status,
                            result,
                        }) => seen.push((operation, status, result)),
                        Inbound::List { .. } => panic!("wrong-kind callback"),
                        _ => {}
                    })
                    .await?,
                    Progress::WaitDeadline
                );
            }
            assert_eq!(
                seen,
                [(live, RequestStatus::SentOk, Some(ResultCode(0xdeadbeef)))]
            );
            assert!(!host.owns_operation(gone));
            assert!(matches!(
                host.operation_cancel(gone),
                Err(gnunet_arm_host::HostError::Core(
                    gnunet_types::Error::StaleGeneration
                ))
            ));
            host.disconnect(|_, _| panic!("retired operation repeated"))?;
            peer.await??;
        }
        Ok(())
    })
}
#[test]
fn maximum_name_and_capacity_rejection_are_atomic_and_stale_generation_cannot_cancel_reused_slot()
-> Test {
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        let dir = Dir::new()?;
        let listener = UnixListener::bind(dir.socket())?;
        let peer = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await?;
            frame(&mut s).await?;
            let first = frame(&mut s).await?;
            assert_eq!(first.len(), 65535);
            assert_eq!(&first[8..16], &1u64.to_be_bytes());
            assert_eq!(first[65534], 0);
            let second = frame(&mut s).await?;
            assert_eq!(&second[8..16], &2u64.to_be_bytes());
            let mut response = result(1, 2);
            response.extend(list_reply(2, 0, &[], b""));
            s.write_all(&response).await?;
            assert_eq!(s.read(&mut [0]).await?, 0);
            Ok::<_, io::Error>(())
        });
        let cfg = config(&dir.socket())?;
        let mut registry = ChildRegistry::new(2)?;
        let mut ops = [OperationSlot::EMPTY; 1];
        let mut slots = [FrameSlot::EMPTY; 4];
        let mut pool = vec![0; 66000];
        let mut host = ClientHost::connect(
            core(&mut ops, &mut slots, &mut pool)?,
            cfg.duplicate()?,
            domain.resolution(),
            launcher(&cfg, &mut registry)?,
            Limits::default(),
            Clock::system()?,
            |_| panic!(),
        )?;
        let old = host.request_service_start(&vec![b'x'; 65518], StdioInheritance(0))?;
        assert!(host.request_service_list().is_err());
        host.operation_cancel(old)?;
        assert!(
            host.request_service_start(&vec![b'x'; 65519], StdioInheritance(0))
                .is_err()
        );
        let live = host.request_service_list()?;
        assert_ne!(old, live);
        assert!(host.operation_cancel(old).is_err());
        assert!(host.owns_operation(live));
        let until = Instant::now() + Duration::from_secs(3);
        let mut done = false;
        while !done {
            assert_ne!(
                host.drive(Some(until), |event, _| match event {
                    Inbound::List { operation, .. } => {
                        assert_eq!(operation, live);
                        done = true;
                    }
                    Inbound::Event(Event::Result { .. }) =>
                        panic!("canceled old generation received result"),
                    _ => {}
                })
                .await?,
                Progress::WaitDeadline
            );
        }
        host.disconnect(|_, _| panic!())?;
        peer.await??;
        Ok(())
    })
}
#[test]
fn canceled_and_disconnected_stop_waiters_reclaim_all_slots_without_callback_or_null_call() -> Test
{
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        for explicit in [false, true] {
            let dir = Dir::new()?;
            let listener = UnixListener::bind(dir.socket())?;
            let peer = tokio::spawn(async move {
                let (mut s, _) = listener.accept().await?;
                frame(&mut s).await?;
                s.write_all(b"\0\x04\0\x0f").await?;
                let stop = frame(&mut s).await?;
                assert_eq!(&stop[16..], b"ARM\0");
                frame(&mut s).await?;
                let mut replies = result(1, 1);
                replies.extend(list_reply(2, 0, &[], b""));
                s.write_all(&replies).await?;
                if explicit {
                    assert_eq!(s.read(&mut [0]).await?, 0);
                } else {
                    assert_eq!(&frame(&mut s).await?[8..16], &3u64.to_be_bytes());
                    drop(s);
                }
                Ok::<_, io::Error>(())
            });
            let cfg = config(&dir.socket())?;
            let mut registry = ChildRegistry::new(2)?;
            let mut ops = [OperationSlot::EMPTY; 2];
            let mut slots = [FrameSlot::EMPTY; 8];
            let mut pool = [0; 512];
            let mut host = ClientHost::connect(
                core(&mut ops, &mut slots, &mut pool)?,
                cfg.duplicate()?,
                domain.resolution(),
                launcher(&cfg, &mut registry)?,
                Limits::default(),
                Clock::system()?,
                |_| panic!(),
            )?;
            let stop = host.request_service_stop(b"ARM\0ignored")?;
            host.request_service_list()?;
            let mut barrier = false;
            let mut disconnected = false;
            let mut callback_error = None;
            let until = Instant::now() + Duration::from_secs(2);
            while if explicit { !barrier } else { !disconnected } {
                assert_ne!(
                    host.drive(Some(until), |event, context| match event {
                        Inbound::List { .. } => {
                            barrier = true;
                            if explicit {
                                context.disconnect();
                            } else {
                                if let Err(error) = context.operation_cancel(stop) {
                                    callback_error = Some(error);
                                }
                                if let Err(error) = context.request_service_list() {
                                    callback_error = Some(error);
                                }
                            }
                        }
                        Inbound::Event(Event::Connection(ConnectionStatus::Disconnected)) =>
                            disconnected = true,
                        Inbound::Event(Event::Result { operation, .. }) if operation == stop =>
                            panic!("canceled/explicit-disconnected waiter callback"),
                        _ => {}
                    })
                    .await?,
                    Progress::WaitDeadline
                );
            }
            assert!(callback_error.is_none());
            assert!(!host.owns_operation(stop));
            host.disconnect(|_, _| {})?;
            assert_eq!(host.drive(None, |_, _| panic!()).await?, Progress::Closed);
            peer.await??;
        }
        Ok(())
    })
}
#[test]
fn two_stop_waiters_keep_each_original_operation_through_replacement_and_real_eof() -> Test {
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        let dir = Dir::new()?;
        let listener = UnixListener::bind(dir.socket())?;
        let peer = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await?;
            frame(&mut s).await?;
            s.write_all(b"\0\x04\0\x0f").await?;
            for name in [b"arm\0", b"aRm\0"] {
                assert_eq!(&frame(&mut s).await?[16..], name);
            }
            let mut replies = result(1, 1);
            replies.extend(result(2, 1));
            s.write_all(&replies).await?;
            drop(s);
            Ok::<_, io::Error>(())
        });
        let cfg = config(&dir.socket())?;
        let mut registry = ChildRegistry::new(2)?;
        let mut ops = [OperationSlot::EMPTY; 2];
        let mut slots = [FrameSlot::EMPTY; 8];
        let mut pool = [0; 256];
        let mut host = ClientHost::connect(
            core(&mut ops, &mut slots, &mut pool)?,
            cfg.duplicate()?,
            domain.resolution(),
            launcher(&cfg, &mut registry)?,
            Limits::default(),
            Clock::system()?,
            |_| panic!(),
        )?;
        let first = host.request_service_stop(b"arm")?;
        let second = host.request_service_stop(b"aRm")?;
        let mut seen = Vec::new();
        let until = Instant::now() + Duration::from_secs(2);
        while seen.len() < 2 {
            assert_ne!(
                host.drive(Some(until), |event, _| {
                    if let Inbound::Event(Event::Result {
                        operation,
                        status,
                        result,
                    }) = event
                    {
                        seen.push((operation, status, result))
                    }
                })
                .await?,
                Progress::WaitDeadline
            );
        }
        assert_eq!(
            seen,
            [
                (first, RequestStatus::SentOk, Some(ResultCode::IS_NOT_KNOWN)),
                (second, RequestStatus::SentOk, Some(ResultCode::STOPPED))
            ]
        );
        host.disconnect(|_, _| panic!("waiter repeated"))?;
        assert_eq!(host.drive(None, |_, _| panic!()).await?, Progress::Closed);
        peer.await??;
        Ok(())
    })
}
#[test]
fn monitor_canceled_partial_rx_recovers_exact_callback_then_stop_closes_original_stream() -> Test {
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        use tokio::sync::oneshot;
        let dir = Dir::new()?;
        let listener = UnixListener::bind(dir.socket())?;
        let (sent, mut partial) = oneshot::channel();
        let (release, wait) = oneshot::channel();
        let peer = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await?;
            assert_eq!(frame(&mut s).await?, b"\0\x04\0\x0e");
            let response = status(0xfedcba98, b"x\0ignored");
            s.write_all(&response[..2]).await?;
            sent.send(())
                .map_err(|_| io::Error::other("partial receiver"))?;
            wait.await.map_err(io::Error::other)?;
            s.write_all(&response[2..]).await?;
            assert_eq!(s.read(&mut [0]).await?, 0);
            Ok::<_, io::Error>(())
        });
        let cfg = config(&dir.socket())?;
        let mut slots = [FrameSlot::EMPTY; 2];
        let mut pool = [0; 8];
        let core = Monitor::new(&mut slots, &mut pool, NEXT.fetch_add(1, Ordering::Relaxed))?;
        let mut monitor = MonitorHost::start(
            core,
            cfg,
            domain.resolution(),
            Limits {
                io_slice_bytes: 1,
                ..Limits::default()
            },
            Clock::system()?,
            |_| panic!(),
        )?;
        let canceled = timeout(Duration::from_millis(30), async {
            loop {
                if let Err(error) = monitor.drive(None, |_, _| panic!("partial callback")).await {
                    break Err::<(), _>(error);
                }
            }
        })
        .await;
        assert!(canceled.is_err());
        assert!(partial.try_recv().is_ok());
        release.send(()).map_err(|_| "release")?;
        let mut seen = 0;
        let until = Instant::now() + Duration::from_secs(2);
        while seen == 0 {
            assert_ne!(
                monitor
                    .drive(Some(until), |event, context| match event {
                        MonitorEvent::Status(value) => {
                            assert_eq!(value.status.0, 0xfedcba98);
                            assert_eq!(value.service, b"x");
                            context.stop();
                            assert_eq!(value.service, b"x");
                            seen += 1;
                        }
                        _ => panic!("physical partial I/O is not configuration-unavailable"),
                    })
                    .await?,
                Progress::WaitDeadline
            );
        }
        assert_eq!(
            monitor
                .drive(None, |_, _| panic!("late monitor callback"))
                .await?,
            Progress::Closed
        );
        peer.await??;
        Ok(())
    })
}
#[test]
fn foreign_owner_scope_cannot_cancel_an_original_operation_even_before_socket_io() -> Test {
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        let dir = Dir::new()?;
        let cfg = config(&dir.socket())?;
        let mut first_registry = ChildRegistry::new(2)?;
        let mut second_registry = ChildRegistry::new(2)?;
        let mut first_ops = [OperationSlot::EMPTY; 1];
        let mut first_frames = [FrameSlot::EMPTY; 4];
        let mut first_pool = [0; 64];
        let mut second_ops = [OperationSlot::EMPTY; 1];
        let mut second_frames = [FrameSlot::EMPTY; 4];
        let mut second_pool = [0; 64];
        let mut first = ClientHost::connect(
            core(&mut first_ops, &mut first_frames, &mut first_pool)?,
            cfg.duplicate()?,
            domain.resolution(),
            launcher(&cfg, &mut first_registry)?,
            Limits::default(),
            Clock::system()?,
            |_| panic!(),
        )?;
        let mut second = ClientHost::connect(
            core(&mut second_ops, &mut second_frames, &mut second_pool)?,
            cfg.duplicate()?,
            domain.resolution(),
            launcher(&cfg, &mut second_registry)?,
            Limits::default(),
            Clock::system()?,
            |_| panic!(),
        )?;
        let a = first.request_service_list()?;
        let b = second.request_service_list()?;
        assert_ne!(a, b);
        assert!(second.operation_cancel(a).is_err());
        assert!(first.operation_cancel(b).is_err());
        assert!(first.owns_operation(a));
        assert!(second.owns_operation(b));
        let mut first_calls = 0;
        first.disconnect(|event, _| {
            if let Inbound::Event(Event::ListDisconnected { operation }) = event {
                assert_eq!(operation, a);
                first_calls += 1;
            }
        })?;
        let mut second_calls = 0;
        second.disconnect(|event, _| {
            if let Inbound::Event(Event::ListDisconnected { operation }) = event {
                assert_eq!(operation, b);
                second_calls += 1;
            }
        })?;
        assert_eq!((first_calls, second_calls), (1, 1));
        Ok(())
    })
}
#[test]
fn valid_wire_reply_over_declared_host_rx_capacity_retires_mq_without_partial_callback() -> Test {
    runtime()?.block_on(async {
        let mut domain = resolution_domain::Domain::new(Configuration::default())?;
        domain.start()?;
        let dir = Dir::new()?;
        let listener = UnixListener::bind(dir.socket())?;
        let peer = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await?;
            frame(&mut s).await?;
            s.write_all(b"\0\x04\0\x0f").await?;
            frame(&mut s).await?;
            let reply = list_reply(1, 1, &[0; 28], b"n\0");
            assert_eq!(reply.len(), 54);
            s.write_all(&reply).await?;
            assert_eq!(s.read(&mut [0]).await?, 0);
            Ok::<_, io::Error>(())
        });
        let cfg = config(&dir.socket())?;
        let mut registry = ChildRegistry::new(2)?;
        let mut ops = [OperationSlot::EMPTY; 1];
        let mut frames = [FrameSlot::EMPTY; 4];
        let mut pool = [0; 128];
        let mut host = ClientHost::connect(
            core(&mut ops, &mut frames, &mut pool)?,
            cfg.duplicate()?,
            domain.resolution(),
            launcher(&cfg, &mut registry)?,
            Limits {
                max_frame_bytes: 32,
                ..Limits::default()
            },
            Clock::system()?,
            |_| panic!(),
        )?;
        let id = host.request_service_list()?;
        let mut disconnected = false;
        let mut failures = 0;
        let until = Instant::now() + Duration::from_secs(2);
        while !disconnected {
            assert_ne!(
                host.drive(Some(until), |event, _| match event {
                    Inbound::Event(Event::ListDisconnected { operation }) => {
                        assert_eq!(operation, id);
                        failures += 1;
                    }
                    Inbound::Event(Event::Connection(ConnectionStatus::Disconnected)) =>
                        disconnected = true,
                    Inbound::List { .. } => panic!("reply exceeded explicit local RX capacity"),
                    _ => {}
                })
                .await?,
                Progress::WaitDeadline
            );
        }
        assert_eq!(failures, 1);
        assert!(host.take_io_error().is_some());
        host.disconnect(|_, _| panic!("old callback repeated"))?;
        peer.await??;
        Ok(())
    })
}
