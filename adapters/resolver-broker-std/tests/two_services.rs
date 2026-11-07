//! Actual ARM and STATISTICS hosts multiplex one explicit process Resolver MQ.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Owned socket/authority invariants are actual assertions"
)]
use gnunet_arm_core::{
    FrameSlot,
    client::{Client, Inbound, OperationSlot},
    wire::ArmAbi,
};
use gnunet_arm_host::{ChildRegistry, ClientHost, Clock, LaunchLimits, LocalLauncher};
use gnunet_client::{
    resolver::{Reply as WireReply, Request, encode_response},
    statistics::Selector,
    statistics_handle::GetFlow,
};
use gnunet_config::Configuration;
use gnunet_ipc_unix::handle::{Event as StatisticsEvent, StatisticsHandle};
use gnunet_resolver_broker::{FamilyProfile, LiveConfiguration, Progress, SystemClock, broker};
use gnunet_wire::official::Frame;
use std::{
    error::Error,
    future::{Future, poll_fn},
    io,
    net::Ipv4Addr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::Poll,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixListener, UnixStream},
    time::{Instant, timeout},
};
type Result<T = ()> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        let p = std::env::temp_dir().join(format!(
            "shared-two-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&p)?;
        Ok(Self(p))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}
async fn frame(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    let mut h = [0; 4];
    stream.read_exact(&mut h).await?;
    let len = usize::from(u16::from_be_bytes([h[0], h[1]]));
    if len < 4 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut b = vec![0; len];
    b[..4].copy_from_slice(&h);
    stream.read_exact(&mut b[4..]).await?;
    Ok(b)
}
fn profile() -> Result<FamilyProfile> {
    let p = gnunet_resolver_broker::native_profile()?;
    Ok(FamilyProfile::new(
        p.encode(gnunet_resolver_broker::Family::V4),
        p.encode(gnunet_resolver_broker::Family::V6),
    )?)
}
fn reply(id: gnunet_client::resolver::WireId, end: bool) -> Result<Vec<u8>> {
    let mut b = vec![0; 24];
    let n = encode_response(
        id,
        if end {
            WireReply::End
        } else {
            WireReply::Address(Ipv4Addr::LOCALHOST.into())
        },
        &mut b,
    )?;
    b.truncate(n);
    Ok(b)
}
#[test]
fn arm_and_statistics_share_fifo_and_keep_dns_subscription_after_arm_test_success() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let dir = Directory::new()?;
            let path = dir.0.join("resolver");
            let resolver = UnixListener::bind(&path)?;
            let arm_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let stats_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let arm_port = arm_listener.local_addr()?.port();
            let stats_port = stats_listener.local_addr()?.port();
            let (command, mut peer_command) = UnixStream::pair()?;
            let dns_peer = tokio::spawn(async move {
                let (mut s, _) = resolver.accept().await?;
                let bytes = frame(&mut s).await?;
                let first = Request::decode(Frame::decode(&bytes)?, profile()?)?;
                assert!(matches!(
                    first.query(),
                    gnunet_client::resolver::Query::Forward {
                        hostname: b"arm-owned",
                        ..
                    }
                ));
                s.write_all(&reply(first.id(), false)?).await?;
                assert_eq!(peer_command.read_u8().await?, 1);
                assert!(
                    timeout(Duration::from_millis(20), s.read_u8())
                        .await
                        .is_err(),
                    "tail must not send before head END even after ARM TCP TEST succeeded"
                );
                s.write_all(&reply(first.id(), true)?).await?;
                let bytes = frame(&mut s).await?;
                let second = Request::decode(Frame::decode(&bytes)?, profile()?)?;
                assert!(matches!(
                    second.query(),
                    gnunet_client::resolver::Query::Forward {
                        hostname: b"stats-owned",
                        ..
                    }
                ));
                assert_ne!(first.id(), second.id());
                s.write_all(&[reply(second.id(), false)?, reply(second.id(), true)?].concat())
                    .await?;
                assert_eq!(
                    timeout(Duration::from_secs(3), s.read_u8())
                        .await?
                        .err()
                        .map(|e| e.kind()),
                    Some(io::ErrorKind::UnexpectedEof)
                );
                assert!(
                    timeout(Duration::from_millis(20), resolver.accept())
                        .await
                        .is_err()
                );
                Ok::<_, Box<dyn Error + Send + Sync>>(())
            });
            let arm_peer = tokio::spawn(async move {
                let (mut s, _) = arm_listener.accept().await?;
                let test = frame(&mut s).await?;
                assert_eq!(&test, b"\0\x04\0\x0f");
                s.write_all(&test).await?;
                let request = frame(&mut s).await?;
                assert_eq!(&request[..4], b"\0\x10\0\x0c");
                let mut list = [0u8; 24];
                list[..4].copy_from_slice(b"\0\x18\0\x0d");
                list[8..16].copy_from_slice(&request[8..16]);
                s.write_all(&list).await?;
                assert_eq!(s.read(&mut [0]).await?, 0);
                Ok::<_, io::Error>(())
            });
            let stats_peer = tokio::spawn(async move {
                let (mut s, _) = stats_listener.accept().await?;
                let get = frame(&mut s).await?;
                assert_eq!(&get, b"\0\x08\0\xa9s\0n\0");
                s.write_all(b"\0\x04\0\xab").await?;
                assert_eq!(s.read(&mut [0]).await?, 0);
                Ok::<_, io::Error>(())
            });
            let mut cfg = Configuration::default();
            cfg.set_value(
                b"resolver",
                b"UNIXPATH",
                Some(path.as_os_str().as_encoded_bytes()),
            )?;
            cfg.set_value(b"arm", b"HOSTNAME", Some(b"arm-owned"))?;
            cfg.set_value(b"arm", b"PORT", Some(arm_port.to_string().as_bytes()))?;
            cfg.set_value(b"statistics", b"HOSTNAME", Some(b"stats-owned"))?;
            cfg.set_value(
                b"statistics",
                b"PORT",
                Some(stats_port.to_string().as_bytes()),
            )?;
            let (ctx, mut resolver_driver) = broker::<8, 64>(
                LiveConfiguration::new(cfg.duplicate()?),
                Default::default(),
                profile()?,
                Arc::new(SystemClock),
            )?;
            let mut registry = ChildRegistry::new(4)?;
            let launcher = LocalLauncher::new(
                cfg.duplicate()?,
                std::env::current_exe()?,
                LaunchLimits::default(),
                &mut registry,
            )?;
            // No local ARM START operation is admitted. The helper port is never executed.
            let mut operations = [OperationSlot::EMPTY; 4];
            let mut slots = [FrameSlot::EMPTY; 4];
            let mut pool = [0; 256];
            let core = Client::new(&mut operations, &mut slots, &mut pool, 1, ArmAbi::U64Align8)?;
            let mut initial_error = false;
            let mut arm = ClientHost::connect(
                core,
                cfg.duplicate()?,
                ctx.resolution_context(),
                launcher,
                Default::default(),
                Clock::system()?,
                |_| initial_error = true,
            )?;
            assert!(!initial_error);
            let mut statistics_instance_1 = gnunet_client::statistics_handle::Instance::new();
            let mut statistics = StatisticsHandle::<8, 128, 1, 8, 4>::from_config(
                &mut statistics_instance_1,
                &cfg,
                ctx.resolution_context(),
                b"s",
                gnunet_ipc_unix::handle::Limits {
                    max_frame_bytes: 512,
                    write_chunk_bytes: 1,
                },
            )?
            .ok_or("statistics disabled")?;
            let until = Instant::now() + Duration::from_secs(4);
            let mut listed = false;
            let mut get_done = false;
            let mut issued = None;
            let mut get_id = None;
            let mut signalled = false;
            while !(listed && get_done) {
                if arm.currently_up() && issued.is_none() {
                    issued = Some(arm.request_service_list()?);
                    get_id = Some(statistics.get(Selector {
                        subsystem: b"s",
                        name: b"n",
                    })?);
                }
                let mut control = Box::pin(arm.drive(Some(until), |event, _| {
                    if let Inbound::List { operation, list } = event {
                        assert_eq!(Some(operation), issued);
                        assert_eq!(list.len(), 0);
                        listed = true;
                    }
                }));
                let mut stats = if get_id.is_some() {
                    Some(Box::pin(statistics.drive(Some(until), |event, _| {
                        if let StatisticsEvent::GetComplete(end) = event {
                            assert_eq!(Some(end.get), get_id);
                            assert!(end.result.is_ok());
                            get_done = true;
                        }
                        GetFlow::Continue
                    })))
                } else {
                    None
                };
                let mut resolving = Box::pin(resolver_driver.drive_waiting(Some(until), |_| {}));
                tokio::time::timeout_at(
                    until,
                    poll_fn(|cx| {
                        if let Poll::Ready(result) = control.as_mut().poll(cx) {
                            return Poll::Ready(
                                result
                                    .map(|p| {
                                        assert_ne!(p, gnunet_arm_host::Progress::WaitDeadline);
                                    })
                                    .map_err(io::Error::other),
                            );
                        }
                        if let Some(stats) = &mut stats
                            && let Poll::Ready(result) = stats.as_mut().poll(cx)
                        {
                            return Poll::Ready(
                                result
                                    .map(|p| {
                                        assert_ne!(
                                            p,
                                            gnunet_ipc_unix::handle::Progress::WaitDeadline
                                        );
                                    })
                                    .map_err(io::Error::other),
                            );
                        }
                        if !signalled && ctx.pending_requests().map_err(io::Error::other)? == 2 {
                            match command.try_write(&[1]) {
                                Ok(1) => {
                                    signalled = true;
                                    return Poll::Ready(Ok(()));
                                }
                                Ok(_) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                                Err(e) => return Poll::Ready(Err(e)),
                            }
                        }
                        if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                            return Poll::Ready(
                                result
                                    .map(|p| {
                                        assert_ne!(p, Progress::WaitDeadline);
                                    })
                                    .map_err(io::Error::other),
                            );
                        }
                        Poll::Pending
                    }),
                )
                .await??;
            }
            assert!(signalled);
            statistics.destroy(false)?;
            arm.disconnect(|_, _| {})?;
            drop(statistics);
            drop(arm);
            while resolver_driver.drive(Some(until), |_| {}).await? != Progress::Idle {}
            assert_eq!(ctx.pending_requests()?, 0);
            dns_peer.await??;
            arm_peer.await??;
            stats_peer.await??;
            assert_eq!(registry.pending_children(), 0);
            Ok(())
        })
}
