//! Native Unix statistics host and descriptor-lifetime fixtures.

#![expect(
    clippy::panic_in_result_fn,
    reason = "Real socket tests assert protocol, resource and lifecycle outcomes"
)]
use super::*;
use crate::{StatisticsClient, StatisticsWatchClient};
use gnunet_client::statistics::{Response, Selector, Set};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::net::TcpListener;
use tokio::net::UnixListener;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

static NEXT: AtomicU64 = AtomicU64::new(1);
type Core = Statistics<8, 64, 4, 8, 16>;
type Completion<T> = Result<(Report, T, Vec<SessionClosed>), IpcError>;
type Running<T> = (PathBuf, UnixStream, tokio::task::JoinHandle<Completion<T>>);
fn bounded_state(core: &mut Core) -> Result<State<'_, 8, 64, 4, 8, 16>, IpcError> {
    let limits = limits();
    let sessions: Vec<Option<Session>> = std::iter::repeat_with(|| None).take(4).collect();
    let scratch = buffer(limits.max_frame_bytes, true)?;
    let baseline = core.external_retained_bytes();
    let external = baseline
        .checked_add(scratch.capacity())
        .and_then(|n| {
            sessions
                .capacity()
                .checked_mul(core::mem::size_of::<Option<Session>>())
                .and_then(|m| n.checked_add(m))
        })
        .ok_or(Error::Overflow)?;
    core.set_external_retained_bytes(external)?;
    Ok(State {
        core,
        sessions,
        scratch,
        limits,
        cursor: 0,
        report: Report::default(),
        accepting: AcceptState::default(),
        tolerant: false,
        unix_access: UnixAccess::default(),
        external,
        baseline,
    })
}
#[test]
fn accepted_tcp_is_canonical_before_statistics_core_admission()
-> Result<(), Box<dyn std::error::Error>> {
    runtime()?.block_on(async {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let _peer = tokio::net::TcpStream::connect(listener.local_addr()?).await?;
        let mut core = Core::new();
        let mut state = bounded_state(&mut core)?;
        let Event::Accept(accepted) =
            poll_fn(|cx| state.poll(&[Listener::Tcp(&listener)], cx, true)).await
        else {
            return Err("expected actual TCP acceptance".into());
        };
        assert_eq!(state.core.client_count(), 0);
        assert!(accepted.diagnostics().is_empty());
        let (stream, peer, _) = accepted.into_parts();
        let socket = socket2::SockRef::from(&stream);
        assert!(socket.nonblocking()?);
        assert!(socket.tcp_nodelay()?);
        use std::os::fd::AsFd;
        assert!(
            nix::fcntl::FdFlag::from_bits_retain(nix::fcntl::fcntl(
                stream.as_fd(),
                nix::fcntl::FcntlArg::F_GETFD
            )?)
            .contains(nix::fcntl::FdFlag::FD_CLOEXEC)
        );
        state.accept(stream, peer, &AccessPolicy::default(), &mut |_| {})?;
        assert_eq!(state.core.client_count(), 1);
        Ok(())
    })
}
#[test]
fn finite_emfile_observation_pauses_accept_until_original_live_client_physically_closes()
-> Result<(), Box<dyn std::error::Error>> {
    runtime()?.block_on(async {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let first = tokio::net::TcpStream::connect(listener.local_addr()?).await?;
        let mut core = Core::new();
        let mut state = bounded_state(&mut core)?;
        let Event::Accept(accepted) =
            poll_fn(|cx| state.poll(&[Listener::Tcp(&listener)], cx, true)).await
        else {
            return Err("expected first actual accept".into());
        };
        let (stream, peer, _) = accepted.into_parts();
        state.accept(stream, peer, &AccessPolicy::default(), &mut |_| {})?;
        let original = state
            .sessions
            .iter()
            .flatten()
            .next()
            .ok_or("original session")?
            .client;
        // This error observation is a finite seam. Both native sockets and
        // the queued connection/EOF below are real; no syscall failure is claimed.
        let event = state
            .accepting
            .failed(AcceptError::Accept(io::Error::from_raw_os_error(
                nix::errno::Errno::EMFILE as i32,
            )));
        assert!(matches!(event, SocketEvent::Failed(error) if error.is_emfile()));
        let _queued = tokio::net::TcpStream::connect(listener.local_addr()?).await?;
        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                poll_fn(|cx| state.poll(&[Listener::Tcp(&listener)], cx, true))
            )
            .await
            .is_err()
        );
        assert_eq!(state.core.client_count(), 1);
        assert!(!state.accepting.ready());
        drop(first);
        let Event::Close(index, reason) =
            poll_fn(|cx| state.poll(&[Listener::Tcp(&listener)], cx, true)).await
        else {
            return Err("original EOF must remain active while accepts are paused".into());
        };
        assert!(matches!(reason, CloseReason::Eof));
        state.close(index, reason, &mut |_| {})?;
        assert_eq!(state.core.client_count(), 0);
        assert!(state.accepting.ready());
        let Event::Accept(accepted) =
            poll_fn(|cx| state.poll(&[Listener::Tcp(&listener)], cx, true)).await
        else {
            return Err(
                "the original kernel-queued connection must be accepted after close".into(),
            );
        };
        let (stream, peer, _) = accepted.into_parts();
        state.accept(stream, peer, &AccessPolicy::default(), &mut |_| {})?;
        let replacement = state
            .sessions
            .iter()
            .flatten()
            .next()
            .ok_or("replacement session")?
            .client;
        assert_ne!(original, replacement);
        assert_eq!(state.report.accepted, 2);
        assert_eq!(state.report.admitted, 2);
        Ok(())
    })
}
fn path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "gnunet-server-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}
fn limits() -> Limits {
    Limits {
        max_connections: 4,
        max_frame_bytes: 128,
        max_pending_bytes: 512,
        idle_timeout: Duration::from_secs(2),
    }
}
fn start<const R: usize, const N: usize, const C: usize, const W: usize, const E: usize>(
    core: Statistics<R, N, C, W, E>,
    limits: Limits,
) -> Result<Running<Statistics<R, N, C, W, E>>, io::Error> {
    start_with_policy(core, limits, false)
}
fn start_with_policy<
    const R: usize,
    const N: usize,
    const C: usize,
    const W: usize,
    const E: usize,
>(
    mut core: Statistics<R, N, C, W, E>,
    limits: Limits,
    soft: bool,
) -> Result<Running<Statistics<R, N, C, W, E>>, io::Error> {
    let path = path();
    let listener = UnixListener::bind(&path)?;
    let (mut stop_reader, stop_writer) = UnixStream::pair()?;
    let task = tokio::spawn(async move {
        let stop = async {
            let mut byte = [0; 1];
            match stop_reader.read(&mut byte).await {
                Ok(_) | Err(_) => {}
            }
        };
        let mut closed = Vec::new();
        let report = serve_statistics_on(
            &[Listener::Unix(&listener)],
            &mut core,
            limits,
            &ServiceOptions {
                shutdown: if soft {
                    ShutdownMode::Soft
                } else {
                    ShutdownMode::Immediate
                },
                ..ServiceOptions::default()
            },
            stop,
            |event| {
                if let ServiceEvent::Closed(event) = event {
                    closed.push(event);
                }
            },
        )
        .await?;
        Ok((report, core, closed))
    });
    Ok((path, stop_writer, task))
}
async fn read<const N: usize>(
    stream: &mut UnixStream,
) -> Result<[u8; N], Box<dyn std::error::Error>> {
    let mut bytes = [0; N];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut bytes)).await??;
    Ok(bytes)
}
async fn eof(stream: &mut UnixStream) -> Result<(), Box<dyn std::error::Error>> {
    let mut byte = [0; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte)).await??,
        0
    );
    Ok(())
}
fn runtime() -> Result<tokio::runtime::Runtime, io::Error> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}

#[test]
fn official_soft_shutdown_finishes_writer_and_does_not_wait_for_monitors()
-> Result<(), Box<dyn std::error::Error>> {
    runtime()?.block_on(async {
        let (path, stop, mut task) = start_with_policy(Core::new(), limits(), true)?;
        let mut monitor = UnixStream::connect(&path).await?;
        monitor.write_all(b"\0\x08\0\xacs\0a\0\0\x04\0\xae").await?;
        assert_eq!(read::<4>(&mut monitor).await?, *b"\0\x04\0\xaf");
        let mut writer = UnixStream::connect(&path).await?;
        writer.write_all(b"\0\x04\0\xae").await?;
        assert_eq!(read::<4>(&mut writer).await?, *b"\0\x04\0\xaf");
        drop(stop);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut task)
                .await
                .is_err()
        );
        // Existing non-monitor requests continue after shutdown was requested.
        writer
            .write_all(b"\0\x14\0\xa8\0\0\0\x02\0\0\0\0\0\0\0\x05s\0a\0\0\x04\0\xae")
            .await?;
        assert_eq!(read::<4>(&mut writer).await?, *b"\0\x04\0\xaf");
        assert_eq!(
            read::<24>(&mut monitor).await?,
            *b"\0\x18\0\xad\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x05"
        );
        // A monitor cannot hold soft shutdown open after the last writer leaves.
        drop(writer);
        let (report, core, events) = tokio::time::timeout(Duration::from_secs(1), task).await???;
        eof(&mut monitor).await?;
        assert_eq!(report.requests, 5);
        assert_eq!(core.client_count(), 0);
        assert_eq!(core.watch_count(), 0);
        assert_eq!(core.persistent().count(), 1);
        assert!(
            events
                .iter()
                .any(|event| matches!(event.reason, CloseReason::Shutdown))
        );
        std::fs::remove_file(path)?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[test]
fn real_rust_client_and_literal_peer_get_watch_and_barrier()
-> Result<(), Box<dyn std::error::Error>> {
    runtime()?.block_on(async {
        let (path, stop, task) = start(Core::new(), limits())?;
        let mut watcher = UnixStream::connect(&path).await?;
        // Independent literal WATCH and barrier prove the watch was processed.
        watcher
            .write_all(b"\0\x0f\0\xaccore\0peers\0\0\x04\0\xae")
            .await?;
        assert_eq!(read::<4>(&mut watcher).await?, *b"\0\x04\0\xaf");
        let selector = Selector {
            subsystem: b"core",
            name: b"peers",
        };
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut writer = StatisticsClient::connect(&path, deadline).await?;
        writer
            .set_and_disconnect(
                Set {
                    selector,
                    flags: 2,
                    value: 9,
                },
                &mut [0; 128],
                deadline,
            )
            .await?;
        assert_eq!(
            read::<24>(&mut watcher).await?,
            *b"\0\x18\0\xad\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x09"
        );
        let mut reader = StatisticsClient::connect(&path, deadline).await?;
        let mut seen = None;
        assert_eq!(
            reader
                .get(selector, 1, &mut [0; 128], deadline, |value| {
                    seen = Some((value.uid(), value.value, value.persistent()));
                    Ok(())
                })
                .await?,
            1
        );
        assert_eq!(seen, Some((0, 9, true)));
        // DISCONNECT does not discard the watch or close the socket.
        watcher
            .write_all(b"\0\x04\0\xae\0\x0f\0\xa9core\0peers\0")
            .await?;
        assert_eq!(read::<4>(&mut watcher).await?, *b"\0\x04\0\xaf");
        let bytes = read::<27>(&mut watcher).await?;
        let Response::Value(value) = Response::decode(&bytes)? else {
            return Err(Error::InvalidInput.into());
        };
        assert_eq!(value.value, 9);
        assert_eq!(read::<4>(&mut watcher).await?, *b"\0\x04\0\xab");
        let mut writer = StatisticsClient::connect(&path, deadline).await?;
        writer
            .set_and_disconnect(
                Set {
                    selector,
                    flags: 0,
                    value: 10,
                },
                &mut [0; 128],
                deadline,
            )
            .await?;
        assert_eq!(
            read::<24>(&mut watcher).await?,
            *b"\0\x18\0\xad\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0a"
        );
        drop(stop);
        let (report, core, events) = task.await??;
        assert_eq!(report.requests, 9);
        assert_eq!(report.notifications, 2);
        assert_eq!(core.client_count(), 0);
        assert_eq!(core.watch_count(), 0);
        assert_eq!(core.notification_count_queued(), 0);
        assert_eq!(core.row_count(), 1);
        assert_eq!(events.len() as u64, report.closed);
        assert!(
            events
                .iter()
                .all(|event| !matches!(event.reason, CloseReason::Failure(_)))
        );
        std::fs::remove_file(path)?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[test]
fn malformed_oversized_and_partial_eof_close_only_their_session()
-> Result<(), Box<dyn std::error::Error>> {
    runtime()?.block_on(async {
            let (path, stop, task) = start(Core::new(), Limits { max_connections: 1, ..limits() })?;
            for bytes in [&b"\0\x03\0\xa9"[..], &b"\0\x81\0\xa9"[..], &b"\0\x0f"[..]] {
                let mut peer = UnixStream::connect(&path).await?;
                peer.write_all(bytes).await?;
                peer.shutdown().await?;
                eof(&mut peer).await?;
            }
            let mut healthy = UnixStream::connect(&path).await?;
            healthy.write_all(b"\0\x04\0\xae").await?;
            assert_eq!(read::<4>(&mut healthy).await?, *b"\0\x04\0\xaf");
            drop(healthy);
            drop(stop);
            let (report, core, events) = task.await??;
            assert_eq!(report.admitted, 4);
            assert_eq!(report.requests, 1);
            assert_eq!(core.client_count(), 0);
            for (event, expected) in events.iter().take(3).zip([Error::InvalidInput, Error::Capacity, Error::Truncated]) {
                assert!(matches!(&event.reason, CloseReason::Failure(IpcError::Protocol(error)) if *error == expected));
            }
            std::fs::remove_file(path)?;
            Ok::<(), Box<dyn std::error::Error>>(())
        })
}

#[test]
fn output_and_core_notification_overflow_have_real_close_outcomes()
-> Result<(), Box<dyn std::error::Error>> {
    runtime()?.block_on(async {
        let mut core = Core::new();
        let id = core.connect()?;
        core.set(
            id,
            Set {
                selector: Selector {
                    subsystem: b"core",
                    name: b"peers",
                },
                flags: 0,
                value: 9,
            },
        )?;
        core.disconnect(id)?;
        let (path, stop, task) = start(
            core,
            Limits {
                max_connections: 1,
                max_pending_bytes: 4,
                ..limits()
            },
        )?;
        for request in [b"\0\x0f\0\xaccore\0peers\0", b"\0\x0f\0\xa9core\0peers\0"] {
            let mut peer = UnixStream::connect(&path).await?;
            peer.write_all(request).await?;
            eof(&mut peer).await?;
        }
        let mut healthy = UnixStream::connect(&path).await?;
        healthy.write_all(b"\0\x04\0\xae").await?;
        assert_eq!(read::<4>(&mut healthy).await?, *b"\0\x04\0\xaf");
        drop(stop);
        let (_, core, events) = task.await??;
        assert_eq!(core.client_count(), 0);
        assert_eq!(core.watch_count(), 0);
        assert_eq!(core.notification_count_queued(), 0);
        assert!(events.iter().take(2).all(|event| matches!(
            event.reason,
            CloseReason::Failure(IpcError::Protocol(Error::Capacity))
        )));
        std::fs::remove_file(path)?;

        let core = Statistics::<8, 64, 4, 8, 0>::new();
        let (path, stop, task) = start(core, limits())?;
        let mut watcher = UnixStream::connect(&path).await?;
        watcher
            .write_all(b"\0\x0f\0\xaccore\0peers\0\0\x04\0\xae")
            .await?;
        assert_eq!(read::<4>(&mut watcher).await?, *b"\0\x04\0\xaf");
        let mut writer = UnixStream::connect(&path).await?;
        writer
            .write_all(b"\0\x1b\0\xa8\0\0\0\0\0\0\0\0\0\0\0\x09core\0peers\0")
            .await?;
        eof(&mut writer).await?;
        watcher.write_all(b"\0\x0f\0\xa9core\0peers\0").await?;
        let bytes = read::<27>(&mut watcher).await?;
        let Response::Value(value) = Response::decode(&bytes)? else {
            return Err(Error::InvalidInput.into());
        };
        assert_eq!(value.value, 0); // Rejected SET did not commit a value.
        assert_eq!(read::<4>(&mut watcher).await?, *b"\0\x04\0\xab");
        drop(stop);
        let (_, core, events) = task.await??;
        assert!(events.iter().any(|event| matches!(
            event.reason,
            CloseReason::Failure(IpcError::Protocol(Error::Capacity))
        )));
        assert_eq!(core.client_count(), 0);
        assert_eq!(core.watch_count(), 0);
        std::fs::remove_file(path)?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[test]
fn connection_limit_and_idle_deadline_release_real_ids() -> Result<(), Box<dyn std::error::Error>> {
    runtime()?.block_on(async {
        let (path, stop, task) = start(
            Core::new(),
            Limits {
                max_connections: 1,
                idle_timeout: Duration::from_millis(50),
                ..limits()
            },
        )?;
        let mut first = UnixStream::connect(&path).await?;
        first.write_all(b"\0\x04\0\xae").await?;
        assert_eq!(read::<4>(&mut first).await?, *b"\0\x04\0\xaf");
        let mut excess = UnixStream::connect(&path).await?;
        eof(&mut excess).await?;
        eof(&mut first).await?;
        let mut replacement = UnixStream::connect(&path).await?;
        replacement.write_all(b"\0\x04\0\xae").await?;
        assert_eq!(read::<4>(&mut replacement).await?, *b"\0\x04\0\xaf");
        drop(stop);
        let (report, core, events) = task.await??;
        assert_eq!(report.accepted, 3);
        assert_eq!(report.admitted, 2);
        assert_eq!(report.rejected, 1);
        assert_eq!(core.client_count(), 0);
        assert!(events.iter().any(|event| event.client.is_none()
            && matches!(
                event.reason,
                CloseReason::Failure(IpcError::Protocol(Error::Capacity))
            )));
        assert!(
            events
                .iter()
                .any(|event| matches!(event.reason, CloseReason::IdleTimeout))
        );
        std::fs::remove_file(path)?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[test]
fn cancelling_the_server_future_releases_watches_and_partial_sessions()
-> Result<(), Box<dyn std::error::Error>> {
    runtime()?.block_on(async {
        let path = path();
        let listener = UnixListener::bind(&path)?;
        let mut core = Core::new();
        let peer_path = path.clone();
        let peer = tokio::spawn(async move {
            let mut watcher = UnixStream::connect(&peer_path).await?;
            watcher
                .write_all(b"\0\x0f\0\xaccore\0peers\0\0\x04\0\xae")
                .await?;
            let mut ack = [0; 4];
            watcher.read_exact(&mut ack).await?;
            assert_eq!(&ack, b"\0\x04\0\xaf");
            let mut partial = UnixStream::connect(&peer_path).await?;
            partial.write_all(b"\0\x0f").await?;
            let mut byte = [0; 1];
            assert_eq!(watcher.read(&mut byte).await?, 0);
            assert_eq!(partial.read(&mut byte).await?, 0);
            Ok::<(), io::Error>(())
        });
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                serve_statistics(
                    &listener,
                    &mut core,
                    limits(),
                    std::future::pending(),
                    |_| {}
                )
            )
            .await
            .is_err()
        );
        peer.await??;
        assert_eq!(core.client_count(), 0);
        assert_eq!(core.watch_count(), 0);
        assert_eq!(core.notification_count_queued(), 0);
        assert_eq!(core.row_count(), 1);
        std::fs::remove_file(path)?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[test]
fn real_watch_client_keeps_id_one_after_cancelling_zero() -> Result<(), Box<dyn std::error::Error>>
{
    runtime()?.block_on(async {
        let old = Selector {
            subsystem: b"core",
            name: b"old",
        };
        let new = Selector {
            subsystem: b"core",
            name: b"new",
        };
        let mut core = Core::new();
        let temporary = core.connect()?;
        core.set(
            temporary,
            Set {
                selector: old,
                flags: 0,
                value: 1,
            },
        )?;
        core.disconnect(temporary)?;
        let (path, stop, task) = start(core, limits())?;
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut statistics_instance_1 = gnunet_client::statistics_handle::Instance::new();
        let mut watcher =
            StatisticsWatchClient::<'_, 2>::connect(&mut statistics_instance_1, &path, deadline)
                .await?;
        let mut scratch = [0; 128];
        let cancelled = watcher.watch(old, &mut scratch, deadline).await?;
        assert_eq!(cancelled.value(), 0);
        let initial = watcher.next(&mut scratch, deadline).await?;
        assert_eq!(initial.id, cancelled);
        assert_eq!(initial.notification.value, 1);
        watcher.cancel(cancelled)?;
        let active = watcher.watch(new, &mut scratch, deadline).await?;
        assert_eq!(active.value(), 1);
        // A real update of cancelled WID 0 must be consumed without
        // becoming an active subscription callback.
        for (selector, value, flags) in [(old, 9, 0), (new, 17, 2)] {
            let mut writer = StatisticsClient::connect(&path, deadline).await?;
            writer
                .set_and_disconnect(
                    Set {
                        selector,
                        flags,
                        value,
                    },
                    &mut scratch,
                    deadline,
                )
                .await?;
        }
        let update = watcher.next(&mut scratch, deadline).await?;
        assert_eq!(update.id, active);
        assert_eq!(update.selector, new);
        assert_eq!(update.notification.value, 17);
        assert!(update.notification.persistent());
        watcher.close();
        assert!(watcher.is_closed());
        assert!(matches!(watcher.cancel(active), Err(IpcError::Closed)));
        // A separate GET makes the host process the watch socket's actual
        // EOF before shutdown, so resource cleanup is observed independently.
        let mut reader = StatisticsClient::connect(&path, deadline).await?;
        assert_eq!(
            reader
                .get(
                    Selector {
                        subsystem: b"",
                        name: b""
                    },
                    2,
                    &mut scratch,
                    deadline,
                    |_| Ok(())
                )
                .await?,
            2
        );
        drop(stop);
        let (report, core, events) = task.await??;
        assert_eq!(report.notifications, 3);
        assert_eq!(core.client_count(), 0);
        assert_eq!(core.watch_count(), 0);
        assert_eq!(core.notification_count_queued(), 0);
        assert!(events.iter().any(|event| {
            event.client.is_some_and(|id| id.resource_id().index == 0)
                && matches!(event.reason, CloseReason::Eof)
        }));
        std::fs::remove_file(path)?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[test]
fn overflowing_one_watch_queue_does_not_consume_another_clients_effects()
-> Result<(), Box<dyn std::error::Error>> {
    runtime()?.block_on(async {
        let (path, stop, task) = start(
            Core::new(),
            Limits {
                max_pending_bytes: 24,
                ..limits()
            },
        )?;
        let mut overflowing = UnixStream::connect(&path).await?;
        overflowing
            .write_all(b"\0\x0f\0\xaccore\0peers\0\0\x0f\0\xaccore\0peers\0\0\x04\0\xae")
            .await?;
        assert_eq!(read::<4>(&mut overflowing).await?, *b"\0\x04\0\xaf");
        let mut healthy = UnixStream::connect(&path).await?;
        healthy
            .write_all(b"\0\x0f\0\xaccore\0peers\0\0\x04\0\xae")
            .await?;
        assert_eq!(read::<4>(&mut healthy).await?, *b"\0\x04\0\xaf");
        let deadline = Instant::now() + Duration::from_secs(2);
        let selector = Selector {
            subsystem: b"core",
            name: b"peers",
        };
        let mut writer = StatisticsClient::connect(&path, deadline).await?;
        writer
            .set_and_disconnect(
                Set {
                    selector,
                    flags: 0,
                    value: 1,
                },
                &mut [0; 128],
                deadline,
            )
            .await?;
        eof(&mut overflowing).await?;
        assert_eq!(
            read::<24>(&mut healthy).await?,
            *b"\0\x18\0\xad\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01"
        );
        let mut writer = StatisticsClient::connect(&path, deadline).await?;
        writer
            .set_and_disconnect(
                Set {
                    selector,
                    flags: 0,
                    value: 2,
                },
                &mut [0; 128],
                deadline,
            )
            .await?;
        assert_eq!(
            read::<24>(&mut healthy).await?,
            *b"\0\x18\0\xad\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x02"
        );
        drop(stop);
        let (_, core, events) = task.await??;
        assert_eq!(core.client_count(), 0);
        assert_eq!(core.watch_count(), 0);
        assert_eq!(core.notification_count_queued(), 0);
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(
                    event.reason,
                    CloseReason::Failure(IpcError::Protocol(Error::Capacity))
                ))
                .count(),
            1
        );
        std::fs::remove_file(path)?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
