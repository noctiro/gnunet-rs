//! Native local/TCP wire behavior and original-source retirement on every host.
#![cfg(any(unix, windows))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Real transport regressions assert independent wire and lifetime outcomes while propagating setup and I/O errors"
)]
use gnunet_client::statistics::{self, SET_PERSISTENT, Selector, Set};
use gnunet_client::statistics_handle::{DestroyOutcome, GetFlow};
use gnunet_ipc_unix::{
    IpcError, StatisticsClient, StatisticsWatchClient,
    handle::{Event, Limits as HandleLimits, StatisticsHandle},
    server::{self, Listener, ServeContext, ServiceOptions},
};
use gnunet_service_runtime::{BoundListeners, LocalListenerAccess};
use gnunet_statistics::Statistics;
use std::{
    error::Error,
    fs,
    future::{Future, poll_fn},
    io,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
    task::Poll,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::{Instant, timeout_at},
};
type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;
type Core = Statistics<8, 64, 4, 8, 16>;
const SELECTOR: Selector<'static> = Selector {
    subsystem: b"native",
    name: b"visits",
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "gn-ipc-{}-{nonce:x}-{:x}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
fn run(work: impl Future<Output = Result>) -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async { timeout_at(deadline(), work).await? })
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(15)
}
fn limits() -> server::Limits {
    server::Limits {
        max_connections: 4,
        max_frame_bytes: 256,
        max_pending_bytes: 1024,
        idle_timeout: Duration::MAX,
    }
}
async fn local(path: &Path) -> Result<BoundListeners> {
    let mut config = gnunet_config::Configuration::default();
    config.set_value(
        b"statistics",
        b"UNIXPATH",
        Some(gnunet_native::os_bytes::encode(path.as_os_str()).as_ref()),
    )?;
    config.set_number(b"statistics", b"PORT", 0)?;
    BoundListeners::bind_configured(&config, b"statistics", LocalListenerAccess::Owner).await
}
fn close(bound: &mut BoundListeners) -> io::Result<()> {
    bound
        .close()
        .map_err(|errors| io::Error::other(format!("{errors:?}")))
}
async fn frame(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    timeout_at(deadline(), stream.read_exact(&mut header)).await??;
    let size = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if !(4..=256).contains(&size) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut bytes = vec![0; size];
    bytes[..4].copy_from_slice(&header);
    timeout_at(deadline(), stream.read_exact(&mut bytes[4..])).await??;
    Ok(bytes)
}
async fn retired(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<()> {
    match timeout_at(deadline(), stream.read(&mut [0])).await? {
        Ok(0) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
            ) =>
        {
            Ok(())
        }
        other => Err(io::Error::other(format!(
            "original retired stream remained usable: {other:?}"
        ))),
    }
}
struct Host {
    path: PathBuf,
    address: SocketAddr,
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<std::result::Result<(server::Report, usize), IpcError>>,
}
async fn host(path: &Path) -> Result<Host> {
    let mut bound = local(path).await?;
    let path = bound
        .unix_paths()
        .next()
        .ok_or("missing actual local listener path")?
        .to_owned();
    let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = tcp.local_addr()?;
    let (stop, stopped) = oneshot::channel();
    let (ready, initialized) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut core = Core::new();
        let mut listeners = bound.listeners();
        listeners.push(Listener::Tcp(&tcp));
        let report = server::serve_statistics_controlled_with_async_ready(
            &listeners,
            &mut core,
            limits(),
            ServeContext {
                options: &ServiceOptions::default(),
                unix_access: Default::default(),
                clock: None,
                shutdown_grace: None,
            },
            async {
                let _request = stopped.await;
            },
            || async {
                ready
                    .send(())
                    .map_err(|_| IpcError::Io(io::Error::other("ready observer closed")))
            },
            |_| {},
        )
        .await?;
        drop(listeners);
        close(&mut bound)?;
        Ok((report, core.client_count()))
    });
    initialized.await?;
    Ok(Host {
        path,
        address,
        stop,
        task,
    })
}

#[test]
fn local_and_tcp_share_values_watches_and_processing_barriers() -> Result {
    run(async {
        let directory = Directory::new()?;
        let host = host(&directory.0.join("ipc")).await?;
        let mut instance = statistics::Instance::new();
        let mut watch =
            StatisticsWatchClient::<4>::connect(&mut instance, &host.path, deadline()).await?;
        let mut scratch = [0; 256];
        watch.watch(SELECTOR, &mut scratch, deadline()).await?;
        let mut tcp = TcpStream::connect(host.address).await?;
        let length = Set {
            selector: SELECTOR,
            flags: SET_PERSISTENT,
            value: 7,
        }
        .encode(&mut scratch)?;
        tcp.write_all(&scratch[..length]).await?;
        let length = statistics::encode_disconnect(&mut scratch)?;
        tcp.write_all(&scratch[..length]).await?;
        statistics::confirm_disconnect(&frame(&mut tcp).await?)?;
        let notification = watch.next(&mut scratch, deadline()).await?.notification;
        assert_eq!(notification.value, 7);
        assert!(notification.persistent());
        let mut getter = StatisticsClient::connect(&host.path, deadline()).await?;
        let mut values = Vec::new();
        assert_eq!(
            getter
                .get(SELECTOR, 4, &mut scratch, deadline(), |value| {
                    values.push(value.value);
                    Ok(())
                })
                .await?,
            1
        );
        assert_eq!(values, [7]);
        // One malformed native peer must not poison the shared core or a healthy
        // connection. A reset and EOF are distinct permitted close observations.
        let mut malformed = TcpStream::connect(host.address).await?;
        malformed.write_all(&[0, 3, 0, 0]).await?;
        retired(&mut malformed).await?;
        values.clear();
        getter
            .get(SELECTOR, 4, &mut scratch, deadline(), |value| {
                values.push(value.value);
                Ok(())
            })
            .await?;
        assert_eq!(values, [7]);
        host.stop
            .send(())
            .map_err(|_| "host stop owner disappeared")?;
        let (report, clients) = host.task.await??;
        assert_eq!(clients, 0);
        assert_eq!(report.admitted, report.closed);
        retired(&mut tcp).await?;
        Ok(())
    })
}

#[test]
fn canceled_partial_local_reply_retires_only_the_original_client() -> Result {
    run(async {
        let directory = Directory::new()?;
        let mut bound = local(&directory.0.join("ipc")).await?;
        let path = bound
            .unix_paths()
            .next()
            .ok_or("missing actual local path")?
            .to_owned();
        let (partial, submitted) = oneshot::channel();
        let peer = tokio::spawn(async move {
            let listeners = bound.listeners();
            let Some(Listener::Unix(listener)) = listeners.first() else {
                return Err(io::ErrorKind::InvalidData.into());
            };
            let (mut stream, _) = listener.accept().await?;
            frame(&mut stream).await?;
            stream.write_all(&[0, 4]).await?;
            partial
                .send(())
                .map_err(|_| io::Error::other("partial observer closed"))?;
            retired(&mut stream).await?;
            drop(listeners);
            close(&mut bound)
        });
        let mut client = StatisticsClient::connect(&path, deadline()).await?;
        let mut scratch = [0; 256];
        {
            let mut getting =
                std::pin::pin!(client.get(SELECTOR, 4, &mut scratch, deadline(), |_| Ok(())));
            let mut submitted = std::pin::pin!(submitted);
            poll_fn(|cx| {
                if let Poll::Ready(outcome) = getting.as_mut().poll(cx) {
                    return Poll::Ready(Err(io::Error::other(format!(
                        "partial reply unexpectedly completed: {outcome:?}"
                    ))));
                }
                submitted
                    .as_mut()
                    .poll(cx)
                    .map(|result| result.map_err(io::Error::other))
            })
            .await?;
        }
        assert!(client.is_closed());
        assert!(matches!(
            client
                .get(SELECTOR, 4, &mut scratch, deadline(), |_| Ok(()))
                .await,
            Err(IpcError::Closed)
        ));
        peer.await??;
        Ok(())
    })
}

#[test]
fn asynchronous_ready_failure_restores_original_core_accounting() -> Result {
    run(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let mut peer = TcpStream::connect(listener.local_addr()?).await?;
        let mut core = Core::new();
        core.set_external_retained_bytes(17)?;
        let result = server::serve_statistics_controlled_with_async_ready(
            &[Listener::Tcp(&listener)],
            &mut core,
            limits(),
            ServeContext {
                options: &ServiceOptions::default(),
                unix_access: Default::default(),
                clock: None,
                shutdown_grace: None,
            },
            std::future::pending(),
            || async {
                Err(IpcError::Io(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "ready publication refused",
                )))
            },
            |_| {},
        )
        .await;
        assert!(
            matches!(result, Err(IpcError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied)
        );
        assert_eq!(core.client_count(), 0);
        assert_eq!(core.external_retained_bytes(), 17);
        drop(listener);
        retired(&mut peer).await?;
        Ok(())
    })
}

#[test]
fn lazy_handle_preserves_callbacks_and_actual_destroy_barrier() -> Result {
    run(async {
        let directory = Directory::new()?;
        let host = host(&directory.0.join("ipc")).await?;
        let mut instance = statistics::Instance::new();
        let mut handle = StatisticsHandle::<16, 128, 4, 8, 4>::new(
            &mut instance,
            &host.path,
            b"native",
            true,
            HandleLimits {
                max_frame_bytes: 256,
                write_chunk_bytes: 1,
            },
        )?
        .ok_or("enabled owner missing")?;
        assert!(handle.connection_epoch().is_none());
        handle.set(b"visits", 29, true)?;
        let watch = handle.watch(SELECTOR)?;
        let get = handle.get(SELECTOR)?;
        let (mut row, mut completed, mut notified) = (None, false, false);
        while row.is_none() || !completed || !notified {
            handle
                .drive(Some(deadline()), |event, _| {
                    match event {
                        Event::GetValue {
                            get: original,
                            statistic,
                        } => {
                            assert_eq!(original, get);
                            row = Some((statistic.value, statistic.persistent()));
                        }
                        Event::GetComplete(completion) => {
                            assert_eq!(completion.get, get);
                            assert!(completion.result.is_ok());
                            completed = true;
                        }
                        Event::WatchValue {
                            watch: original,
                            notification,
                            ..
                        } => {
                            assert_eq!(original, watch);
                            assert_eq!(notification.value, 29);
                            notified = true;
                        }
                        _ => {}
                    }
                    GetFlow::Continue
                })
                .await?;
        }
        assert_eq!(row, Some((29, true)));
        handle.watch_cancel(watch)?;
        // The official sync-first branch requires nontransmitted MQ work.
        // Do not confuse closing an empty queue with receiving a confirmation.
        handle.set(b"visits", 31, true)?;
        handle.destroy(true)?;
        let mut destroyed = None;
        while destroyed.is_none() {
            handle
                .drive(Some(deadline()), |event, _| {
                    if let Event::Destroyed(report) = event {
                        destroyed = Some(report);
                    }
                    GetFlow::Continue
                })
                .await?;
        }
        let destroyed = destroyed.ok_or("missing original destruction report")?;
        assert_eq!(destroyed.outcome, DestroyOutcome::ProcessingConfirmed);
        assert_eq!(destroyed.queued_mutations_discarded, 0, "{destroyed:?}");
        assert_eq!(destroyed.unconfirmed_mutations, 0, "{destroyed:?}");
        assert_eq!(
            destroyed.unconfirmed_persistent_mutations, 0,
            "{destroyed:?}"
        );
        assert!(handle.is_closed());
        let mut getter = StatisticsClient::connect(&host.path, deadline()).await?;
        let mut scratch = [0; 256];
        let mut rows = Vec::new();
        getter
            .get(SELECTOR, 4, &mut scratch, deadline(), |row| {
                rows.push(row.value);
                Ok(())
            })
            .await?;
        assert_eq!(rows, [31]);
        host.stop
            .send(())
            .map_err(|_| "host stop owner disappeared")?;
        let (report, clients) = host.task.await??;
        assert_eq!(clients, 0);
        assert_eq!(report.admitted, report.closed);
        Ok(())
    })
}
