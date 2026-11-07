//! Real mixed Unix/TCP admission, notification, framing and shutdown behavior.
#![cfg(unix)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible real-socket tests assert actual admission and protocol outcomes"
)]
use gnunet_client::statistics::{Selector, Set, WatchValue};
use gnunet_ipc_unix::{
    StatisticsClient,
    acl::AccessPolicy,
    server::{self, Listener, ServiceOptions},
};
use gnunet_statistics::Statistics;
use std::{error::Error, io, path::PathBuf, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixListener, UnixStream},
    time::Instant,
};
type Result<T> = std::result::Result<T, Box<dyn Error>>;
type Core = Statistics<8, 64, 4, 8, 16>;
fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
fn limits() -> server::Limits {
    server::Limits {
        max_connections: 4,
        max_frame_bytes: 256,
        max_pending_bytes: 1024,
        idle_timeout: Duration::MAX,
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}
struct Path(PathBuf);
impl Path {
    fn new() -> io::Result<Self> {
        let dir = std::env::temp_dir().join(format!("gnunet-mixed-server-{}", std::process::id()));
        std::fs::create_dir(&dir)?;
        Ok(Self(dir))
    }
    fn socket(&self) -> PathBuf {
        self.0.join("s")
    }
}
impl Drop for Path {
    fn drop(&mut self) {
        match std::fs::remove_dir_all(&self.0) {
            Ok(()) | Err(_) => {}
        }
    }
}
async fn receive(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut header)).await??;
    let len = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if !(4..=65535).contains(&len) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut out = vec![0; len];
    out[..4].copy_from_slice(&header);
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut out[4..])).await??;
    Ok(out)
}
#[test]
fn unix_and_tcp_share_one_core_and_acl_rejection_does_not_consume_an_id() -> Result<()> {
    runtime()?.block_on(async {
        let path = Path::new()?;
        let unix = UnixListener::bind(path.socket())?;
        let tcp = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let address = tcp.local_addr()?;
        let (mut stop, mut trigger) = UnixStream::pair()?;
        let (mut ready, mut ready_rx) = UnixStream::pair()?;
        let mut config = gnunet_config::Configuration::new(Default::default());
        config.set_value(b"s", b"ACCEPT_FROM", Some(b"127.0.0.0/8;"))?;
        let policy = ServiceOptions {
            access: AccessPolicy::from_config(&config, b"s")?,
            ..ServiceOptions::default()
        };
        let server = tokio::spawn(async move {
            let mut core = Core::new();
            let mut closed = Vec::new();
            ready.write_all(b"r").await?;
            let report = server::serve_statistics_on(
                &[Listener::Unix(&unix), Listener::Tcp(&tcp)],
                &mut core,
                limits(),
                &policy,
                async {
                    let mut b = [0];
                    match stop.read_exact(&mut b).await {
                        Ok(_) | Err(_) => {}
                    }
                },
                |e| {
                    if let server::ServiceEvent::Closed(e) = e {
                        closed.push(e);
                    }
                },
            )
            .await?;
            Ok::<_, gnunet_ipc_unix::IpcError>((report, core.client_count(), closed))
        });
        ready_rx.read_exact(&mut [0]).await?;
        let mut watcher = TcpStream::connect(address).await?;
        // Independent literal WATCH(s,n), before the value exists.
        watcher
            .write_all(&[0, 8, 0, 0xac, b's', 0, b'n', 0])
            .await?;
        // GET on the same stream is a processing barrier for registration.
        watcher
            .write_all(&[0, 8, 0, 0xa9, b's', 0, b'n', 0])
            .await?;
        // WATCH creates an uninitialized zero row, visible to GET, without an
        // initial WATCH_VALUE. This is the official service's distinct behavior.
        assert_eq!(
            receive(&mut watcher).await?,
            [
                0, 20, 0, 170, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, b's', 0, b'n', 0
            ]
        );
        assert_eq!(receive(&mut watcher).await?, [0, 4, 0, 0xab]);
        let mut setter = StatisticsClient::connect(&path.socket(), deadline()).await?;
        let mut scratch = [0; 256];
        setter
            .set_and_disconnect(
                Set {
                    selector: Selector {
                        subsystem: b"s",
                        name: b"n",
                    },
                    flags: 0,
                    value: 77,
                },
                &mut scratch,
                deadline(),
            )
            .await?;
        let value = receive(&mut watcher).await?;
        assert_eq!(WatchValue::decode(&value)?.value, 77);
        drop(setter);
        drop(watcher);
        trigger.write_all(b"x").await?;
        let (report, clients, _) = server.await??;
        assert_eq!(report.admitted, 2);
        assert_eq!(report.rejected, 0);
        assert_eq!(report.notifications, 1);
        assert_eq!(clients, 0);
        Ok(())
    })
}
#[test]
fn denied_tcp_peer_and_tolerant_unknown_frame_have_explicit_separate_outcomes() -> Result<()> {
    runtime()?.block_on(async {
        for denied in [true, false] {
            let tcp = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let address = tcp.local_addr()?;
            let mut config = gnunet_config::Configuration::new(Default::default());
            config.set_value(
                b"s",
                b"ACCEPT_FROM",
                Some(if denied { b"192.0.2.1;" } else { b"127.0.0.1;" }),
            )?;
            let options = ServiceOptions {
                access: AccessPolicy::from_config(&config, b"s")?,
                tolerant: true,
                ..ServiceOptions::default()
            };
            let (mut stop, mut trigger) = UnixStream::pair()?;
            let task = tokio::spawn(async move {
                let mut core = Core::new();
                let mut outcomes = Vec::new();
                let report = server::serve_statistics_on(
                    &[Listener::Tcp(&tcp)],
                    &mut core,
                    limits(),
                    &options,
                    async {
                        let mut b = [0];
                        match stop.read_exact(&mut b).await {
                            Ok(_) | Err(_) => {}
                        }
                    },
                    |e| {
                        if let server::ServiceEvent::Closed(e) = e {
                            outcomes.push(e);
                        }
                    },
                )
                .await?;
                Ok::<_, gnunet_ipc_unix::IpcError>((report, core.client_count(), outcomes))
            });
            let mut peer = TcpStream::connect(address).await?;
            if denied {
                let mut b = [0];
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(2), peer.read(&mut b)).await??,
                    0
                );
            } else {
                peer.write_all(&[0, 4, 0x7f, 0xff, 0, 4, 0, 0xae]).await?;
                assert_eq!(receive(&mut peer).await?, [0, 4, 0, 0xaf]);
            }
            drop(peer);
            trigger.write_all(b"x").await?;
            let (report, clients, outcomes) = task.await??;
            assert_eq!(clients, 0);
            assert_eq!(report.accepted, 1);
            assert_eq!(report.rejected, u64::from(denied));
            assert_eq!(report.admitted, u64::from(!denied));
            if denied {
                assert!(matches!(
                    outcomes[0].reason,
                    server::CloseReason::AccessDenied(_)
                ));
                assert!(outcomes[0].client.is_none());
            }
        }
        Ok(())
    })
}
