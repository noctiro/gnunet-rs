//! Real Windows AF_UNIX readiness, original connection ownership and admission limits.
#![cfg(windows)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Native fixtures assert independent byte/lifetime properties while setup and cleanup errors remain fallible"
)]
use gnunet_service_runtime::BoundListeners;
use gnunet_service_runtime::LocalListenerAccess;
use gnunet_service_runtime::{
    credentials::UnixAccess,
    local::{Listener, Stream},
    service::{Listener as ServiceListener, PeerAddress},
};
use socket2::{Domain, SockAddr, Socket, Type};
use std::{
    fs,
    future::{Future, poll_fn},
    io,
    net::{Ipv4Addr, SocketAddr},
    os::windows::io::{AsRawSocket, AsSocket},
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    task::Poll,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
static NEXT: AtomicUsize = AtomicUsize::new(0);

fn missing(path: &std::path::Path) -> io::Result<bool> {
    match gnunet_native::local_path::is_socket(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error),
    }
}

fn configuration(
    path: &std::path::Path,
) -> Result<gnunet_config::Configuration, Box<dyn std::error::Error>> {
    let mut config = gnunet_config::Configuration::default();
    config.set_value(
        b"local",
        b"UNIXPATH",
        Some(gnunet_native::os_bytes::encode(path.as_os_str()).as_ref()),
    )?;
    config.set_number(b"local", b"PORT", 0)?;
    Ok(config)
}

#[tokio::test]
async fn configured_listener_preserves_live_node_and_reclaims_stale_node()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let socket = fixture.bound()?;
    let config = configuration(&fixture.socket)?;
    drop(gnunet_native::local_path::LocalPath::inspect(
        fixture.socket.clone(),
    )?);
    assert!(
        BoundListeners::bind_configured(&config, b"local", LocalListenerAccess::Owner)
            .await
            .is_err()
    );
    assert!(gnunet_native::local_path::is_socket(&fixture.socket)?);
    drop(Stream::connect(&fixture.socket).await?);
    drop(socket);
    let mut bound =
        BoundListeners::bind_configured(&config, b"local", LocalListenerAccess::Owner).await?;
    assert_eq!(
        bound.unix_paths().collect::<Vec<_>>(),
        vec![fixture.socket.as_path()]
    );
    assert!(bound.failures().is_empty());
    drop(Stream::connect(&fixture.socket).await?);
    bound
        .close()
        .map_err(|errors| io::Error::other(format!("{errors:?}")))?;
    assert!(missing(&fixture.socket)?);
    Ok(())
}

#[tokio::test]
async fn configured_cleanup_failure_retains_original_node_for_retry()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::windows::fs::OpenOptionsExt;
    let fixture = Fixture::new()?;
    let config = configuration(&fixture.socket)?;
    let mut bound =
        BoundListeners::bind_configured(&config, b"local", LocalListenerAccess::Owner).await?;
    // READ_CONTROL, sharing read/write but not delete, and OPEN_REPARSE_POINT:
    // deliberately deny a concurrent DELETE reopen of this original node.
    let blocker = fs::OpenOptions::new()
        .access_mode(0x0002_0000)
        .share_mode(3)
        .custom_flags(0x0020_0000)
        .open(&fixture.socket)?;
    let errors = bound
        .close()
        .err()
        .ok_or_else(|| io::Error::other("sharing denial must be observable"))?;
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].raw_os_error(), Some(32));
    assert!(bound.listeners().is_empty());
    assert_eq!(bound.unix_paths().count(), 1);
    drop(blocker);
    bound
        .close()
        .map_err(|errors| io::Error::other(format!("{errors:?}")))?;
    assert_eq!(bound.unix_paths().count(), 0);
    assert!(missing(&fixture.socket)?);
    Ok(())
}

#[tokio::test]
async fn configured_regular_file_is_never_reclaimed() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    fs::write(&fixture.socket, b"foreign node")?;
    let config = configuration(&fixture.socket)?;
    assert!(
        BoundListeners::bind_configured(&config, b"local", LocalListenerAccess::Owner)
            .await
            .is_err()
    );
    assert_eq!(fs::read(&fixture.socket)?, b"foreign node");
    Ok(())
}

#[test]
fn original_node_cleanup_leaves_replacement_untouched() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let socket = fixture.bound()?;
    let mut node = gnunet_native::local_path::LocalPath::capture(fixture.socket.clone())?;
    drop(socket);
    let old = fixture.directory.join("renamed.sock");
    fs::rename(&fixture.socket, &old)?;
    fs::write(&fixture.socket, b"replacement")?;
    node.remove()?;
    assert_eq!(fs::read(&fixture.socket)?, b"replacement");
    assert!(missing(&old)?);
    Ok(())
}
struct Fixture {
    directory: PathBuf,
    socket: PathBuf,
}
impl Fixture {
    fn new() -> io::Result<Self> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "gu-{:x}-{nonce:x}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory)?;
        Ok(Self {
            socket: directory.join("é.sock"),
            directory,
        })
    }
    fn bound(&self) -> io::Result<Socket> {
        let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        socket.bind(&SockAddr::unix(&self.socket)?)?;
        socket.listen(5)?;
        Ok(socket)
    }
    fn remove(&self) -> io::Result<()> {
        match fs::remove_file(&self.socket) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        fs::remove_dir(&self.directory)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _cleanup = self.remove();
    }
}
#[tokio::test]
async fn original_local_stream_rearms_accept_and_read_and_preserves_eof() -> io::Result<()> {
    let fixture = Fixture::new()?;
    tokio::time::timeout(Duration::from_secs(10), async {
        let socket = fixture.bound()?;
        let original = socket.as_raw_socket();
        let listener = Listener::from_bound_socket(socket)?;
        assert_eq!(listener.as_socket().as_raw_socket(), original);
        let native = ServiceListener::Unix(&listener);
        // Both polls must register an actual wait before any client exists.
        for _ in 0..2 {
            poll_fn(|cx| match native.poll_canonical_connection(cx) {
                Poll::Pending => Poll::Ready(Ok(())),
                Poll::Ready(_) => Poll::Ready(Err(io::Error::other("empty accept did not wait"))),
            })
            .await?;
        }
        for _ in 0..2 {
            let (client, accepted) = tokio::join!(
                Stream::connect(&fixture.socket),
                poll_fn(|cx| native.poll_canonical_connection(cx))
            );
            let mut client = client?;
            let accepted = accepted.map_err(io::Error::other)?;
            assert_eq!(accepted.peer(), PeerAddress::Unix);
            assert!(accepted.diagnostics().tcp_no_delay().is_none());
            let (mut server, _, _) = accepted.into_parts();
            assert!(server.is_unix());
            assert_eq!(server.unix_peer_process_id()?, Some(std::process::id()));
            assert_eq!(
                gnunet_native::local_socket::peer_process_id(client.as_socket())?,
                std::process::id()
            );
            assert!(
                UnixAccess {
                    match_uid: true,
                    match_gid: false
                }
                .allows(&server)
                .is_err()
            );
            assert!(UnixAccess::default().allows(&server)?);
            let mut bytes = [0u8; 6];
            let mut read = std::pin::pin!(server.read_exact(&mut bytes));
            poll_fn(|cx| match read.as_mut().poll(cx) {
                Poll::Pending => Poll::Ready(Ok(())),
                Poll::Ready(_) => Poll::Ready(Err(io::Error::other("empty read did not wait"))),
            })
            .await?;
            client.write_all(b"first!").await?;
            read.await?;
            assert_eq!(&bytes, b"first!");
            server.write_all(b"ack").await?;
            let mut ack = [0; 3];
            client.read_exact(&mut ack).await?;
            assert_eq!(&ack, b"ack");
            // A second read occurs after readiness was consumed and cleared.
            let mut second = [0u8; 6];
            let mut read = std::pin::pin!(server.read_exact(&mut second));
            poll_fn(|cx| match read.as_mut().poll(cx) {
                Poll::Pending => Poll::Ready(Ok(())),
                Poll::Ready(_) => {
                    Poll::Ready(Err(io::Error::other("second empty read did not wait")))
                }
            })
            .await?;
            client.write_all(b"second").await?;
            read.await?;
            assert_eq!(&second, b"second");
            client.shutdown().await?;
            let mut eof = [0u8; 1];
            assert_eq!(server.read(&mut eof).await?, 0);
        }
        drop(listener);
        Ok::<_, io::Error>(())
    })
    .await
    .map_err(io::Error::other)??;
    fixture.remove()?;
    Ok(())
}
#[test]
fn registration_without_runtime_reports_error_and_retains_caller_path_cleanup() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let socket = fixture.bound()?;
    let error = Listener::from_bound_socket(socket)
        .err()
        .ok_or_else(|| io::Error::other("registration without runtime succeeded"))?;
    assert_eq!(error.kind(), io::ErrorKind::Other);
    assert!(fs::symlink_metadata(&fixture.socket).is_ok());
    fixture.remove()?;
    Ok(())
}
#[tokio::test]
async fn invalid_paths_and_ip_socket_adoption_are_explicit_errors() -> io::Result<()> {
    for name in ["", "a\0b", &"x".repeat(108)] {
        assert_eq!(
            Stream::connect(name).await.err().map(|error| error.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
    }
    let tcp = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    tcp.bind(&SockAddr::from(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))))?;
    tcp.listen(1)?;
    assert!(Listener::from_bound_socket(tcp).is_err());
    Ok(())
}
