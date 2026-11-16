//! Actual private backlog observations without accepting or consuming a connection.
#![cfg(any(unix, windows))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Regressions compare actual native readiness with the original separately accepted backlog bytes"
)]
use gnunet_service_runtime::readiness::RegisteredListener;
use socket2::{Domain, Protocol, SockAddr, SockRef, Socket, Type};
use std::{
    future::poll_fn,
    io,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
type Result = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn canceled_registration_and_repeated_readiness_preserve_the_original_accept_queue() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
            socket.bind(&SockAddr::from(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))))?;
            socket.listen(4)?;
            let address = socket
                .local_addr()?
                .as_socket()
                .ok_or("missing actual bind address")?;
            let registered = RegisteredListener::new(socket)?;
            assert_eq!(
                registered.level().err().map(|error| error.kind()),
                Some(io::ErrorKind::WouldBlock)
            );
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(5),
                    poll_fn(|cx| registered.poll_ready(cx))
                )
                .await
                .is_err()
            );
            for _ in 0..2 {
                let mut peer = tokio::net::TcpStream::connect(address).await?;
                let observed = tokio::time::timeout(
                    Duration::from_secs(2),
                    poll_fn(|cx| registered.poll_ready(cx)),
                )
                .await??;
                assert!(observed.readable);
                assert!(!observed.error);
                assert!(registered.level()?.readable);
                assert!(registered.level()?.readable);
                peer.write_all(b"queue").await?;
                // Only this explicit operation consumes one pending connection.
                let (accepted, _) = SockRef::from(&registered).accept()?;
                accepted.set_nonblocking(true)?;
                let accepted: std::net::TcpStream = accepted.into();
                let mut accepted = tokio::net::TcpStream::from_std(accepted)?;
                let mut bytes = [0; 5];
                tokio::time::timeout(Duration::from_secs(2), accepted.read_exact(&mut bytes))
                    .await??;
                assert_eq!(&bytes, b"queue");
                assert_eq!(
                    registered.level().err().map(|error| error.kind()),
                    Some(io::ErrorKind::WouldBlock)
                );
                // A stale reactor hint after the accept must be cleared and rearmed.
                assert!(
                    tokio::time::timeout(
                        Duration::from_millis(5),
                        poll_fn(|cx| registered.poll_ready(cx))
                    )
                    .await
                    .is_err()
                );
            }
            Ok(())
        })
}

#[test]
fn datagrams_are_refused_before_registration() -> Result {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let _entered = runtime.enter();
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    let error = RegisteredListener::new(socket)
        .err()
        .ok_or("datagram admitted as a managed stream listener")?;
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    let error = RegisteredListener::new(socket)
        .err()
        .ok_or("unlistening stream admitted as a managed listener")?;
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    Ok(())
}
