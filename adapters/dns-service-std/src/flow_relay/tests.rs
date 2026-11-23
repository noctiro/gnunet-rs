//! Ordinary loopback socket adapter and pure endpoint checks; no provider runs.
use super::{RelayLimits, TcpUpstream, same_endpoint};
use std::{
    future::poll_fn,
    io,
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    task::Poll,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    runtime::Builder,
    time::Instant,
};

#[test]
fn endpoint_matching_keeps_the_original_zone_and_ignores_flow_labels() {
    let address = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 53);
    let original = SocketAddr::V6(SocketAddrV6::new(address, 53, 1, 7));
    assert!(same_endpoint(
        original,
        SocketAddr::V6(SocketAddrV6::new(address, 53, 2, 7))
    ));
    assert!(!same_endpoint(
        original,
        SocketAddr::V6(SocketAddrV6::new(address, 53, 1, 8))
    ));
    assert!(!same_endpoint(
        original,
        SocketAddr::V6(SocketAddrV6::new(address, 53, 1, 0))
    ));
    assert!(!same_endpoint(
        original,
        SocketAddr::V6(SocketAddrV6::new(address, 54, 1, 7))
    ));
    assert!(
        RelayLimits {
            buffer_bytes: 0,
            ..RelayLimits::default()
        }
        .validate(Instant::now())
        .is_err()
    );
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Ordinary private TCP loopback verifies exact bytes and independent half-close, without constructing any native flow"
)]
fn socket_upstream_keeps_bytes_after_write_half_close_and_canceled_read_wait() -> io::Result<()> {
    Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let socket = TcpStream::connect(listener.local_addr()?).await?;
            let (mut peer, _) = listener.accept().await?;
            let mut upstream = TcpUpstream::socket(socket);
            let query = [0, 5, 0x12, 0x34, 0, 0xff, 0, 0, 2, 0xab, 0xcd];
            let mut written = 0;
            while written < query.len() {
                let count = poll_fn(|cx| upstream.poll_write(cx, &query[written..])).await?;
                assert!(count > 0);
                written += count;
            }
            poll_fn(|cx| upstream.poll_shutdown(cx)).await?;
            let mut accepted = Vec::new();
            peer.read_to_end(&mut accepted).await?;
            assert_eq!(accepted, query);

            let mut storage = [0; 3];
            let mut read_wait = Box::pin(poll_fn(|cx| {
                let mut buffer = ReadBuf::new(&mut storage);
                upstream.poll_read(cx, &mut buffer)
            }));
            assert!(
                std::future::Future::poll(
                    read_wait.as_mut(),
                    &mut std::task::Context::from_waker(std::task::Waker::noop())
                )
                .is_pending()
            );
            drop(read_wait);
            let response = [0, 4, 0x12, 0x34, 0x80, 0, 0, 1, 0xff];
            peer.write_all(&response).await?;
            peer.shutdown().await?;
            let mut received = Vec::new();
            loop {
                let count = poll_fn(|cx| {
                    let mut buffer = ReadBuf::new(&mut storage);
                    match upstream.poll_read(cx, &mut buffer) {
                        Poll::Ready(result) => Poll::Ready(result.map(|()| buffer.filled().len())),
                        Poll::Pending => Poll::Pending,
                    }
                })
                .await?;
                if count == 0 {
                    break;
                }
                received.extend_from_slice(&storage[..count]);
            }
            assert_eq!(received, response);
            upstream.close();
            assert!(poll_fn(|cx| upstream.poll_retirement(cx)).await.is_none());
            Ok(())
        })
}
