//! Pure peer qualification and explicit native UDP loopback integration.
use super::{Connection, qualify_udp_peer};
use std::{
    io,
    net::UdpSocket,
    sync::Arc,
    task::{Context, Poll, Wake, Waker},
    thread::{self, Thread},
    time::{Duration, Instant},
};

struct Notify(Thread);
impl Wake for Notify {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

fn wait<T>(
    until: Instant,
    mut poll: impl FnMut(&mut Context<'_>) -> Poll<io::Result<T>>,
) -> io::Result<T> {
    let waker = Waker::from(Arc::new(Notify(thread::current())));
    let mut cx = Context::from_waker(&waker);
    loop {
        if let Poll::Ready(result) = poll(&mut cx) {
            return result;
        }
        let remaining = until.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "native UDP callback or retirement deadline expired",
            ));
        }
        // An unpark between poll and park leaves a token, so a native callback
        // cannot lose its notification while this thread prepares to wait.
        thread::park_timeout(remaining);
    }
}

fn operation<T>(result: Option<io::Result<T>>) -> io::Result<T> {
    result.ok_or_else(|| io::Error::other("original native operation disappeared"))?
}

#[test]
fn fixed_udp_peer_qualification_preserves_original_numeric_endpoints() -> io::Result<()> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
    let link = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 53);
    let site = Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 53);
    for peer in [
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        SocketAddr::from((Ipv6Addr::LOCALHOST, 53)),
        SocketAddr::V6(SocketAddrV6::new(link, 53, 0x1234, 7)),
        SocketAddr::V6(SocketAddrV6::new(site, 53, 0x5678, 29)),
        SocketAddr::V6(SocketAddrV6::new(
            Ipv4Addr::new(192, 0, 2, 53).to_ipv6_mapped(),
            53,
            0xabcd,
            11,
        )),
    ] {
        if qualify_udp_peer(peer)? != peer {
            return Err(io::Error::other(
                "fixed UDP peer qualification rewrote its original sockaddr",
            ));
        }
    }
    Ok(())
}

#[test]
fn fixed_udp_peer_qualification_refuses_invalid_sources_without_native_calls() -> io::Result<()> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    for ip in [
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::BROADCAST,
        Ipv4Addr::new(224, 0, 0, 53),
    ] {
        for peer in [
            SocketAddr::from((ip, 53)),
            SocketAddr::from((ip.to_ipv6_mapped(), 53)),
        ] {
            if qualify_udp_peer(peer).is_ok() {
                return Err(io::Error::other(format!(
                    "fixed UDP peer admitted an invalid reply source: {peer}",
                )));
            }
        }
    }
    for peer in [
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        SocketAddr::from((Ipv6Addr::LOCALHOST, 0)),
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 53)),
        SocketAddr::from((Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 53), 53)),
        SocketAddr::from((Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 53), 53)),
        SocketAddr::from((Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 53), 53)),
        SocketAddr::from((Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0, 53), 53)),
    ] {
        if qualify_udp_peer(peer).is_ok() {
            return Err(io::Error::other(format!(
                "fixed UDP peer admitted an unqualified native endpoint: {peer}",
            )));
        }
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Native integration assertions retain fallible socket and callback errors"
)]
fn native_udp_loopback_preserves_datagrams_and_retires_callbacks() -> io::Result<()> {
    let budget = Duration::from_secs(10);
    let until = Instant::now() + budget;
    let server = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    server.set_read_timeout(Some(budget))?;
    server.set_write_timeout(Some(budget))?;
    let peer = server.local_addr()?;
    let mut connection = Connection::udp(peer)?;
    let outcome = (|| {
        wait(until, |cx| connection.poll_ready(cx))?;
        assert_eq!(connection.peer_addr()?, peer);
        assert!(!connection.is_tcp());

        let query = b"original-native-query";
        connection.begin_send(query)?;
        wait(until, |cx| connection.poll_send(cx).map(operation))?;
        let mut input = [0_u8; 64];
        server.set_read_timeout(Some(until.saturating_duration_since(Instant::now())))?;
        let (received, source) = server.recv_from(&mut input)?;
        assert_eq!(&input[..received], query);
        assert!(source.ip().is_loopback());

        let answer = b"original-native-response";
        connection.begin_receive(input.len())?;
        assert_eq!(server.send_to(answer, source)?, answer.len());
        let received = wait(until, |cx| connection.poll_receive(cx).map(operation))?;
        assert_eq!(received.bytes(), answer);
        let (mut bytes, end, error) = received.into_parts();
        assert!(!end, "a complete UDP message must not become TCP EOF");
        assert!(error.is_none(), "native receive error: {error:?}");
        zeroize::Zeroize::zeroize(&mut bytes);

        // A whole datagram exceeds this original receive reservation. Refuse
        // without truncation, then prove the same native connection can recover.
        connection.begin_receive(8)?;
        assert_eq!(server.send_to(b"oversized", source)?, 9);
        let refused = wait(until, |cx| connection.poll_receive(cx).map(operation));
        assert!(
            matches!(refused, Err(ref error) if error.kind() == io::ErrorKind::InvalidData),
            "expected an explicit bounded receive refusal: {refused:?}"
        );
        connection.begin_receive(8)?;
        assert_eq!(server.send_to(b"recovery", source)?, 8);
        let recovered = wait(until, |cx| connection.poll_receive(cx).map(operation))?;
        assert_eq!(recovered.bytes(), b"recovery");
        Ok::<(), io::Error>(())
    })();
    connection.request_cancel();
    let retirement = wait(until, |cx| connection.poll_retirement(cx).map(Ok));
    outcome?;
    let retirement = retirement?;
    assert!(
        retirement.cancellation_observed(),
        "original native cancellation was not observed"
    );
    assert!(
        retirement.has_failure(),
        "the deliberate oversized receive must remain in the retirement report"
    );
    Ok(())
}
