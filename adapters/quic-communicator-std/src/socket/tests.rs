use super::*;
use std::{
    net::Ipv4Addr,
    sync::atomic::AtomicUsize,
    task::{Wake, Waker},
    time::Duration,
};

#[derive(Debug)]
struct Receives {
    polls: AtomicUsize,
    reset_code: Option<i32>,
}

#[derive(Debug)]
struct UnusedPoller;

impl UdpPoller for UnusedPoller {
    fn poll_writable(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::ErrorKind::Unsupported.into()))
    }
}

impl AsyncUdpSocket for Receives {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(UnusedPoller)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, 1)))
    }

    fn try_send(&self, _: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn poll_recv(
        &self,
        _: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(match self.polls.fetch_add(1, Ordering::Relaxed) {
            0 => Err(self.reset_code.map_or_else(
                || io::ErrorKind::ConnectionReset.into(),
                io::Error::from_raw_os_error,
            )),
            1 => {
                buffers[0][0] = 42;
                meta[0].len = 1;
                meta[0].stride = 1;
                Ok(1)
            }
            _ => Err(io::ErrorKind::NotConnected.into()),
        })
    }
}

#[derive(Default)]
struct Wakes(AtomicUsize);

impl Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn receive_after_reset(reset_code: Option<i32>) {
    let inner = Arc::new(Receives {
        polls: AtomicUsize::new(0),
        reset_code,
    });
    let gate = Gate::new(Instant::now() + Duration::from_secs(10));
    let socket = Socket::new(inner.clone(), gate.clone());
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(wakes.clone());
    let mut cx = Context::from_waker(&waker);
    let mut data = [0];
    let mut buffers = [IoSliceMut::new(&mut data)];
    let mut meta = [quinn::udp::RecvMeta::default()];

    assert!(
        socket
            .poll_recv(&mut cx, &mut buffers, &mut meta)
            .is_pending()
    );
    assert_eq!(inner.polls.load(Ordering::Relaxed), 1);
    assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
    assert!(gate.take_error().is_none());
    let statistics = gate.statistics();
    assert_eq!(statistics.received, 0);
    assert_eq!(statistics.isolated_receives, 1);
    assert_eq!(statistics.last_isolated_receive_os_error, reset_code);

    assert!(matches!(
        socket.poll_recv(&mut cx, &mut buffers, &mut meta),
        Poll::Ready(Ok(1))
    ));
    assert_eq!(buffers[0][0], 42);
    assert_eq!(gate.statistics().received, 1);

    assert!(matches!(
        socket.poll_recv(&mut cx, &mut buffers, &mut meta),
        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::NotConnected
    ));
    assert_eq!(
        gate.take_error().as_ref().map(io::Error::kind),
        Some(io::ErrorKind::NotConnected)
    );
    assert_eq!(gate.statistics().isolated_receives, 1);
}

#[test]
fn connection_reset_keeps_the_endpoint_and_next_receive_live() {
    receive_after_reset(None);
}

#[cfg(windows)]
#[test]
fn winsock_ttl_expiry_preserves_the_endpoint_and_native_code() {
    const WSAENETRESET: i32 = 10052;
    receive_after_reset(Some(WSAENETRESET));
}

#[cfg(windows)]
#[test]
fn winsock_packet_truncation_reaches_the_original_receive_policy() -> io::Result<()> {
    use std::future::poll_fn;
    const WSAEMSGSIZE: i32 = 10040;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let hard = Instant::now() + Duration::from_secs(5);
            tokio::time::timeout_at(hard, async {
                let native = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
                native.set_nonblocking(true)?;
                let gate = Gate::new(hard);
                let socket = Socket::from_std(native, gate.clone())?;
                let destination = socket.local_addr()?;
                let peer = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
                let mut data = [0];
                let mut buffers = [IoSliceMut::new(&mut data)];
                let mut meta = [quinn::udp::RecvMeta::default()];
                peer.send_to(b"oversized", destination).await?;
                poll_fn(|cx| match socket.poll_recv(cx, &mut buffers, &mut meta) {
                    Poll::Ready(Ok(_)) => {
                        Poll::Ready(Err(io::Error::other("truncated datagram was admitted")))
                    }
                    Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                    Poll::Pending
                        if gate.statistics().last_isolated_receive_os_error
                            == Some(WSAEMSGSIZE) =>
                    {
                        Poll::Ready(Ok(()))
                    }
                    Poll::Pending => Poll::Pending,
                })
                .await?;
                peer.send_to(b"x", destination).await?;
                let received = poll_fn(|cx| socket.poll_recv(cx, &mut buffers, &mut meta)).await?;
                let stats = gate.statistics();
                if received != 1
                    || data != *b"x"
                    || stats.received != 1
                    || stats.isolated_receives != 1
                    || gate.take_error().is_some()
                {
                    return Err(io::Error::other(
                        "truncation affected a later valid datagram",
                    ));
                }
                Ok(())
            })
            .await
            .map_err(io::Error::other)?
        })
}
