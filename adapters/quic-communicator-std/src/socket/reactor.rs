//! Tokio readiness for the original Quinn UDP socket and ancillary data.
use quinn::{AsyncUdpSocket, UdpPoller, udp};
use std::{
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};
use tokio::{io::Interest, net::UdpSocket};

#[derive(Debug)]
pub(super) struct ReactorSocket {
    io: UdpSocket,
    protocol: udp::UdpSocketState,
}

impl ReactorSocket {
    pub(super) fn new(socket: std::net::UdpSocket) -> io::Result<Self> {
        let protocol = udp::UdpSocketState::new((&socket).into())?;
        let io = UdpSocket::from_std(socket)?;
        Ok(Self { io, protocol })
    }
}

#[derive(Debug)]
struct Writable(Arc<ReactorSocket>);

impl UdpPoller for Writable {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The private endpoint owner polls every original Quinn driver with
        // the same caller context. The readiness slot needs only that waker.
        self.0.io.poll_send_ready(cx)
    }
}

impl AsyncUdpSocket for ReactorSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Writable(self))
    }

    fn try_send(&self, packet: &udp::Transmit<'_>) -> io::Result<()> {
        self.io.try_io(Interest::WRITABLE, || {
            self.protocol.try_send((&self.io).into(), packet)
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        ready!(self.io.poll_recv_ready(cx))?;
        match self.io.try_io(Interest::READABLE, || {
            self.protocol.recv((&self.io).into(), buffers, meta)
        }) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                // try_io cleared this readiness after a cached hint. Give the
                // caller one turn to register again before any further I/O.
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            result => Poll::Ready(result),
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.protocol.max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.protocol.gro_segments()
    }

    fn may_fragment(&self) -> bool {
        self.protocol.may_fragment()
    }
}
