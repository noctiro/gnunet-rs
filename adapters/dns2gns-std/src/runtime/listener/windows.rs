//! Poll the original Tokio listener around synchronous Winsock datagram I/O.
use gnunet_native::network::{LocalDatagramIo, LocalReplyPath};
use std::{
    io,
    net::UdpSocket as StdSocket,
    task::{Context, Poll, ready},
};
use tokio::{io::Interest, net::UdpSocket};

pub(super) struct Datagram(LocalDatagramIo<UdpSocket>);

impl Datagram {
    pub(super) fn register(socket: StdSocket) -> io::Result<Self> {
        Ok(Self(LocalDatagramIo::new(UdpSocket::from_std(socket)?)?))
    }

    pub(super) fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        payload: &mut [u8],
    ) -> Poll<io::Result<(usize, LocalReplyPath)>> {
        let socket = self.0.socket();
        ready!(socket.poll_recv_ready(cx))?;
        settle(
            cx,
            socket.try_io(Interest::READABLE, || self.0.receive(payload)),
        )
    }

    pub(super) fn poll_send(
        &self,
        cx: &mut Context<'_>,
        path: &LocalReplyPath,
        payload: &[u8],
    ) -> Poll<io::Result<usize>> {
        let socket = self.0.socket();
        ready!(socket.poll_send_ready(cx))?;
        settle(
            cx,
            socket.try_io(Interest::WRITABLE, || self.0.send(path, payload)),
        )
    }
}

fn settle<T>(cx: &Context<'_>, result: io::Result<T>) -> Poll<io::Result<T>> {
    match result {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            // try_io cleared the stale readiness hint. Re-register on the next turn.
            cx.waker().wake_by_ref();
            Poll::Pending
        }
        result => Poll::Ready(result),
    }
}
