//! Listener owns the original UDP socket. A request retains its native return path.
#[cfg(windows)]
mod windows;

use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io,
    net::{SocketAddr, UdpSocket as StdSocket},
    task::{Context, Poll},
};

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
use gnunet_native::network::LocalDatagram;
#[cfg(any(
    windows,
    target_os = "linux",
    target_os = "freebsd",
    target_os = "macos"
))]
pub(super) use gnunet_native::network::LocalReplyPath as ReplyPath;
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
use gnunet_service_runtime::readiness::RegisteredIo;
#[cfg(not(any(
    windows,
    target_os = "linux",
    target_os = "freebsd",
    target_os = "macos"
)))]
use tokio::{io::ReadBuf, net::UdpSocket};

#[cfg(not(any(
    windows,
    target_os = "linux",
    target_os = "freebsd",
    target_os = "macos"
)))]
pub(super) struct ReplyPath(SocketAddr);

#[cfg(not(any(
    windows,
    target_os = "linux",
    target_os = "freebsd",
    target_os = "macos"
)))]
impl ReplyPath {
    pub(super) const fn peer(&self) -> SocketAddr {
        self.0
    }
}

pub(super) struct Listener {
    #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
    socket: RegisteredIo<LocalDatagram>,
    #[cfg(windows)]
    socket: windows::Datagram,
    #[cfg(not(any(
        windows,
        target_os = "linux",
        target_os = "freebsd",
        target_os = "macos"
    )))]
    socket: UdpSocket,
}

impl Listener {
    pub(super) fn bind(address: SocketAddr) -> io::Result<(Self, SocketAddr)> {
        let domain = Domain::for_address(address);
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        #[cfg(windows)]
        {
            use std::os::windows::io::AsSocket;
            gnunet_native::network::suppress_udp_connection_resets(socket.as_socket())?;
        }
        if address.is_ipv6() {
            socket.set_only_v6(true)?;
        }
        #[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "macos")))]
        socket.set_nonblocking(true)?;
        socket.bind(&address.into())?;
        let socket = StdSocket::from(socket);
        let actual = socket.local_addr()?;
        #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
        let socket = RegisteredIo::from_descriptor(LocalDatagram::new(socket)?)
            .map_err(|(_, error)| error)?;
        #[cfg(windows)]
        let socket = windows::Datagram::register(socket)?;
        #[cfg(not(any(
            windows,
            target_os = "linux",
            target_os = "freebsd",
            target_os = "macos"
        )))]
        let socket = UdpSocket::from_std(socket)?;
        Ok((Self { socket }, actual))
    }

    pub(super) fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        payload: &mut [u8],
    ) -> Poll<io::Result<(usize, ReplyPath)>> {
        #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
        return self
            .socket
            .poll_read_on(cx, |socket| socket.receive(payload));
        #[cfg(windows)]
        return self.socket.poll_recv(cx, payload);
        #[cfg(not(any(
            windows,
            target_os = "linux",
            target_os = "freebsd",
            target_os = "macos"
        )))]
        {
            let mut buffer = ReadBuf::new(payload);
            self.socket
                .poll_recv_from(cx, &mut buffer)
                .map_ok(|peer| (buffer.filled().len(), ReplyPath(peer)))
        }
    }

    pub(super) fn poll_send(
        &self,
        cx: &mut Context<'_>,
        path: &ReplyPath,
        payload: &[u8],
    ) -> Poll<io::Result<usize>> {
        #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
        return self
            .socket
            .poll_write_on(cx, |socket| socket.send(path, payload));
        #[cfg(windows)]
        return self.socket.poll_send(cx, path, payload);
        #[cfg(not(any(
            windows,
            target_os = "linux",
            target_os = "freebsd",
            target_os = "macos"
        )))]
        self.socket.poll_send_to(cx, payload, path.peer())
    }
}
