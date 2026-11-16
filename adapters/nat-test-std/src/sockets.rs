//! Original challenge sockets with native binding and datagram error policy.
use socket2::{Domain, Protocol, Socket, Type};
use std::{io, net::SocketAddr};
use tokio::net::{TcpListener, UdpSocket};
fn socket(address: SocketAddr, kind: Type, protocol: Protocol) -> io::Result<Socket> {
    let socket = Socket::new(Domain::for_address(address), kind, Some(protocol))?;
    #[cfg(windows)]
    {
        use std::os::windows::io::AsSocket;
        gnunet_native::network::set_exclusive_address_use(socket.as_socket())?;
    }
    #[cfg(unix)]
    if kind == Type::STREAM {
        socket.set_reuse_address(true)?;
    }
    socket.bind(&address.into())?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}
pub(super) fn tcp(address: SocketAddr) -> io::Result<TcpListener> {
    let socket = socket(address, Type::STREAM, Protocol::TCP)?;
    socket.listen(128)?;
    TcpListener::from_std(socket.into())
}
pub(super) fn udp(address: SocketAddr) -> io::Result<UdpSocket> {
    let socket = socket(address, Type::DGRAM, Protocol::UDP)?;
    #[cfg(windows)]
    {
        use std::os::windows::io::AsSocket;
        gnunet_native::network::suppress_udp_connection_resets(socket.as_socket())?;
    }
    UdpSocket::from_std(socket.into())
}
