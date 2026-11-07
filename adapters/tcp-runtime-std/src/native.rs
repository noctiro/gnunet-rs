use gnunet_service_runtime::connection::Connection;
use gnunet_tcp_communicator_host::Connect;
use socket2::{Domain, Protocol, Socket, Type};
use std::{io, net::SocketAddr};
use tokio::{io::Interest, net::TcpStream};
/// One original nonblocking native connect admitted by an actual connect syscall.
/// Constructing this value starts the attempt. Waiting/poll cancellation retains
/// the same socket; neither admission nor writability authenticates its peer.
pub struct NativeConnect {
    stream: TcpStream,
}
impl NativeConnect {
    /// Create/options/connect the original native socket. Success includes actual
    /// EINPROGRESS; synchronous refusal returns its original cause and drops it.
    /// The caller must run inside its intended Tokio reactor while constructing.
    pub fn begin(address: SocketAddr) -> io::Result<Self> {
        let socket = Socket::new(
            if address.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            },
            Type::STREAM,
            Some(Protocol::TCP),
        )?;
        socket.set_nonblocking(true)?;
        socket.set_tcp_nodelay(true)?;
        match socket.connect(&address.into()) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
            Err(e) => return Err(e),
        }
        let stream = TcpStream::from_std(socket.into())?;
        Ok(Self { stream })
    }
    /// Transfer the exact already-started socket into the manager's original
    /// retained future. It checks actual SO_ERROR/peer state after readiness.
    pub fn into_future(self) -> Connect<'static> {
        Box::pin(async move {
            loop {
                self.stream.writable().await?;
                let connected = self.stream.try_io(Interest::WRITABLE, || {
                    if let Some(error) = self.stream.take_error()? {
                        return Err(error);
                    }
                    match self.stream.peer_addr() {
                        Ok(_) => Ok(()),
                        Err(e) if e.kind() == io::ErrorKind::NotConnected => {
                            Err(io::ErrorKind::WouldBlock.into())
                        }
                        Err(e) => Err(e),
                    }
                });
                match connected {
                    Ok(()) => return Ok(Connection::from_tcp(self.stream)),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
                }
            }
        })
    }
}
