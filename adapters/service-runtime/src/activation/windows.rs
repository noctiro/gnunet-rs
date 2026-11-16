//! Actual unregistered Windows stream-listener ownership for native activation.
use gnunet_native::local_socket;
use socket2::{Domain, SockRef, Socket, Type};
use std::{
    io,
    net::TcpListener,
    os::windows::io::{AsSocket, BorrowedSocket, OwnedSocket},
};

/// Owned original listeners in declaration order. Original filesystem nodes
/// remain the creator's responsibility; no inherited path cleanup is installed.
#[derive(Debug, Default)]
pub struct Activation {
    sockets: Vec<ActivatedSocket>,
}
/// One actual native stream listener, still unregistered with the child reactor.
#[derive(Debug)]
pub enum ActivatedSocket {
    /// AF_UNIX listener; no inherited path may be unlinked by its recipient.
    Unix(Socket),
    /// IPv4/IPv6 TCP listener.
    Tcp(TcpListener),
}
impl ActivatedSocket {
    /// Borrow the original native socket without transferring ownership.
    pub fn as_socket(&self) -> BorrowedSocket<'_> {
        match self {
            Self::Unix(socket) => socket.as_socket(),
            Self::Tcp(socket) => socket.as_socket(),
        }
    }
}
enum Kind {
    Unix,
    Tcp,
}
impl Activation {
    /// Borrow validated original listeners without transferring ownership.
    pub fn sockets(&self) -> &[ActivatedSocket] {
        &self.sockets
    }
    /// Number of validated stream listeners.
    pub fn len(&self) -> usize {
        self.sockets.len()
    }
    /// Whether no listener transfer was declared.
    pub fn is_empty(&self) -> bool {
        self.sockets.is_empty()
    }
    /// Transfer all original validated listener owners without cloning or rebinding.
    pub fn into_sockets(self) -> Vec<ActivatedSocket> {
        self.sockets
    }

    /// Validate every owned source before conversion and enable nonblocking I/O.
    /// Native transfer callers retain creator path leases and exclude concurrent
    /// I/O/options/registration while passing these listeners to another process.
    pub fn from_sockets(sockets: Vec<Socket>) -> io::Result<Self> {
        validate(sockets)
    }
    /// Consume fresh descriptors returned by native WSASocket import, never raw
    /// advertised SOCKET numbers. Validation failure closes all imported owners.
    pub fn from_imported(sockets: Vec<OwnedSocket>) -> io::Result<Self> {
        validate(sockets)
    }
}
fn validate<T: AsSocket + Into<Socket>>(sockets: Vec<T>) -> io::Result<Activation> {
    if sockets.len() > gnunet_native::socket_activation::MAX_LISTENERS {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut kinds = Vec::new();
    kinds
        .try_reserve_exact(sockets.len())
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    for socket in &sockets {
        let socket = SockRef::from(socket);
        if socket.r#type()? != Type::STREAM || !local_socket::is_listener(socket.as_socket())? {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let family = socket.local_addr()?.family();
        if i32::from(family) == i32::from(Domain::UNIX) {
            kinds.push(Kind::Unix);
        } else if i32::from(family) == i32::from(Domain::IPV4)
            || i32::from(family) == i32::from(Domain::IPV6)
        {
            socket.tcp_nodelay()?;
            kinds.push(Kind::Tcp);
        } else {
            return Err(io::ErrorKind::Unsupported.into());
        }
    }
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(sockets.len())
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    for (socket, kind) in sockets.into_iter().zip(kinds) {
        let socket: Socket = socket.into();
        socket.set_nonblocking(true)?;
        owned.push(match kind {
            Kind::Unix => ActivatedSocket::Unix(socket),
            Kind::Tcp => ActivatedSocket::Tcp(socket.into()),
        });
    }
    Ok(Activation { sockets: owned })
}
