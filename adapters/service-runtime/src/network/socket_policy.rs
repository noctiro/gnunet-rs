//! Preparation of each original Internet socket before its first native use.
use socket2::{Domain, Protocol, Socket, Type};
use std::{fmt, io, net::SocketAddr};
use tokio::net::{TcpSocket, UdpSocket};

#[cfg(unix)]
use std::{
    os::fd::{AsFd, BorrowedFd},
    sync::Arc,
};

#[cfg(unix)]
type Protector = dyn Fn(BorrowedFd<'_>) -> io::Result<()> + Send + Sync;

/// Application policy for newly allocated Internet sockets. The native default
/// preserves ordinary process networking. A protected node keeps the same
/// original policy through reconnection and address replacement.
#[derive(Clone, Default)]
pub struct SocketPolicy {
    #[cfg(unix)]
    protector: Option<Arc<Protector>>,
}

/// Origin of a failure opening an unused Internet socket.
#[derive(Debug)]
pub enum SocketOpenError {
    /// The operating system could not allocate the descriptor.
    Create(io::Error),
    /// The application refused to prepare the allocated descriptor.
    Protection(io::Error),
}

impl fmt::Display for SocketOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Create(error) => write!(formatter, "create Internet socket: {error}"),
            Self::Protection(error) => write!(formatter, "protect Internet socket: {error}"),
        }
    }
}

impl std::error::Error for SocketOpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Create(error) | Self::Protection(error) => Some(error),
        }
    }
}

impl From<SocketOpenError> for io::Error {
    fn from(error: SocketOpenError) -> Self {
        match error {
            SocketOpenError::Create(error) | SocketOpenError::Protection(error) => error,
        }
    }
}

impl SocketPolicy {
    /// Require successful application protection on each original Unix socket.
    /// The callback borrows the original descriptor through its synchronous
    /// operation. It may adjust socket routing but must never close the descriptor.
    #[cfg(unix)]
    pub fn protected(
        protector: impl Fn(BorrowedFd<'_>) -> io::Result<()> + Send + Sync + 'static,
    ) -> Self {
        Self {
            protector: Some(Arc::new(protector)),
        }
    }

    /// Whether the caller supplied a required protection callback.
    #[must_use]
    pub fn is_protected(&self) -> bool {
        #[cfg(unix)]
        {
            self.protector.is_some()
        }
        #[cfg(windows)]
        {
            false
        }
    }

    fn open(
        &self,
        address: SocketAddr,
        kind: Type,
        protocol: Protocol,
    ) -> Result<Socket, SocketOpenError> {
        let socket = Socket::new(Domain::for_address(address), kind, Some(protocol))
            .map_err(SocketOpenError::Create)?;
        #[cfg(unix)]
        if let Some(protect) = &self.protector {
            protect(socket.as_fd()).map_err(SocketOpenError::Protection)?;
        }
        Ok(socket)
    }

    /// Allocate a TCP socket in the matching address family and apply this
    /// policy before the caller can listen or connect.
    pub fn open_tcp(&self, address: SocketAddr) -> Result<Socket, SocketOpenError> {
        self.open(address, Type::STREAM, Protocol::TCP)
    }

    /// Allocate a UDP socket in the matching address family and apply this
    /// policy before the caller can bind or send.
    pub fn open_udp(&self, address: SocketAddr) -> Result<Socket, SocketOpenError> {
        self.open(address, Type::DGRAM, Protocol::UDP)
    }

    /// Allocate and prepare an original nonblocking TCP socket for Tokio.
    pub fn tcp_socket(&self, address: SocketAddr) -> io::Result<TcpSocket> {
        let socket = self.open_tcp(address)?;
        socket.set_nonblocking(true)?;
        Ok(TcpSocket::from_std_stream(socket.into()))
    }

    /// Allocate, prepare and bind a new nonblocking UDP socket on the caller's
    /// I/O-enabled reactor.
    pub fn udp_bind(&self, address: SocketAddr) -> io::Result<UdpSocket> {
        let socket = self.open_udp(address)?;
        socket.set_nonblocking(true)?;
        socket.bind(&address.into())?;
        UdpSocket::from_std(socket.into())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn protection_observes_the_original_unbound_socket_and_can_refuse_it() -> io::Result<()> {
        let called = Arc::new(AtomicBool::new(false));
        let observed = called.clone();
        let policy = SocketPolicy::protected(move |fd| {
            let address = socket2::SockRef::from(&fd).local_addr()?.as_socket();
            observed.store(address.is_some_and(|ip| ip.port() == 0), Ordering::Relaxed);
            Err(io::ErrorKind::PermissionDenied.into())
        });
        let attempt = policy.udp_bind(SocketAddr::from(([127, 0, 0, 1], 0)));
        if !called.load(Ordering::Relaxed)
            || !matches!(attempt, Err(error) if error.kind() == io::ErrorKind::PermissionDenied)
        {
            return Err(io::Error::other(
                "UDP factory did not apply protection before binding",
            ));
        }
        Ok(())
    }
}
