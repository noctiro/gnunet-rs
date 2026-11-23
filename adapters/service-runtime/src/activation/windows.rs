//! Actual unregistered Windows stream-listener ownership for native activation.
use crate::credentials::UnixAccess;
use gnunet_native::{
    local_path::EndpointProtection,
    local_socket,
    socket_activation::{ImportedSocket, Source},
};
use socket2::{Domain, SockRef, Socket, Type};
use std::{
    io,
    net::TcpListener,
    os::windows::io::{AsSocket, BorrowedSocket},
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
    Unix(ActivatedLocalSocket),
    /// IPv4/IPv6 TCP listener.
    Tcp(TcpListener),
}
/// An original activated AF_UNIX descriptor and its optional publisher evidence.
#[derive(Debug)]
pub struct ActivatedLocalSocket {
    socket: Socket,
    protection: Option<EndpointProtection>,
}
impl ActivatedLocalSocket {
    pub(crate) fn into_parts(self) -> (Socket, Option<EndpointProtection>) {
        (self.socket, self.protection)
    }
}
impl AsSocket for ActivatedLocalSocket {
    fn as_socket(&self) -> BorrowedSocket<'_> {
        self.socket.as_socket()
    }
}
impl ActivatedSocket {
    /// Borrow the original native socket without transferring ownership.
    pub fn as_socket(&self) -> BorrowedSocket<'_> {
        match self {
            Self::Unix(socket) => socket.as_socket(),
            Self::Tcp(socket) => socket.as_socket(),
        }
    }

    /// Borrow the original listener and preserve verified ACL evidence through
    /// a same-account bootstrap handoff.
    pub fn launch_source(&self) -> Source<'_> {
        let source = Source::new(self.as_socket());
        match self {
            Self::Unix(ActivatedLocalSocket {
                protection: Some(protection),
                ..
            }) => source.with_protection(protection),
            _ => source,
        }
    }
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

    pub(crate) fn validate_local_access(&self, policy: UnixAccess) -> io::Result<()> {
        for socket in &self.sockets {
            if let ActivatedSocket::Unix(local) = socket
                && !policy.allows_windows_listener(
                    local.protection.as_ref().map(EndpointProtection::access),
                )?
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "original Windows AF_UNIX listener ACL does not satisfy the configured service restriction",
                ));
            }
        }
        Ok(())
    }

    /// Validate every owned source before conversion and enable nonblocking I/O.
    /// Native transfer callers retain creator path leases and exclude concurrent
    /// I/O/options/registration while passing these listeners to another process.
    pub fn from_sockets(sockets: Vec<Socket>) -> io::Result<Self> {
        validate(sockets.into_iter().map(|socket| (socket, None)))
    }
    /// Consume fresh descriptors returned by native WSASocket import, never raw
    /// advertised SOCKET numbers. Validation failure closes all imported owners.
    pub fn from_imported(sockets: Vec<ImportedSocket>) -> io::Result<Self> {
        validate(sockets.into_iter().map(ImportedSocket::into_parts))
    }
}
fn validate<T: Into<Socket>>(
    sockets: impl ExactSizeIterator<Item = (T, Option<EndpointProtection>)>,
) -> io::Result<Activation> {
    if sockets.len() > gnunet_native::socket_activation::MAX_LISTENERS {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(sockets.len())
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    for (socket, protection) in sockets {
        let socket: Socket = socket.into();
        if socket.r#type()? != Type::STREAM || !local_socket::is_listener(socket.as_socket())? {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let family = socket.local_addr()?.family();
        if i32::from(family) == i32::from(Domain::UNIX) {
            if protection.is_some()
                && local_socket::local_address(socket.as_socket())?
                    .as_pathname()
                    .is_none()
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            owned.push(ActivatedSocket::Unix(ActivatedLocalSocket {
                socket,
                protection,
            }));
        } else if i32::from(family) == i32::from(Domain::IPV4)
            || i32::from(family) == i32::from(Domain::IPV6)
        {
            if protection.is_some() {
                return Err(io::ErrorKind::InvalidData.into());
            }
            socket.tcp_nodelay()?;
            owned.push(ActivatedSocket::Tcp(socket.into()));
        } else {
            return Err(io::ErrorKind::Unsupported.into());
        }
    }
    for socket in &owned {
        SockRef::from(&socket.as_socket()).set_nonblocking(true)?;
    }
    Ok(Activation { sockets: owned })
}
