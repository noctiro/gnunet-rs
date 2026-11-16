//! Raw-byte native getaddrinfo port with explicit source hints.
//! Native operating-system boundary; no GNUnet C FFI or ordinary
//! resolver-service bypass. Explicit hints remain native platform values.
use std::{
    ffi::{OsStr, OsString},
    fmt, io,
    net::SocketAddr,
};
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
pub use unix::resolve;
#[cfg(windows)]
pub use windows::resolve;

/// Native address-family policy for the ARM endpoint profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Families {
    /// Request IPv4 or IPv6 directly from the native resolver.
    Any,
    /// Request AF_INET directly; never resolve all families and discard IPv6.
    Ipv4Only,
}
/// Exact native input hints; ARM leaves socktype/flags0, protocolTCP, serviceNULL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hints {
    /// Native AF_UNSPEC or AF_INET for the official ARM profile.
    pub family: i32,
    /// Native requested socket type; official ARM passes0, then filters output.
    pub socket_type: i32,
    /// Native requested protocol; official ARM passes IPPROTO_TCP.
    pub protocol: i32,
    /// Native getaddrinfo flags; official ARM passes0.
    pub flags: i32,
}
impl Hints {
    /// Source-exact get_server_addresses input, not UNSPEC followed by IPv4 filtering.
    pub const fn arm(families: Families) -> Self {
        #[cfg(unix)]
        use libc::{AF_INET, AF_UNSPEC, IPPROTO_TCP};
        #[cfg(windows)]
        use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_UNSPEC, IPPROTO_TCP};
        let family = match families {
            Families::Ipv4Only => AF_INET,
            Families::Any => AF_UNSPEC,
        };
        #[cfg(windows)]
        let family = family as i32;
        Self {
            family,
            socket_type: 0,
            protocol: IPPROTO_TCP,
            flags: 0,
        }
    }
}
/// Owned copy of one native result, preserving source order and metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Address {
    /// Native sockaddr value, including IPv6 scope/flow and original port.
    pub address: SocketAddr,
    /// Original ai_family.
    pub family: i32,
    /// Original ai_socktype.
    pub socket_type: i32,
    /// Original ai_protocol.
    pub protocol: i32,
    /// Original ai_flags.
    pub flags: i32,
    /// Original optional raw ai_canonname bytes; no UTF8 conversion.
    pub canonical: Option<OsString>,
}
/// Native or bounded-copy failure; never a successful partial result list.
#[derive(Debug)]
pub enum Error {
    /// Native getaddrinfo code plus owned raw-byte diagnostic.
    Resolution {
        /// Original EAI code.
        code: i32,
        /// Raw static diagnostic copied before return.
        message: OsString,
    },
    /// Invalid CString, sockaddr, empty successful result or OS-level failure.
    Io(io::Error),
    /// Caller maximum or allocation bound refused the entire result list.
    Capacity,
    /// Native result has an unsupported address family.
    Family(i32),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolution { code, message } => write!(
                f,
                "native getaddrinfo {code}: {}",
                message.to_string_lossy()
            ),
            Self::Io(e) => e.fmt(f),
            Self::Capacity => f.write_str("native address result capacity"),
            Self::Family(family) => write!(f, "unsupported native address family {family}"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}
impl From<io::ErrorKind> for Error {
    fn from(kind: io::ErrorKind) -> Self {
        Self::Io(kind.into())
    }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
