//! Raw-byte native getaddrinfo port with explicit source hints.
//! Native operating-system boundary; no GNUnet C FFI or ordinary
//! resolver-service bypass. Explicit hints remain native platform values.
use std::{
    ffi::{CStr, CString, OsStr, OsString},
    fmt, io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::unix::ffi::{OsStrExt, OsStringExt},
    ptr,
};
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
    pub const fn arm(disable_v6: bool) -> Self {
        Self {
            family: if disable_v6 {
                libc::AF_INET
            } else {
                libc::AF_UNSPEC
            },
            socket_type: 0,
            protocol: libc::IPPROTO_TCP,
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
impl std::error::Error for Error {}
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
struct OwnedAddressInfo(*mut libc::addrinfo);
impl Drop for OwnedAddressInfo {
    #[expect(
        unsafe_code,
        reason = "Only one successful nonnull getaddrinfo allocation creates this nonclone guard, and its complete list is freed exactly once"
    )]
    fn drop(&mut self) {
        // SAFETY: successful native getaddrinfo created this complete live list;
        // ownership never escapes or clones, and all result copies already own data.
        unsafe { libc::freeaddrinfo(self.0) };
    }
}
fn own(bytes: &[u8]) -> Result<OsString, Error> {
    let mut out = Vec::new();
    out.try_reserve_exact(bytes.len())
        .map_err(|_| Error::Capacity)?;
    out.extend_from_slice(bytes);
    Ok(OsString::from_vec(out))
}
/// Invoke the actual native function with explicit hints and genuinely NULL service.
/// Raw host bytes are copied into a CString without Unicode/IDNA transformation.
/// This can consult native NSS/DNS for ordinary names; local tests use only numeric
/// addresses or explicitly verified local hosts aliases inside an IP-denying sandbox.
#[expect(
    unsafe_code,
    reason = "Initialized native hints and CString/output pointers remain live; successful ownership is guarded through every sockaddr/string copy"
)]
pub fn resolve(host: &OsStr, hints: Hints, maximum: usize) -> Result<Vec<Address>, Error> {
    if maximum == 0 {
        return Err(Error::Capacity);
    }
    let name = CString::new(host.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "BINDTO contains NUL"))?;
    // SAFETY: addrinfo is native C integer/pointer storage, all-zero is the same
    // initialization used by the official source before its four scalar hints.
    let mut native: libc::addrinfo = unsafe { std::mem::zeroed() };
    native.ai_family = hints.family;
    native.ai_socktype = hints.socket_type;
    native.ai_protocol = hints.protocol;
    native.ai_flags = hints.flags;
    let mut head = ptr::null_mut();
    // SAFETY: name is NUL terminated, service is truly NULL, initialized hints
    // and writable output slot remain live, and no pointer is borrowed by Rust.
    let code = unsafe { libc::getaddrinfo(name.as_ptr(), ptr::null(), &native, &mut head) };
    if code != 0 {
        // SAFETY: native gai_strerror returns a static diagnostic or NULL.
        let raw = unsafe { libc::gai_strerror(code) };
        let message = if raw.is_null() {
            OsString::new()
        } else {
            // SAFETY: nonnull static C diagnostic is terminated; copy before returning.
            own(unsafe { CStr::from_ptr(raw) }.to_bytes())?
        };
        return Err(Error::Resolution { code, message });
    }
    if head.is_null() {
        return Err(
            io::Error::new(io::ErrorKind::InvalidData, "empty native addrinfo result").into(),
        );
    }
    let owner = OwnedAddressInfo(head);
    let mut cursor = owner.0;
    let mut results = Vec::new();
    while !cursor.is_null() {
        if results.len() == maximum {
            return Err(Error::Capacity);
        }
        // SAFETY: successful getaddrinfo owns this initialized acyclic node list;
        // the guard keeps it alive until the full owned result copy completes.
        let record = unsafe { &*cursor };
        let length = usize::try_from(record.ai_addrlen).map_err(|_| io::ErrorKind::InvalidData)?;
        if record.ai_addr.is_null() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let address = match record.ai_family {
            libc::AF_INET => {
                if length < std::mem::size_of::<libc::sockaddr_in>() {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                // SAFETY: native family/length identify an initialized sockaddr_in.
                let address =
                    unsafe { ptr::read_unaligned(record.ai_addr.cast::<libc::sockaddr_in>()) };
                SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()),
                    u16::from_be(address.sin_port),
                ))
            }
            libc::AF_INET6 => {
                if length < std::mem::size_of::<libc::sockaddr_in6>() {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                // SAFETY: native family/length identify an initialized sockaddr_in6.
                let address =
                    unsafe { ptr::read_unaligned(record.ai_addr.cast::<libc::sockaddr_in6>()) };
                SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(address.sin6_addr.s6_addr),
                    u16::from_be(address.sin6_port),
                    address.sin6_flowinfo,
                    address.sin6_scope_id,
                ))
            }
            family => return Err(Error::Family(family)),
        };
        let canonical = if record.ai_canonname.is_null() {
            None
        } else {
            // SAFETY: optional native canonical name is part of the guarded list.
            Some(own(
                unsafe { CStr::from_ptr(record.ai_canonname) }.to_bytes()
            )?)
        };
        results.try_reserve(1).map_err(|_| Error::Capacity)?;
        results.push(Address {
            address,
            family: record.ai_family,
            socket_type: record.ai_socktype,
            protocol: record.ai_protocol,
            flags: record.ai_flags,
            canonical,
        });
        cursor = record.ai_next;
    }
    Ok(results)
}
