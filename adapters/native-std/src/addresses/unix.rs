//! POSIX address allocation and lossless bounded native-result copies.
use super::*;
use std::{
    ffi::{CStr, CString},
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
    os::unix::ffi::{OsStrExt, OsStringExt},
    ptr,
};
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
pub fn resolve(host: &OsStr, hints: Hints, maximum: usize) -> Result<Vec<Address>, Error> {
    if maximum == 0 {
        return Err(Error::Capacity);
    }
    let name = CString::new(host.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "BINDTO contains NUL"))?;
    resolve_native(&name, None, hints, maximum)
}

#[expect(
    unsafe_code,
    reason = "Initialized native hints and C strings remain live; successful ownership is guarded through every sockaddr/string copy"
)]
pub(crate) fn resolve_native(
    name: &CStr,
    service: Option<&CStr>,
    hints: Hints,
    maximum: usize,
) -> Result<Vec<Address>, Error> {
    if maximum == 0 {
        return Err(Error::Capacity);
    }
    // SAFETY: addrinfo is native C integer/pointer storage, all-zero is the same
    // initialization used by the official source before its four scalar hints.
    let mut native: libc::addrinfo = unsafe { std::mem::zeroed() };
    native.ai_family = hints.family;
    native.ai_socktype = hints.socket_type;
    native.ai_protocol = hints.protocol;
    native.ai_flags = hints.flags;
    let mut head = ptr::null_mut();
    // SAFETY: name and optional service are NUL terminated. Hints and the
    // writable output slot remain live through the call.
    let code = unsafe {
        libc::getaddrinfo(
            name.as_ptr(),
            service.map_or(ptr::null(), CStr::as_ptr),
            &native,
            &mut head,
        )
    };
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
