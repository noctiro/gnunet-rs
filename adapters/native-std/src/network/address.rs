use std::mem::offset_of;

#[cfg(unix)]
use libc::{AF_UNIX, sockaddr_in as Ipv4, sockaddr_in6 as Ipv6, sockaddr_un as Local};
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{
    AF_UNIX, SOCKADDR_IN as Ipv4, SOCKADDR_IN6 as Ipv6, SOCKADDR_UN as Local,
};

/// Target SDK layout of `sockaddr_un`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnixAddressLayout {
    /// Width of the native address family field.
    pub family_bytes: usize,
    /// Complete structure size, including padding.
    pub sockaddr_bytes: usize,
    /// Byte offset of the path field.
    pub path_offset: usize,
}

/// Read the native structure layout without opening a socket.
#[must_use]
pub const fn unix_address_layout() -> UnixAddressLayout {
    #[cfg(unix)]
    type Family = libc::sa_family_t;
    #[cfg(windows)]
    type Family = windows_sys::Win32::Networking::WinSock::ADDRESS_FAMILY;

    UnixAddressLayout {
        family_bytes: size_of::<Family>(),
        sockaddr_bytes: size_of::<Local>(),
        path_offset: offset_of!(Local, sun_path),
    }
}

/// Header shared by the target SDK's IPv4, IPv6 and Unix structures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketAddressHeader {
    /// A native-endian 16-bit family.
    NativeFamily,
    /// An 8-bit structure length followed by an 8-bit family.
    LengthAndFamily,
}

/// Identify the header for the 16-byte IPv4 and 28-byte IPv6 structures used
/// with a two-byte Unix path offset. Returns `None` for other layouts.
#[must_use]
pub const fn socket_address_header() -> Option<SocketAddressHeader> {
    let unix = unix_address_layout();
    #[cfg(unix)]
    let scope_offset = offset_of!(Ipv6, sin6_scope_id);
    #[cfg(windows)]
    let scope_offset = offset_of!(Ipv6, Anonymous);

    if AF_UNIX != 1
        || unix.path_offset != 2
        || size_of::<Ipv4>() != 16
        || offset_of!(Ipv4, sin_port) != 2
        || offset_of!(Ipv4, sin_addr) != 4
        || size_of::<Ipv6>() != 28
        || offset_of!(Ipv6, sin6_port) != 2
        || offset_of!(Ipv6, sin6_flowinfo) != 4
        || offset_of!(Ipv6, sin6_addr) != 8
        || scope_offset != 24
    {
        return None;
    }

    match (
        unix.family_bytes,
        offset_of!(Local, sun_family),
        offset_of!(Ipv4, sin_family),
        offset_of!(Ipv6, sin6_family),
    ) {
        (2, 0, 0, 0) => Some(SocketAddressHeader::NativeFamily),
        (1, 1, 1, 1) => Some(SocketAddressHeader::LengthAndFamily),
        _ => None,
    }
}
