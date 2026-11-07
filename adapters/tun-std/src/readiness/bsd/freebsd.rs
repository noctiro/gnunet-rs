//! FreeBSD in6_var.h address-specific query ABI, independent of Darwin layouts.
use super::*;
use std::{mem::size_of, os::fd::AsRawFd};

// The largest in6_ifreq union member is icmp6_ifstat: 17 input and
// 17 output uint64_t counters. Its extent/alignment and both commands are
// independently checked against the running FreeBSD host's installed headers.
#[repr(C)]
union Value {
    address: libc::sockaddr_in6,
    flags: libc::c_int,
    storage: [u64; 34],
}
#[repr(C)]
struct Request {
    name: [libc::c_char; libc::IFNAMSIZ],
    value: Value,
}
const GET_NETMASK: libc::c_ulong = nix::request_code_readwrite!(b'i', 37, size_of::<Request>());
const GET_FLAGS: libc::c_ulong = nix::request_code_readwrite!(b'i', 73, size_of::<Request>());
pub(super) const TENTATIVE: u32 = 0x02;
pub(super) const DUPLICATED: u32 = 0x04;
pub(super) const DETACHED: u32 = 0x08;

pub(super) fn netmask(fd: &OwnedFd, interface: &Info, address: Ipv6Addr) -> io::Result<[u8; 16]> {
    let mut req = request(interface, address)?;
    ioctl(fd, GET_NETMASK, &mut req)?;
    #[expect(
        unsafe_code,
        reason = "Successful FreeBSD SIOCGIFNETMASK_IN6 initialized the sockaddr member of this exact native request"
    )]
    // SAFETY: mask bytes are read only after the corresponding native getter.
    Ok(unsafe { req.value.address }.sin6_addr.s6_addr)
}
pub(super) fn flags(fd: &OwnedFd, interface: &Info, address: Ipv6Addr) -> io::Result<u32> {
    let mut req = request(interface, address)?;
    ioctl(fd, GET_FLAGS, &mut req)?;
    #[expect(
        unsafe_code,
        reason = "Successful FreeBSD SIOCGIFAFLAG_IN6 initialized this exact flags6 integer union member"
    )]
    // SAFETY: the native getter wrote this initialized request's flags output.
    Ok(unsafe { req.value.flags } as u32)
}
fn request(interface: &Info, address: Ipv6Addr) -> io::Result<Request> {
    let mut req = Request {
        name: [0; libc::IFNAMSIZ],
        value: Value { storage: [0; 34] },
    };
    let name = crate::platform::name(&interface.name)?;
    for (a, b) in req.name.iter_mut().zip(name.as_bytes_with_nul()) {
        *a = *b as libc::c_char;
    }
    req.value.address = sockaddr(interface, address);
    Ok(req)
}
fn ioctl(fd: &OwnedFd, command: libc::c_ulong, req: &mut Request) -> io::Result<()> {
    #[expect(
        unsafe_code,
        reason = "Fixed read-only FreeBSD commands borrow exact repr(C) in6_ifreq storage whose entire union was initialized, with a bounded native name/address"
    )]
    // SAFETY: the command encodes this request's native extent; no pointer escapes.
    let result = unsafe { libc::ioctl(fd.as_raw_fd(), command, req as *mut Request) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn query_layout_matches_installed_freebsd_headers() -> io::Result<()> {
        crate::native_abi::check(
            "freebsd_ipv6_abi.c",
            &[
                size_of::<Request>() as u64,
                std::mem::align_of::<Request>() as u64,
                std::mem::offset_of!(Request, value) as u64,
                size_of::<Value>() as u64,
                GET_NETMASK,
                GET_FLAGS,
                TENTATIVE.into(),
                DUPLICATED.into(),
                DETACHED.into(),
            ],
        )
    }
}
