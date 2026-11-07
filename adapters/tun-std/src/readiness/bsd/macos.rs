//! Darwin SDK in6_ifreq boundary, with no network configuration writes.
use super::*;
use std::os::fd::AsRawFd;
const GET_NETMASK: libc::c_ulong = (libc::SIOCGIFAFLAG_IN6 & !0xff) | 37;
pub(super) const DUPLICATED: u32 = libc::IN6_IFF_DUPLICATED as u32;
pub(super) const TENTATIVE: u32 = (libc::IN6_IFF_TENTATIVE | libc::IN6_IFF_OPTIMISTIC) as u32;
pub(super) const DETACHED: u32 = libc::IN6_IFF_DETACHED as u32;

pub(super) fn netmask(fd: &OwnedFd, interface: &Info, address: Ipv6Addr) -> io::Result<[u8; 16]> {
    let mut req = request(interface, address)?;
    ioctl(fd, GET_NETMASK, &mut req)?;
    #[expect(
        unsafe_code,
        reason = "Successful SIOCGIFNETMASK_IN6 initialized the SDK sockaddr union member; only its initialized mask octets are read"
    )]
    // SAFETY: this exact live request was filled by the mask ioctl.
    Ok(unsafe { req.ifr_ifru.ifru_addr }.sin6_addr.s6_addr)
}
pub(super) fn flags(fd: &OwnedFd, interface: &Info, address: Ipv6Addr) -> io::Result<u32> {
    let mut req = request(interface, address)?;
    ioctl(fd, libc::SIOCGIFAFLAG_IN6, &mut req)?;
    #[expect(
        unsafe_code,
        reason = "Successful SIOCGIFAFLAG_IN6 initialized this exact SDK flags6 output member"
    )]
    // SAFETY: this exact initialized request was filled by the flags ioctl.
    Ok(unsafe { req.ifr_ifru.ifru_flags6 } as u32)
}
fn request(interface: &Info, address: Ipv6Addr) -> io::Result<libc::in6_ifreq> {
    let mut req = libc::in6_ifreq::default();
    let name = crate::platform::name(&interface.name)?;
    for (a, b) in req.ifr_name.iter_mut().zip(name.as_bytes_with_nul()) {
        *a = *b as libc::c_char;
    }
    req.ifr_ifru.ifru_addr = sockaddr(interface, address);
    Ok(req)
}
fn ioctl(fd: &OwnedFd, command: libc::c_ulong, req: &mut libc::in6_ifreq) -> io::Result<()> {
    #[expect(
        unsafe_code,
        reason = "Only fixed read-only SDK IPv6 commands receive this exact initialized exclusive in6_ifreq and bounded name/address"
    )]
    // SAFETY: command ABI matches the live request; no pointer is retained.
    let result = unsafe { libc::ioctl(fd.as_raw_fd(), command, req as *mut libc::in6_ifreq) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
