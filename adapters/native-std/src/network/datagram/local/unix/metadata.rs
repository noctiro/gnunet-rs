//! Unix UDP destination observation and source selection.
use super::{LocalReplyPath, invalid};
use std::{
    io,
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroU32,
    os::fd::{AsRawFd, BorrowedFd},
    ptr,
};

#[expect(
    unsafe_code,
    reason = "CMSG_LEN determines the configured native header alignment"
)]
// SAFETY: zero payload length is permitted and requires no memory access.
const HEADER: usize = unsafe { libc::CMSG_LEN(0) as usize };
const CAPACITY: usize = 128;

#[repr(C, align(8))]
pub(super) struct Control([u8; CAPACITY]);

impl Control {
    pub(super) const fn new() -> Self {
        Self([0; CAPACITY])
    }

    pub(super) const fn capacity(&self) -> usize {
        self.0.len()
    }

    pub(super) fn as_mut_ptr(&mut self) -> *mut libc::c_void {
        self.0.as_mut_ptr().cast()
    }

    #[expect(
        unsafe_code,
        reason = "native header and ancillary payloads are read only from checked initialized byte extents"
    )]
    pub(super) fn destination(&self, used: usize, ipv4: bool) -> io::Result<(IpAddr, NonZeroU32)> {
        let mut records = self
            .0
            .get(..used)
            .ok_or_else(|| invalid("oversized UDP control data"))?;
        let mut destination = None;
        let mut ingress = None;
        while !records.is_empty() {
            if records.len() < HEADER {
                return Err(invalid("short UDP control header"));
            }
            // SAFETY: HEADER includes the full initialized native cmsghdr.
            let header = unsafe { records.as_ptr().cast::<libc::cmsghdr>().read_unaligned() };
            let length = native_size(header.cmsg_len)?;
            let value = records
                .get(HEADER..length)
                .ok_or_else(|| invalid("bad UDP control extent"))?;
            match (header.cmsg_level, header.cmsg_type) {
                (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
                    if ipv4 || value.len() != size_of::<libc::in6_pktinfo>() {
                        return Err(invalid("invalid IPv6 UDP packet info"));
                    }
                    // SAFETY: exact, initialized native pktinfo.
                    let info =
                        unsafe { value.as_ptr().cast::<libc::in6_pktinfo>().read_unaligned() };
                    insert(
                        &mut destination,
                        Ipv6Addr::from(info.ipi6_addr.s6_addr).into(),
                    )?;
                    insert(&mut ingress, info.ipi6_ifindex)?;
                }
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
                    if !ipv4 || value.len() != size_of::<libc::in_pktinfo>() {
                        return Err(invalid("invalid IPv4 UDP packet info"));
                    }
                    // SAFETY: exact, initialized native pktinfo.
                    let info =
                        unsafe { value.as_ptr().cast::<libc::in_pktinfo>().read_unaligned() };
                    insert(
                        &mut destination,
                        Ipv4Addr::from(info.ipi_addr.s_addr.to_ne_bytes()).into(),
                    )?;
                    #[cfg(target_os = "linux")]
                    let ingress_index = u32::try_from(info.ipi_ifindex)
                        .map_err(|_| invalid("negative IPv4 UDP ingress"))?;
                    #[cfg(target_os = "macos")]
                    let ingress_index = info.ipi_ifindex;
                    insert(&mut ingress, ingress_index)?;
                }
                #[cfg(target_os = "freebsd")]
                (libc::IPPROTO_IP, libc::IP_RECVDSTADDR) => {
                    let octets: [u8; 4] = value
                        .try_into()
                        .map_err(|_| invalid("bad IPv4 UDP destination extent"))?;
                    if !ipv4 {
                        return Err(invalid("unexpected IPv4 UDP destination"));
                    }
                    insert(&mut destination, Ipv4Addr::from(octets).into())?;
                }
                #[cfg(target_os = "freebsd")]
                (libc::IPPROTO_IP, libc::IP_RECVIF) => {
                    if !ipv4 {
                        return Err(invalid("unexpected IPv4 UDP ingress"));
                    }
                    insert(&mut ingress, freebsd_ingress(value)?)?;
                }
                _ => {}
            }
            if length == records.len() {
                break;
            }
            // SAFETY: value.len() is bounded by the 128-byte owned buffer.
            let padded = unsafe { libc::CMSG_SPACE(value.len() as u32) as usize };
            records = records
                .get(padded..)
                .ok_or_else(|| invalid("partial UDP control padding"))?;
        }
        let destination = destination.ok_or_else(|| invalid("missing UDP destination address"))?;
        let ingress = ingress
            .and_then(NonZeroU32::new)
            .ok_or_else(|| invalid("missing UDP ingress interface"))?;
        Ok((destination, ingress))
    }

    #[expect(
        unsafe_code,
        reason = "only initialized integer-only native source-control records are encoded"
    )]
    pub(super) fn reply(&mut self, path: &LocalReplyPath) -> io::Result<usize> {
        match path.local {
            SocketAddr::V4(local) => {
                let source = libc::in_addr {
                    s_addr: u32::from_ne_bytes(local.ip().octets()),
                };
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                {
                    let info = libc::in_pktinfo {
                        ipi_ifindex: 0,
                        ipi_spec_dst: source,
                        ipi_addr: libc::in_addr { s_addr: 0 },
                    };
                    // SAFETY: initialized native IPv4 pktinfo.
                    unsafe { self.write(libc::IPPROTO_IP, libc::IP_PKTINFO, &info) }
                }
                #[cfg(target_os = "freebsd")]
                // SAFETY: initialized exact IPv4 source address.
                unsafe {
                    self.write(libc::IPPROTO_IP, libc::IP_SENDSRCADDR, &source)
                }
            }
            SocketAddr::V6(local) => {
                let scoped = local.scope_id() != 0
                    || matches!(path.peer, SocketAddr::V6(peer) if peer.scope_id() != 0);
                let info = libc::in6_pktinfo {
                    ipi6_addr: libc::in6_addr {
                        s6_addr: local.ip().octets(),
                    },
                    ipi6_ifindex: if scoped { path.ingress.get() } else { 0 },
                };
                // SAFETY: initialized native IPv6 pktinfo.
                unsafe { self.write(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, &info) }
            }
        }
    }

    #[expect(
        unsafe_code,
        reason = "checked writes fit the owned native control buffer"
    )]
    unsafe fn write<T>(&mut self, level: i32, kind: i32, value: &T) -> io::Result<usize> {
        let length = size_of::<T>();
        // SAFETY: this leaf calls with only small native ABI payloads.
        let space = unsafe { libc::CMSG_SPACE(length as u32) as usize };
        if space > self.capacity() || length > space.saturating_sub(HEADER) {
            return Err(invalid("UDP reply control extent does not fit"));
        }
        let header = libc::cmsghdr {
            cmsg_len: (HEADER + length) as _,
            cmsg_level: level,
            cmsg_type: kind,
        };
        // SAFETY: the caller provides an initialized integer-only record and
        // the checked header and payload extents are within the buffer.
        unsafe {
            self.0
                .as_mut_ptr()
                .cast::<libc::cmsghdr>()
                .write_unaligned(header);
            ptr::copy_nonoverlapping(
                ptr::from_ref(value).cast::<u8>(),
                self.0.as_mut_ptr().add(HEADER),
                length,
            );
        }
        Ok(space)
    }
}

pub(super) fn native_size(size: impl TryInto<usize>) -> io::Result<usize> {
    size.try_into()
        .map_err(|_| invalid("invalid UDP control extent"))
}

fn insert<T>(slot: &mut Option<T>, value: T) -> io::Result<()> {
    if slot.replace(value).is_some() {
        return Err(invalid("duplicate UDP destination or ingress"));
    }
    Ok(())
}

#[cfg(target_os = "freebsd")]
fn freebsd_ingress(value: &[u8]) -> io::Result<u32> {
    use std::mem::offset_of;
    let family = offset_of!(libc::sockaddr_dl, sdl_family);
    let index = offset_of!(libc::sockaddr_dl, sdl_index);
    let minimum = offset_of!(libc::sockaddr_dl, sdl_data);
    if value.len() < minimum
        || usize::from(value[0]) != value.len()
        || i32::from(value[family]) != libc::AF_LINK
    {
        return Err(invalid("invalid variable-length UDP link address"));
    }
    let native = [value[index], value[index + 1]];
    Ok(u32::from(u16::from_ne_bytes(native)))
}

pub(super) fn enable(socket: BorrowedFd<'_>, ipv4: bool) -> io::Result<()> {
    if !ipv4 {
        return set(socket, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO);
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    return set(socket, libc::IPPROTO_IP, libc::IP_PKTINFO);
    #[cfg(target_os = "freebsd")]
    {
        set(socket, libc::IPPROTO_IP, libc::IP_RECVDSTADDR)?;
        set(socket, libc::IPPROTO_IP, libc::IP_RECVIF)
    }
}

#[expect(
    unsafe_code,
    reason = "setsockopt borrows one live socket and initialized scalar"
)]
fn set(socket: BorrowedFd<'_>, level: i32, option: i32) -> io::Result<()> {
    let value: libc::c_int = 1;
    // SAFETY: the pointer is to an initialized scalar of the supplied extent.
    if unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            ptr::from_ref(&value).cast(),
            size_of::<libc::c_int>() as _,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
