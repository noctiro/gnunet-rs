//! Bounded Linux original-destination and pktinfo control records.
use super::{address, invalid_data};
use std::{
    io,
    mem::{align_of, size_of},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroU32,
    ptr,
};

const fn align(bytes: usize) -> usize {
    (bytes + size_of::<usize>() - 1) & !(size_of::<usize>() - 1)
}
const HEADER: usize = align(size_of::<libc::cmsghdr>());
const fn space(bytes: usize) -> usize {
    HEADER + align(bytes)
}
const CAPACITY: usize =
    space(size_of::<libc::sockaddr_in6>()) + space(size_of::<libc::in6_pktinfo>());
const WORDS: usize = CAPACITY.div_ceil(size_of::<usize>());
const _: () = assert!(align_of::<libc::cmsghdr>() <= align_of::<usize>());

pub(super) struct Control([usize; WORDS]);

pub(super) struct Observed {
    pub(super) original: SocketAddr,
    pub(super) interface: NonZeroU32,
}

impl Control {
    pub(super) const fn new() -> Self {
        Self([0; WORDS])
    }

    pub(super) const fn capacity(&self) -> usize {
        size_of::<Self>()
    }

    pub(super) fn as_mut_ptr(&mut self) -> *mut libc::c_void {
        self.0.as_mut_ptr().cast()
    }

    #[expect(
        unsafe_code,
        reason = "Only bounded initialized native cmsghdr and integer-only pktinfo fields are copied unaligned; selected sockaddr payloads have exact checked lengths"
    )]
    pub(super) fn parse(&self, used: usize, ipv4: bool) -> io::Result<Observed> {
        if used > self.capacity() {
            return Err(invalid_data("oversized transparent DNS ancillary extent"));
        }
        // SAFETY: the complete control buffer is initialized; used is bounded.
        let bytes = unsafe { std::slice::from_raw_parts(self.0.as_ptr().cast::<u8>(), used) };
        let mut offset = 0;
        let mut original = None;
        let mut packet = None;
        while offset < bytes.len() {
            let remaining = &bytes[offset..];
            if remaining.len() < HEADER {
                return Err(invalid_data("short transparent DNS ancillary header"));
            }
            // SAFETY: header extent is initialized and contains integer fields;
            // the unaligned copy does not assume malicious lengths are aligned.
            let header = unsafe { remaining.as_ptr().cast::<libc::cmsghdr>().read_unaligned() };
            let length = header.cmsg_len;
            if length < HEADER || length > remaining.len() {
                return Err(invalid_data("invalid transparent DNS ancillary length"));
            }
            let body = &remaining[HEADER..length];
            match (header.cmsg_level, header.cmsg_type) {
                (libc::IPPROTO_IP, libc::IP_ORIGDSTADDR) => {
                    if !ipv4 || original.is_some() {
                        return Err(invalid_data(
                            "duplicate or wrong-family original DNS address",
                        ));
                    }
                    original = Some(address::decode_bytes(body, true)?);
                }
                (libc::IPPROTO_IPV6, libc::IPV6_ORIGDSTADDR) => {
                    if ipv4 || original.is_some() {
                        return Err(invalid_data(
                            "duplicate or wrong-family original DNS address",
                        ));
                    }
                    original = Some(address::decode_bytes(body, false)?);
                }
                (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
                    if !ipv4 || packet.is_some() || body.len() != size_of::<libc::in_pktinfo>() {
                        return Err(invalid_data("invalid or duplicate IPv4 DNS pktinfo"));
                    }
                    // SAFETY: the exact native integer-only pktinfo is initialized.
                    let info = unsafe { body.as_ptr().cast::<libc::in_pktinfo>().read_unaligned() };
                    let interface = u32::try_from(info.ipi_ifindex)
                        .ok()
                        .and_then(NonZeroU32::new)
                        .ok_or_else(|| invalid_data("missing transparent DNS ingress interface"))?;
                    // ipi_spec_dst is a local routing observation, not necessarily
                    // the intercepted IP header's destination. Compare ipi_addr.
                    packet = Some((
                        IpAddr::V4(Ipv4Addr::from(info.ipi_addr.s_addr.to_ne_bytes())),
                        interface,
                    ));
                }
                (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
                    if ipv4 || packet.is_some() || body.len() != size_of::<libc::in6_pktinfo>() {
                        return Err(invalid_data("invalid or duplicate IPv6 DNS pktinfo"));
                    }
                    // SAFETY: the exact native integer-only pktinfo is initialized.
                    let info =
                        unsafe { body.as_ptr().cast::<libc::in6_pktinfo>().read_unaligned() };
                    let interface = NonZeroU32::new(info.ipi6_ifindex)
                        .ok_or_else(|| invalid_data("missing transparent DNS ingress interface"))?;
                    packet = Some((
                        IpAddr::V6(Ipv6Addr::from(info.ipi6_addr.s6_addr)),
                        interface,
                    ));
                }
                _ => {}
            }
            // A final native record can omit its alignment padding. Partial
            // padding plus another incomplete header is not a complete record.
            let padded = align(length);
            if padded > remaining.len() {
                if length == remaining.len() {
                    break;
                }
                return Err(invalid_data("truncated transparent DNS ancillary padding"));
            }
            offset += padded;
        }
        let original = original.ok_or_else(|| invalid_data("missing original DNS destination"))?;
        let (destination, interface) = packet.ok_or_else(|| invalid_data("missing DNS pktinfo"))?;
        if original.ip() != destination {
            return Err(invalid_data(
                "contradictory original DNS destination and pktinfo",
            ));
        }
        Ok(Observed {
            original,
            interface,
        })
    }

    #[expect(
        unsafe_code,
        reason = "Only fully initialized native integer-only IPv4/IPv6 pktinfo is copied into bounded aligned control storage"
    )]
    pub(super) fn outgoing(local: SocketAddr, interface: NonZeroU32) -> io::Result<(Self, usize)> {
        let mut control = Self::new();
        let mut used = 0;
        match local {
            SocketAddr::V4(local) => {
                let info = libc::in_pktinfo {
                    ipi_ifindex: i32::try_from(interface.get()).map_err(|_| {
                        invalid_data("transparent DNS interface exceeds native range")
                    })?,
                    ipi_spec_dst: libc::in_addr {
                        s_addr: u32::from_ne_bytes(local.ip().octets()),
                    },
                    ipi_addr: libc::in_addr { s_addr: 0 },
                };
                // SAFETY: the exact initialized pktinfo has no references or
                // constrained bit patterns and fits the owned control buffer.
                unsafe { control.push(&mut used, libc::IPPROTO_IP, libc::IP_PKTINFO, &info) }?;
            }
            SocketAddr::V6(local) => {
                let info = libc::in6_pktinfo {
                    ipi6_addr: libc::in6_addr {
                        s6_addr: local.ip().octets(),
                    },
                    ipi6_ifindex: interface.get(),
                };
                // SAFETY: same exact initialized integer-only pktinfo contract.
                unsafe { control.push(&mut used, libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, &info) }?;
            }
        }
        Ok((control, used))
    }

    /// Append only a fully initialized native integer-only ABI record.
    #[expect(
        unsafe_code,
        reason = "The caller supplies the exact initialized native ancillary payload; bounded unaligned writes stay within owned control storage"
    )]
    unsafe fn push<T>(
        &mut self,
        used: &mut usize,
        level: i32,
        kind: i32,
        value: &T,
    ) -> io::Result<()> {
        let length = HEADER + size_of::<T>();
        let end = used
            .checked_add(space(size_of::<T>()))
            .filter(|end| *end <= self.capacity())
            .ok_or_else(|| invalid_data("transparent DNS control storage overflow"))?;
        let header = libc::cmsghdr {
            cmsg_len: length,
            cmsg_level: level,
            cmsg_type: kind,
        };
        // SAFETY: the checked complete extent is owned and initialized. The
        // original native payload is borrowed and its bytes remain live.
        unsafe {
            let destination = self.0.as_mut_ptr().cast::<u8>().add(*used);
            destination.cast::<libc::cmsghdr>().write_unaligned(header);
            ptr::copy_nonoverlapping(
                ptr::from_ref(value).cast::<u8>(),
                destination.add(HEADER),
                size_of::<T>(),
            );
        }
        *used = end;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[expect(
        unsafe_code,
        reason = "Tests append only initialized native sockaddr integer fields to exercise the actual ancillary parser without sockets"
    )]
    fn add_destination(
        control: &mut Control,
        used: &mut usize,
        address: SocketAddr,
    ) -> io::Result<()> {
        let (native, _) = address::encode(address);
        if address.is_ipv4() {
            // SAFETY: encode initialized the full same-family native address.
            let native = unsafe { ptr::from_ref(&native).cast::<libc::sockaddr_in>().read() };
            // SAFETY: original initialized integer-only sockaddr record.
            unsafe { control.push(used, libc::IPPROTO_IP, libc::IP_ORIGDSTADDR, &native) }
        } else {
            // SAFETY: same-family initialized sockaddr_in6.
            let native = unsafe { ptr::from_ref(&native).cast::<libc::sockaddr_in6>().read() };
            // SAFETY: original initialized integer-only sockaddr record.
            unsafe { control.push(used, libc::IPPROTO_IPV6, libc::IPV6_ORIGDSTADDR, &native) }
        }
    }

    #[test]
    fn destination_metadata_requires_complete_consistent_unique_records() -> io::Result<()> {
        let interface = NonZeroU32::new(7).ok_or_else(|| invalid_data("test interface"))?;
        let original = "[2001:db8::53]:53"
            .parse::<SocketAddr>()
            .map_err(io::Error::other)?;
        let (mut control, mut used) = Control::outgoing(original, interface)?;
        add_destination(&mut control, &mut used, original)?;
        let observed = control.parse(used, false)?;
        if observed.original != original || observed.interface != interface {
            return Err(invalid_data(
                "ancillary parser changed original destination or ingress",
            ));
        }
        if control.parse(used - 1, false).is_ok() || control.parse(used, true).is_ok() {
            return Err(invalid_data(
                "accepted truncated or wrong-family DNS metadata",
            ));
        }

        let other = "[2001:db8::54]:53"
            .parse::<SocketAddr>()
            .map_err(io::Error::other)?;
        let (mut conflict, mut used) = Control::outgoing(other, interface)?;
        add_destination(&mut conflict, &mut used, original)?;
        if conflict.parse(used, false).is_ok() {
            return Err(invalid_data(
                "accepted conflicting DNS metadata destinations",
            ));
        }

        let mut duplicate = Control::new();
        let mut used = 0;
        let ipv4 = "192.0.2.53:53"
            .parse::<SocketAddr>()
            .map_err(io::Error::other)?;
        add_destination(&mut duplicate, &mut used, ipv4)?;
        add_destination(&mut duplicate, &mut used, ipv4)?;
        if duplicate.parse(used, true).is_ok() {
            return Err(invalid_data("accepted duplicate original DNS destinations"));
        }
        Ok(())
    }

    #[test]
    #[expect(
        unsafe_code,
        reason = "Only initialized native pktinfo integers are appended to exercise distinct packet/local-routing addresses without a socket"
    )]
    fn ipv4_destination_uses_packet_address_not_local_route_address() -> io::Result<()> {
        let mut control = Control::new();
        let mut used = 0;
        let original = "192.0.2.53:53"
            .parse::<SocketAddr>()
            .map_err(io::Error::other)?;
        let info = libc::in_pktinfo {
            ipi_ifindex: 7,
            ipi_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes([192, 0, 2, 53]),
            },
            ipi_spec_dst: libc::in_addr {
                s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
            },
        };
        // SAFETY: this exact native pktinfo contains only initialized integers.
        unsafe { control.push(&mut used, libc::IPPROTO_IP, libc::IP_PKTINFO, &info) }?;
        add_destination(&mut control, &mut used, original)?;
        let observed = control.parse(used, true)?;
        if observed.original != original || observed.interface.get() != 7 {
            return Err(invalid_data(
                "IPv4 metadata confused packet and local route addresses",
            ));
        }
        Ok(())
    }
}
