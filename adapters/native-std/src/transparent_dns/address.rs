//! Exact Linux sockaddr conversion and received unicast-scope validation.
use super::{DNS_PORT, invalid_data};
use std::{
    io,
    mem::size_of,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    num::NonZeroU32,
    ptr,
};

#[expect(
    unsafe_code,
    reason = "Zeroed sockaddr_storage is large/aligned enough for the fully initialized same-family native sockaddr written into its start"
)]
pub(super) fn encode(address: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: sockaddr_storage permits a zero scalar/padding representation.
    let mut storage = unsafe { std::mem::zeroed::<libc::sockaddr_storage>() };
    let length = match address {
        SocketAddr::V4(address) => {
            let native = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: address.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(address.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: storage is large and aligned for sockaddr_in, with no
            // existing borrowed value; native has initialized address fields.
            unsafe {
                ptr::from_mut(&mut storage)
                    .cast::<libc::sockaddr_in>()
                    .write(native)
            };
            size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(address) => {
            let native = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: address.port().to_be(),
                sin6_flowinfo: address.flowinfo().to_be(),
                sin6_addr: libc::in6_addr {
                    s6_addr: address.ip().octets(),
                },
                sin6_scope_id: address.scope_id(),
            };
            // SAFETY: same owned storage is large and aligned for sockaddr_in6.
            unsafe {
                ptr::from_mut(&mut storage)
                    .cast::<libc::sockaddr_in6>()
                    .write(native)
            };
            size_of::<libc::sockaddr_in6>()
        }
    };
    (storage, length as libc::socklen_t)
}

#[expect(
    unsafe_code,
    reason = "Only exact-length native sockaddr bytes are borrowed from initialized sockaddr_storage; all selected fields have integer representations"
)]
pub(super) fn decode(
    storage: &libc::sockaddr_storage,
    length: libc::socklen_t,
    ipv4: bool,
) -> io::Result<SocketAddr> {
    let length = usize::try_from(length)
        .map_err(|_| invalid_data("transparent DNS sockaddr length overflow"))?;
    if length > size_of::<libc::sockaddr_storage>() {
        return Err(invalid_data("oversized transparent DNS peer address"));
    }
    // SAFETY: caller owns the initialized complete storage, and length is bounded.
    let bytes = unsafe { std::slice::from_raw_parts(ptr::from_ref(storage).cast::<u8>(), length) };
    decode_bytes(bytes, ipv4)
}

#[expect(
    unsafe_code,
    reason = "Exact-sized native sockaddr bytes are copied unaligned into same-family integer-only ABI records before field decoding"
)]
pub(super) fn decode_bytes(bytes: &[u8], ipv4: bool) -> io::Result<SocketAddr> {
    if ipv4 {
        if bytes.len() != size_of::<libc::sockaddr_in>() {
            return Err(invalid_data("invalid transparent DNS IPv4 address extent"));
        }
        // SAFETY: exact extent holds initialized native integer fields; the
        // copy does not assume the ancillary buffer has sockaddr alignment.
        let native = unsafe { bytes.as_ptr().cast::<libc::sockaddr_in>().read_unaligned() };
        if i32::from(native.sin_family) != libc::AF_INET {
            return Err(invalid_data("contradictory transparent DNS IPv4 family"));
        }
        Ok(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from(native.sin_addr.s_addr.to_ne_bytes()),
            u16::from_be(native.sin_port),
        )))
    } else {
        if bytes.len() != size_of::<libc::sockaddr_in6>() {
            return Err(invalid_data("invalid transparent DNS IPv6 address extent"));
        }
        // SAFETY: as above, the full integer-only sockaddr_in6 is initialized.
        let native = unsafe { bytes.as_ptr().cast::<libc::sockaddr_in6>().read_unaligned() };
        if i32::from(native.sin6_family) != libc::AF_INET6 {
            return Err(invalid_data("contradictory transparent DNS IPv6 family"));
        }
        Ok(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(native.sin6_addr.s6_addr),
            u16::from_be(native.sin6_port),
            u32::from_be(native.sin6_flowinfo),
            native.sin6_scope_id,
        )))
    }
}

pub(super) fn validate(
    peer: SocketAddr,
    original: SocketAddr,
    interface: NonZeroU32,
    peer_interface: NonZeroU32,
) -> io::Result<()> {
    if peer.port() == 0 || original.port() != DNS_PORT || peer.is_ipv4() != original.is_ipv4() {
        return Err(invalid_data(
            "invalid transparent DNS original UDP endpoints",
        ));
    }
    unicast(peer, peer_interface)?;
    unicast(original, interface)
}

fn unicast(address: SocketAddr, interface: NonZeroU32) -> io::Result<()> {
    match address {
        SocketAddr::V4(address) => {
            let ip = address.ip();
            if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
                return Err(invalid_data(
                    "transparent DNS requires IPv4 unicast endpoints",
                ));
            }
        }
        SocketAddr::V6(address) => {
            let ip = address.ip();
            if ip.is_unspecified() || ip.is_multicast() || ip.to_ipv4_mapped().is_some() {
                return Err(invalid_data(
                    "transparent DNS requires native IPv6 unicast endpoints",
                ));
            }
            // A Linux pktinfo interface cannot identify an IPv6 site zone.
            if ip.segments()[0] & 0xffc0 == 0xfec0 {
                return Err(invalid_data(
                    "transparent DNS cannot identify an IPv6 site zone",
                ));
            }
            let scope = if ip.is_unicast_link_local() {
                interface.get()
            } else {
                0
            };
            if address.scope_id() != scope {
                return Err(invalid_data(
                    "missing or contradictory transparent DNS IPv6 scope",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_or_conflicting_scopes_are_not_invented() -> io::Result<()> {
        let interface = NonZeroU32::new(7).ok_or_else(|| invalid_data("test interface"))?;
        let peer = SocketAddr::V6(SocketAddrV6::new(
            "fe80::1".parse().map_err(io::Error::other)?,
            2048,
            0,
            7,
        ));
        let mut original =
            SocketAddrV6::new("fe80::53".parse().map_err(io::Error::other)?, 53, 0, 0);
        if validate(peer, original.into(), interface, interface).is_ok() {
            return Err(invalid_data("accepted missing original IPv6 zone"));
        }
        original.set_scope_id(8);
        if validate(peer, original.into(), interface, interface).is_ok() {
            return Err(invalid_data("accepted conflicting original IPv6 zone"));
        }
        original.set_scope_id(7);
        validate(peer, original.into(), interface, interface)?;
        original.set_ip("2001:db8::53".parse().map_err(io::Error::other)?);
        if validate(peer, original.into(), interface, interface).is_ok() {
            return Err(invalid_data("accepted a zone on an unscoped IPv6 address"));
        }
        original.set_scope_id(0);
        validate(peer, original.into(), interface, interface)?;
        for prefix in [0xfec0, 0xfeff] {
            let ip = Ipv6Addr::new(prefix, 0, 0, 0, 0, 0, 0, 53);
            for scope in [0, interface.get()] {
                let site_destination = SocketAddrV6::new(ip, 53, 0, scope);
                let site_peer = SocketAddrV6::new(ip, 2048, 0, scope);
                if validate(peer, site_destination.into(), interface, interface).is_ok()
                    || validate(site_peer.into(), original.into(), interface, interface).is_ok()
                {
                    return Err(invalid_data(
                        "accepted site scope without the original zone",
                    ));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn native_sockaddrs_preserve_endian_and_zone_fields() -> io::Result<()> {
        for original in [
            "192.0.2.53:53"
                .parse::<SocketAddr>()
                .map_err(io::Error::other)?,
            SocketAddr::V6(SocketAddrV6::new(
                "fe80::53".parse().map_err(io::Error::other)?,
                53,
                0x12345,
                7,
            )),
        ] {
            let (native, length) = encode(original);
            if decode(&native, length, original.is_ipv4())? != original {
                return Err(invalid_data(
                    "native sockaddr did not preserve original endpoint",
                ));
            }
        }
        Ok(())
    }
}
