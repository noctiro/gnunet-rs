//! Numeric raw-packet eligibility, without claiming socket or zone authority.
use super::Address;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(super) fn numeric(address: Address) -> IpAddr {
    match address {
        Address::V4(bytes) => IpAddr::V4(Ipv4Addr::from(bytes)),
        Address::V6(bytes) => IpAddr::V6(Ipv6Addr::from(bytes)),
    }
}

pub(crate) fn unicast(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast(),
        // Mapped addresses describe IPv4 through socket APIs; they are not
        // valid endpoints in an actual IPv6 packet (RFC 4291 section 2.5.5.2).
        IpAddr::V6(ip) => {
            !ip.is_unspecified() && !ip.is_multicast() && ip.to_ipv4_mapped().is_none()
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Scope {
    Unscoped,
    LinkLocal,
    SiteLocal,
}

pub(crate) fn scope(address: IpAddr) -> Scope {
    match address {
        IpAddr::V6(ip) if ip.octets()[0] == 0xfe => match ip.octets()[1] & 0xc0 {
            0x80 => Scope::LinkLocal,
            0xc0 => Scope::SiteLocal,
            _ => Scope::Unscoped,
        },
        _ => Scope::Unscoped,
    }
}
