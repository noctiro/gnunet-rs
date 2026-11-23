//! Qualification of numeric SDK endpoints without interpreting zones as interfaces.
use super::{EndpointRole, EndpointScope, unsupported};
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
};

pub(in crate::dns_proxy) fn numeric_scope(
    address: SocketAddr,
    role: EndpointRole,
) -> io::Result<EndpointScope> {
    match address {
        SocketAddr::V4(address) => qualify_ipv4(*address.ip(), role),
        SocketAddr::V6(address) => qualify_ipv6(*address.ip(), address.scope_id(), role),
    }
}

fn qualify_ipv4(address: Ipv4Addr, role: EndpointRole) -> io::Result<EndpointScope> {
    if address.is_multicast() {
        return Err(multicast(role));
    }
    if role == EndpointRole::UdpReply && (address.is_unspecified() || address.is_broadcast()) {
        return Err(invalid_reply_source());
    }
    Ok(EndpointScope::Unscoped)
}

fn qualify_ipv6(address: Ipv6Addr, zone: u32, role: EndpointRole) -> io::Result<EndpointScope> {
    if let Some(mapped) = address.to_ipv4_mapped() {
        // Eligibility follows the IPv4 address. The retained SDK object and
        // its complete sockaddr/zone representation are never replaced here.
        return qualify_ipv4(mapped, role);
    }
    if role == EndpointRole::UdpReply && address.is_unspecified() {
        return Err(invalid_reply_source());
    }
    if address.is_multicast() {
        // RFC 4291 reserves scopes 0 and F. The global scope is E.
        if matches!(address.octets()[1] & 0x0f, 0 | 15) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "IPv6 multicast address uses a reserved scope",
            ));
        }
        return Err(multicast(role));
    }
    let scope = if address.octets()[0] == 0xfe {
        match address.octets()[1] & 0xc0 {
            0x80 => EndpointScope::LinkLocal,
            // XNU retains legacy site-local scope. Preserve an explicit native
            // zone rather than treating this deprecated prefix as invalid or
            // converting its site zone into an interface index.
            0xc0 => EndpointScope::LegacySiteLocal,
            _ => EndpointScope::Unscoped,
        }
    } else {
        EndpointScope::Unscoped
    };
    if scope.requires_local_endpoint() && zone == 0 {
        return Err(unsupported("scoped DNS endpoint lacks its native zone"));
    }
    Ok(scope)
}

pub(super) fn check_local_zone(
    peer: SocketAddr,
    peer_scope: EndpointScope,
    local: SocketAddr,
) -> io::Result<()> {
    if let (SocketAddr::V6(peer), SocketAddr::V6(local)) = (peer, local)
        && qualify_ipv6(*local.ip(), local.scope_id(), EndpointRole::Local)? == peer_scope
        && local.scope_id() != peer.scope_id()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "original DNS flow endpoints disagree on their native zone",
        ));
    }
    Ok(())
}

fn invalid_reply_source() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "DNS reply source cannot be unspecified or limited broadcast",
    )
}

fn multicast(role: EndpointRole) -> io::Error {
    unsupported(match role {
        EndpointRole::Local => "a native flow local endpoint cannot be multicast",
        EndpointRole::TcpRemote => "TCP cannot use a multicast remote endpoint",
        EndpointRole::UdpReply => "multicast address cannot be a DNS reply source",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn mapped_ipv4_uses_the_same_endpoint_role() {
        for group in [
            Ipv4Addr::new(224, 0, 0, 251),
            Ipv4Addr::new(239, 255, 255, 250),
        ] {
            for role in [
                EndpointRole::Local,
                EndpointRole::TcpRemote,
                EndpointRole::UdpReply,
            ] {
                assert_eq!(
                    qualify_ipv6(group.to_ipv6_mapped(), 7, role).map_err(|error| error.kind()),
                    Err(io::ErrorKind::Unsupported),
                );
            }
        }
        assert_eq!(
            qualify_ipv6(
                Ipv4Addr::LOCALHOST.to_ipv6_mapped(),
                0,
                EndpointRole::UdpReply,
            )
            .map_err(|error| error.kind()),
            Ok(EndpointScope::Unscoped),
        );
    }

    #[test]
    fn invalid_reply_sources_do_not_change_local_wildcard_rules() {
        for address in [Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST] {
            assert_eq!(
                qualify_ipv4(address, EndpointRole::UdpReply).map_err(|error| error.kind()),
                Err(io::ErrorKind::InvalidInput),
            );
            assert_eq!(
                qualify_ipv6(address.to_ipv6_mapped(), 0, EndpointRole::UdpReply)
                    .map_err(|error| error.kind()),
                Err(io::ErrorKind::InvalidInput),
            );
        }
        for address in [
            Ipv6Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED.to_ipv6_mapped(),
        ] {
            assert_eq!(
                qualify_ipv6(address, 0, EndpointRole::Local).map_err(|error| error.kind()),
                Ok(EndpointScope::Unscoped),
            );
            assert_eq!(
                qualify_ipv6(address, 0, EndpointRole::UdpReply).map_err(|error| error.kind()),
                Err(io::ErrorKind::InvalidInput),
            );
        }
        assert_eq!(
            qualify_ipv4(Ipv4Addr::UNSPECIFIED, EndpointRole::Local).map_err(|error| error.kind()),
            Ok(EndpointScope::Unscoped),
        );
    }
}
