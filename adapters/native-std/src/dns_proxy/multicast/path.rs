//! Original unicast receive destination and concrete multicast responder checks.
use crate::dns_proxy::sdk::{Endpoint, EndpointRole, EndpointScope, numeric_scope};
use std::{io, net::SocketAddr};

#[derive(Debug)]
pub(super) struct Path {
    local: Endpoint,
    addresses: Addresses,
}

impl Path {
    pub(super) fn new(local: &Endpoint, group: &Endpoint) -> io::Result<Self> {
        let addresses = Addresses::new(local.socket_addr()?, group.socket_addr()?)?;
        Ok(Self {
            local: local.clone(),
            addresses,
        })
    }

    pub(super) fn accept(&self, local: &Endpoint, sender: &Endpoint) -> io::Result<()> {
        sender.qualify_flow_peer(EndpointRole::UdpReply, Some(&self.local))?;
        self.addresses
            .accept(local.socket_addr()?, sender.socket_addr()?)
    }

    pub(super) fn require_interface(&self, index: u32) -> io::Result<()> {
        self.addresses.require_interface(index)
    }
}

/// Opaque endpoints keep their ordinary flow path. A numeric group must pass
/// the native multicast profile before the caller can select this relay.
pub(super) fn is_multicast_destination(endpoint: &Endpoint) -> io::Result<bool> {
    if !endpoint.is_address() {
        return Ok(false);
    }
    multicast_destination(endpoint.socket_addr()?)
}

#[derive(Clone, Copy, Debug)]
struct Addresses {
    local: SocketAddr,
    group: SocketAddr,
}

impl Addresses {
    fn new(local: SocketAddr, group: SocketAddr) -> io::Result<Self> {
        unicast(local)?;
        if !multicast_destination(group)? || local.is_ipv4() != group.is_ipv4() {
            return Err(invalid(
                "multicast flow endpoint family or destination differs",
            ));
        }
        group_zone(group, local)?;
        Ok(Self { local, group })
    }

    fn accept(self, local: SocketAddr, sender: SocketAddr) -> io::Result<()> {
        // Receiving a multicast packet on the group does not prove that the
        // original application joined it. Only its exact unicast destination
        // can authorize a response for this narrower relay profile.
        if !same_endpoint(self.local, local) {
            return Err(invalid(
                "multicast response has a foreign local destination",
            ));
        }
        unicast(sender)?;
        if sender.is_ipv4() != self.local.is_ipv4() || sender.port() != self.group.port() {
            return Err(invalid(
                "multicast response has a foreign sender family or port",
            ));
        }
        same_scope_zone(self.local, sender)?;
        group_zone(self.group, sender)
    }

    fn require_interface(self, index: u32) -> io::Result<()> {
        for address in [self.local, self.group] {
            let SocketAddr::V6(address) = address else {
                continue;
            };
            let ip = address.ip();
            let link =
                ip.is_unicast_link_local() || ip.is_multicast() && ip.octets()[1] & 0x0f == 2;
            if !link {
                continue;
            }
            if index == 0 {
                return Err(unsupported(
                    "original bound interface has no index for its IPv6 link zone",
                ));
            }
            if address.scope_id() != index {
                return Err(invalid(
                    "IPv6 link zone differs from the original bound interface",
                ));
            }
        }
        Ok(())
    }
}

fn unicast(address: SocketAddr) -> io::Result<()> {
    if address.port() == 0 {
        return Err(invalid("multicast flow endpoint has no port"));
    }
    if matches!(address, SocketAddr::V6(ip) if ip.ip().to_ipv4_mapped().is_some()) {
        return Err(unsupported(
            "mapped addresses have no unambiguous multicast family",
        ));
    }
    numeric_scope(address, EndpointRole::UdpReply)?;
    Ok(())
}

fn multicast_destination(address: SocketAddr) -> io::Result<bool> {
    match address {
        SocketAddr::V4(ip) => {
            if !ip.ip().is_multicast() {
                return Ok(false);
            }
        }
        SocketAddr::V6(ip) => {
            if ip.ip().to_ipv4_mapped().is_some_and(|ip| ip.is_multicast()) {
                return Err(unsupported("mapped multicast destination is ambiguous"));
            }
            if !ip.ip().is_multicast() {
                return Ok(false);
            }
            let scope = ip.ip().octets()[1] & 0x0f;
            if matches!(scope, 0 | 15) {
                return Err(invalid("multicast destination has a reserved IPv6 scope"));
            }
            if !matches!(scope, 1 | 2 | 3 | 4 | 5 | 8 | 14) {
                return Err(unsupported(
                    "multicast destination has an unknown IPv6 scope",
                ));
            }
            if scope != 14 && ip.scope_id() == 0 {
                return Err(unsupported(
                    "scoped multicast destination lacks its native zone",
                ));
            }
        }
    }
    if address.port() == 0 {
        return Err(invalid("multicast destination has no port"));
    }
    Ok(true)
}

fn same_endpoint(original: SocketAddr, actual: SocketAddr) -> bool {
    match (original, actual) {
        (SocketAddr::V4(original), SocketAddr::V4(actual)) => original == actual,
        (SocketAddr::V6(original), SocketAddr::V6(actual)) => {
            original.ip() == actual.ip()
                && original.port() == actual.port()
                && original.scope_id() == actual.scope_id()
        }
        _ => false,
    }
}

fn same_scope_zone(local: SocketAddr, sender: SocketAddr) -> io::Result<()> {
    if let (SocketAddr::V6(local), SocketAddr::V6(sender)) = (local, sender) {
        let local_scope = numeric_scope(local.into(), EndpointRole::UdpReply)?;
        let sender_scope = numeric_scope(sender.into(), EndpointRole::UdpReply)?;
        if local_scope != EndpointScope::Unscoped
            && local_scope == sender_scope
            && local.scope_id() != sender.scope_id()
        {
            return Err(invalid(
                "multicast response differs from its original native zone",
            ));
        }
    }
    Ok(())
}

fn group_zone(group: SocketAddr, address: SocketAddr) -> io::Result<()> {
    if let (SocketAddr::V6(group), SocketAddr::V6(address)) = (group, address) {
        let scope = group.ip().octets()[1] & 0x0f;
        let address_scope = numeric_scope(address.into(), EndpointRole::UdpReply)?;
        // Zone numbers are comparable only within the same scope. In
        // particular, a site zone is never interpreted as an interface index.
        if matches!(
            (scope, address_scope),
            (2, EndpointScope::LinkLocal) | (5, EndpointScope::LegacySiteLocal)
        ) && group.scope_id() != address.scope_id()
        {
            return Err(invalid(
                "multicast group and unicast endpoint native zones differ",
            ));
        }
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

#[cfg(test)]
mod tests {
    use super::{Addresses, multicast_destination};
    use std::{
        io,
        net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    };

    fn v6(prefix: u16, tail: u16, port: u16, zone: u32) -> SocketAddr {
        SocketAddrV6::new(Ipv6Addr::new(prefix, 0, 0, 0, 0, 0, 0, tail), port, 0, zone).into()
    }

    #[test]
    fn ambient_group_packets_and_other_original_sockets_cannot_become_replies() -> io::Result<()> {
        let local = SocketAddr::from(([192, 0, 2, 1], 53000));
        let group = SocketAddr::from(([239, 1, 2, 3], 53));
        let sender = SocketAddr::from(([192, 0, 2, 53], 53));
        let path = Addresses::new(local, group)?;
        path.accept(local, sender)?;
        for (actual_local, actual_sender) in [
            (SocketAddr::from(([239, 1, 2, 3], 53000)), sender),
            (SocketAddr::from(([192, 0, 2, 2], 53000)), sender),
            (SocketAddr::from(([192, 0, 2, 1], 53001)), sender),
            (local, SocketAddr::from(([192, 0, 2, 53], 54))),
            (local, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 53))),
            (local, SocketAddr::from((Ipv4Addr::BROADCAST, 53))),
            (local, group),
            (local, v6(0x2001, 53, 53, 0)),
        ] {
            if path.accept(actual_local, actual_sender).is_ok() {
                return Err(io::Error::other("unowned multicast response was admitted"));
            }
        }
        Ok(())
    }

    #[test]
    fn native_link_and_site_zones_stay_distinct_from_interface_indices() -> io::Result<()> {
        for (prefix, group_prefix, zone) in [(0xfe80, 0xff02, 7), (0xfec0, 0xff05, 29)] {
            let local = v6(prefix, 1, 53000, zone);
            let group = v6(group_prefix, 53, 53, zone);
            let sender = v6(prefix, 2, 53, zone);
            let path = Addresses::new(local, group)?;
            let SocketAddr::V6(mut actual) = local else {
                return Err(io::Error::other("IPv6 fixture lost its family"));
            };
            actual.set_flowinfo(0x1234);
            path.accept(actual.into(), sender)?;
            for result in [
                path.accept(v6(prefix, 1, 53000, zone + 1), sender),
                path.accept(local, v6(prefix, 2, 53, zone + 1)),
                path.accept(local, v6(prefix, 2, 53, 0)),
                Addresses::new(local, v6(group_prefix, 53, 53, zone + 1)).map(|_| ()),
                Addresses::new(local, v6(group_prefix, 53, 53, 0)).map(|_| ()),
            ] {
                if result.is_ok() {
                    return Err(io::Error::other(
                        "multicast native zone was replaced or omitted",
                    ));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn group_selection_preserves_numeric_family_and_refuses_reserved_scopes() -> io::Result<()> {
        for endpoint in [
            SocketAddr::from(([239, 1, 2, 3], 53)),
            v6(0xff02, 53, 53, 7),
            v6(0xff05, 53, 53, 29),
            v6(0xff0e, 53, 53, 0),
        ] {
            if !multicast_destination(endpoint)? {
                return Err(io::Error::other(
                    "valid multicast group lost its classification",
                ));
            }
        }
        for endpoint in [
            v6(0xff00, 53, 53, 7),
            v6(0xff0f, 53, 53, 7),
            v6(0xff06, 53, 53, 7),
            v6(0xff02, 53, 53, 0),
            SocketAddr::from(([239, 1, 2, 3], 0)),
            SocketAddr::from((Ipv4Addr::new(239, 1, 2, 3).to_ipv6_mapped(), 53)),
        ] {
            if multicast_destination(endpoint).is_ok() {
                return Err(io::Error::other("ambiguous multicast group was admitted"));
            }
        }
        if multicast_destination(SocketAddr::from(([192, 0, 2, 53], 53)))? {
            return Err(io::Error::other(
                "ordinary unicast was selected as multicast",
            ));
        }
        Ok(())
    }

    #[test]
    fn bound_interface_qualifies_only_original_link_zones() -> io::Result<()> {
        for (local, group) in [
            (v6(0x2001, 1, 53000, 0), v6(0xff02, 53, 53, 7)),
            (v6(0xfe80, 1, 53000, 7), v6(0xff0e, 53, 53, 0)),
        ] {
            let addresses = Addresses::new(local, group)?;
            addresses.require_interface(7)?;
            for index in [0, 8] {
                if addresses.require_interface(index).is_ok() {
                    return Err(io::Error::other(
                        "original IPv6 link zone lost its bound-interface check",
                    ));
                }
            }
        }
        for (local, group) in [
            (
                SocketAddr::from(([192, 0, 2, 1], 53000)),
                SocketAddr::from(([239, 1, 2, 3], 53)),
            ),
            (v6(0x2001, 1, 53000, 0), v6(0xff0e, 53, 53, 0)),
            (v6(0xfec0, 1, 53000, 29), v6(0xff05, 53, 53, 29)),
            (v6(0x2001, 1, 53000, 0), v6(0xff01, 53, 53, 29)),
        ] {
            let addresses = Addresses::new(local, group)?;
            for index in [0, 7, 29] {
                addresses.require_interface(index)?;
            }
        }
        Ok(())
    }
}
