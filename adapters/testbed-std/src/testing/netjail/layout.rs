//! Address and bridge allocation for the official netjail peer ordering.
use crate::testing::topology::{Node, Role, Topology};
use std::{collections::BTreeMap, io, net::Ipv4Addr, num::NonZeroU8};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum Segment {
    Backbone,
    Carrier(NonZeroU8),
    Subnet {
        carrier: NonZeroU8,
        subnet: NonZeroU8,
        carrier_boundary: bool,
    },
}

impl Segment {
    pub(super) fn bridge_name(self) -> String {
        match self {
            Self::Backbone => "br-bb".into(),
            Self::Carrier(carrier) => format!("br-c{carrier:02x}"),
            Self::Subnet {
                carrier, subnet, ..
            } => format!("br-s{carrier:02x}{subnet:02x}"),
        }
    }

    pub(super) const fn network(self) -> Ipv4Addr {
        match self {
            Self::Backbone => Ipv4Addr::new(192, 168, 0, 0),
            Self::Carrier(carrier) => Ipv4Addr::new(10, carrier.get(), 0, 0),
            Self::Subnet {
                carrier, subnet, ..
            } => Ipv4Addr::new(10, carrier.get(), subnet.get(), 0),
        }
    }

    pub(super) const fn prefix(self) -> u8 {
        match self {
            Self::Subnet { .. } => 24,
            Self::Backbone | Self::Carrier(_) => 16,
        }
    }

    pub(super) const fn carrier_boundary(self) -> Option<Ipv4Addr> {
        match self {
            Self::Subnet {
                carrier_boundary: true,
                ..
            } => Some(self.network()),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Port {
    pub(super) segment: Segment,
    pub(super) address: Ipv4Addr,
}

impl Port {
    const fn backbone(last: u8) -> Self {
        Self {
            segment: Segment::Backbone,
            address: Ipv4Addr::new(192, 168, 1, last),
        }
    }

    const fn carrier(carrier: NonZeroU8, third: u8, last: u8) -> Self {
        Self {
            segment: Segment::Carrier(carrier),
            address: Ipv4Addr::new(10, carrier.get(), third, last),
        }
    }

    const fn subnet(
        carrier: NonZeroU8,
        subnet: NonZeroU8,
        last: u8,
        carrier_boundary: bool,
    ) -> Self {
        let segment = Segment::Subnet {
            carrier,
            subnet,
            carrier_boundary,
        };
        Self {
            segment,
            address: Ipv4Addr::new(10, carrier.get(), subnet.get(), last),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Links {
    Standalone(Port),
    Client {
        port: Port,
        gateway: Ipv4Addr,
    },
    Router {
        uplink: Port,
        gateway: Ipv4Addr,
        downlink: Port,
    },
}

impl Links {
    pub(super) const fn address(self) -> Ipv4Addr {
        match self {
            Self::Standalone(port) | Self::Client { port, .. } => port.address,
            Self::Router { uplink, .. } => uplink.address,
        }
    }
}

pub(super) struct Plan<'a> {
    pub(super) nodes: Vec<(&'a Node, Links)>,
    pub(super) gateway: Port,
}

#[derive(Default)]
struct Carrier {
    direct_peers: u8,
    subnets: u8,
}

impl Carrier {
    const fn gateway(&self, carrier: NonZeroU8) -> Port {
        // Reserve 10.C.0.1 when the script's candidate overlaps a direct
        // peer or a subnet uplink. Peer and uplink addresses stay stable.
        if self.direct_peers == 0 {
            Port::carrier(carrier, self.subnets + 1, 0)
        } else {
            Port::carrier(carrier, 0, 1)
        }
    }
}

#[derive(Default)]
struct Counts {
    backbone_peers: u8,
    carriers: BTreeMap<NonZeroU8, Carrier>,
    subnet_peers: BTreeMap<(NonZeroU8, NonZeroU8), u8>,
}

impl Counts {
    fn inspect(topology: &Topology) -> Self {
        let mut counts = Self::default();
        for node in topology.nodes() {
            match node.role() {
                Role::BackbonePeer { peer } => counts.backbone_peers = peer.get(),
                Role::Carrier { carrier } => {
                    counts.carriers.entry(carrier).or_default();
                }
                Role::CarrierPeer { carrier, peer } => {
                    counts.carriers.entry(carrier).or_default().direct_peers = peer.get()
                }
                Role::Subnet { carrier, subnet } => {
                    counts.carriers.entry(carrier).or_default().subnets = subnet.get()
                }
                Role::SubnetPeer {
                    carrier,
                    subnet,
                    peer,
                } => {
                    counts.subnet_peers.insert((carrier, subnet), peer.get());
                }
            }
        }
        counts
    }

    fn gateway(&self) -> io::Result<Port> {
        let carriers = u8::try_from(self.carriers.len()).map_err(io::Error::other)?;
        Ok(Port::backbone(octet(
            octet(self.backbone_peers, carriers)?,
            1,
        )?))
    }

    fn links(&self, role: Role, gateway: Port) -> io::Result<Links> {
        let links = match role {
            Role::BackbonePeer { peer } => Links::Standalone(Port::backbone(peer.get())),
            Role::Carrier { carrier } => Links::Router {
                uplink: Port::backbone(octet(self.backbone_peers, carrier.get())?),
                gateway: gateway.address,
                downlink: self.carriers[&carrier].gateway(carrier),
            },
            Role::CarrierPeer { carrier, peer } => Links::Client {
                port: Port::carrier(carrier, peer.get(), 0),
                gateway: self.carriers[&carrier].gateway(carrier).address,
            },
            Role::Subnet { carrier, subnet } => {
                let owned_carrier = &self.carriers[&carrier];
                Links::Router {
                    uplink: Port::carrier(
                        carrier,
                        octet(owned_carrier.direct_peers, subnet.get())?,
                        0,
                    ),
                    gateway: owned_carrier.gateway(carrier).address,
                    downlink: self.subnet_gateway(carrier, subnet)?,
                }
            }
            Role::SubnetPeer {
                carrier,
                subnet,
                peer,
            } => Links::Client {
                port: self.subnet_port(carrier, subnet, peer.get()),
                gateway: self.subnet_gateway(carrier, subnet)?.address,
            },
        };
        Ok(links)
    }

    fn subnet_gateway(&self, carrier: NonZeroU8, subnet: NonZeroU8) -> io::Result<Port> {
        let peers = self
            .subnet_peers
            .get(&(carrier, subnet))
            .copied()
            .unwrap_or(0);
        Ok(self.subnet_port(carrier, subnet, octet(peers, 1)?))
    }

    fn subnet_port(&self, carrier: NonZeroU8, subnet: NonZeroU8, address: u8) -> Port {
        Port::subnet(
            carrier,
            subnet,
            address,
            subnet.get() <= self.carriers[&carrier].direct_peers,
        )
    }
}

impl<'a> Plan<'a> {
    pub(super) fn new(topology: &'a Topology) -> io::Result<Self> {
        let counts = Counts::inspect(topology);
        let gateway = counts.gateway()?;
        let nodes = topology
            .nodes()
            .iter()
            .map(|node| Ok((node, counts.links(node.role(), gateway)?)))
            .collect::<io::Result<_>>()?;
        Ok(Self { nodes, gateway })
    }
}

fn octet(left: u8, right: u8) -> io::Result<u8> {
    left.checked_add(right).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "netjail address allocation exhausted",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_peer_addresses_and_connects_each_gateway_to_its_real_segment()
    -> Result<(), Box<dyn std::error::Error>> {
        let topology = Topology::parse(b"[DEFAULTS]\nSUBNETS = 1\nCARRIER_PEERS = 1\nSUBNET_PEERS = 1\nTESTBED_PLUGIN = test\n[BACKBONE]\nCARRIERS = 1\nBACKBONE_PEERS = 1\n")?;
        let plan = Plan::new(&topology)?;
        let addresses: Vec<_> = plan
            .nodes
            .iter()
            .map(|(_, links)| links.address())
            .collect();
        if addresses
            != [
                Ipv4Addr::new(192, 168, 1, 1),
                Ipv4Addr::new(192, 168, 1, 2),
                Ipv4Addr::new(10, 1, 1, 0),
                Ipv4Addr::new(10, 1, 2, 0),
                Ipv4Addr::new(10, 1, 1, 1),
            ]
            || plan.gateway.address != Ipv4Addr::new(192, 168, 1, 3)
        {
            return Err("incorrect backbone or fixture address allocation".into());
        }
        let Links::Router {
            downlink: carrier, ..
        } = plan.nodes[1].1
        else {
            return Err("carrier lost its downlink".into());
        };
        let Links::Router {
            downlink: subnet,
            gateway,
            ..
        } = plan.nodes[3].1
        else {
            return Err("subnet router lost its downlink".into());
        };
        let Links::Client {
            port: peer,
            gateway: peer_gateway,
        } = plan.nodes[4].1
        else {
            return Err("subnet peer lost its gateway".into());
        };
        if gateway != carrier.address
            || gateway == addresses[3]
            || peer_gateway != subnet.address
            || peer.segment != subnet.segment
            || subnet.address != Ipv4Addr::new(10, 1, 1, 2)
            || subnet.segment.carrier_boundary() != Some(addresses[2])
        {
            return Err("local route did not select its original separate gateway".into());
        }
        Ok(())
    }
}
