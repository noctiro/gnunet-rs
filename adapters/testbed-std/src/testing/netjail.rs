//! Linux network provisioning for a discrete GNUnet TESTING run.
use super::{
    Helper, RunError, helper, run_helpers_with,
    topology::{Node, Topology},
};
use gnunet_native::netjail::{
    Ipv4Prefix, LinkName, PrivateNetworkNamespace, RouteSocket, enable_ipv4_masquerade,
};
use std::{collections::BTreeSet, io, net::Ipv4Addr};
use tokio::{runtime::Handle, time::Instant};

pub use gnunet_native::netjail::enter_fixture_user_namespace;

mod layout;
use layout::{Links, Plan, Port, Segment};

const MAX_NODES: usize = 256;

/// An original peer in a provisioned fixture, supplied to the command factory.
#[derive(Clone, Copy, Debug)]
pub struct Peer<'a> {
    node: &'a Node,
    address: Ipv4Addr,
    gateway: Ipv4Addr,
}

impl<'a> Peer<'a> {
    /// Original peer coordinates, settings and numeric identity.
    pub const fn node(self) -> &'a Node {
        self.node
    }

    /// IPv4 address of this peer inside the private topology.
    pub const fn address(self) -> Ipv4Addr {
        self.address
    }

    /// IPv4 address of the fixture's isolated backbone gateway.
    pub const fn backbone_gateway(self) -> Ipv4Addr {
        self.gateway
    }

    /// Original identifier spelling accepted by the official command helper.
    pub fn helper_id(self) -> String {
        format!(
            "if{:06x}-{:06x}",
            std::process::id(),
            self.node.id().namespace_index()
        )
    }
}

struct NodeNetwork {
    namespace: PrivateNetworkNamespace,
    address: Ipv4Addr,
}

/// A fully provisioned original network and the only enrollment path into it.
/// The bridge namespace, gateway and nodes have no host network attachment.
/// Dropping the fixture releases its original namespace descriptors.
pub struct Netjail<'a> {
    topology: &'a Topology,
    nodes: Vec<NodeNetwork>,
    gateway: NodeNetwork,
    switch: PrivateNetworkNamespace,
    deadline: Instant,
}

impl<'a> Netjail<'a> {
    /// Provision a private topology with a maximum of 256 counted nodes.
    /// This synchronous operation requires the native namespace and network
    /// privileges in the current user namespace. Partial fixtures are discarded.
    /// The original deadline bounds request admission, response waits and the
    /// helper run. A syscall already executing in the kernel can return later.
    pub fn provision(topology: &'a Topology, deadline: Instant) -> io::Result<Self> {
        if topology.nodes().len() > MAX_NODES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "netjail supports up to 256 nodes",
            ));
        }
        if !(1..=super::MAX_HELPERS).contains(&topology.peer_count()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "netjail requires 1 through 64 command peers",
            ));
        }
        let plan = Plan::new(topology)?;
        check_deadline(deadline)?;
        let switch = PrivateNetworkNamespace::create()?;
        let mut switch_socket = RouteSocket::open(&switch, deadline.into_std())?;
        let mut fabric = Fabric {
            socket: &mut switch_socket,
            segments: BTreeSet::new(),
            deadline,
        };
        let mut nodes = Vec::with_capacity(plan.nodes.len());
        for (node, links) in plan.nodes {
            nodes.push(fabric.provision(node.id().namespace_index(), links)?);
        }
        let gateway = fabric.provision(
            topology.gateway_namespace_index(),
            Links::Standalone(plan.gateway),
        )?;
        check_deadline(deadline)?;
        Ok(Self {
            topology,
            nodes,
            gateway,
            switch,
            deadline,
        })
    }

    /// Run exactly one helper per peer in its originally assigned namespace.
    /// Consumes the fixture after the supervisor reaps its direct children.
    pub async fn run(
        self,
        mut prepare: impl FnMut(Peer<'_>) -> Result<Helper, RunError>,
    ) -> Result<(), RunError> {
        let handle = Handle::try_current()
            .map_err(|_| RunError::Plan("netjail requires a Tokio runtime"))?;
        let Self {
            topology,
            nodes,
            gateway,
            switch,
            deadline,
        } = self;
        let outcome = run_helpers_with(
            topology,
            |node| {
                let original = &nodes[node.id().namespace_index() as usize];
                prepare(Peer {
                    node,
                    address: original.address,
                    gateway: gateway.address,
                })
            },
            |node, command| {
                let original = &nodes[node.id().namespace_index() as usize];
                original.namespace.with_worker(|| {
                    let _runtime = handle.enter();
                    helper::Process::start(command)
                })
            },
            deadline,
        )
        .await;
        drop((nodes, gateway, switch));
        outcome
    }
}

struct Fabric<'a> {
    socket: &'a mut RouteSocket,
    segments: BTreeSet<Segment>,
    deadline: Instant,
}

impl Fabric<'_> {
    fn provision(&mut self, index: u32, links: Links) -> io::Result<NodeNetwork> {
        check_deadline(self.deadline)?;
        let namespace = PrivateNetworkNamespace::create()?;
        let mut route = RouteSocket::open(&namespace, self.deadline.into_std())?;
        route.set_up(LinkName::new("lo")?)?;
        let uplink = LinkName::new("eth0")?;
        match links {
            Links::Standalone(port) => {
                self.attach(&namespace, &mut route, index, 'a', uplink, port)?
            }
            Links::Client { port, gateway } => {
                self.attach(&namespace, &mut route, index, 'a', uplink, port)?;
                if let Some(boundary) = port.segment.carrier_boundary() {
                    route.add_host_route_via(uplink, boundary, gateway)?;
                }
                route.add_default_route(uplink, gateway)?;
            }
            Links::Router {
                uplink: upstream,
                gateway,
                downlink,
            } => {
                self.attach(&namespace, &mut route, index, 'a', uplink, upstream)?;
                self.attach(
                    &namespace,
                    &mut route,
                    index,
                    'b',
                    LinkName::new("eth1")?,
                    downlink,
                )?;
                if let Some(boundary) = downlink.segment.carrier_boundary() {
                    route.add_on_link_route(uplink, boundary)?;
                }
                route.add_on_link_route(uplink, gateway)?;
                route.add_default_route(uplink, gateway)?;
                enable_ipv4_masquerade(
                    &namespace,
                    downlink.segment.network(),
                    Ipv4Prefix::new(downlink.segment.prefix())?,
                    self.deadline.into_std(),
                )?;
            }
        }
        Ok(NodeNetwork {
            namespace,
            address: links.address(),
        })
    }

    fn attach(
        &mut self,
        namespace: &PrivateNetworkNamespace,
        route: &mut RouteSocket,
        index: u32,
        end: char,
        name: LinkName,
        port: Port,
    ) -> io::Result<()> {
        check_deadline(self.deadline)?;
        let bridge = LinkName::new(&port.segment.bridge_name())?;
        if self.segments.insert(port.segment) {
            self.socket.create_bridge(bridge)?;
            self.socket.set_up(bridge)?;
        }
        let host = LinkName::new(&format!("v{index:06x}{end}"))?;
        self.socket.create_veth(host, name, namespace)?;
        self.socket.attach_to_bridge(host, bridge)?;
        self.socket.set_up(host)?;
        route.add_ipv4(name, port.address, Ipv4Prefix::new(port.segment.prefix())?)?;
        route.set_up(name)?;
        if let Some(boundary) = port.segment.carrier_boundary() {
            route.remove_legacy_broadcast(name, boundary, port.address)?;
        }
        Ok(())
    }
}

fn check_deadline(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "netjail setup deadline expired",
        ))
    } else {
        Ok(())
    }
}
