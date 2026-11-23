//! Parse the GNUnet TESTING netjail layout without running the launcher.

use gnunet_config::{Configuration, Section};
use std::{
    collections::BTreeMap,
    ffi::{CStr, CString},
    fmt,
    net::Ipv4Addr,
    num::{NonZeroU8, NonZeroU32},
    sync::Arc,
};

const DEFAULT_NODE_LIMIT: usize = 4096;
const MAX_NAMESPACE_INDEX: usize = 0xff_ffff;
const MAX_BACKBONE_NODES: u8 = 254;
const MAX_SUBNETS: u8 = 254;
const MAX_SUBNET_PEERS: u8 = 253;

/// The official one-based TESTING node number.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NodeId(NonZeroU32);

impl NodeId {
    /// Numeric TESTING node number.
    #[must_use]
    pub const fn number(self) -> u32 {
        self.0.get()
    }

    /// Zero-based suffix assigned by the netjail namespace allocator.
    #[must_use]
    pub const fn namespace_index(self) -> u32 {
        self.0.get() - 1
    }
}

/// Role and one-based configuration coordinates of a TESTING node.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Role {
    /// Direct peer on the backbone.
    BackbonePeer {
        /// Index within the backbone.
        peer: NonZeroU8,
    },
    /// Router joining the backbone to a carrier.
    Carrier {
        /// Carrier index within the backbone.
        carrier: NonZeroU8,
    },
    /// Direct peer on a carrier.
    CarrierPeer {
        /// Owning carrier.
        carrier: NonZeroU8,
        /// Index within the carrier's direct peers.
        peer: NonZeroU8,
    },
    /// Router joining a carrier to a subnet.
    Subnet {
        /// Owning carrier.
        carrier: NonZeroU8,
        /// Index within the carrier's subnets.
        subnet: NonZeroU8,
    },
    /// Peer attached to a carrier's subnet.
    SubnetPeer {
        /// Owning carrier.
        carrier: NonZeroU8,
        /// Owning subnet within the carrier.
        subnet: NonZeroU8,
        /// Index within the subnet's peers.
        peer: NonZeroU8,
    },
}

impl Role {
    /// Whether the C command launcher assigns a helper to this role.
    #[must_use]
    pub const fn is_peer(self) -> bool {
        matches!(
            self,
            Self::BackbonePeer { .. } | Self::CarrierPeer { .. } | Self::SubnetPeer { .. }
        )
    }

    fn from_section(name: &[u8]) -> Result<Option<Self>, Error> {
        let mut parts = name.splitn(7, |byte| *byte == b'-');
        let [Some(head), a, b, c, d, e, end] = std::array::from_fn(|_| parts.next()) else {
            return Ok(None);
        };
        let invalid = || Error::InvalidSection(String::from_utf8_lossy(name).into_owned());
        let index = |bytes: &[u8]| section_index(bytes).ok_or_else(invalid);
        let is = |part: &[u8], expected: &[u8]| part.eq_ignore_ascii_case(expected);

        if head.eq_ignore_ascii_case(b"BACKBONE") {
            return match (a, b, c) {
                (None, None, None) => Ok(None),
                (Some(tag), Some(peer), None) if is(tag, b"PEER") => {
                    Ok(Some(Self::BackbonePeer { peer: index(peer)? }))
                }
                _ => Err(invalid()),
            };
        }
        if !head.eq_ignore_ascii_case(b"CARRIER") {
            return Ok(None);
        }
        let carrier = index(a.ok_or_else(invalid)?)?;
        let role = match (b, c, d, e, end) {
            (None, None, None, None, None) => Self::Carrier { carrier },
            (Some(tag), Some(peer), None, None, None) if is(tag, b"PEER") => Self::CarrierPeer {
                carrier,
                peer: index(peer)?,
            },
            (Some(tag), Some(subnet), None, None, None) if is(tag, b"SUBNET") => Self::Subnet {
                carrier,
                subnet: index(subnet)?,
            },
            (Some(tag), Some(subnet), Some(peer_tag), Some(peer), None)
                if is(tag, b"SUBNET") && is(peer_tag, b"PEER") =>
            {
                Self::SubnetPeer {
                    carrier,
                    subnet: index(subnet)?,
                    peer: index(peer)?,
                }
            }
            _ => return Err(invalid()),
        };
        Ok(Some(role))
    }
}

fn section_index(bytes: &[u8]) -> Option<NonZeroU8> {
    // The launcher selects canonical decimal section names without leading zeros.
    if !matches!(bytes.first(), Some(b'1'..=b'9')) {
        return None;
    }
    std::str::from_utf8(bytes).ok()?.parse().ok()
}

/// A carrier or subnet's resolved declarative SUBNET setting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubnetSetting {
    /// Address of the default network in the generated layout.
    Default(Ipv4Addr),
    /// The original explicit value, including any written CIDR prefix.
    Configured(Arc<[u8]>),
}

/// One counted TESTING node in native namespace creation order.
#[derive(Debug)]
pub struct Node {
    id: NodeId,
    role: Role,
    testbed_plugin: Arc<[u8]>,
    setup_programs: Option<Arc<[u8]>>,
    subnet: Option<SubnetSetting>,
}

impl Node {
    /// Official one-based identity.
    #[must_use]
    pub const fn id(&self) -> NodeId {
        self.id
    }

    /// Role and relative configuration coordinates.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Resolved launcher TESTBED_PLUGIN setting for this node.
    #[must_use]
    pub fn testbed_plugin(&self) -> &[u8] {
        &self.testbed_plugin
    }

    /// Resolved SETUP_PROGRAMMS text for this level, if supplied.
    /// The parser retains it as configuration bytes.
    #[must_use]
    pub fn setup_programs(&self) -> Option<&[u8]> {
        self.setup_programs.as_deref()
    }

    /// Declared SUBNET setting on carrier and subnet routers.
    /// The pinned shell launcher computes its link addresses independently.
    #[must_use]
    pub const fn subnet(&self) -> Option<&SubnetSetting> {
        self.subnet.as_ref()
    }
}

/// Validated in-memory netjail topology and its original configuration.
#[derive(Debug)]
pub struct Topology {
    source: CString,
    default_plugin: Arc<[u8]>,
    nodes: Vec<Node>,
    gateway_namespace_index: u32,
}

impl Topology {
    /// Parse memory-only GNUnet configuration with a 4096-node allocation limit.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid configuration, topology counts or selectors.
    pub fn parse(input: &[u8]) -> Result<Self, Error> {
        Self::parse_with_node_limit(input, DEFAULT_NODE_LIMIT)
    }

    /// Parse with an explicit limit on the number of counted TESTING nodes.
    /// The native six-digit hexadecimal namespace index also bounds the layout.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid configuration, topology counts or selectors,
    /// or when the resolved topology exceeds its allocation limit.
    pub fn parse_with_node_limit(input: &[u8], node_limit: usize) -> Result<Self, Error> {
        let mut config = Configuration::default();
        config
            .deserialize(input, None)
            .map_err(Error::Configuration)?;
        let mut overrides = BTreeMap::new();
        for section in config.sections() {
            if let Some(role) = Role::from_section(section.name())?
                && overrides.insert(role, section).is_some()
            {
                return Err(Error::InvalidSection(
                    String::from_utf8_lossy(section.name()).into_owned(),
                ));
            }
        }
        let defaults = Defaults::read(&config)?;
        let backbone = Backbone::read(&config)?;
        let default_plugin = Arc::clone(&defaults.testbed_plugin);
        let mut layout = Layout {
            defaults,
            overrides,
            nodes: Vec::new(),
            limit: node_limit.min(MAX_NAMESPACE_INDEX),
        };
        // The namespace allocator is zero based. The launcher's configuration
        // loops use one-based selectors and create each parent before its peers.
        for peer in indices(backbone.peers) {
            layout.add(Role::BackbonePeer { peer })?;
        }
        for carrier in indices(backbone.carriers) {
            layout.carrier(carrier)?;
        }
        if let Some(section) = layout.overrides.values().next() {
            return Err(Error::UnmatchedSection(
                String::from_utf8_lossy(section.name()).into_owned(),
            ));
        }
        let gateway_namespace_index =
            u32::try_from(layout.nodes.len()).map_err(|_| Error::NodeLimit(layout.limit))?;
        let source = CString::new(input)
            .map_err(|_| Error::Configuration(gnunet_config::Error::InvalidInput))?;
        Ok(Self {
            source,
            default_plugin,
            nodes: layout.nodes,
            gateway_namespace_index,
        })
    }

    /// Original configuration bytes with the C command helper's NUL terminator.
    #[must_use]
    pub fn source(&self) -> &CStr {
        &self.source
    }

    /// Default plugin used by the official C plugin getter.
    #[must_use]
    pub fn default_plugin(&self) -> &[u8] {
        &self.default_plugin
    }

    /// All TESTING nodes in the original namespace creation order.
    #[must_use]
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// The peer subset in command-helper launch order.
    pub fn peers(&self) -> impl Iterator<Item = &Node> {
        self.nodes.iter().filter(|node| node.role.is_peer())
    }

    /// Number of TESTING nodes that run command helpers.
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.peers().count()
    }

    /// Find a counted TESTING node by its one-based identity.
    #[must_use]
    pub fn node(&self, id: NodeId) -> Option<&Node> {
        let index = usize::try_from(id.namespace_index()).ok()?;
        self.nodes.get(index)
    }

    /// Zero-based namespace suffix of the gateway created after all TESTING nodes.
    #[must_use]
    pub const fn gateway_namespace_index(&self) -> u32 {
        self.gateway_namespace_index
    }
}

/// Failure to construct a validated topology.
#[derive(Debug)]
pub enum Error {
    /// The GNUnet configuration syntax or resource bounds rejected the input.
    Configuration(gnunet_config::Error),
    /// A required setting was absent or empty.
    Missing {
        /// Required section.
        section: &'static str,
        /// Required option.
        option: &'static str,
    },
    /// A count is invalid or overflows an address allocation bound.
    InvalidCount {
        /// Section supplying the count.
        section: String,
        /// Count option whose constraint failed.
        option: &'static str,
    },
    /// A recognized topology section has an invalid selector or index.
    InvalidSection(String),
    /// A recognized topology section has no node in the resolved layout.
    UnmatchedSection(String),
    /// Counted nodes exceed the selected limit.
    NodeLimit(usize),
    /// Memory could not be reserved for the counted nodes.
    Capacity(std::collections::TryReserveError),
}

impl fmt::Display for Error {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(error) => error.fmt(out),
            Self::Missing { section, option } => write!(out, "missing {option} in [{section}]"),
            Self::InvalidCount { section, option } => {
                write!(out, "invalid netjail count {option} in [{section}]")
            }
            Self::InvalidSection(section) => write!(out, "invalid netjail section [{section}]"),
            Self::UnmatchedSection(section) => {
                write!(
                    out,
                    "netjail section [{section}] has no node in the topology"
                )
            }
            Self::NodeLimit(limit) => write!(out, "netjail topology exceeds {limit} counted nodes"),
            Self::Capacity(error) => error.fmt(out),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Configuration(error) => Some(error),
            Self::Capacity(error) => Some(error),
            _ => None,
        }
    }
}

struct Backbone {
    peers: u8,
    carriers: u8,
}

impl Backbone {
    fn read(config: &Configuration) -> Result<Self, Error> {
        let peers = required_count(config, "BACKBONE", "BACKBONE_PEERS", MAX_BACKBONE_NODES)?;
        let carriers = required_count(config, "BACKBONE", "CARRIERS", MAX_BACKBONE_NODES)?;
        // The gateway uses the first backbone octet after peers and carriers.
        if u16::from(peers) + u16::from(carriers) > u16::from(MAX_BACKBONE_NODES) {
            return Err(count_error(b"BACKBONE", "CARRIERS"));
        }
        Ok(Self { peers, carriers })
    }
}

struct Defaults {
    testbed_plugin: Arc<[u8]>,
    carrier_setup: Option<Arc<[u8]>>,
    subnet_setup: Option<Arc<[u8]>>,
    peer_setup: Option<Arc<[u8]>>,
    carrier_peers: u8,
    subnets: u8,
    subnet_peers: u8,
}

impl Defaults {
    fn read(config: &Configuration) -> Result<Self, Error> {
        let default = |key: &str| nonempty(config.get(b"DEFAULTS", key.as_bytes()));
        let testbed_plugin = default("TESTBED_PLUGIN").ok_or(Error::Missing {
            section: "DEFAULTS",
            option: "TESTBED_PLUGIN",
        })?;
        Ok(Self {
            testbed_plugin: testbed_plugin.into(),
            carrier_setup: default("CARRIER_SETUP_PROGRAMMS").map(Arc::from),
            subnet_setup: default("SUBNET_SETUP_PROGRAMMS").map(Arc::from),
            peer_setup: default("PEER_SETUP_PROGRAMMS").map(Arc::from),
            carrier_peers: required_count(config, "DEFAULTS", "CARRIER_PEERS", u8::MAX)?,
            subnets: required_count(config, "DEFAULTS", "SUBNETS", MAX_SUBNETS)?,
            subnet_peers: required_count(config, "DEFAULTS", "SUBNET_PEERS", MAX_SUBNET_PEERS)?,
        })
    }
}

struct Layout<'config> {
    defaults: Defaults,
    overrides: BTreeMap<Role, &'config Section>,
    nodes: Vec<Node>,
    limit: usize,
}

impl Layout<'_> {
    fn add(&mut self, role: Role) -> Result<(), Error> {
        if self.nodes.len() == self.limit {
            return Err(Error::NodeLimit(self.limit));
        }
        let id = u32::try_from(self.nodes.len() + 1)
            .ok()
            .and_then(NonZeroU32::new)
            .map(NodeId)
            .ok_or(Error::NodeLimit(self.limit))?;
        self.nodes.try_reserve(1).map_err(Error::Capacity)?;
        let settings = self.overrides.remove(&role);
        let testbed_plugin = option(settings, b"TESTBED_PLUGIN")
            .map_or_else(|| Arc::clone(&self.defaults.testbed_plugin), Arc::from);
        let program = |default: &Option<Arc<[u8]>>| {
            option(settings, b"SETUP_PROGRAMMS")
                .map(Arc::from)
                .or_else(|| default.clone())
        };
        let network = |address| {
            option(settings, b"SUBNET").map_or(SubnetSetting::Default(address), |value| {
                SubnetSetting::Configured(value.into())
            })
        };
        let (setup_programs, subnet) = match role {
            Role::BackbonePeer { .. } | Role::CarrierPeer { .. } => (None, None),
            Role::Carrier { carrier } => (
                program(&self.defaults.carrier_setup),
                Some(network(Ipv4Addr::new(10, carrier.get(), 0, 0))),
            ),
            Role::Subnet { carrier, subnet } => (
                program(&self.defaults.subnet_setup),
                Some(network(Ipv4Addr::new(10, carrier.get(), subnet.get(), 0))),
            ),
            Role::SubnetPeer { .. } => (program(&self.defaults.peer_setup), None),
        };
        self.nodes.push(Node {
            id,
            role,
            testbed_plugin,
            setup_programs,
            subnet,
        });
        Ok(())
    }

    fn carrier(&mut self, carrier: NonZeroU8) -> Result<(), Error> {
        let role = Role::Carrier { carrier };
        let settings = self.overrides.get(&role).copied();
        let peers = count_or(
            settings,
            "CARRIER_PEERS",
            u8::MAX,
            self.defaults.carrier_peers,
        )?;
        let subnets = count_or(settings, "SUBNETS", MAX_SUBNETS, self.defaults.subnets)?;
        if peers.checked_add(subnets).is_none() {
            let section = format!("CARRIER-{carrier}");
            return Err(count_error(section.as_bytes(), "SUBNETS"));
        }
        self.add(role)?;
        for peer in indices(peers) {
            self.add(Role::CarrierPeer { carrier, peer })?;
        }
        for subnet in indices(subnets) {
            self.subnet(carrier, subnet)?;
        }
        Ok(())
    }

    fn subnet(&mut self, carrier: NonZeroU8, subnet: NonZeroU8) -> Result<(), Error> {
        let role = Role::Subnet { carrier, subnet };
        let settings = self.overrides.get(&role).copied();
        let peers = count_or(
            settings,
            "SUBNET_PEERS",
            MAX_SUBNET_PEERS,
            self.defaults.subnet_peers,
        )?;
        self.add(role)?;
        for peer in indices(peers) {
            self.add(Role::SubnetPeer {
                carrier,
                subnet,
                peer,
            })?;
        }
        Ok(())
    }
}

fn indices(count: u8) -> impl Iterator<Item = NonZeroU8> {
    (1..=count).filter_map(NonZeroU8::new)
}

fn nonempty(value: Option<&[u8]>) -> Option<&[u8]> {
    value.filter(|value| !value.is_empty())
}

fn option<'section>(section: Option<&'section Section>, key: &[u8]) -> Option<&'section [u8]> {
    nonempty(
        section?
            .entries()
            .iter()
            .find(|entry| entry.key().eq_ignore_ascii_case(key))?
            .value(),
    )
}

fn count_error(section: &[u8], option: &'static str) -> Error {
    Error::InvalidCount {
        section: String::from_utf8_lossy(section).into_owned(),
        option,
    }
}

fn count(value: &[u8], section: &[u8], key: &'static str, max: u8) -> Result<u8, Error> {
    // A signed negative count must never wrap through the configuration API.
    if value.starts_with(b"-") {
        return Err(count_error(section, key));
    }
    let parsed = gnunet_config::parse_number(value)
        .ok()
        .and_then(|number| u8::try_from(number).ok())
        .filter(|value| *value <= max);
    parsed.ok_or_else(|| count_error(section, key))
}

fn required_count(
    config: &Configuration,
    section: &'static str,
    key: &'static str,
    max: u8,
) -> Result<u8, Error> {
    let value = nonempty(config.get(section.as_bytes(), key.as_bytes())).ok_or(Error::Missing {
        section,
        option: key,
    })?;
    count(value, section.as_bytes(), key, max)
}

fn count_or(
    section: Option<&Section>,
    key: &'static str,
    max: u8,
    fallback: u8,
) -> Result<u8, Error> {
    let Some(section) = section else {
        return Ok(fallback);
    };
    option(Some(section), key.as_bytes())
        .map_or(Ok(fallback), |value| count(value, section.name(), key, max))
}

#[cfg(test)]
mod tests;
