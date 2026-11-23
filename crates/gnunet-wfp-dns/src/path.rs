//! Direction-neutral UDP using the original application's local/remote roles.
use core::num::{NonZeroU32, NonZeroU64};

/// IP family of the native flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    /// IPv4.
    V4,
    /// IPv6.
    V6,
}

/// Original local and remote network byte addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Addresses {
    /// IPv4 unicast endpoints.
    V4 {
        /// Original local IPv4 address.
        local: [u8; 4],
        /// Original remote IPv4 address.
        remote: [u8; 4],
    },
    /// IPv6 unicast endpoints.
    V6 {
        /// Original local IPv6 address.
        local: [u8; 16],
        /// Original remote IPv6 address.
        remote: [u8; 16],
    },
}

/// Native path normalization error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathError {
    /// Missing unicast addresses or UDP ports.
    Endpoint,
    /// An interface or required link-local zone was unavailable.
    Interface,
}

/// The local address's native WFP interface identity and injection indices.
/// Both are taken from the same classification. An index can be reused by
/// a different LUID, and the LUID does not pin a subinterface generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalInterface {
    luid: NonZeroU64,
    index: NonZeroU32,
    subinterface: NonZeroU32,
}

impl LocalInterface {
    /// Bind the classified LUID, interface index and subinterface index.
    ///
    /// # Errors
    /// Refuses a missing native observation represented by zero.
    pub fn new(luid: u64, index: u32, subinterface: u32) -> Result<Self, PathError> {
        Ok(Self {
            luid: NonZeroU64::new(luid).ok_or(PathError::Interface)?,
            index: NonZeroU32::new(index).ok_or(PathError::Interface)?,
            subinterface: NonZeroU32::new(subinterface).ok_or(PathError::Interface)?,
        })
    }

    /// Native interface index for receive injection.
    pub const fn index(self) -> u32 {
        self.index.get()
    }

    /// Native subinterface index for receive injection.
    pub const fn subinterface(self) -> u32 {
        self.subinterface.get()
    }
}

const ZONE_MASK: u32 = 0x0fff_ffff;
const LINK_LEVEL: u32 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RemoteScope {
    Unscoped,
    Link,
    Site,
}

impl Addresses {
    fn remote_scope(self) -> RemoteScope {
        let Self::V6 { remote, .. } = self else {
            return RemoteScope::Unscoped;
        };
        match (remote[0], remote[1] & 0xc0) {
            (0xfe, 0x80) => RemoteScope::Link,
            (0xfe, 0xc0) => RemoteScope::Site,
            _ => RemoteScope::Unscoped,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Route {
    interface: LocalInterface,
    addresses: Addresses,
    ports: [u16; 2],
    compartment: u32,
}

impl Route {
    fn new(
        addresses: Addresses,
        ports: [u16; 2],
        compartment: u32,
        interface: LocalInterface,
    ) -> Result<Self, PathError> {
        let valid = match addresses {
            Addresses::V4 { local, remote } => [local, remote]
                .into_iter()
                .all(|addr| addr[0] != 0 && addr[0] < 224),
            Addresses::V6 { local, remote } => [local, remote]
                .into_iter()
                .all(|addr| addr != [0; 16] && addr[0] != 0xff),
        };
        if !valid || ports.contains(&0) {
            return Err(PathError::Endpoint);
        }
        Ok(Self {
            interface,
            addresses,
            ports,
            compartment,
        })
    }
}

/// UDP endpoints, compartment and native interface facts retained at capture.
/// Local and remote are the application socket's roles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Path {
    route: Route,
    remote_scope: u32,
}

impl Path {
    /// Preserve the outbound WFP scope value and the original local interface.
    /// Ports use host byte order.
    ///
    /// # Errors
    /// Refuses incomplete and non-unicast observations. Link-local remotes
    /// require a native link zone on the classified interface. Site-local
    /// remotes cannot be qualified by this receiving path.
    pub fn new(
        addresses: Addresses,
        ports: [u16; 2],
        compartment: u32,
        interface: LocalInterface,
        remote_scope: u32,
    ) -> Result<Self, PathError> {
        match addresses.remote_scope() {
            RemoteScope::Unscoped => {}
            RemoteScope::Link
                if remote_scope & ZONE_MASK == interface.index()
                    && matches!(remote_scope >> 28, 0 | LINK_LEVEL) => {}
            RemoteScope::Link | RemoteScope::Site => return Err(PathError::Interface),
        }
        Ok(Self {
            route: Route::new(addresses, ports, compartment, interface)?,
            remote_scope,
        })
    }

    /// Address family of the native datagram.
    pub const fn family(self) -> Family {
        match self.route.addresses {
            Addresses::V4 { .. } => Family::V4,
            Addresses::V6 { .. } => Family::V6,
        }
    }

    /// Original UDP ports in application local, remote order.
    pub const fn ports(self) -> [u16; 2] {
        self.route.ports
    }

    /// Original application-local and remote address bytes.
    pub const fn addresses(self) -> Addresses {
        self.route.addresses
    }

    /// Native local interface identity and route indices from the validated path.
    pub const fn interface(self) -> LocalInterface {
        self.route.interface
    }

    /// Original outbound WFP remote scope, preserving the level and zone.
    pub const fn remote_scope(self) -> u32 {
        self.remote_scope
    }

    /// Native routing compartment.
    pub const fn compartment(self) -> u32 {
        self.route.compartment
    }

    pub(crate) fn agrees_with(self, received: ReceivePath) -> bool {
        // A captured link-local zone and any inbound arrival index were already
        // checked against their own classified interface. Equal routes preserve
        // that link along with the original compartment and native identities.
        self.route == received.0
    }
}

/// Facts observed at inbound DATAGRAM_DATA, in the application's local/remote
/// roles. The outbound transport scope field is absent from this representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivePath(Route);

impl ReceivePath {
    /// Qualify the inbound route using its classified interface. When WFP also
    /// reports the arrival interface, a link-local remote needs the same index.
    ///
    /// # Errors
    /// Refuses incomplete or non-unicast endpoints, a contradictory arrival
    /// interface for a link-local remote, and unqualified site-local remotes.
    pub fn new(
        addresses: Addresses,
        ports: [u16; 2],
        compartment: u32,
        interface: LocalInterface,
        arrival_interface: Option<u32>,
    ) -> Result<Self, PathError> {
        match addresses.remote_scope() {
            RemoteScope::Unscoped => {}
            RemoteScope::Link
                if arrival_interface.is_none_or(|index| index == interface.index()) => {}
            RemoteScope::Link | RemoteScope::Site => return Err(PathError::Interface),
        }
        Route::new(addresses, ports, compartment, interface).map(Self)
    }
}
