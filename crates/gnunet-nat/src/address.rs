//! Address scope and the official registration-to-notification selection.
use gnunet_types::Error;
use gnunet_wire::official::nat::{Address, AddressClass};
/// Allocation-free Internet socket address; no native padding or platform ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum SocketAddress {
    /// IPv4 endpoint.
    V4 {
        /// Network address.
        ip: [u8; 4],
        /// Host-order port.
        port: u16,
    },
    /// IPv6 endpoint preserving scope/flow.
    V6 {
        /// Network address.
        ip: [u8; 16],
        /// Host-order port.
        port: u16,
        /// Native scope index.
        scope: u32,
        /// Original flow value.
        flow: u32,
    },
}
impl SocketAddress {
    /// Convert a validated native view, rejecting Unix for Internet operations.
    pub fn from_wire(a: Address<'_>) -> Result<Self, Error> {
        match a {
            Address::V4 { ip, port } => Ok(Self::V4 { ip, port }),
            Address::V6 {
                ip,
                port,
                scope,
                flow,
            } => Ok(Self::V6 {
                ip,
                port,
                scope,
                flow,
            }),
            Address::Unix(_) => Err(Error::Unsupported),
        }
    }
    /// Portable wire fields, canonicalized by an explicit native ABI encoder.
    pub const fn wire(self) -> Address<'static> {
        match self {
            Self::V4 { ip, port } => Address::V4 { ip, port },
            Self::V6 {
                ip,
                port,
                scope,
                flow,
            } => Address::V6 {
                ip,
                port,
                scope,
                flow,
            },
        }
    }
    /// Host-order port.
    pub const fn port(self) -> u16 {
        match self {
            Self::V4 { port, .. } | Self::V6 { port, .. } => port,
        }
    }
    /// Replace only the port.
    pub const fn with_port(self, port: u16) -> Self {
        match self {
            Self::V4 { ip, .. } => Self::V4 { ip, port },
            Self::V6 {
                ip, scope, flow, ..
            } => Self::V6 {
                ip,
                port,
                scope,
                flow,
            },
        }
    }
    /// Whether the address is an unspecified bind address.
    pub fn is_unspecified(self) -> bool {
        match self {
            Self::V4 { ip, .. } => ip == [0; 4],
            Self::V6 { ip, .. } => ip == [0; 16],
        }
    }
    /// Loopback scope (all IPv4 127/8 and IPv6 ::1).
    pub fn is_loopback(self) -> bool {
        match self {
            Self::V4 { ip, .. } => ip[0] == 127,
            Self::V6 { ip, .. } => ip == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        }
    }
    /// Link-local IPv6 scope.
    pub const fn is_v6_link_local(self) -> bool {
        matches!(self,Self::V6{ip,..}if ip[0]==0xfe&&ip[1]&0xc0==0x80)
    }
    /// Documented private/NAT ranges. Correct RFC1918 masks replace the C
    /// implementation's accidental192.168/12 and172.16/16 constants.
    pub const fn is_private(self) -> bool {
        match self {
            Self::V4 { ip, .. } => {
                ip[0] == 10
                    || (ip[0] == 100 && ip[1] & 0xc0 == 64)
                    || (ip[0] == 192 && ip[1] == 168)
                    || (ip[0] == 169 && ip[1] == 254)
                    || (ip[0] == 172 && ip[1] & 0xf0 == 16)
            }
            Self::V6 { ip, .. } => {
                ip[0] & 0xfe == 0xfc
                    || (ip[0] == 0xfe && (ip[1] & 0xc0 == 0x80 || ip[1] & 0xc0 == 0xc0))
            }
        }
    }
    /// Same IP family and network address; ports/flow/scope do not alter this
    /// predicate. GNUNET_NAT_test_address instead checks a complete native address.
    pub fn same_ip(self, other: Self) -> bool {
        match (self, other) {
            (Self::V4 { ip: a, .. }, Self::V4 { ip: b, .. }) => a == b,
            (Self::V6 { ip: a, .. }, Self::V6 { ip: b, .. }) => a == b,
            _ => false,
        }
    }
    /// Interface address class, with the caller's actual link class modifier.
    pub fn classify(self, link: AddressClass) -> AddressClass {
        let class = if self.is_loopback() {
            AddressClass::LOOPBACK
        } else if self.is_private() {
            link
        } else {
            AddressClass::GLOBAL
        };
        if matches!(self,Self::V6{ip,..}if ip[11]==0xff&&ip[12]==0xfe) {
            AddressClass(class.0 | AddressClass::PRIVATE.0)
        } else {
            class
        }
    }
}
/// Select a local/manual/UPnP observation for one original binding. A wildcard
/// binding normally hides loopback and IPv6 link-local addresses. A zero
/// observation port adopts this binding's original port.
pub fn select(
    binding: SocketAddress,
    observation: SocketAddress,
    class: AddressClass,
    return_local: bool,
) -> Option<SocketAddress> {
    match (binding, observation) {
        (SocketAddress::V4 { .. }, SocketAddress::V4 { .. })
        | (SocketAddress::V6 { .. }, SocketAddress::V6 { .. }) => {}
        _ => return None,
    };
    let wildcard = binding.is_unspecified();
    if !return_local && wildcard && (observation.is_loopback() || observation.is_v6_link_local()) {
        return None;
    }
    if !wildcard && binding.is_loopback() != observation.is_loopback() {
        return None;
    }
    if class.0 & AddressClass::EXTERN.0 != 0 && !wildcard && !binding.is_private() {
        return None;
    }
    if !wildcard && !binding.is_private() && !binding.same_ip(observation) {
        return None;
    }
    if binding.is_v6_link_local()
        && class.0 & AddressClass::EXTERN.0 == 0
        && !binding.same_ip(observation)
    {
        return None;
    }
    Some(if observation.port() == 0 {
        observation.with_port(binding.port())
    } else {
        observation
    })
}
/// Parse a literal dotted IPv4 address without DNS, allocation or libc.
pub fn parse_ipv4(input: &[u8]) -> Result<[u8; 4], Error> {
    let mut out = [0; 4];
    let mut parts = 0usize;
    for part in input.split(|&c| c == b'.') {
        if parts >= 4 || part.is_empty() || part.len() > 3 {
            return Err(Error::Malformed);
        }
        let mut n = 0u16;
        for &c in part {
            if !c.is_ascii_digit() {
                return Err(Error::Malformed);
            }
            n = n * 10 + u16::from(c - b'0');
        }
        out[parts] = u8::try_from(n).map_err(|_| Error::Malformed)?;
        parts += 1;
    }
    if parts != 4 {
        return Err(Error::Malformed);
    }
    Ok(out)
}
