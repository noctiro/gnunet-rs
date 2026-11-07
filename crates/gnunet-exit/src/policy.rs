//! Explicit IP capability/range/port policy; no platform routes or hidden DNS.
use crate::{Address, Family};
use gnunet_types::Error;
/// Supported real IP transport. TCP state itself remains at the real endpoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Protocol {
    /// IPv4 control messages.
    Icmp = 1,
    /// TCP segment transport.
    Tcp = 6,
    /// UDP datagrams.
    Udp = 17,
    /// IPv6 control messages.
    Icmp6 = 58,
}
impl Protocol {
    /// Checked supported IP registry value with actual family validation.
    pub fn from_number(family: Family, number: u8) -> Result<Self, Error> {
        match (family, number) {
            (Family::V4, 1) => Ok(Self::Icmp),
            (_, 6) => Ok(Self::Tcp),
            (_, 17) => Ok(Self::Udp),
            (Family::V6, 58) => Ok(Self::Icmp6),
            _ => Err(Error::Unsupported),
        }
    }
    /// Actual wire IP protocol number.
    #[must_use]
    pub const fn number(self) -> u8 {
        self as u8
    }
    /// ICMP matching does not use transport ports in the active reference.
    #[must_use]
    pub const fn is_icmp(self) -> bool {
        matches!(self, Self::Icmp | Self::Icmp6)
    }
}
/// A real IP endpoint, with decoded host-order port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Endpoint {
    /// Actual IP address.
    pub address: Address,
    /// Host-order TCP/UDP port or0 for control messages.
    pub port: u16,
}
/// Actual NAT six-tuple. No hash truncation is used as uniqueness authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tuple {
    /// Remote target (reply source).
    pub remote: Endpoint,
    /// Actual chosen local TUN source (reply destination).
    pub local: Endpoint,
    /// Actual original IP transport.
    pub protocol: Protocol,
}
impl Tuple {
    /// Validate source/target address family and control-port semantics.
    pub fn validate(self) -> Result<(), Error> {
        if self.remote.address.family() != self.local.address.family() {
            return Err(Error::InvalidInput);
        }
        Protocol::from_number(self.remote.address.family(), self.protocol.number())?;
        if self.protocol.is_icmp() && (self.remote.port != 0 || self.local.port != 0) {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}
/// Configured prefix, independent of native sockaddr ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Prefix {
    /// Address within the configured prefix.
    pub address: Address,
    /// Prefix length0..32 or0..128.
    pub bits: u8,
}
impl Prefix {
    /// Validate actual family width.
    pub fn validate(self) -> Result<(), Error> {
        if usize::from(self.bits) > self.address.len() * 8 {
            Err(Error::InvalidInput)
        } else {
            Ok(())
        }
    }
    /// Exact bitwise prefix test with no temporary strings or allocation.
    #[must_use]
    pub fn contains(self, address: Address) -> bool {
        fn yes(a: &[u8], b: &[u8], bits: u8) -> bool {
            if usize::from(bits) > a.len() * 8 {
                return false;
            }
            let whole = usize::from(bits / 8);
            let rest = bits % 8;
            if a[..whole] != b[..whole] {
                return false;
            }
            rest == 0 || (a[whole] & (!0u8 << (8 - rest))) == (b[whole] & (!0u8 << (8 - rest)))
        }
        match (self.address, address) {
            (Address::V4(a), Address::V4(b)) => yes(&a, &b, self.bits),
            (Address::V6(a), Address::V6(b)) => yes(&a, &b, self.bits),
            _ => false,
        }
    }
}
/// One ordered caller-supplied destination rule. C's regex announcement policy
/// alone is not treated as proof that any particular endpoint accepted traffic.
#[derive(Clone, Copy, Debug)]
pub struct Rule {
    /// Destination address prefix.
    pub destination: Prefix,
    /// Optional selected transport, otherwise all supported.
    pub protocol: Option<Protocol>,
    /// Inclusive destination port lower bound.
    pub first_port: u16,
    /// Inclusive destination port upper bound.
    pub last_port: u16,
    /// True allows this matching destination.
    pub allow: bool,
}
impl Rule {
    /// Check shape before installing policy.
    pub fn validate(self) -> Result<(), Error> {
        self.destination.validate()?;
        if self.first_port > self.last_port {
            Err(Error::InvalidInput)
        } else {
            Ok(())
        }
    }
}
/// Explicit source of Internet destination authorization. Named service redirects
/// have their own configured targets and do not pass through this Internet gate.
#[derive(Clone, Copy)]
pub enum InternetRules<'a> {
    /// Official EXIT_RANGE_IPV4_POLICY/EXIT_RANGE_IPV6_POLICY network/port sets.
    /// The same typed rules are used to construct REGEX exit announcements.
    Official(&'a [gnunet_vpn::discovery::policy::Rule]),
    /// Pure Rust callers may supply an explicit ordered policy. This is not the
    /// daemon's product configuration or an alternative advertised permission set.
    Ordered {
        /// First matching destination rule wins.
        rules: &'a [Rule],
        /// Default action after these ordered rules.
        default_allow: bool,
    },
}
/// Borrowed Internet-family gate and explicit authorization source. Official
/// rules share their address/port semantics with the announcement generator.
#[derive(Clone, Copy)]
pub struct Policy<'a> {
    /// Actual Internet-v4 capability.
    pub ipv4: bool,
    /// Actual Internet-v6 capability.
    pub ipv6: bool,
    /// One explicitly chosen policy source; sources are never implicitly mixed.
    pub rules: InternetRules<'a>,
}
impl Policy<'_> {
    /// Validate every configured rule before any forwarding source is admitted.
    pub fn validate(self) -> Result<(), Error> {
        match self.rules {
            InternetRules::Official(rules) => {
                for rule in rules {
                    rule.validate()?;
                }
            }
            InternetRules::Ordered { rules, .. } => {
                for rule in rules {
                    rule.validate()?;
                }
            }
        }
        Ok(())
    }
    /// Actual selected local Internet forwarding policy. ICMP uses the matching
    /// family's port-zero query; TCP and UDP share the official port set.
    #[must_use]
    pub fn allows(self, endpoint: Endpoint, protocol: Protocol) -> bool {
        if Protocol::from_number(endpoint.address.family(), protocol.number()).is_err()
            || (protocol.is_icmp() && endpoint.port != 0)
        {
            return false;
        }
        let enabled = match endpoint.address.family() {
            Family::V4 => self.ipv4,
            Family::V6 => self.ipv6,
        };
        if !enabled {
            return false;
        }
        match self.rules {
            InternetRules::Official(rules) => rules.iter().any(|rule| {
                rule.contains(endpoint.address, endpoint.port)
                    .unwrap_or(false)
            }),
            InternetRules::Ordered {
                rules,
                default_allow,
            } => rules
                .iter()
                .find(|rule| {
                    rule.destination.contains(endpoint.address)
                        && rule.protocol.is_none_or(|p| p == protocol)
                        && (rule.first_port..=rule.last_port).contains(&endpoint.port)
                })
                .map_or(default_allow, |rule| rule.allow),
        }
    }
}

#[cfg(test)]
mod official_tests {
    use super::*;
    use gnunet_vpn::discovery::policy::{Ports, Rule as Network};
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "One authorization model asserts the same official destination set for forwarding and announcement"
    )]
    fn official_advertised_sets_are_actual_internet_authorization() -> Result<(), Error> {
        let rules = [Network::prefix(
            Address::V4([192, 0, 2, 0]),
            24,
            Ports::Range {
                first: 25,
                last: 25,
                negated: true,
            },
        )?];
        let policy = Policy {
            ipv4: true,
            ipv6: false,
            rules: InternetRules::Official(&rules),
        };
        policy.validate()?;
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            assert!(policy.allows(
                Endpoint {
                    address: Address::V4([192, 0, 2, 1]),
                    port: 80
                },
                protocol
            ));
            assert!(!policy.allows(
                Endpoint {
                    address: Address::V4([192, 0, 2, 1]),
                    port: 25
                },
                protocol
            ));
            assert!(!policy.allows(
                Endpoint {
                    address: Address::V4([198, 51, 100, 1]),
                    port: 80
                },
                protocol
            ));
        }
        let control = Endpoint {
            address: Address::V4([192, 0, 2, 1]),
            port: 0,
        };
        assert!(policy.allows(control, Protocol::Icmp));
        assert!(!policy.allows(control, Protocol::Icmp6));
        assert!(!policy.allows(Endpoint { port: 1, ..control }, Protocol::Icmp));
        assert!(
            !Policy {
                ipv4: false,
                ..policy
            }
            .allows(control, Protocol::Icmp)
        );
        assert!(
            !Policy {
                rules: InternetRules::Official(&[]),
                ..policy
            }
            .allows(control, Protocol::Icmp)
        );
        Ok(())
    }
}
