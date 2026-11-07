//! Published GANA names used in GNS BOX service labels.
//!
//! These are the complete GNS-specific assignments in the pinned official
//! protocol/service headers and the observed public GANA registries. They
//! supplement the operating system's databases; host providers choose that
//! precedence. Looking up this data performs no allocation or native work.

const PROTOCOLS: &[(&str, u16)] = &[("trust", 49152)];
const SERVICE_PORTS: &[(&str, u16)] = &[("scheme", 49152), ("translation", 49153)];

/// Independent GNS protocol and service-port namespaces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Registry {
    /// Protocol numbers for the second label of a service prefix.
    Protocols,
    /// Service-port numbers for the first label of a service prefix.
    ServicePorts,
}
impl Registry {
    /// Borrow every assignment in this versioned GNS namespace.
    #[must_use]
    pub const fn entries(self) -> &'static [(&'static str, u16)] {
        match self {
            Self::Protocols => PROTOCOLS,
            Self::ServicePorts => SERVICE_PORTS,
        }
    }

    /// Resolve a registered ASCII name using GANA's case-insensitive policy.
    #[must_use]
    pub fn number(self, name: &str) -> Option<u16> {
        self.entries()
            .iter()
            .find(|entry| entry.0.eq_ignore_ascii_case(name))
            .map(|entry| entry.1)
    }

    /// Return the registered spelling of an assigned number.
    #[must_use]
    pub fn name(self, number: u16) -> Option<&'static str> {
        self.entries()
            .iter()
            .find(|entry| entry.1 == number)
            .map(|entry| entry.0)
    }
}
