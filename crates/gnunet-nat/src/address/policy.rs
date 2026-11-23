//! Observed endpoints and their projection onto an original NAT binding.

use super::SocketAddress;
use gnunet_wire::official::nat::AddressClass;

/// An observed or selected endpoint with its NAT wire classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Advertised {
    /// Original observed endpoint or its per-binding projection.
    pub address: SocketAddress,
    /// NAT address class, including any sensitivity modifier.
    pub class: AddressClass,
}

impl Advertised {
    /// Classify an observed interface address without carrying a provider port.
    ///
    /// The caller supplies the assigned address and native link class (OTHER,
    /// LAN, WLAN or BT; LOOPBACK is also valid for a loopback address). An
    /// unspecified, multicast or IPv4 limited broadcast address is not an
    /// interface observation. IPv6 scope and flow are retained unchanged.
    pub fn interface(address: SocketAddress, link: AddressClass) -> Option<Self> {
        let unicast = !address.is_unspecified()
            && match address {
                SocketAddress::V4 { ip, .. } => ip[0] & 0xf0 != 0xe0 && ip != [255; 4],
                SocketAddress::V6 { ip, .. } => ip[0] != 0xff,
            };
        let valid_link = matches!(
            link,
            AddressClass::OTHER | AddressClass::LAN | AddressClass::WLAN | AddressClass::BT
        ) || (link == AddressClass::LOOPBACK && address.is_loopback());
        (unicast && valid_link).then(|| Self {
            address: address.with_port(0),
            class: address.classify(link),
        })
    }
}

/// Effective address selection for one NAT registration, independent of storage.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AddressPolicy {
    /// Expose loopback and IPv6 link-local observations to wildcard bindings.
    pub return_local_addresses: bool,
    /// Suppress IPv6 notifications, regardless of binding or provider.
    pub disable_v6: bool,
}

impl AddressPolicy {
    /// Whether the address family is enabled for this registration.
    pub const fn allows(self, address: SocketAddress) -> bool {
        !self.disable_v6 || matches!(address, SocketAddress::V4 { .. })
    }

    /// Project one interface or manual observation onto one original binding.
    ///
    /// The observation keeps its original class, nonzero port and IPv6 scope.
    /// A zero observation port adopts this binding's port independently of
    /// other bindings. The caller owns registration flags, deduplication and
    /// the effective set used to generate add/remove notifications.
    pub fn select(self, binding: SocketAddress, observation: Advertised) -> Option<Advertised> {
        let address = observation.address;
        let same_family = matches!(
            (binding, address),
            (SocketAddress::V4 { .. }, SocketAddress::V4 { .. })
                | (SocketAddress::V6 { .. }, SocketAddress::V6 { .. })
        );
        if !same_family || !self.allows(address) {
            return None;
        }
        if binding.is_unspecified() {
            if !self.return_local_addresses && (address.is_loopback() || address.is_v6_link_local())
            {
                return None;
            }
        } else {
            let external = observation.class.0 & AddressClass::EXTERN.0 != 0;
            if binding.is_loopback() != address.is_loopback()
                || !binding.is_private() && (external || !binding.same_ip(address))
                || binding.is_v6_link_local() && !external && !same_bound_link(binding, address)
            {
                return None;
            }
        }
        Some(Advertised {
            address: if address.port() == 0 {
                address.with_port(binding.port())
            } else {
                address
            },
            ..observation
        })
    }
}

fn same_bound_link(binding: SocketAddress, observation: SocketAddress) -> bool {
    binding.same_ip(observation)
        && matches!(
            (binding, observation),
            (SocketAddress::V6 { scope: bound, .. }, SocketAddress::V6 { scope: observed, .. })
                if bound == 0 || bound == observed
        )
}

#[cfg(test)]
mod tests;
