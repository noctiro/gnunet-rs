//! Fixed identities for the GNUnet native DNS callout contract.
use gnunet_wfp_dns::keys;
use windows_sys::{Win32::NetworkManagement::WindowsFilteringPlatform as api, core::GUID};

/// Persistent provider of the native DNS callout metadata.
pub const DRIVER_PROVIDER: GUID = GUID::from_u128(keys::DRIVER_PROVIDER);
/// IPv4 flow discovery callout; associates context with the IPv4 datagram callout.
pub const FLOW_V4: GUID = GUID::from_u128(keys::FLOW_V4);
/// IPv6 flow discovery callout; associates context with the IPv6 datagram callout.
pub const FLOW_V6: GUID = GUID::from_u128(keys::FLOW_V6);
/// IPv4 bidirectional datagram callout, including receiving-flow checks.
pub const DATAGRAM_V4: GUID = GUID::from_u128(keys::DATAGRAM_V4);
/// IPv6 bidirectional datagram callout, including receiving-flow checks.
pub const DATAGRAM_V6: GUID = GUID::from_u128(keys::DATAGRAM_V6);
/// IPv4 original endpoint lifetime callout.
pub const CLOSURE_V4: GUID = GUID::from_u128(keys::CLOSURE_V4);
/// IPv6 original endpoint lifetime callout.
pub const CLOSURE_V6: GUID = GUID::from_u128(keys::CLOSURE_V6);
/// Native callout identities; callers cannot substitute an arbitrary provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Callout {
    /// IPv4 ALE flow-established callback.
    FlowV4,
    /// IPv6 ALE flow-established callback.
    FlowV6,
    /// IPv4 datagram capture and receive gate.
    DatagramV4,
    /// IPv6 datagram capture and receive gate.
    DatagramV6,
    /// IPv4 ALE endpoint-closure callback.
    ClosureV4,
    /// IPv6 ALE endpoint-closure callback.
    ClosureV6,
}
pub(super) const CALLOUTS: [Callout; 6] = [
    Callout::FlowV4,
    Callout::FlowV6,
    Callout::DatagramV4,
    Callout::DatagramV6,
    Callout::ClosureV4,
    Callout::ClosureV6,
];
impl Callout {
    pub(super) const fn key(self) -> GUID {
        match self {
            Self::FlowV4 => FLOW_V4,
            Self::FlowV6 => FLOW_V6,
            Self::DatagramV4 => DATAGRAM_V4,
            Self::DatagramV6 => DATAGRAM_V6,
            Self::ClosureV4 => CLOSURE_V4,
            Self::ClosureV6 => CLOSURE_V6,
        }
    }
    pub(super) const fn layer(self) -> GUID {
        match self {
            Self::FlowV4 => api::FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
            Self::FlowV6 => api::FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,
            Self::DatagramV4 => api::FWPM_LAYER_DATAGRAM_DATA_V4,
            Self::DatagramV6 => api::FWPM_LAYER_DATAGRAM_DATA_V6,
            Self::ClosureV4 => api::FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V4,
            Self::ClosureV6 => api::FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V6,
        }
    }
}
pub(super) fn same_guid(a: GUID, b: GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}
