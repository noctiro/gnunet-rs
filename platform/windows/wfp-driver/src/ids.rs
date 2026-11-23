//! Translate the shared policy keys into WDK GUID values.
use crate::sdk;

use gnunet_wfp_dns::keys;

const fn guid(key: u128) -> sdk::GUID {
    let [_, _, _, _, _, _, _, _, a, b, c, d, e, f, g, h] = key.to_be_bytes();
    sdk::GUID {
        Data1: (key >> 96) as u32,
        Data2: (key >> 80) as u16,
        Data3: (key >> 64) as u16,
        Data4: [a, b, c, d, e, f, g, h],
    }
}

pub(crate) const DRIVER_PROVIDER: sdk::GUID = guid(keys::DRIVER_PROVIDER);
pub(crate) const FLOW_V4: sdk::GUID = guid(keys::FLOW_V4);
pub(crate) const FLOW_V6: sdk::GUID = guid(keys::FLOW_V6);
pub(crate) const DATAGRAM_V4: sdk::GUID = guid(keys::DATAGRAM_V4);
pub(crate) const DATAGRAM_V6: sdk::GUID = guid(keys::DATAGRAM_V6);
pub(crate) const CLOSURE_V4: sdk::GUID = guid(keys::CLOSURE_V4);
pub(crate) const CLOSURE_V6: sdk::GUID = guid(keys::CLOSURE_V6);
pub(crate) const GUARD_PROVIDER: sdk::GUID = guid(keys::GUARD_PROVIDER);
pub(crate) const GUARD_SUBLAYER: sdk::GUID = guid(keys::GUARD_SUBLAYER);
pub(crate) const GUARD_V4: sdk::GUID = guid(keys::GUARD_V4);
pub(crate) const GUARD_V6: sdk::GUID = guid(keys::GUARD_V6);
