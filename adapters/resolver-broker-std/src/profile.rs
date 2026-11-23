//! Native Resolver profile utilities; actual process ownership is gnunet-resolver-broker.
use gnunet_client::resolver::{Family, FamilyProfile};
use gnunet_config::Configuration;
use gnunet_types::Error;
use std::net::IpAddr;

/// Actual native resolver check_config acceptance, independent of reachability.
pub fn check_config(config: &Configuration) -> bool {
    config.get(b"resolver", b"UNIXPATH").is_some()
        || config
            .get(b"resolver", b"HOSTNAME")
            .is_some_and(|name| fast(name, Family::Any))
}
/// Build the official resolver frame profile from the target SDK's socket ABI.
pub fn native_profile() -> Result<FamilyProfile, Error> {
    let (inet, inet6) = gnunet_native::addresses::internet_address_families();
    FamilyProfile::new(inet, inet6)
}

fn fast(name: &[u8], family: Family) -> bool {
    name.eq_ignore_ascii_case(b"localhost")
        || name.eq_ignore_ascii_case(b"ip6-localnet")
        || std::str::from_utf8(name)
            .ok()
            .and_then(|s| s.parse::<IpAddr>().ok())
            .is_some_and(|address| family.accepts(address))
}
