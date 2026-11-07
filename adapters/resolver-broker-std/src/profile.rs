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
/// Actual native address-family profile for official resolver frames.
pub fn native_profile() -> Result<FamilyProfile, Error> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        Ok(FamilyProfile::LINUX)
    }
    #[cfg(target_vendor = "apple")]
    {
        Ok(FamilyProfile::DARWIN)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
    {
        Err(Error::Unsupported)
    }
}

fn fast(name: &[u8], family: Family) -> bool {
    name.eq_ignore_ascii_case(b"localhost")
        || name.eq_ignore_ascii_case(b"ip6-localnet")
        || std::str::from_utf8(name)
            .ok()
            .and_then(|s| s.parse::<IpAddr>().ok())
            .is_some_and(|address| family.accepts(address))
}
