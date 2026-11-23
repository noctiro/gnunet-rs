//! Parse the configured upstream with its native IPv6 zone intact.
use crate::{Failure, packet_source::Profile};
use std::{
    net::{IpAddr, SocketAddr, SocketAddrV6},
    num::NonZeroU32,
};

const DNS_PORT: u16 = 53;

pub(super) fn read(
    config: &gnunet_config::Configuration,
    profile: Profile,
) -> Result<SocketAddr, Failure> {
    let value = config
        .get(b"dns", b"DNS_EXIT")
        .ok_or("[dns] DNS_EXIT is required")?;
    let value =
        std::str::from_utf8(value).map_err(|_| "[dns] DNS_EXIT must be a numeric address")?;
    parse(value, profile)
}

fn parse(value: &str, profile: Profile) -> Result<SocketAddr, Failure> {
    let (address, zone) = match value.split_once('%') {
        Some((address, zone)) => {
            let scope = zone
                .parse::<NonZeroU32>()
                .ok()
                .filter(|_| zone.bytes().all(|b| b.is_ascii_digit()))
                .ok_or("DNS_EXIT IPv6 zone must be a nonzero decimal value")?;
            (address, Some(scope))
        }
        None => (value, None),
    };
    match address.parse::<IpAddr>()? {
        IpAddr::V4(ip)
            if zone.is_none()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_broadcast() =>
        {
            Ok(SocketAddr::new(ip.into(), DNS_PORT))
        }
        IpAddr::V6(ip)
            if !ip.is_unspecified() && !ip.is_multicast() && ip.to_ipv4_mapped().is_none() =>
        {
            let supports_site_zone = match profile {
                Profile::Service => cfg!(windows),
                #[cfg(all(
                    any(target_os = "macos", target_os = "ios"),
                    feature = "apple-dns-proxy"
                ))]
                Profile::Provider => true,
            };
            let scoped = ip.is_unicast_link_local()
                || (supports_site_zone && ip.segments()[0] & 0xffc0 == 0xfec0);
            if scoped != zone.is_some() {
                return Err("DNS_EXIT IPv6 zone must agree with the resolver address scope".into());
            }
            Ok(SocketAddrV6::new(ip, DNS_PORT, 0, zone.map_or(0, NonZeroU32::get)).into())
        }
        _ => Err("DNS_EXIT must be a numeric unicast resolver address".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_upstream_does_not_select_a_public_resolver() -> Result<(), Failure> {
        let mut config = gnunet_config::Configuration::default();
        if read(&config, Profile::Service).is_ok() {
            return Err("DNS selected an implicit upstream".into());
        }
        config.set_value(b"dns", b"DNS_EXIT", Some(b"192.0.2.53"))?;
        if read(&config, Profile::Service)? != "192.0.2.53:53".parse::<SocketAddr>()? {
            return Err("DNS did not retain the configured upstream".into());
        }
        Ok(())
    }

    #[test]
    fn preserves_original_zone_and_standard_dns_port() -> Result<(), Failure> {
        for (config, endpoint) in [
            ("192.0.2.53", "192.0.2.53:53"),
            ("2001:db8::53", "[2001:db8::53]:53"),
            ("fe80::53%7", "[fe80::53%7]:53"),
        ] {
            if parse(config, Profile::Service)? != endpoint.parse::<SocketAddr>()? {
                return Err(format!("DNS_EXIT {config} changed its original endpoint").into());
            }
        }
        for invalid in [
            "fe80::53",
            "fe80::53%0",
            "fe80::53%",
            "fe80::53%7%8",
            "fe80::53%eth0",
            "2001:db8::53%7",
            "192.0.2.53%7",
            "::ffff:192.0.2.53",
            "255.255.255.255",
        ] {
            if parse(invalid, Profile::Service).is_ok() {
                return Err(format!("DNS_EXIT admitted {invalid}").into());
            }
        }
        let (site, unsupported) = if cfg!(windows) {
            ("fec0::53%11", "fec0::53")
        } else {
            ("fec0::53", "fec0::53%11")
        };
        if parse(site, Profile::Service)?.port() != DNS_PORT
            || parse(unsupported, Profile::Service).is_ok()
        {
            return Err("DNS_EXIT admitted a site zone the socket backend cannot match".into());
        }
        Ok(())
    }

    #[cfg(all(
        any(target_os = "macos", target_os = "ios"),
        feature = "apple-dns-proxy"
    ))]
    #[test]
    fn connected_provider_requires_an_explicit_site_zone() -> Result<(), Failure> {
        let expected = "[fec0::53%11]:53".parse::<SocketAddr>()?;
        if parse("fec0::53%11", Profile::Provider)? != expected
            || parse("fec0::53", Profile::Provider).is_ok()
        {
            return Err("native provider site zone was lost or inferred".into());
        }
        Ok(())
    }
}
