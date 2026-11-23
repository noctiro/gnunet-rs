//! Explicit transparent UDP interception without helper interface settings.
use crate::{Failure, settings::LOCAL};
use gnunet_config::Configuration;
use gnunet_dns_service_host::{
    PacketSource, TransparentFamilies, TransparentInterfaces, TransparentPort, Upstream,
};
use gnunet_dnsstub_host::Family;
use std::{net::IpAddr, num::NonZeroU32};

pub(crate) struct Settings {
    families: TransparentFamilies,
    port: TransparentPort,
    bypass_mark: NonZeroU32,
    interfaces: TransparentInterfaces,
}

fn families(config: &Configuration) -> Result<TransparentFamilies, Failure> {
    let Some(value) = config.get(LOCAL, b"TPROXY_FAMILIES") else {
        return Ok(TransparentFamilies::default());
    };
    for (name, families) in [
        (b"ipv4", TransparentFamilies::Ipv4),
        (b"ipv6", TransparentFamilies::Ipv6),
        (b"dual", TransparentFamilies::Dual),
    ] {
        if value.eq_ignore_ascii_case(name) {
            return Ok(families);
        }
    }
    Err("TPROXY_FAMILIES must be ipv4, ipv6 or dual".into())
}

fn required<'a>(config: &'a Configuration, key: &[u8]) -> Result<&'a str, Failure> {
    config
        .get(LOCAL, key)
        .ok_or_else(|| {
            format!(
                "LINUX_BACKEND=TPROXY requires {}",
                String::from_utf8_lossy(key)
            )
            .into()
        })
        .and_then(|value| std::str::from_utf8(value).map_err(Into::into))
}

fn mark(value: &str) -> Result<NonZeroU32, Failure> {
    let (digits, radix) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or((value, 10), |digits| (digits, 16));
    if digits.is_empty()
        || !digits.bytes().all(|byte| match radix {
            16 => byte.is_ascii_hexdigit(),
            _ => byte.is_ascii_digit(),
        })
    {
        return Err("TPROXY_BYPASS_MARK must be a nonzero decimal or 0x hexadecimal u32".into());
    }
    NonZeroU32::new(u32::from_str_radix(digits, radix)?)
        .ok_or_else(|| "TPROXY_BYPASS_MARK must be nonzero".into())
}

pub(super) fn read(config: &Configuration) -> Result<Option<Settings>, Failure> {
    let backend = config.get(LOCAL, b"LINUX_BACKEND").unwrap_or(b"HELPER");
    if backend.eq_ignore_ascii_case(b"HELPER") {
        return Ok(None);
    }
    if !backend.eq_ignore_ascii_case(b"TPROXY") {
        return Err("LINUX_BACKEND must be HELPER or TPROXY".into());
    }
    let value = required(config, b"TPROXY_PORT")?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("TPROXY_PORT must be an explicit nonzero UDP port other than 53".into());
    }
    let port = TransparentPort::new(value.parse()?)
        .ok_or("TPROXY_PORT must be an explicit nonzero UDP port other than 53")?;
    Ok(Some(Settings {
        families: families(config)?,
        port,
        bypass_mark: mark(required(config, b"TPROXY_BYPASS_MARK")?)?,
        interfaces: TransparentInterfaces::new(
            required(config, b"TPROXY_INTERFACES")?.split_ascii_whitespace(),
        )
        .map_err(|error| format!("TPROXY_INTERFACES {error}"))?,
    }))
}

pub(super) async fn open<'id>(
    settings: Settings,
    upstream: &mut Upstream,
    exit: IpAddr,
) -> Result<PacketSource<'id>, Failure> {
    let family = match exit {
        IpAddr::V4(_) => Family::V4,
        IpAddr::V6(_) => Family::V6,
    };
    let reservations = upstream
        .standard_owner_mut()
        .ok_or("Linux TPROXY requires original standard DNSSTUB socket reservations")?
        .reserve_sockets(family)?;
    // The native boundary resolves each ingress name against the live kernel
    // interface table before admitting captures. These exact sockets remain
    // owned through its capture and upstream-bypass lifetime.
    Ok(PacketSource::transparent(
        reservations,
        settings.families,
        settings.port,
        settings.bypass_mark,
        settings.interfaces,
    )
    .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configured() -> Result<Configuration, Failure> {
        let mut config = Configuration::new(Default::default());
        for (key, value) in [
            (b"LINUX_BACKEND".as_slice(), b"TPROXY".as_slice()),
            (b"TPROXY_PORT", b"5353"),
            (b"TPROXY_BYPASS_MARK", b"0x80000000"),
            (b"TPROXY_INTERFACES", b"eth0 eth1"),
        ] {
            config.set_value(LOCAL, key, Some(value))?;
        }
        Ok(config)
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Configuration regressions assert explicit native selection and rejection before any system operation"
    )]
    fn explicit_transparent_configuration_preserves_full_mark_and_skips_helper_fields()
    -> Result<(), Failure> {
        let mut config = configured()?;
        config.set_value(b"dns", b"IPV4ADDR", Some(b"malformed"))?;
        config.set_value(b"dns", b"IFNAME", Some(b"invalid helper interface"))?;
        config.set_value(LOCAL, b"HELPER_BINARY", Some(b"relative-helper"))?;
        let settings = super::super::config::read(
            &config,
            65535,
            std::time::Duration::from_secs(1),
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            super::super::Profile::Service,
        )?;
        let super::super::Settings::Transparent(settings) = settings else {
            return Err("explicit TPROXY did not select its native backend".into());
        };
        assert_eq!(settings.families, TransparentFamilies::Dual);
        assert_eq!(settings.port.get(), 5353);
        assert_eq!(settings.bypass_mark.get(), 0x8000_0000);
        assert!(settings.interfaces.contains("eth0"));
        assert!(settings.interfaces.contains("eth1"));
        assert_eq!(mark("4294967295")?.get(), u32::MAX);
        Ok(())
    }

    #[test]
    fn ingress_family_is_independent_of_the_upstream_address() -> Result<(), Failure> {
        let mut config = configured()?;
        for (value, families, exit) in [
            (
                b"IPv4",
                TransparentFamilies::Ipv4,
                IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            ),
            (
                b"ipv6",
                TransparentFamilies::Ipv6,
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            ),
        ] {
            config.set_value(LOCAL, b"TPROXY_FAMILIES", Some(value))?;
            let settings = super::super::config::read(
                &config,
                65535,
                std::time::Duration::from_secs(1),
                exit,
                super::super::Profile::Service,
            )?;
            if !matches!(settings, super::super::Settings::Transparent(settings) if settings.families == families)
            {
                return Err("wrong TPROXY ingress family for the configured upstream".into());
            }
        }
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Every malformed or missing explicit capture field must fail before reserving sockets or changing native policy"
    )]
    fn missing_or_malformed_transparent_settings_never_fall_back_to_helper() -> Result<(), Failure>
    {
        for (key, values) in [
            (
                b"LINUX_BACKEND".as_slice(),
                [b"".as_slice(), b"UNKNOWN", b" TPROXY"],
            ),
            (b"TPROXY_PORT", [b"0".as_slice(), b"53", b"65536"]),
            (b"TPROXY_FAMILIES", [b"".as_slice(), b"both", b"ipv4 ipv6"]),
            (
                b"TPROXY_BYPASS_MARK",
                [b"0".as_slice(), b"0x", b"4294967296"],
            ),
            (b"TPROXY_INTERFACES", [b"".as_slice(), b"lo lo", b"a:b"]),
        ] {
            for value in values {
                let mut config = configured()?;
                config.set_value(LOCAL, key, Some(value))?;
                assert!(read(&config).is_err(), "accepted {key:?}={value:?}");
            }
        }
        for key in [
            b"TPROXY_PORT".as_slice(),
            b"TPROXY_BYPASS_MARK",
            b"TPROXY_INTERFACES",
        ] {
            let mut config = configured()?;
            config.set_value(LOCAL, key, None)?;
            assert!(read(&config).is_err(), "accepted missing {key:?}");
        }
        assert!(read(&Configuration::new(Default::default()))?.is_none());
        Ok(())
    }
}
