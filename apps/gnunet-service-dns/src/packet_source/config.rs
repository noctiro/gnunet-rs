//! Concrete helper/device settings, independent of shared DNS phase policy.
use super::{Profile, Settings};
#[cfg(all(
    any(target_os = "macos", target_os = "ios"),
    feature = "apple-dns-proxy"
))]
use crate::settings::number;
#[cfg(unix)]
use crate::settings::{LOCAL, duration};
use crate::{
    Failure,
    settings::{text, yes},
};
use gnunet_config::Configuration;
#[cfg(unix)]
use gnunet_dns_service_host::HelperOptions;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

#[cfg(unix)]
fn helper_binary(c: &Configuration) -> Result<std::path::PathBuf, Failure> {
    let binary = if c.get(LOCAL, b"HELPER_BINARY").is_some() {
        c.get_absolute_filename(LOCAL, b"HELPER_BINARY", &gnunet_config::ProcessEnvironment)?
    } else {
        c.suid_binary_path_with(b"gnunet-helper-dns", &mut Default::default())?
    };
    if !binary.is_absolute() {
        return Err("DNS helper path must be absolute".into());
    }
    Ok(binary)
}

pub(crate) fn read(
    c: &Configuration,
    slice: usize,
    grace: Duration,
    exit: IpAddr,
    profile: Profile,
) -> Result<Settings, Failure> {
    #[cfg(all(
        any(target_os = "macos", target_os = "ios"),
        feature = "apple-dns-proxy"
    ))]
    if matches!(profile, Profile::Provider) {
        let multicast_timeout = c
            .get(LOCAL, b"NATIVE_MULTICAST_RELAY")
            .map(|_| c.get_yesno(LOCAL, b"NATIVE_MULTICAST_RELAY"))
            .transpose()?
            .unwrap_or(false)
            .then(|| duration(c, b"REQUEST_HARD_LIFETIME", Duration::from_secs(45)))
            .transpose()?;
        return Ok(Settings::ApplicationFlows(
            gnunet_dns_service_host::FlowLimits {
                flows: number(c, b"NATIVE_FLOWS", 32)?,
                read: gnunet_native::dns_proxy::ReadLimits {
                    datagrams: number(c, b"NATIVE_BATCH_DATAGRAMS", 16)?,
                    datagram_bytes: number(
                        c,
                        b"DNS_BYTES",
                        gnunet_dns_service_host::core::MAX_DNS_BYTES,
                    )?,
                    batch_bytes: number(c, b"NATIVE_BATCH_BYTES", 128 * 1024)?,
                },
                open_timeout: duration(c, b"NATIVE_OPEN_TIMEOUT", Duration::from_secs(5))?,
                multicast_timeout,
            },
        ));
    }
    let _ = profile;
    let _ = (slice, grace);
    #[cfg(target_os = "linux")]
    if let Some(settings) = super::linux::read(c)? {
        return Ok(Settings::Transparent(settings));
    }
    let ipv4: Ipv4Addr = text(c, b"IPV4ADDR", "169.254.1.1")?.parse()?;
    let mask: Ipv4Addr = text(c, b"IPV4MASK", "255.255.0.0")?.parse()?;
    let ipv6: Ipv6Addr = text(c, b"IPV6ADDR", "2001:db8::1")?.parse()?;
    let prefix: u8 = text(c, b"IPV6PREFIX", "126")?.parse()?;
    if prefix > 128 {
        return Err("DNS IPV6PREFIX exceeds128".into());
    }
    let interface = text(
        c,
        b"IFNAME",
        if cfg!(target_os = "macos") {
            "utun"
        } else {
            "gnunet-dns"
        },
    )?
    .to_owned();
    #[cfg(unix)]
    if interface.is_empty()
        || interface.len() >= 16
        || !interface
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    {
        return Err("invalid DNS IFNAME".into());
    }
    #[cfg(windows)]
    if interface.is_empty() || interface.encode_utf16().count() > 128 || interface.contains('\0') {
        return Err("invalid Windows DNS IFNAME".into());
    }
    if exit == IpAddr::V4(ipv4) || exit == IpAddr::V6(ipv6) {
        return Err("DNS_EXIT must differ from interception interface addresses".into());
    }
    #[cfg(unix)]
    let source = Settings::Helper(HelperOptions {
        program: helper_binary(c)?,
        interface,
        ipv6,
        prefix,
        ipv4,
        mask,
        skip_routing: yes(c, b"SKIP_ROUTING_SETUP", false)?,
        frame_bytes: 65535,
        io_slice_bytes: slice,
        input_lifetime: duration(c, b"HELPER_INPUT_LIFETIME", Duration::from_secs(10))?,
        stop_grace: grace,
    });
    #[cfg(windows)]
    let source = Settings::Windows(super::windows::Settings::read(
        c,
        super::windows::Addresses {
            interface,
            ipv4,
            mask,
            ipv6,
            prefix,
        },
        yes(c, b"SKIP_ROUTING_SETUP", false)?,
    )?);
    Ok(source)
}

#[cfg(all(test, unix))]
#[test]
fn helper_resolution_uses_the_selected_installation_policy() -> Result<(), Failure> {
    use std::path::Path;
    let mut config = Configuration::default();
    config.set_value(b"PATHS", b"SUID_BINARY_PATH", Some(b"/selected/libexec"))?;
    if helper_binary(&config)? != Path::new("/selected/libexec/gnunet-helper-dns") {
        return Err("DNS helper ignored the installation policy".into());
    }
    config.set_value(LOCAL, b"HELPER_BINARY", Some(b"/selected/helper"))?;
    if helper_binary(&config)? != Path::new("/selected/helper") {
        return Err("DNS helper ignored its explicit override".into());
    }
    config.set_value(LOCAL, b"HELPER_BINARY", Some(b"$SUID_BINARY_PATH/explicit"))?;
    if helper_binary(&config)? != Path::new("/selected/libexec/explicit") {
        return Err("DNS helper ignored the absolute configured expansion".into());
    }
    config.set_value(LOCAL, b"HELPER_BINARY", Some(b"relative-helper"))?;
    if helper_binary(&config).is_ok() {
        return Err("DNS helper accepted a relative executable".into());
    }
    Ok(())
}
