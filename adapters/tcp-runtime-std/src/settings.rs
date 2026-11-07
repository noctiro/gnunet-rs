use gnunet_config::Configuration;
use gnunet_tcp_communicator_core::session::Policy;
use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroUsize,
};
/// A configured BINDTO hostname, not a public TRANSPORT address or DNS result.
#[derive(Debug)]
pub struct Hostname {
    name: Vec<u8>,
    port: u16,
}
impl Hostname {
    /// Original name passed to the shared official Resolver.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name
    }
    /// Requested bind port; zero asks each actual socket's kernel for a port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }
}
/// Parsed official TCP communicator options, independent of wire extensions.
pub struct Settings {
    /// Numeric bindings. Empty only when `hostname` requires actual resolution.
    pub bindings: Vec<SocketAddr>,
    /// Original hostname binding, resolved and prebound before USERNAME.
    pub hostname: Option<Hostname>,
    /// Original reference policy with official overrides.
    pub policy: Policy,
    /// Explicit IPv6 admission policy.
    pub disable_v6: bool,
    /// Selected PILS identity/HELLO profile, independent of the TCP handshake.
    pub identity_profile: gnunet_pils::Profile,
}
fn bindto(
    bind: &str,
    disable_v6: bool,
) -> Result<(Vec<SocketAddr>, Option<Hostname>), Box<dyn Error>> {
    if !bind.is_empty() && bind.bytes().all(|byte| byte.is_ascii_digit()) {
        let port = bind.parse::<u16>()?;
        let mut addresses = vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)];
        if !disable_v6 {
            addresses.push(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port));
        }
        return Ok((addresses, None));
    }
    let numeric = bind.parse::<SocketAddr>().ok().or_else(|| {
        let ip = bind
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .unwrap_or(bind);
        ip.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, 0))
    });
    if let Some(address) = numeric {
        if disable_v6 && address.is_ipv6() {
            return Err("IPv6 BINDTO disabled".into());
        }
        return Ok((vec![address], None));
    }
    let (name, port) = match bind.rsplit_once(':') {
        Some((name, port)) => (name, port.parse::<u16>()?),
        None => (bind, 0),
    };
    if name.is_empty()
        || name.len() > 255
        || name.bytes().any(|byte| {
            byte == 0 || byte.is_ascii_whitespace() || matches!(byte, b':' | b'[' | b']')
        })
    {
        return Err("BINDTO requires a bounded hostname, numeric address, or bare port".into());
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(name.len())?;
    bytes.extend_from_slice(name.as_bytes());
    Ok((Vec::new(), Some(Hostname { name: bytes, port })))
}
impl Settings {
    /// Parse official BINDTO bare port, numeric address (including port0), or
    /// hostname with optional port. Hostnames remain unresolved until the
    /// original shared Resolver and prebinding owner actually run.
    pub fn parse(config: &Configuration) -> Result<Self, Box<dyn Error>> {
        let section = b"communicator-tcp";
        let identity_profile = gnunet_pils::Profile::configured(
            config.get(b"PILS", b"PROFILE"),
            config.get(b"communicator-tcp-rust", b"PILS_PROFILE"),
        )?;
        let bind = std::str::from_utf8(
            config
                .get(section, b"BINDTO")
                .ok_or("missing communicator-tcp BINDTO")?,
        )?;
        let disable_v6 = config.get_yesno(section, b"DISABLE_V6").unwrap_or(false);
        let (bindings, hostname) = bindto(bind, disable_v6)?;
        let mut policy = Policy::reference(NonZeroUsize::new(1024).ok_or("entropy policy")?);
        policy.max_backpressure =
            usize::try_from(config.get_number(section, b"MAX_QUEUE_LENGTH").unwrap_or(8))?;
        policy.rekey_interval_us = config
            .get_time(section, b"REKEY_INTERVAL")
            .unwrap_or(86_400_000_000);
        policy.rekey_max_bytes = config
            .get_number(section, b"REKEY_MAX_BYTES")
            .unwrap_or(400 * 1024 * 1024);
        if policy.rekey_max_bytes == 0 {
            return Err("REKEY_MAX_BYTES must be positive".into());
        }
        Ok(Self {
            bindings,
            hostname,
            policy,
            disable_v6,
            identity_profile,
        })
    }
}

#[cfg(test)]
mod profile_tests {
    use super::*;
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "The actual normal settings parser must select one identity profile and reject incoherent node/local policy"
    )]
    fn node_identity_profile_reaches_tcp_startup_settings_without_changing_handshake_policy()
    -> Result<(), Box<dyn Error>> {
        let mut config = Configuration::default();
        config.set_value(b"communicator-tcp", b"BINDTO", Some(b"127.0.0.1:0"))?;
        config.set_number(b"communicator-tcp", b"REKEY_MAX_BYTES", 777)?;
        assert_eq!(
            Settings::parse(&config)?.identity_profile,
            gnunet_pils::Profile::Reference029
        );
        config.set_value(b"PILS", b"PROFILE", Some(b"deterministic"))?;
        let selected = Settings::parse(&config)?;
        assert_eq!(
            selected.identity_profile,
            gnunet_pils::Profile::ReferenceDeterministic
        );
        assert_eq!(selected.policy.rekey_max_bytes, 777);
        assert_eq!(selected.bindings, ["127.0.0.1:0".parse::<SocketAddr>()?]);
        config.set_value(
            b"communicator-tcp-rust",
            b"PILS_PROFILE",
            Some(b"reference-0.29.1"),
        )?;
        let failure = Settings::parse(&config)
            .err()
            .ok_or("incoherent TCP identity profile admitted")?;
        assert_eq!(
            failure.downcast_ref::<gnunet_types::Error>(),
            Some(&gnunet_types::Error::Conflict)
        );
        config.set_value(
            b"communicator-tcp-rust",
            b"PILS_PROFILE",
            Some(b"deterministic"),
        )?;
        assert_eq!(
            Settings::parse(&config)?.identity_profile,
            selected.identity_profile
        );
        Ok(())
    }
}
