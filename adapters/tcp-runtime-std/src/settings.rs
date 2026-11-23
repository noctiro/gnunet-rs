use gnunet_config::Configuration;
use gnunet_tcp_communicator_core::session::Policy;
use std::{
    error::Error,
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
};
/// Native TCP peer ingress policy; the public TCP protocol is unchanged.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PeerMode {
    /// Bind/adopt configured peer listeners and publish their actual addresses.
    #[default]
    Listening,
    /// Initiate ordinary peer connections only; no listener or local address ADD.
    OutboundOnly,
}
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
#[derive(Debug)]
pub(crate) enum Binding {
    Wildcard(u16),
    Numeric(SocketAddr),
    Hostname(Hostname),
}

/// Parsed official TCP communicator options, independent of wire extensions.
pub struct Settings {
    binding: Option<Binding>,
    /// Original reference policy with official overrides.
    pub policy: Policy,
    disable_v6: bool,
    /// Selected PILS identity/HELLO profile, independent of the TCP handshake.
    pub identity_profile: gnunet_pils::Profile,
}
fn bindto(bind: &str, disable_v6: bool) -> Result<Binding, Box<dyn Error>> {
    if !bind.is_empty() && bind.bytes().all(|byte| byte.is_ascii_digit()) {
        return Ok(Binding::Wildcard(bind.parse()?));
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
        return Ok(Binding::Numeric(address));
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
    Ok(Binding::Hostname(Hostname { name: bytes, port }))
}
impl Settings {
    /// The configured IPv6 admission policy used for all native endpoints.
    #[must_use]
    pub const fn disable_v6(&self) -> bool {
        self.disable_v6
    }

    /// Only listening settings carry a binding that can create or adopt ingress.
    pub(crate) fn binding(&self) -> Option<&Binding> {
        self.binding.as_ref()
    }

    /// Original hostname awaiting resolution, if BINDTO selected a name.
    #[must_use]
    pub fn hostname(&self) -> Option<&Hostname> {
        match self.binding()? {
            Binding::Hostname(name) => Some(name),
            _ => None,
        }
    }

    /// Parse official BINDTO bare port, numeric address (including port0), or
    /// hostname with optional port. Hostnames remain unresolved until the
    /// original shared Resolver and prebinding owner actually run.
    pub fn parse(config: &Configuration) -> Result<Self, Box<dyn Error>> {
        Self::parse_for(config, PeerMode::Listening)
    }
    /// Select native ingress independently from the official session policy.
    /// Outbound-only mode neither reads BINDTO nor requests bind-name resolution.
    pub fn parse_for(config: &Configuration, mode: PeerMode) -> Result<Self, Box<dyn Error>> {
        let section = b"communicator-tcp";
        let identity_profile = gnunet_pils::Profile::configured(
            config.get(b"PILS", b"PROFILE"),
            config.get(b"communicator-tcp-rust", b"PILS_PROFILE"),
        )?;
        let disable_v6 = config
            .get(section, b"DISABLE_V6")
            .map(|_| config.get_yesno(section, b"DISABLE_V6"))
            .transpose()?
            .unwrap_or(false);
        let binding = match mode {
            PeerMode::Listening => {
                let bind = std::str::from_utf8(
                    config
                        .get(section, b"BINDTO")
                        .ok_or("missing communicator-tcp BINDTO")?,
                )?;
                Some(bindto(bind, disable_v6)?)
            }
            PeerMode::OutboundOnly => None,
        };
        let mut policy = Policy::reference(NonZeroUsize::new(1024).ok_or("entropy policy")?);
        if let Ok(max) = config.get_number(section, b"MAX_QUEUE_LENGTH") {
            policy.max_backpressure = usize::try_from(max)?;
        }
        policy.rekey_interval_us = config
            .get_time(section, b"REKEY_INTERVAL")
            .unwrap_or(policy.rekey_interval_us);
        policy.rekey_max_bytes = config
            .get_number(section, b"REKEY_MAX_BYTES")
            .unwrap_or(policy.rekey_max_bytes);
        if policy.rekey_max_bytes == 0 {
            return Err("REKEY_MAX_BYTES must be positive".into());
        }
        Ok(Self {
            binding,
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
        reason = "Outbound mode must preserve actual official session policy while omitting all bind selection"
    )]
    fn outbound_profile_needs_no_bindto_and_preserves_peer_protocol_policy()
    -> Result<(), Box<dyn Error>> {
        let mut config = Configuration::default();
        config.set_number(b"communicator-tcp", b"REKEY_MAX_BYTES", 777)?;
        let outbound = Settings::parse_for(&config, PeerMode::OutboundOnly)?;
        assert!(outbound.binding().is_none());
        assert!(outbound.hostname().is_none());
        assert_eq!(outbound.policy.rekey_max_bytes, 777);
        let refusal = crate::listeners::Listeners::prepare(&outbound, Default::default())
            .err()
            .ok_or("outbound settings admitted listener preparation")?;
        assert_eq!(refusal.kind(), std::io::ErrorKind::InvalidInput);
        config.set_value(
            b"communicator-tcp",
            b"BINDTO",
            Some(b"invalid bind selection:letters"),
        )?;
        let selected = Settings::parse_for(&config, PeerMode::OutboundOnly)?;
        assert!(selected.binding().is_none());
        assert!(selected.hostname().is_none());
        assert_eq!(
            selected.policy.rekey_max_bytes,
            outbound.policy.rekey_max_bytes
        );
        assert!(Settings::parse(&config).is_err());
        Ok(())
    }
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
        assert!(
            matches!(selected.binding(), Some(Binding::Numeric(address)) if *address == SocketAddr::from(([127, 0, 0, 1], 0)))
        );
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
