//! Configuration-only selection. No key, state, socket or interface is opened here.
use gnunet_config::{Configuration, ProcessEnvironment};
use gnunet_udp_communicator_core::send::Policy;
use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
};
type Cause = Box<dyn Error>;
const SECTION: &[u8] = b"communicator-udp";
const RUST: &[u8] = b"communicator-udp-rust";
pub(super) struct Settings {
    pub binds: [Option<SocketAddr>; 2],
    pub directory: PathBuf,
    pub ikm: PathBuf,
    pub transmit: Policy,
    pub peers: usize,
    pub endpoints: usize,
    pub startup_micros: u64,
    pub disable_broadcast: bool,
    /// Selected PILS identity/HELLO profile; UDP rekey policy is independent.
    pub identity_profile: gnunet_pils::Profile,
}
fn bind(value: &[u8], v6: bool) -> Result<SocketAddr, Cause> {
    let text = std::str::from_utf8(value)?.trim();
    let wildcard = if v6 {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    };
    let address = if let Ok(port) = text.parse::<u16>() {
        SocketAddr::new(wildcard, port)
    } else if let Ok(address) = text.parse::<SocketAddr>() {
        address
    } else {
        SocketAddr::new(text.parse::<IpAddr>()?, 0)
    };
    if address.is_ipv6() != v6
        || matches!(address, SocketAddr::V6(a) if a.ip().to_ipv4_mapped().is_some())
    {
        return Err("UDP bind address does not match the selected native family".into());
    }
    Ok(address)
}
fn number(config: &Configuration, key: &[u8], default: usize) -> Result<usize, Cause> {
    if config.get(RUST, key).is_none() {
        return Ok(default);
    }
    let n = usize::try_from(config.get_number(RUST, key)?)?;
    if !(1..=4096).contains(&n) {
        return Err("UDP peer/endpoint resource limit must be 1..=4096".into());
    }
    Ok(n)
}
impl Settings {
    pub fn parse(config: &Configuration, ipv6_supported: bool) -> Result<Self, Cause> {
        let identity_profile = gnunet_pils::Profile::configured(
            config.get(b"PILS", b"PROFILE"),
            config.get(RUST, b"PILS_PROFILE"),
        )?;
        let disabled = !ipv6_supported
            || (config.get(SECTION, b"DISABLE_V6").is_some()
                && config.get_yesno(SECTION, b"DISABLE_V6")?);
        let v4 = bind(
            config
                .get(SECTION, b"BINDTO")
                .ok_or("missing [communicator-udp] BINDTO")?,
            false,
        )?;
        let v6 = if disabled {
            None
        } else {
            Some(bind(
                config
                    .get(SECTION, b"BINDTO6")
                    .ok_or("missing [communicator-udp] BINDTO6")?,
                true,
            )?)
        };
        let mut transmit = Policy::default();
        if config.get(SECTION, b"REKEY_INTERVAL").is_some() {
            transmit.rekey_after_us = config.get_time(SECTION, b"REKEY_INTERVAL")?;
        }
        if config.get(SECTION, b"REKEY_MAX_BYTES").is_some() {
            let bytes = config.get_size(SECTION, b"REKEY_MAX_BYTES")?;
            if bytes == 0 {
                return Err("REKEY_MAX_BYTES must be positive".into());
            }
            transmit.maximum_secret_bytes = bytes;
            transmit.rekey_after_bytes = u64::try_from(u128::from(bytes) * 7 / 10)?;
        }
        let ikm = config.get_filename(b"peer", b"PRIVATE_KEY", &ProcessEnvironment)?;
        let directory = if config.get(RUST, b"STATE_DIRECTORY").is_some() {
            config.get_filename(RUST, b"STATE_DIRECTORY", &ProcessEnvironment)?
        } else {
            let raw = b"$GNUNET_DATA_HOME/udp-rust-state";
            let expanded = config.expand_dollar(raw, &ProcessEnvironment)?;
            if expanded == raw {
                return Err(
                    "set GNUNET_DATA_HOME or [communicator-udp-rust] STATE_DIRECTORY".into(),
                );
            }
            config.expand_filename(&expanded, &ProcessEnvironment)?
        };
        if !directory.is_absolute()
            || directory.file_name().is_none()
            || directory == ikm
            || directory.starts_with(&ikm)
            || ikm.starts_with(&directory)
        {
            return Err("UDP state must be an independent absolute Rust-owned directory".into());
        }
        let startup_micros = if config.get(RUST, b"STARTUP_TIMEOUT").is_some() {
            config.get_time(RUST, b"STARTUP_TIMEOUT")?
        } else {
            60_000_000
        };
        if startup_micros == 0 || startup_micros == u64::MAX {
            return Err("STARTUP_TIMEOUT must be finite and positive".into());
        }
        Ok(Self {
            binds: [Some(v4), v6],
            directory,
            ikm,
            transmit,
            peers: number(config, b"MAX_PEERS", 64)?,
            endpoints: number(config, b"MAX_ENDPOINTS", 128)?,
            startup_micros,
            identity_profile,
            disable_broadcast: config.get(SECTION, b"DISABLE_BROADCAST").is_some()
                && config.get_yesno(SECTION, b"DISABLE_BROADCAST")?,
        })
    }
}

#[cfg(test)]
mod profile_tests {
    use super::*;
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "The real configuration-only startup parser must keep identity selection separate from UDP session policy"
    )]
    fn node_identity_profile_reaches_udp_client_settings_and_conflicts_fail_before_io()
    -> Result<(), Cause> {
        let mut config = Configuration::default();
        config.set_value(SECTION, b"BINDTO", Some(b"127.0.0.1:0"))?;
        config.set_value(
            b"PEER",
            b"PRIVATE_KEY",
            Some(b"/private/tmp/udp-profile-key"),
        )?;
        config.set_value(
            RUST,
            b"STATE_DIRECTORY",
            Some(b"/private/tmp/udp-profile-state"),
        )?;
        config.set_value(SECTION, b"REKEY_MAX_BYTES", Some(b"999"))?;
        assert_eq!(
            Settings::parse(&config, false)?.identity_profile,
            gnunet_pils::Profile::Reference029
        );
        config.set_value(b"PILS", b"PROFILE", Some(b"deterministic"))?;
        let selected = Settings::parse(&config, false)?;
        assert_eq!(
            selected.identity_profile,
            gnunet_pils::Profile::ReferenceDeterministic
        );
        assert_eq!(selected.transmit.maximum_secret_bytes, 999);
        assert_eq!(
            selected.binds,
            [Some("127.0.0.1:0".parse::<SocketAddr>()?), None]
        );
        config.set_value(RUST, b"PILS_PROFILE", Some(b"reference029"))?;
        let failure = Settings::parse(&config, false)
            .err()
            .ok_or("incoherent UDP identity profile admitted")?;
        assert_eq!(
            failure.downcast_ref::<gnunet_types::Error>(),
            Some(&gnunet_types::Error::Conflict)
        );
        config.set_value(RUST, b"PILS_PROFILE", Some(b"deterministic"))?;
        assert_eq!(
            Settings::parse(&config, false)?.identity_profile,
            selected.identity_profile
        );
        Ok(())
    }
}
