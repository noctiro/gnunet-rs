use gnunet_cadet::service;
use gnunet_cadet_host::server;
use gnunet_config::Configuration;
use gnunet_service_runtime::{
    credentials::UnixAccess,
    service::{ServiceOptions, ShutdownMode},
    service_options,
};
use gnunet_types::Error as ProtocolError;
use std::{error::Error, time::Duration};

fn number(config: &Configuration, key: &[u8], default: usize) -> Result<usize, Box<dyn Error>> {
    Ok(config
        .get(b"cadet-rust", key)
        .map(|_| config.get_number(b"cadet-rust", key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}
fn access(config: &Configuration, key: &[u8]) -> Result<bool, Box<dyn Error>> {
    Ok(config
        .get(b"cadet", key)
        .map(|_| config.get_yesno(b"cadet", key))
        .transpose()?
        .unwrap_or(false))
}
pub(super) fn filled<T: Clone>(length: usize, value: T) -> Result<Vec<T>, Box<dyn Error>> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(length)
        .map_err(|_| ProtocolError::Capacity)?;
    values.resize(length, value);
    Ok(values)
}
pub(super) struct Settings {
    /// One selected PILS/HELLO source profile, separate from CORE/service layout.
    pub pils_profile: gnunet_pils::Profile,
    pub clients: usize,
    pub ports: usize,
    pub channels: usize,
    pub source_buffers: usize,
    pub ingress_bytes: usize,
    pub source_bytes: usize,
    pub source_payload_bytes: usize,
    pub protocol: service::Limits,
    pub native: server::Limits,
    pub options: ServiceOptions,
    pub unix: UnixAccess,
    pub pils_startup_timeout: Duration,
    pub peer: crate::peer::Settings,
    pub statistics: gnunet_ipc_unix::producer::Limits,
    pub statistics_grace: Duration,
}
impl Settings {
    pub(super) fn read(config: &Configuration) -> Result<Self, Box<dyn Error>> {
        let pils_profile = gnunet_pils::Profile::configured(
            config.get(b"PILS", b"PROFILE"),
            config.get(b"cadet-rust", b"PILS_PROFILE"),
        )?;
        let clients = number(config, b"CLIENTS", 16)?;
        let ports = number(config, b"PORTS", 128)?;
        let channels = number(config, b"CHANNELS", 128)?;
        let source_buffers = number(config, b"SOURCE_BUFFERS", channels)?;
        let window = u8::try_from(number(config, b"WINDOW", 4)?)?;
        let loop_payload_bytes = number(config, b"LOOP_PAYLOAD_BYTES", 65523)?;
        let remote_payload_bytes = number(config, b"REMOTE_PAYLOAD_BYTES", 64348)?;
        let io_slice_bytes = number(config, b"IO_SLICE_BYTES", 65535)?;
        let timeout = config
            .get(b"cadet-rust", b"PILS_STARTUP_TIMEOUT")
            .map(|_| config.get_time(b"cadet-rust", b"PILS_STARTUP_TIMEOUT"))
            .transpose()?
            .unwrap_or(10_000_000);
        if clients == 0
            || ports == 0
            || channels < 2
            || source_buffers < channels
            || !(1..=4).contains(&window)
            || !(4..=65523).contains(&loop_payload_bytes)
            || !(4..=64348).contains(&remote_payload_bytes)
            || io_slice_bytes == 0
            || timeout == 0
            || timeout == u64::MAX
        {
            return Err("invalid finite CADET resource policy; see foreground README".into());
        }
        let stats_time = |key: &[u8]| -> Result<Duration, Box<dyn Error>> {
            let value = config
                .get(b"cadet-rust", key)
                .map(|_| config.get_time(b"cadet-rust", key))
                .transpose()?
                .unwrap_or(5_000_000);
            if value == 0 || value == u64::MAX {
                return Err("CADET statistics timeout must be finite and positive".into());
            }
            Ok(Duration::from_micros(value))
        };
        let statistics = gnunet_ipc_unix::producer::Limits {
            operation: stats_time(b"STATISTICS_TIMEOUT")?,
            ..Default::default()
        };
        statistics.validate()?;
        let statistics_grace = stats_time(b"STATISTICS_SHUTDOWN_GRACE")?;
        let source_payload_bytes = loop_payload_bytes.max(remote_payload_bytes);
        let ingress_bytes = clients
            .checked_mul(remote_payload_bytes)
            .ok_or(ProtocolError::Overflow)?;
        let source_bytes = source_buffers
            .checked_mul(source_payload_bytes)
            .ok_or(ProtocolError::Overflow)?;
        clients
            .checked_add(source_buffers)
            .ok_or(ProtocolError::Overflow)?;
        ingress_bytes
            .checked_add(source_bytes)
            .ok_or(ProtocolError::Overflow)?;
        let peer = crate::peer::Settings::read(config, remote_payload_bytes, io_slice_bytes)?;
        let peer_bytes = if peer.enabled { peer.payload_memory } else { 0 };
        if ingress_bytes
            .checked_add(source_bytes)
            .and_then(|n| n.checked_add(peer_bytes))
            .is_none_or(|n| n > 256 * 1024 * 1024)
        {
            return Err("CADET combined application/peer payload memory exceeds256MiB".into());
        }
        Ok(Self {
            pils_profile,
            statistics,
            statistics_grace,
            peer,
            clients,
            ports,
            channels,
            source_buffers,
            ingress_bytes,
            source_bytes,
            source_payload_bytes,
            protocol: service::Limits {
                window,
                loop_payload_bytes,
                remote_payload_bytes,
            },
            native: server::Limits {
                clients,
                io_slice_bytes,
            },
            options: service_options(config, b"cadet", ShutdownMode::Immediate)?,
            unix: UnixAccess {
                match_uid: access(config, b"UNIX_MATCH_UID")?,
                match_gid: access(config, b"UNIX_MATCH_GID")?,
            },
            pils_startup_timeout: Duration::from_micros(timeout),
        })
    }
}

#[cfg(test)]
mod profile_tests {
    use super::*;
    use gnunet_pils::Profile;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Actual normal settings must keep identity semantics separate from CADET/CORE resource and wire policy"
    )]
    fn normal_pils_profile_is_selected_once_without_changing_cadet_layout()
    -> Result<(), Box<dyn Error>> {
        let mut config = Configuration::default();
        config.set_value(b"cadet-rust", b"PEER_CORE", Some(b"NO"))?;
        let normal = Settings::read(&config)?;
        assert_eq!(normal.pils_profile, Profile::Reference029);
        config.set_value(b"PILS", b"PROFILE", Some(b"deterministic"))?;
        let conditional = Settings::read(&config)?;
        assert_eq!(conditional.pils_profile, Profile::ReferenceDeterministic);
        assert_eq!(conditional.protocol.window, normal.protocol.window);
        assert_eq!(
            conditional.protocol.remote_payload_bytes,
            normal.protocol.remote_payload_bytes
        );
        assert_eq!(
            conditional.native.io_slice_bytes,
            normal.native.io_slice_bytes
        );
        config.set_value(
            b"cadet-rust",
            b"PILS_PROFILE",
            Some(b"reference-deterministic"),
        )?;
        assert_eq!(
            Settings::read(&config)?.pils_profile,
            Profile::ReferenceDeterministic
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Unknown or contradictory choices are exact typed startup refusals"
    )]
    fn normal_pils_profile_refuses_conflicting_or_unknown_sources() -> Result<(), Box<dyn Error>> {
        let mut config = Configuration::default();
        config.set_value(b"PILS", b"PROFILE", Some(b"deterministic"))?;
        config.set_value(b"cadet-rust", b"PILS_PROFILE", Some(b"reference029"))?;
        let refused = Settings::read(&config)
            .err()
            .ok_or("conflicting profile admitted")?;
        assert_eq!(
            refused.downcast_ref::<ProtocolError>(),
            Some(&ProtocolError::Conflict)
        );
        config.set_value(b"PILS", b"PROFILE", Some(b"unknown"))?;
        config.set_value(b"cadet-rust", b"PILS_PROFILE", Some(b"deterministic"))?;
        let refused = Settings::read(&config)
            .err()
            .ok_or("unknown profile admitted")?;
        assert_eq!(
            refused.downcast_ref::<ProtocolError>(),
            Some(&ProtocolError::InvalidInput)
        );
        Ok(())
    }
}
