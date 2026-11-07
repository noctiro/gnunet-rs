use crate::Failure;
use gnunet_config::Configuration;
use gnunet_topology_host::Limits;
use std::time::Duration;
pub(super) struct Settings {
    pub limits: Limits,
    pub startup: Duration,
    pub resolver: gnunet_resolver_broker::Limits,
}
const SECTION: &[u8] = b"topology-rust";
fn number(c: &Configuration, key: &[u8], default: usize) -> Result<usize, Failure> {
    Ok(c.get(SECTION, key)
        .map(|_| c.get_number(SECTION, key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}
fn duration(c: &Configuration, key: &[u8], default: Duration) -> Result<Duration, Failure> {
    let n = c
        .get(SECTION, key)
        .map(|_| c.get_time(SECTION, key))
        .transpose()?
        .unwrap_or(u64::try_from(default.as_micros())?);
    if n == 0
        || n == u64::MAX
        || std::time::Instant::now()
            .checked_add(Duration::from_micros(n))
            .is_none()
    {
        return Err("TOPOLOGY time limits must be finite nonzero".into());
    }
    Ok(Duration::from_micros(n))
}
impl Settings {
    pub fn read(c: &Configuration) -> Result<Self, Failure> {
        let mut limits = Limits::default();
        limits.core.target = c
            .get(b"topology", b"TARGET-CONNECTION-COUNT")
            .map(|_| c.get_number(b"topology", b"TARGET-CONNECTION-COUNT"))
            .transpose()?
            .map(usize::try_from)
            .transpose()?
            .unwrap_or(16);
        limits.core.peers = number(c, b"MAX_PEERS", limits.core.peers)?;
        limits.core.hello_bytes = number(c, b"HELLO_BYTES", limits.core.hello_bytes)?;
        limits.core.frame_bytes = number(c, b"HELLO_FRAME_BYTES", limits.core.frame_bytes)?;
        limits.hello.maximum_input_bytes = limits.core.frame_bytes;
        limits.hello.maximum_address_bytes =
            number(c, b"ADDRESS_BYTES", limits.hello.maximum_address_bytes)?;
        limits.hello.maximum_addresses =
            number(c, b"MAX_ADDRESSES", limits.hello.maximum_addresses)?;
        limits.incoming = number(c, b"INCOMING_HELLOS", limits.incoming)?;
        limits.io_slice = number(c, b"IO_SLICE_BYTES", limits.io_slice)?;
        limits.operation = duration(c, b"OPERATION_LIFETIME", limits.operation)?;
        limits.grace = duration(c, b"RETIREMENT_GRACE", limits.grace)?;
        limits.source_lifetime = duration(c, b"SOURCE_LIFETIME", limits.source_lifetime)?;
        limits.lifetime = duration(c, b"DAEMON_LIFETIME", limits.lifetime)?;
        limits.tick = duration(c, b"TICK_INTERVAL", limits.tick)?;
        limits.pils_profile = gnunet_pils::Profile::configured(
            c.get(b"PILS", b"PROFILE"),
            c.get(SECTION, b"PILS_PROFILE"),
        )?;
        limits.profile = match c.get(SECTION, b"HELLO_PROFILE") {
            None => limits.pils_profile.hello(),
            Some(b"reference029" | b"reference-0.29.1") => {
                gnunet_hello::SignatureProfile::Gnunet029
            }
            Some(b"deterministic" | b"reference-deterministic") => {
                gnunet_hello::SignatureProfile::DeterministicPidDerivation
            }
            Some(_) => return Err("HELLO_PROFILE must be reference029/deterministic".into()),
        };
        limits.core_order = match c.get(SECTION, b"CORE_CLASS_ORDER").unwrap_or(b"native") {
            b"native" => limits.core_order,
            b"little" => gnunet_core_client_host::ClassOrder::Little,
            b"big" => gnunet_core_client_host::ClassOrder::Big,
            _ => return Err("CORE_CLASS_ORDER must be native/little/big".into()),
        };
        Ok(Self {
            limits,
            startup: duration(c, b"STARTUP_TIMEOUT", Duration::from_secs(30))?,
            resolver: gnunet_resolver_broker::Limits {
                max_frame_bytes: 65535,
                io_chunk_bytes: limits.io_slice,
                max_queued_frames: 8,
            },
        })
    }
}

#[cfg(test)]
mod profile_tests {
    use super::*;
    use gnunet_hello::SignatureProfile;
    use gnunet_pils::Profile;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Local derivation and explicit remote HELLO coverage are independent source contracts"
    )]
    fn local_pils_profile_is_not_reconstructed_from_remote_hello_policy() -> Result<(), Failure> {
        let mut config = Configuration::default();
        config.set_value(b"PILS", b"PROFILE", Some(b"lsd0014-text"))?;
        let limits = Settings::read(&config)?.limits;
        assert_eq!(limits.pils_profile, Profile::Lsd0014Text);
        assert_eq!(limits.profile, SignatureProfile::DeterministicPidDerivation);
        config.set_value(SECTION, b"HELLO_PROFILE", Some(b"reference029"))?;
        let remote = Settings::read(&config)?.limits;
        assert_eq!(remote.pils_profile, Profile::Lsd0014Text);
        assert_eq!(remote.profile, SignatureProfile::Gnunet029);
        config.set_value(SECTION, b"PILS_PROFILE", Some(b"deterministic"))?;
        assert!(Settings::read(&config).is_err());
        config.set_value(SECTION, b"PILS_PROFILE", None)?;
        config.set_value(b"PILS", b"PROFILE", Some(b"unknown"))?;
        assert!(Settings::read(&config).is_err());
        Ok(())
    }
}
