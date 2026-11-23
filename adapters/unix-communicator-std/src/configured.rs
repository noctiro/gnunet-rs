//! Official UNIX communicator configuration and explicit resource limits.
use crate::{Limits, embedded::SECTION, native::Address};
use gnunet_config::{Configuration, Environment, ProcessEnvironment};
use std::{error::Error, os::unix::ffi::OsStrExt, time::Duration};

type Failure = Box<dyn Error>;
const RUST_SECTION: &[u8] = b"communicator-unix-rust";

/// Parsed UNIX communicator settings. No socket is opened while reading them.
pub struct Configured {
    pub(crate) limits: Limits,
    pub(crate) path: Vec<u8>,
}

impl Configured {
    /// Bounded runtime resources and selected PILS profile.
    #[must_use]
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Native filesystem bytes or a literal Linux ABI abstract name.
    #[must_use]
    pub fn path(&self) -> &[u8] {
        &self.path
    }

    /// Read the standard settings with the current process filename context.
    pub fn read(config: &Configuration) -> Result<Self, Failure> {
        Self::read_with_environment(config, &ProcessEnvironment)
    }

    /// Read settings with caller-supplied variable and filename resolution.
    pub fn read_with_environment(
        config: &Configuration,
        environment: &impl Environment,
    ) -> Result<Self, Failure> {
        let defaults = Limits::default();
        let limits = Limits {
            queues: number(config, RUST_SECTION, b"MAX_QUEUES", defaults.queues)?,
            incoming: number(config, SECTION, b"MAX_QUEUE_LENGTH", defaults.incoming)?,
            output_frames: number(
                config,
                RUST_SECTION,
                b"OUTPUT_FRAMES",
                defaults.output_frames,
            )?,
            output_bytes: number(config, RUST_SECTION, b"OUTPUT_BYTES", defaults.output_bytes)?,
            io_slice: number(config, RUST_SECTION, b"IO_SLICE_BYTES", defaults.io_slice)?,
            datagram_bytes: number(
                config,
                RUST_SECTION,
                b"DATAGRAM_BYTES",
                defaults.datagram_bytes,
            )?,
            socket_buffer: number(
                config,
                RUST_SECTION,
                b"SOCKET_BUFFER_BYTES",
                defaults.socket_buffer,
            )?,
            operation: duration(config, b"OPERATION_LIFETIME", defaults.operation)?,
            idle: duration(config, b"QUEUE_IDLE_TIMEOUT", defaults.idle)?,
            lifetime: duration(config, b"DAEMON_LIFETIME", defaults.lifetime)?,
            startup: duration(config, b"STARTUP_TIMEOUT", defaults.startup)?,
            enobufs_retry: duration(config, b"ENOBUFS_RETRY", defaults.enobufs_retry)?,
            profile: gnunet_pils::Profile::configured(
                config.get(b"PILS", b"PROFILE"),
                config.get(RUST_SECTION, b"PILS_PROFILE"),
            )?,
        };
        limits.validate()?;
        let original = config
            .get(SECTION, b"UNIXPATH")
            .ok_or("missing communicator UNIXPATH")?;
        let expanded = config.expand_dollar(original, environment)?;
        let path = if expanded.starts_with(b"@") {
            Address::validate(&expanded)?;
            expanded
        } else {
            let filename = config.expand_filename(&expanded, environment)?;
            let bytes = filename.as_os_str().as_bytes();
            if !filename.is_absolute() {
                return Err("communicator UNIXPATH must resolve to an absolute path".into());
            }
            Address::validate(bytes)?;
            let mut path = Vec::new();
            path.try_reserve_exact(bytes.len())?;
            path.extend_from_slice(bytes);
            path
        };
        Ok(Self { limits, path })
    }
}

fn number(
    config: &Configuration,
    section: &[u8],
    key: &[u8],
    default: usize,
) -> Result<usize, Failure> {
    Ok(config
        .get(section, key)
        .map(|_| config.get_number(section, key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}

fn duration(config: &Configuration, key: &[u8], default: Duration) -> Result<Duration, Failure> {
    let micros = config
        .get(RUST_SECTION, key)
        .map(|_| config.get_time(RUST_SECTION, key))
        .transpose()?
        .unwrap_or(u64::try_from(default.as_micros())?);
    if micros == 0 || micros == u64::MAX {
        return Err("UNIX communicator time bounds must be finite and positive".into());
    }
    Ok(Duration::from_micros(micros))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Compare actual startup settings and its typed refusal"
    )]
    fn node_profile_reaches_native_limits_and_local_conflict_refuses_startup() -> Result<(), Failure>
    {
        let mut config = Configuration::default();
        config.set_value(SECTION, b"UNIXPATH", Some(b"/private/tmp/profile-unix"))?;
        assert_eq!(
            Configured::read(&config)?.limits.profile,
            gnunet_pils::Profile::Reference029
        );
        config.set_value(b"PILS", b"PROFILE", Some(b"deterministic"))?;
        assert_eq!(
            Configured::read(&config)?.limits.profile,
            gnunet_pils::Profile::ReferenceDeterministic
        );
        config.set_value(RUST_SECTION, b"PILS_PROFILE", Some(b"reference-0.29.1"))?;
        let refused = Configured::read(&config)
            .err()
            .ok_or("conflicting profile admitted")?;
        assert_eq!(
            refused.downcast_ref::<gnunet_types::Error>(),
            Some(&gnunet_types::Error::Conflict)
        );
        config.set_value(RUST_SECTION, b"PILS_PROFILE", Some(b"deterministic"))?;
        assert_eq!(
            Configured::read(&config)?.limits.profile,
            gnunet_pils::Profile::ReferenceDeterministic
        );
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn abstract_unixpath_keeps_its_literal_namespace() -> Result<(), Failure> {
        let mut config = Configuration::default();
        config.set_value(SECTION, b"UNIXPATH", Some(b"@gnunet-embedded-test"))?;
        if Configured::read(&config)?.path != b"@gnunet-embedded-test" {
            return Err("abstract name was expanded as a filesystem path".into());
        }
        Ok(())
    }
}
