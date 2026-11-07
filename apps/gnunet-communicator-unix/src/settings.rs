use crate::Failure;
use gnunet_config::{Configuration, ProcessEnvironment};
use gnunet_unix_communicator_host::Limits;
use std::{os::unix::ffi::OsStrExt, time::Duration};
pub(super) struct Settings {
    pub limits: Limits,
    pub path: Vec<u8>,
    pub resolver: gnunet_resolver_broker::Limits,
}
const SECTION: &[u8] = b"communicator-unix-rust";
fn number(c: &Configuration, key: &[u8], default: usize) -> Result<usize, Failure> {
    Ok(c.get(SECTION, key)
        .map(|_| c.get_number(SECTION, key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}
fn duration(c: &Configuration, key: &[u8], default: Duration) -> Result<Duration, Failure> {
    let us = c
        .get(SECTION, key)
        .map(|_| c.get_time(SECTION, key))
        .transpose()?
        .unwrap_or(u64::try_from(default.as_micros())?);
    if us == 0
        || us == u64::MAX
        || std::time::Instant::now()
            .checked_add(Duration::from_micros(us))
            .is_none()
    {
        return Err("UNIX communicator time bounds must be finite/nonzero".into());
    }
    Ok(Duration::from_micros(us))
}
impl Settings {
    pub fn read(c: &Configuration) -> Result<Self, Failure> {
        let mut limits = Limits::default();
        limits.queues = number(c, b"MAX_QUEUES", limits.queues)?;
        limits.incoming = c
            .get(b"communicator-unix", b"MAX_QUEUE_LENGTH")
            .map(|_| c.get_number(b"communicator-unix", b"MAX_QUEUE_LENGTH"))
            .transpose()?
            .map(usize::try_from)
            .transpose()?
            .unwrap_or(limits.incoming);
        limits.output_frames = number(c, b"OUTPUT_FRAMES", limits.output_frames)?;
        limits.output_bytes = number(c, b"OUTPUT_BYTES", limits.output_bytes)?;
        limits.io_slice = number(c, b"IO_SLICE_BYTES", limits.io_slice)?;
        limits.datagram_bytes = number(c, b"DATAGRAM_BYTES", limits.datagram_bytes)?;
        limits.socket_buffer = number(c, b"SOCKET_BUFFER_BYTES", limits.socket_buffer)?;
        limits.operation = duration(c, b"OPERATION_LIFETIME", limits.operation)?;
        limits.idle = duration(c, b"QUEUE_IDLE_TIMEOUT", limits.idle)?;
        limits.lifetime = duration(c, b"DAEMON_LIFETIME", limits.lifetime)?;
        limits.startup = duration(c, b"STARTUP_TIMEOUT", limits.startup)?;
        limits.enobufs_retry = duration(c, b"ENOBUFS_RETRY", limits.enobufs_retry)?;
        limits.profile = gnunet_pils::Profile::configured(
            c.get(b"PILS", b"PROFILE"),
            c.get(SECTION, b"PILS_PROFILE"),
        )?;
        let path = c.get_filename(b"communicator-unix", b"UNIXPATH", &ProcessEnvironment)?;
        let bytes = path.as_os_str().as_bytes();
        if !bytes.starts_with(b"/") && !bytes.starts_with(b"@") {
            return Err("UNIXPATH must be absolute or a Linux abstract @name".into());
        }
        let mut path = Vec::new();
        path.try_reserve_exact(bytes.len())?;
        path.extend_from_slice(bytes);
        let io = limits.io_slice;
        Ok(Self {
            limits,
            path,
            resolver: gnunet_resolver_broker::Limits {
                max_frame_bytes: 65535,
                io_chunk_bytes: io,
                max_queued_frames: 8,
            },
        })
    }
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
        config.set_value(
            b"communicator-unix",
            b"UNIXPATH",
            Some(b"/private/tmp/profile-unix"),
        )?;
        assert_eq!(
            Settings::read(&config)?.limits.profile,
            gnunet_pils::Profile::Reference029
        );
        config.set_value(b"PILS", b"PROFILE", Some(b"deterministic"))?;
        assert_eq!(
            Settings::read(&config)?.limits.profile,
            gnunet_pils::Profile::ReferenceDeterministic
        );
        config.set_value(SECTION, b"PILS_PROFILE", Some(b"reference-0.29.1"))?;
        let refused = Settings::read(&config)
            .err()
            .ok_or("conflicting profile admitted")?;
        assert_eq!(
            refused.downcast_ref::<gnunet_types::Error>(),
            Some(&gnunet_types::Error::Conflict)
        );
        config.set_value(SECTION, b"PILS_PROFILE", Some(b"deterministic"))?;
        assert_eq!(
            Settings::read(&config)?.limits.profile,
            gnunet_pils::Profile::ReferenceDeterministic
        );
        Ok(())
    }
}
