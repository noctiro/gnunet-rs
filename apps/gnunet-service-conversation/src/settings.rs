//! Actual configured listeners and finite native/per-Line deployment resources.
use crate::{Cause, Mode};
use gnunet_config::Configuration;
use gnunet_conversation_host::Limits;
use gnunet_pils::Profile;
use gnunet_service_runtime::{
    credentials::UnixAccess,
    service::{ServiceOptions, ShutdownMode},
    service_options,
};
use std::time::Duration;
const POLICY: &[u8] = b"conversation-service-rust";
fn number(c: &Configuration, key: &[u8], default: usize) -> Result<usize, Cause> {
    Ok(c.get(POLICY, key)
        .map(|_| c.get_number(POLICY, key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}
fn bytes(c: &Configuration, key: &[u8], default: usize) -> Result<usize, Cause> {
    Ok(c.get(POLICY, key)
        .map(|_| c.get_size(POLICY, key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}
fn time(c: &Configuration, key: &[u8], default: Duration, zero: bool) -> Result<Duration, Cause> {
    let us = c
        .get(POLICY, key)
        .map(|_| c.get_time(POLICY, key))
        .transpose()?
        .unwrap_or(u64::try_from(default.as_micros())?);
    let value = Duration::from_micros(us);
    if (!zero && us == 0)
        || us == u64::MAX
        || std::time::Instant::now().checked_add(value).is_none()
    {
        return Err("CONVERSATION requires finite representable duration bounds".into());
    }
    Ok(value)
}
fn core_time(c: &Configuration, key: &[u8], default: u64) -> Result<u64, Cause> {
    Ok(u64::try_from(
        time(c, key, Duration::from_micros(default), false)?.as_micros(),
    )?)
}
pub(super) struct Settings {
    pub native: Limits,
    pub resolver: gnunet_resolver_broker::Limits,
    pub access: UnixAccess,
    pub options: ServiceOptions,
    pub shutdown_grace: Duration,
}
impl Settings {
    pub fn read(c: &Configuration, mode: Mode) -> Result<Self, Cause> {
        let mut native = Limits::default();
        native.clients = number(c, b"MAX_CLIENTS", native.clients)?;
        native.calls = number(c, b"MAX_CALLS", native.calls)?;
        native.line_bytes = bytes(c, b"LINE_RETAINED_BYTES", native.line_bytes)?;
        native.total_retained_bytes =
            bytes(c, b"TOTAL_RETAINED_BYTES", native.total_retained_bytes)?;
        native.frame_bytes = bytes(c, b"FRAME_BYTES", native.frame_bytes)?;
        native.io_slice_bytes = bytes(c, b"IO_SLICE_BYTES", native.io_slice_bytes)?;
        native.work_units = number(c, b"WORK_UNITS", native.work_units)?;
        native.startup = time(c, b"STARTUP_TIMEOUT", native.startup, false)?;
        native.first_input = time(c, b"FIRST_INPUT_TIMEOUT", native.first_input, false)?;
        native.partial_input = time(c, b"PARTIAL_INPUT_TIMEOUT", native.partial_input, false)?;
        native.peer_input = time(c, b"PEER_INPUT_TIMEOUT", native.peer_input, false)?;
        native.utc_uncertainty = time(c, b"UTC_UNCERTAINTY", native.utc_uncertainty, true)?;
        native.core.calls = number(c, b"MAX_CALLS_PER_LINE", native.core.calls)?;
        native.core.effects = number(c, b"CORE_EFFECTS", native.core.effects)?;
        native.core.frame_bytes = bytes(c, b"CORE_FRAME_BYTES", native.core.frame_bytes)?;
        native.core.queued_bytes = bytes(c, b"CORE_QUEUED_BYTES", native.core.queued_bytes)?;
        native.core.retained_bytes = bytes(c, b"CORE_RETAINED_BYTES", native.core.retained_bytes)?;
        native.core.ring_timeout = core_time(c, b"RING_TIMEOUT", native.core.ring_timeout)?;
        native.core.write_timeout = core_time(c, b"WRITE_TIMEOUT", native.core.write_timeout)?;
        native.core.close_timeout = core_time(c, b"CLOSE_TIMEOUT", native.core.close_timeout)?;
        native.cadet.frame_bytes = bytes(c, b"CADET_FRAME_BYTES", native.cadet.frame_bytes)?;
        native.cadet.io_slice_bytes =
            bytes(c, b"CADET_IO_SLICE_BYTES", native.cadet.io_slice_bytes)?;
        native.cadet.max_payload_bytes =
            bytes(c, b"CADET_PAYLOAD_BYTES", native.cadet.max_payload_bytes)?;
        native.cadet.max_send_credit = u32::try_from(number(
            c,
            b"CADET_MAX_SEND_CREDIT",
            usize::try_from(native.cadet.max_send_credit)?,
        )?)?;
        native.pils.pending_operations =
            number(c, b"PILS_OPERATIONS", native.pils.pending_operations)?;
        native.pils.frame_bytes = bytes(c, b"PILS_FRAME_BYTES", native.pils.frame_bytes)?;
        native.pils.io_slice_bytes = bytes(c, b"PILS_IO_SLICE_BYTES", native.pils.io_slice_bytes)?;
        native.hello.maximum_input_bytes =
            bytes(c, b"HELLO_INPUT_BYTES", native.hello.maximum_input_bytes)?;
        native.hello.maximum_address_bytes = bytes(
            c,
            b"HELLO_ADDRESS_BYTES",
            native.hello.maximum_address_bytes,
        )?;
        native.hello.maximum_addresses =
            number(c, b"HELLO_ADDRESSES", native.hello.maximum_addresses)?;
        native.pils_profile =
            Profile::configured(c.get(b"PILS", b"PROFILE"), c.get(POLICY, b"PILS_PROFILE"))?;
        native.validate()?;
        let rd = gnunet_resolver_broker::Limits::default();
        let selected = |key: &[u8], default: bool| {
            c.get(mode.section(), key)
                .map(|_| c.get_yesno(mode.section(), key))
                .transpose()
                .map(|value| value.unwrap_or(default))
        };
        Ok(Self {
            native,
            resolver: gnunet_resolver_broker::Limits {
                max_frame_bytes: bytes(c, b"RESOLVER_FRAME_BYTES", rd.max_frame_bytes)?,
                io_chunk_bytes: bytes(c, b"RESOLVER_IO_SLICE_BYTES", rd.io_chunk_bytes)?,
                max_queued_frames: number(c, b"RESOLVER_OUTPUT_FRAMES", rd.max_queued_frames)?,
            },
            access: UnixAccess {
                match_uid: selected(b"UNIX_MATCH_UID", false)?,
                match_gid: selected(b"UNIX_MATCH_GID", true)?,
            },
            options: service_options(c, mode.section(), ShutdownMode::Immediate)?,
            shutdown_grace: time(c, b"SHUTDOWN_GRACE", Duration::from_secs(10), false)?,
        })
    }
}

#[cfg(test)]
mod profile_tests {
    use super::*;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Normal entry configuration must retain one explicit identity profile"
    )]
    fn node_profile_reaches_conversation_limits_and_refuses_conflicts() -> Result<(), Cause> {
        let mut config = Configuration::default();
        assert_eq!(
            Settings::read(&config, Mode)?.native.pils_profile,
            Profile::Reference029
        );
        config.set_value(b"PILS", b"PROFILE", Some(b"deterministic"))?;
        assert_eq!(
            Settings::read(&config, Mode)?.native.pils_profile,
            Profile::ReferenceDeterministic
        );
        config.set_value(POLICY, b"PILS_PROFILE", Some(b"reference-deterministic"))?;
        assert_eq!(
            Settings::read(&config, Mode)?.native.pils_profile,
            Profile::ReferenceDeterministic
        );
        config.set_value(POLICY, b"PILS_PROFILE", Some(b"reference029"))?;
        assert!(Settings::read(&config, Mode).is_err());
        config.set_value(b"PILS", b"PROFILE", Some(b"unknown"))?;
        assert!(Settings::read(&config, Mode).is_err());
        Ok(())
    }
}
