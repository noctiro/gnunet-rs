//! Explicit original SECRETSharing endpoint and bounded decrypt deployment.
use crate::{Cause, Mode};
use gnunet_config::Configuration;
use gnunet_secretsharing_host::Limits;
use gnunet_service_runtime::{
    credentials::UnixAccess,
    service::{ServiceOptions, ShutdownMode},
    service_options,
};
use std::time::Duration;
const POLICY: &[u8] = b"secretsharing-service-rust";
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
fn time(c: &Configuration, key: &[u8], default: Duration) -> Result<Duration, Cause> {
    let us = c
        .get(POLICY, key)
        .map(|_| c.get_time(POLICY, key))
        .transpose()?
        .unwrap_or(u64::try_from(default.as_micros())?);
    let value = Duration::from_micros(us);
    if us == 0 || us == u64::MAX || std::time::Instant::now().checked_add(value).is_none() {
        return Err("SECRETSHARING requires finite representable original lifetimes".into());
    }
    Ok(value)
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
        let profile = gnunet_pils::Profile::configured(c.get(b"PILS", b"PROFILE"), None)?;
        let d = Limits::default();
        let mut decrypt = d.decrypt;
        decrypt.profile = profile;
        let frame_bytes = bytes(c, b"FRAME_BYTES", d.frame_bytes)?;
        decrypt.frame_bytes = frame_bytes;
        decrypt.peers = number(c, b"MAX_PEERS", decrypt.peers)?;
        decrypt.retained_bytes = bytes(c, b"NATIVE_RETAINED_BYTES", decrypt.retained_bytes)?;
        decrypt.math.participants = number(c, b"MATH_PARTICIPANTS", decrypt.math.participants)?;
        decrypt.math.retained_bytes =
            bytes(c, b"MATH_RETAINED_BYTES", decrypt.math.retained_bytes)?;
        decrypt.math.units_per_turn = u16::try_from(number(
            c,
            b"WORK_UNITS",
            usize::from(decrypt.math.units_per_turn),
        )?)?;
        let index_order = match c.get(POLICY, b"INDEX_ORDER").unwrap_or(b"native") {
            v if v.eq_ignore_ascii_case(b"native") => {
                gnunet_secretsharing_decrypt_host::IndexOrder::native()
            }
            v if v.eq_ignore_ascii_case(b"little") => {
                gnunet_secretsharing_decrypt_host::IndexOrder::Little
            }
            v if v.eq_ignore_ascii_case(b"big") => {
                gnunet_secretsharing_decrypt_host::IndexOrder::Big
            }
            _ => return Err("INDEX_ORDER must explicitly select native, little or big".into()),
        };
        let native = Limits {
            clients: number(c, b"MAX_CLIENTS", d.clients)?,
            operations: number(c, b"MAX_OPERATIONS", d.operations)?,
            operation_bytes: bytes(c, b"OPERATION_BYTES", d.operation_bytes)?,
            total_retained_bytes: bytes(c, b"TOTAL_RETAINED_BYTES", d.total_retained_bytes)?,
            frame_bytes,
            io_slice_bytes: bytes(c, b"IO_SLICE_BYTES", d.io_slice_bytes)?,
            first_input: time(c, b"FIRST_INPUT", d.first_input)?,
            partial_input: time(c, b"PARTIAL_INPUT", d.partial_input)?,
            operation: time(c, b"OPERATION_TIMEOUT", d.operation)?,
            output: time(c, b"OUTPUT_TIMEOUT", d.output)?,
            index_order,
            decrypt,
        };
        native.validate()?;
        let rd = gnunet_resolver_broker::Limits::default();
        let yes = |key: &[u8]| {
            c.get(mode.section(), key)
                .map(|_| c.get_yesno(mode.section(), key))
                .transpose()
                .map(|v| v.unwrap_or(true))
        };
        Ok(Self {
            native,
            resolver: gnunet_resolver_broker::Limits {
                max_frame_bytes: bytes(c, b"RESOLVER_FRAME_BYTES", rd.max_frame_bytes)?,
                io_chunk_bytes: bytes(c, b"RESOLVER_IO_SLICE_BYTES", rd.io_chunk_bytes)?,
                max_queued_frames: number(c, b"RESOLVER_OUTPUT_FRAMES", rd.max_queued_frames)?,
            },
            access: UnixAccess {
                match_uid: yes(b"UNIX_MATCH_UID")?,
                match_gid: yes(b"UNIX_MATCH_GID")?,
            },
            options: service_options(c, mode.section(), ShutdownMode::Immediate)?,
            shutdown_grace: time(c, b"SHUTDOWN_GRACE", Duration::from_secs(10))?,
        })
    }
}

#[cfg(test)]
mod profile_tests {
    use super::*;
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Compare the shared normal generation/decryption policy before any request exists"
    )]
    fn generation_and_decryption_inherit_one_node_profile() -> Result<(), Cause> {
        let mut config = Configuration::default();
        assert_eq!(
            Settings::read(&config, Mode)?.native.decrypt.profile,
            gnunet_pils::Profile::Reference029
        );
        config.set_value(b"PILS", b"PROFILE", Some(b"deterministic"))?;
        assert_eq!(
            Settings::read(&config, Mode)?.native.decrypt.profile,
            gnunet_pils::Profile::ReferenceDeterministic
        );
        config.set_value(b"PILS", b"PROFILE", Some(b"unknown"))?;
        let error = Settings::read(&config, Mode)
            .err()
            .ok_or("unknown SECRETSHARING source profile admitted")?;
        assert_eq!(
            error.downcast_ref::<gnunet_types::Error>(),
            Some(&gnunet_types::Error::InvalidInput)
        );
        Ok(())
    }
}
