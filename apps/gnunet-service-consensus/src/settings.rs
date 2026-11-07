//! Ordinary endpoint policy and explicit finite core/native resource settings.
use crate::{Cause, Mode};
use gnunet_config::Configuration;
use gnunet_consensus_host::{HelloLimits, Profile};
use gnunet_consensus_host::{Limits, ServerLimits};
use gnunet_service_runtime::{
    credentials::UnixAccess,
    service::{ServiceOptions, ShutdownMode},
    service_options,
};
use gnunet_wire::official::set::{Abi, Order};
use std::time::Duration;
const POLICY: &[u8] = b"consensus-service-rust";
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
    let life = Duration::from_micros(us);
    if us == 0 || us == u64::MAX || std::time::Instant::now().checked_add(life).is_none() {
        return Err("CONSENSUS requires finite representable nonzero duration bounds".into());
    }
    Ok(life)
}
pub(super) struct Settings {
    pub native: ServerLimits,
    pub resolver: gnunet_resolver_broker::Limits,
    pub access: UnixAccess,
    pub options: ServiceOptions,
    pub shutdown_grace: Duration,
}
impl Settings {
    pub fn read(c: &Configuration, mode: Mode) -> Result<Self, Cause> {
        let d = ServerLimits::default();
        let b = d.bridge;
        let s = b.set;
        let abi = Abi {
            order: match c.get(POLICY, b"SET_BYTE_ORDER") {
                None => s.abi.order,
                Some(b"little") => Order::Little,
                Some(b"big") => Order::Big,
                Some(_) => return Err("SET_BYTE_ORDER must be little or big".into()),
            },
            align64: u8::try_from(number(c, b"SET_ALIGN64", usize::from(s.abi.align64))?)?,
        };
        abi.validate()?;
        let native = ServerLimits {
            bridge: Limits {
                core: gnunet_consensus::Limits {
                    peers: number(c, b"MAX_PEERS", b.core.peers)?,
                    elements: number(c, b"MAX_ELEMENTS", b.core.elements)?,
                    payload_bytes: bytes(c, b"PAYLOAD_BYTES", b.core.payload_bytes)?,
                    element_bytes: bytes(c, b"ELEMENT_BYTES", b.core.element_bytes)?,
                    tasks: number(c, b"MAX_TASKS", b.core.tasks)?,
                    sets: number(c, b"MAX_SETS", b.core.sets)?,
                    offers: number(c, b"MAX_OFFERS", b.core.offers)?,
                    retained_bytes: bytes(c, b"CORE_RETAINED_BYTES", b.core.retained_bytes)?,
                },
                set: gnunet_set_client_host::Limits {
                    abi,
                    frame_bytes: bytes(c, b"SET_FRAME_BYTES", s.frame_bytes)?,
                    queued_frames: number(c, b"SET_OUTPUT_FRAMES", s.queued_frames)?,
                    queued_bytes: bytes(c, b"SET_OUTPUT_BYTES", s.queued_bytes)?,
                    operations: number(c, b"SET_OPERATIONS", s.operations)?,
                    io_slice_bytes: bytes(c, b"SET_IO_SLICE_BYTES", s.io_slice_bytes)?,
                    initial_timeout: time(c, b"SET_INITIAL_TIMEOUT", s.initial_timeout)?,
                    input_timeout: time(c, b"SET_PARTIAL_INPUT", s.input_timeout)?,
                    write_timeout: time(c, b"SET_WRITE_TIMEOUT", s.write_timeout)?,
                },
                retained_bytes: bytes(c, b"BRIDGE_RETAINED_BYTES", b.retained_bytes)?,
                work_budget: number(c, b"WORK_UNITS", b.work_budget)?,
            },
            clients: number(c, b"MAX_CLIENTS", d.clients)?,
            session_bytes: bytes(c, b"SESSION_BYTES", d.session_bytes)?,
            total_retained_bytes: bytes(c, b"TOTAL_RETAINED_BYTES", d.total_retained_bytes)?,
            frame_bytes: bytes(c, b"FRAME_BYTES", d.frame_bytes)?,
            io_slice_bytes: bytes(c, b"IO_SLICE_BYTES", d.io_slice_bytes)?,
            first_input: time(c, b"FIRST_INPUT", d.first_input)?,
            partial_input: time(c, b"PARTIAL_INPUT", d.partial_input)?,
            operation: time(c, b"OPERATION_TIMEOUT", d.operation)?,
            retirement_grace: time(c, b"RETIREMENT_GRACE", d.retirement_grace)?,
            pils: gnunet_pils_host::client::Limits {
                pending_operations: 1,
                frame_bytes: bytes(c, b"PILS_FRAME_BYTES", d.pils.frame_bytes)?,
                io_slice_bytes: bytes(c, b"PILS_IO_SLICE_BYTES", d.pils.io_slice_bytes)?,
            },
            hello: HelloLimits {
                maximum_input_bytes: bytes(c, b"HELLO_INPUT_BYTES", d.hello.maximum_input_bytes)?,
                maximum_address_bytes: bytes(
                    c,
                    b"HELLO_ADDRESS_BYTES",
                    d.hello.maximum_address_bytes,
                )?,
                maximum_addresses: number(c, b"HELLO_MAX_ADDRESSES", d.hello.maximum_addresses)?,
            },
            profile: Profile::configured(
                c.get(b"PILS", b"PROFILE"),
                c.get(POLICY, b"PILS_PROFILE"),
            )?,
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
        reason = "Actual native identity selection remains independent of the SET ABI"
    )]
    fn node_profile_reaches_consensus_without_changing_set_layout() -> Result<(), Cause> {
        let mut config = Configuration::default();
        let normal = Settings::read(&config, Mode)?;
        assert_eq!(normal.native.profile, Profile::Reference029);
        config.set_value(b"PILS", b"PROFILE", Some(b"deterministic"))?;
        let conditional = Settings::read(&config, Mode)?;
        assert_eq!(conditional.native.profile, Profile::ReferenceDeterministic);
        assert_eq!(
            conditional.native.bridge.set.abi,
            normal.native.bridge.set.abi
        );
        config.set_value(POLICY, b"PILS_PROFILE", Some(b"lsd0014-text"))?;
        assert!(Settings::read(&config, Mode).is_err());
        config.set_value(b"PILS", b"PROFILE", Some(b"lsd0014-text"))?;
        assert_eq!(
            Settings::read(&config, Mode)?.native.profile,
            Profile::Lsd0014Text
        );
        config.set_value(b"PILS", b"PROFILE", Some(b"unknown"))?;
        assert!(Settings::read(&config, Mode).is_err());
        Ok(())
    }
}
