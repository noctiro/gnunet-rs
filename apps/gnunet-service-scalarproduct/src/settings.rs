//! Official endpoint policy and separate finite Rust resource configuration.
use crate::{Cause, Mode};
use gnunet_config::Configuration;
use gnunet_scalarproduct::{DlogLimits, HashOrder};
use gnunet_scalarproduct_host::{Limits, Profile};
use gnunet_service_runtime::{
    credentials::UnixAccess,
    service::{ServiceOptions, ShutdownMode},
    service_options,
};
use std::time::Duration;

const POLICY: &[u8] = b"scalarproduct-service-rust";
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
    let value = c
        .get(POLICY, key)
        .map(|_| c.get_time(POLICY, key))
        .transpose()?
        .unwrap_or(u64::try_from(default.as_micros())?);
    let duration = Duration::from_micros(value);
    if value == 0 || value == u64::MAX || std::time::Instant::now().checked_add(duration).is_none()
    {
        return Err("SCALARPRODUCT requires finite nonzero representable time bounds".into());
    }
    Ok(duration)
}
pub(super) struct Settings {
    pub native: Limits,
    pub profile: Profile,
    pub resolver: gnunet_resolver_broker::Limits,
    pub access: UnixAccess,
    pub options: ServiceOptions,
    pub shutdown_grace: Duration,
}
impl Settings {
    pub fn read(c: &Configuration, mode: Mode) -> Result<Self, Cause> {
        let profile = match mode.profile() {
            Profile::Ecc => Profile::Ecc,
            Profile::Paillier(mut policy) => {
                policy.max_rows = number(c, b"MAX_ROWS", policy.max_rows)?;
                policy.max_retained_bytes =
                    bytes(c, b"CORE_RETAINED_BYTES", policy.max_retained_bytes)?;
                policy.frame_bytes = bytes(c, b"PAILLIER_FRAME_BYTES", policy.frame_bytes)?;
                policy.lifetime_micros = u64::try_from(
                    time(
                        c,
                        b"OPERATION_TIMEOUT",
                        Duration::from_micros(policy.lifetime_micros),
                    )?
                    .as_micros(),
                )?;
                policy.primitive.candidates = u32::try_from(number(
                    c,
                    b"PAILLIER_KEY_CANDIDATES",
                    policy.primitive.candidates as usize,
                )?)?;
                policy.primitive.rejections = u32::try_from(number(
                    c,
                    b"PAILLIER_REJECTIONS",
                    policy.primitive.rejections as usize,
                )?)?;
                policy.primitive.units_per_turn = u16::try_from(number(
                    c,
                    b"WORK_UNITS",
                    usize::from(policy.primitive.units_per_turn),
                )?)?;
                policy.validate()?;
                Profile::Paillier(policy)
            }
        };
        let d = profile.default_host_limits()?;
        let mut seti = d.seti;
        seti.operations = number(c, b"SETI_OPERATIONS", seti.operations)?;
        seti.incoming = number(c, b"SETI_INCOMING", seti.incoming)?;
        seti.incoming_bytes = bytes(c, b"SETI_INCOMING_BYTES", seti.incoming_bytes)?;
        seti.output.frames = number(c, b"SETI_OUTPUT_FRAMES", seti.output.frames)?;
        seti.output.bytes = bytes(c, b"SETI_OUTPUT_BYTES", seti.output.bytes)?;
        seti.frame_bytes = bytes(c, b"SETI_FRAME_BYTES", seti.frame_bytes)?;
        seti.io_slice_bytes = bytes(c, b"SETI_IO_SLICE_BYTES", seti.io_slice_bytes)?;
        seti.retirement_grace_micros = u64::try_from(
            time(
                c,
                b"SETI_RETIREMENT_GRACE",
                Duration::from_micros(seti.retirement_grace_micros),
            )?
            .as_micros(),
        )?;
        seti.incoming_lifetime_micros = u64::try_from(
            time(
                c,
                b"SETI_INCOMING_LIFETIME",
                Duration::from_micros(seti.incoming_lifetime_micros),
            )?
            .as_micros(),
        )?;
        seti.result_layout = match number(c, b"SETI_RESULT_PREFIX", seti.result_layout.prefix())? {
            20 => gnunet_wire::official::seti::ResultLayout::Packed20,
            24 => gnunet_wire::official::seti::ResultLayout::Aligned24,
            _ => return Err("SETI_RESULT_PREFIX must be20 or24".into()),
        };
        seti.element_type_order = match c.get(POLICY, b"SETI_ELEMENT_TYPE_ORDER") {
            None | Some(b"network") => gnunet_seti_client_host::ElementTypeOrder::Network,
            Some(b"little") => gnunet_seti_client_host::ElementTypeOrder::CNativeLittle,
            Some(b"big") => gnunet_seti_client_host::ElementTypeOrder::CNativeBig,
            Some(_) => return Err("SETI_ELEMENT_TYPE_ORDER must be network, little or big".into()),
        };
        let hash_order = match c.get(POLICY, b"HASH_BYTE_ORDER") {
            None => d.hash_order,
            Some(b"little") => HashOrder::Little,
            Some(b"big") => HashOrder::Big,
            Some(_) => return Err("HASH_BYTE_ORDER must be little or big".into()),
        };
        let native = Limits {
            clients: number(c, b"MAX_CLIENTS", d.clients)?,
            max_rows: number(c, b"MAX_ROWS", d.max_rows)?,
            session_bytes: bytes(c, b"SESSION_BYTES", d.session_bytes)?,
            total_retained_bytes: bytes(c, b"TOTAL_RETAINED_BYTES", d.total_retained_bytes)?,
            frame_bytes: bytes(c, b"FRAME_BYTES", d.frame_bytes)?,
            io_slice_bytes: bytes(c, b"IO_SLICE_BYTES", d.io_slice_bytes)?,
            work_units: number(c, b"WORK_UNITS", d.work_units)?,
            first_input: time(c, b"FIRST_INPUT", d.first_input)?,
            partial_input: time(c, b"PARTIAL_INPUT", d.partial_input)?,
            operation: time(c, b"OPERATION_TIMEOUT", d.operation)?,
            retirement_grace: time(c, b"RETIREMENT_GRACE", d.retirement_grace)?,
            hash_order,
            core: match profile {
                Profile::Ecc => gnunet_scalarproduct::Limits {
                    pairs_per_chunk: number(c, b"PAIRS_PER_CHUNK", d.core.pairs_per_chunk)?,
                    max_retained_bytes: bytes(
                        c,
                        b"CORE_RETAINED_BYTES",
                        d.core.max_retained_bytes,
                    )?,
                    dlog: DlogLimits {
                        max_result: u32::try_from(number(
                            c,
                            b"MAX_RESULT",
                            d.core.dlog.max_result as usize,
                        )?)?,
                        memory: u32::try_from(number(
                            c,
                            b"DLOG_MEMORY",
                            d.core.dlog.memory as usize,
                        )?)?,
                        max_retained_bytes: bytes(
                            c,
                            b"DLOG_RETAINED_BYTES",
                            d.core.dlog.max_retained_bytes,
                        )?,
                    },
                },
                Profile::Paillier(_) => d.core,
            },
            seti,
            cadet: gnunet_cadet_host::Limits {
                frame_bytes: bytes(c, b"CADET_FRAME_BYTES", d.cadet.frame_bytes)?,
                io_slice_bytes: bytes(c, b"CADET_IO_SLICE_BYTES", d.cadet.io_slice_bytes)?,
                max_payload_bytes: bytes(c, b"CADET_PAYLOAD_BYTES", d.cadet.max_payload_bytes)?,
                max_send_credit: u32::try_from(number(
                    c,
                    b"CADET_SEND_CREDIT",
                    d.cadet.max_send_credit as usize,
                )?)?,
            },
        };
        profile.validate(native)?;
        let rd = gnunet_resolver_broker::Limits::default();
        let yes = |key: &[u8], default: bool| {
            c.get(mode.section(), key)
                .map(|_| c.get_yesno(mode.section(), key))
                .transpose()
                .map(|v| v.unwrap_or(default))
        };
        Ok(Self {
            native,
            profile,
            resolver: gnunet_resolver_broker::Limits {
                max_frame_bytes: bytes(c, b"RESOLVER_FRAME_BYTES", rd.max_frame_bytes)?,
                io_chunk_bytes: bytes(c, b"RESOLVER_IO_SLICE_BYTES", rd.io_chunk_bytes)?,
                max_queued_frames: number(c, b"RESOLVER_OUTPUT_FRAMES", rd.max_queued_frames)?,
            },
            access: UnixAccess {
                match_uid: yes(b"UNIX_MATCH_UID", false)?,
                match_gid: yes(b"UNIX_MATCH_GID", true)?,
            },
            options: service_options(c, mode.section(), ShutdownMode::Immediate)?,
            shutdown_grace: time(c, b"SHUTDOWN_GRACE", Duration::from_secs(10))?,
        })
    }
}
