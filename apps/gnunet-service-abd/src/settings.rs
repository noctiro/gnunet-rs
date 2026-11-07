//! Original endpoint policy and finite native/proof deployment settings.
use crate::{Cause, Mode};
use gnunet_abd_host::Limits;
use gnunet_config::Configuration;
use gnunet_service_runtime::{
    credentials::UnixAccess,
    framing::Budget,
    service::{ServiceOptions, ShutdownMode},
    service_options,
};
use gnunet_wire::official::abd::RecordLayout;
use std::time::Duration;
const POLICY: &[u8] = b"abd-service-rust";
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
        return Err("ABD requires finite representable duration bounds".into());
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
        let d = Limits::default();
        let n = d.namestore;
        let core = gnunet_abd::Limits {
            principals: number(c, b"MAX_PRINCIPALS", d.core.principals)?,
            roles: number(c, b"MAX_ROLES", d.core.roles)?,
            rules: number(c, b"MAX_RULES", d.core.rules)?,
            terms: number(c, b"MAX_TERMS", d.core.terms)?,
            depth: number(c, b"MAX_DEPTH", d.core.depth)?,
            facts: number(c, b"MAX_FACTS", d.core.facts)?,
            supports: number(c, b"MAX_SUPPORTS", d.core.supports)?,
            lookups: number(c, b"MAX_LOOKUPS", d.core.lookups)?,
            credentials: number(c, b"MAX_CREDENTIALS", d.core.credentials)?,
            name_bytes: bytes(c, b"NAME_BYTES", d.core.name_bytes)?,
            retained_bytes: bytes(c, b"CORE_RETAINED_BYTES", d.core.retained_bytes)?,
            record_layout: RecordLayout {
                align64: u8::try_from(number(
                    c,
                    b"ATTR_ALIGN64",
                    usize::from(d.core.record_layout.align64),
                )?)?,
            },
        };
        let native = Limits {
            clients: number(c, b"MAX_CLIENTS", d.clients)?,
            queries: number(c, b"MAX_QUERIES", d.queries)?,
            queries_per_client: number(c, b"QUERIES_PER_CLIENT", d.queries_per_client)?,
            query_bytes: bytes(c, b"QUERY_BYTES", d.query_bytes)?,
            total_retained_bytes: bytes(c, b"TOTAL_RETAINED_BYTES", d.total_retained_bytes)?,
            frame_bytes: bytes(c, b"FRAME_BYTES", d.frame_bytes)?,
            io_slice_bytes: bytes(c, b"IO_SLICE_BYTES", d.io_slice_bytes)?,
            work_units: number(c, b"WORK_UNITS", d.work_units)?,
            first_input: time(c, b"FIRST_INPUT", d.first_input, false)?,
            partial_input: time(c, b"PARTIAL_INPUT", d.partial_input, false)?,
            operation: time(c, b"OPERATION_TIMEOUT", d.operation, false)?,
            output: time(c, b"OUTPUT_TIMEOUT", d.output, false)?,
            utc_uncertainty: time(c, b"UTC_UNCERTAINTY", d.utc_uncertainty, true)?,
            core,
            gns: gnunet_gns_client_host::Limits {
                frame_bytes: bytes(c, b"GNS_FRAME_BYTES", d.gns.frame_bytes)?,
                records: number(c, b"GNS_RECORDS", d.gns.records)?,
                output: Budget {
                    frames: number(c, b"GNS_OUTPUT_FRAMES", d.gns.output.frames)?,
                    bytes: bytes(c, b"GNS_OUTPUT_BYTES", d.gns.output.bytes)?,
                },
                io_slice_bytes: bytes(c, b"GNS_IO_SLICE_BYTES", d.gns.io_slice_bytes)?,
            },
            namestore: gnunet_namestore_client_host::Limits {
                operations: 1,
                source_bytes: bytes(c, b"NAMESTORE_SOURCE_BYTES", n.source_bytes)?,
                frame_bytes: bytes(c, b"NAMESTORE_FRAME_BYTES", n.frame_bytes)?,
                io_slice_bytes: bytes(c, b"NAMESTORE_IO_SLICE_BYTES", n.io_slice_bytes)?,
                record_sets: number(c, b"NAMESTORE_RECORD_SETS", n.record_sets)?,
                records: number(c, b"NAMESTORE_RECORDS", n.records)?,
                label_bytes: bytes(c, b"NAMESTORE_LABEL_BYTES", n.label_bytes)?,
                hint_bytes: bytes(c, b"NAMESTORE_HINT_BYTES", n.hint_bytes)?,
                credit: c
                    .get(POLICY, b"NAMESTORE_CREDIT")
                    .map(|_| c.get_number(POLICY, b"NAMESTORE_CREDIT"))
                    .transpose()?
                    .unwrap_or(n.credit),
                retirement_grace: time(
                    c,
                    b"NAMESTORE_RETIREMENT_GRACE",
                    n.retirement_grace,
                    false,
                )?,
                reconnect: false,
            },
        };
        if !(1..=64).contains(&native.work_units) {
            return Err("WORK_UNITS must be1 through64".into());
        }
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
            shutdown_grace: time(c, b"SHUTDOWN_GRACE", Duration::from_secs(10), false)?,
        })
    }
}
