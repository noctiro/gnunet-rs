//! Official SERVICE and ticket TTL settings, plus explicit bounded Rust policy.
use crate::Failure;
use gnunet_config::Configuration;
use gnunet_reclaim_host::{reclaim::business, server};
use gnunet_service_runtime::{
    credentials::UnixAccess,
    service::{ServiceOptions, ShutdownMode},
    service_options,
};
use std::time::Duration;
const LOCAL: &[u8] = b"reclaim-rust";
fn number(c: &Configuration, key: &[u8], default: usize) -> Result<usize, Failure> {
    Ok(c.get(LOCAL, key)
        .map(|_| c.get_number(LOCAL, key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}
fn size(c: &Configuration, key: &[u8], default: usize) -> Result<usize, Failure> {
    Ok(c.get(LOCAL, key)
        .map(|_| c.get_size(LOCAL, key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}
fn time(c: &Configuration, key: &[u8], default: u64) -> Result<Duration, Failure> {
    let value = c
        .get(LOCAL, key)
        .map(|_| c.get_time(LOCAL, key))
        .transpose()?
        .unwrap_or(default);
    if value == 0
        || value == u64::MAX
        || std::time::Instant::now()
            .checked_add(Duration::from_micros(value))
            .is_none()
    {
        return Err("RECLAIM native time budgets must be finite, nonzero and representable".into());
    }
    Ok(Duration::from_micros(value))
}
fn yes(c: &Configuration, key: &[u8], default: bool) -> Result<bool, Failure> {
    Ok(c.get(b"reclaim", key)
        .map(|_| c.get_yesno(b"reclaim", key))
        .transpose()?
        .unwrap_or(default))
}
pub(super) struct Settings {
    pub core: business::Limits,
    pub native: server::Limits,
    pub options: ServiceOptions,
    pub unix: UnixAccess,
    pub resolver: gnunet_resolver_broker::Limits,
    pub grace: Duration,
    pub statistics: gnunet_reclaim_host::statistics::Limits,
    pub statistics_grace: Duration,
}
impl Settings {
    pub fn read(c: &Configuration) -> Result<Self, Failure> {
        let d = business::Limits::default();
        let refresh = c
            .get(b"reclaim", b"TICKET_REFRESH_INTERVAL")
            .map(|_| c.get_time(b"reclaim", b"TICKET_REFRESH_INTERVAL"))
            .transpose()?
            .unwrap_or(d.refresh_micros);
        let core = business::Limits {
            jobs: number(c, b"MAX_JOBS", d.jobs)?,
            sources: number(c, b"PROVIDER_SOURCES", d.sources)?,
            rows: number(c, b"SCAN_ROWS", d.rows)?,
            records: number(c, b"RECORDS_PER_SET", d.records)?,
            items: number(c, b"MAX_ITEMS", d.items)?,
            bytes: size(c, b"RETAINED_BYTES", d.bytes)?,
            frame_bytes: size(c, b"FRAME_BYTES", d.frame_bytes)?,
            refresh_micros: refresh,
            work_units: number(c, b"WORK_UNITS", d.work_units)?,
        };
        let d = server::Limits::default();
        let native = server::Limits {
            clients: number(c, b"MAX_CLIENTS", d.clients)?,
            operations: core.jobs,
            per_client: number(c, b"JOBS_PER_CLIENT", d.per_client)?,
            frame_bytes: core.frame_bytes,
            io_slice_bytes: size(c, b"IO_SLICE_BYTES", d.io_slice_bytes)?,
            first_input: time(c, b"FIRST_INPUT_TIMEOUT", 30_000_000)?,
            input_lifetime: time(c, b"INPUT_LIFETIME", 30_000_000)?,
            output_lifetime: time(c, b"OUTPUT_LIFETIME", 30_000_000)?,
            operation_lifetime: time(c, b"OPERATION_LIFETIME", 180_000_000)?,
            retirement_grace: time(c, b"RETIREMENT_GRACE", 5_000_000)?,
            gns_options: u16::try_from(number(c, b"GNS_OPTIONS", 0)?)?,
            gns_recursion: u16::try_from(number(c, b"GNS_RECURSION_DEPTH", 128)?)?,
        };
        if core.jobs == 0
            || core.jobs > 1024
            || core.sources < 6
            || core.sources > 4096
            || core.rows == 0
            || core.rows > 4096
            || core.records == 0
            || core.records > 4096
            || core.items == 0
            || core.items > 4096
            || core.bytes < 1024
            || core.bytes > 256 * 1024 * 1024
            || core.frame_bytes < 309
            || core.frame_bytes > 65535
            || core.refresh_micros == 0
            || core.work_units == 0
            || core.work_units > 256_000_000
            || native.clients == 0
            || native.clients > 1024
            || native.per_client == 0
            || native.per_client > native.operations
            || native.io_slice_bytes == 0
        {
            return Err("invalid RECLAIM factory/MQ/provider/frame/work resource bounds".into());
        }
        Ok(Self {
            core,
            native,
            options: service_options(c, b"reclaim", ShutdownMode::Immediate)?,
            unix: UnixAccess {
                match_uid: yes(c, b"UNIX_MATCH_UID", false)?,
                match_gid: yes(c, b"UNIX_MATCH_GID", false)?,
            },
            resolver: gnunet_resolver_broker::Limits {
                max_frame_bytes: 65535,
                io_chunk_bytes: native.io_slice_bytes,
                max_queued_frames: 4,
            },
            grace: time(c, b"SHUTDOWN_GRACE", 10_000_000)?,
            statistics: gnunet_reclaim_host::statistics::Limits {
                operation: time(c, b"STATISTICS_TIMEOUT", 5_000_000)?,
                ..Default::default()
            },
            statistics_grace: time(c, b"STATISTICS_SHUTDOWN_GRACE", 5_000_000)?,
        })
    }
}
