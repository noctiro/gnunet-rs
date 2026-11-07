//! Official service keys and explicit internal volatile-memory resource policy.
use crate::Failure;
use gnunet_config::Configuration;
use gnunet_ipc_unix::producer;
use gnunet_namecache_host::server;
use gnunet_service_runtime::{
    credentials::UnixAccess,
    service::{ServiceOptions, ShutdownMode},
    service_options,
};
use std::time::Duration;

const LOCAL: &[u8] = b"namecache-rust";
fn n(c: &Configuration, key: &[u8], default: usize) -> Result<usize, Failure> {
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
fn yes(c: &Configuration, key: &[u8]) -> Result<bool, Failure> {
    Ok(c.get(b"namecache", key)
        .map(|_| c.get_yesno(b"namecache", key))
        .transpose()?
        .unwrap_or(false))
}
fn duration(c: &Configuration, key: &[u8], default: u64) -> Result<Duration, Failure> {
    let us = c
        .get(LOCAL, key)
        .map(|_| c.get_time(LOCAL, key))
        .transpose()?
        .unwrap_or(default);
    if us == 0
        || us == u64::MAX
        || std::time::Instant::now()
            .checked_add(Duration::from_micros(us))
            .is_none()
    {
        return Err("NAMECACHE timers must be finite, nonzero and representable".into());
    }
    Ok(Duration::from_micros(us))
}
pub(super) struct Settings {
    pub core: gnunet_namecache::Limits,
    pub native: server::Limits,
    pub options: ServiceOptions,
    pub unix: UnixAccess,
    pub resolver: gnunet_resolver_broker::Limits,
    pub grace: Duration,
    pub statistics: producer::Limits,
    pub statistics_grace: Duration,
}
impl Settings {
    pub fn read(c: &Configuration) -> Result<Self, Failure> {
        if c.get(LOCAL, b"BACKEND")
            .is_some_and(|value| !value.eq_ignore_ascii_case(b"memory"))
        {
            return Err("NAMECACHE Rust BACKEND must be memory; no SQL plugin or durable storage backend is implemented by this foreground".into());
        }
        let d = gnunet_namecache::Limits::default();
        let core = gnunet_namecache::Limits {
            entries: n(c, b"MAX_ENTRIES", d.entries)?,
            bytes: size(c, b"CACHE_BYTES", d.bytes)?,
            block_bytes: size(c, b"MAX_BLOCK_BYTES", d.block_bytes)?,
        };
        let d = server::Limits::default();
        let native = server::Limits {
            clients: n(c, b"MAX_CLIENTS", d.clients)?,
            frame_bytes: size(c, b"FRAME_BYTES", d.frame_bytes)?,
            output_frames: n(c, b"OUTPUT_FRAMES", d.output_frames)?,
            output_bytes: size(c, b"OUTPUT_BYTES", d.output_bytes)?,
            io_slice_bytes: size(c, b"IO_SLICE_BYTES", d.io_slice_bytes)?,
            first_input: duration(c, b"FIRST_INPUT_TIMEOUT", 30_000_000)?,
            input_lifetime: duration(c, b"INPUT_LIFETIME", 30_000_000)?,
            output_lifetime: duration(c, b"OUTPUT_LIFETIME", 30_000_000)?,
            maintenance_interval: duration(c, b"MAINTENANCE_INTERVAL", 3_600_000_000)?,
        };
        if core.entries == 0
            || core.entries > 65536
            || core.bytes > 1024 * 1024 * 1024
            || core.block_bytes < 112
            || core.block_bytes > 65519
            || core
                .block_bytes
                .checked_add(16)
                .is_none_or(|n| n > native.frame_bytes)
        {
            return Err("invalid NAMECACHE entry/cache/block/frame resource bounds".into());
        }
        Ok(Self {
            core,
            native,
            options: service_options(c, b"namecache", ShutdownMode::Immediate)?,
            unix: UnixAccess {
                match_uid: yes(c, b"UNIX_MATCH_UID")?,
                match_gid: yes(c, b"UNIX_MATCH_GID")?,
            },
            resolver: gnunet_resolver_broker::Limits {
                max_frame_bytes: 65535,
                io_chunk_bytes: native.io_slice_bytes,
                max_queued_frames: 4,
            },
            grace: duration(c, b"SHUTDOWN_GRACE", 10_000_000)?,
            statistics: producer::Limits {
                operation: duration(c, b"STATISTICS_OPERATION_TIMEOUT", 5_000_000)?,
                write_chunk_bytes: native.io_slice_bytes.min(256),
                ..producer::Limits::default()
            },
            statistics_grace: duration(c, b"STATISTICS_SHUTDOWN_GRACE", 5_000_000)?,
        })
    }
}
