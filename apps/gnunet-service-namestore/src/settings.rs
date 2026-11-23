//! Official SERVICE keys plus finite resources for an independent Rust store.
use crate::Failure;
use gnunet_config::Configuration;
use gnunet_namestore_host::{database, server};
use gnunet_service_runtime::{
    credentials::UnixAccess,
    service::{ServiceOptions, ShutdownMode},
    service_options,
};
use std::time::Duration;
const LOCAL: &[u8] = b"namestore-rust";
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
    Ok(c.get(b"namestore", key)
        .map(|_| c.get_yesno(b"namestore", key))
        .transpose()?
        .unwrap_or(false))
}
fn duration(c: &Configuration, key: &[u8], default: u64) -> Result<Duration, Failure> {
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
        return Err("NAMESTORE timers must be finite, nonzero and representable".into());
    }
    Ok(Duration::from_micros(value))
}
pub(super) struct Settings {
    pub database: database::Options,
    pub native: server::Limits,
    pub options: ServiceOptions,
    pub unix: UnixAccess,
    pub resolver: gnunet_resolver_broker::Limits,
    pub grace: Duration,
}
impl Settings {
    pub fn read(c: &Configuration) -> Result<Self, Failure> {
        let database = database::Options::read(c)?;
        let d = server::Limits::default();
        let native = server::Limits {
            clients: n(c, b"MAX_CLIENTS", d.clients)?,
            output_items: n(c, b"OUTPUT_ITEMS", d.output_items)?,
            frame_bytes: size(c, b"FRAME_BYTES", d.frame_bytes)?,
            output_frames: n(c, b"OUTPUT_FRAMES", d.output_frames)?,
            output_bytes: size(c, b"OUTPUT_BYTES", d.output_bytes)?,
            io_slice_bytes: size(c, b"IO_SLICE_BYTES", d.io_slice_bytes)?,
            snapshot_body_bytes: database.body_bytes(),
            iterators: n(c, b"ITERATORS_PER_CLIENT", d.iterators)?,
            streams: gnunet_namestore::StreamLimits {
                changes: n(c, b"MONITOR_CHANGES", d.streams.changes)?,
                scan_rows: n(c, b"SCAN_ROWS", d.streams.scan_rows)?,
            },
            first_input: duration(c, b"FIRST_INPUT_TIMEOUT", 30_000_000)?,
            input_lifetime: duration(c, b"INPUT_LIFETIME", 30_000_000)?,
            output_lifetime: duration(c, b"OUTPUT_LIFETIME", 30_000_000)?,
            storage_lifetime: duration(c, b"STORAGE_LIFETIME", 30_000_000)?,
        };
        if native.clients == 0
            || native.clients > 1024
            || native.output_items == 0
            || native.output_items > 4096
            || native.output_frames == 0
            || native.output_frames > 64
            || native.output_bytes < native.frame_bytes
            || native.frame_bytes < 64
            || native.frame_bytes > 65535
            || native.io_slice_bytes == 0
            || native.iterators == 0
            || native.iterators > 4096
            || native.streams.changes == 0
            || native.streams.changes > 4096
            || native.streams.scan_rows == 0
            || native.streams.scan_rows > 65535
        {
            return Err(
                "invalid NAMESTORE inventory/retained/FIFO/frame/stream resource bounds".into(),
            );
        }
        Ok(Self {
            database,
            native,
            options: service_options(c, b"namestore", ShutdownMode::Soft)?,
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
        })
    }
}
