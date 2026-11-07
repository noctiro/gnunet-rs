//! Official listener/ACL keys and explicit finite private Rust resources.
use crate::Failure;
use gnunet_config::{Configuration, ProcessEnvironment};
use gnunet_identity_host::{backend, server};
use gnunet_service_runtime::{
    credentials::UnixAccess,
    service::{ServiceOptions, ShutdownMode},
    service_options,
};
use std::{path::PathBuf, time::Duration};
const LOCAL: &[u8] = b"identity-rust";
fn n(c: &Configuration, key: &[u8], d: usize) -> Result<usize, Failure> {
    Ok(c.get(LOCAL, key)
        .map(|_| c.get_number(LOCAL, key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(d))
}
fn size(c: &Configuration, key: &[u8], d: usize) -> Result<usize, Failure> {
    Ok(c.get(LOCAL, key)
        .map(|_| c.get_size(LOCAL, key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(d))
}
fn yes(c: &Configuration, key: &[u8]) -> Result<bool, Failure> {
    Ok(c.get(b"identity", key)
        .map(|_| c.get_yesno(b"identity", key))
        .transpose()?
        .unwrap_or(false))
}
fn duration(c: &Configuration, key: &[u8], d: u64) -> Result<Duration, Failure> {
    let n = c
        .get(LOCAL, key)
        .map(|_| c.get_time(LOCAL, key))
        .transpose()?
        .unwrap_or(d);
    if n == 0
        || n == u64::MAX
        || std::time::Instant::now()
            .checked_add(Duration::from_micros(n))
            .is_none()
    {
        return Err("IDENTITY timers must be finite, nonzero and representable".into());
    }
    Ok(Duration::from_micros(n))
}
pub(super) struct Settings {
    pub directory: PathBuf,
    pub core: gnunet_identity::Limits,
    pub native: server::Limits,
    pub backend: backend::Limits,
    pub options: ServiceOptions,
    pub unix: UnixAccess,
    pub resolver: gnunet_resolver_broker::Limits,
    pub grace: Duration,
}
impl Settings {
    pub fn read(c: &Configuration) -> Result<Self, Failure> {
        let directory = if c.get(LOCAL, b"DIRECTORY").is_some() {
            c.get_filename(LOCAL, b"DIRECTORY", &ProcessEnvironment)?
        } else {
            let raw = b"${GNUNET_DATA_HOME}/identity-rust-v1";
            let expanded = c.expand_dollar(raw, &ProcessEnvironment)?;
            if expanded == raw {
                return Err("set [identity-rust] DIRECTORY or GNUNET_DATA_HOME".into());
            }
            c.expand_filename(&expanded, &ProcessEnvironment)?
        };
        if !directory.is_absolute() {
            return Err("IDENTITY Rust store DIRECTORY must be absolute".into());
        }
        let pure = gnunet_identity::Limits::default();
        let core = gnunet_identity::Limits {
            egos: n(c, b"MAX_EGOS", pure.egos)?,
            name_bytes: size(c, b"MAX_NAME_BYTES", pure.name_bytes)?,
            snapshot_bytes: size(c, b"SNAPSHOT_BYTES", pure.snapshot_bytes)?,
        };
        let d = server::Limits::default();
        let native = server::Limits {
            clients: n(c, b"MAX_CLIENTS", d.clients)?,
            output_items: n(c, b"OUTPUT_ITEMS", d.output_items)?,
            frame_bytes: size(c, b"FRAME_BYTES", d.frame_bytes)?,
            output_frames: n(c, b"OUTPUT_FRAMES", d.output_frames)?,
            output_bytes: size(c, b"OUTPUT_BYTES", d.output_bytes)?,
            io_slice_bytes: size(c, b"IO_SLICE_BYTES", d.io_slice_bytes)?,
            snapshot_body_bytes: size(c, b"STORE_BODY_BYTES", d.snapshot_body_bytes)?,
            retained_versions: n(c, b"RETAINED_VERSIONS", d.retained_versions)?,
            first_input: duration(c, b"FIRST_INPUT_TIMEOUT", 30_000_000)?,
            input_lifetime: duration(c, b"INPUT_LIFETIME", 30_000_000)?,
            output_lifetime: duration(c, b"OUTPUT_LIFETIME", 30_000_000)?,
            storage_lifetime: duration(c, b"STORAGE_LIFETIME", 30_000_000)?,
        };
        let largest_body = core
            .egos
            .checked_mul(
                core.name_bytes
                    .checked_add(38)
                    .ok_or("snapshot row overflow")?,
            )
            .and_then(|n| n.checked_add(12))
            .ok_or("snapshot body overflow")?;
        if core.egos == 0
            || core.egos > 4096
            || core.name_bytes > gnunet_identity::MAX_NAME_BYTES
            || core.snapshot_bytes < 4096
            || core.snapshot_bytes > 64 * 1024 * 1024
            || largest_body > native.snapshot_body_bytes
            || native.snapshot_body_bytes > 64 * 1024 * 1024
            || core
                .name_bytes
                .checked_add(49)
                .is_none_or(|n| n > native.frame_bytes)
        {
            return Err("invalid IDENTITY snapshot/name/frame bounds or STORE_BODY_BYTES too small for MAX_EGOS/MAX_NAME_BYTES".into());
        }
        Ok(Self {
            directory,
            core,
            native,
            backend: backend::Limits {
                body_bytes: native.snapshot_body_bytes,
            },
            options: service_options(c, b"identity", ShutdownMode::Soft)?,
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
