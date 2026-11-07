//! Exact original PEERSTORE resource/configuration policy; no command-line storage override.
use crate::Failure;
use gnunet_config::{Configuration, ProcessEnvironment, ProjectData};
use gnunet_peerstore as core;
use gnunet_peerstore_host::{backend, server};
use gnunet_service_runtime::{
    credentials::UnixAccess,
    service::{ServiceOptions, ShutdownMode},
    service_options,
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
pub(crate) fn configuration(selected: Option<&Path>) -> Result<Configuration, Failure> {
    let project = Arc::new(ProjectData::default());
    let mut cfg = Configuration::create(project.clone(), Default::default())?;
    let discovered = gnunet_config::default_filename(&project)?;
    let path = selected
        .map(Path::to_path_buf)
        .or_else(|| discovered.filter(|p| p.is_file()));
    cfg.load(path.as_deref())?;
    Ok(cfg)
}
fn number(c: &Configuration, key: &[u8], default: usize) -> Result<usize, Failure> {
    Ok(c.get(b"peerstore-rust", key)
        .map(|_| c.get_number(b"peerstore-rust", key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}
fn size(c: &Configuration, key: &[u8], default: u64) -> Result<u64, Failure> {
    Ok(c.get(b"peerstore-rust", key)
        .map(|_| c.get_size(b"peerstore-rust", key))
        .transpose()?
        .unwrap_or(default))
}
fn yes(c: &Configuration, key: &[u8]) -> Result<bool, Failure> {
    Ok(c.get(b"peerstore", key)
        .map(|_| c.get_yesno(b"peerstore", key))
        .transpose()?
        .unwrap_or(false))
}
pub(crate) struct Settings {
    pub(crate) directory: PathBuf,
    pub(crate) backend: backend::Limits,
    pub(crate) native: server::Limits,
    pub(crate) core: core::Limits,
    pub(crate) operations: usize,
    pub(crate) filter_bytes: usize,
    pub(crate) worker: usize,
    pub(crate) access: UnixAccess,
    pub(crate) options: ServiceOptions,
    pub(crate) hellos: Option<PathBuf>,
    pub(crate) hello_files: usize,
    pub(crate) shutdown_grace: Duration,
}
impl Settings {
    pub(crate) fn read(c: &Configuration) -> Result<Self, Failure> {
        let directory = if c.get(b"peerstore-rust", b"DIRECTORY").is_some() {
            c.get_filename(b"peerstore-rust", b"DIRECTORY", &ProcessEnvironment)?
        } else {
            let raw = b"${GNUNET_DATA_HOME}/peerstore/rust";
            let p = c.expand_dollar(raw, &ProcessEnvironment)?;
            if p == raw {
                return Err("set [peerstore-rust] DIRECTORY or GNUNET_DATA_HOME".into());
            }
            c.expand_filename(&p, &ProcessEnvironment)?
        };
        let d = backend::Limits::default();
        let backend = backend::Limits {
            records: number(c, b"MAX_RECORDS", d.records)?,
            live_bytes: usize::try_from(size(c, b"MAX_LIVE_BYTES", d.live_bytes as u64)?)?,
            wal_bytes: size(c, b"MAX_WAL_BYTES", d.wal_bytes)?,
            checkpoint_bytes: size(c, b"CHECKPOINT_BYTES", d.checkpoint_bytes)?,
        };
        let n = server::Limits::default();
        let clients = number(c, b"MAX_CLIENTS", n.clients)?;
        let interval = c
            .get(b"peerstore-rust", b"MAINTENANCE_INTERVAL")
            .map(|_| c.get_time(b"peerstore-rust", b"MAINTENANCE_INTERVAL"))
            .transpose()?
            .unwrap_or(300_000_000);
        if interval == 0 || interval == u64::MAX {
            return Err("maintenance interval must be finite and nonzero".into());
        }
        let native = server::Limits {
            clients,
            io_slice_bytes: number(c, b"IO_SLICE_BYTES", n.io_slice_bytes)?,
            maintenance_interval: Duration::from_micros(interval),
        };
        let core = core::Limits {
            record_bytes: number(c, b"MAX_RECORD_BYTES", 65535)?,
        };
        let operations = number(c, b"MAX_OPERATIONS", 64)?;
        let filter_bytes = number(c, b"FILTER_BYTES", 1024)?;
        let worker = number(
            c,
            b"WORKER_QUEUE",
            clients.checked_add(1).ok_or("worker bound overflow")?,
        )?;
        if clients == 0
            || clients > 1024
            || operations == 0
            || operations > 4096
            || filter_bytes == 0
            || filter_bytes > 65535
            || !(60..=65535).contains(&core.record_bytes)
            || worker < clients + 1
            || worker > 4096
        {
            return Err("invalid explicit peerstore resource bounds".into());
        }
        let grace = c
            .get(b"peerstore-rust", b"SHUTDOWN_GRACE")
            .map(|_| c.get_time(b"peerstore-rust", b"SHUTDOWN_GRACE"))
            .transpose()?
            .unwrap_or(10_000_000);
        if grace == 0
            || grace == u64::MAX
            || std::time::Instant::now()
                .checked_add(Duration::from_micros(grace))
                .is_none()
        {
            return Err("SHUTDOWN_GRACE must be finite, nonzero and representable".into());
        }
        let hellos = if yes(c, b"USE_INCLUDED_HELLOS")? {
            Some(if c.get(b"peerstore-rust", b"HELLO_DIRECTORY").is_some() {
                c.get_filename(b"peerstore-rust", b"HELLO_DIRECTORY", &ProcessEnvironment)?
            } else {
                c.get_filename(b"PATHS", b"DATADIR", &ProcessEnvironment)?
                    .join("hellos")
            })
        } else {
            None
        };
        Ok(Self {
            directory,
            backend,
            native,
            core,
            operations,
            filter_bytes,
            worker,
            access: UnixAccess {
                match_uid: yes(c, b"UNIX_MATCH_UID")?,
                match_gid: yes(c, b"UNIX_MATCH_GID")?,
            },
            options: service_options(c, b"peerstore", ShutdownMode::Soft)?,
            hellos,
            hello_files: number(c, b"MAX_INCLUDED_HELLOS", 1024)?,
            shutdown_grace: Duration::from_micros(grace),
        })
    }
}
