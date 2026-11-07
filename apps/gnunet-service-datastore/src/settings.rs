//! Checked configuration; DATASTORE's durable format remains an internal backend choice.
use gnunet_config::{Configuration, ProcessEnvironment, ProjectData};
use gnunet_datastore::Config;
use gnunet_datastore_host::{
    backend,
    server::{Limits, UnixAccess},
};
use gnunet_service_runtime::{
    service::{ServiceOptions, ShutdownMode},
    service_options,
};
use std::{
    error::Error,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
pub(crate) fn configuration(selected: Option<&Path>) -> Result<Configuration, Box<dyn Error>> {
    let project = Arc::new(ProjectData::default());
    let mut config = Configuration::create(project.clone(), Default::default())?;
    let path = match selected {
        Some(path) => Some(path.to_path_buf()),
        None => gnunet_config::default_filename(&project)?.filter(|path| path.is_file()),
    };
    config.load(path.as_deref())?;
    Ok(config)
}
fn number(config: &Configuration, key: &[u8], default: usize) -> Result<usize, Box<dyn Error>> {
    config
        .get(b"datastore-rust", key)
        .map(|_| config.get_number(b"datastore-rust", key))
        .transpose()?
        .map(usize::try_from)
        .transpose()
        .map(|value| value.unwrap_or(default))
        .map_err(Into::into)
}

fn size(config: &Configuration, key: &[u8], default: u64) -> Result<u64, Box<dyn Error>> {
    Ok(config
        .get(b"datastore-rust", key)
        .map(|_| config.get_size(b"datastore-rust", key))
        .transpose()?
        .unwrap_or(default))
}

fn yesno(config: &Configuration, key: &[u8]) -> Result<bool, Box<dyn Error>> {
    Ok(config
        .get(b"datastore", key)
        .map(|_| config.get_yesno(b"datastore", key))
        .transpose()?
        .unwrap_or(false))
}

fn storage(config: &Configuration) -> Result<PathBuf, Box<dyn Error>> {
    if config.get(b"datastore-rust", b"DIRECTORY").is_some() {
        return Ok(config.get_filename(b"datastore-rust", b"DIRECTORY", &ProcessEnvironment)?);
    }
    let input = b"${GNUNET_DATA_HOME}/datastore/rust";
    let expanded = config.expand_dollar(input, &ProcessEnvironment)?;
    if expanded == input {
        return Err("set [datastore-rust] DIRECTORY or GNUNET_DATA_HOME".into());
    }
    Ok(config.expand_filename(&expanded, &ProcessEnvironment)?)
}

pub(crate) struct Settings {
    pub(crate) directory: PathBuf,
    pub(crate) backend: backend::Limits,
    pub(crate) service: Config,
    pub(crate) native: Limits,
    pub(crate) access: UnixAccess,
    pub(crate) options: ServiceOptions,
}

impl Settings {
    pub(crate) fn read(config: &Configuration) -> Result<Self, Box<dyn Error>> {
        let backend_defaults = backend::Limits::default();
        let backend = backend::Limits {
            max_records: number(config, b"MAX_RECORDS", backend_defaults.max_records)?,
            max_wal_bytes: size(config, b"MAX_WAL_BYTES", backend_defaults.max_wal_bytes)?,
            max_transaction_ops: number(
                config,
                b"MAX_TRANSACTION_OPS",
                backend_defaults.max_transaction_ops,
            )?,
            checkpoint_bytes: size(
                config,
                b"CHECKPOINT_BYTES",
                backend_defaults.checkpoint_bytes,
            )?,
            garbage_entries: number(config, b"GARBAGE_ENTRIES", backend_defaults.garbage_entries)?,
        };
        let core_defaults = Config::default();
        let service = Config {
            quota_bytes: config
                .get(b"datastore", b"QUOTA")
                .map(|_| config.get_size(b"datastore", b"QUOTA"))
                .transpose()?
                .unwrap_or(5_000_000_000),
            max_value_bytes: number(config, b"MAX_VALUE_BYTES", core_defaults.max_value_bytes)?,
            max_put_evictions: number(
                config,
                b"MAX_PUT_EVICTIONS",
                core_defaults.max_put_evictions,
            )?,
            max_maintenance_evictions: number(
                config,
                b"MAX_MAINTENANCE_EVICTIONS",
                core_defaults.max_maintenance_evictions,
            )?,
        };
        let native_defaults = Limits::default();
        let maintenance_micros = config
            .get(b"datastore-rust", b"MAINTENANCE_INTERVAL")
            .map(|_| config.get_time(b"datastore-rust", b"MAINTENANCE_INTERVAL"))
            .transpose()?;
        if maintenance_micros == Some(u64::MAX) {
            return Err("MAINTENANCE_INTERVAL cannot be forever".into());
        }
        let maintenance_interval = maintenance_micros
            .map(Duration::from_micros)
            .unwrap_or(native_defaults.maintenance_interval);
        // Refuse a wrapped/unrepresentable native deadline before starting
        // the worker or creating its asynchronous maintenance timer.
        if maintenance_interval.is_zero()
            || std::time::Instant::now()
                .checked_add(maintenance_interval)
                .is_none()
        {
            return Err("MAINTENANCE_INTERVAL must be finite, nonzero and representable".into());
        }
        let native = Limits {
            clients: number(config, b"MAX_CLIENTS", native_defaults.clients)?,
            reservations: number(config, b"MAX_RESERVATIONS", native_defaults.reservations)?,
            worker_queue: number(config, b"WORKER_QUEUE", native_defaults.worker_queue)?,
            io_slice_bytes: number(config, b"IO_SLICE_BYTES", native_defaults.io_slice_bytes)?,
            maintenance_interval,
        };
        Ok(Self {
            directory: storage(config)?,
            backend,
            service,
            native,
            access: UnixAccess {
                match_uid: yesno(config, b"UNIX_MATCH_UID")?,
                match_gid: yesno(config, b"UNIX_MATCH_GID")?,
            },
            options: service_options(config, b"datastore", ShutdownMode::Immediate)?,
        })
    }
}
