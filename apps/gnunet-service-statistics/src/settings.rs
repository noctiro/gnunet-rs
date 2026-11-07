//! Official service configuration and explicit bounded deployment resources.
use crate::Failure;
use gnunet::{
    config::{Configuration, Environment, ProcessEnvironment, ProjectData},
    ipc::server::Limits as HostLimits,
    statistics::ResourceLimits,
    statistics_store::Limits as StoreLimits,
};
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
    let mut config = Configuration::create(project.clone(), Default::default())?;
    // SERVICE uses the XDG/user candidate, not the configuration tool's /etc
    // fallback discovery. Loading None still reads actual installed defaults.
    let path = match selected {
        Some(path) => Some(path.to_path_buf()),
        None => {
            let raw = match ProcessEnvironment.variable(b"XDG_CONFIG_HOME") {
                Some(mut base) => {
                    base.push(b'/');
                    base.extend_from_slice(&project.config_file);
                    base
                }
                None => project.user_config_file.clone(),
            };
            let path = config.expand_filename(&raw, &ProcessEnvironment)?;
            (path.is_file() && nix::unistd::access(&path, nix::unistd::AccessFlags::F_OK).is_ok())
                .then_some(path)
        }
    };
    config.load(path.as_deref())?;
    Ok(config)
}
fn number(c: &Configuration, key: &[u8], default: u64) -> Result<u64, Failure> {
    Ok(c.get(b"statistics-rust", key)
        .map(|_| c.get_number(b"statistics-rust", key))
        .transpose()?
        .unwrap_or(default))
}
fn size(c: &Configuration, key: &[u8], default: u64) -> Result<u64, Failure> {
    Ok(c.get(b"statistics-rust", key)
        .map(|_| c.get_size(b"statistics-rust", key))
        .transpose()?
        .unwrap_or(default))
}
fn interval(c: &Configuration, key: &[u8], default: u64) -> Result<u64, Failure> {
    Ok(c.get(b"statistics-rust", key)
        .map(|_| c.get_time(b"statistics-rust", key))
        .transpose()?
        .unwrap_or(default))
}
fn yes(c: &Configuration, key: &[u8]) -> Result<bool, Failure> {
    Ok(c.get(b"statistics", key)
        .map(|_| c.get_yesno(b"statistics", key))
        .transpose()?
        .unwrap_or(false))
}
pub(crate) struct Settings {
    pub(crate) database: Option<PathBuf>,
    pub(crate) core: ResourceLimits,
    pub(crate) host: HostLimits,
    pub(crate) store: StoreLimits,
    pub(crate) options: ServiceOptions,
    pub(crate) access: UnixAccess,
    pub(crate) shutdown_grace: Duration,
}
impl Settings {
    pub(crate) fn read(c: &Configuration) -> Result<Self, Failure> {
        let rows = usize::try_from(number(c, b"MAX_ROWS", 65536)?)?;
        let clients = usize::try_from(number(c, b"MAX_CLIENTS", 32)?)?;
        let watches = usize::try_from(number(c, b"MAX_WATCHES", 65536)?)?;
        let events = usize::try_from(number(c, b"MAX_EVENTS", 262144)?)?;
        let retained = size(c, b"MAX_RETAINED_BYTES", 64 * 1024 * 1024)?;
        let frame = usize::try_from(size(c, b"MAX_FRAME_BYTES", 65535)?)?;
        let names_default = u64::try_from(frame.saturating_sub(16).min(65519))?;
        let names = usize::try_from(size(c, b"MAX_NAME_BYTES", names_default)?)?;
        let pending = usize::try_from(size(c, b"MAX_PENDING_BYTES", 1024 * 1024)?)?;
        let file = size(c, b"MAX_DATABASE_BYTES", 16 * 1024 * 1024)?;
        let records = usize::try_from(number(c, b"MAX_DATABASE_RECORDS", 65536)?)?;
        let idle = interval(c, b"IDLE_TIMEOUT", u64::MAX)?;
        let grace = interval(c, b"SHUTDOWN_GRACE", 5_000_000)?;
        if !(1..=1_048_576).contains(&rows)
            || !(1..=65_536).contains(&clients)
            || !(1..=1_048_576).contains(&watches)
            || !(1..=1_048_576).contains(&events)
            || retained == 0
            || retained > 4_294_967_296
            || !(18..=65535).contains(&frame)
            || names < 2
            || names > frame.saturating_sub(16)
            || pending < frame
            || pending > 16 * 1024 * 1024
            || file == 0
            || file > 256 * 1024 * 1024
            || records == 0
            || records > 1_048_576
            || idle == 0
            || grace == 0
            || grace == u64::MAX
        {
            return Err("invalid statistics resource bounds".into());
        }
        let shutdown_grace = Duration::from_micros(grace);
        if tokio::time::Instant::now()
            .checked_add(shutdown_grace)
            .is_none()
        {
            return Err("statistics SHUTDOWN_GRACE cannot be represented".into());
        }
        Ok(Self {
            core: ResourceLimits {
                max_rows: rows,
                max_name_bytes: names,
                max_clients: clients,
                max_watches: watches,
                max_events: events,
                max_retained_bytes: usize::try_from(retained)?,
            },
            database: c
                .get(b"statistics", b"DATABASE")
                .map(|_| c.get_filename(b"statistics", b"DATABASE", &ProcessEnvironment))
                .transpose()?,
            host: HostLimits {
                max_connections: clients,
                max_frame_bytes: frame,
                max_pending_bytes: pending,
                idle_timeout: if idle == u64::MAX {
                    Duration::MAX
                } else {
                    Duration::from_micros(idle)
                },
            },
            store: StoreLimits {
                max_file_bytes: file,
                max_records: records,
                max_frame_bytes: 65535,
            },
            options: service_options(c, b"statistics", ShutdownMode::Soft)?,
            access: UnixAccess {
                match_uid: yes(c, b"UNIX_MATCH_UID")?,
                match_gid: yes(c, b"UNIX_MATCH_GID")?,
            },
            shutdown_grace,
        })
    }
}
