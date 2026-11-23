//! Actual ARM configuration with separate explicit host quotas.
use super::Failure;
use crate::{reactor, registry};
use gnunet_arm_core::wire::ArmAbi;
use gnunet_config::{Configuration, ProcessEnvironment, ProjectData};
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
pub(super) fn configuration(selected: Option<&Path>) -> Result<Configuration, Failure> {
    let project = Arc::new(ProjectData::default());
    let mut config = Configuration::create(project.clone(), Default::default())?;
    let discovered = gnunet_config::default_filename(&project)?;
    let path = selected
        .map(Path::to_path_buf)
        .or_else(|| discovered.filter(|p| p.is_file()));
    config.load(path.as_deref())?;
    Ok(config)
}
fn number(c: &Configuration, key: &[u8], default: usize) -> Result<usize, Failure> {
    Ok(c.get(b"arm-rust", key)
        .map(|_| c.get_number(b"arm-rust", key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}
fn duration(c: &Configuration, key: &[u8], default: Duration) -> Result<Duration, Failure> {
    let d = c
        .get(b"arm-rust", key)
        .map(|_| c.get_time(b"arm-rust", key))
        .transpose()?
        .map(Duration::from_micros)
        .unwrap_or(default);
    if d.is_zero()
        || d.as_micros() >= u64::MAX as u128
        || tokio::time::Instant::now().checked_add(d).is_none()
    {
        return Err("ARM duration must be finite and nonzero".into());
    }
    Ok(d)
}
fn yes(c: &Configuration, key: &[u8]) -> Result<bool, Failure> {
    Ok(c.get(b"arm", key)
        .map(|_| c.get_yesno(b"arm", key))
        .transpose()?
        .unwrap_or(false))
}
pub(super) struct Settings {
    pub(super) native: reactor::Limits,
    pub(super) registry: registry::Limits,
    pub(super) options: ServiceOptions,
    pub(super) access: UnixAccess,
    pub(super) listeners: usize,
    pub(super) addresses: usize,
    pub(super) frames: usize,
    #[cfg(unix)]
    pub(super) helper: PathBuf,
    pub(super) abi: ArmAbi,
    pub(super) shutdown_grace: Duration,
    pub(super) kill_grace: Duration,
    pub(super) resource: Option<PathBuf>,
}
impl Settings {
    pub(super) fn read(c: &Configuration) -> Result<Self, Failure> {
        let d = reactor::Limits::default();
        let services = number(c, b"MAX_SERVICES", d.services)?;
        let clients = number(c, b"MAX_CLIENTS", d.clients)?;
        let process = platform::process(c, services)?;
        let native = reactor::Limits {
            clients,
            services,
            frame_bytes: number(c, b"FRAME_BYTES", d.frame_bytes)?,
            tx_bytes: number(c, b"TX_BYTES", d.tx_bytes)?,
            tx_frames: number(c, b"TX_FRAMES", d.tx_frames)?,
            io_slice: number(c, b"IO_SLICE_BYTES", d.io_slice)?,
            settlement_budget: number(c, b"SETTLEMENT_BUDGET", d.settlement_budget)?,
            diagnostics: number(c, b"DIAGNOSTICS", d.diagnostics)?,
            process,
        };
        let listeners = number(c, b"MAX_LISTENERS", 1024)?;
        let addresses = number(c, b"ADDRESSES_PER_SERVICE", 64)?;
        let frames = number(c, b"FRAME_SLOTS", 64)?;
        if services == 0
            || services > 4096
            || clients == 0
            || clients > 4096
            || !(4..=65535).contains(&native.frame_bytes)
            || native.tx_bytes < 65535
            || native.tx_frames == 0
            || native.tx_frames > 65536
            || native.io_slice == 0
            || native.settlement_budget == 0
            || native.diagnostics > 65536
            || listeners == 0
            || listeners > 65535
            || addresses == 0
            || addresses > 1024
            || frames == 0
            || frames > 65536
        {
            return Err("invalid finite ARM resource profile".into());
        }
        let abi = ArmAbi::configured(c.get(b"arm-rust", b"ABI"))?;
        #[cfg(unix)]
        let helper = platform::helper(c)?;
        let shutdown_grace = duration(c, b"SHUTDOWN_GRACE", Duration::from_secs(5))?;
        let kill_grace = duration(c, b"KILL_GRACE", Duration::from_secs(5))?;
        let whole = shutdown_grace
            .checked_add(kill_grace)
            .ok_or("ARM combined cleanup bound overflow")?;
        tokio::time::Instant::now()
            .checked_add(whole)
            .ok_or("ARM combined cleanup native bound overflow")?;
        Ok(Self {
            native,
            registry: registry::Limits {
                services,
                command_bytes: platform::command_bytes(process),
                substitutions: number(c, b"MAX_SUBSTITUTIONS", 65535)?,
            },
            options: service_options(c, b"arm", ShutdownMode::Immediate)?,
            access: UnixAccess {
                match_uid: yes(c, b"UNIX_MATCH_UID")?,
                match_gid: yes(c, b"UNIX_MATCH_GID")?,
            },
            listeners,
            addresses,
            frames,
            #[cfg(unix)]
            helper,
            abi,
            shutdown_grace,
            kill_grace,
            resource: c
                .get(b"arm", b"RESOURCE_DIAGNOSTICS")
                .map(|_| c.get_filename(b"arm", b"RESOURCE_DIAGNOSTICS", &ProcessEnvironment))
                .transpose()?,
        })
    }
}

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as platform;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as platform;
