//! Official foreground startup with private-root disk preparation outside polling.
use crate::{
    identity,
    service::{Host, Limits},
};
use gnunet_config::{Configuration, ProcessEnvironment, ProjectData};
use gnunet_pils::{HeapService, HelloLimits, MasterKey, Profile};
use gnunet_service_runtime::{
    clock::RuntimeClock, credentials::UnixAccess, service::ShutdownMode, service_options,
};

use std::{
    error::Error,
    path::{Path, PathBuf},
    sync::Arc,
};

mod foreground;
pub use foreground::{
    EmbeddedStartup, ForegroundExit, ForegroundFailure, foreground, foreground_embedded,
    foreground_listening, foreground_listening_with_async_ready,
};
/// Maximum public announcement supported by the normal foreground owner.
pub const ANNOUNCEMENT_BYTES: usize = 65535;
struct InitialRoot {
    // The real secret owner is erased before its persistent fence on failure.
    master: MasterKey,
    lease: identity::KeyLease,
}
/// Fully prepared durable identity and bounded host, before service polling.
/// Dropping it erases the pure secret owner before releasing its writer fence.
pub struct Prepared {
    config: Configuration,
    host: Host<ANNOUNCEMENT_BYTES>,
}
impl Prepared {
    /// Actual derived public identity. This reveals no private root material.
    #[must_use]
    pub fn identity(&self) -> Option<[u8; 32]> {
        self.host.identity()
    }
    /// Transfer the actual bounded host to a caller owning its own listeners.
    /// This does not bind sockets or start background work.
    #[must_use]
    pub fn into_host(self) -> Host<ANNOUNCEMENT_BYTES> {
        self.host
    }
}
/// Load installation defaults followed by the selected/default user configuration.
pub fn configuration(selected: Option<&Path>) -> Result<Configuration, Box<dyn Error>> {
    let project = Arc::new(ProjectData::default());
    let mut config = Configuration::create(project.clone(), Default::default())?;
    let discovered = gnunet_config::default_filename(&project)?;
    let selected = selected
        .map(Path::to_path_buf)
        .or_else(|| discovered.filter(|path| path.is_file()));
    config.load(selected.as_deref())?;
    Ok(config)
}
/// Read exact official Unix options; UID priority is supplied by UnixAccess.
pub fn unix_access(config: &Configuration) -> Result<UnixAccess, gnunet_config::Error> {
    let read = |key: &[u8]| {
        config
            .get(b"PILS", key)
            .map(|_| config.get_yesno(b"PILS", key))
            .transpose()
            .map(|value| value.unwrap_or(false))
    };
    Ok(UnixAccess {
        match_uid: read(b"UNIX_MATCH_UID")?,
        match_gid: read(b"UNIX_MATCH_GID")?,
    })
}
/// An embedding caller must switch to the configured account before private-root
/// preparation or starting service tasks/workers. This function only checks
/// actual primary real/effective IDs; it never mutates a process identity from an async context.
pub fn verify_configured_identity(config: &Configuration) -> Result<(), Box<dyn Error>> {
    #[cfg(windows)]
    gnunet_service_startup::verify_configured_identity(config, b"PILS")?;
    #[cfg(unix)]
    {
        use gnunet_service_startup::{Identity, configured_user, resolve_user};
        use std::io;
        if let Some(name) = configured_user(config, b"PILS")? {
            let plan = resolve_user(&name)?;
            let actual = Identity::current();
            if actual.uid != plan.uid()
                || actual.euid != plan.uid()
                || actual.gid != plan.gid()
                || actual.egid != plan.gid()
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "PILS configured identity must be applied before private-root preparation",
                )
                .into());
            }
        }
    }
    Ok(())
}
/// Prepare the complete selected official service in a fresh startup section, after
/// configured identity switching, outside service polling and before active
/// tasks/workers. An idle current-thread runtime may already own prebound TCP
/// listeners across the explicit identity transition. Actual active C
/// source reads `[PEER] PRIVATE_KEY`; `[PILS] SECRET_KEY_FILE` is not used there.
/// Private load/create, fencing, file/parent synchronization and reconciliation
/// all finish here. A failed/unknown durable creation returns no owner or READY.
/// Polling the returned host performs no filesystem synchronization or hidden job.
/// `[PILS] PROFILE` selects the default normal build or the official conditional
/// address-derived identity build before loading or creating private material.
pub fn prepare(
    config: &Configuration,
    clock: Arc<dyn RuntimeClock>,
    limits: Limits,
) -> Result<Prepared, Box<dyn Error>> {
    prepare_using(config, clock, limits, || {
        config
            .get_filename(b"PEER", b"PRIVATE_KEY", &ProcessEnvironment)
            .map_err(Into::into)
    })
}

fn prepare_using(
    config: &Configuration,
    clock: Arc<dyn RuntimeClock>,
    limits: Limits,
    keyfile: impl FnOnce() -> Result<PathBuf, Box<dyn Error>>,
) -> Result<Prepared, Box<dyn Error>> {
    verify_configured_identity(config)?;
    limits.validate()?;
    let profile = Profile::configured(config.get(b"PILS", b"PROFILE"), None)?;
    let unix = unix_access(config)?;
    let options = service_options(config, b"PILS", ShutdownMode::Immediate)?;
    let copied = config.duplicate()?;
    let (master, lease) = identity::load_or_create(&keyfile()?)?;
    let root = InitialRoot { master, lease };
    // Sample after actual durable preparation. Root's declaration order also
    // preserves secret-before-fence cleanup on an original clock refusal.
    let now = clock.sample()?.now.as_micros();
    let InitialRoot { master, lease } = root;
    let service = HeapService::<ANNOUNCEMENT_BYTES>::new_heap(
        master,
        profile,
        now,
        HelloLimits {
            maximum_input_bytes: limits.frame_bytes,
            maximum_address_bytes: limits.address_bytes,
            maximum_addresses: limits.addresses,
        },
    )?;
    let host = Host::new_heap(service, lease, clock, limits, options, unix)?;
    Ok(Prepared {
        config: copied,
        host,
    })
}
