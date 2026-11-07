//! Official foreground startup with private-root disk preparation outside polling.
use crate::{
    identity,
    service::{Host, Limits, Progress, Report},
};
use gnunet_config::{Configuration, ProcessEnvironment, ProjectData};
use gnunet_pils::{HelloLimits, MasterKey, Profile, Service};
use gnunet_service_runtime::{
    Activation, BoundListeners, accepted::SocketEvent, clock::RuntimeClock,
    credentials::UnixAccess, service::ShutdownMode, service_options,
};
use gnunet_service_startup::{Identity, configured_user, resolve_user};
use std::{
    error::Error,
    future::{Future, poll_fn},
    io,
    path::Path,
    sync::Arc,
    task::Poll,
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
    if let Some(name) = configured_user(config, b"PILS")? {
        let plan = resolve_user(&name)?;
        let actual = Identity::current();
        if actual.uid != plan.uid()
            || actual.euid != plan.uid()
            || actual.gid != plan.gid()
            || actual.egid != plan.gid()
        {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!(
                "PILS USERNAME requires uid={} gid={} before private-root preparation/service tasks; actual={actual:?}", plan.uid(), plan.gid()
            )).into());
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
    verify_configured_identity(config)?;
    limits.validate()?;
    let profile = Profile::configured(config.get(b"PILS", b"PROFILE"), None)?;
    let unix = unix_access(config)?;
    let options = service_options(config, b"PILS", ShutdownMode::Immediate)?;
    let copied = config.duplicate()?;
    let keyfile = config.get_filename(b"PEER", b"PRIVATE_KEY", &ProcessEnvironment)?;
    let (master, lease) = identity::load_or_create(&keyfile)?;
    let root = InitialRoot { master, lease };
    // Sample after actual durable preparation. Root's declaration order also
    // preserves secret-before-fence cleanup on an original clock refusal.
    let now = clock.sample()?.now.as_micros();
    let InitialRoot { master, lease } = root;
    let service = Service::<ANNOUNCEMENT_BYTES>::new(
        master,
        profile,
        now,
        HelloLimits {
            maximum_input_bytes: limits.frame_bytes,
            maximum_address_bytes: limits.address_bytes,
            maximum_addresses: limits.addresses,
        },
    )?;
    let host = Host::new(Box::new(service), lease, clock, limits, options, unix)?;
    Ok(Prepared {
        config: copied,
        host,
    })
}
/// Bind configured/inherited shared Unix/TCP listeners and explicitly drive the
/// prepared native service on this task. Original socket/progress errors stay
/// visible to the caller's synchronous observers. No C daemon, busy polling,
/// implicit Resolver or per-peer worker is created. `ready` runs only after the
/// private root is durable and all selected actual listeners are bound.
pub async fn foreground(
    prepared: Prepared,
    activation: Activation,
    ready: impl FnMut(&BoundListeners, [u8; 32]) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    observe_socket: impl FnMut(SocketEvent),
    observe_progress: impl FnMut(&Progress) -> io::Result<()>,
) -> Result<Report, Box<dyn Error>> {
    verify_configured_identity(&prepared.config)?;
    let bound = BoundListeners::bind(&prepared.config, b"PILS", activation).await?;
    run_listening(
        prepared,
        bound,
        ready,
        shutdown,
        observe_socket,
        observe_progress,
    )
    .await
}
/// Drive a genuine prepared host on actual caller-owned listeners. The standard
/// process prepares TCP/activation before USERNAME and finishes new Unix paths
/// after the transition. This entry never binds/reopens sockets, switches IDs,
/// forks, loads private roots or invents a successful privilege/ready receipt.
/// The caller must supply the listeners intended for this service; their inode
/// guards stay owned until all actual host streams have closed.
pub async fn foreground_listening(
    prepared: Prepared,
    bound: BoundListeners,
    ready: impl FnMut(&BoundListeners, [u8; 32]) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    observe_socket: impl FnMut(SocketEvent),
    observe_progress: impl FnMut(&Progress) -> io::Result<()>,
) -> Result<Report, Box<dyn Error>> {
    verify_configured_identity(&prepared.config)?;
    run_listening(
        prepared,
        bound,
        ready,
        shutdown,
        observe_socket,
        observe_progress,
    )
    .await
}
#[derive(Debug)]
struct ForegroundFailure {
    original: Box<dyn Error>,
    cleanup: Box<dyn Error>,
}
impl std::fmt::Display for ForegroundFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}; independent PILS cleanup observer failure: {}",
            self.original, self.cleanup
        )
    }
}
impl Error for ForegroundFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.original.as_ref())
    }
}
async fn run_listening(
    prepared: Prepared,
    bound: BoundListeners,
    mut ready: impl FnMut(&BoundListeners, [u8; 32]) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    mut observe_socket: impl FnMut(SocketEvent),
    mut observe_progress: impl FnMut(&Progress) -> io::Result<()>,
) -> Result<Report, Box<dyn Error>> {
    let Prepared {
        config: _,
        mut host,
    } = prepared;
    let outcome: Result<(), Box<dyn Error>> = async {
        let peer = host
            .identity()
            .ok_or("PILS prepared owner is already closed")?;
        ready(&bound, peer)?;
        let listeners = bound.listeners();
        let mut shutdown = std::pin::pin!(shutdown);
        loop {
            let result = {
                let mut driving = std::pin::pin!(host.drive(&listeners, &mut observe_socket, None));
                poll_fn(|cx| {
                    if let Poll::Ready(result) = shutdown.as_mut().poll(cx) {
                        return Poll::Ready(
                            result
                                .map(|()| None)
                                .map_err(|error| Box::new(error) as Box<dyn Error>),
                        );
                    }
                    driving.as_mut().poll(cx).map(|result| {
                        result
                            .map(Some)
                            .map_err(|error| Box::new(error) as Box<dyn Error>)
                    })
                })
                .await
            };
            match result {
                Ok(None) => break Ok(()),
                Ok(Some(progress)) => {
                    if let Err(error) = observe_progress(&progress) {
                        break Err(Box::new(error) as Box<dyn Error>);
                    }
                    if matches!(progress, Progress::Closed) {
                        break Ok(());
                    }
                }
                Err(error) => break Err(error),
            }
        }
    }
    .await;
    host.close();
    // Every cleanup event is from an already closed actual stream. Preserve
    // observer failure too, while retaining an earlier original service cause.
    let mut cleanup = Ok(());
    while let Some(event) = host.next_event() {
        if let Err(error) = observe_progress(&event)
            && cleanup.is_ok()
        {
            cleanup = Err(Box::new(error) as Box<dyn Error>);
        }
    }
    let report = host.report();
    match (outcome, cleanup) {
        (Ok(()), Ok(())) => Ok(report),
        (Err(original), Ok(())) => Err(original),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Err(original), Err(cleanup)) => Err(Box::new(ForegroundFailure { original, cleanup })),
    }
}
