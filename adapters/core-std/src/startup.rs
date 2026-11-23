//! Actual configuration/PILS bootstrap and foreground ownership. The service
//! never creates a C subprocess. A Node may instead supply Host's typed identity.
use crate::{Limits, Report};
use gnunet_config::{Configuration, ProjectData};
use gnunet_pils::Profile;
use gnunet_service_runtime::{
    Activation, BoundListeners,
    accepted::SocketEvent,
    clock::{RuntimeClock, SystemClock},
    credentials::UnixAccess,
    service::{ServiceOptions, ShutdownMode},
    service_options,
};
use gnunet_wire::official::core::{PeerClass, PeerId};
use std::{
    error::Error as StdError,
    future::{Future, poll_fn},
    io,
    path::Path,
    pin::Pin,
    sync::Arc,
    task::Poll,
};
mod driver;
use driver::run_foreground;
mod pils;
pub use pils::PilsFeed;
#[cfg(unix)]
mod process;
#[cfg(unix)]
pub use process::{PreparedProcess, ProcessPreparation, prepare_process};
/// Load official defaults plus the selected user's configuration.
pub fn configuration(selected: Option<&Path>) -> Result<Configuration, Box<dyn StdError>> {
    let project = Arc::new(ProjectData::default());
    let mut config = Configuration::create(project.clone(), Default::default())?;
    let discovered = gnunet_config::default_filename(&project)?;
    let selected = selected
        .map(Path::to_owned)
        .or_else(|| discovered.filter(|path| path.is_file()));
    config.load(selected.as_deref())?;
    Ok(config)
}
fn class(config: &Configuration) -> Result<PeerClass, Box<dyn StdError>> {
    let Some(value) = config.get(b"core", b"CLASS") else {
        return Ok(PeerClass::UNKNOWN);
    };
    for (index, name) in [
        b"UNKNOWN".as_slice(),
        b"UNWILLING",
        b"MOBILE",
        b"DESKTOP",
        b"ROUTER",
        b"SERVER",
    ]
    .iter()
    .enumerate()
    {
        if value.eq_ignore_ascii_case(name) {
            return Ok(PeerClass(index as u32));
        }
    }
    Err("unsupported core CLASS".into())
}
/// Run a foreground service using real PILS announcements and the configured
/// TRANSPORT CLIENT endpoint. A single process Resolver is shared by both MQs.
/// Identity changes close old application/transport/session owners before key
/// replacement. PILS loss closes the old epoch and retries its actual endpoint.
/// This embedding entry never changes process identity. A configured USERNAME
/// must already match the actual process account. Unix services can apply it
/// through explicit fresh-process preparation before foreground work.
/// This API does not daemonize or launch C.
pub async fn foreground(
    config: &Configuration,
    activation: Activation,
    limits: Limits,
    ready: impl FnMut(&BoundListeners, PeerId) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    observe: impl FnMut(SocketEvent),
) -> Result<Report, Box<dyn StdError>> {
    foreground_with_clock(
        config,
        activation,
        limits,
        ready,
        shutdown,
        observe,
        Arc::new(SystemClock),
    )
    .await
}
/// Foreground assembly on the caller's canonical process clock, shared by CORE,
/// PILS verification, Resolver callbacks and both configured CLIENT endpoints.
/// Like [`foreground`], this never changes process identity; USERNAME requires
/// the explicit prepared-process path.
///
/// An embedding host supplies the same absolute `[PEER] PRIVATE_KEY` path as
/// PILS and already resolved absolute `UNIXPATH` values for its local services.
/// The caller owns stop and readiness. A successful stop before activation
/// returns its report without invoking readiness.
pub async fn foreground_with_clock(
    config: &Configuration,
    activation: Activation,
    limits: Limits,
    ready: impl FnMut(&BoundListeners, PeerId) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    observe: impl FnMut(SocketEvent),
    clock: Arc<dyn RuntimeClock>,
) -> Result<Report, Box<dyn StdError>> {
    let mut shutdown = std::pin::pin!(shutdown);
    let binding = async {
        verify_configured_identity(config)?;
        ForegroundResources::bind(config, activation).await
    };
    let Some(resources) = until_stop(binding, shutdown.as_mut()).await? else {
        return Ok(Report::default());
    };
    run_foreground(
        resources?,
        limits,
        ready,
        shutdown.as_mut(),
        observe,
        clock,
        std::future::ready(Ok(())),
    )
    .await
}

// Each stage polls the original stop first, even if the operation would be
// ready immediately. None is a successful stop and ends the entire foreground.
async fn until_stop<T>(
    operation: impl Future<Output = T>,
    mut shutdown: Pin<&mut impl Future<Output = io::Result<()>>>,
) -> io::Result<Option<T>> {
    let mut operation = std::pin::pin!(operation);
    poll_fn(|cx| {
        if let Poll::Ready(result) = shutdown.as_mut().poll(cx) {
            return Poll::Ready(result.map(|()| None));
        }
        operation.as_mut().poll(cx).map(|result| Ok(Some(result)))
    })
    .await
}

// A single owner carries the original initialized listeners across the explicit
// synchronous identity transition. No raw descriptor is reconstructed later.
struct ForegroundPolicy {
    options: ServiceOptions,
    unix_access: UnixAccess,
    local_class: PeerClass,
    profile: Profile,
}
impl ForegroundPolicy {
    fn read(config: &Configuration) -> Result<Self, Box<dyn StdError>> {
        let unix_access = unix_access(config)?;
        let options = service_options(config, b"core", ShutdownMode::Immediate)?;
        let local_class = class(config)?;
        let profile = Profile::configured(config.get(b"PILS", b"PROFILE"), None)?;
        Ok(Self {
            options,
            unix_access,
            local_class,
            profile,
        })
    }
}
struct ForegroundResources<'config> {
    config: &'config Configuration,
    bound: BoundListeners,
    policy: ForegroundPolicy,
}
impl<'config> ForegroundResources<'config> {
    async fn bind(
        config: &'config Configuration,
        activation: Activation,
    ) -> Result<Self, Box<dyn StdError>> {
        let policy = ForegroundPolicy::read(config)?;
        #[cfg(unix)]
        let bound = BoundListeners::bind(config, b"core", activation).await?;
        #[cfg(windows)]
        let bound = if activation.is_empty() {
            BoundListeners::bind_configured(config, b"core", policy.unix_access.into()).await?
        } else {
            BoundListeners::from_activation_with_access(activation, policy.unix_access)?
        };
        Ok(Self {
            config,
            bound,
            policy,
        })
    }
}

/// Read official local credential options. Windows does not invent Unix IDs.
pub fn unix_access(config: &Configuration) -> Result<UnixAccess, gnunet_config::Error> {
    Ok(UnixAccess {
        match_uid: config.get(b"core", b"UNIX_MATCH_UID").is_some()
            && config.get_yesno(b"core", b"UNIX_MATCH_UID")?,
        match_gid: config.get(b"core", b"UNIX_MATCH_GID").is_some()
            && config.get_yesno(b"core", b"UNIX_MATCH_GID")?,
    })
}
fn verify_configured_identity(config: &Configuration) -> Result<(), Box<dyn StdError>> {
    #[cfg(windows)]
    gnunet_service_startup::verify_configured_identity(config, b"core")?;
    #[cfg(unix)]
    {
        use gnunet_service_startup::{Identity, configured_user, resolve_user};
        if let Some(name) = configured_user(config, b"core")? {
            let plan = resolve_user(&name)?;
            let actual = Identity::current();
            if actual.uid != plan.uid()
                || actual.euid != plan.uid()
                || actual.gid != plan.gid()
                || actual.egid != plan.gid()
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "CORE configured identity must precede private and service work",
                )
                .into());
            }
        }
    }
    Ok(())
}
/// Completed native listeners and validated configuration before private work.
/// Construct through real listener preparation or configured-identity verification.
pub struct PreparedService<'config> {
    resources: ForegroundResources<'config>,
}
impl<'config> PreparedService<'config> {
    /// Adopt already completed listeners after read-only identity verification.
    /// No account transition, private-key read or service task occurs here.
    pub fn from_listening(
        config: &'config Configuration,
        bound: BoundListeners,
    ) -> Result<Self, Box<dyn StdError>> {
        verify_configured_identity(config)?;
        Ok(Self {
            resources: ForegroundResources {
                config,
                bound,
                policy: ForegroundPolicy::read(config)?,
            },
        })
    }
    /// Drive the actual CORE service and one original readiness notification.
    /// The notification runs only after a verified PILS identity and real Host
    /// construction; shutdown/Resolver progress and a native deadline bound it.
    pub async fn foreground_with_readiness(
        self,
        limits: Limits,
        ready: impl FnMut(&BoundListeners, PeerId) -> io::Result<()>,
        shutdown: impl Future<Output = io::Result<()>>,
        observe: impl FnMut(SocketEvent),
        clock: Arc<dyn RuntimeClock>,
        notification: impl Future<Output = Result<(), Box<dyn StdError>>>,
    ) -> Result<Report, Box<dyn StdError>> {
        run_foreground(
            self.resources,
            limits,
            ready,
            shutdown,
            observe,
            clock,
            notification,
        )
        .await
    }
}
#[cfg(test)]
#[path = "startup/profile_tests.rs"]
mod profile_tests;
