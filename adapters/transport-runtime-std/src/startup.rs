//! Official configuration/activation and explicit Rust transport+peerstore entry.
use crate::{
    EndpointPolicy, Limits, LocalKeyCapability, LocalPorts, Policies, Progress, Report, Runtime,
    ServicePorts,
};
use gnunet_client_host::EndpointSource;
/// Shared process environment used for official filename expansion.
pub use gnunet_config::ProcessEnvironment;
use gnunet_config::{Configuration, ProjectData};
use gnunet_resolver_broker::{FamilyProfile, LiveConfiguration, broker};
use gnunet_service_runtime::{
    Activation, BoundListeners, LocalListenerAccess,
    accepted::SocketEvent,
    clock::{RuntimeClock, SystemClock},
    credentials::UnixAccess,
    service::ShutdownMode,
    service_options,
};
use gnunet_transport::addresses::AddressRejection;
use gnunet_transport_host::peerstore::Journal;
/// Explicit shared included-HELLO resource directory and finite import policy.
pub use gnunet_transport_host::peerstore::bootstrap::Directory as IncludedHellos;
use std::{
    error::Error,
    future::{Future, poll_fn},
    io,
    num::NonZeroU64,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    task::Poll,
    time::Duration,
};
use tokio::time::{Instant, Sleep, sleep_until};

/// One explicit foreground resource choice. Only TRANSPORT inherits activation;
/// companion PEERSTORE binds its configured public endpoints independently.
pub struct LocalStartup<'a> {
    /// Official configuration snapshot; no hidden reload or DNS task is created.
    pub config: &'a Configuration,
    /// Original caller-transferred TRANSPORT listening sockets.
    pub activation: Activation,
    /// Explicit new-format Rust backend directory, never a C sqlite filename.
    pub state_directory: PathBuf,
    /// Optional caller-selected public bootstrap resources, imported before service startup.
    pub included_hellos: Option<IncludedHellos>,
    /// Explicit caller authorization for verified local PILS key access.
    pub local_key: LocalKeyCapability,
    /// Finite runtime policy.
    pub limits: Limits,
}
/// Standard service-signing foreground resources; no local IKM authorization.
pub struct ServiceStartup<'a> {
    /// Official configuration snapshot.
    pub config: &'a Configuration,
    /// Original caller-transferred TRANSPORT listeners.
    pub activation: Activation,
    /// Explicit new-format native backend directory.
    pub state_directory: PathBuf,
    /// Optional caller-selected public bootstrap resources, imported before service startup.
    pub included_hellos: Option<IncludedHellos>,
    /// Finite caller-driven resource policy.
    pub limits: Limits,
}

/// When TRANSPORT may begin publishing the aggregate address set to PILS.
pub enum PublicationStart<Start = std::future::Ready<()>> {
    /// Allow aggregate FEED after the address set's quiet interval.
    Immediate,
    /// Track addresses immediately and also require this future to resolve before FEED.
    After(Start),
}

/// The host's publication start, stop source and maximum drain grace.
pub struct ForegroundLifecycle<Stop, Start = std::future::Ready<()>> {
    /// A single stop request. Failure propagates as the original I/O error.
    pub stop: Stop,
    /// Time to settle the original PILS epoch after stop, in clock microseconds.
    pub drain_budget_micros: NonZeroU64,
    /// Hold aggregate PILS FEED until the host has completed its readiness barrier.
    pub publication_start: PublicationStart<Start>,
}

impl<Stop: Future<Output = io::Result<()>>> ForegroundLifecycle<Stop> {
    fn desktop(stop: Stop) -> Result<Self, gnunet_types::Error> {
        Ok(Self {
            stop,
            drain_budget_micros: NonZeroU64::new(30_000_000)
                .ok_or(gnunet_types::Error::InvalidInput)?,
            publication_start: PublicationStart::Immediate,
        })
    }
}

/// Clean retirement, distinguished by whether the host's readiness callback completed.
#[derive(Clone, Copy, Debug)]
pub enum ForegroundExit {
    /// Retirement completed before the first successful readiness callback.
    BeforeReady(Report),
    /// The readiness callback completed at least once before stop.
    AfterReady(Report),
}

impl ForegroundExit {
    fn report(self) -> Report {
        match self {
            Self::BeforeReady(report) | Self::AfterReady(report) => report,
        }
    }
}

/// Notices delivered synchronously to the foreground's caller.
#[derive(Debug)]
pub enum Diagnostic {
    /// The consumed local outcome of an original own-publication operation.
    OwnPublication(crate::Error),
    /// An original communicator address refused by the local address policy.
    AddressRejected(AddressRejection),
    /// One startup URL rejected by the canonical public HELLO checks.
    IncludedHelloSkipped {
        /// Original resource path.
        path: PathBuf,
        /// Exact bounded codec/signature/time refusal.
        reason: gnunet_transport_host::peerstore::bootstrap::SkipReason,
    },
}

/// A foreground failure with an independent failure retiring its runtime.
#[derive(Debug)]
pub struct ForegroundFailure {
    /// The initiating drive or deadline error.
    pub original: Box<dyn Error>,
    /// The actual failure closing the original runtime.
    pub cleanup: crate::Error,
}

impl std::fmt::Display for ForegroundFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}. TRANSPORT cleanup: {}", self.original, self.cleanup)
    }
}

impl Error for ForegroundFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.original.as_ref())
    }
}

struct Observers<Socket, Pils, Runtime> {
    socket: Socket,
    pils: Pils,
    runtime: Runtime,
}

/// Load installation defaults and selected/default official user configuration.
pub fn configuration(selected: Option<&Path>) -> Result<Configuration, Box<dyn Error>> {
    let project = Arc::new(ProjectData::default());
    let mut cfg = Configuration::create(project.clone(), Default::default())?;
    let discovered = gnunet_config::default_filename(&project)?;
    let selected = selected
        .map(Path::to_path_buf)
        .or_else(|| discovered.filter(|p| p.is_file()));
    cfg.load(selected.as_deref())?;
    Ok(cfg)
}

fn endpoint_policy(
    config: &Configuration,
    section: &[u8],
) -> Result<EndpointPolicy, Box<dyn Error>> {
    let configured_match = |key: &[u8]| {
        config
            .get(section, key)
            .map_or(Ok(false), |_| config.get_yesno(section, key))
    };
    Ok(EndpointPolicy {
        options: service_options(config, section, ShutdownMode::Immediate)?,
        unix: UnixAccess {
            match_uid: configured_match(b"UNIX_MATCH_UID")?,
            match_gid: configured_match(b"UNIX_MATCH_GID")?,
        },
    })
}

fn listener_access(unix: UnixAccess) -> LocalListenerAccess {
    if !unix.match_uid && unix.match_gid {
        LocalListenerAccess::Group
    } else {
        LocalListenerAccess::Owner
    }
}

fn configured_limits(
    config: &Configuration,
    mut limits: Limits,
) -> Result<Limits, gnunet_types::Error> {
    limits.pils_profile = gnunet_pils::Profile::configured(
        config.get(b"PILS", b"PROFILE"),
        config.get(b"transport-rust", b"PILS_PROFILE"),
    )?;
    limits.discovery_hello_profile = match config.get(b"transport-rust", b"HELLO_PROFILE") {
        Some(label) => gnunet_pils::Profile::from_label(label)?.hello(),
        None => limits.pils_profile.hello(),
    };
    Ok(limits)
}
/// Run the explicit verified-local-capability mode on the real system clock.
/// Standard no-IKM signing uses `foreground_service` instead.
pub async fn foreground_local(
    setup: LocalStartup<'_>,
    ready: impl AsyncFnMut(&BoundListeners, &BoundListeners, [u8; 32]) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    observe_socket: impl FnMut(SocketEvent),
    observe_pils: impl for<'a> FnMut(gnunet_pils_host::client::Progress<'a>),
) -> Result<Report, Box<dyn Error>> {
    foreground_local_with_clock(
        setup,
        ready,
        shutdown,
        observe_socket,
        observe_pils,
        Arc::new(SystemClock),
    )
    .await
}
/// Run standard asynchronous PILS signing on the actual system clock. Only a
/// current verified service announcement activates the transport identity.
pub async fn foreground_service(
    setup: ServiceStartup<'_>,
    ready: impl AsyncFnMut(&BoundListeners, &BoundListeners, [u8; 32]) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    observe_socket: impl FnMut(SocketEvent),
    observe_pils: impl for<'a> FnMut(gnunet_pils_host::client::Progress<'a>),
) -> Result<Report, Box<dyn Error>> {
    foreground_service_with_clock(
        setup,
        ready,
        shutdown,
        observe_socket,
        observe_pils,
        Arc::new(SystemClock),
    )
    .await
}
/// Join the explicit process clock with the asynchronous identity-service mode.
pub async fn foreground_service_with_clock(
    setup: ServiceStartup<'_>,
    ready: impl AsyncFnMut(&BoundListeners, &BoundListeners, [u8; 32]) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    observe_socket: impl FnMut(SocketEvent),
    observe_pils: impl for<'a> FnMut(gnunet_pils_host::client::Progress<'a>),
    clock: Arc<dyn RuntimeClock>,
) -> Result<Report, Box<dyn Error>> {
    foreground_service_with_lifecycle(
        setup,
        ready,
        ForegroundLifecycle::desktop(shutdown)?,
        observe_socket,
        observe_pils,
        diagnose_runtime,
        clock,
    )
    .await
    .map(ForegroundExit::report)
}

/// Drive the standard signing profile under the host's lifecycle and clock.
/// Polls stop before opening startup resources and before each listener wait or
/// readiness poll. A synchronous storage operation already in progress must
/// return before stop can be observed. The supplied budget governs the original
/// canonical drain deadline and the independent native monotonic limit.
/// The caller receives runtime notices through its own diagnostic observer.
/// Pending publication permission leaves communicator address operations active.
pub async fn foreground_service_with_lifecycle(
    setup: ServiceStartup<'_>,
    ready: impl AsyncFnMut(&BoundListeners, &BoundListeners, [u8; 32]) -> io::Result<()>,
    lifecycle: ForegroundLifecycle<impl Future<Output = io::Result<()>>, impl Future<Output = ()>>,
    observe_socket: impl FnMut(SocketEvent),
    observe_pils: impl for<'a> FnMut(gnunet_pils_host::client::Progress<'a>),
    observe_diagnostic: impl FnMut(Diagnostic),
    clock: Arc<dyn RuntimeClock>,
) -> Result<ForegroundExit, Box<dyn Error>> {
    foreground_with_clock(
        setup,
        None,
        ready,
        lifecycle,
        Observers {
            socket: observe_socket,
            pils: observe_pils,
            runtime: observe_diagnostic,
        },
        clock,
    )
    .await
}
/// Join an explicit canonical clock for actual lifecycle/offset/refusal tests or
/// a larger caller-driven node. All endpoint/broker/runtime ports share it.
pub async fn foreground_local_with_clock(
    setup: LocalStartup<'_>,
    ready: impl AsyncFnMut(&BoundListeners, &BoundListeners, [u8; 32]) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    observe_socket: impl FnMut(SocketEvent),
    observe_pils: impl for<'a> FnMut(gnunet_pils_host::client::Progress<'a>),
    clock: Arc<dyn RuntimeClock>,
) -> Result<Report, Box<dyn Error>> {
    let LocalStartup {
        config,
        activation,
        state_directory,
        included_hellos,
        local_key,
        limits,
    } = setup;
    foreground_with_clock(
        ServiceStartup {
            config,
            activation,
            state_directory,
            included_hellos,
            limits,
        },
        Some(local_key),
        ready,
        ForegroundLifecycle::desktop(shutdown)?,
        Observers {
            socket: observe_socket,
            pils: observe_pils,
            runtime: diagnose_runtime,
        },
        clock,
    )
    .await
    .map(ForegroundExit::report)
}
async fn foreground_with_clock(
    setup: ServiceStartup<'_>,
    local_key: Option<LocalKeyCapability>,
    mut ready: impl AsyncFnMut(&BoundListeners, &BoundListeners, [u8; 32]) -> io::Result<()>,
    lifecycle: ForegroundLifecycle<impl Future<Output = io::Result<()>>, impl Future<Output = ()>>,
    mut observers: Observers<
        impl FnMut(SocketEvent),
        impl for<'a> FnMut(gnunet_pils_host::client::Progress<'a>),
        impl FnMut(Diagnostic),
    >,
    clock: Arc<dyn RuntimeClock>,
) -> Result<ForegroundExit, Box<dyn Error>> {
    let ForegroundLifecycle {
        stop,
        drain_budget_micros,
        publication_start,
    } = lifecycle;
    let mut shutdown = std::pin::pin!(stop);
    if until_stop(std::future::ready(()), shutdown.as_mut())
        .await?
        .is_none()
    {
        return Ok(ForegroundExit::BeforeReady(Report::default()));
    }
    let ServiceStartup {
        config,
        activation,
        state_directory,
        included_hellos,
        limits,
    } = setup;
    let limits = configured_limits(config, limits)?;
    for section in [b"transport".as_slice(), b"peerstore"] {
        #[cfg(unix)]
        if config.get(section, b"USERNAME").is_some() {
            return Err("shared foreground does not switch configured USERNAME".into());
        }
        #[cfg(windows)]
        gnunet_service_startup::verify_configured_identity(config, section)?;
    }
    let policies = Policies {
        transport: endpoint_policy(config, b"transport")?,
        peerstore: endpoint_policy(config, b"peerstore")?,
    };
    if until_stop(std::future::ready(()), shutdown.as_mut())
        .await?
        .is_none()
    {
        return Ok(ForegroundExit::BeforeReady(Report::default()));
    }
    let journal_path = state_directory.join("peerstore.rust-journal");
    gnunet_service_runtime::private_parents(&journal_path)?;
    let mut journal = Journal::open_with_profiles(
        &journal_path,
        gnunet_transport_host::peerstore::HelloProfiles {
            managed: limits.pils_profile.hello(),
            discovery: limits.discovery_hello_profile,
        },
    )?;
    journal.import_hellos(
        included_hellos.as_ref(),
        clock.sample()?.now,
        |path, reason| {
            (observers.runtime)(Diagnostic::IncludedHelloSkipped {
                path: path.to_path_buf(),
                reason,
            });
        },
    )?;
    let bind_transport = async {
        if activation.is_empty() {
            return BoundListeners::bind_configured(
                config,
                b"transport",
                listener_access(policies.transport.unix),
            )
            .await;
        }
        #[cfg(unix)]
        {
            BoundListeners::bind(config, b"transport", activation).await
        }
        #[cfg(windows)]
        {
            Ok(BoundListeners::from_activation_with_access(
                activation,
                policies.transport.unix,
            )?)
        }
    };
    let Some(transport_bound) = until_stop(bind_transport, shutdown.as_mut()).await? else {
        return Ok(ForegroundExit::BeforeReady(Report::default()));
    };
    let transport_bound = transport_bound?;
    let bind_peerstore = BoundListeners::bind_configured(
        config,
        b"peerstore",
        listener_access(policies.peerstore.unix),
    );
    let Some(peerstore_bound) = until_stop(bind_peerstore, shutdown.as_mut()).await? else {
        return Ok(ForegroundExit::BeforeReady(Report::default()));
    };
    let peerstore_bound = peerstore_bound?;
    let native = gnunet_resolver_broker::native_profile()?;
    let family = FamilyProfile::new(
        native.encode(gnunet_resolver_broker::Family::V4),
        native.encode(gnunet_resolver_broker::Family::V6),
    )?;
    let live = LiveConfiguration::new(config.duplicate()?);
    let (context, mut resolver) =
        broker::<128, 256>(live.clone(), Default::default(), family, clock.clone())?;
    let source = EndpointSource::live(live, b"pils", context.resolution_context());
    let mut instance = gnunet_pils::client::Instance::new();
    let mut runtime = if let Some(capability) = local_key {
        Runtime::new_local(
            &mut instance,
            LocalPorts {
                pils: source,
                capability,
                clock,
                journal,
            },
            limits,
            policies,
        )?
    } else {
        Runtime::new_service(
            &mut instance,
            ServicePorts {
                pils: source,
                clock,
                journal,
            },
            limits,
            policies,
        )?
    };
    let mut starting_publication = std::pin::pin!(match publication_start {
        PublicationStart::Immediate => None,
        PublicationStart::After(start) => {
            runtime.hold_address_publication();
            Some(start)
        }
    });
    let transport_listeners = transport_bound.listeners();
    let peerstore_listeners = peerstore_bound.listeners();
    let mut drain_alarm = std::pin::pin!(None::<Sleep>);
    let mut was_ready = false;
    let outcome: Result<(), Box<dyn Error>> = loop {
        let selected = {
            let mut resolving = std::pin::pin!(resolver.drive_waiting(None, |_| {}));
            poll_fn(|cx| {
                let complete = runtime.drain_completed();
                let deadline = if let Some(mut alarm) = drain_alarm.as_mut().as_pin_mut() {
                    let deadline = alarm.deadline();
                    if !complete
                        && (Instant::now() >= deadline || alarm.as_mut().poll(cx).is_ready())
                    {
                        return Poll::Ready(Err(drain_timeout().into()));
                    }
                    Some(deadline)
                } else if let Poll::Ready(result) = shutdown.as_mut().poll(cx) {
                    return Poll::Ready(
                        result
                            .map(|()| None)
                            .map_err(|e| Box::new(e) as Box<dyn Error>),
                    );
                } else {
                    None
                };
                if deadline.is_none()
                    && let Some(start) = starting_publication.as_mut().as_pin_mut()
                    && start.poll(cx).is_ready()
                {
                    starting_publication.set(None);
                    runtime.start_address_publication();
                }
                // One bounded process-Resolver poll cannot starve or be starved
                // by continuously ready service work/notifications.
                let resolver_progress =
                    if !complete && let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                        match result {
                            Ok(_) => true,
                            Err(e) => return Poll::Ready(Err(Box::new(e) as Box<dyn Error>)),
                        }
                    } else {
                        false
                    };
                if !complete && deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    return Poll::Ready(Err(drain_timeout().into()));
                }
                match runtime.poll_drive(
                    cx,
                    &transport_listeners,
                    &peerstore_listeners,
                    &mut observers.socket,
                ) {
                    Poll::Ready(result) => {
                        Poll::Ready(result.map(Some).map_err(|e| Box::new(e) as Box<dyn Error>))
                    }
                    // Rebuild the completed Resolver future after polling the
                    // service once. Returning Pending here would poll that
                    // completed async future again on the next wake.
                    Poll::Pending if resolver_progress => Poll::Ready(Ok(Some(Progress::Activity))),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await
        };
        let selected = match selected {
            Ok(Some(Progress::Activated(peer))) if drain_alarm.is_none() && !was_ready => {
                let notify = async { ready(&transport_bound, &peerstore_bound, peer).await };
                match until_stop(notify, shutdown.as_mut()).await {
                    Ok(Some(Ok(()))) => {
                        was_ready = true;
                        continue;
                    }
                    Ok(None) => Ok(None),
                    Ok(Some(Err(error))) | Err(error) => Err(error.into()),
                }
            }
            other => other,
        };
        match selected {
            Ok(None) => {
                // The completed shutdown future is never polled again. Keep the
                // same physical PILS owner until the final empty local write or
                // original deadline. Clock changes cannot renew this alarm.
                let Some(deadline) =
                    Instant::now().checked_add(Duration::from_micros(drain_budget_micros.get()))
                else {
                    break Err(crate::Error::from(gnunet_types::Error::Overflow).into());
                };
                if let Err(error) = runtime.begin_shutdown(drain_budget_micros) {
                    break Err(error.into());
                }
                drain_alarm.set(Some(sleep_until(deadline)));
            }
            Ok(Some(Progress::Drained { .. } | Progress::Closed)) => break Ok(()),
            Ok(Some(Progress::Pils(original))) => (observers.pils)(original),
            Ok(Some(Progress::OwnPublicationNotice(original))) => {
                (observers.runtime)(Diagnostic::OwnPublication(original));
            }
            Ok(Some(Progress::AddressRejected(original))) => {
                (observers.runtime)(Diagnostic::AddressRejected(original));
            }
            Ok(Some(_)) => {}
            Err(error) => break Err(error),
        }
    };
    let closed = runtime.close();
    while let Some(original) = runtime.take_pils_notice() {
        (observers.pils)(original);
    }
    while let Some(original) = runtime.take_own_notice() {
        (observers.runtime)(Diagnostic::OwnPublication(original));
    }
    let report = runtime.report();
    match (outcome, closed) {
        (Ok(()), Ok(())) => {}
        (Err(original), Ok(())) => return Err(original),
        (Ok(()), Err(cleanup)) => return Err(cleanup.into()),
        (Err(original), Err(cleanup)) => {
            return Err(Box::new(ForegroundFailure { original, cleanup }));
        }
    }
    Ok(if was_ready {
        ForegroundExit::AfterReady(report)
    } else {
        ForegroundExit::BeforeReady(report)
    })
}

fn drain_timeout() -> crate::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "original PILS publication drain deadline",
    )
    .into()
}

// Poll stop before work, including the first poll. One original stop request is
// retained across all waits. None means that stop completed successfully.
async fn until_stop<T>(
    work: impl Future<Output = T>,
    mut shutdown: Pin<&mut impl Future<Output = io::Result<()>>>,
) -> io::Result<Option<T>> {
    let mut work = std::pin::pin!(work);
    poll_fn(|cx| {
        if let Poll::Ready(result) = shutdown.as_mut().poll(cx) {
            return Poll::Ready(result.map(|()| None));
        }
        work.as_mut().poll(cx).map(|result| Ok(Some(result)))
    })
    .await
}

fn diagnose_runtime(event: Diagnostic) {
    match event {
        Diagnostic::OwnPublication(error) => diagnose_own(error),
        Diagnostic::AddressRejected(original) => diagnose_address(&original),
        Diagnostic::IncludedHelloSkipped { path, reason } => {
            use std::io::Write;
            let _diagnostic = writeln!(
                io::stderr().lock(),
                "PEERSTORE included HELLO skipped {path:?}: {reason:?}"
            );
        }
    }
}

/// Report an actual own-publication cause after the original state outcome was
/// consumed. This observation never instructs replay of an old signing or STORE.
pub fn diagnose_own(error: crate::Error) {
    use std::io::Write;
    let _written = writeln!(
        std::io::stderr().lock(),
        "TRANSPORT own-publication observation: {error}"
    );
}

/// Emit only actual public loss/configuration diagnostics; secret completions
/// deliberately have no Debug output and are never formatted.
pub fn diagnose_pils(event: gnunet_pils_host::client::Progress<'_>) {
    use std::io::Write;
    match event {
        gnunet_pils_host::client::Progress::Lost { cause, .. } => {
            let _diagnostic = writeln!(io::stderr().lock(), "PILS original MQ lost: {cause:?}");
        }
        gnunet_pils_host::client::Progress::ConnectRetry { error, .. } => {
            let _diagnostic = writeln!(io::stderr().lock(), "PILS native attempt: {error}");
        }
        gnunet_pils_host::client::Progress::Unavailable(error) => {
            let _diagnostic = writeln!(io::stderr().lock(), "PILS endpoint: {error}");
        }
        _ => {}
    }
}

/// Report only original local metadata; this is not an official wire ACK.
pub fn diagnose_address(original: &gnunet_transport::addresses::AddressRejection) {
    use std::io::Write;
    let _diagnostic = writeln!(
        io::stderr().lock(),
        "TRANSPORT local address rejected: owner={:?} id={} reason={:?}",
        original.client,
        original.address_id,
        original.reason
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transport_and_peerstore_keep_independent_credential_policies() -> Result<(), Box<dyn Error>>
    {
        let mut config = Configuration::default();
        config.set_value(b"transport", b"UNIX_MATCH_UID", Some(b"YES"))?;
        config.set_value(b"transport", b"UNIX_MATCH_GID", Some(b"YES"))?;
        config.set_value(b"peerstore", b"UNIX_MATCH_GID", Some(b"YES"))?;
        let transport = endpoint_policy(&config, b"transport")?.unix;
        let peerstore = endpoint_policy(&config, b"peerstore")?.unix;
        if !transport.match_uid
            || !transport.match_gid
            || listener_access(transport) != LocalListenerAccess::Owner
            || peerstore.match_uid
            || !peerstore.match_gid
            || listener_access(peerstore) != LocalListenerAccess::Group
            || listener_access(UnixAccess::default()) != LocalListenerAccess::Owner
        {
            return Err("shared listener policy lost its service settings".into());
        }
        config.set_value(b"peerstore", b"UNIX_MATCH_UID", Some(b"invalid"))?;
        if endpoint_policy(&config, b"peerstore").is_ok() {
            return Err("invalid local credential configuration was accepted".into());
        }
        Ok(())
    }
    #[test]
    fn original_shutdown_cancels_a_pending_readiness_wait() {
        use std::{cell::Cell, task::Waker};
        let stop = Cell::new(false);
        let stop_completed = Cell::new(false);
        let ready_polls = Cell::new(0);
        let mut shutdown = std::pin::pin!(poll_fn(|_| {
            assert!(
                !stop_completed.get(),
                "completed shutdown future was polled again"
            );
            if stop.get() {
                stop_completed.set(true);
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }));
        let ready = poll_fn(|_| {
            ready_polls.set(ready_polls.get() + 1);
            Poll::<io::Result<()>>::Pending
        });
        let mut waiting = std::pin::pin!(until_stop(ready, shutdown.as_mut()));
        let mut cx = std::task::Context::from_waker(Waker::noop());
        assert!(waiting.as_mut().poll(&mut cx).is_pending());
        assert_eq!(ready_polls.get(), 1);
        stop.set(true);
        assert!(matches!(
            waiting.as_mut().poll(&mut cx),
            Poll::Ready(Ok(None))
        ));
        assert_eq!(
            ready_polls.get(),
            1,
            "readiness advanced after the original stop"
        );
        assert!(stop_completed.get());
    }
    #[test]
    fn foreground_stop_precedes_startup_and_readiness() -> Result<(), Box<dyn Error>> {
        let mut config = Configuration::default();
        config.set_value(b"PILS", b"PROFILE", Some(b"invalid-stop-fixture-profile"))?;
        let ready_called = std::cell::Cell::new(false);
        let publication_polled = std::cell::Cell::new(false);
        let mut foreground = std::pin::pin!(foreground_service_with_lifecycle(
            ServiceStartup {
                config: &config,
                activation: Activation::default(),
                state_directory: std::env::current_exe()?,
                included_hellos: None,
                limits: Limits::default(),
            },
            async |_, _, _| {
                ready_called.set(true);
                Ok(())
            },
            ForegroundLifecycle {
                stop: std::future::ready(Ok(())),
                drain_budget_micros: NonZeroU64::MIN,
                publication_start: PublicationStart::After(poll_fn(|_| {
                    publication_polled.set(true);
                    Poll::Pending
                })),
            },
            |_| {},
            |_| {},
            |_| {},
            Arc::new(SystemClock),
        ));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        let outcome = foreground.as_mut().poll(&mut cx);
        if ready_called.get()
            || publication_polled.get()
            || !matches!(outcome, Poll::Ready(Ok(ForegroundExit::BeforeReady(report))) if report.activations == 0)
        {
            return Err(format!("stop did not preempt startup and readiness: {outcome:?}").into());
        }
        Ok(())
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions check the actual foreground configuration selection before native admission"
    )]
    fn profile_selection_keeps_remote_discovery_independent_and_rejects_identity_conflicts()
    -> Result<(), Box<dyn Error>> {
        let mut config = Configuration::default();
        config.set_value(b"PILS", b"PROFILE", Some(b"deterministic"))?;
        let limits = configured_limits(&config, Limits::default())?;
        assert_eq!(
            limits.pils_profile,
            gnunet_pils::Profile::ReferenceDeterministic
        );
        assert_eq!(limits.discovery_hello_profile, limits.pils_profile.hello());
        config.set_value(b"transport-rust", b"HELLO_PROFILE", Some(b"reference029"))?;
        let limits = configured_limits(&config, Limits::default())?;
        assert_eq!(
            limits.pils_profile,
            gnunet_pils::Profile::ReferenceDeterministic
        );
        assert_eq!(
            limits.discovery_hello_profile,
            gnunet_hello::SignatureProfile::Gnunet029
        );
        config.set_value(b"transport-rust", b"PILS_PROFILE", Some(b"reference029"))?;
        assert!(matches!(
            configured_limits(&config, Limits::default()),
            Err(gnunet_types::Error::Conflict)
        ));
        config.set_value(
            b"transport-rust",
            b"PILS_PROFILE",
            Some(b"reference-deterministic"),
        )?;
        assert_eq!(
            configured_limits(&config, Limits::default())?.pils_profile,
            gnunet_pils::Profile::ReferenceDeterministic
        );
        config.set_value(b"PILS", b"PROFILE", Some(b"unknown"))?;
        assert!(matches!(
            configured_limits(&config, Limits::default()),
            Err(gnunet_types::Error::InvalidInput)
        ));
        Ok(())
    }
}
