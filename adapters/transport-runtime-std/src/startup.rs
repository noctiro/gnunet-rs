//! Official configuration/activation and explicit Rust transport+peerstore entry.
use crate::{
    Limits, LocalKeyCapability, LocalPorts, Policies, Progress, Report, Runtime, ServicePorts,
};
use gnunet_client_host::EndpointSource;
/// Shared process environment used for official filename expansion.
pub use gnunet_config::ProcessEnvironment;
use gnunet_config::{Configuration, ProjectData};
use gnunet_resolver_broker::{FamilyProfile, LiveConfiguration, broker};
use gnunet_service_runtime::{
    Activation, BoundListeners,
    accepted::SocketEvent,
    clock::{RuntimeClock, SystemClock},
    service::ShutdownMode,
    service_options,
};
use gnunet_transport_host::peerstore::Journal;
use std::{
    error::Error,
    future::{Future, poll_fn},
    io,
    path::{Path, PathBuf},
    sync::Arc,
    task::Poll,
};

/// One explicit foreground resource choice. Only TRANSPORT inherits activation;
/// companion PEERSTORE binds its configured public endpoints independently.
pub struct LocalStartup<'a> {
    /// Official configuration snapshot; no hidden reload or DNS task is created.
    pub config: &'a Configuration,
    /// Original caller-transferred TRANSPORT listening sockets.
    pub activation: Activation,
    /// Explicit new-format Rust backend directory, never a C sqlite filename.
    pub state_directory: PathBuf,
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
    /// Finite caller-driven resource policy.
    pub limits: Limits,
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
    ready: impl FnMut(&BoundListeners, &BoundListeners, [u8; 32]) -> io::Result<()>,
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
    ready: impl FnMut(&BoundListeners, &BoundListeners, [u8; 32]) -> io::Result<()>,
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
    ready: impl FnMut(&BoundListeners, &BoundListeners, [u8; 32]) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    observe_socket: impl FnMut(SocketEvent),
    observe_pils: impl for<'a> FnMut(gnunet_pils_host::client::Progress<'a>),
    clock: Arc<dyn RuntimeClock>,
) -> Result<Report, Box<dyn Error>> {
    foreground_with_clock(
        setup,
        None,
        ready,
        shutdown,
        observe_socket,
        observe_pils,
        clock,
    )
    .await
}
/// Join an explicit canonical clock for actual lifecycle/offset/refusal tests or
/// a larger caller-driven node. All endpoint/broker/runtime ports share it.
pub async fn foreground_local_with_clock(
    setup: LocalStartup<'_>,
    ready: impl FnMut(&BoundListeners, &BoundListeners, [u8; 32]) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    observe_socket: impl FnMut(SocketEvent),
    observe_pils: impl for<'a> FnMut(gnunet_pils_host::client::Progress<'a>),
    clock: Arc<dyn RuntimeClock>,
) -> Result<Report, Box<dyn Error>> {
    let LocalStartup {
        config,
        activation,
        state_directory,
        local_key,
        limits,
    } = setup;
    foreground_with_clock(
        ServiceStartup {
            config,
            activation,
            state_directory,
            limits,
        },
        Some(local_key),
        ready,
        shutdown,
        observe_socket,
        observe_pils,
        clock,
    )
    .await
}
async fn foreground_with_clock(
    setup: ServiceStartup<'_>,
    local_key: Option<LocalKeyCapability>,
    mut ready: impl FnMut(&BoundListeners, &BoundListeners, [u8; 32]) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    mut observe_socket: impl FnMut(SocketEvent),
    mut observe_pils: impl for<'a> FnMut(gnunet_pils_host::client::Progress<'a>),
    clock: Arc<dyn RuntimeClock>,
) -> Result<Report, Box<dyn Error>> {
    let ServiceStartup {
        config,
        activation,
        state_directory,
        limits,
    } = setup;
    let limits = configured_limits(config, limits)?;
    for section in [b"transport".as_slice(), b"peerstore"] {
        if config.get(section, b"USERNAME").is_some() {
            return Err("shared foreground does not switch configured USERNAME".into());
        }
        for field in [b"UNIX_MATCH_UID".as_slice(), b"UNIX_MATCH_GID"] {
            if config.get(section, field).is_some() && config.get_yesno(section, field)? {
                return Err("shared listeners do not implement Unix credential matching".into());
            }
        }
    }
    let journal_path = state_directory.join("peerstore.rust-journal");
    gnunet_service_runtime::private_parents(&journal_path)?;
    let journal = Journal::open_with_profiles(
        &journal_path,
        gnunet_transport_host::peerstore::HelloProfiles {
            managed: limits.pils_profile.hello(),
            discovery: limits.discovery_hello_profile,
        },
    )?;
    let transport_bound = BoundListeners::bind(config, b"transport", activation).await?;
    let peerstore_bound = BoundListeners::bind(config, b"peerstore", Activation::default()).await?;
    let policies = Policies {
        transport: service_options(config, b"transport", ShutdownMode::Immediate)?,
        peerstore: service_options(config, b"peerstore", ShutdownMode::Immediate)?,
    };
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
    let transport_listeners = transport_bound.listeners();
    let peerstore_listeners = peerstore_bound.listeners();
    let mut shutdown = std::pin::pin!(shutdown);
    let mut stopping = false;
    let outcome: Result<(), Box<dyn Error>> = loop {
        let selected = {
            let mut driving = std::pin::pin!(runtime.drive(
                &transport_listeners,
                &peerstore_listeners,
                &mut observe_socket
            ));
            let mut resolving = std::pin::pin!(resolver.drive_waiting(None, |_| {}));
            poll_fn(|cx| {
                if !stopping && let Poll::Ready(result) = shutdown.as_mut().poll(cx) {
                    return Poll::Ready(
                        result
                            .map(|()| None)
                            .map_err(|e| Box::new(e) as Box<dyn Error>),
                    );
                }
                // One bounded process-Resolver poll cannot starve or be starved
                // by continuously ready service work/notifications.
                let resolver_progress = if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                    match result {
                        Ok(_) => true,
                        Err(e) => return Poll::Ready(Err(Box::new(e) as Box<dyn Error>)),
                    }
                } else {
                    false
                };
                match driving.as_mut().poll(cx) {
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
        match selected {
            Ok(None) => {
                // The completed shutdown future is never polled again. Keep the
                // same physical PILS owner until the final empty local write.
                let budget = std::num::NonZeroU64::new(30_000_000).ok_or("shutdown budget")?;
                if let Err(error) = runtime.begin_shutdown(budget) {
                    break Err(error.into());
                }
                stopping = true;
            }
            Ok(Some(Progress::Drained { .. } | Progress::Closed)) => break Ok(()),
            Ok(Some(Progress::Activated(peer))) => {
                if let Err(error) = ready(&transport_bound, &peerstore_bound, peer) {
                    break Err(error.into());
                }
            }
            Ok(Some(Progress::Pils(original))) => observe_pils(original),
            Ok(Some(Progress::OwnPublicationNotice(original))) => diagnose_own(original),
            Ok(Some(Progress::AddressRejected(original))) => diagnose_address(&original),
            Ok(Some(_)) => {}
            Err(error) => break Err(error),
        }
    };
    let closed = runtime.close();
    while let Some(original) = runtime.take_pils_notice() {
        observe_pils(original);
    }
    while let Some(original) = runtime.take_own_notice() {
        diagnose_own(original);
    }
    let report = runtime.report();
    outcome?;
    closed?;
    Ok(report)
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
