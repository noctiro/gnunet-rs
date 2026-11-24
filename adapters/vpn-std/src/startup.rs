//! Shared configuration, fixed pools and foreground composition for VPN.
use crate::{
    coordinator::{
        self, Coordinator, Device, DiscoveryMode, Parts, Progress,
        provider::{CloseOutcome, Provider},
    },
    discovery, server,
};
use gnunet_cadet_host as cadet;
use gnunet_config::Configuration;
use gnunet_service_runtime::{
    BoundListeners, LocalListenerAccess, clock::RuntimeClock, local::qualify_private_endpoints,
};
use gnunet_vpn::{self as core, RouteState};
use std::{
    error::Error as StdError,
    fmt,
    future::{Future, poll_fn},
    io,
    path::PathBuf,
    pin::{Pin, pin},
    sync::Arc,
    task::{Context, Poll},
};
use tokio::time::{Instant, timeout_at};

mod configuration;
pub use configuration::ServiceSettings;
mod pools;
pub use pools::{Pools, Slots};
#[cfg(all(test, unix))]
mod tests;

/// Immutable validated application VPN policy. Automatic REGEX discovery is the
/// default, shared with the standalone service. Device resources remain separate.
pub struct ApplicationSettings {
    service: ServiceSettings,
}

impl ApplicationSettings {
    /// Parse the official VPN and bounded local configuration once, without
    /// opening a local endpoint or touching the application provider.
    pub fn read(config: &Configuration) -> Result<Self, Error> {
        Ok(Self {
            service: ServiceSettings::read(config, DiscoveryMode::External).map_err(Error::with)?,
        })
    }

    /// Whether this immutable policy needs the node's local REGEX service.
    #[must_use]
    pub fn uses_regex(&self) -> bool {
        self.service.regex.is_some()
    }
}

/// Exact discovery dependency selected by the prepared application policy.
pub enum DiscoveryEndpoint {
    /// Original literal REGEX endpoint in the same private directory.
    Regex(PathBuf),
    /// Explicit `[vpn-rust] EXIT_DISCOVERY=configured` opt-out.
    Configured,
}

/// Distinct local services in one caller-owned private directory.
pub struct LocalEndpoints {
    /// Distinct literal VPN endpoint to bind in the node's private directory.
    pub vpn: PathBuf,
    /// The node's private outbound CADET client endpoint in the same directory.
    pub cadet: PathBuf,
    /// Actual discovery dependency, matching the prepared policy.
    pub discovery: DiscoveryEndpoint,
}

/// Prepared local IPC and the actual OS packet and settings owner for one run.
pub struct EmbeddedSettings {
    /// Configuration parsed once before the enclosing node chooses dependencies.
    pub settings: ApplicationSettings,
    /// Explicit original local service endpoints.
    pub endpoints: LocalEndpoints,
    /// The node's original canonical clock.
    pub clock: Arc<dyn RuntimeClock>,
    /// Original application packet and route owner, consumed for this run.
    pub provider: Box<dyn Provider + Send>,
}

/// Original failures and independent cleanup results for an embedded run.
#[derive(Debug, Default)]
pub struct Error {
    /// Original construction, control and drive failures in observation order.
    pub failures: Vec<Box<dyn StdError>>,
    /// Independent coordinator cleanup errors, when present.
    pub cleanup: Option<Box<coordinator::CleanupErrors>>,
    /// An unadopted provider closed without proving its settings absent.
    pub provider_routes_unconfirmed: bool,
    /// Local listener path cleanup errors, retained in visitation order.
    pub listener_close: Vec<io::Error>,
    /// Original route, work or physical control debt remaining after shutdown.
    pub unresolved: Option<coordinator::Debt>,
}

impl Error {
    fn with(error: impl Into<Box<dyn StdError>>) -> Self {
        Self {
            failures: vec![error.into()],
            ..Self::default()
        }
    }

    fn record_early_provider_close(&mut self, closed: CloseOutcome) {
        // Startup admitted no route command. Keep the provider's observation
        // separate from unresolved coordinator route effects.
        self.provider_routes_unconfirmed |= !closed.routes_absent;
        if let Some(error) = closed.error {
            self.cleanup.get_or_insert_with(Box::default).provider = Some(error);
        }
    }

    fn finish_early_provider_close(
        result: Result<coordinator::Report, Self>,
        closed: Option<CloseOutcome>,
    ) -> Result<coordinator::Report, Self> {
        let Some(closed) = closed.filter(|closed| !closed.routes_absent || closed.error.is_some())
        else {
            return result;
        };
        let mut failure = result.err().unwrap_or_default();
        failure.record_early_provider_close(closed);
        Err(failure)
    }

    fn finish(self, report: coordinator::Report) -> Result<coordinator::Report, Self> {
        if self.failures.is_empty()
            && self.cleanup.is_none()
            && !self.provider_routes_unconfirmed
            && self.listener_close.is_empty()
            && self.unresolved.is_none()
        {
            Ok(report)
        } else {
            Err(self)
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "embedded VPN failed")?;
        for error in &self.failures {
            write!(f, ". {error}")?;
        }
        if let Some(cleanup) = &self.cleanup {
            write!(f, ". {cleanup}")?;
        }
        if self.provider_routes_unconfirmed {
            write!(f, ". VPN provider close did not confirm route absence")?;
        }
        for error in &self.listener_close {
            write!(f, ". VPN endpoint cleanup failed with {error}")?;
        }
        if let Some(debt) = &self.unresolved {
            write!(f, ". VPN shutdown left {debt:?}")?;
        }
        Ok(())
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.failures
            .first()
            .map(Box::as_ref)
            .or_else(|| self.cleanup.as_deref().map(|error| error as &dyn StdError))
            .or_else(|| {
                self.listener_close
                    .first()
                    .map(|error| error as &dyn StdError)
            })
    }
}

#[test]
fn early_close_preserves_unproved_provider_routes_without_inventing_route_debt()
-> Result<(), Box<dyn StdError>> {
    let no_native_error = CloseOutcome {
        routes_absent: false,
        error: None,
    };
    let failure = Error::finish_early_provider_close(
        Ok(coordinator::Report::default()),
        Some(no_native_error),
    )
    .err()
    .ok_or("an unconfirmed provider close was reported as successful")?;
    if !failure.provider_routes_unconfirmed
        || failure.cleanup.is_some()
        || failure.unresolved.is_some()
    {
        return Err(
            "provider close evidence was conflated with a native error or route debt".into(),
        );
    }
    Ok(())
}

// Until the coordinator adopts the original provider, startup owns its cleanup.
// This also covers cancellation while a private listener is being prepared.
struct Unadopted(Option<Box<dyn Provider>>);

impl Unadopted {
    fn take_device(&mut self) -> Result<Device, io::Error> {
        let provider = self
            .0
            .take()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
        Device::from_boxed_provider(provider).map_err(|(error, provider)| {
            self.0 = Some(provider);
            error
        })
    }

    fn close(&mut self) -> Option<CloseOutcome> {
        self.0.take().map(|mut provider| provider.close())
    }
}

impl Drop for Unadopted {
    fn drop(&mut self) {
        let _closed = self.close();
    }
}

fn startup_timeout() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "VPN startup waited for private IPC, routes and CADET",
    )
}

struct Lifecycle<S, R> {
    stop: Option<S>,
    on_ready: Option<R>,
    deadline: Instant,
}

impl<S: Future<Output = io::Result<()>>, R> Lifecycle<Pin<&mut S>, R> {
    fn poll_stop(&mut self, cx: &mut Context<'_>) -> Option<io::Result<()>> {
        let Poll::Ready(reason) = self.stop.as_mut()?.as_mut().poll(cx) else {
            return None;
        };
        self.stop = None;
        self.on_ready = None;
        Some(reason)
    }
}

struct Sources {
    cadet: PathBuf,
    regex: Option<(PathBuf, discovery::Limits)>,
}

// Drop closes native searches and retires their original VPN obligations before
// the coordinator retires its packet, route and CADET resources.
struct Owners<'id, 'store, 'bytes, 'cadet, 'cstore, 'policy, 'regex> {
    discovery: Option<discovery::Provider<'id, 'regex>>,
    discovery_stopping: bool,
    discovery_failed: bool,
    vpn: Coordinator<'id, 'store, 'bytes, 'cadet, 'cstore, 'policy>,
}

impl Owners<'_, '_, '_, '_, '_, '_, '_> {
    fn stop_discovery(&mut self) -> Result<(), discovery::Error> {
        if self.discovery_stopping {
            return Ok(());
        }
        self.discovery_stopping = true;
        self.close_discovery()
    }
    fn close_discovery(&mut self) -> Result<(), discovery::Error> {
        if let Some(provider) = &mut self.discovery {
            provider.close_all(&mut self.vpn, &mut |_| {})?;
        }
        Ok(())
    }
}

impl Drop for Owners<'_, '_, '_, '_, '_, '_, '_> {
    fn drop(&mut self) {
        if let Some(mut provider) = self.discovery.take() {
            let _closed = provider.close_all(&mut self.vpn, &mut |_| {});
            // Native Search owners drop even if logical retirement was refused.
            drop(provider);
        }
        self.vpn.close(&mut |_| {});
    }
}

/// Run the official local VPN service on the caller's I/O-enabled runtime.
/// Readiness requires accepted routing settings and a live local CADET source.
/// Named services use their expected peers. Internet exits use the prepared
/// REGEX or configured policy. After signaling `stop`, keep driving through cleanup.
///
/// # Errors
/// Returns original failures and independent endpoint, provider and route cleanup facts.
pub async fn serve_embedded(
    settings: EmbeddedSettings,
    stop: impl Future<Output = io::Result<()>>,
    on_ready: impl FnOnce() -> io::Result<()>,
) -> Result<coordinator::Report, Error> {
    let EmbeddedSettings {
        settings,
        endpoints,
        clock,
        provider,
    } = settings;
    let mut source = Unadopted(Some(provider));
    let mut stop = pin!(stop);
    let result = async {
        let ApplicationSettings { service: settings } = settings;
        let LocalEndpoints {
            vpn,
            cadet,
            discovery,
        } = endpoints;
        let regex = match (settings.regex, discovery) {
            (Some(limits), DiscoveryEndpoint::Regex(path)) => Some((path, limits)),
            (None, DiscoveryEndpoint::Configured) => None,
            _ => {
                return Err(Error::with(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "VPN discovery endpoint does not match its prepared policy",
                )));
            }
        };
        let paths = [
            Some(vpn.as_path()),
            Some(cadet.as_path()),
            regex.as_ref().map(|(path, _)| path.as_path()),
        ];
        let _ipc = qualify_private_endpoints(paths.into_iter().flatten()).map_err(Error::with)?;
        let deadline = Instant::now()
            .checked_add(settings.startup)
            .ok_or_else(|| Error::with(startup_timeout()))?;
        let mut binding = pin!(timeout_at(
            deadline,
            BoundListeners::bind_local(vpn, LocalListenerAccess::Owner)
        ));
        let bound = poll_fn(|cx| {
            if let Poll::Ready(stopped) = stop.as_mut().poll(cx) {
                return Poll::Ready(stopped.map(|()| None).map_err(Error::with));
            }
            binding.as_mut().poll(cx).map(|bound| {
                bound
                    .map_err(|_| Error::with(startup_timeout()))?
                    .map(Some)
                    .map_err(Error::with)
            })
        })
        .await?;
        let Some(mut bound) = bound else {
            return Ok(coordinator::Report::default());
        };
        let result = drive_embedded(
            &settings,
            &bound,
            Sources { cadet, regex },
            clock,
            &mut source,
            Lifecycle {
                stop: Some(stop.as_mut()),
                on_ready: Some(on_ready),
                deadline,
            },
        )
        .await;
        match bound.close() {
            Ok(()) => result,
            Err(listener_close) => {
                let mut failure = result.err().unwrap_or_default();
                failure.listener_close = listener_close;
                Err(failure)
            }
        }
    }
    .await;
    Error::finish_early_provider_close(result, source.close())
}

async fn drive_embedded(
    settings: &ServiceSettings,
    bound: &BoundListeners,
    sources: Sources,
    clock: Arc<dyn RuntimeClock>,
    source: &mut Unadopted,
    mut lifecycle: Lifecycle<
        Pin<&mut impl Future<Output = io::Result<()>>>,
        impl FnOnce() -> io::Result<()>,
    >,
) -> Result<coordinator::Report, Error> {
    let mut pools = settings.allocate().map_err(Error::with)?;
    let mut slots = pools.slots().map_err(Error::with)?;
    let (storage, channels) = slots.split();
    let mut instance = core::Instance::new();
    let engine = core::Engine::new(&mut instance, storage, settings.core).map_err(Error::with)?;
    let server = server::Server::new(
        engine,
        clock.clone(),
        settings.native,
        settings.options.clone(),
        settings.unix,
    )
    .map_err(Error::with)?;
    let mut cadet_instance = cadet::Instance::new();
    let mut ports = [];
    let cadet = cadet::Client::new(
        &mut cadet_instance,
        cadet::EndpointSource::unix_with_clock(sources.cadet, clock.clone()),
        &mut ports,
        channels,
        settings.cadet,
    )
    .map_err(Error::with)?;
    let regex_instance = gnunet_regex_client_host::Instance::new();
    let discovery = sources
        .regex
        .map(|(path, limits)| {
            discovery::Provider::new(
                &regex_instance,
                gnunet_client_host::EndpointSource::unix_with_clock(path, clock.clone()),
                clock,
                limits,
            )
        })
        .transpose()
        .map_err(Error::with)?;
    let device = source.take_device().map_err(Error::with)?;
    let parts = Parts {
        server,
        cadet,
        device,
    };
    let vpn = match Coordinator::new(
        parts,
        &settings.exits,
        &settings.peer_profiles,
        settings.coordinator,
    ) {
        Ok(vpn) => vpn,
        Err(rejected) => {
            let mut error = Error::with(rejected.error);
            let mut parts = rejected.parts;
            let cleanup = coordinator::CleanupErrors {
                ipc: parts.server.shutdown(|_| {}).failure,
                failure: parts.cadet.close().err().map(Into::into),
                ..coordinator::CleanupErrors::default()
            };
            if !cleanup.is_empty() {
                error.cleanup = Some(Box::new(cleanup));
            }
            if let Some(closed) = parts.device.into_io().close_provider() {
                error.record_early_provider_close(closed);
            }
            return Err(error);
        }
    };
    let mut owners = Owners {
        discovery,
        discovery_stopping: false,
        discovery_failed: false,
        vpn,
    };
    let listeners = bound.listeners();
    let mut failures = Error::default();
    loop {
        let step = poll_fn(|cx| {
            if let Some(reason) = lifecycle.poll_stop(cx) {
                if let Err(error) = reason {
                    failures.failures.push(error.into());
                }
                if let Err(error) = owners.stop_discovery() {
                    failures.failures.push(error.into());
                }
                owners.vpn.request_shutdown();
            }
            if owners.vpn.retiring() {
                lifecycle.on_ready = None;
                if let Err(error) = owners.stop_discovery() {
                    failures.failures.push(error.into());
                }
            }
            if lifecycle.on_ready.is_some() && Instant::now() >= lifecycle.deadline {
                failures.failures.push(startup_timeout().into());
                lifecycle.on_ready = None;
                if let Err(error) = owners.stop_discovery() {
                    failures.failures.push(error.into());
                }
                owners.vpn.request_shutdown();
            }
            let (vpn, discovery, discovery_failed) = (
                &mut owners.vpn,
                &mut owners.discovery,
                &mut owners.discovery_failed,
            );
            let mut rejected = None;
            let mut duplicate_refusal = false;
            let progress = vpn.poll(
                cx,
                &listeners,
                lifecycle.on_ready.as_ref().map(|_| lifecycle.deadline),
                &mut |event| {
                    if let coordinator::Event::Discovery(request) = event {
                        let refusal = match discovery.as_mut() {
                            Some(provider) => provider.offer(request).err(),
                            None => Some(discovery::Rejected {
                                request,
                                reason: gnunet_types::Error::Unavailable,
                            }),
                        };
                        if let Some(refusal) = refusal {
                            if rejected.is_some() {
                                duplicate_refusal = true;
                            } else {
                                rejected = Some(refusal);
                            }
                        }
                    }
                },
            );
            if matches!(&progress, Poll::Ready(Err(_))) {
                return progress;
            }
            if duplicate_refusal {
                return Poll::Ready(Err(gnunet_types::Error::Capacity.into()));
            }
            if let Some(rejected) = rejected
                && let Err(error) = discovery::Provider::reject(rejected, vpn, &mut |_| {})
            {
                failures.failures.push(error.into());
                vpn.request_shutdown();
            }
            let discovery_changed = match discovery
                .as_mut()
                .filter(|_| !*discovery_failed)
                .map(|provider| provider.poll(cx, vpn, &mut |_| {}))
            {
                Some(Poll::Ready(Ok(()))) => true,
                Some(Poll::Ready(Err(error))) => {
                    *discovery_failed = true;
                    failures.failures.push(error.into());
                    lifecycle.on_ready = None;
                    vpn.request_shutdown();
                    true
                }
                Some(Poll::Pending) | None => false,
            };
            let progress = if progress.is_pending() && discovery_changed {
                Poll::Ready(Ok(Progress::Activity))
            } else {
                progress
            };
            if !matches!(&progress, Poll::Ready(Ok(Progress::Activity)))
                || lifecycle.on_ready.is_none()
            {
                return progress;
            }
            let reason: Result<(), Box<dyn StdError>> = match vpn.startup_ready() {
                Ok(false) => return progress,
                Err(error) => Err(error.into()),
                Ok(true) => {
                    if let Some(reason) = lifecycle.poll_stop(cx) {
                        if let Err(error) = reason {
                            failures.failures.push(error.into());
                        }
                        vpn.request_shutdown();
                        return progress;
                    }
                    if Instant::now() >= lifecycle.deadline {
                        Err(startup_timeout().into())
                    } else if let Some(ready) = lifecycle.on_ready.take() {
                        ready().map_err(Into::into)
                    } else {
                        Ok(())
                    }
                }
            };
            if let Err(error) = reason {
                failures.failures.push(error);
                lifecycle.on_ready = None;
                vpn.request_shutdown();
            }
            progress
        })
        .await;
        match step {
            Err(error) => {
                failures.failures.push(error.into());
                break;
            }
            Ok(Progress::Stopped) => break,
            Ok(Progress::Activity | Progress::WaitDeadline) => {}
        }
        tokio::task::consume_budget().await;
    }
    if let Err(error) = owners.close_discovery() {
        failures.failures.push(error.into());
    }
    let vpn = &mut owners.vpn;
    vpn.close(&mut |_| {});
    let debt = vpn.debt();
    if debt.routes != RouteState::Absent
        || debt.unconfirmed_control_closes != 0
        || debt.flows != 0
        || debt.buffers != 0
        || debt.discoveries != 0
    {
        failures.unresolved = Some(debt);
    }
    let cleanup = vpn.take_cleanup_errors();
    if !cleanup.is_empty() {
        failures.cleanup = Some(Box::new(cleanup));
    }
    failures.finish(vpn.report())
}
