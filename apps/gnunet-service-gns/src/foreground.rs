//! Same-clock GNS IPC, native dependency owners and unconditional retirement.
use crate::{
    Cause,
    control::Signals,
    lifecycle::{Cleanup, Resolver},
    settings::Settings,
};
use gnunet_client_host::{EndpointSource, LiveConfiguration};
use gnunet_config::Configuration;
use gnunet_gns_service_host::{
    self as host, Manager, Shared,
    auxiliary::{self, dns, registry, system},
    interceptor::{self, SourceCause, SourceProgress},
    native::{
        self,
        diagnostics::{OwnedError, OwnedProviderReport, OwnedReport},
    },
    server::{self, Event, Server},
};
use gnunet_program_host::{reporting::Reporter, shared_clock::SharedClock};
use gnunet_resolver_broker::{broker, native_profile};
use gnunet_service_runtime::{BoundListeners, clock::RuntimeClock, service::ShutdownMode};
use gnunet_service_startup::{ParentControl, daemon::ChildReady};
use gnunet_types::Error as Fault;
use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io::{self, Write},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};

type Backend<'a> = native::NativeProvider<'a, auxiliary::Auxiliary<'a, 128, 256>>;
#[derive(Debug, Default)]
struct Observations {
    errors: [Option<OwnedError>; 8],
    error_counts: [u64; 8],
    reports: [Option<OwnedReport>; 6],
    report_counts: [u64; 6],
    // Optional preparation failures stay distinct from a real lookup miss.
    initial_registry: Option<Arc<registry::Error>>,
    initial_dns_bootstrap: Option<Arc<dns::Error>>,
    first_frontend: Option<server::Error>,
    frontend_errors: u64,
    first_accept: Option<gnunet_service_runtime::accepted::AcceptError>,
    accept_errors: u64,
    first_socket_diagnostics: Option<gnunet_native::network::Diagnostics>,
    socket_diagnostics: u64,
    first_receipt: Option<Fault>,
    receipt_errors: u64,
    first_cache_status: Option<i32>,
    cache_statuses: u64,
    intercepted: u64,
    interception_lookups: u64,
    interception_forward_admitted: u64,
    interception_drop_admitted: u64,
    interception_answers_admitted: u64,
    interception_reply_whole_writes: u64,
    interception_retired: u64,
    interception_errors: u64,
    interception_losses: u64,
    first_interception_error: Option<interceptor::Error>,
    first_interception_loss: Option<SourceCause>,
    first_clock: Option<Fault>,
    clock_failures: u64,
    first_resolver: Option<gnunet_resolver_broker::BrokerError>,
    resolver_errors: u64,
    accepted: u64,
    queries: u64,
    replies: u64,
    whole_reply_writes: u64,
    written_bytes: u64,
    expired: u64,
    late: u64,
    closed_clients: u64,
    discarded_frames: u64,
    discarded_suffix_bytes: u64,
    exposed_prefix_bytes: u64,
    local_closed: bool,
    provider: Option<OwnedProviderReport>,
    first_refresh_native: Option<OwnedError>,
    refresh_native_errors: u64,
    refresh_native_omitted: u64,
    first_refresh_reason: Option<Fault>,
    refresh_refusals: u64,
    first_refresh_status: Option<i32>,
    refresh_status_failures: u64,
    refresh_expired: u64,
    refresh_late: u64,
    refresh: Option<host::refresh::Stats>,
}
impl Observations {
    fn native(&mut self, error: native::Error<'_>, reports: &Reporter) -> bool {
        let recover = error.requires_port_recovery();
        // Preserve the original cause before releasing its lifetime-bound token.
        let error = error.into_owned();
        reports.warning(
            "gns.dependency.failed",
            format_args!("GNS original dependency {error:?}"),
        );
        let i = match &error {
            OwnedError::CacheLoss { .. }
            | OwnedError::CacheLocal { .. }
            | OwnedError::CacheOrphan { .. } => 0,
            OwnedError::DhtLoss { .. } => 1,
            OwnedError::Revocation { .. } | OwnedError::RevocationStatus(_) => 2,
            OwnedError::Dns(_) => 3,
            OwnedError::Resolver(_) => 4,
            OwnedError::Clock(_) => 5,
            OwnedError::Ports(_) | OwnedError::Connect(_) => 6,
            OwnedError::Protocol(_) | OwnedError::Registry(_) => 7,
        };
        self.error_counts[i] = self.error_counts[i].saturating_add(1);
        if self.errors[i].is_none() {
            self.errors[i] = Some(error)
        }
        recover
    }
    fn refresh_native(&mut self, error: native::Error<'_>, reports: &Reporter) -> bool {
        let recover = error.requires_port_recovery();
        let error = error.into_owned();
        reports.warning(
            "gns.refresh.native",
            format_args!("GNS original optional refresh dependency {error:?}"),
        );
        self.refresh_native_errors = self.refresh_native_errors.saturating_add(1);
        if self.first_refresh_native.is_none() {
            self.first_refresh_native = Some(error);
        } else {
            self.refresh_native_omitted = self.refresh_native_omitted.saturating_add(1);
        }
        recover
    }
    fn refresh_reason(&mut self, error: Fault, reports: &Reporter) {
        self.refresh_refusals = self.refresh_refusals.saturating_add(1);
        self.first_refresh_reason.get_or_insert(error);
        reports.debug(
            "gns.refresh.refused",
            format_args!("GNS optional refresh stopped: {error}"),
        );
    }
    fn refresh_status(&mut self, status: i32, reports: &Reporter) {
        if status != 1 {
            self.refresh_status_failures = self.refresh_status_failures.saturating_add(1);
            self.first_refresh_status.get_or_insert(status);
            reports.warning(
                "gns.refresh.cache.status",
                format_args!("GNS optional refresh actual NAMECACHE status {status}"),
            );
        }
    }
    fn interception_error(&mut self, error: interceptor::Error, reports: &Reporter) {
        reports.warning(
            "gns.interception.failed",
            format_args!("GNS original interception cause: {error}"),
        );
        self.interception_errors = self.interception_errors.saturating_add(1);
        self.first_interception_error.get_or_insert(error);
    }
    fn interception(&mut self, event: interceptor::Event<'_>, reports: &Reporter) {
        match event {
            interceptor::Event::Received(_) => {
                self.intercepted = self.intercepted.saturating_add(1)
            }
            interceptor::Event::Lookup(_) => {
                self.interception_lookups = self.interception_lookups.saturating_add(1)
            }
            interceptor::Event::Admitted { action, .. } => match action {
                interceptor::Action::Forward => {
                    self.interception_forward_admitted =
                        self.interception_forward_admitted.saturating_add(1)
                }
                interceptor::Action::Drop => {
                    self.interception_drop_admitted =
                        self.interception_drop_admitted.saturating_add(1)
                }
                interceptor::Action::Answer { .. } => {
                    self.interception_answers_admitted =
                        self.interception_answers_admitted.saturating_add(1)
                }
            },
            interceptor::Event::Retired(_) => {
                self.interception_retired = self.interception_retired.saturating_add(1)
            }
            interceptor::Event::Failed { error, .. } => self.interception_error(error, reports),
            interceptor::Event::Source(progress) => match progress {
                SourceProgress::Written(_) => {
                    self.interception_reply_whole_writes =
                        self.interception_reply_whole_writes.saturating_add(1)
                }
                SourceProgress::Lost { cause, .. } => {
                    self.interception_losses = self.interception_losses.saturating_add(1);
                    if !matches!(cause, SourceCause::Closed | SourceCause::Cancelled) {
                        reports.warning(
                            "gns.interception.lost",
                            format_args!("GNS original DNS source: {cause:?}"),
                        );
                        self.first_interception_loss.get_or_insert(cause);
                    }
                }
                SourceProgress::Retry { error, .. } => {
                    self.interception_error(interceptor::Error::Source(error.into()), reports)
                }
                SourceProgress::Unavailable(error) => {
                    self.interception_error(interceptor::Error::Source(error), reports)
                }
                SourceProgress::Connected(_)
                | SourceProgress::InitWritten(_)
                | SourceProgress::Dropping(_)
                | SourceProgress::Activity { .. }
                | SourceProgress::Wait
                | SourceProgress::Closed => {}
                SourceProgress::Request(_) => {
                    self.interception_error(interceptor::Error::Protocol(Fault::Conflict), reports)
                }
            },
            interceptor::Event::Stopped => {}
        }
    }
    fn receipt(&mut self, error: Fault, reports: &Reporter) {
        reports.warning(
            "gns.receipt.failed",
            format_args!("GNS original receipt {error}"),
        );
        self.receipt_errors = self.receipt_errors.saturating_add(1);
        self.first_receipt.get_or_insert(error);
    }
    fn frontend(&mut self, error: server::Error, reports: &Reporter) {
        reports.warning("gns.client.failed", format_args!("GNS IPC owner {error}"));
        self.frontend_errors = self.frontend_errors.saturating_add(1);
        if self.first_frontend.is_none() {
            self.first_frontend = Some(error)
        }
    }
    fn report(&mut self, report: native::Report<'_>, reports: &Reporter) {
        let report = report.into_owned();
        reports.debug(
            "gns.dependency.closed",
            format_args!("GNS actual operation retirement {report:?}"),
        );
        let i = match &report {
            OwnedReport::Cache { .. } => 0,
            OwnedReport::Remote { .. } => 1,
            OwnedReport::Revocation { .. } => 2,
            OwnedReport::Dns(_) => 3,
            OwnedReport::System(_) => 4,
            OwnedReport::Registry { .. } => 5,
        };
        self.report_counts[i] = self.report_counts[i].saturating_add(1);
        if self.reports[i].is_none() {
            self.reports[i] = Some(report)
        }
    }
    fn socket(&mut self, d: gnunet_native::network::Diagnostics, reports: &Reporter) {
        if d.is_empty() {
            return;
        }
        reports.warning(
            "gns.socket.diagnostic",
            format_args!("GNS actual accepted-socket diagnostics {d:?}"),
        );
        self.socket_diagnostics = self.socket_diagnostics.saturating_add(1);
        if self.first_socket_diagnostics.is_none() {
            self.first_socket_diagnostics = Some(d)
        }
    }
}
fn observe(
    event: Event<'_, '_, Backend<'_>>,
    reports: &Reporter,
    state: &mut Observations,
) -> bool {
    let mut recover = false;
    match event {
        Event::Accepted { diagnostics, .. } => {
            state.accepted = state.accepted.saturating_add(1);
            state.socket(diagnostics, reports);
        }
        Event::Refused {
            address,
            reason,
            diagnostics,
        } => {
            state.socket(diagnostics, reports);
            reports.debug(
                "gns.client.refused",
                format_args!("GNS actual {address:?}: {reason}"),
            );
        }
        Event::AdmissionFailed {
            diagnostics, cause, ..
        } => {
            state.socket(diagnostics, reports);
            state.frontend(server::Error::Io(cause), reports);
        }
        Event::Accept(gnunet_service_runtime::accepted::SocketEvent::Failed(error)) => {
            if !error.is_emfile() {
                reports.warning(
                    "gns.accept.failed",
                    format_args!("GNS actual accept {error}"),
                );
            }
            state.accept_errors = state.accept_errors.saturating_add(1);
            if state.first_accept.is_none() {
                state.first_accept = Some(error)
            }
        }
        Event::Accept(gnunet_service_runtime::accepted::SocketEvent::Diagnostic(error)) => {
            reports.warning(
                "gns.accept.diagnostic",
                format_args!("GNS actual socket {error:?}"),
            );
        }
        Event::Read { .. } | Event::Ignored(_) => {}
        Event::Lookup { .. } => state.queries = state.queries.saturating_add(1),
        Event::Rejected { reason, .. } => state.receipt(reason, reports),
        Event::Reply { failure, .. } => {
            state.replies = state.replies.saturating_add(1);
            if let Some(failure) = failure {
                reports.debug(
                    "gns.lookup.result",
                    format_args!(
                        "GNS actual semantic failure {failure:?}; IPC result has zero records"
                    ),
                );
            }
        }
        Event::Written {
            bytes, complete, ..
        } => {
            state.written_bytes = state.written_bytes.saturating_add(bytes as u64);
            if complete {
                state.whole_reply_writes = state.whole_reply_writes.saturating_add(1)
            }
        }
        Event::Closed {
            cause,
            cancel_errors,
            pending_frames,
            pending_suffix_bytes,
            partial_prefix_bytes,
            ..
        } => {
            state.closed_clients = state.closed_clients.saturating_add(1);
            state.discarded_frames = state.discarded_frames.saturating_add(pending_frames as u64);
            state.discarded_suffix_bytes = state
                .discarded_suffix_bytes
                .saturating_add(pending_suffix_bytes as u64);
            state.exposed_prefix_bytes = state
                .exposed_prefix_bytes
                .saturating_add(partial_prefix_bytes as u64);
            if let Some(error) = cause {
                state.frontend(error, reports)
            }
            for error in cancel_errors {
                state.receipt(error, reports)
            }
        }
        Event::Interception(event) => state.interception(event, reports),
        Event::ClockFailed(error) => {
            state.clock_failures = state.clock_failures.saturating_add(1);
            state.first_clock.get_or_insert(error);
            reports.warning(
                "gns.clock.failed",
                format_args!("GNS canonical clock suspended: {error}"),
            );
            recover = true;
        }
        Event::Stopped => state.local_closed = true,
        Event::Manager(event) => match event {
            host::Event::Failed {
                cause,
                receipt_error,
                ..
            } => {
                match cause {
                    host::Cause::Native(e) => recover |= state.native(e, reports),
                    host::Cause::Protocol(e) => state.receipt(e, reports),
                    host::Cause::CacheStore(status) => {
                        state.cache_statuses = state.cache_statuses.saturating_add(1);
                        state.first_cache_status.get_or_insert(status);
                        reports.warning(
                            "gns.cache.status",
                            format_args!("GNS actual NAMECACHE status {status}"),
                        );
                    }
                }
                if let Some(error) = receipt_error {
                    state.receipt(error, reports)
                }
            }
            host::Event::GuardFailed { error, .. }
            | host::Event::LateRefusal { error, .. }
            | host::Event::RetireFailed { error, .. } => recover |= state.native(error, reports),
            host::Event::LateObservation { value, .. } => {
                state.late = state.late.saturating_add(1);
                if let Err(e) = value {
                    recover |= state.native(e, reports)
                }
            }
            host::Event::Ignored { reason, .. } => reports.debug(
                "gns.candidate.ignored",
                format_args!("GNS rejected candidate, original GET remains: {reason}"),
            ),
            host::Event::Expired { .. } => state.expired = state.expired.saturating_add(1),
            host::Event::Retired { report, .. } => state.report(report, reports),
            host::Event::Refresh(event) => {
                use host::refresh::Event as Refresh;
                match event {
                    Refresh::Failed { error, expired, .. } => {
                        if expired {
                            state.refresh_expired = state.refresh_expired.saturating_add(1);
                        }
                        recover |= state.refresh_native(error, reports);
                    }
                    Refresh::GuardFailed { error, .. } | Refresh::RetireFailed { error, .. } => {
                        recover |= state.refresh_native(error, reports)
                    }
                    Refresh::Retired { report, .. } => state.report(report, reports),
                    Refresh::Refused { reason, .. }
                    | Refresh::Ignored {
                        reason: Some(reason),
                        ..
                    } => state.refresh_reason(reason, reports),
                    Refresh::Stored { status, .. } => state.refresh_status(status, reports),
                    Refresh::LateObservation { value, .. } => {
                        state.refresh_late = state.refresh_late.saturating_add(1);
                        match value {
                            Err(error) => recover |= state.refresh_native(error, reports),
                            Ok(host::Value::Stored(status)) => {
                                state.refresh_status(status, reports)
                            }
                            _ => {}
                        }
                    }
                    Refresh::Expired { .. } | Refresh::Started { expired: true, .. } => {
                        state.refresh_expired = state.refresh_expired.saturating_add(1)
                    }
                    Refresh::Queued { .. }
                    | Refresh::Started { .. }
                    | Refresh::Ignored { reason: None, .. }
                    | Refresh::Selected { .. }
                    | Refresh::Retiring { .. }
                    | Refresh::Finished { .. } => {}
                }
            }
            host::Event::Shared(Shared::Failed(error)) => recover |= state.native(error, reports),
            host::Event::Started { .. }
            | host::Event::Observed { .. }
            | host::Event::Retiring { .. }
            | host::Event::Ready { .. }
            | host::Event::Shared(Shared::Activity | Shared::Recovered)
            | host::Event::Stopped => {}
        },
    }
    recover
}
struct Timer {
    hard: Instant,
    alarm: Pin<Box<Sleep>>,
}
impl Timer {
    fn new(duration: Duration) -> Result<Self, Cause> {
        let hard = Instant::now()
            .checked_add(duration)
            .ok_or("GNS native target overflow")?;
        Ok(Self {
            hard,
            alarm: Box::pin(tokio::time::sleep_until(hard)),
        })
    }
    fn expired(&mut self, cx: &mut Context<'_>) -> bool {
        Instant::now() >= self.hard || self.alarm.as_mut().poll(cx).is_ready()
    }
}
#[derive(Debug, Default)]
struct Failure {
    original: Option<Cause>,
    signal: Option<io::Error>,
    running: Option<server::Error>,
    cleanup: Option<server::Error>,
    cleanup_errors: u64,
    output: Option<io::Error>,
    logging: Option<io::Error>,
    observations: Observations,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GNS original lifecycle and bounded observations {self:?}"
        )
    }
}
impl Error for Failure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.signal.as_ref().map(|e| e as &dyn Error))
            .or_else(|| self.running.as_ref().map(|e| e as &dyn Error))
            .or_else(|| self.cleanup.as_ref().map(|e| e as &dyn Error))
            .or_else(|| self.output.as_ref().map(|e| e as &dyn Error))
            .or_else(|| self.logging.as_ref().map(|e| e as &dyn Error))
            .or_else(|| {
                self.observations
                    .first_interception_error
                    .as_ref()
                    .map(|e| e as &dyn Error)
            })
            .or(match self.observations.first_interception_loss.as_ref() {
                Some(SourceCause::Io(e)) => Some(e as &dyn Error),
                Some(SourceCause::Protocol(e) | SourceCause::Clock(e)) => Some(e as &dyn Error),
                _ => None,
            })
            .or_else(|| {
                self.observations
                    .errors
                    .iter()
                    .flatten()
                    .next()
                    .map(|e| e as &dyn Error)
            })
            .or_else(|| {
                self.observations
                    .first_resolver
                    .as_ref()
                    .map(|e| e as &dyn Error)
            })
    }
}
impl Failure {
    fn failed(&self) -> bool {
        self.original.is_some()
            || self.signal.is_some()
            || self.running.is_some()
            || self.cleanup.is_some()
            || self.output.is_some()
            || self.logging.is_some()
            || self.observations.errors.iter().any(Option::is_some)
            || self.observations.first_resolver.is_some()
            || self.observations.first_clock.is_some()
            || self.observations.first_frontend.is_some()
            || self.observations.first_interception_error.is_some()
            || self.observations.first_interception_loss.is_some()
    }
}
pub(super) struct Inputs<'a> {
    pub config: &'a Configuration,
    pub settings: &'a Settings,
    pub bound: &'a BoundListeners,
    pub parent: Option<ParentControl>,
    pub clock: SharedClock,
    pub reports: Reporter,
    pub child: &'a mut ChildReady,
    pub cleanup: Cleanup,
}
pub(super) async fn run(input: Inputs<'_>) -> Result<(), Cause> {
    let Inputs {
        config,
        settings,
        bound,
        parent,
        clock,
        reports,
        child,
        cleanup,
    } = input;
    let mut signals = Signals::new(parent)?;
    let pre_stopped = poll_fn(|cx| {
        reports.register(cx);
        if reports.failed() {
            return Poll::Ready(Ok(true));
        }
        Poll::Ready(match signals.poll(cx) {
            Poll::Ready(result) => result.map(|()| true),
            Poll::Pending => Ok(false),
        })
    })
    .await?;
    if pre_stopped {
        return Ok(());
    }
    // Bounded synchronous public configuration files, before live MQ work.
    // OS file reads cannot be forcibly canceled; no contrary guarantee is made.
    let mut observations = Observations::default();
    let registry =
        registry::Files::from_files(&settings.protocols, &settings.services, settings.registry)
            .map_err(Arc::new);
    if let Err(error) = &registry {
        observations.initial_registry = Some(error.clone());
        reports.warning(
            "gns.registry.unavailable",
            format_args!("GNS optional files registry unavailable: {error}"),
        );
    }
    let source_clock: Arc<dyn RuntimeClock> = Arc::new(clock);
    let dns = if settings.core.dns {
        let dns = match dns::RecursiveDns::from_resolv_conf(
            source_clock.clone(),
            &settings.resolv_conf,
            settings.resolv_conf_bytes,
            settings.dns,
        ) {
            Ok(dns) => dns,
            Err(error) => {
                reports.warning(
                    "gns.dns.bootstrap.unavailable",
                    format_args!("GNS optional DNS bootstrap unavailable: {error}"),
                );
                let dns = dns::RecursiveDns::without_bootstrap(
                    source_clock.clone(),
                    error,
                    settings.dns,
                )?;
                observations.initial_dns_bootstrap = dns.bootstrap_error().cloned();
                dns
            }
        };
        dns.with_dnssec(dns::dnssec::Limits::default())?
    } else {
        // Disabled DNS cannot issue its effects; do not read unused OS data.
        dns::RecursiveDns::new(source_clock.clone(), &[], settings.dns)?
    };
    let stopped = poll_fn(|cx| {
        reports.register(cx);
        if reports.failed() {
            return Poll::Ready(Ok(true));
        }
        Poll::Ready(match signals.poll(cx) {
            Poll::Ready(result) => result.map(|()| true),
            Poll::Pending => Ok(false),
        })
    })
    .await?;
    if stopped {
        return Ok(());
    }
    let live = LiveConfiguration::new(config.duplicate()?);
    let (context, driver) = broker::<128, 256>(
        live.clone(),
        settings.resolver,
        native_profile()?,
        source_clock.clone(),
    )?;
    let mut resolver = Resolver::new(driver, cleanup);
    let resolution = context.resolution_context();
    let interception_source = settings
        .interception
        .map(|_| EndpointSource::live(live.clone(), b"dns", resolution.clone()));
    let sources = native::Sources {
        namecache: EndpointSource::live(live.clone(), b"namecache", resolution.clone()),
        revocation: EndpointSource::live(live.clone(), b"revocation", resolution.clone()),
        dht: EndpointSource::live(live, b"dht", resolution),
    };
    let system = system::Factory::new(context, source_clock.clone(), settings.system)?;
    let auxiliary = auxiliary::Auxiliary::with_registry(system, dns, registry)?;
    let mut domains = native::Domains::new();
    let provider = native::NativeProvider::new(
        &mut domains,
        sources,
        source_clock.clone(),
        settings.native,
        auxiliary,
    )
    .map_err(native::Error::into_owned)?;
    let mut instance = host::Instance::new();
    let mut manager =
        Manager::new_with_refresh(&mut instance, provider, settings.core, settings.refresh)?;
    let mut frontend = server::Instance::new();
    let mut server = Server::new(
        &mut frontend,
        &mut manager,
        source_clock,
        settings.options.clone(),
        settings.access,
        settings.frontend,
    )?;
    if let (Some(source), Some(limits)) = (interception_source, settings.interception) {
        server.enable_interception(source, config.duplicate()?, limits)?;
    }
    let listeners = bound.listeners();
    let mut failure = Failure {
        observations,
        ..Failure::default()
    };
    let mut recover: Option<Timer> = None;
    let mut resolver_backoff: Option<Timer> = None;
    let mut grace: Option<Timer> = None;
    let mut cursor = false;
    let mut stopping = false;
    let outcome: Result<(), Cause> = async {
        let stopped = poll_fn(|cx| {
            reports.register(cx);
            if reports.failed() {
                return Poll::Ready(Ok(true));
            }
            Poll::Ready(match signals.poll(cx) {
                Poll::Ready(r) => r.map(|()| true),
                Poll::Pending => Ok(false),
            })
        })
        .await?;
        if stopped {
            return Ok(());
        }
        {
            let mut out = io::stdout().lock();
            writeln!(
                out,
                "READY gns wire=0.29.1 listeners=bound dependency-clients=configured"
            )?;
            out.flush()?;
        }
        child.ready()?;
        loop {
            enum Turn {
                Activity,
                Stop,
                Expired,
                Stopped,
                Failed,
            }
            let turn = poll_fn(|cx| -> Poll<Result<Turn, Cause>> {
                if grace.as_mut().is_some_and(|g| g.expired(cx)) {
                    return Poll::Ready(Ok(Turn::Expired));
                }
                reports.register(cx);
                if reports.failed() {
                    return Poll::Ready(Ok(Turn::Stop));
                }
                if let Poll::Ready(result) = signals.poll(cx) {
                    match result {
                        Ok(()) => {}
                        Err(error) => failure.signal = Some(error),
                    }
                    return Poll::Ready(Ok(Turn::Stop));
                }
                // Native source/query guards precede any canonical-capability use.
                if let Some(event) = server.poll_native_guard(cx)? {
                    let stopped = matches!(event, Event::Stopped);
                    if observe(event, &reports, &mut failure.observations)
                        && !stopping
                        && recover.is_none()
                    {
                        recover = Some(Timer::new(Duration::from_secs(1))?);
                    }
                    return Poll::Ready(Ok(if stopped {
                        Turn::Stopped
                    } else {
                        Turn::Activity
                    }));
                }
                if recover.as_mut().is_some_and(|timer| timer.expired(cx)) {
                    recover = None;
                    if let Err(error) = server.recover_clock() {
                        failure.observations.frontend(error, &reports);
                        recover = Some(Timer::new(Duration::from_secs(1))?);
                    }
                    if !reports.failed()
                        && let Err(error) = server.provider_mut().recover_cache_ports()
                    {
                        failure.observations.native(error, &reports);
                        recover = Some(Timer::new(Duration::from_secs(1))?);
                    }
                    if !reports.failed()
                        && let Err(error) = server.provider_mut().recover_dht_ports()
                    {
                        failure.observations.native(error, &reports);
                        recover = Some(Timer::new(Duration::from_secs(1))?);
                    }
                    return Poll::Ready(Ok(Turn::Activity));
                }
                let mut activity = false;
                for offset in 0..2 {
                    if reports.failed() {
                        return Poll::Ready(Ok(Turn::Stop));
                    }
                    if grace.as_mut().is_some_and(|g| g.expired(cx)) {
                        return Poll::Ready(Ok(Turn::Expired));
                    }
                    if (usize::from(cursor) + offset) % 2 == 0 {
                        if resolver_backoff
                            .as_mut()
                            .is_some_and(|timer| !timer.expired(cx))
                        {
                            continue;
                        }
                        resolver_backoff = None;
                        match resolver.poll(cx, &reports) {
                            Poll::Pending => {}
                            Poll::Ready(Ok(_)) => activity = true,
                            Poll::Ready(Err(error)) => {
                                reports.warning(
                                    "gns.resolver.failed",
                                    format_args!(
                                        "GNS shared Resolver remains the original owner: {error}"
                                    ),
                                );
                                failure.observations.resolver_errors =
                                    failure.observations.resolver_errors.saturating_add(1);
                                if failure.observations.first_resolver.is_none() {
                                    failure.observations.first_resolver = Some(error)
                                }
                                resolver_backoff = Some(Timer::new(Duration::from_secs(1))?);
                                if !stopping {
                                    recover = Some(Timer::new(Duration::from_secs(1))?);
                                }
                                activity = true;
                            }
                        }
                    } else if let Poll::Ready(result) = server.poll(cx, &listeners) {
                        match result {
                            Ok(event) => {
                                let stopped = matches!(event, Event::Stopped);
                                if observe(event, &reports, &mut failure.observations)
                                    && !stopping
                                    && recover.is_none()
                                {
                                    recover = Some(Timer::new(Duration::from_secs(1))?);
                                }
                                if stopped {
                                    return Poll::Ready(Ok(Turn::Stopped));
                                }
                                activity = true;
                            }
                            Err(error) => {
                                failure.running = Some(error);
                                return Poll::Ready(Ok(Turn::Failed));
                            }
                        }
                    }
                }
                if activity {
                    Poll::Ready(Ok(Turn::Activity))
                } else {
                    Poll::Pending
                }
            })
            .await?;
            cursor = !cursor;
            match turn {
                Turn::Activity => tokio::task::yield_now().await,
                Turn::Stopped | Turn::Failed => break,
                Turn::Expired => {
                    server.force_stop();
                    break;
                }
                Turn::Stop => {
                    stopping = true;
                    recover = None;
                    if !reports.failed()
                        && failure.signal.is_none()
                        && grace.is_none()
                        && settings.options.shutdown == ShutdownMode::Soft
                    {
                        grace = Some(Timer::new(settings.shutdown_grace)?);
                        server.request_stop(ShutdownMode::Soft);
                    } else {
                        server.force_stop();
                        break;
                    }
                }
            }
        }
        Ok(())
    }
    .await;
    failure.original = outcome.err();
    // No post-Server error path bypasses retirement. No fresh query/provider is
    // admitted here; original operation/native deadlines remain unchanged.
    server.force_stop();
    while !failure.observations.local_closed {
        let result = poll_fn(|cx| {
            if let Some(event) = server.poll_native_guard(cx)? {
                return Poll::Ready(Ok(event));
            }
            reports.register(cx);
            match server.poll(cx, &[]) {
                Poll::Ready(result) => Poll::Ready(result),
                Poll::Pending => {
                    // Only the still-original Driver's retained debts are driven.
                    // A failed logger gates all further Resolver/native admissions.
                    if !reports.failed() {
                        let ready = resolver_backoff
                            .as_mut()
                            .is_none_or(|timer| timer.expired(cx));
                        if ready {
                            match resolver.poll(cx, &reports) {
                                Poll::Ready(Err(error)) => {
                                    failure.observations.resolver_errors =
                                        failure.observations.resolver_errors.saturating_add(1);
                                    if failure.observations.first_resolver.is_none() {
                                        failure.observations.first_resolver = Some(error)
                                    }
                                    resolver_backoff =
                                        Some(Timer::new(Duration::from_secs(1)).map_err(|_| {
                                            server::Error::Protocol(Fault::Overflow)
                                        })?);
                                    cx.waker().wake_by_ref();
                                }
                                Poll::Ready(Ok(_)) => cx.waker().wake_by_ref(),
                                Poll::Pending => {}
                            }
                        }
                    }
                    Poll::Pending
                }
            }
        })
        .await;
        match result {
            Ok(event) => {
                observe(event, &reports, &mut failure.observations);
            }
            Err(error) => {
                failure.cleanup_errors = failure.cleanup_errors.saturating_add(1);
                if failure.cleanup.is_none() {
                    failure.cleanup = Some(error)
                }
                // All original hard guards still execute on the next turn. This is
                // bounded by existing operation bounds, never a renewed grace.
                tokio::task::yield_now().await;
            }
        }
    }
    failure.observations.provider = Some(server.manager().provider().report().into_owned());
    failure.observations.refresh = Some(server.manager().refresh_stats());
    drop(server);
    resolver.close();
    failure.output = {
        let mut out = io::stdout().lock();
        writeln!(
            out,
            "STOPPED gns local-operations-closed={} shared-provider={:?} optional-refresh={:?}",
            failure.observations.local_closed,
            failure.observations.provider,
            failure.observations.refresh
        )
        .and_then(|()| out.flush())
        .err()
    };
    reports.debug(
        "gns.stopped",
        format_args!("GNS actual retirement {:?}", failure.observations),
    );
    failure.logging = reports.take_error();
    if failure.failed() {
        Err(Box::new(failure))
    } else {
        Ok(())
    }
}
