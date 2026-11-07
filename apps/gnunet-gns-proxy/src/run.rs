//! Original proxy owners and shared Resolver, retained through actual retirement.
use crate::{Cause, control::Control, settings::Settings};
use gnunet_client_host::{EndpointSource, LiveConfiguration};
use gnunet_gns_proxy_host as proxy;
use gnunet_program_host::reporting::Reporter;
use gnunet_resolver_broker::{BrokerError, Context as Broker, Driver, DriverEvent};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_service_startup::ParentControl;
use gnunet_types::Error as Fault;
use std::{
    cell::Cell,
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io,
    net::SocketAddr,
    rc::Rc,
    sync::Arc,
    task::Poll,
    time::Duration,
};

pub(super) struct Inputs {
    pub settings: Settings,
    pub configuration: gnunet_config::Configuration,
    pub live: LiveConfiguration,
    pub context: Broker<128, 256>,
    pub resolver: Driver<128, 256>,
    pub source: Arc<dyn RuntimeClock>,
    pub reporter: Reporter,
    pub stop: Rc<Cell<bool>>,
    pub parent: Option<ParentControl>,
}
#[derive(Debug, Default)]
pub(super) struct Report {
    proxy: Option<proxy::Report>,
    sessions: [Option<proxy::SessionReport>; 4],
    session_events: u64,
    additional_sessions: u64,
    accept_errors: [Option<gnunet_service_runtime::accepted::SocketEvent>; 4],
    additional_accept_errors: u64,
    refusals: [Option<Refusal>; 4],
    additional_refusals: u64,
    stopped: bool,
    closed_observed: bool,
    report_rejected: bool,
    startup_clock: Option<Fault>,
    resolver_io: [Option<io::Error>; 4],
    resolver_connect: [Option<BrokerError>; 4],
    resolver_loss: Option<(u64, Fault)>,
    resolver_losses: u64,
    additional_resolver_errors: u64,
    resolver_pending: Option<usize>,
    resolver_queued: Option<usize>,
    resolver_disconnected: bool,
    resolver_dropped: bool,
}
struct Refusal {
    peer: SocketAddr,
    reason: Fault,
    diagnostics: Option<gnunet_native::network::Diagnostics>,
}
impl fmt::Debug for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Refusal")
            .field("peer", &self.peer)
            .field("reason", &self.reason)
            .field("diagnostics", &self.diagnostics)
            .finish()
    }
}
#[derive(Debug, Default)]
struct Causes {
    original: Option<Cause>,
    host: Option<proxy::Error>,
    further_host_errors: u64,
    signal: Option<io::Error>,
    resolver: Option<BrokerError>,
    resolver_unavailable: bool,
    disconnect: Option<BrokerError>,
    logging: Option<io::Error>,
}
impl Causes {
    fn failed(&self) -> bool {
        self.original.is_some()
            || self.host.is_some()
            || self.signal.is_some()
            || self.resolver.is_some()
            || self.resolver_unavailable
            || self.disconnect.is_some()
            || self.logging.is_some()
    }
    fn host(&mut self, error: proxy::Error) {
        if self.host.is_none() {
            self.host = Some(error);
        } else {
            self.further_host_errors = self.further_host_errors.saturating_add(1);
        }
    }
}
#[derive(Debug)]
struct Failed {
    report: Report,
    causes: Causes,
}
impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GNS proxy terminal facts: {:?}; causes: {:?}",
            self.report, self.causes
        )
    }
}
impl Error for Failed {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.causes
            .original
            .as_deref()
            .or_else(|| self.causes.host.as_ref().map(|error| error as _))
            .or_else(|| self.causes.signal.as_ref().map(|error| error as _))
            .or_else(|| self.causes.resolver.as_ref().map(|error| error as _))
            .or_else(|| self.causes.disconnect.as_ref().map(|error| error as _))
            .or_else(|| self.causes.logging.as_ref().map(|error| error as _))
    }
}
fn take_resolver_errors(resolver: &mut Driver<128, 256>, report: &mut Report) {
    if let Some(error) = resolver.take_io_error() {
        if let Some(slot) = report.resolver_io.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(error);
        } else {
            report.additional_resolver_errors = report.additional_resolver_errors.saturating_add(1);
        }
    }
    if let Some(error) = resolver.take_connect_error() {
        if let Some(slot) = report
            .resolver_connect
            .iter_mut()
            .find(|slot| slot.is_none())
        {
            *slot = Some(error);
        } else {
            report.additional_resolver_errors = report.additional_resolver_errors.saturating_add(1);
        }
    }
}
fn event(event: proxy::Event, reporter: &Reporter, report: &mut Report) {
    match event {
        proxy::Event::Session(session) => {
            report.session_events = report.session_events.saturating_add(1);
            if session.has_diagnostics() {
                reporter.warning("gns-proxy.session.failed", format_args!("{session:?}"));
                if let Some(slot) = report.sessions.iter_mut().find(|slot| slot.is_none()) {
                    *slot = Some(session);
                } else {
                    report.additional_sessions = report.additional_sessions.saturating_add(1);
                }
            } else {
                reporter.debug("gns-proxy.session", format_args!("{session:?}"));
            }
        }
        proxy::Event::AcceptFailed(error) => {
            reporter.warning("gns-proxy.accept.failed", format_args!("{error:?}"));
            if let Some(slot) = report.accept_errors.iter_mut().find(|slot| slot.is_none()) {
                *slot = Some(error);
            } else {
                report.additional_accept_errors = report.additional_accept_errors.saturating_add(1);
            }
        }
        proxy::Event::Refused {
            peer,
            reason,
            diagnostics,
        } => {
            let actual = Refusal {
                peer,
                reason,
                diagnostics,
            };
            reporter.warning("gns-proxy.accept.refused", format_args!("{actual:?}"));
            if let Some(slot) = report.refusals.iter_mut().find(|slot| slot.is_none()) {
                *slot = Some(actual);
            } else {
                report.additional_refusals = report.additional_refusals.saturating_add(1);
            }
        }
        proxy::Event::Closed => report.closed_observed = true,
        other => reporter.debug("gns-proxy.activity", format_args!("{other:?}")),
    }
}
#[derive(Default)]
struct Turn {
    host: Option<Result<proxy::Event, proxy::Error>>,
    resolver: Option<Result<gnunet_resolver_broker::Progress, BrokerError>>,
    signal: Option<io::Result<()>>,
}
impl Turn {
    fn ready(&self) -> bool {
        self.host.is_some() || self.resolver.is_some() || self.signal.is_some()
    }
}

async fn drive(
    owner: &mut proxy::Runtime,
    resolver: &mut Driver<128, 256>,
    control: &mut Control,
    reporter: &Reporter,
    report: &mut Report,
    causes: &mut Causes,
    closing: bool,
) {
    let mut cursor = 0;
    loop {
        if owner.is_closed() {
            break;
        }
        let changed = Cell::new(false);
        let unavailable = Cell::new(false);
        let loss = Cell::new(None);
        let turn = {
            let mut source = std::pin::pin!(resolver.drive_waiting(None, |observation| {
                changed.set(true);
                match observation {
                    DriverEvent::Lost { epoch, cause } => loss.set(Some((epoch.value(), cause))),
                    DriverEvent::Unavailable => unavailable.set(true),
                    _ => {}
                }
                reporter.debug(
                    "gns-proxy.resolver.activity",
                    format_args!("{observation:?}"),
                );
            }));
            poll_fn(|cx| {
                reporter.register(cx);
                let mut turn = Turn::default();
                // Native hard/Stop and reporting gates precede either source's IO.
                if let Some(observation) = owner.poll_native_guard(cx) {
                    turn.host = Some(Ok(observation));
                    return Poll::Ready(turn);
                }
                if !closing && let Poll::Ready(result) = control.poll(cx) {
                    turn.signal = Some(result);
                    return Poll::Ready(turn);
                }
                for step in 0..2 {
                    if (cursor + step) % 2 == 0 {
                        if let Poll::Ready(result) = if closing {
                            owner.poll_close(cx)
                        } else {
                            owner.poll(cx)
                        } {
                            turn.host = Some(result);
                        }
                    } else if let Poll::Ready(result) = source.as_mut().poll(cx) {
                        turn.resolver = Some(result);
                    }
                    if turn.ready() || changed.get() {
                        break;
                    }
                }
                cursor = (cursor + 1) % 2;
                if turn.ready() || changed.get() {
                    Poll::Ready(turn)
                } else {
                    Poll::Pending
                }
            })
            .await
        };
        take_resolver_errors(resolver, report);
        if let Some(actual) = loss.get() {
            report.resolver_losses = report.resolver_losses.saturating_add(1);
            report.resolver_loss.get_or_insert(actual);
        }
        causes.resolver_unavailable |= unavailable.get();
        if let Some(Err(error)) = turn.resolver {
            causes.resolver.get_or_insert(error);
        }
        if let Some(result) = turn.host {
            match result {
                Ok(observation) => event(observation, reporter, report),
                Err(error) => causes.host(error),
            }
        }
        if let Some(result) = turn.signal {
            report.stopped = true;
            if let Err(error) = result {
                causes.signal = Some(error);
            }
        }
        if !closing && (report.stopped || causes.failed() || reporter.failed()) {
            break;
        }
        tokio::task::yield_now().await;
    }
}

pub(super) async fn run(inputs: Inputs) -> Result<Report, Cause> {
    let Inputs {
        settings,
        configuration,
        live,
        context,
        mut resolver,
        source,
        reporter,
        stop,
        parent,
    } = inputs;
    let mut report = Report::default();
    let mut causes = Causes::default();
    let mut runtime = None;
    let mut control = None;
    let startup_stop = proxy::budget::Stop::new();
    let mut startup = None;
    let outcome = async {
        let mut original_control = Control::new(parent, stop, reporter.clone())?;
        if let Poll::Ready(result) = poll_fn(|cx| Poll::Ready(original_control.poll(cx))).await {
            report.stopped = true;
            result?;
            return Ok::<(), Cause>(());
        }
        let budget = proxy::budget::Budget::new(
            source.clone(),
            Duration::from_secs(60),
            startup_stop.clone(),
        )?;
        startup = Some(budget.clone());
        let guard = budget.tls_guard();
        let authority =
            proxy::tls::Authority::load(&settings.authority, 64, Duration::from_secs(300), &guard)?;
        if let Poll::Ready(result) = poll_fn(|cx| Poll::Ready(original_control.poll(cx))).await {
            startup_stop.request();
            report.stopped = true;
            result?;
            return Ok(());
        }
        let roots = match settings.roots {
            Some(path) => proxy::tls::TrustRoots::from_pem(&path, Default::default(), &guard)?,
            None => proxy::tls::TrustRoots::mozilla(&guard)?,
        };
        budget.check()?;
        if let Poll::Ready(result) = poll_fn(|cx| Poll::Ready(original_control.poll(cx))).await {
            startup_stop.request();
            report.stopped = true;
            result?;
            return Ok(());
        }
        let resolution = context.resolution_context();
        let sources = proxy::Sources {
            gns: EndpointSource::live(live.clone(), b"gns", resolution.clone()),
            identity: EndpointSource::live(live.clone(), b"identity", resolution.clone()),
            vpn: EndpointSource::live(live, b"vpn", resolution),
        };
        let owner = proxy::Runtime::bind(
            proxy::Ports {
                configuration,
                context: context.clone(),
                clock: source,
                authority,
                roots,
                startup_guard: guard.clone(),
            },
            sources,
            proxy::Options {
                bind: settings.bind,
                disable_ipv6: settings.disable_ipv6,
            },
            proxy::Limits::default(),
        )?;
        runtime = Some(owner);
        control = Some(original_control);
        if let Some(owner) = runtime.as_mut() {
            for error in owner.bind_failures() {
                reporter.warning("gns-proxy.bind.failed", format_args!("{error}"));
            }
            for address in owner.local_addresses() {
                reporter.debug(
                    "gns-proxy.bound",
                    format_args!("Actual TCP listener {address}"),
                );
            }
            if !reporter.failed()
                && let Some(control) = control.as_mut()
            {
                drive(
                    owner,
                    &mut resolver,
                    control,
                    &reporter,
                    &mut report,
                    &mut causes,
                    false,
                )
                .await;
            }
        }
        Ok(())
    }
    .await;
    if let Err(error) = outcome {
        causes.original = Some(error);
    }
    if let Some(budget) = startup {
        report.startup_clock = budget.first_clock_error();
    }
    startup_stop.request();
    if let Some(mut owner) = runtime {
        if let Err(error) = owner.begin_close() {
            causes.host(error);
        }
        if let Some(control) = control.as_mut() {
            drive(
                &mut owner,
                &mut resolver,
                control,
                &reporter,
                &mut report,
                &mut causes,
                true,
            )
            .await;
        }
        match owner.into_report() {
            Ok(actual) => report.proxy = Some(actual),
            Err(_original) => report.report_rejected = true,
        }
    }
    take_resolver_errors(&mut resolver, &mut report);
    match context.pending_requests() {
        Ok(count) => report.resolver_pending = Some(count),
        Err(error) => {
            causes.resolver.get_or_insert(error);
        }
    }
    match resolver.queued_frames() {
        Ok(count) => report.resolver_queued = Some(count),
        Err(error) => {
            causes.resolver.get_or_insert(error);
        }
    }
    match resolver.disconnect() {
        Ok(()) => report.resolver_disconnected = true,
        Err(error) => causes.disconnect = Some(error),
    }
    take_resolver_errors(&mut resolver, &mut report);
    drop(resolver);
    report.resolver_dropped = true;
    reporter.debug(
        "gns-proxy.stopped",
        format_args!("Original retirement: {report:?}"),
    );
    causes.logging = reporter.take_error();
    if causes.failed() || report.report_rejected {
        Err(Box::new(Failed { report, causes }))
    } else {
        Ok(report)
    }
}
