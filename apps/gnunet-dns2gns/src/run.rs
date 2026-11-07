//! The actual gateway, shared Resolver and retained PROGRAM future through close.
use crate::{Cause, control::Control, settings::Settings};
use gnunet_client_host::{EndpointSource, LiveConfiguration};
use gnunet_dns2gns_host as gateway;
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
    rc::Rc,
    sync::Arc,
    task::Poll,
    time::Duration,
};
use tokio::time::{Instant, Sleep};

pub(super) struct Inputs {
    pub settings: Settings,
    pub configuration: gnunet_config::Configuration,
    pub live: LiveConfiguration,
    pub context: Broker<16, 64>,
    pub resolver: Driver<16, 64>,
    pub source: Arc<dyn RuntimeClock>,
    pub reporter: Reporter,
    pub stop: Rc<Cell<bool>>,
    pub parent: Option<ParentControl>,
}
#[derive(Default, Debug)]
pub(super) struct Report {
    gateway: Option<gateway::Report>,
    stopped: bool,
    closed_observed: bool,
    resolver_disconnected: bool,
    resolver_dropped: bool,
    resolver_pending: Option<usize>,
    resolver_queued: Option<usize>,
    resolver_io: [Option<io::Error>; 4],
    resolver_connect: [Option<BrokerError>; 4],
    additional_resolver_errors: u64,
    request_events: u64,
    retained_request_diagnostics: [Option<Arc<gateway::RequestReport>>; 4],
    additional_request_diagnostics: u64,
}
#[derive(Default, Debug)]
struct Errors {
    original: Option<Cause>,
    runtime: Option<gateway::Failure>,
    close: Option<gateway::Failure>,
    additional_close_errors: u64,
    signal: Option<io::Error>,
    resolver: Option<BrokerError>,
    resolver_loss: Option<(u64, Fault)>,
    resolver_unavailable: bool,
    disconnect: Option<BrokerError>,
    cleanup_timeout: Option<Fault>,
    logging: Option<io::Error>,
}
impl Errors {
    fn failed(&self) -> bool {
        self.original.is_some()
            || self.runtime.is_some()
            || self.close.is_some()
            || self.additional_close_errors != 0
            || self.signal.is_some()
            || self.resolver.is_some()
            || self.resolver_loss.is_some()
            || self.resolver_unavailable
            || self.disconnect.is_some()
            || self.cleanup_timeout.is_some()
            || self.logging.is_some()
    }
}
#[derive(Debug)]
struct Failed {
    report: Report,
    errors: Errors,
}
impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DNS2GNS terminal facts: {:?}; causes: {:?}",
            self.report, self.errors
        )
    }
}
impl Error for Failed {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.errors
            .original
            .as_deref()
            .or_else(|| {
                self.errors
                    .runtime
                    .as_ref()
                    .map(|error| error as &dyn Error)
            })
            .or_else(|| self.errors.close.as_ref().map(|error| error as &dyn Error))
            .or_else(|| self.errors.signal.as_ref().map(|error| error as &dyn Error))
            .or_else(|| {
                self.errors
                    .resolver
                    .as_ref()
                    .map(|error| error as &dyn Error)
            })
            .or_else(|| {
                self.errors
                    .resolver_loss
                    .as_ref()
                    .map(|(_, error)| error as &dyn Error)
            })
            .or_else(|| {
                self.errors
                    .disconnect
                    .as_ref()
                    .map(|error| error as &dyn Error)
            })
            .or_else(|| {
                self.errors
                    .cleanup_timeout
                    .as_ref()
                    .map(|error| error as &dyn Error)
            })
            .or_else(|| {
                self.errors
                    .logging
                    .as_ref()
                    .map(|error| error as &dyn Error)
            })
    }
}
#[derive(Clone, Copy, Default)]
struct Observed {
    changed: bool,
    lost: Option<(u64, Fault)>,
    unavailable: bool,
}
fn resolver_observation(event: DriverEvent, events: &Cell<Observed>, reporter: &Reporter) {
    let mut value = events.get();
    value.changed = true;
    match event {
        DriverEvent::Lost { epoch, cause } => value.lost = Some((epoch.value(), cause)),
        DriverEvent::Unavailable => value.unavailable = true,
        _ => {}
    }
    events.set(value);
    reporter.debug(
        "dns2gns.resolver.activity",
        format_args!("Resolver source: {event:?}"),
    );
}
fn take_resolver_errors(resolver: &mut Driver<16, 64>, report: &mut Report) {
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
fn apply_observation(value: Observed, errors: &mut Errors) {
    if value.lost.is_some() {
        errors.resolver_loss = value.lost;
    }
    errors.resolver_unavailable |= value.unavailable;
}
#[derive(Default)]
struct Turn {
    gateway: Option<Result<gateway::Progress, gateway::Failure>>,
    resolver: Option<Result<gnunet_resolver_broker::Progress, BrokerError>>,
    signal: Option<io::Result<()>>,
    timed_out: bool,
    event: Option<gateway::Event>,
}
impl Turn {
    fn ready(&self) -> bool {
        self.gateway.is_some() || self.resolver.is_some() || self.signal.is_some() || self.timed_out
    }
}
fn has_diagnostics(request: &gateway::RequestReport) -> bool {
    request.error.is_some()
        || request.dns_io.is_some()
        || request.dns_cancel_error.is_some()
        || request.gns_connect_error.is_some()
        || request.identity_connect_error.is_some()
        || request.lookup.as_ref().is_some_and(|lookup| {
            lookup.gns_cancel_error.is_some() || lookup.identity_cancel_error.is_some()
        })
        || request.vpn.iter().any(|vpn| {
            vpn.close_error.is_some()
                || vpn.loss.is_some()
                || vpn.connect_error.is_some()
                || matches!(&vpn.cancel, Some(Err(_)))
        })
}
fn gateway_observation(
    event: gateway::Event,
    slot: &mut Option<gateway::Event>,
    reporter: &Reporter,
) {
    match &event {
        gateway::Event::Request(request) if has_diagnostics(request) => reporter.warning(
            "dns2gns.request.failed",
            format_args!(
                "Original request {}: {:?}; independent cleanup retained",
                request.serial, request.error
            ),
        ),
        gateway::Event::Request(_) => reporter.debug(
            "dns2gns.request.completed",
            format_args!("Original request completed locally"),
        ),
        gateway::Event::ListenerLost(index) => reporter.warning(
            "dns2gns.listener.lost",
            format_args!("Original listener {index} closed; original IO cause retained"),
        ),
        gateway::Event::Closed => reporter.debug(
            "dns2gns.gateway.closed",
            format_args!("Original gateway owners retired locally"),
        ),
    }
    *slot = Some(event);
}
fn take_gateway_event(
    event: Option<gateway::Event>,
    runtime: &gateway::Runtime,
    reporter: &Reporter,
    report: &mut Report,
) {
    match event {
        Some(gateway::Event::Request(request)) => {
            report.request_events = report.request_events.saturating_add(1);
            if has_diagnostics(&request) {
                if let Some(slot) = report
                    .retained_request_diagnostics
                    .iter_mut()
                    .find(|slot| slot.is_none())
                {
                    *slot = Some(request);
                } else {
                    report.additional_request_diagnostics =
                        report.additional_request_diagnostics.saturating_add(1);
                }
            }
        }
        Some(gateway::Event::ListenerLost(index)) => {
            if !reporter.failed()
                && let Some(error) = runtime
                    .report()
                    .listener_errors
                    .get(index)
                    .and_then(Option::as_ref)
            {
                reporter.warning(
                    "dns2gns.listener.error",
                    format_args!("Original listener {index}: {error}"),
                );
            }
        }
        _ => {}
    }
}
async fn active(
    runtime: &mut gateway::Runtime,
    resolver: &mut Driver<16, 64>,
    control: &mut Control,
    reporter: &Reporter,
    report: &mut Report,
    errors: &mut Errors,
) {
    let events = Cell::new(Observed::default());
    let mut cursor = 0;
    loop {
        events.set(Observed::default());
        let turn = {
            let mut driving = std::pin::pin!(
                resolver
                    .drive_waiting(None, |event| resolver_observation(event, &events, reporter))
            );
            poll_fn(|cx| {
                let mut turn = Turn::default();
                reporter.register(cx);
                // Native-only guards precede any canonical wait/provider effect.
                // Runtime emits at most one event before returning to this gate.
                if let Some(progress) = runtime.poll_native_guard(cx, &mut |event| {
                    gateway_observation(event, &mut turn.event, reporter)
                }) {
                    turn.gateway = Some(Ok(progress));
                }
                if let Poll::Ready(result) = control.poll(cx) {
                    turn.signal = Some(result);
                }
                if turn.ready() {
                    return Poll::Ready(turn);
                }
                for offset in 0..2 {
                    if reporter.failed() {
                        turn.signal = Some(Ok(()));
                        break;
                    }
                    if let Some(progress) = runtime.poll_native_guard(cx, &mut |event| {
                        gateway_observation(event, &mut turn.event, reporter)
                    }) {
                        turn.gateway = Some(Ok(progress));
                        break;
                    }
                    match (cursor + offset) % 2 {
                        0 => {
                            if let Poll::Ready(result) = runtime.poll(cx, &mut |event| {
                                gateway_observation(event, &mut turn.event, reporter)
                            }) {
                                turn.gateway = Some(result);
                            }
                        }
                        _ => {
                            if let Poll::Ready(result) = driving.as_mut().poll(cx) {
                                turn.resolver = Some(result);
                            }
                            let value = events.get();
                            if value.lost.is_some() || value.unavailable {
                                break;
                            }
                        }
                    }
                    if turn.event.is_some()
                        || matches!(&turn.gateway, Some(Err(_) | Ok(gateway::Progress::Closed)))
                        || matches!(&turn.resolver, Some(Err(_)))
                    {
                        break;
                    }
                }
                cursor = (cursor + 1) % 2;
                if turn.ready() || events.get().changed {
                    Poll::Ready(turn)
                } else {
                    Poll::Pending
                }
            })
            .await
        };
        take_gateway_event(turn.event, runtime, reporter, report);
        take_resolver_errors(resolver, report);
        apply_observation(events.get(), errors);
        if let Some(result) = turn.signal {
            report.stopped = true;
            if let Err(error) = result {
                errors.signal = Some(error);
            }
        }
        if let Some(Err(error)) = turn.resolver {
            errors.resolver = Some(error);
        }
        if let Some(result) = turn.gateway {
            match result {
                Err(error) => errors.runtime = Some(error),
                Ok(gateway::Progress::Closed) => {
                    report.closed_observed = true;
                    errors.original = Some("gateway closed without a requested stop".into());
                }
                Ok(gateway::Progress::Activity) => {}
            }
        }
        if errors.failed() || report.stopped || reporter.failed() {
            break;
        }
        tokio::task::yield_now().await;
    }
}
struct Closing {
    hard: Instant,
    alarm: std::pin::Pin<Box<Sleep>>,
}
impl Closing {
    fn new() -> Result<Self, Fault> {
        let hard = Instant::now()
            .checked_add(Duration::from_secs(5))
            .ok_or(Fault::Overflow)?;
        Ok(Self {
            hard,
            alarm: Box::pin(tokio::time::sleep_until(hard)),
        })
    }
    fn expired(&mut self, cx: &mut std::task::Context<'_>) -> bool {
        Instant::now() >= self.hard || self.alarm.as_mut().poll(cx).is_ready()
    }
}
async fn close(
    runtime: &mut gateway::Runtime,
    resolver: &mut Driver<16, 64>,
    reporter: &Reporter,
    report: &mut Report,
    errors: &mut Errors,
) {
    // Capture once. This is only a bounded observation window for the same
    // original close, never a claim of worker join or remote VPN revocation.
    let mut closing = Closing::new();
    runtime.begin_close();
    let closing = match closing.as_mut() {
        Ok(closing) => closing,
        Err(error) => {
            errors.cleanup_timeout = Some(*error);
            return;
        }
    };
    let events = Cell::new(Observed::default());
    let mut cursor = 0;
    loop {
        if runtime.is_closed() {
            report.closed_observed = true;
            break;
        }
        events.set(Observed::default());
        let turn = {
            let mut driving = std::pin::pin!(resolver.drive_waiting(Some(closing.hard), |event| {
                resolver_observation(event, &events, reporter)
            }));
            poll_fn(|cx| {
                let mut turn = Turn::default();
                reporter.register(cx);
                if let Some(progress) = runtime.poll_native_guard(cx, &mut |event| {
                    gateway_observation(event, &mut turn.event, reporter)
                }) {
                    turn.gateway = Some(Ok(progress));
                }
                if closing.expired(cx) {
                    turn.timed_out = true;
                    return Poll::Ready(turn);
                }
                if turn.ready() {
                    return Poll::Ready(turn);
                }
                for offset in 0..2 {
                    if closing.expired(cx) {
                        turn.timed_out = true;
                        break;
                    }
                    match (cursor + offset) % 2 {
                        0 => {
                            if let Poll::Ready(result) = runtime.poll_close(cx, &mut |event| {
                                gateway_observation(event, &mut turn.event, reporter)
                            }) {
                                turn.gateway = Some(result);
                            }
                        }
                        _ if !reporter.failed() && !errors.failed() => {
                            if let Poll::Ready(result) = driving.as_mut().poll(cx) {
                                turn.resolver = Some(result);
                            }
                            let value = events.get();
                            if value.lost.is_some() || value.unavailable {
                                break;
                            }
                        }
                        _ => {}
                    }
                    if turn.event.is_some()
                        || matches!(&turn.gateway, Some(Err(_) | Ok(gateway::Progress::Closed)))
                        || matches!(&turn.resolver, Some(Err(_)))
                    {
                        break;
                    }
                }
                cursor = (cursor + 1) % 2;
                if turn.ready() || events.get().changed {
                    Poll::Ready(turn)
                } else {
                    Poll::Pending
                }
            })
            .await
        };
        take_gateway_event(turn.event, runtime, reporter, report);
        take_resolver_errors(resolver, report);
        apply_observation(events.get(), errors);
        if let Some(Err(error)) = turn.resolver
            && errors.resolver.is_none()
        {
            errors.resolver = Some(error);
        }
        if let Some(result) = turn.gateway {
            match result {
                Ok(gateway::Progress::Closed) => report.closed_observed = true,
                Ok(gateway::Progress::Activity) => {}
                Err(error) => {
                    if errors.close.is_none() {
                        errors.close = Some(error);
                    } else {
                        errors.additional_close_errors =
                            errors.additional_close_errors.saturating_add(1);
                    }
                }
            }
        }
        if turn.timed_out {
            errors.cleanup_timeout = Some(Fault::Deadline);
            break;
        }
        if report.closed_observed {
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
    let mut errors = Errors::default();
    let mut runtime = None;
    let outcome = async {
        let mut control = Control::new(parent, stop, reporter.clone())?;
        if let Poll::Ready(result) = poll_fn(|cx| Poll::Ready(control.poll(cx))).await {
            report.stopped = true;
            result?;
            return Ok::<(), Cause>(());
        }
        let resolution = context.resolution_context();
        let ports = gateway::Ports {
            gns: EndpointSource::live(live.clone(), b"gns", resolution.clone()),
            identity: EndpointSource::live(live.clone(), b"identity", resolution.clone()),
            vpn: EndpointSource::live(live, b"vpn", resolution),
            configuration: Arc::new(configuration),
            clock: source,
            upstream: settings.upstream,
        };
        let original = gateway::Runtime::new(
            gateway::BindOptions {
                ipv4: settings.ipv4,
                ipv6: settings.ipv6,
            },
            ports,
            gateway::Limits::default(),
        )?;
        runtime = Some(original);
        if let Some(owner) = runtime.as_mut() {
            for binding in &owner.report().bindings {
                if reporter.failed() {
                    break;
                }
                if let Some(error) = &binding.error {
                    reporter.warning(
                        "dns2gns.bind.failed",
                        format_args!("Original listener {}: {error}", binding.requested),
                    );
                }
                if !reporter.failed()
                    && let Some(local) = binding.local
                {
                    reporter.debug(
                        "dns2gns.bound",
                        format_args!("Actual local UDP listener: {local}"),
                    );
                }
            }
            if !reporter.failed() {
                active(
                    owner,
                    &mut resolver,
                    &mut control,
                    &reporter,
                    &mut report,
                    &mut errors,
                )
                .await;
            }
        }
        Ok(())
    }
    .await;
    if let Err(error) = outcome {
        errors.original = Some(error);
    }
    if let Some(mut owner) = runtime {
        close(
            &mut owner,
            &mut resolver,
            &reporter,
            &mut report,
            &mut errors,
        )
        .await;
        report.gateway = Some(owner.into_report());
    }
    take_resolver_errors(&mut resolver, &mut report);
    match context.pending_requests() {
        Ok(count) => report.resolver_pending = Some(count),
        Err(error) => {
            if errors.resolver.is_none() {
                errors.resolver = Some(error);
            }
        }
    }
    match resolver.queued_frames() {
        Ok(count) => report.resolver_queued = Some(count),
        Err(error) => {
            if errors.resolver.is_none() {
                errors.resolver = Some(error);
            }
        }
    }
    match resolver.disconnect() {
        Ok(()) => report.resolver_disconnected = true,
        Err(error) => errors.disconnect = Some(error),
    }
    take_resolver_errors(&mut resolver, &mut report);
    drop(resolver);
    report.resolver_dropped = true;
    reporter.debug(
        "dns2gns.stopped",
        format_args!("Actual gateway/physical retirement facts: {report:?}"),
    );
    errors.logging = reporter.take_error();
    if errors.failed() {
        Err(Box::new(Failed { report, errors }))
    } else {
        Ok(report)
    }
}
