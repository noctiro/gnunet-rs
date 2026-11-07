//! One original with-TLD owner and the same shared Resolver through finally.
use crate::{
    Cause,
    budget::Budget,
    control::Control,
    options::Settings,
    output::{Output, Projection},
};
use gnunet_client_host::{EndpointSource, LiveConfiguration};
use gnunet_gns_client_host as gns;
use gnunet_gns_host::tld;
use gnunet_identity_client_host as identity;
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
    io::{self, Stdout},
    rc::Rc,
    sync::Arc,
    task::Poll,
};
use tokio::time::Instant;

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
    pub output: Stdout,
}
#[derive(Default, Debug)]
pub(super) struct Report {
    pub code: u8,
    lookup: Option<tld::Diagnostics>,
    close: Option<tld::Diagnostics>,
    projection: Projection,
    output: Option<(usize, usize)>,
    output_complete: bool,
    stopped: bool,
    answer_received: bool,
    not_gns: bool,
    resolver_disconnected: bool,
    resolver_dropped: bool,
    resolver_pending: Option<usize>,
    resolver_queued: Option<usize>,
    connect_retries: u64,
    retry_errors: [Option<io::Error>; 4],
    resolver_io: [Option<io::Error>; 4],
    resolver_connect: [Option<BrokerError>; 4],
    additional_observations: u64,
}
#[derive(Default, Debug)]
struct Errors {
    original: Option<Cause>,
    lookup: Option<tld::Cause>,
    signal: Option<io::Error>,
    output: Option<io::Error>,
    resolver: Option<BrokerError>,
    disconnect: Option<BrokerError>,
    resolver_loss: Option<(u64, Fault)>,
    resolver_unavailable: bool,
    logging: Option<io::Error>,
}
impl Errors {
    fn failed(&self) -> bool {
        self.original.is_some()
            || self.lookup.is_some()
            || self.signal.is_some()
            || self.output.is_some()
            || self.resolver.is_some()
            || self.disconnect.is_some()
            || self.resolver_loss.is_some()
            || self.resolver_unavailable
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
            "GNS query terminal facts: {:?}; causes: {:?}",
            self.report, self.errors
        )
    }
}
impl Error for Failed {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.errors
            .original
            .as_deref()
            .or_else(|| self.errors.lookup.as_ref().map(|e| e as &dyn Error))
            .or_else(|| self.errors.signal.as_ref().map(|e| e as &dyn Error))
            .or_else(|| self.errors.output.as_ref().map(|e| e as &dyn Error))
            .or_else(|| self.errors.resolver.as_ref().map(|e| e as &dyn Error))
            .or_else(|| self.errors.disconnect.as_ref().map(|e| e as &dyn Error))
            .or_else(|| {
                self.errors
                    .resolver_loss
                    .as_ref()
                    .map(|(_, e)| e as &dyn Error)
            })
            .or_else(|| self.errors.logging.as_ref().map(|e| e as &dyn Error))
    }
}
fn cleanup_failed(report: &tld::Diagnostics) -> bool {
    report.gns_cancel_error.is_some() || report.identity_cancel_error.is_some()
}
fn retry(error: io::Error, report: &mut Report) {
    report.connect_retries = report.connect_retries.saturating_add(1);
    if let Some(slot) = report.retry_errors.iter_mut().find(|e| e.is_none()) {
        *slot = Some(error);
    } else {
        report.additional_observations = report.additional_observations.saturating_add(1);
    }
}
fn take_resolver_errors(driver: &mut Driver<16, 64>, report: &mut Report) {
    if let Some(error) = driver.take_io_error() {
        if let Some(slot) = report.resolver_io.iter_mut().find(|e| e.is_none()) {
            *slot = Some(error);
        } else {
            report.additional_observations = report.additional_observations.saturating_add(1);
        }
    }
    if let Some(error) = driver.take_connect_error() {
        if let Some(slot) = report.resolver_connect.iter_mut().find(|e| e.is_none()) {
            *slot = Some(error);
        } else {
            report.additional_observations = report.additional_observations.saturating_add(1);
        }
    }
}
#[derive(Clone, Copy, Default)]
struct Observed {
    changed: bool,
    lost: Option<(u64, Fault)>,
    unavailable: bool,
}
fn observe(event: DriverEvent, cell: &Cell<Observed>, reporter: &Reporter) {
    let mut value = cell.get();
    value.changed = true;
    match event {
        DriverEvent::Lost { epoch, cause } => value.lost = Some((epoch.value(), cause)),
        DriverEvent::Unavailable => value.unavailable = true,
        _ => {}
    }
    cell.set(value);
    reporter.debug(
        "gns.resolver.activity",
        format_args!("Resolver source: {event:?}"),
    );
}
#[derive(Default)]
struct Turn<'gns, 'id> {
    lookup: Option<Result<tld::Progress<'gns, 'id>, tld::Failure<'gns, 'id>>>,
    output: Option<io::Result<usize>>,
    resolver: Option<Result<gnunet_resolver_broker::Progress, BrokerError>>,
    signal: Option<io::Result<()>>,
    budget: Option<Fault>,
}
impl Turn<'_, '_> {
    fn ready(&self) -> bool {
        self.lookup.is_some()
            || self.output.is_some()
            || self.resolver.is_some()
            || self.signal.is_some()
            || self.budget.is_some()
    }
}
struct Ports<'a> {
    settings: &'a Settings,
    budget: &'a mut Budget,
    control: &'a mut Control,
    output: &'a mut Output,
    resolver: &'a mut Driver<16, 64>,
    reporter: &'a Reporter,
    report: &'a mut Report,
    errors: &'a mut Errors,
}
async fn query(owner: &mut tld::Lookup<'_, '_>, ports: Ports<'_>) {
    let Ports {
        settings,
        budget,
        control,
        output,
        resolver,
        reporter,
        report,
        errors,
    } = ports;
    let events = Cell::new(Observed::default());
    let started = Instant::now();
    let mut terminal = false;
    let mut cursor = 0;
    loop {
        if terminal && output.finished() {
            report.output_complete = true;
            break;
        }
        events.set(Observed::default());
        let turn = {
            let mut driving = std::pin::pin!(
                resolver.drive_waiting(budget.hard, |event| observe(event, &events, reporter))
            );
            poll_fn(|cx| {
                let mut turn = Turn::default();
                reporter.register(cx);
                if let Poll::Ready(result) = control.poll(cx) {
                    turn.signal = Some(result);
                }
                if let Some(failure) = owner.poll_native_guard(cx) {
                    turn.lookup = Some(Err(failure));
                }
                if turn.ready() {
                    return Poll::Ready(turn);
                }
                if let Err(error) = budget.poll(cx) {
                    turn.budget = Some(error);
                    return Poll::Ready(turn);
                }
                for offset in 0..3 {
                    if reporter.failed() {
                        turn.signal = Some(Ok(()));
                        break;
                    }
                    if let Err(error) = budget.native_guard(cx) {
                        turn.budget = Some(error);
                        break;
                    }
                    match (cursor + offset) % 3 {
                        0 if !terminal => {
                            if let Poll::Ready(result) = owner.poll(cx) {
                                turn.lookup = Some(result);
                            }
                        }
                        1 => {
                            if let Poll::Ready(result) = driving.as_mut().poll(cx) {
                                turn.resolver = Some(result);
                            }
                            let event = events.get();
                            if event.lost.is_some() || event.unavailable {
                                break;
                            }
                        }
                        _ => {
                            if let Poll::Ready(result) = output.poll(cx) {
                                turn.output = Some(result);
                            }
                        }
                    }
                    if matches!(
                        &turn.lookup,
                        Some(Err(_) | Ok(tld::Progress::Finished(_) | tld::Progress::Closed))
                    ) || matches!(&turn.resolver, Some(Err(_)))
                        || matches!(&turn.output, Some(Err(_)))
                    {
                        break;
                    }
                }
                cursor = (cursor + 1) % 3;
                if turn.ready() || events.get().changed {
                    Poll::Ready(turn)
                } else {
                    Poll::Pending
                }
            })
            .await
        };
        take_resolver_errors(resolver, report);
        let event = events.get();
        if event.lost.is_some() {
            errors.resolver_loss = event.lost;
        }
        errors.resolver_unavailable |= event.unavailable;
        if let Some(error) = turn.budget {
            errors.original = Some(error.into());
        }
        if let Some(result) = turn.signal {
            report.stopped = true;
            if let Err(error) = result {
                errors.signal = Some(error);
            }
        }
        if let Some(Err(error)) = turn.output {
            errors.output = Some(error);
        }
        if let Some(Err(error)) = turn.resolver {
            errors.resolver = Some(error);
        }
        if let Some(result) = turn.lookup {
            match result {
                Err(failure) => {
                    let (cause, diagnostics) = failure.into_diagnostics();
                    errors.lookup = Some(cause);
                    report.lookup = Some(diagnostics);
                }
                Ok(tld::Progress::Finished(tld::Outcome::Answer {
                    answer,
                    report: retired,
                })) => {
                    report.answer_received = true;
                    report.lookup = Some(retired.into_diagnostics());
                    terminal = true;
                    if !errors.failed()
                        && !report.stopped
                        && !reporter.failed()
                        && let Err(error) = output.answer(
                            &answer,
                            settings.raw,
                            reporter,
                            &mut report.projection,
                            started.elapsed(),
                            budget.hard,
                        )
                    {
                        errors.original = Some(error);
                    }
                }
                Ok(tld::Progress::Finished(tld::Outcome::NotGns { report: retired })) => {
                    report.not_gns = true;
                    report.code = 4;
                    report.lookup = Some(retired.into_diagnostics());
                    terminal = true;
                    reporter.debug(
                        "gns.not-gns",
                        format_args!("Actual user-name routing returned NotGns"),
                    );
                }
                Ok(tld::Progress::Closed) => {
                    errors.original = Some(
                        "original GNS owner closed without a transferred terminal outcome".into(),
                    );
                }
                Ok(
                    tld::Progress::Gns(gns::Progress::ConnectRetry { error, .. })
                    | tld::Progress::Identity(identity::Progress::ConnectRetry { error, .. }),
                ) => retry(error, report),
                Ok(_) => reporter.debug(
                    "gns.lookup.activity",
                    format_args!("Original lookup source progressed"),
                ),
            }
        }
        if errors.failed() || report.stopped || reporter.failed() {
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
        output,
    } = inputs;
    let mut report = Report::default();
    let mut errors = Errors::default();
    let mut output = Output::new(output, settings.maximum_output_bytes);
    let outcome = async {
        let mut control = Control::new(parent, stop, reporter.clone())?;
        if control.stopped() {
            report.stopped = true;
            return Ok::<(), Cause>(());
        }
        if let Poll::Ready(result) = poll_fn(|cx| Poll::Ready(control.poll(cx))).await {
            report.stopped = true;
            result?;
            return Ok(());
        }
        // Capture the finite native target before the first canonical sample.
        // The official FOREVER profile has neither a MAX timer nor a new budget.
        let mut budget = Budget::new(source, settings.timeout)?;
        let checked = poll_fn(|cx| {
            budget.poll(cx).map_err(|error| Box::new(error) as Cause)?;
            Poll::Ready(Ok::<_, Cause>(control.poll(cx)))
        })
        .await?;
        if let Poll::Ready(result) = checked {
            report.stopped = true;
            result?;
            return Ok(());
        }
        let bounds = tld::Bounds {
            until: budget.until.as_micros(),
            hard: budget.hard,
        };
        let resolution = context.resolution_context();
        let sources = tld::Sources {
            gns: EndpointSource::live(live.clone(), b"gns", resolution.clone()),
            identity: EndpointSource::live(live, b"identity", resolution),
        };
        let mut gns_instance = gns::Instance::new();
        let identity_instance = identity::Instance::new();
        let mut owner = tld::Lookup::new(
            &mut gns_instance,
            &identity_instance,
            sources,
            &configuration,
            tld::Request {
                name: &settings.name,
                record_type: settings.record_type,
                options: gns::LocalOptions::DEFAULT,
                recursion_depth: 128,
            },
            bounds,
            tld::Limits::default(),
        )?;
        // From this point every fallible branch reaches the same owner's cancel.
        let body = async {
            output.looking(&settings)?;
            query(
                &mut owner,
                Ports {
                    settings: &settings,
                    budget: &mut budget,
                    control: &mut control,
                    output: &mut output,
                    resolver: &mut resolver,
                    reporter: &reporter,
                    report: &mut report,
                    errors: &mut errors,
                },
            )
            .await;
            Ok::<(), Cause>(())
        }
        .await;
        report.close = owner.cancel().map(tld::Report::into_diagnostics);
        drop(owner);
        body
    }
    .await;
    if let Err(error) = outcome {
        errors.original = Some(error);
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
    report.output = Some(output.extent());
    drop(output);
    reporter.debug(
        "gns.query.stopped",
        format_args!("Actual query/output/physical retirement facts: {report:?}"),
    );
    errors.logging = reporter.take_error();
    if errors.failed()
        || report.lookup.as_ref().is_some_and(cleanup_failed)
        || report.close.as_ref().is_some_and(cleanup_failed)
    {
        Err(Box::new(Failed { report, errors }))
    } else {
        Ok(report)
    }
}
