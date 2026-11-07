//! One original query and one actual process Resolver owner through finally.
use crate::{
    Cause,
    budget::Budget,
    control::Control,
    options::{Request, Settings},
    output::{self, Callback, Line, Output},
};
use gnunet_program_host::reporting::Reporter;
use gnunet_resolver_broker::{
    BrokerError, Completion, Context as Broker, Driver, DriverEvent, Family, Query, Token,
};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_service_startup::ParentControl;
use gnunet_types::{Duration, Error as Fault, GenerationalId};
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
pub(super) struct Inputs {
    pub settings: Settings,
    pub context: Broker<16, 64>,
    pub resolver: Driver<16, 64>,
    pub source: Arc<dyn RuntimeClock>,
    pub reporter: Reporter,
    pub stop: Rc<Cell<bool>>,
    pub parent: Option<ParentControl>,
    pub output: Stdout,
}
#[derive(Default)]
pub(super) struct Report {
    token: Option<GenerationalId>,
    rows: usize,
    lines_written: usize,
    bytes_written: usize,
    completion: Option<Completion>,
    stopped: bool,
    stream_closed: bool,
    cancelled: bool,
    disconnect: bool,
    driver_dropped: bool,
    pending_requests: Option<usize>,
    queued_frames: Option<usize>,
    pending_line: Option<(usize, usize)>,
    connected: Option<u64>,
    idle_closed: Option<u64>,
    socket_retries: u64,
    io_errors: [Option<io::Error>; 4],
    connect_errors: [Option<BrokerError>; 4],
    additional_errors: u64,
}
impl fmt::Debug for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolverReport")
            .field("token", &self.token)
            .field("rows", &self.rows)
            .field("lines_written", &self.lines_written)
            .field("bytes_written", &self.bytes_written)
            .field("completion", &self.completion)
            .field("stopped", &self.stopped)
            .field("stream_closed", &self.stream_closed)
            .field("cancelled", &self.cancelled)
            .field("disconnect", &self.disconnect)
            .field("driver_dropped", &self.driver_dropped)
            .field("pending_requests", &self.pending_requests)
            .field("queued_frames", &self.queued_frames)
            .field("pending_line", &self.pending_line)
            .field("connected", &self.connected)
            .field("idle_closed", &self.idle_closed)
            .field("socket_retries", &self.socket_retries)
            .field("io_errors", &self.io_errors)
            .field("connect_errors", &self.connect_errors)
            .field("additional_errors", &self.additional_errors)
            .finish()
    }
}
#[derive(Default, Debug)]
struct Errors {
    original: [Option<Cause>; 4],
    additional: u64,
    cancel: Option<BrokerError>,
    signal: Option<io::Error>,
    output: Option<io::Error>,
    driver: Option<BrokerError>,
    disconnect: Option<BrokerError>,
    source_lost: Option<(u64, Fault)>,
    unavailable: bool,
    logging: Option<io::Error>,
}
impl Errors {
    fn record(&mut self, error: Cause) {
        if let Some(slot) = self.original.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(error);
        } else {
            self.additional = self.additional.saturating_add(1);
        }
    }
    fn failed(&self) -> bool {
        self.original.iter().any(Option::is_some)
            || self.additional != 0
            || self.cancel.is_some()
            || self.signal.is_some()
            || self.output.is_some()
            || self.driver.is_some()
            || self.disconnect.is_some()
            || self.source_lost.is_some()
            || self.unavailable
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
            "Resolver query terminal facts: {:?}; causes: {:?}",
            self.report, self.errors
        )
    }
}
impl Error for Failed {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.errors
            .original
            .iter()
            .find_map(|error| error.as_deref())
            .or_else(|| self.errors.cancel.as_ref().map(|error| error as &dyn Error))
            .or_else(|| self.errors.signal.as_ref().map(|error| error as &dyn Error))
            .or_else(|| self.errors.output.as_ref().map(|error| error as &dyn Error))
            .or_else(|| self.errors.driver.as_ref().map(|error| error as &dyn Error))
            .or_else(|| {
                self.errors
                    .disconnect
                    .as_ref()
                    .map(|error| error as &dyn Error)
            })
            .or_else(|| {
                self.errors
                    .source_lost
                    .as_ref()
                    .map(|(_, error)| error as &dyn Error)
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
    connected: Option<u64>,
    lost: Option<(u64, Fault)>,
    unavailable: bool,
    idle: Option<u64>,
    retries: u64,
    changed: bool,
}
fn observation(event: DriverEvent, cell: &Cell<Observed>, reporter: &Reporter) {
    let mut current = cell.get();
    current.changed = true;
    match event {
        DriverEvent::Connected(epoch) => current.connected = Some(epoch.value()),
        DriverEvent::SocketRetry { .. } => current.retries = current.retries.saturating_add(1),
        DriverEvent::Lost { epoch, cause } => current.lost = Some((epoch.value(), cause)),
        DriverEvent::Unavailable => current.unavailable = true,
        DriverEvent::IdleClosed(epoch) => current.idle = Some(epoch.value()),
    }
    cell.set(current);
    reporter.debug(
        "resolver.driver.activity",
        format_args!("Resolver owner: {event:?}"),
    );
}
fn take_errors(driver: &mut Driver<16, 64>, report: &mut Report) {
    if let Some(error) = driver.take_io_error() {
        if let Some(slot) = report.io_errors.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(error);
        } else {
            report.additional_errors = report.additional_errors.saturating_add(1);
        }
    }
    if let Some(error) = driver.take_connect_error() {
        if let Some(slot) = report.connect_errors.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(error);
        } else {
            report.additional_errors = report.additional_errors.saturating_add(1);
        }
    }
}
fn observed(value: Observed, report: &mut Report, errors: &mut Errors) {
    if value.connected.is_some() {
        report.connected = value.connected;
    }
    if value.idle.is_some() {
        report.idle_closed = value.idle;
    }
    report.socket_retries = report.socket_retries.saturating_add(value.retries);
    if let Some(lost) = value.lost {
        errors.source_lost = Some(lost);
    }
    errors.unavailable |= value.unavailable;
}
#[derive(Default)]
struct Turn {
    callback: Option<Result<Option<Callback>, Cause>>,
    output: Option<io::Result<usize>>,
    driver: Option<Result<gnunet_resolver_broker::Progress, BrokerError>>,
    signal: Option<io::Result<()>>,
    failure: Option<Cause>,
}
impl Turn {
    fn ready(&self) -> bool {
        self.callback.is_some()
            || self.output.is_some()
            || self.driver.is_some()
            || self.signal.is_some()
            || self.failure.is_some()
    }
}
struct Driving<'a> {
    budget: &'a mut Budget,
    output: &'a mut Output,
    control: &'a mut Control,
    driver: &'a mut Driver<16, 64>,
    reporter: &'a Reporter,
    settings: &'a Settings,
    report: &'a mut Report,
    errors: &'a mut Errors,
    pending: &'a mut Option<Line>,
}
async fn active(query: &mut Query<16, 64>, ports: Driving<'_>) {
    let Driving {
        budget,
        output,
        control,
        driver,
        reporter,
        settings,
        report,
        errors,
        pending,
    } = ports;
    let expected: Token = query.token();
    let reverse = matches!(&settings.request, Request::Reverse(_));
    let events = Cell::new(Observed::default());
    let mut cursor = 0;
    let mut queued_bytes = 0usize;
    loop {
        events.set(Observed::default());
        let turn = {
            let mut reading = std::pin::pin!(query.next());
            let mut driving =
                std::pin::pin!(driver.drive_waiting(Some(budget.hard), |event| observation(
                    event, &events, reporter
                )));
            poll_fn(|cx| {
                let mut turn = Turn::default();
                reporter.register(cx);
                if let Err(error) = budget.poll(cx) {
                    turn.failure = Some(Box::new(error));
                    return Poll::Ready(turn);
                }
                if let Poll::Ready(result) = control.poll(cx) {
                    turn.signal = Some(result);
                    return Poll::Ready(turn);
                }
                for offset in 0..3 {
                    if reporter.failed() {
                        turn.signal = Some(Ok(()));
                        break;
                    }
                    if let Err(error) = budget.native_guard(cx) {
                        turn.failure = Some(Box::new(error));
                        break;
                    }
                    match (cursor + offset) % 3 {
                        0 => {
                            if pending.is_none()
                                && let Poll::Ready(result) = reading.as_mut().poll(cx)
                            {
                                let value = match result {
                                    Err(error) => Err(Box::new(error) as Cause),
                                    Ok(None) => Ok(None),
                                    Ok(Some(delivery)) => {
                                        let result = if delivery.token() != &expected {
                                            Err("foreign Resolver callback token".into())
                                        } else {
                                            delivery
                                                .reply()
                                                .map_err(|error| Box::new(error) as Cause)
                                                .and_then(|reply| output::copy(reply, reverse))
                                                .map(Some)
                                        };
                                        drop(delivery);
                                        result
                                    }
                                };
                                turn.callback = Some(value);
                            }
                        }
                        1 => {
                            if let Poll::Ready(result) = driving.as_mut().poll(cx) {
                                turn.driver = Some(result);
                            }
                            let now = events.get();
                            if now.lost.is_some() || now.unavailable {
                                break;
                            }
                        }
                        _ => {
                            if let Some(line) = pending.as_mut()
                                && let Poll::Ready(result) = output.poll(cx, line)
                            {
                                turn.output = Some(result);
                            }
                        }
                    }
                    if matches!(
                        &turn.callback,
                        Some(Err(_) | Ok(None) | Ok(Some(Callback::Complete(_))))
                    ) || matches!(&turn.output, Some(Err(_)))
                        || matches!(&turn.driver, Some(Err(_)))
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
        take_errors(driver, report);
        observed(events.get(), report, errors);
        if let Some(error) = turn.failure {
            errors.record(error);
        }
        if let Some(result) = turn.signal {
            report.stopped = true;
            if let Err(error) = result {
                errors.signal = Some(error);
            }
        }
        if let Some(result) = turn.driver
            && let Err(error) = result
        {
            errors.driver = Some(error);
        }
        if let Some(result) = turn.output {
            match result {
                Ok(count) => {
                    report.bytes_written = report.bytes_written.saturating_add(count);
                    if pending.as_ref().is_some_and(Line::finished) {
                        report.lines_written += 1;
                        drop(pending.take());
                    }
                }
                Err(error) => errors.output = Some(error),
            }
        }
        if let Some(result) = turn.callback {
            match result {
                Err(error) => errors.record(error),
                Ok(None) => {
                    report.stream_closed = true;
                    errors.record(
                        io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "original Resolver stream closed without a terminal callback",
                        )
                        .into(),
                    );
                }
                Ok(Some(Callback::Complete(reason))) => {
                    report.completion = Some(reason);
                    if reason != Completion::End {
                        errors.record(format!("original Resolver completion: {reason:?}").into());
                    }
                }
                Ok(Some(Callback::Line(line))) => {
                    report.rows += 1;
                    match queued_bytes.checked_add(line.len()) {
                        Some(bytes)
                            if report.rows <= settings.maximum_results
                                && bytes <= settings.maximum_output_bytes =>
                        {
                            queued_bytes = bytes;
                            *pending = Some(line);
                        }
                        _ => {
                            errors.record("bounded Resolver result/output capacity exceeded".into())
                        }
                    }
                }
            }
        }
        if errors.failed() || report.stopped || report.completion.is_some() || reporter.failed() {
            break;
        }
        tokio::task::yield_now().await;
    }
}
async fn cleanup(ports: Driving<'_>, context: &Broker<16, 64>) {
    let Driving {
        budget,
        output,
        control: _,
        driver,
        reporter,
        settings: _,
        report,
        errors,
        pending,
    } = ports;
    let events = Cell::new(Observed::default());
    let mut cursor = 0;
    loop {
        if errors.failed() || reporter.failed() {
            break;
        }
        let need_driver = match context.pending_requests() {
            Ok(count) => {
                report.pending_requests = Some(count);
                if count == 0 && pending.is_none() {
                    break;
                }
                count != 0
            }
            Err(error) => {
                errors.driver = Some(error);
                break;
            }
        };
        events.set(Observed::default());
        let turn = {
            let mut driving =
                std::pin::pin!(driver.drive_waiting(Some(budget.hard), |event| observation(
                    event, &events, reporter
                )));
            poll_fn(|cx| {
                let mut turn = Turn::default();
                reporter.register(cx);
                if let Err(error) = budget.poll(cx) {
                    turn.failure = Some(Box::new(error));
                    return Poll::Ready(turn);
                }
                if reporter.failed() {
                    return Poll::Ready(turn);
                }
                for offset in 0..2 {
                    if reporter.failed() {
                        break;
                    }
                    if let Err(error) = budget.native_guard(cx) {
                        turn.failure = Some(Box::new(error));
                        break;
                    }
                    match (cursor + offset) % 2 {
                        0 => {
                            if need_driver && let Poll::Ready(result) = driving.as_mut().poll(cx) {
                                turn.driver = Some(result);
                            }
                            let now = events.get();
                            if now.lost.is_some() || now.unavailable {
                                break;
                            }
                        }
                        _ => {
                            if let Some(line) = pending.as_mut()
                                && let Poll::Ready(result) = output.poll(cx, line)
                            {
                                turn.output = Some(result);
                            }
                        }
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
        take_errors(driver, report);
        observed(events.get(), report, errors);
        if let Some(error) = turn.failure {
            errors.record(error);
        }
        if let Some(result) = turn.driver
            && let Err(error) = result
        {
            errors.driver = Some(error);
        }
        if let Some(result) = turn.output {
            match result {
                Ok(count) => {
                    report.bytes_written = report.bytes_written.saturating_add(count);
                    if pending.as_ref().is_some_and(Line::finished) {
                        report.lines_written += 1;
                        drop(pending.take());
                    }
                }
                Err(error) => errors.output = Some(error),
            }
        }
        tokio::task::yield_now().await;
    }
}
pub(super) async fn run(inputs: Inputs) -> Result<Report, Cause> {
    let Inputs {
        settings,
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
    let mut pending = None;
    let outcome = async {
        let mut control = Control::new(parent, stop, reporter.clone())?;
        let mut output = Output::new(output);
        if control.stopped() {
            report.stopped = true;
            return Ok::<(), Cause>(());
        }
        if let Poll::Ready(result) = poll_fn(|cx| Poll::Ready(control.poll(cx))).await {
            report.stopped = true;
            result?;
            return Ok(());
        }
        let mut budget = Budget::new(source)?;
        let initial = poll_fn(|cx| {
            if let Err(error) = budget.poll(cx) {
                return Poll::Ready(Err(Box::new(error) as Cause));
            }
            Poll::Ready(Ok(control.poll(cx)))
        })
        .await?;
        if let Poll::Ready(result) = initial {
            report.stopped = true;
            result?;
            return Ok(());
        }
        let mut query = match &settings.request {
            Request::Forward(name) => context.ip_get(name, Family::Any, Duration(5_000_000))?,
            Request::Reverse(address) => {
                context.hostname_get(*address, true, Duration(5_000_000))?
            }
        };
        report.token = Some(query.token().resource_id());
        active(
            &mut query,
            Driving {
                budget: &mut budget,
                output: &mut output,
                control: &mut control,
                driver: &mut resolver,
                reporter: &reporter,
                settings: &settings,
                report: &mut report,
                errors: &mut errors,
                pending: &mut pending,
            },
        )
        .await;
        if report.completion.is_none() && !report.stream_closed {
            match query.cancel() {
                Ok(()) => report.cancelled = true,
                Err(error) => errors.cancel = Some(error),
            }
        }
        drop(query);
        cleanup(
            Driving {
                budget: &mut budget,
                output: &mut output,
                control: &mut control,
                driver: &mut resolver,
                reporter: &reporter,
                settings: &settings,
                report: &mut report,
                errors: &mut errors,
                pending: &mut pending,
            },
            &context,
        )
        .await;
        Ok(())
    }
    .await;
    if let Err(error) = outcome {
        errors.record(error);
    }
    take_errors(&mut resolver, &mut report);
    match context.pending_requests() {
        Ok(count) => report.pending_requests = Some(count),
        Err(error) => {
            if errors.driver.is_none() {
                errors.driver = Some(error);
            }
        }
    }
    match resolver.queued_frames() {
        Ok(count) => report.queued_frames = Some(count),
        Err(error) => {
            if errors.driver.is_none() {
                errors.driver = Some(error);
            }
        }
    }
    report.pending_line = pending.as_ref().map(|line| (line.len(), line.offset()));
    if let Err(error) = resolver.disconnect() {
        errors.disconnect = Some(error);
    } else {
        report.disconnect = true;
    }
    drop(resolver);
    report.driver_dropped = true;
    drop(pending);
    reporter.debug(
        "resolver.query.stopped",
        format_args!("actual callback/output/close facts: {report:?}"),
    );
    errors.logging = reporter.take_error();
    if errors.failed() {
        Err(Box::new(Failed { report, errors }))
    } else {
        Ok(report)
    }
}
