//! Actual original handle/WID/epoch lifecycle, with one held output and no hidden task.
use super::{Failure, control::Signals, output::Output};
use gnunet_client::{
    statistics::{Selector, WatchValue},
    statistics_handle::{ConnectionEpoch, DestroyReport, GetFlow, WatchId},
};
use gnunet_client_host::{LiveConfiguration, resolution::SharedResolution};
use gnunet_ipc_unix::{
    IpcError,
    handle::{self, Event, Progress},
};
use gnunet_program_host::reporting::Reporter;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_service_startup::ParentControl;
use gnunet_types::Error;
use std::{
    cell::{Cell, RefCell},
    future::{Future, poll_fn},
    io,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
type Owner<'id> = handle::StatisticsHandle<'id, 2, 512, 1, 1, 2>;
const ADMISSION: Duration = Duration::from_secs(30);
const ROW: Duration = Duration::from_secs(30);
const CLEANUP: Duration = Duration::from_secs(5);
const CADENCE: Duration = Duration::from_millis(10);
pub(super) struct Names {
    pub subsystem: Vec<u8>,
    pub name: Vec<u8>,
}
impl Names {
    pub(super) fn selector(&self) -> Selector<'_> {
        Selector {
            subsystem: &self.subsystem,
            name: &self.name,
        }
    }
}
pub(super) struct Inputs {
    pub selector: Names,
    pub parent: Option<ParentControl>,
    pub live: LiveConfiguration,
    pub resolution: SharedResolution,
    pub source: Arc<dyn RuntimeClock>,
    pub reports: Reporter,
    pub stop: Rc<Cell<bool>>,
    pub resolver: gnunet_resolver_broker::Driver<4, 256>,
}
#[derive(Default)]
pub(super) struct Report {
    pub(super) notifications: u64,
    pub(super) rows_written: u64,
    pub(super) epochs: u64,
    pub(super) losses: u64,
    pub(super) connect_retries: u64,
    pub(super) current_epoch: Option<u64>,
    pub(super) last_loss: Option<(u64, Error)>,
    pub(super) registration_whole_written: bool,
    pub(super) output_prefix: usize,
    pub(super) output_total: usize,
    pub(super) cancelled_original: bool,
    pub(super) destroyed: Option<DestroyReport>,
    pub(super) physical_drop: bool,
    pub(super) latest_retry_io: Option<io::Error>,
    pub(super) latest_retry_connection: Option<IpcError>,
}
impl std::fmt::Debug for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Report")
            .field("notifications", &self.notifications)
            .field("rows_written", &self.rows_written)
            .field("epochs", &self.epochs)
            .field("losses", &self.losses)
            .field("connect_retries", &self.connect_retries)
            .field("current_epoch", &self.current_epoch)
            .field("last_loss", &self.last_loss)
            .field(
                "registration_whole_written",
                &self.registration_whole_written,
            )
            .field("output_prefix", &self.output_prefix)
            .field("output_total", &self.output_total)
            .field("cancelled_original", &self.cancelled_original)
            .field("destroyed", &self.destroyed)
            .field("physical_drop", &self.physical_drop)
            .field("latest_retry_io", &self.latest_retry_io)
            .field("latest_retry_connection", &self.latest_retry_connection)
            .finish()
    }
}
#[derive(Debug, Default)]
pub(super) struct Errors {
    pub(super) original: Option<Failure>,
    pub(super) native: Option<IpcError>,
    pub(super) protocol: Option<Error>,
    pub(super) output: Option<io::Error>,
    pub(super) cancel: Option<IpcError>,
    pub(super) destroy: Option<IpcError>,
    pub(super) terminal: Option<IpcError>,
    pub(super) transport: Option<io::Error>,
    pub(super) connection: Option<IpcError>,
    pub(super) resolver: Option<Failure>,
    pub(super) resolver_drain: Option<Failure>,
    pub(super) resolver_close: Option<Failure>,
    pub(super) stdout_flush: Option<io::Error>,
    pub(super) logging: Option<io::Error>,
    pub(super) deadline: bool,
}
impl Errors {
    pub(super) fn failed(&self) -> bool {
        self.original.is_some()
            || self.native.is_some()
            || self.protocol.is_some()
            || self.output.is_some()
            || self.cancel.is_some()
            || self.destroy.is_some()
            || self.terminal.is_some()
            || self.transport.is_some()
            || self.connection.is_some()
            || self.resolver.is_some()
            || self.resolver_drain.is_some()
            || self.resolver_close.is_some()
            || self.stdout_flush.is_some()
            || self.logging.is_some()
            || self.deadline
    }
}
#[derive(Debug)]
pub(super) struct Failed {
    pub(super) errors: Errors,
    pub(super) report: Report,
}
impl std::fmt::Display for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "STATISTICS original failures={:?}; actual report={:?}",
            self.errors, self.report
        )
    }
}
impl std::error::Error for Failed {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.errors
            .original
            .as_deref()
            .or_else(|| {
                self.errors
                    .native
                    .as_ref()
                    .map(|e| e as &dyn std::error::Error)
            })
            .or_else(|| {
                self.errors
                    .output
                    .as_ref()
                    .map(|e| e as &dyn std::error::Error)
            })
            .or_else(|| {
                self.errors
                    .cancel
                    .as_ref()
                    .map(|e| e as &dyn std::error::Error)
            })
            .or_else(|| {
                self.errors
                    .destroy
                    .as_ref()
                    .map(|e| e as &dyn std::error::Error)
            })
            .or_else(|| {
                self.errors
                    .terminal
                    .as_ref()
                    .map(|e| e as &dyn std::error::Error)
            })
            .or_else(|| {
                self.errors
                    .transport
                    .as_ref()
                    .map(|e| e as &dyn std::error::Error)
            })
            .or_else(|| {
                self.errors
                    .connection
                    .as_ref()
                    .map(|e| e as &dyn std::error::Error)
            })
            .or(self.errors.resolver.as_deref())
            .or(self.errors.resolver_drain.as_deref())
            .or(self.errors.resolver_close.as_deref())
            .or_else(|| {
                self.errors
                    .stdout_flush
                    .as_ref()
                    .map(|e| e as &dyn std::error::Error)
            })
            .or_else(|| {
                self.errors
                    .protocol
                    .as_ref()
                    .map(|e| e as &dyn std::error::Error)
            })
            .or_else(|| {
                self.errors
                    .logging
                    .as_ref()
                    .map(|e| e as &dyn std::error::Error)
            })
    }
}
pub(super) struct Bound {
    pub(super) hard: Instant,
    pub(super) alarm: Pin<Box<Sleep>>,
}
impl Bound {
    pub(super) fn new(duration: Duration) -> Result<Self, Failure> {
        Self::at(
            Instant::now()
                .checked_add(duration)
                .ok_or("STATISTICS native target overflow")?,
        )
    }
    pub(super) fn at(hard: Instant) -> Result<Self, Failure> {
        if Instant::now() >= hard {
            return Err("original STATISTICS native target already expired".into());
        }
        Ok(Self {
            hard,
            alarm: Box::pin(tokio::time::sleep_until(hard)),
        })
    }
    pub(super) fn expired(&self) -> bool {
        Instant::now() >= self.hard
    }
    pub(super) fn guard(&mut self, cx: &mut Context<'_>) -> bool {
        self.alarm.as_mut().poll(cx).is_ready() || self.expired()
    }
}
#[derive(Clone, Copy)]
struct Notice<'id> {
    epoch: ConnectionEpoch<'id>,
    value: WatchValue,
    hard: Instant,
}
struct Events<'id> {
    current: Option<ConnectionEpoch<'id>>,
    notice: Option<Notice<'id>>,
    lost: Option<(ConnectionEpoch<'id>, Error)>,
    retry: bool,
    unavailable: bool,
    fault: Option<Error>,
    destroyed: Option<DestroyReport>,
    connected: bool,
}
impl Events<'_> {
    pub(super) fn new() -> Self {
        Self {
            current: None,
            notice: None,
            lost: None,
            retry: false,
            unavailable: false,
            fault: None,
            destroyed: None,
            connected: false,
        }
    }
}
fn callback<'id>(
    events: &mut Events<'id>,
    expected: Option<WatchId<'id>>,
    names: &Names,
    closing: bool,
    event: Event<'id, '_>,
) -> GetFlow {
    match event {
        Event::Connected(epoch) => {
            events.current = Some(epoch);
            events.connected = true;
        }
        Event::WatchValue {
            watch,
            selector,
            notification,
        } if !closing => {
            if Some(watch) != expected
                || selector.subsystem != names.subsystem.as_slice()
                || selector.name != names.name.as_slice()
            {
                events.fault = Some(Error::Stale);
            } else if let Some(epoch) = events.current {
                if events.notice.is_some() {
                    events.fault = Some(Error::Capacity);
                } else if let Some(hard) = Instant::now().checked_add(ROW) {
                    events.notice = Some(Notice {
                        epoch,
                        value: notification,
                        hard,
                    });
                } else {
                    events.fault = Some(Error::Overflow);
                }
            } else {
                events.fault = Some(Error::Stale);
            }
        }
        Event::ConnectionLost { epoch, cause } => {
            events.lost = Some((epoch, cause));
            if events.current == Some(epoch) {
                events.current = None;
            }
        }
        Event::ConnectRetry { .. } => events.retry = true,
        Event::ConnectionUnavailable { .. } => events.unavailable = true,
        Event::Destroyed(report) => {
            events.destroyed = Some(report);
            events.current = None;
        }
        _ => {}
    }
    GetFlow::Continue
}
pub(super) fn stop(
    cx: &mut Context<'_>,
    signals: &mut Signals,
    reports: &Reporter,
    latch: &Cell<bool>,
) -> Result<bool, Failure> {
    reports.register(cx);
    if latch.get() || reports.failed() {
        return Ok(true);
    }
    match signals.poll(cx) {
        Poll::Ready(result) => {
            result?;
            latch.set(true);
            Ok(true)
        }
        Poll::Pending => Ok(false),
    }
}
pub(super) struct ResolverOwner {
    pub(super) driver: gnunet_resolver_broker::Driver<4, 256>,
    pub(super) cleanup: Rc<RefCell<Option<Failure>>>,
    pub(super) closed: bool,
}
impl ResolverOwner {
    pub(super) fn close(&mut self) {
        if !self.closed {
            self.closed = true;
            if let Err(error) = self.driver.disconnect() {
                *self.cleanup.borrow_mut() = Some(Box::new(error));
            }
        }
    }
}
impl Drop for ResolverOwner {
    fn drop(&mut self) {
        self.close();
    }
}
pub(super) fn harvest_retry<
    const A: usize,
    const N: usize,
    const W: usize,
    const WW: usize,
    const T: usize,
>(
    owner: &mut handle::StatisticsHandle<'_, A, N, W, WW, T>,
    report: &mut Report,
    reports: &Reporter,
) {
    if let Some(error) = owner.take_io_error() {
        reports.warning(
            "statistics.retry.io",
            format_args!("original transport retry: {error}"),
        );
        report.latest_retry_io = Some(error);
    }
    if let Some(error) = owner.take_connect_error() {
        reports.warning(
            "statistics.retry.connection",
            format_args!("original connection retry: {error}"),
        );
        report.latest_retry_connection = Some(error);
    }
}
pub(super) fn harvest_terminal<
    const A: usize,
    const N: usize,
    const W: usize,
    const WW: usize,
    const T: usize,
>(
    owner: &mut handle::StatisticsHandle<'_, A, N, W, WW, T>,
    errors: &mut Errors,
) {
    errors.transport = owner.take_io_error();
    errors.connection = owner.take_connect_error();
}
struct Closing<'a, 'id> {
    owner: &'a mut Option<Owner<'id>>,
    watch: Option<WatchId<'id>>,
    events: &'a mut Events<'id>,
    resolver: &'a mut gnunet_resolver_broker::Driver<4, 256>,
    reports: &'a Reporter,
    report: &'a mut Report,
    errors: &'a mut Errors,
}
async fn close(input: Closing<'_, '_>) {
    let Closing {
        owner,
        watch,
        events,
        resolver,
        reports,
        report,
        errors,
    } = input;
    let Some(current) = owner.as_mut() else {
        return;
    };
    harvest_terminal(current, errors);
    if let Some(watch) = watch
        && current.owns_watch(watch)
    {
        match current.watch_cancel(watch) {
            Ok(()) => report.cancelled_original = true,
            Err(error) => errors.cancel = Some(error),
        }
    }
    retire(
        owner,
        &mut events.destroyed,
        false,
        resolver,
        reports,
        report,
        errors,
    )
    .await;
}
pub(super) async fn retire<
    'id,
    const A: usize,
    const N: usize,
    const W: usize,
    const WW: usize,
    const T: usize,
>(
    owner: &mut Option<handle::StatisticsHandle<'id, A, N, W, WW, T>>,
    destroyed: &mut Option<DestroyReport>,
    destroy_started: bool,
    resolver: &mut gnunet_resolver_broker::Driver<4, 256>,
    reports: &Reporter,
    report: &mut Report,
    errors: &mut Errors,
) {
    let Some(current) = owner.as_mut() else {
        return;
    };
    let mut force = false;
    if !destroy_started
        && !current.is_closed()
        && let Err(error) = current.destroy(false)
    {
        errors.destroy = Some(error);
        force = true;
    }
    let target = Instant::now().checked_add(CLEANUP);
    let Some(target) = target else {
        errors
            .original
            .get_or_insert_with(|| "STATISTICS cleanup native overflow".into());
        drop(owner.take());
        report.physical_drop = true;
        return;
    };
    let mut alarm = Box::pin(tokio::time::sleep_until(target));
    let mut resolver_live = true;
    let mut cursor = false;
    while !force && destroyed.is_none() {
        enum Action {
            Native(Result<Progress, IpcError>),
            Resolver(Result<(), Failure>),
            Expired,
        }
        let action = {
            let mut driving = std::pin::pin!(current.drive(None, |event, _| {
                match event {
                    Event::Destroyed(receipt) => *destroyed = Some(receipt),
                    Event::ConnectionLost { epoch, cause } => {
                        report.losses = report.losses.saturating_add(1);
                        report.last_loss = Some((epoch.value(), cause));
                        report.current_epoch = None;
                        errors.protocol.get_or_insert(cause);
                    }
                    _ => {}
                }
                GetFlow::Continue
            }));
            let diagnostic = reports.clone();
            let mut resolving =
                std::pin::pin!(resolver.drive_waiting(None, |event| diagnostic.debug(
                    "statistics.resolver.cleanup",
                    format_args!("original Resolver={event:?}")
                )));
            poll_fn(|cx| {
                if alarm.as_mut().poll(cx).is_ready() || Instant::now() >= target {
                    return Poll::Ready(Action::Expired);
                }
                for offset in 0..2 {
                    let resolve = (usize::from(cursor) + offset) % 2 == 0;
                    if resolve && resolver_live {
                        if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                            return Poll::Ready(Action::Resolver(
                                result.map(|_| ()).map_err(|e| Box::new(e) as Failure),
                            ));
                        }
                    } else if !resolve && let Poll::Ready(result) = driving.as_mut().poll(cx) {
                        return Poll::Ready(Action::Native(result));
                    }
                }
                Poll::Pending
            })
            .await
        };
        cursor = !cursor;
        match action {
            Action::Expired => {
                errors.deadline = true;
                force = true;
            }
            Action::Resolver(Err(error)) => {
                errors.resolver_drain = Some(error);
                resolver_live = false;
            }
            Action::Native(Err(error)) => {
                errors.terminal = Some(error);
                force = true;
            }
            Action::Native(Ok(Progress::Closed)) if destroyed.is_none() => {
                errors.protocol = Some(Error::Closed);
                force = true;
            }
            _ => {}
        }
    }
    report.destroyed = *destroyed;
    if errors.transport.is_none() {
        errors.transport = current.take_io_error();
    }
    if errors.connection.is_none() {
        errors.connection = current.take_connect_error();
    }
    drop(owner.take());
    report.physical_drop = true;
}

pub(super) async fn command(inputs: Inputs) -> Result<Report, Failure> {
    let Inputs {
        selector,
        parent,
        live,
        resolution,
        source,
        reports,
        stop: latch,
        resolver,
    } = inputs;
    let cleanup = Rc::new(RefCell::new(None));
    let mut resolver = ResolverOwner {
        driver: resolver,
        cleanup: cleanup.clone(),
        closed: false,
    };
    let mut report = Report::default();
    let mut errors = Errors::default();
    let mut instance = handle::Instance::new();
    let mut owner = None;
    let mut watch = None;
    let mut events = Events::new();
    // Outside the fallible body, so every return retains the actual byte cursor
    // and performs the original stdout flush before native-owner cleanup.
    let mut output = None;
    let result: Result<(), Failure> = async {
        if latch.get() || reports.failed() {
            return Err("WATCH stopped before original native admission".into());
        }
        let mut signals = Signals::new(parent)?;
        output = Some(Output::new()?);
        let output = output.as_mut().ok_or("original stdout owner absent")?;
        let marker = gnunet_client_host::EndpointSource::live(
            live.clone(), b"statistics", resolution.clone(),
        );
        if !Arc::ptr_eq(&marker.clock(), &source) {
            return Err("WATCH actual clock source mismatch".into());
        }
        owner = Owner::from_live_config(
            &mut instance, live, resolution, b"gnunet-statistics",
            handle::Limits { max_frame_bytes: 4096, write_chunk_bytes: 4096 },
        )?;
        let current = owner.as_mut().ok_or(
            "configured STATISTICS disabled; no WATCH source created",
        )?;
        let mut attempt = Some(Bound::new(ADMISSION)?);
        watch = Some(current.watch(selector.selector())?);
        let mut row_bound: Option<Bound> = None;
        let mut retry: Option<Pin<Box<Sleep>>> = None;
        let mut cursor = false;
        loop {
            // is_idle includes ALL transmits, including a started partial. The
            // current actual epoch and original logical watch must also match.
            // This is local whole-write knowledge, never a remote WATCH ACK.
            if let (Some(epoch), Some(watch)) = (events.current, watch)
                && current.connection_epoch() == Some(epoch)
                && current.owns_watch(watch)
                && current.is_idle()
            {
                report.registration_whole_written = true;
                if attempt.as_ref().is_some_and(|bound| !bound.expired()) {
                    attempt = None;
                }
            }
            if let Some(notice) = events.notice.take() {
                report.notifications = report.notifications.saturating_add(1);
                let id = watch.ok_or("actual WATCH callback lost original logical id")?.resource_id();
                output.stage(&selector, notice.epoch.value(), id.index, id.generation, notice.value)?;
                row_bound = Some(Bound::at(notice.hard)?);
            }
            enum Action {
                Stop,
                Native(Result<Progress, IpcError>),
                Resolver(Result<(), Failure>),
                Output,
                OutputError(io::Error),
                Expired,
            }
            let action = {
                let mut driving = std::pin::pin!(current.drive(None, |event, _| {
                    callback(&mut events, watch, &selector, false, event)
                }));
                let diagnostic = reports.clone();
                let mut resolving = std::pin::pin!(resolver.driver.drive_waiting(None, |event| {
                    diagnostic.debug("statistics.watch.resolver", format_args!("original Resolver={event:?}"))
                }));
                poll_fn(|cx| {
                    if attempt.as_mut().is_some_and(|bound| bound.guard(cx))
                        || row_bound.as_mut().is_some_and(|bound| bound.guard(cx))
                    {
                        return Poll::Ready(Ok(Action::Expired));
                    }
                    if stop(cx, &mut signals, &reports, &latch)? {
                        return Poll::Ready(Ok(Action::Stop));
                    }
                    if row_bound.is_some() {
                        if retry.as_mut().is_none_or(|timer| timer.as_mut().poll(cx).is_ready()) {
                            retry = None;
                            match output.step() {
                                Ok(Some(true)) => return Poll::Ready(Ok(Action::Output)),
                                Ok(Some(false)) => cx.waker().wake_by_ref(),
                                Ok(None) => {
                                    let hard = row_bound.as_ref().map(|b| b.hard)
                                        .ok_or("original output bound absent")?;
                                    let next = Instant::now().checked_add(CADENCE)
                                        .ok_or("WATCH output cadence overflow")?.min(hard);
                                    retry = Some(Box::pin(tokio::time::sleep_until(next)));
                                    if let Some(timer) = &mut retry {
                                        let _ready = timer.as_mut().poll(cx);
                                    }
                                }
                                Err(error) => return Poll::Ready(Ok(Action::OutputError(error))),
                            }
                        }
                        // A held line never causes another notification to be
                        // consumed. The same Resolver still gets one fair poll.
                        if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                            return Poll::Ready(Ok(Action::Resolver(
                                result.map(|_| ()).map_err(|e| Box::new(e) as Failure),
                            )));
                        }
                        return Poll::Pending;
                    }
                    for offset in 0..2 {
                        // The preceding Resolver callback may have failed the
                        // selected logger even when its drive future is Pending.
                        if reports.failed() || latch.get() {
                            return Poll::Ready(Ok(Action::Stop));
                        }
                        let resolve = (usize::from(cursor) + offset) % 2 == 0;
                        if resolve {
                            if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                                return Poll::Ready(Ok(Action::Resolver(
                                    result.map(|_| ()).map_err(|e| Box::new(e) as Failure),
                                )));
                            }
                        } else if let Poll::Ready(result) = driving.as_mut().poll(cx) {
                            return Poll::Ready(Ok(Action::Native(result)));
                        }
                    }
                    Poll::Pending
                }).await
            };
            cursor = !cursor;
            // A real error remains independent of a later elapsed native bound.
            let expired = attempt.as_ref().is_some_and(Bound::expired)
                || row_bound.as_ref().is_some_and(Bound::expired);
            if expired {
                errors.deadline = true;
            }
            match action {
                Err(error) => return Err(error),
                Ok(Action::Stop) => break,
                Ok(Action::Expired) => { errors.deadline = true; break; }
                Ok(Action::Resolver(Err(error))) => { errors.resolver = Some(error); break; }
                Ok(Action::Native(Err(error))) => { errors.native = Some(error); break; }
                Ok(Action::Native(Ok(Progress::Closed))) => { errors.protocol = Some(Error::Closed); break; }
                Ok(Action::Output) => {
                    report.rows_written = report.rows_written.saturating_add(1);
                    output.release();
                    row_bound = None;
                    retry = None;
                }
                Ok(Action::OutputError(error)) => { errors.output = Some(error); break; }
                _ => {}
            }
            if let Some(fault) = events.fault.take() {
                errors.protocol = Some(fault);
                break;
            }
            if events.connected {
                report.epochs = report.epochs.saturating_add(1);
                events.connected = false;
            }
            report.current_epoch = events.current.map(|e| e.value());
            if events.retry {
                report.connect_retries = report.connect_retries.saturating_add(1);
                events.retry = false;
                harvest_retry(current, &mut report, &reports);
            }
            if events.unavailable {
                events.unavailable = false;
                harvest_retry(current, &mut report, &reports);
            }
            if let Some((epoch, cause)) = events.lost.take() {
                report.losses = report.losses.saturating_add(1);
                report.last_loss = Some((epoch.value(), cause));
                report.registration_whole_written = false;
                harvest_retry(current, &mut report, &reports);
                reports.warning("statistics.watch.source.lost", format_args!(
                    "original epoch={} lost={cause:?}; readonly watch may register on a new actual epoch",
                    epoch.value(),
                ));
                // Only real source retirement starts a genuinely new attempt.
                // An elapsed old budget cannot be refreshed by this event.
                if !expired {
                    attempt = Some(Bound::new(ADMISSION)?);
                }
            }
            if expired { break; }
        }
        Ok(())
    }.await;
    if let Err(error) = result {
        errors.original = Some(error);
    }
    if let Some(output) = &mut output {
        let (prefix, total) = output.pending();
        report.output_prefix = prefix;
        report.output_total = total;
        errors.stdout_flush = output.flush().err();
    }
    close(Closing {
        owner: &mut owner,
        watch,
        events: &mut events,
        resolver: &mut resolver.driver,
        reports: &reports,
        report: &mut report,
        errors: &mut errors,
    })
    .await;
    resolver.close();
    errors.resolver_close = cleanup.borrow_mut().take();
    errors.logging = reports.take_error();
    if errors.failed() {
        Err(Box::new(Failed { errors, report }))
    } else {
        Ok(report)
    }
}
#[derive(Debug)]
struct Finished {
    original: Option<Failure>,
    logging: io::Error,
    completion: Option<Report>,
}
impl std::fmt::Display for Finished {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "STATISTICS original={:?}; logging={}; completion={:?}",
            self.original, self.logging, self.completion
        )
    }
}
impl std::error::Error for Finished {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.as_deref().or(Some(&self.logging))
    }
}
pub(super) fn finish(result: Result<Report, Failure>, reports: Reporter) -> Result<(), Failure> {
    match &result {
        Ok(report) => reports.debug(
            "statistics.stopped",
            format_args!("actual STATISTICS report={report:?}"),
        ),
        Err(error) => reports.warning(
            "statistics.failed",
            format_args!("original STATISTICS failure: {error}"),
        ),
    }
    if let Some(logging) = reports.take_error() {
        let (original, completion) = match result {
            Ok(report) => (None, Some(report)),
            Err(error) => (Some(error), None),
        };
        Err(Box::new(Finished {
            original,
            logging,
            completion,
        }))
    } else {
        result.map(|_| ())
    }
}
