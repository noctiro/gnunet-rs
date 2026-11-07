//! One retained importer future. Only this scope owns its clients and cleanup.
use crate::{
    Cause,
    control::Control,
    input::{Input, Names},
    settings::Settings,
    statistics,
};
use gnunet_client_host::{EndpointSource, LiveConfiguration};
use gnunet_ipc_unix::{handle, producer};
use gnunet_program_host::reporting::Reporter;
use gnunet_resolver_broker::{BrokerError, Context as Broker, Driver};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_service_startup::ParentControl;
use gnunet_zoneimport_host::{self as host, Progress, Runtime, core};
use std::{
    cell::Cell,
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io::{self, Stdin},
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;
pub(super) struct Inputs {
    pub settings: Settings,
    pub live: LiveConfiguration,
    pub context: Broker<128, 256>,
    pub resolver: Driver<128, 256>,
    pub source: Arc<dyn RuntimeClock>,
    pub reporter: Reporter,
    pub stop: Rc<Cell<bool>>,
    pub parent: Option<ParentControl>,
    pub stdin: Stdin,
}
#[derive(Default)]
pub(super) struct Report {
    input_names: usize,
    input_eof: bool,
    admitted_names: usize,
    rejected_names: usize,
    initialized: bool,
    native: Option<host::Report>,
    statistics: Option<statistics::Report>,
    metrics: Option<host::metrics::Metrics>,
}
impl fmt::Debug for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Report")
            .field("input_names", &self.input_names)
            .field("input_eof", &self.input_eof)
            .field("admitted_names", &self.admitted_names)
            .field("rejected_names", &self.rejected_names)
            .field("initialized", &self.initialized)
            .field("native", &self.native)
            .field("statistics", &self.statistics)
            .field("metrics", &self.metrics)
            .finish()
    }
}
#[derive(Debug, Default)]
struct Errors {
    original: Option<Cause>,
    business: Option<core::NameFailures>,
    signal: Option<io::Error>,
    cleanup: [Option<host::Error>; 4],
    additional_cleanup: u64,
    cleanup_deadline: Option<io::Error>,
    statistics: Option<producer::Failure>,
    statistics_abort: Option<producer::Failure>,
    resolver: Option<BrokerError>,
    resolver_close: Option<BrokerError>,
    logging: Option<io::Error>,
}
impl Errors {
    fn original(&mut self, error: impl Error + 'static) {
        if self.original.is_none() {
            self.original = Some(Box::new(error));
        }
    }
    fn cleanup(&mut self, error: host::Error) {
        if let Some(slot) = self.cleanup.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(error);
        } else {
            self.additional_cleanup = self.additional_cleanup.saturating_add(1);
        }
    }
    fn failed(&self) -> bool {
        self.original.is_some()
            || self.business.is_some()
            || self.signal.is_some()
            || self.cleanup.iter().any(Option::is_some)
            || self.additional_cleanup != 0
            || self.cleanup_deadline.is_some()
            || self.statistics.is_some()
            || self.statistics_abort.is_some()
            || self.resolver.is_some()
            || self.resolver_close.is_some()
            || self.logging.is_some()
    }
    fn runtime_failed(&self) -> bool {
        self.original.is_some()
            || self.signal.is_some()
            || self.resolver.is_some()
            || self.cleanup.iter().any(Option::is_some)
            || self.cleanup_deadline.is_some()
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
            "zoneimport terminal facts: report={:?}; causes={:?}",
            self.report, self.errors
        )
    }
}
impl Error for Failed {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.errors
            .original
            .as_deref()
            .or_else(|| self.errors.signal.as_ref().map(|error| error as &dyn Error))
            .or_else(|| {
                self.errors
                    .cleanup
                    .iter()
                    .flatten()
                    .next()
                    .map(|error| error as &dyn Error)
            })
            .or_else(|| {
                self.errors
                    .cleanup_deadline
                    .as_ref()
                    .map(|error| error as &dyn Error)
            })
            .or_else(|| {
                self.errors
                    .resolver
                    .as_ref()
                    .map(|error| error as &dyn Error)
            })
            .or_else(|| {
                self.errors
                    .resolver_close
                    .as_ref()
                    .map(|error| error as &dyn Error)
            })
            .or_else(|| {
                self.errors
                    .statistics
                    .as_ref()
                    .map(|error| error as &dyn Error)
            })
            .or_else(|| {
                self.errors
                    .statistics_abort
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

fn observe(reporter: &Reporter, event: host::Event<'_>) {
    match event {
        host::Event::Io { .. }
        | host::Event::DnsRejected { .. }
        | host::Event::ReadFailed { .. }
        | host::Event::Deadline { .. } => {
            reporter.warning("zoneimport.native.problem", format_args!("{event:?}"))
        }
        _ => reporter.debug("zoneimport.native.activity", format_args!("{event:?}")),
    }
}
fn abort_statistics(owner: &mut Option<statistics::Owner<'_>>, errors: &mut Errors) {
    if let Some(owner) = owner.as_mut()
        && !owner.is_closed()
        && let Err(error) = owner.abort()
        && errors.statistics_abort.is_none()
    {
        errors.statistics_abort = Some(error);
    }
}
fn statistics_result(
    result: Result<producer::Progress, producer::Failure>,
    reporter: &Reporter,
    errors: &mut Errors,
) {
    match result {
        Ok(progress) => reporter.debug(
            "zoneimport.statistics.activity",
            format_args!("local statistics: {progress:?}"),
        ),
        Err(error) => {
            reporter.warning(
                "zoneimport.statistics.failed",
                format_args!("statistics source retired: {error}"),
            );
            if errors.statistics.is_none() {
                errors.statistics = Some(error);
            }
        }
    }
}
enum InputTurn {
    Stop(io::Result<()>),
    Read(io::Result<usize>),
    Resolver(Result<gnunet_resolver_broker::Progress, BrokerError>),
}
async fn collect(
    input: &mut Input,
    names: &mut Names,
    control: &mut Control,
    resolver: &mut Driver<128, 256>,
    reporter: &Reporter,
) -> Result<bool, Cause> {
    let mut bytes = [0; 4096];
    let mut cursor = 0;
    loop {
        let turn = {
            let mut resolving =
                std::pin::pin!(resolver.drive_waiting(None, |event| reporter.debug(
                    "zoneimport.resolver.activity",
                    format_args!("Resolver: {event:?}")
                )));
            poll_fn(|cx| {
                if let Poll::Ready(result) = control.poll(cx) {
                    return Poll::Ready(InputTurn::Stop(result));
                }
                for offset in 0..2 {
                    if control.stopped() {
                        return Poll::Ready(InputTurn::Stop(Ok(())));
                    }
                    let class = (cursor + offset) % 2;
                    if class == 0 {
                        if let Poll::Ready(result) = input.poll(cx, &mut bytes) {
                            cursor = 1;
                            return Poll::Ready(InputTurn::Read(result));
                        }
                    } else if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                        cursor = 0;
                        return Poll::Ready(InputTurn::Resolver(result));
                    }
                }
                Poll::Pending
            })
            .await
        };
        match turn {
            InputTurn::Stop(result) => {
                result?;
                return Ok(false);
            }
            InputTurn::Read(Ok(0)) => {
                names.finish()?;
                return Ok(true);
            }
            InputTurn::Read(Ok(count)) => names.push(&bytes[..count])?,
            InputTurn::Read(Err(error)) => return Err(Box::new(error)),
            InputTurn::Resolver(Err(error)) => return Err(Box::new(error)),
            InputTurn::Resolver(Ok(_)) => {}
        }
        tokio::task::yield_now().await;
    }
}
#[derive(Default)]
struct Turn {
    stop: Option<io::Result<()>>,
    runtime: Option<Result<Progress, host::Error>>,
    runtime_guard_error: Option<host::Error>,
    statistics: Option<Result<producer::Progress, producer::Failure>>,
    resolver: Option<Result<gnunet_resolver_broker::Progress, BrokerError>>,
    expired: bool,
}
impl Turn {
    fn ready(&self) -> bool {
        self.stop.is_some()
            || self.runtime_guard_error.is_some()
            || self.runtime.is_some()
            || self.statistics.is_some()
            || self.resolver.is_some()
            || self.expired
    }
}
fn native_guards(
    runtime: &mut Runtime<'_>,
    statistics: &mut Option<statistics::Owner<'_>>,
    cx: &mut Context<'_>,
    reporter: &Reporter,
) -> Turn {
    let mut turn = Turn::default();
    match runtime.poll_native_guard(cx, &mut |event| observe(reporter, event)) {
        Ok(Some(progress)) => turn.runtime = Some(Ok(progress)),
        Ok(None) => {}
        Err(error) => turn.runtime = Some(Err(error)),
    }
    if let Some(owner) = statistics.as_mut()
        && let Poll::Ready(result) = owner.poll_native_guard(cx)
    {
        turn.statistics = Some(result);
    }
    turn
}
async fn active(
    runtime: &mut Runtime<'_>,
    statistics: &mut Option<statistics::Owner<'_>>,
    resolver: &mut Driver<128, 256>,
    control: &mut Control,
    reporter: &Reporter,
    report: &mut Report,
    errors: &mut Errors,
) {
    let mut cursor = 0;
    loop {
        let turn = {
            let mut resolving =
                std::pin::pin!(resolver.drive_waiting(None, |event| reporter.debug(
                    "zoneimport.resolver.activity",
                    format_args!("Resolver: {event:?}")
                )));
            poll_fn(|cx| {
                // Both original native guards precede any canonical sample,
                // resolver effect, new publisher admission or ordinary host IO.
                let mut turn = native_guards(runtime, statistics, cx, reporter);
                if let Poll::Ready(result) = control.poll(cx) {
                    turn.stop = Some(result);
                }
                if turn.ready() {
                    return Poll::Ready(turn);
                }
                for offset in 0..3 {
                    if control.stopped() {
                        turn.stop = Some(Ok(()));
                        break;
                    }
                    match (cursor + offset) % 3 {
                        0 => {
                            if let Poll::Ready(result) =
                                runtime.poll(cx, &mut |event| observe(reporter, event))
                            {
                                let failed = result.is_err();
                                turn.runtime = Some(result);
                                if failed {
                                    break;
                                }
                            }
                        }
                        1 => {
                            if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                                let failed = result.is_err();
                                turn.resolver = Some(result);
                                if failed {
                                    break;
                                }
                            }
                        }
                        _ => {
                            if errors.statistics.is_none()
                                && let Some(owner) = statistics.as_mut()
                                && !owner.is_closed()
                            {
                                match owner.refresh(statistics::snapshot(runtime.metrics())) {
                                    Err(error) => turn.statistics = Some(Err(error)),
                                    Ok(_) => {
                                        if let Poll::Ready(result) = owner.poll(cx, None) {
                                            turn.statistics = Some(result);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                cursor = (cursor + 1) % 3;
                if turn.ready() {
                    Poll::Ready(turn)
                } else {
                    Poll::Pending
                }
            })
            .await
        };
        let mut stop = false;
        if let Some(result) = turn.runtime {
            match result {
                Err(error) => {
                    errors.original(error);
                    stop = true;
                }
                Ok(Progress::Initialized) => {
                    report.initialized = true;
                    reporter.debug(
                        "zoneimport.initialized",
                        format_args!("actual initial IDENTITY inventory ended; importer activated"),
                    );
                }
                Ok(Progress::Closed) => stop = true,
                Ok(Progress::Activity) => {}
            }
        }
        if let Some(result) = turn.resolver
            && let Err(error) = result
        {
            errors.resolver = Some(error);
            stop = true;
        }
        if let Some(result) = turn.statistics {
            statistics_result(result, reporter, errors);
        }
        if let Some(result) = turn.stop {
            if let Err(error) = result {
                errors.signal = Some(error);
            }
            stop = true;
        }
        if stop || control.stopped() {
            break;
        }
        tokio::task::yield_now().await;
    }
}
async fn retire(
    runtime: &mut Runtime<'_>,
    statistics: &mut Option<statistics::Owner<'_>>,
    resolver: &mut Driver<128, 256>,
    reporter: &Reporter,
    errors: &mut Errors,
    grace: Duration,
) {
    // One original native hard, established before any canonical work, never
    // reset by progress, another signal, a failed report or a cleanup error.
    let hard = Instant::now().checked_add(grace);
    runtime.begin_close();
    if errors.runtime_failed() || reporter.failed() {
        abort_statistics(statistics, errors);
    }
    let Some(hard) = hard else {
        errors.cleanup_deadline = Some(io::Error::other("cleanup native deadline overflow"));
        abort_statistics(statistics, errors);
        return;
    };
    let mut alarm = Box::pin(tokio::time::sleep_until(hard));
    let mut cursor = 0;
    loop {
        let turn = {
            let mut resolving =
                std::pin::pin!(resolver.drive_waiting(Some(hard), |event| reporter.debug(
                    "zoneimport.resolver.cleanup",
                    format_args!("Resolver cleanup: {event:?}")
                )));
            poll_fn(|cx| {
                let mut turn = native_guards(runtime, statistics, cx, reporter);
                if let Some(Err(error)) = turn.runtime.take() {
                    turn.runtime_guard_error = Some(error);
                }
                reporter.register(cx);
                if Instant::now() >= hard || alarm.as_mut().poll(cx).is_ready() {
                    turn.expired = true;
                    return Poll::Ready(turn);
                }
                if reporter.failed() {
                    abort_statistics(statistics, errors);
                }
                // A failed logger never suppresses old source/operation cleanup.
                // poll_close is explicitly clockfree, and does not admit work.
                if let Poll::Ready(result) =
                    runtime.poll_close(cx, &mut |event| observe(reporter, event))
                {
                    turn.runtime = Some(result);
                }
                if !reporter.failed()
                    && !errors.runtime_failed()
                    && turn.runtime_guard_error.is_none()
                    && turn.runtime.as_ref().is_none_or(Result::is_ok)
                {
                    for offset in 0..2 {
                        if reporter.failed() {
                            abort_statistics(statistics, errors);
                            break;
                        }
                        match (cursor + offset) % 2 {
                            0 => {
                                if errors.statistics.is_none()
                                    && turn.statistics.is_none()
                                    && let Some(owner) = statistics.as_mut()
                                    && !owner.is_closed()
                                    && let Poll::Ready(result) = owner.poll(cx, Some(hard))
                                {
                                    turn.statistics = Some(result);
                                }
                            }
                            _ => {
                                if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                                    turn.resolver = Some(result);
                                }
                            }
                        }
                    }
                    cursor = (cursor + 1) % 2;
                }
                if turn.ready() {
                    Poll::Ready(turn)
                } else {
                    Poll::Pending
                }
            })
            .await
        };
        let mut closed = false;
        if let Some(error) = turn.runtime_guard_error {
            errors.cleanup(error);
        }
        if let Some(result) = turn.runtime {
            match result {
                Ok(Progress::Closed) => closed = true,
                Err(error) => errors.cleanup(error),
                _ => {}
            }
        }
        if let Some(result) = turn.statistics {
            statistics_result(result, reporter, errors);
        }
        if let Some(result) = turn.resolver
            && let Err(error) = result
        {
            errors.resolver = Some(error);
            abort_statistics(statistics, errors);
        }
        if errors.runtime_failed() || reporter.failed() {
            abort_statistics(statistics, errors);
        }
        if closed {
            break;
        }
        if turn.expired {
            errors.cleanup_deadline = Some(io::Error::new(
                io::ErrorKind::TimedOut,
                "original importer cleanup hard expired; report retains unretired metadata",
            ));
            abort_statistics(statistics, errors);
            break;
        }
        tokio::task::yield_now().await;
    }
}
async fn drain_statistics(
    statistics: &mut Option<statistics::Owner<'_>>,
    resolver: &mut Driver<128, 256>,
    reporter: &Reporter,
    errors: &mut Errors,
    final_metrics: host::metrics::Metrics,
    grace: Duration,
) {
    if let Some(owner) = statistics.as_mut()
        && !owner.is_closed()
    {
        if errors.runtime_failed() || reporter.failed() || errors.statistics.is_some() {
            abort_statistics(statistics, errors);
        } else if let Err(error) = owner.begin_close(statistics::snapshot(final_metrics), grace) {
            errors.statistics = Some(error);
            abort_statistics(statistics, errors);
        }
    }
    loop {
        if statistics.as_ref().is_none_or(|owner| owner.is_closed()) {
            break;
        }
        let turn = {
            let mut resolving =
                std::pin::pin!(resolver.drive_waiting(None, |event| reporter.debug(
                    "zoneimport.resolver.cleanup",
                    format_args!("Resolver cleanup: {event:?}")
                )));
            poll_fn(|cx| {
                let mut turn = Turn::default();
                if let Some(owner) = statistics.as_mut()
                    && let Poll::Ready(result) = owner.poll_native_guard(cx)
                {
                    turn.statistics = Some(result);
                }
                reporter.register(cx);
                if reporter.failed() {
                    abort_statistics(statistics, errors);
                    return Poll::Ready(turn);
                }
                if turn.statistics.is_none()
                    && let Some(owner) = statistics.as_mut()
                    && let Poll::Ready(result) = owner.poll(cx, None)
                {
                    turn.statistics = Some(result);
                }
                if !reporter.failed()
                    && errors.resolver.is_none()
                    && let Poll::Ready(result) = resolving.as_mut().poll(cx)
                {
                    turn.resolver = Some(result);
                }
                if turn.ready() {
                    Poll::Ready(turn)
                } else {
                    Poll::Pending
                }
            })
            .await
        };
        if let Some(result) = turn.statistics {
            statistics_result(result, reporter, errors);
        }
        if let Some(result) = turn.resolver
            && let Err(error) = result
        {
            errors.resolver = Some(error);
            abort_statistics(statistics, errors);
        }
        tokio::task::yield_now().await;
    }
}
pub(super) async fn run(inputs: Inputs) -> Result<Report, Cause> {
    let Inputs {
        settings,
        live,
        context,
        mut resolver,
        source,
        reporter,
        stop,
        parent,
        stdin,
    } = inputs;
    let mut report = Report::default();
    let mut errors = Errors::default();
    let identity_instance = host::identity::Instance::new();
    let namestore_instance = host::namestore::Instance::new();
    let mut statistics_instance = handle::Instance::new();
    let outcome = async {
        let mut control = Control::new(parent, stop, reporter.clone())?;
        let mut input = Input::new(stdin);
        let mut names = Names::new(
            settings.input_bytes,
            settings.core.names,
            settings.initial_names,
        )?;
        let collected = collect(
            &mut input,
            &mut names,
            &mut control,
            &mut resolver,
            &reporter,
        )
        .await;
        report.input_names = names.len();
        report.input_eof = collected?;
        if !report.input_eof || control.stopped() {
            return Ok::<(), Cause>(());
        }
        let core = core::Core::new(settings.core, settings.policy)?;
        let ports = host::Ports {
            identity: EndpointSource::live(live.clone(), b"identity", context.resolution_context()),
            namestore: EndpointSource::live(
                live.clone(),
                b"namestore",
                context.resolution_context(),
            ),
            clock: source.clone(),
        };
        let mut runtime = Runtime::new(
            core,
            host::Instances {
                identity: &identity_instance,
                namestore: &namestore_instance,
            },
            ports,
            host::time::Clock::new(source.clone()),
            settings.host,
            &settings.servers,
        )?;
        let mut statistics = match statistics::Owner::new(
            &mut statistics_instance,
            live,
            context.resolution_context(),
            source,
            producer::Configuration {
                subsystem: b"zoneimport",
                metrics: &statistics::METRICS,
                initial: statistics::snapshot(runtime.metrics()),
                limits: producer::Limits::default(),
            },
        ) {
            Ok(owner) => Some(owner),
            Err(error) => {
                reporter.warning(
                    "zoneimport.statistics.failed",
                    format_args!("statistics construction: {error}"),
                );
                errors.statistics = Some(error);
                None
            }
        };
        // Every error after native-owner construction flows through the same
        // retirement scope below; no `?` can escape that ownership boundary.
        let admitted = async {
            for index in 0..names.len() {
                if index % 32 == 0 {
                    let turn = poll_fn(|cx| {
                        let mut turn = native_guards(&mut runtime, &mut statistics, cx, &reporter);
                        if let Poll::Ready(result) = control.poll(cx) {
                            turn.stop = Some(result);
                        }
                        Poll::Ready(turn)
                    })
                    .await;
                    let runtime_error = turn.runtime.and_then(Result::err);
                    if let Some(result) = turn.statistics {
                        statistics_result(result, &reporter, &mut errors);
                    }
                    let stopped = turn.stop.is_some();
                    if let Some(Err(error)) = turn.stop {
                        errors.signal = Some(error);
                    }
                    if let Some(error) = runtime_error {
                        return Err(error);
                    }
                    if stopped {
                        return Ok::<bool, host::Error>(false);
                    }
                    tokio::task::yield_now().await;
                }
                if control.stopped() {
                    return Ok(false);
                }
                let name = names
                    .get(index)
                    .ok_or_else(|| io::Error::other("original input range missing"))?;
                match runtime.add_name(name) {
                    Ok(_original_name) => report.admitted_names += 1,
                    Err(host::Error::InvalidName(reason)) => {
                        report.rejected_names += 1;
                        reporter.warning(
                            "zoneimport.input.rejected",
                            format_args!(
                                "input line{} rejected by IDNA/FQDN validation: {reason:?}",
                                index + 1
                            ),
                        );
                    }
                    Err(error) => return Err(error),
                }
            }
            if control.stopped() {
                return Ok(false);
            }
            runtime.finish_input()?;
            Ok(true)
        }
        .await;
        drop(names);
        match admitted {
            Ok(true) => {
                active(
                    &mut runtime,
                    &mut statistics,
                    &mut resolver,
                    &mut control,
                    &reporter,
                    &mut report,
                    &mut errors,
                )
                .await
            }
            Ok(false) => {}
            Err(error) => errors.original(error),
        }
        retire(
            &mut runtime,
            &mut statistics,
            &mut resolver,
            &reporter,
            &mut errors,
            settings.cleanup,
        )
        .await;
        let final_metrics = runtime.metrics();
        report.metrics = Some(final_metrics);
        let native = runtime.into_report();
        if native.name_failures.failed != 0 || native.name_failures.uncertain != 0 {
            errors.business = Some(native.name_failures);
        }
        report.native = Some(native);
        drain_statistics(
            &mut statistics,
            &mut resolver,
            &reporter,
            &mut errors,
            final_metrics,
            settings.cleanup,
        )
        .await;
        report.statistics = statistics.as_ref().map(statistics::Owner::report);
        drop(statistics);
        Ok(())
    }
    .await;
    if let Err(error) = outcome
        && errors.original.is_none()
    {
        errors.original = Some(error);
    }
    if let Err(error) = resolver.disconnect() {
        errors.resolver_close = Some(error);
    }
    drop(resolver); // physical same-owner fallback even when disconnect rejected.
    reporter.debug(
        "zoneimport.stopped",
        format_args!("actual terminal report: {report:?}"),
    );
    // Like the public program's stderr summary, this is a diagnostic. Route it
    // through the selected logger; it never claims queueing was a STORE result.
    reporter.message(
        gnunet_program_host::policy::Level::INFO,
        "zoneimport.summary",
        format_args!(
            "Read {} names; admitted {} input lines; rejected {}; initialized={}; failed/uncertain inputs={:?}; actual metrics={:?}",
            report.input_names, report.admitted_names, report.rejected_names, report.initialized,
            report.native.as_ref().map(|native| native.name_failures), report.metrics
        ),
    );
    errors.logging = reporter.take_error();
    if errors.failed() {
        Err(Box::new(Failed { report, errors }))
    } else {
        Ok(report)
    }
}
