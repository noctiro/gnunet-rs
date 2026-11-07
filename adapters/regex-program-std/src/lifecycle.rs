//! One actual Driver, shared Resolver and bounded statistics owner through cleanup.
use crate::{
    Factory, Failure, Settings, control::Control, factory, reporting::Diagnostics, statistics,
};
use gnunet_client_host::{EndpointSource, LiveConfiguration};
use gnunet_program_host::policy::Level;
use gnunet_regex_server_host::{
    Ports, Server,
    dht::Provider,
    driver::{Driver, Progress},
    pils::Signer,
};
use gnunet_service_runtime::{BoundListeners, clock::RuntimeClock};
use gnunet_service_startup::{ParentControl, daemon::ChildReady};
use std::{
    fmt,
    future::{Future, poll_fn},
    io::{self, Write},
    pin::pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
/// Actual final observations. Local writes are not remote replication or durability.
#[derive(Debug)]
pub struct Report {
    /// Actual original IPC accept/write/retirement observations.
    pub host: gnunet_regex_server_host::Report,
    /// Actual distributed Core counters; never guessed from native activity.
    pub metrics: gnunet_regex_service::Metrics,
    /// Actual diagnostic publisher result, absent when construction failed.
    pub statistics: Option<statistics::Report>,
    /// True only after the same original Driver actually returned Closed.
    pub driver_drained: bool,
}
/// Independent original failures are retained without overwriting one another.
#[derive(Debug, Default)]
pub struct Errors {
    /// First startup/control/Driver/logger-triggered business failure.
    pub original: Option<Failure>,
    /// Actual stop errors: IPC, PILS metadata and original DHT close.
    pub stop: [Option<Failure>; 3],
    /// First subsequent failure during original Driver retirement.
    pub retirement: Option<Failure>,
    /// First statistics error; it fences diagnostics but does not stop business.
    pub statistics: Option<Failure>,
    /// Independent explicit statistics retirement error after another source failed.
    pub statistics_cleanup: Option<Failure>,
    /// Actual shared Resolver source/retirement error.
    pub resolver: Option<Failure>,
    /// Independent original disconnect failure after a previous Resolver fault.
    pub resolver_cleanup: Option<Failure>,
}
impl Errors {
    fn failed(&self) -> bool {
        self.original.is_some()
            || self.stop.iter().any(Option::is_some)
            || self.retirement.is_some()
            || self.statistics.is_some()
            || self.resolver.is_some()
            || self.statistics_cleanup.is_some()
            || self.resolver_cleanup.is_some()
    }
    fn first(&mut self, error: Failure) {
        if self.original.is_none() {
            self.original = Some(error);
        }
    }
}
/// Actual report and original independent failure owners from the same service.
#[derive(Debug)]
pub struct LifecycleFailure {
    /// Original and independent cleanup errors, never a fabricated DONE.
    pub errors: Errors,
    /// Observed original ownership state at return.
    pub report: Option<Report>,
}
impl fmt::Display for LifecycleFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "REGEX frontend original/cleanup failures: {:?}; actual report {:?}",
            self.errors, self.report
        )
    }
}
impl std::error::Error for LifecycleFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.errors
            .original
            .as_deref()
            .or_else(|| self.errors.stop.iter().flatten().next().map(|e| e.as_ref()))
            .or(self.errors.retirement.as_deref())
            .or(self.errors.statistics.as_deref())
            .or(self.errors.statistics_cleanup.as_deref())
            .or(self.errors.resolver.as_deref())
            .or(self.errors.resolver_cleanup.as_deref())
    }
}
pub(crate) struct Inputs<'a, 'log> {
    pub(crate) config: gnunet_config::Configuration,
    pub(crate) settings: Settings,
    pub(crate) bound: BoundListeners,
    pub(crate) clock: Arc<dyn RuntimeClock>,
    pub(crate) control: Option<ParentControl>,
    pub(crate) child: &'a mut ChildReady,
    pub(crate) diagnostics: &'a Diagnostics<'log>,
}
fn due(duration: Duration) -> Result<Instant, Failure> {
    Instant::now()
        .checked_add(duration)
        .ok_or_else(|| "REGEX native time overflow".into())
}
fn poll_broker<const R: usize, const N: usize>(
    broker: &mut gnunet_resolver_broker::Driver<R, N>,
    cx: &mut Context<'_>,
    diagnostics: &Diagnostics<'_>,
) -> Poll<Result<gnunet_resolver_broker::Progress, gnunet_resolver_broker::BrokerError>> {
    // The broker documents retained cursors across canceled wait futures. Every
    // callback is synchronous; no resolution lease crosses another owner poll.
    let future = broker.drive_waiting(None, |event| {
        diagnostics.observe(
            "regex.resolver.activity",
            Level::DEBUG,
            format_args!("REGEX shared Resolver {event:?}"),
        )
    });
    let mut future = pin!(future);
    future.as_mut().poll(cx)
}
fn poll_timer(timer: &mut std::pin::Pin<Box<Sleep>>, cx: &mut Context<'_>) -> bool {
    timer.as_mut().poll(cx).is_ready()
}
fn statistics_error(
    slot: &mut Option<Failure>,
    error: statistics::Failure,
    diagnostics: &Diagnostics<'_>,
) {
    if slot.is_none() {
        diagnostics.observe(
            "regex.statistics.failed",
            Level::WARNING,
            format_args!("REGEX diagnostic publisher fenced: {error}"),
        );
        *slot = Some(Box::new(error));
    }
}
fn abort_statistics(
    stats: &mut Option<statistics::Owner<'_>>,
    errors: &mut Errors,
    diagnostics: &Diagnostics<'_>,
) {
    if let Some(stats) = stats
        && !stats.is_closed()
        && let Err(error) = stats.abort()
    {
        statistics_error(&mut errors.statistics_cleanup, error, diagnostics);
    }
}
fn begin_stop<D: Provider>(
    driver: &mut Driver<'_, D>,
    errors: &mut Errors,
    stopping: &mut bool,
    notice: &mut Option<std::pin::Pin<Box<Sleep>>>,
    delay: Duration,
    diagnostics: &Diagnostics<'_>,
) -> bool {
    if *stopping {
        return false;
    }
    *stopping = true;
    let actual = driver.stop(|event| diagnostics.host(event));
    errors.stop = actual.failures;
    // This fixed native alarm is a diagnostic point, never a cancellation ACK.
    *notice = Some(Box::pin(tokio::time::sleep(delay)));
    true
}
pub(crate) async fn run<F: Factory + 'static>(input: Inputs<'_, '_>) -> Result<Report, Failure> {
    let Inputs {
        config,
        settings,
        bound,
        clock,
        control,
        child,
        diagnostics,
    } = input;
    let listeners = bound.listeners();
    for error in bound.failures() {
        diagnostics.message(
            "regex.listener.alternate",
            Level::WARNING,
            format_args!("REGEX alternate listener failed: {error}"),
        )?;
    }
    let mut control = Control::new(control)?;
    let startup_until = due(settings.startup)?;
    let mut startup_timer = Box::pin(tokio::time::sleep_until(startup_until));
    let core = gnunet_regex_service::Core::new(settings.core)?;
    let server = Server::new(
        core,
        settings.host,
        Ports {
            clock: clock.clone(),
            options: settings.service(&config)?,
            unix: settings.unix,
        },
    )?;
    let live = LiveConfiguration::new(config);
    let (resolution, mut broker) = gnunet_resolver_broker::broker::<64, 4096>(
        live.clone(),
        settings.resolver,
        gnunet_resolver_broker::native_profile()?,
        clock.clone(),
    )?;
    let shared = resolution.resolution_context();
    let mut instance = gnunet_pils::client::Instance::new();
    let signer = Signer::new(
        &mut instance,
        EndpointSource::live(live.clone(), b"pils", shared.clone()),
        settings.pils_profile,
        gnunet_pils::HelloLimits {
            maximum_input_bytes: 65535,
            maximum_address_bytes: 65535,
            maximum_addresses: 4096,
        },
    )?;
    let mut statistics_instance = gnunet_client::statistics_handle::Instance::new();
    let mut stat_error = None;
    let mut stats = match statistics::Owner::new(
        &mut statistics_instance,
        live.clone(),
        shared.clone(),
        clock.clone(),
        server.core().metrics(),
        settings.statistics,
    ) {
        Ok(owner) => Some(owner),
        Err(error) => {
            stat_error = Some(Box::new(error) as Failure);
            None
        }
    };
    // These values are constructed only here, after fork/identity/runtime/broker.
    // Storage lives outside the actual Provider and any Driver borrowing it.
    let mut storage = match F::storage() {
        Ok(storage) => storage,
        Err(error) => {
            return setup_failure::<F::Provider<'_>>(
                error,
                stat_error,
                server,
                signer,
                None,
                stats.as_mut(),
                &mut broker,
                diagnostics,
                settings.statistics_grace,
            )
            .await;
        }
    };
    let provider = match F::create(factory::Context {
        storage: &mut storage,
        configuration: live.clone(),
        resolution: shared.clone(),
        endpoint: EndpointSource::live(live, b"dht", shared),
        clock: clock.clone(),
        startup_until,
        settings: &settings,
    }) {
        Ok(provider) => provider,
        Err(error) => {
            return setup_failure::<F::Provider<'_>>(
                error,
                stat_error,
                server,
                signer,
                None,
                stats.as_mut(),
                &mut broker,
                diagnostics,
                settings.statistics_grace,
            )
            .await;
        }
    };
    let mut driver = match Driver::try_new(server, signer, provider, settings.driver) {
        Ok(driver) => driver,
        Err(failed) => {
            let gnunet_regex_server_host::driver::ConstructionFailure {
                error,
                server,
                signer,
                dht: provider,
            } = failed;
            return setup_failure(
                error,
                stat_error,
                server,
                signer,
                Some(provider),
                stats.as_mut(),
                &mut broker,
                diagnostics,
                settings.statistics_grace,
            )
            .await;
        }
    };
    let mut errors = Errors {
        statistics: stat_error,
        ..Default::default()
    };
    let mut stopping = false;
    let mut ready = false;
    let mut driver_closed = false;
    let mut stats_closing = false;
    let mut retirement_notice = None;
    let mut turn = 0u8;
    let mut tick = Box::pin(tokio::time::sleep(settings.tick));
    loop {
        // The outer turn explicitly yields; local Ready work cannot starve
        // native sockets, original deadlines or signals on this current thread.
        turn = turn.wrapping_add(1);
        if turn.is_multiple_of(64) {
            tokio::task::yield_now().await;
        }
        poll_fn(|cx| {
            let mut changed = false;
            let mut need_stop = false;
            if !stopping {
                need_stop |= diagnostics.failed(cx);
                if let Poll::Ready(result) = control.poll(cx) {
                    if let Err(error) = result { errors.first(Box::new(error)); }
                    need_stop = true;
                }
                if !ready && poll_timer(&mut startup_timer, cx) {
                    errors.first("REGEX actual PILS/DHT startup deadline expired; not ready".into());
                    need_stop = true;
                }
            }
            // Native guards precede canonical-clock dependent polls. Driver
            // itself checks IPC/DHT/PILS native guards at every original poll.
            if let Some(stats) = &mut stats && !stats.is_closed() {
                match stats.poll_native_guard(cx) {
                    Poll::Ready(Ok(_)) => changed = true,
                    Poll::Ready(Err(error)) => {
                        statistics_error(&mut errors.statistics, error, diagnostics);
                        changed = true;
                    }
                    Poll::Pending => {}
                }
            }
            if need_stop {
                changed |= begin_stop(&mut driver, &mut errors, &mut stopping,
                    &mut retirement_notice, settings.shutdown_grace, diagnostics);
            }
            if !driver_closed {
                match driver.poll(cx, &listeners, None, |event| diagnostics.host(event)) {
                    Poll::Ready(Ok(Progress::Closed)) => {
                        driver_closed = true;
                        changed = true;
                    }
                    Poll::Ready(Ok(event)) => {
                        diagnostics.driver(event);
                        changed = true;
                    }
                    Poll::Ready(Err(error)) => {
                        if stopping && errors.retirement.is_none() {
                            errors.retirement = Some(error);
                        } else if !stopping {
                            errors.first(error);
                            begin_stop(&mut driver, &mut errors, &mut stopping,
                                &mut retirement_notice, settings.shutdown_grace, diagnostics);
                        }
                        // No fresh diagnostic IO after a potentially failed
                        // canonical source. Preserve its pending Unknown state.
                        abort_statistics(&mut stats, &mut errors, diagnostics);
                        changed = true;
                    }
                    Poll::Pending => {}
                }
            }
            // A failure emitted by this very Driver callback fences Ready now.
            if !stopping && diagnostics.failed(cx) {
                changed |= begin_stop(&mut driver, &mut errors, &mut stopping,
                    &mut retirement_notice, settings.shutdown_grace, diagnostics);
            }
            if !stopping && !ready && driver.peer().is_some() {
                let actual = driver.server().sample_times()
                    .map_err(|e| Box::new(e) as Failure)
                    .and_then(|_| F::ready(driver.provider()));
                match actual {
                    Ok(true) => {
                        let result = (|| -> io::Result<()> {
                            diagnostics.message("regex.ready", Level::INFO, format_args!(
                                "REGEX actual IPC/Driver current PILS identity and original DHT provider ready"))?;
                            let mut out = io::stdout().lock();
                            writeln!(out, "READY regex")?;
                            out.flush()?;
                            child.ready()
                        })();
                        match result {
                            Ok(()) => ready = true,
                            Err(error) => {
                                errors.first(Box::new(error));
                                begin_stop(&mut driver, &mut errors, &mut stopping,
                                    &mut retirement_notice, settings.shutdown_grace, diagnostics);
                            }
                        }
                        changed = true;
                    }
                    Ok(false) => {}
                    Err(error) => {
                        errors.first(error);
                        begin_stop(&mut driver, &mut errors, &mut stopping,
                            &mut retirement_notice, settings.shutdown_grace, diagnostics);
                        abort_statistics(&mut stats, &mut errors, diagnostics);
                        changed = true;
                    }
                }
            }
            if let Some(notice) = &mut retirement_notice && poll_timer(notice, cx) {
                diagnostics.observe("regex.retirement.pending", Level::WARNING, format_args!(
                    "REGEX original retirement still pending; actual drained={}", driver.is_drained()));
                retirement_notice = None; // Same original threshold, once only.
                changed = true;
            }
            if driver_closed && !stats_closing {
                stats_closing = true;
                if let Some(stats) = &mut stats && !stats.is_closed()
                    && let Err(error) = stats.begin_close(driver.metrics(), settings.statistics_grace)
                {
                    statistics_error(&mut errors.statistics, error, diagnostics);
                }
                changed = true;
            }
            if let Some(stats) = &mut stats {
                if !stats_closing && errors.statistics.is_none()
                    && let Err(error) = stats.refresh(driver.metrics())
                {
                    statistics_error(&mut errors.statistics, error, diagnostics);
                    changed = true;
                }
                // refresh admits only metadata. Poll immediately so each newly
                // admitted original operation registers its fixed hard alarm.
                if !stats.is_closed() {
                    match stats.poll(cx, None) {
                        Poll::Ready(Ok(_)) => changed = true,
                        Poll::Ready(Err(error)) => {
                            statistics_error(&mut errors.statistics, error, diagnostics);
                            changed = true;
                        }
                        Poll::Pending => {}
                    }
                }
            }
            // Resolver stays alive through actual Driver and statistics drain.
            match poll_broker(&mut broker, cx, diagnostics) {
                Poll::Ready(Ok(_)) => changed = true,
                Poll::Ready(Err(error)) => {
                    if errors.resolver.is_none() { errors.resolver = Some(Box::new(error)); }
                    abort_statistics(&mut stats, &mut errors, diagnostics);
                    begin_stop(&mut driver, &mut errors, &mut stopping,
                        &mut retirement_notice, settings.shutdown_grace, diagnostics);
                    changed = true;
                }
                Poll::Pending => {}
            }
            if driver_closed && stats.as_ref().is_none_or(|owner| owner.is_closed()) {
                return Poll::Ready(());
            }
            if poll_timer(&mut tick, cx) {
                if let Some(at) = Instant::now().checked_add(settings.tick) {
                    tick.as_mut().reset(at);
                } else {
                    errors.first("REGEX reactor observation time overflow".into());
                    begin_stop(&mut driver, &mut errors, &mut stopping,
                        &mut retirement_notice, settings.shutdown_grace, diagnostics);
                }
                changed = true;
            }
            if changed { Poll::Ready(()) } else { Poll::Pending }
        }).await;
        if driver_closed && stats.as_ref().is_none_or(|owner| owner.is_closed()) {
            break;
        }
    }
    while let Some(event) = driver.take_observation() {
        diagnostics.driver(event);
    }
    if let Err(error) = broker.disconnect() {
        if errors.resolver.is_none() {
            errors.resolver = Some(Box::new(error));
        } else {
            errors.resolver_cleanup = Some(Box::new(error));
        }
    }
    let report = Report {
        host: driver.server().report(),
        metrics: driver.metrics(),
        statistics: stats.as_ref().map(|owner| owner.report()),
        driver_drained: driver_closed,
    };
    if errors.failed() {
        Err(Box::new(LifecycleFailure {
            errors,
            report: Some(report),
        }))
    } else {
        Ok(report)
    }
}
// Construction failures retain the same actual Provider while its original
// close/worker receipts drain; no failed allocation is called ready or success.
#[expect(
    clippy::too_many_arguments,
    reason = "Original independently owned construction parts must remain outside one another through actual cleanup"
)]
async fn setup_failure<'p, D: Provider>(
    original: Failure,
    initial_statistics: Option<Failure>,
    mut server: Server,
    mut signer: Signer<'p, gnunet_regex_service::JobId>,
    mut provider: Option<D>,
    mut stats: Option<&mut statistics::Owner<'_>>,
    broker: &mut gnunet_resolver_broker::Driver<64, 4096>,
    diagnostics: &Diagnostics<'_>,
    statistics_grace: Duration,
) -> Result<Report, Failure> {
    let mut errors = Errors {
        original: Some(original),
        statistics: initial_statistics,
        ..Default::default()
    };
    errors.stop[0] = server
        .close_all(|event| diagnostics.host(event))
        .err()
        .map(|e| Box::new(e) as Failure);
    let _original = signer.close();
    if let Some(provider) = &mut provider {
        errors.stop[2] = provider.close().err();
    }
    if let Some(stats) = &mut stats
        && let Err(error) = stats.begin_close(server.core().metrics(), statistics_grace)
        && errors.statistics.is_none()
    {
        errors.statistics = Some(Box::new(error));
    }
    loop {
        let done = poll_fn(|cx| {
            let mut changed = false;
            if let Some(provider) = &mut provider
                && !provider.is_closed()
            {
                match provider.poll_native_guard(cx) {
                    Ok(p) => changed |= p,
                    Err(error) => {
                        if errors.retirement.is_none() {
                            errors.retirement = Some(error);
                        }
                        changed = true;
                    }
                }
                match provider.poll_next(cx) {
                    Poll::Ready(Ok(_)) => {
                        match provider.consume() {
                            Ok(Some(error)) | Err(error) if errors.retirement.is_none() => {
                                errors.retirement = Some(error)
                            }
                            _ => {}
                        }
                        changed = true;
                    }
                    Poll::Ready(Err(error)) => {
                        if errors.retirement.is_none() {
                            errors.retirement = Some(error);
                        }
                        changed = true;
                    }
                    Poll::Pending => {}
                }
            }
            if let Some(stats) = &mut stats
                && !stats.is_closed()
            {
                match stats.poll_native_guard(cx) {
                    Poll::Ready(Ok(_)) => changed = true,
                    Poll::Ready(Err(error)) => {
                        if errors.statistics.is_none() {
                            errors.statistics = Some(Box::new(error));
                        }
                        changed = true;
                    }
                    Poll::Pending => {}
                }
                match stats.poll(cx, None) {
                    Poll::Ready(Ok(_)) => changed = true,
                    Poll::Ready(Err(error)) => {
                        if errors.statistics.is_none() {
                            errors.statistics = Some(Box::new(error));
                        }
                        changed = true;
                    }
                    Poll::Pending => {}
                }
            }
            match poll_broker(broker, cx, diagnostics) {
                Poll::Ready(Ok(_)) => changed = true,
                Poll::Ready(Err(error)) => {
                    if errors.resolver.is_none() {
                        errors.resolver = Some(Box::new(error));
                    }
                    if let Some(stats) = &mut stats
                        && !stats.is_closed()
                        && let Err(error) = stats.abort()
                        && errors.statistics_cleanup.is_none()
                    {
                        errors.statistics_cleanup = Some(Box::new(error));
                    }
                    changed = true;
                }
                Poll::Pending => {}
            }
            let done = provider.as_ref().is_none_or(|p| p.is_closed())
                && stats.as_ref().is_none_or(|s| s.is_closed());
            if done || changed {
                Poll::Ready(done)
            } else {
                Poll::Pending
            }
        })
        .await;
        if done {
            break;
        }
        tokio::task::yield_now().await;
    }
    if let Err(error) = broker.disconnect() {
        if errors.resolver.is_none() {
            errors.resolver = Some(Box::new(error));
        } else {
            errors.resolver_cleanup = Some(Box::new(error));
        }
    }
    let report = Report {
        host: server.report(),
        metrics: server.core().metrics(),
        statistics: stats.as_ref().map(|s| s.report()),
        driver_drained: provider.as_ref().is_none_or(|p| p.is_closed()) && server.is_drained(),
    };
    Err(Box::new(LifecycleFailure {
        errors,
        report: Some(report),
    }))
}
