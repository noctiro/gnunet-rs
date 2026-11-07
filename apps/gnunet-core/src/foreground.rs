use crate::{
    Failure,
    bounds::{Check, Due, Guard},
    control::Signals,
    early::Inherited,
    reporting::{Cleanup, Reports},
    settings::Settings,
};
use gnunet_client_host::{EndpointSource, LiveConfiguration};
use gnunet_core_client_host::{ConnectionEpoch, LossCause, Monitor, MonitorEvent, MonitorProgress};
use gnunet_program_host::{program::Prepared, shared_clock::SharedClock};
use gnunet_resolver_broker::Driver;
use gnunet_service_runtime::clock::RuntimeClock;
use std::{
    cell::RefCell,
    future::{Future, poll_fn},
    io::{self, Write},
    rc::Rc,
    sync::Arc,
    task::Poll,
};

#[derive(Debug, Default)]
struct Failures {
    program: Option<Failure>,
    task: Option<Failure>,
    native: Option<Failure>,
    resolver: Option<Failure>,
    cleanup: Option<Failure>,
    report: Option<Failure>,
}
impl Failures {
    fn finish(self) -> Result<(), Failure> {
        if self.program.is_none()
            && self.task.is_none()
            && self.native.is_none()
            && self.resolver.is_none()
            && self.cleanup.is_none()
            && self.report.is_none()
        {
            Ok(())
        } else {
            Err(Box::new(self))
        }
    }
}
impl std::fmt::Display for Failures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CORE CLI failures: {self:?}")
    }
}
impl std::error::Error for Failures {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.program
            .as_deref()
            .or(self.task.as_deref())
            .or(self.native.as_deref())
            .or(self.resolver.as_deref())
            .or(self.cleanup.as_deref())
            .or(self.report.as_deref())
    }
}
#[derive(Debug)]
struct Lost {
    epoch: u64,
    cause: LossCause,
}
impl std::fmt::Display for Lost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "original CORE source {} lost: {:?}",
            self.epoch, self.cause
        )
    }
}
impl std::error::Error for Lost {}
#[derive(Debug)]
struct Limit {
    bound: &'static str,
    attempt: Option<Failure>,
}
impl std::fmt::Display for Limit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "original CORE CLI {} reached; prior attempt={:?}",
            self.bound, self.attempt
        )
    }
}
impl std::error::Error for Limit {}

// Own the actual Resolver before the PROGRAM callback/task is constructed.
// A scheduler refusal or unpolled task drop still disconnects the same driver
// and retains its original cleanup cause through the outer selected Reporter.
struct ResolverOwner {
    driver: Driver<32, 64>,
    closed: bool,
    reports: Reports,
}
impl ResolverOwner {
    fn close(&mut self) -> Option<Failure> {
        if self.closed {
            return None;
        }
        self.closed = true;
        self.driver
            .disconnect()
            .err()
            .map(|error| Box::new(error) as Failure)
    }
}
impl Drop for ResolverOwner {
    fn drop(&mut self) {
        if let Some(error) = self.close() {
            self.reports.cleanup(Cleanup::Resolver, error);
        }
    }
}
struct Owners<'a> {
    monitor: Monitor<'a>,
    resolver: ResolverOwner,
    closed: bool,
    reports: Reports,
}
impl Owners<'_> {
    fn close(&mut self) -> (Option<Failure>, Option<Failure>) {
        if self.closed {
            return (None, None);
        }
        self.closed = true;
        // Both close calls remain independent; neither requires a fresh clock.
        let monitor = match self.monitor.close() {
            Ok(Some(MonitorProgress::Lost { epoch, cause })) => {
                self.reports.debug(
                    "core-cli.source.retired",
                    format_args!(
                        "core-cli original source epoch={} physically retired: {cause:?}",
                        epoch.value()
                    ),
                );
                None
            }
            Ok(None) => None,
            Ok(Some(_)) => Some("CORE monitor returned an unexpected close receipt".into()),
            Err(error) => Some(Box::new(error) as Failure),
        };
        let resolver = self.resolver.close();
        (monitor, resolver)
    }
}
impl Drop for Owners<'_> {
    fn drop(&mut self) {
        let (monitor, resolver) = self.close();
        if let Some(error) = monitor {
            self.reports.cleanup(Cleanup::Monitor, error);
        }
        if let Some(error) = resolver {
            self.reports.cleanup(Cleanup::Resolver, error);
        }
    }
}

pub(super) async fn scheduled(
    prepared: Prepared,
    clock: SharedClock,
    settings: Settings,
    inherited: Inherited,
    reports: Reports,
) -> Result<(), Failure> {
    let config = prepared.main().config.duplicate()?;
    let runtime: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
    // The scope's native and logical origins are fixed before creating ports.
    let overall = Due::after(&*runtime, settings.lifetime, "lifetime")?;
    let initial = Due::after(&*runtime, settings.snapshot, "initial snapshot")?.within(overall);
    let live = LiveConfiguration::new(config);
    let (mut context, resolver) = gnunet_resolver_broker::broker::<32, 64>(
        live.clone(),
        settings.resolver,
        gnunet_resolver_broker::native_profile()?,
        runtime.clone(),
    )?;
    let resolution = context.resolution_context();
    let resolver = ResolverOwner {
        driver: resolver,
        closed: false,
        reports: reports.clone(),
    };
    let result = Rc::new(RefCell::new(None));
    let receiving = result.clone();
    let task_reports = reports.clone();
    let program = prepared
        .run_scheduled(&mut context, clock, 1, move |_main, scope| {
            let destination = receiving.clone();
            let stopping = scope.clone();
            let reports = task_reports.clone();
            if let Err(error) = scope.spawn(async move {
                let completed = run(
                    Setup {
                        settings,
                        inherited,
                        live,
                        resolution,
                        clock: runtime,
                        overall,
                        initial,
                    },
                    resolver,
                    reports,
                )
                .await;
                *destination.borrow_mut() = Some(completed);
                if let Err(error) = stopping.shutdown() {
                    let prior = destination.borrow_mut().take().and_then(Result::err);
                    *destination.borrow_mut() = Some(
                        Failures {
                            program: Some(Box::new(error)),
                            task: prior,
                            ..Default::default()
                        }
                        .finish(),
                    );
                }
            }) {
                *receiving.borrow_mut() = Some(Err(error.into()));
                if let Err(cleanup) = scope.shutdown() {
                    let prior = receiving.borrow_mut().take().and_then(Result::err);
                    *receiving.borrow_mut() = Some(
                        Failures {
                            program: Some(Box::new(cleanup)),
                            task: prior,
                            ..Default::default()
                        }
                        .finish(),
                    );
                }
            }
        })
        .await;
    let task = match result.borrow_mut().take() {
        Some(outcome) => outcome.err(),
        None => Some("PROGRAM ended without the original CORE CLI task completion".into()),
    };
    let program = match program {
        Ok(1) => None,
        Ok(code) => Some(format!("CORE CLI PROGRAM returned source code {code}").into()),
        Err(error) => Some(Box::new(error) as Failure),
    };
    Failures {
        program,
        task,
        ..Default::default()
    }
    .finish()
}
struct Setup {
    settings: Settings,
    inherited: Inherited,
    live: LiveConfiguration,
    resolution: gnunet_client_host::resolution::SharedResolution,
    clock: Arc<dyn RuntimeClock>,
    overall: Due,
    initial: Due,
}
fn prepare<'a>(
    instance: &'a mut gnunet_core_client_host::Instance,
    setup: &Setup,
    parent: Option<gnunet_service_startup::ParentControl>,
) -> Result<(Monitor<'a>, Guard, Signals), Failure> {
    let source =
        EndpointSource::live(setup.live.clone(), b"core", setup.resolution.clone()).snapshot()?;
    if !Arc::ptr_eq(&setup.clock, &source.clock()) {
        return Err("CORE CLI clock domains differ".into());
    }
    let guard = Guard::new(setup.clock.clone())?;
    let signals = Signals::new(parent)?;
    let monitor = Monitor::new(instance, source, setup.settings.native)?;
    Ok((monitor, guard, signals))
}
async fn run(
    mut setup: Setup,
    mut resolver: ResolverOwner,
    reports: Reports,
) -> Result<(), Failure> {
    let mut instance = gnunet_core_client_host::Instance::new();
    let parent = setup.inherited.parent.take();
    let prepared = prepare(&mut instance, &setup, parent);
    let (monitor, mut guard, mut signals) = match prepared {
        Ok(v) => v,
        Err(error) => {
            let cleanup = resolver.close();
            return Failures {
                native: Some(error),
                cleanup,
                ..Default::default()
            }
            .finish();
        }
    };
    let mut owners = Owners {
        monitor,
        resolver,
        closed: false,
        reports: reports.clone(),
    };
    let mut current: Option<ConnectionEpoch<'_>> = None;
    let mut snapshot = Some(setup.initial);
    let mut frame = None;
    let mut current_snapshot = false;
    let mut rows = 0u64;
    let mut reconnects = 0u64;
    let mut written = 0usize;
    let mut prefix = 0usize;
    let mut first_attempt = None;
    let mut turn = false;
    let mut native = None;
    let mut resolver_failure = None;
    if setup.settings.monitor
        && let Err(error) = writeln!(
            io::stdout().lock(),
            "Monitoring connections. Press CTRL-C to quit.\n"
        )
    {
        native = Some(Box::new(error) as Failure);
    }
    while native.is_none() && resolver_failure.is_none() && !reports.failed() {
        enum Wake<'a> {
            ReportingFailed,
            Signal,
            Resolver,
            Monitor(MonitorProgress<'a>),
            Expired(&'static str),
        }
        let targets = [
            setup.overall,
            snapshot.unwrap_or(setup.overall),
            frame.unwrap_or(setup.overall),
        ];
        let wait = targets.iter().map(|d| d.native).min();
        let result = {
            let (monitor, resolver) = (&mut owners.monitor, &mut owners.resolver.driver);
            let mut resolving = std::pin::pin!(resolver.drive_waiting(wait, |_event| {}));
            let mut monitoring = std::pin::pin!(monitor.drive(wait));
            poll_fn(|cx| {
                reports.register(cx);
                if reports.failed() {
                    return Poll::Ready(Ok(Wake::ReportingFailed));
                }
                match signals.poll(cx) {
                    Poll::Ready(Ok(())) => return Poll::Ready(Ok(Wake::Signal)),
                    Poll::Ready(Err(error)) => {
                        return Poll::Ready(Err((Box::new(error) as Failure, false)));
                    }
                    Poll::Pending => {}
                }
                match guard.poll(cx, &targets) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err((error, false))),
                    Poll::Ready(Ok(Check::Expired(label))) => {
                        return Poll::Ready(Ok(Wake::Expired(label)));
                    }
                    Poll::Ready(Ok(Check::Current)) => {}
                }
                for direction in [turn, !turn] {
                    if direction {
                        if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                            turn = false;
                            return Poll::Ready(
                                result
                                    .map(|_| Wake::Resolver)
                                    .map_err(|e| (Box::new(e) as Failure, true)),
                            );
                        }
                    } else if let Poll::Ready(result) = monitoring.as_mut().poll(cx) {
                        turn = true;
                        return Poll::Ready(
                            result
                                .map(Wake::Monitor)
                                .map_err(|e| (Box::new(e) as Failure, false)),
                        );
                    }
                }
                Poll::Pending
            })
            .await
        };
        let progress = match result {
            Err((error, is_resolver)) => {
                if is_resolver {
                    resolver_failure = Some(error)
                } else {
                    native = Some(error)
                }
                break;
            }
            Ok(Wake::ReportingFailed) => break,
            Ok(Wake::Expired(label)) => {
                if label == "lifetime" && setup.settings.monitor && current_snapshot {
                    reports.debug(
                        "core-cli.lifetime",
                        format_args!("core-cli declared original monitor lifetime reached"),
                    );
                } else {
                    native = Some(Box::new(Limit {
                        bound: label,
                        attempt: first_attempt.take(),
                    }));
                }
                break;
            }
            Ok(Wake::Signal) => {
                if !setup.settings.monitor && !current_snapshot {
                    native =
                        Some("CORE snapshot canceled before the actual iteration marker".into());
                }
                break;
            }
            Ok(Wake::Resolver) => {
                tokio::task::yield_now().await;
                continue;
            }
            Ok(Wake::Monitor(progress)) => progress,
        };
        let handled = (|| -> Result<bool, Failure> {
            match progress {
                MonitorProgress::Connected(epoch) => {
                    if current.is_some() {
                        return Err(
                            "CORE monitor attached while an original source remains current".into(),
                        );
                    }
                    current = Some(epoch);
                    current_snapshot = false;
                    written = 0;
                    prefix = 0;
                    frame = None;
                    first_attempt = None;
                    reports.debug(
                        "core-cli.source.attached",
                        format_args!(
                            "core-cli actual source epoch={} attached; initial snapshot pending",
                            epoch.value()
                        ),
                    );
                }
                MonitorProgress::Inbound { epoch, event } => {
                    if current != Some(epoch) {
                        return Err("CORE monitor returned a foreign retired epoch".into());
                    }
                    if written != 4 {
                        return Err(
                            "CORE response preceded the complete original monitor-request write"
                                .into(),
                        );
                    }
                    frame = None;
                    prefix = 0;
                    let after = setup.clock.sample()?.now;
                    if let Some(due) = targets.iter().find(|due| {
                        tokio::time::Instant::now() >= due.native || after >= due.logical
                    }) {
                        return Err(Box::new(Limit {
                            bound: due.name,
                            attempt: first_attempt.take(),
                        }));
                    }
                    match event {
                        MonitorEvent::SnapshotFinished => {
                            if current_snapshot {
                                return Err("duplicate CORE initial snapshot marker".into());
                            }
                            current_snapshot = true;
                            snapshot = None;
                            reports.debug(
                                "core-cli.snapshot.finished",
                                format_args!(
                                    "core-cli actual source epoch={} initial iteration finished",
                                    epoch.value()
                                ),
                            );
                            if !setup.settings.monitor {
                                return Ok(true);
                            }
                        }
                        MonitorEvent::Update {
                            peer,
                            state,
                            timeout,
                        } => {
                            if rows >= setup.settings.rows {
                                return Err("CORE CLI output-row capacity reached before another actual update".into());
                            }
                            rows = rows
                                .checked_add(1)
                                .ok_or("CORE CLI row counter exhausted")?;
                            crate::output::update(
                                &mut io::stdout().lock(),
                                after,
                                &peer.0,
                                state,
                                timeout,
                            )?;
                        }
                        MonitorEvent::ServiceLost => {
                            return Err(
                                "CORE local-loss callback appeared as an inbound wire event".into(),
                            );
                        }
                    }
                }
                MonitorProgress::Activity {
                    epoch,
                    read_bytes,
                    written_bytes,
                } => {
                    if current != Some(epoch) {
                        return Err("CORE activity has a foreign source epoch".into());
                    }
                    written = written
                        .checked_add(written_bytes)
                        .ok_or("CORE original write count overflow")?;
                    if written > 4 {
                        return Err(
                            "CORE monitor wrote beyond its original four-byte request".into()
                        );
                    }
                    if read_bytes != 0 {
                        if frame.is_none() {
                            frame = Some(
                                Due::after(&*setup.clock, setup.settings.frame, "partial frame")?
                                    .within(setup.overall),
                            );
                        }
                        prefix = prefix
                            .checked_add(read_bytes)
                            .ok_or("CORE original frame byte count overflow")?;
                        if prefix > setup.settings.native.frame_bytes {
                            return Err("CORE monitor input-frame capacity".into());
                        }
                    }
                }
                MonitorProgress::Lost { epoch, cause } => {
                    if current != Some(epoch) {
                        return Err("CORE loss has a foreign source epoch".into());
                    }
                    // The shared native owner physically stopped this exact MQ
                    // before reporting loss. No old marker/update is carried over.
                    current = None;
                    current_snapshot = false;
                    frame = None;
                    reports.warning(
                        "core-cli.source.lost",
                        format_args!(
                            "Connection to CORE service lost; original epoch={} request-prefix={written}/4 input-prefix={prefix} cause={cause:?}",
                            epoch.value()
                        ),
                    );
                    let lost = Box::new(Lost {
                        epoch: epoch.value(),
                        cause,
                    }) as Failure;
                    if !setup.settings.monitor {
                        return Err(lost);
                    }
                    reconnects = reconnects
                        .checked_add(1)
                        .ok_or("CORE reconnect count exhausted")?;
                    if reconnects > setup.settings.reconnects {
                        return Err(Box::new(Limit {
                            bound: "replacement-source limit",
                            attempt: Some(lost),
                        }));
                    }
                    first_attempt = Some(lost);
                    prefix = 0;
                    written = 0;
                    snapshot = Some(
                        Due::after(
                            &*setup.clock,
                            setup.settings.snapshot,
                            "replacement snapshot",
                        )?
                        .within(setup.overall),
                    );
                }
                MonitorProgress::ConnectRetry { error, retry_after } => {
                    reports.warning(
                        "core-cli.connect.retry",
                        format_args!(
                            "core-cli actual connect attempt failed; source retry={retry_after:?} cause={error}"
                        ),
                    );
                    if first_attempt.is_none() {
                        first_attempt = Some(Box::new(error) as Failure);
                    }
                }
                MonitorProgress::Unavailable(error) => return Err(error.into()),
                MonitorProgress::WaitDeadline => {}
                MonitorProgress::Closed => {
                    return Err("CORE monitor closed without original request completion".into());
                }
            }
            Ok(false)
        })();
        match handled {
            Ok(true) => break,
            Ok(false) => {}
            Err(error) => {
                native = Some(error);
                break;
            }
        }
        // Bound foreground monopolization even for a large already-buffered
        // snapshot or a simultaneously ready Resolver. Cursors stay in owners.
        tokio::task::yield_now().await;
    }
    let (monitor_cleanup, resolver_cleanup) = owners.close();
    // Final output flushing happens only after both actual network owners stop.
    let report = io::stdout()
        .lock()
        .flush()
        .err()
        .map(|e| Box::new(e) as Failure);
    reports.debug(
        "core-cli.sources.finished",
        format_args!(
            "core-cli sources retired rows={rows} reconnects={reconnects}; original request-prefix={written}/4 input-prefix={prefix}"
        ),
    );
    Failures {
        native,
        resolver: resolver_failure,
        report,
        cleanup: match (monitor_cleanup, resolver_cleanup) {
            (None, None) => None,
            (Some(error), None) | (None, Some(error)) => Some(error),
            (Some(monitor), Some(resolver)) => Some(Box::new(Failures {
                native: Some(monitor),
                resolver: Some(resolver),
                ..Default::default()
            })),
        },
        ..Default::default()
    }
    .finish()
}
