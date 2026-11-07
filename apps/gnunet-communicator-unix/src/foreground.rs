//! One PROGRAM task drives original UNIX providers, shared Producer and Resolver.
use crate::{Failure, control::Signals, early::Inherited, settings::Settings, statistics};
use gnunet_client_host::{EndpointSource, LiveConfiguration, resolution::SharedResolution};
use gnunet_config::Configuration;
use gnunet_ipc_unix::producer;
use gnunet_program_host::{program::Prepared, shared_clock::SharedClock};
use gnunet_resolver_broker::Driver;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_unix_communicator_host::{Close, Event, Progress, Runtime, Statistics};
use std::{
    cell::RefCell,
    future::{Future, poll_fn},
    io::{self, Write},
    rc::Rc,
    sync::Arc,
    task::Poll,
};
use tokio::time::Instant;

/// Preallocated original cleanup/report slots survive PROGRAM cancellation.
/// No report is an acknowledgement, persistence receipt or permission to retry.
#[derive(Debug, Default)]
struct Cleanup {
    native: Option<Close>,
    final_snapshot: Option<Statistics>,
    statistics: Option<producer::Failure>,
    statistics_drain: Option<producer::Failure>,
    statistics_abort: Option<producer::Failure>,
    publisher: Option<statistics::Report>,
    resolver_drain: Option<Failure>,
    resolver_close: Option<Failure>,
}
impl Cleanup {
    fn failed(&self) -> bool {
        self.native.as_ref().is_some_and(Close::uncertain)
            || self.statistics.is_some()
            || self.statistics_drain.is_some()
            || self.statistics_abort.is_some()
            || self.resolver_drain.is_some()
            || self.resolver_close.is_some()
    }
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.statistics
            .as_ref()
            .map(|e| e as &dyn std::error::Error)
            .or_else(|| {
                self.statistics_drain
                    .as_ref()
                    .map(|e| e as &dyn std::error::Error)
            })
            .or_else(|| {
                self.statistics_abort
                    .as_ref()
                    .map(|e| e as &dyn std::error::Error)
            })
            .or(self.resolver_drain.as_deref())
            .or(self.resolver_close.as_deref())
    }
}
type Retained = Rc<RefCell<Cleanup>>;
#[derive(Debug, Default)]
struct Failures {
    program: Option<Failure>,
    task: Option<Failure>,
    cleanup: Cleanup,
}
impl Failures {
    fn finish(self) -> Result<(), Failure> {
        if self.program.is_none() && self.task.is_none() && !self.cleanup.failed() {
            Ok(())
        } else {
            Err(Box::new(self))
        }
    }
}
impl std::fmt::Display for Failures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UNIX communicator program={:?}; task={:?}; original cleanup/publisher={:?}",
            self.program, self.task, self.cleanup
        )
    }
}
impl std::error::Error for Failures {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.program
            .as_deref()
            .or(self.task.as_deref())
            .or_else(|| self.cleanup.source())
    }
}
#[derive(Debug)]
struct RunFailure {
    original: Option<Failure>,
    output: Option<io::Error>,
}
impl std::fmt::Display for RunFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UNIX original={:?}; independent stdout={:?}",
            self.original, self.output
        )
    }
}
impl std::error::Error for RunFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.output.as_ref().map(|e| e as &dyn std::error::Error))
    }
}
fn observe(event: Event<'_>) {
    match event {
        Event::Bound(_)
        | Event::Attached(_)
        | Event::Identity { .. }
        | Event::ConnectRetry(_)
        | Event::Closed { .. }
        | Event::SendRetired { .. }
        | Event::IncomingRetired { .. }
        | Event::OutputRetired { .. }
        | Event::InputRetired { .. }
        | Event::TransportLost { .. }
        | Event::QueueExpired(_)
        | Event::SendError {
            retrying: false, ..
        }
        | Event::Restored { .. } => crate::diagnostic(format_args!("communicator-unix: {event:?}")),
        _ => {}
    }
}
/// This guard is built before PROGRAM is allowed to reject/drop the task.
/// Thus even a never-polled task retains actual original Resolver cleanup.
struct ResolverOwner {
    driver: Option<Driver<64, 256>>,
    live: bool,
    retained: Retained,
}
impl ResolverOwner {
    fn close(&mut self) {
        if let Some(mut driver) = self.driver.take() {
            let result = driver.disconnect();
            if let Err(error) = result {
                self.retained.borrow_mut().resolver_close = Some(Box::new(error));
            }
        }
        self.live = false;
    }
}
impl Drop for ResolverOwner {
    fn drop(&mut self) {
        self.close();
    }
}
struct Owners<'id> {
    runtime: Option<Runtime<'id>>,
    statistics: Option<statistics::Forwarder<'id>>,
    resolver: ResolverOwner,
    retained: Retained,
    done: bool,
}
impl Owners<'_> {
    fn retire_runtime(&mut self) {
        if let Some(mut runtime) = self.runtime.take() {
            let close = runtime.close(&mut observe);
            let final_snapshot = runtime.statistics();
            let mut retained = self.retained.borrow_mut();
            retained.native = Some(close);
            retained.final_snapshot = Some(final_snapshot);
        }
    }
    fn abort_statistics(&mut self) {
        if let Some(statistics) = &mut self.statistics {
            let error = statistics.abort().err();
            let report = statistics.report();
            let mut retained = self.retained.borrow_mut();
            if let Some(error) = error {
                retained.statistics_abort = Some(error);
            }
            retained.publisher = Some(report);
        }
    }
}
impl Drop for Owners<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.retire_runtime();
            self.abort_statistics();
            self.resolver.close();
            self.done = true;
        }
    }
}
pub(super) async fn scheduled(
    prepared: Prepared,
    clock: SharedClock,
    settings: Settings,
    inherited: Inherited,
) -> Result<(), Failure> {
    let config = prepared.main().config.duplicate()?;
    let source: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
    let live = LiveConfiguration::new(config.duplicate()?);
    let (mut program_context, resolver) = gnunet_resolver_broker::broker::<64, 256>(
        live.clone(),
        settings.resolver,
        gnunet_resolver_broker::native_profile()?,
        source.clone(),
    )?;
    let resolution = program_context.resolution_context();
    let retained = Rc::new(RefCell::new(Cleanup::default()));
    let resolver = ResolverOwner {
        driver: Some(resolver),
        live: true,
        retained: retained.clone(),
    };
    let result = Rc::new(RefCell::new(None));
    let receiving = Rc::clone(&result);
    let task_cleanup = retained.clone();
    let program = prepared
        .run_scheduled(&mut program_context, clock, 1, move |_main, scope| {
            let destination = Rc::clone(&receiving);
            let stopping = scope.clone();
            if let Err(error) = scope.spawn(async move {
                let completed = run_owned(
                    resolver,
                    RunInputs {
                        config,
                        settings,
                        inherited,
                        live,
                        resolution,
                        source,
                        retained: task_cleanup,
                    },
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
        None => Some("PROGRAM ended without UNIX communicator task completion".into()),
    };
    let program = match program {
        Ok(1) => None,
        Ok(code) => Some(format!("UNIX communicator PROGRAM returned source code {code}").into()),
        Err(error) => Some(Box::new(error) as Failure),
    };
    let cleanup = std::mem::take(&mut *retained.borrow_mut());
    Failures {
        program,
        task,
        cleanup,
    }
    .finish()
}
enum Turn {
    Signal,
    Resolver,
    Statistics,
    StatisticsFailed,
    Runtime(Progress),
}
struct RunInputs {
    config: Configuration,
    settings: Settings,
    inherited: Inherited,
    live: LiveConfiguration,
    resolution: SharedResolution,
    source: Arc<dyn RuntimeClock>,
    retained: Retained,
}
async fn run_owned(resolver: ResolverOwner, inputs: RunInputs) -> Result<(), Failure> {
    let RunInputs {
        config: _config,
        settings,
        inherited,
        live,
        resolution,
        source,
        retained,
    } = inputs;
    let instance = gnunet_unix_communicator_host::Instance::new();
    let mut pils = gnunet_pils::client::Instance::new();
    let mut statistics_instance = gnunet_ipc_unix::handle::Instance::new();
    // Install the guard before signals/bind/statistics construction can fail.
    let mut owners = Owners {
        runtime: None,
        statistics: None,
        resolver,
        retained,
        done: false,
    };
    let mut signals = Signals::new(inherited.parent)?;
    let endpoint =
        |section: &'static [u8]| EndpointSource::live(live.clone(), section, resolution.clone());
    let runtime = Runtime::bind(
        &instance,
        &mut pils,
        gnunet_unix_communicator_host::Sources {
            transport: endpoint(b"transport"),
            pils: endpoint(b"pils"),
        },
        &settings.path,
        settings.limits,
    )?;
    let initial = runtime.statistics();
    owners.runtime = Some(runtime);
    owners.statistics = Some(statistics::new(
        &mut statistics_instance,
        live,
        resolution,
        source,
        initial,
    )?);
    let startup = Instant::now()
        .checked_add(settings.limits.startup)
        .ok_or("UNIX communicator startup bound overflow")?;
    let mut ready = false;
    let mut cursor = 0usize;
    let outcome = loop {
        let runtime = owners
            .runtime
            .as_ref()
            .ok_or("original UNIX Runtime is absent")?;
        if !ready && runtime.ready() {
            let output = {
                let mut out = io::stdout().lock();
                writeln!(out,"READY communicator-unix wire=0.29.1 purpose=testing sender-authentication=none pils=actual-public-identity transport=registration-written address=written mtu={} hidden-tasks=0",runtime.mtu()).and_then(|()|out.flush())
            };
            if let Err(error) = output {
                break Err(Box::new(error) as Failure);
            }
            ready = true;
        }
        let wait = (!ready).then_some(startup);
        let step = turn(&mut owners, &mut signals, wait, &mut cursor).await;
        match step {
            Ok(Turn::Signal | Turn::Runtime(Progress::Stopped) | Turn::StatisticsFailed) => break Ok(()),
            Ok(Turn::Runtime(Progress::WaitDeadline)) if !ready => break Err("UNIX communicator actual source readiness did not complete before original startup deadline".into()),
            Ok(_) => {},
            Err(error) => break Err(error),
        }
    };
    // Physical Runtime close changes queues/failure counters. Snapshot only AFTER
    // that real close, then freeze one original 5s statistics final-drain target.
    owners.retire_runtime();
    drain_statistics(&mut owners).await;
    owners.resolver.close();
    owners.done = true;
    let report = {
        let mut out = io::stdout().lock();
        writeln!(out,"STOPPED communicator-unix ready-observed={ready} original-sources=retired remote-delivery=not-claimed sender-authentication=none").and_then(|()|out.flush())
    };
    {
        let retained = owners.retained.borrow();
        crate::diagnostic(format_args!(
            "communicator-unix original STATISTICS final={:?}; final Runtime counters={:?}",
            retained.publisher, retained.final_snapshot,
        ));
    }
    if outcome.is_err() || report.is_err() {
        Err(Box::new(RunFailure {
            original: outcome.err(),
            output: report.err(),
        }))
    } else {
        Ok(())
    }
}
async fn turn(
    owners: &mut Owners<'_>,
    signals: &mut Signals,
    wait: Option<Instant>,
    cursor: &mut usize,
) -> Result<Turn, Failure> {
    let runtime = owners
        .runtime
        .as_mut()
        .ok_or("original UNIX Runtime is absent")?;
    let statistics = owners
        .statistics
        .as_mut()
        .ok_or("original UNIX statistics owner is absent")?;
    let resolver = owners
        .resolver
        .driver
        .as_mut()
        .ok_or("original Resolver owner is absent")?;
    let resolver_live = &mut owners.resolver.live;
    let retained = owners.retained.clone();
    let mut resolving = std::pin::pin!(resolver.drive_waiting(wait, |event| crate::diagnostic(
        format_args!("communicator-unix Resolver={event:?}")
    )));
    poll_fn(|cx| {
        if let Poll::Ready(Err(error)) = statistics.poll_native_guard(cx) {
            retained.borrow_mut().statistics = Some(error);
            return Poll::Ready(Ok(Turn::StatisticsFailed));
        }
        if let Poll::Ready(result) = signals.poll(cx) {
            return Poll::Ready(
                result
                    .map(|()| Turn::Signal)
                    .map_err(|e| Box::new(e) as Failure),
            );
        }
        if !statistics.is_closed() {
            if let Err(error) = statistics.refresh(statistics::snapshot(runtime.statistics())) {
                retained.borrow_mut().statistics = Some(error);
                return Poll::Ready(Ok(Turn::StatisticsFailed));
            }
            // A new setter gets its unchanged native alarm in this very poll,
            // before Resolver/canonical work can stay Pending.
            if let Poll::Ready(Err(error)) = statistics.poll_native_guard(cx) {
                retained.borrow_mut().statistics = Some(error);
                return Poll::Ready(Ok(Turn::StatisticsFailed));
            }
        }
        for offset in 0..3 {
            let class = (*cursor + offset) % 3;
            let polled = match class {
                0 if *resolver_live => resolving.as_mut().poll(cx).map(|result| {
                    result.map(|_| Turn::Resolver).map_err(|error| {
                        *resolver_live = false;
                        Box::new(error) as Failure
                    })
                }),
                1 => runtime.poll(cx, wait, &mut observe).map(|result| {
                    result
                        .map(Turn::Runtime)
                        .map_err(|e| Box::new(e) as Failure)
                }),
                2 if !statistics.is_closed() => match statistics.poll(cx, wait) {
                    Poll::Ready(Ok(_)) => Poll::Ready(Ok(Turn::Statistics)),
                    Poll::Ready(Err(error)) => {
                        retained.borrow_mut().statistics = Some(error);
                        Poll::Ready(Ok(Turn::StatisticsFailed))
                    }
                    Poll::Pending => Poll::Pending,
                },
                _ => Poll::Pending,
            };
            if polled.is_ready() {
                *cursor = (class + 1) % 3;
                return polled;
            }
        }
        Poll::Pending
    })
    .await
}
async fn drain_statistics(owners: &mut Owners<'_>) {
    let final_snapshot = owners.retained.borrow().final_snapshot;
    let Some(statistics) = owners.statistics.as_mut() else {
        return;
    };
    if let Some(final_snapshot) = final_snapshot
        && let Err(error) = statistics.begin_close(
            statistics::snapshot(final_snapshot),
            statistics::FINAL_GRACE,
        )
    {
        owners.retained.borrow_mut().statistics_drain = Some(error);
    }
    let mut cursor = false;
    while !statistics.is_closed() {
        let retained = owners.retained.clone();
        let resolver_live = &mut owners.resolver.live;
        {
            let resolving = owners.resolver.driver.as_mut().map(|resolver| {
                resolver.drive_waiting(None, |event| {
                    crate::diagnostic(format_args!("communicator-unix final Resolver={event:?}"))
                })
            });
            let mut resolving = std::pin::pin!(resolving);
            poll_fn(|cx| {
                // Source-independent native hard comes before any Resolver or
                // canonical-clock work, even if that source constantly wakes.
                if let Poll::Ready(Err(error)) = statistics.poll_native_guard(cx) {
                    retained.borrow_mut().statistics_drain = Some(error);
                    return Poll::Ready(());
                }
                for offset in 0..2 {
                    let resolver_turn = (usize::from(cursor) + offset) % 2 == 0;
                    if resolver_turn && *resolver_live {
                        if let Some(mut resolving) = resolving.as_mut().as_pin_mut() {
                            match resolving.as_mut().poll(cx) {
                                Poll::Ready(Ok(_)) => return Poll::Ready(()),
                                Poll::Ready(Err(error)) => {
                                    *resolver_live = false;
                                    retained.borrow_mut().resolver_drain = Some(Box::new(error));
                                    return Poll::Ready(());
                                }
                                Poll::Pending => {}
                            }
                        }
                    } else if !resolver_turn {
                        match statistics.poll(cx, None) {
                            Poll::Ready(Ok(_)) => return Poll::Ready(()),
                            Poll::Ready(Err(error)) => {
                                retained.borrow_mut().statistics_drain = Some(error);
                                return Poll::Ready(());
                            }
                            Poll::Pending => {}
                        }
                    }
                }
                Poll::Pending
            })
            .await
        }
        cursor = !cursor;
    }
    // A healthy native Destroyed has been consumed, or fail/abort physically
    // retired the original owner; no queue admission is interpreted as delivery.
    owners.retained.borrow_mut().publisher = Some(statistics.report());
}
