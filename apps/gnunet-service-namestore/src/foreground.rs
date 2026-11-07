//! Original NAMESTORE/worker owners under standard SERVICE startup.
use crate::{
    Failure,
    control::Signals,
    lifecycle::{Cleanup, Resolver},
    settings::Settings,
};
use gnunet_config::Configuration;
use gnunet_namestore_host::{
    backend::{self, Store},
    server::{self, Event, Progress, Server},
    worker::{self, Worker},
};
use gnunet_program_host::{reporting::Reporter, shared_clock::SharedClock};
use gnunet_resolver_broker::LiveConfiguration;
use gnunet_service_runtime::{
    BoundListeners,
    accepted::SocketEvent,
    clock::RuntimeClock,
    service::{Listener, ShutdownMode},
};
use gnunet_service_startup::{ParentControl, daemon::ChildReady};
use std::{
    fmt,
    future::{Future, poll_fn},
    io::{self, Write},
    pin::Pin,
    sync::Arc,
    task::Poll,
};
use tokio::time::{Instant, Sleep};
struct StreamFact {
    client: u64,
    request: Option<u32>,
    debt: gnunet_namestore::StreamLoss,
}
impl fmt::Debug for StreamFact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamFact")
            .field("client", &self.client)
            .field("request", &self.request)
            .field("debt", &self.debt)
            .finish()
    }
}
/// Bounded original diagnostic causes; no request/key/snapshot is retained here.
#[derive(Default)]
struct Observations {
    socket: Option<SocketEvent>,
    source: Option<(u64, server::CloseCause)>,
    stream: Option<StreamFact>,
    storage: Option<Arc<backend::Failure>>,
    cleanup: Option<server::Error>,
}
impl fmt::Debug for Observations {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Observations")
            .field("socket", &self.socket)
            .field("source", &self.source)
            .field("stream", &self.stream)
            .field("storage", &self.storage)
            .field("cleanup", &self.cleanup)
            .finish()
    }
}
impl Observations {
    fn observe(&mut self, event: Event, reports: &Reporter) {
        match event {
            Event::Socket(SocketEvent::Failed(error)) if error.is_emfile() => {}
            Event::Socket(SocketEvent::Failed(error)) => {
                reports.warning(
                    "namestore.socket.failed",
                    format_args!("NAMESTORE socket: {error:?}"),
                );
                self.socket.get_or_insert(SocketEvent::Failed(error));
            }
            Event::Socket(event) => reports.debug(
                "namestore.socket.activity",
                format_args!("NAMESTORE socket: {event:?}"),
            ),
            Event::Closed { client, cause } => {
                if matches!(
                    &cause,
                    server::CloseCause::Shutdown | server::CloseCause::Eof
                ) {
                    reports.debug(
                        "namestore.source.closed",
                        format_args!("NAMESTORE source={} closed: {cause:?}", client.value()),
                    );
                } else {
                    reports.warning(
                        "namestore.source.failed",
                        format_args!("NAMESTORE source={} retired: {cause:?}", client.value()),
                    );
                    self.source.get_or_insert((client.value(), cause));
                }
            }
            Event::StreamLost {
                client,
                request,
                debt,
            } => {
                reports.debug(
                    "namestore.stream.retired",
                    format_args!(
                        "NAMESTORE source={} stream={request:?} debt={debt:?}",
                        client.value()
                    ),
                );
                self.stream.get_or_insert(StreamFact {
                    client: client.value(),
                    request,
                    debt,
                });
            }
            Event::StorageFailed(error) => {
                reports.warning(
                    "namestore.storage.failed",
                    format_args!("NAMESTORE actual storage: {error}"),
                );
                self.storage.get_or_insert(error);
            }
            Event::CleanupFailed(error) => {
                reports.warning(
                    "namestore.source.cleanup",
                    format_args!("NAMESTORE independent cleanup: {error}"),
                );
                self.cleanup.get_or_insert(server::Error::Protocol(error));
            }
            _ => {}
        }
    }
}
/// The same Server closes original MQs if this private future is abandoned.
/// Worker Drop remains the original blocking join fallback, not a fake receipt.
struct Owners<'worker> {
    server: Server<'worker>,
    reports: Reporter,
    done: bool,
}
impl Drop for Owners<'_> {
    fn drop(&mut self) {
        if !self.done {
            let mut facts = Observations::default();
            self.server
                .close_all(&mut |event| facts.observe(event, &self.reports));
            self.reports.warning("namestore.task.cancelled",format_args!("NAMESTORE private foreground was abandoned; actual sources retired; original worker owner still joins; source observations={facts:?}"));
        }
    }
}
struct Failed {
    original: Option<Failure>,
    shutdown: Option<server::Shutdown>,
    fallback_worker: Option<worker::Stopped>,
    fallback_error: Option<Failure>,
    resolver_drain: Option<Failure>,
    resolver_close: Option<Failure>,
    output: Option<io::Error>,
    logging: Option<io::Error>,
    observations: Observations,
}
impl fmt::Debug for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NAMESTORE actual failures")
            .field("original", &self.original)
            .field("shutdown", &self.shutdown)
            .field("fallback_worker", &self.fallback_worker)
            .field("fallback_error", &self.fallback_error)
            .field("resolver_drain", &self.resolver_drain)
            .field("resolver_close", &self.resolver_close)
            .field("output", &self.output)
            .field("logging", &self.logging)
            .field("observations", &self.observations)
            .finish()
    }
}
impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NAMESTORE original lifecycle: {self:?}")
    }
}
impl std::error::Error for Failed {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| {
                self.shutdown
                    .as_ref()
                    .and_then(|report| report.failure.as_ref())
                    .map(|error| error as _)
            })
            .or_else(|| {
                self.shutdown
                    .as_ref()
                    .and_then(|report| report.worker.as_ref())
                    .and_then(|worker| worker.failure.as_ref())
                    .map(|error| error.as_ref() as _)
            })
            .or_else(|| {
                self.fallback_worker
                    .as_ref()
                    .and_then(|worker| worker.failure.as_ref())
                    .map(|error| error.as_ref() as _)
            })
            .or(self.fallback_error.as_deref())
            .or(self.resolver_drain.as_deref())
            .or(self.resolver_close.as_deref())
            .or(self.output.as_ref().map(|e| e as _))
            .or(self.logging.as_ref().map(|e| e as _))
    }
}
/// Poll one original mandatory cleanup future until its actual result. In-flight
/// OS storage cannot be force-cancelled by socket deadlines or a failed logger.
async fn settle<F: Future>(
    original: F,
    resolver: &mut Resolver,
    reports: &Reporter,
    drain_error: &mut Option<Failure>,
) -> F::Output {
    let mut original = std::pin::pin!(original);
    poll_fn(|cx| {
        reports.register(cx);
        if reports.failed() {
            resolver.close();
        }
        // Original disk/server debt is always driven, even when another class
        // stays ready or a permanent diagnostic failure has requested stop.
        let completed = original.as_mut().poll(cx);
        if reports.failed() {
            resolver.close();
        }
        if !reports.failed() {
            match resolver.poll(cx, reports, None) {
                Poll::Ready(Err(error)) => {
                    if drain_error.is_none() {
                        *drain_error = Some(Box::new(error));
                    }
                    resolver.close();
                }
                Poll::Ready(Ok(_)) => cx.waker().wake_by_ref(),
                Poll::Pending => {}
            }
        }
        if reports.failed() {
            resolver.close();
        }
        completed
    })
    .await
}
struct Wait<'a> {
    signals: &'a mut Signals,
    reports: &'a Reporter,
    alarm: &'a mut Option<Pin<Box<Sleep>>>,
    until: Option<Instant>,
    resolver_first: bool,
}
enum Turn {
    Signal,
    Resolver,
    Server(Progress),
}
async fn turn(
    owners: &mut Owners<'_>,
    resolver: &mut Resolver,
    listeners: &[Listener<'_>],
    observations: &mut Observations,
    wait: Wait<'_>,
) -> Result<Turn, Failure> {
    let Wait {
        signals,
        reports,
        alarm,
        until,
        resolver_first,
    } = wait;
    poll_fn(|cx| {
        // The first soft-stop native alarm is fixed and precedes canonical IO.
        if let Some(alarm) = alarm.as_mut()
            && (alarm.as_mut().poll(cx).is_ready()
                || until.is_some_and(|hard| Instant::now() >= hard))
        {
            return Poll::Ready(Ok(Turn::Server(Progress::WaitDeadline)));
        }
        reports.register(cx);
        if reports.failed() {
            resolver.close();
            return Poll::Ready(Ok(Turn::Signal));
        } else if let Poll::Ready(signal) = signals.poll(cx) {
            return Poll::Ready(
                signal
                    .map(|()| Turn::Signal)
                    .map_err(|e| Box::new(e) as Failure),
            );
        }
        for offset in 0..2 {
            // A preceding canonical/Resolver callback cannot hide an already
            // elapsed original native target from the next class in this turn.
            if until.is_some_and(|hard| Instant::now() >= hard) {
                return Poll::Ready(Ok(Turn::Server(Progress::WaitDeadline)));
            }
            if reports.failed() {
                resolver.close();
                return Poll::Ready(Ok(Turn::Signal));
            }
            if (offset == 0) == resolver_first {
                if !reports.failed()
                    && let Poll::Ready(result) = resolver.poll(cx, reports, until)
                {
                    return Poll::Ready(
                        result
                            .map(|_| Turn::Resolver)
                            .map_err(|e| Box::new(e) as Failure),
                    );
                }
            } else if let Poll::Ready(result) =
                owners.server.poll(cx, listeners, until, &mut |event| {
                    observations.observe(event, reports)
                })
            {
                return Poll::Ready(
                    result
                        .map(Turn::Server)
                        .map_err(|error| Box::new(error) as Failure),
                );
            }
        }
        Poll::Pending
    })
    .await
}
pub(super) struct Inputs<'a> {
    pub config: &'a Configuration,
    pub settings: Settings,
    pub bound: &'a BoundListeners,
    pub parent: Option<ParentControl>,
    pub clock: SharedClock,
    pub reports: Reporter,
    pub child: &'a mut ChildReady,
    pub cleanup: Cleanup,
}

#[expect(
    clippy::too_many_lines,
    reason = "One lexical scope retains the actual store worker, its borrowed Server, original cleanup futures and real join report on every construction/runtime error"
)]
pub(super) async fn run(input: Inputs<'_>) -> Result<(), Failure> {
    let Inputs {
        config,
        settings,
        bound,
        parent,
        clock: shared_clock,
        reports,
        child,
        cleanup,
    } = input;
    let mut signals = Signals::new(parent)?;
    if reports.failed() {
        return Ok(());
    }
    let stopped_before_start = poll_fn(|cx| {
        reports.register(cx);
        Poll::Ready(match signals.poll(cx) {
            Poll::Ready(result) => result.map(|()| true),
            Poll::Pending => Ok(false),
        })
    })
    .await?;
    if stopped_before_start {
        return Ok(());
    }
    let clock: Arc<dyn RuntimeClock> = Arc::new(shared_clock.clone());
    let live = LiveConfiguration::new(config.duplicate()?);
    let (_context, original_resolver) = gnunet_resolver_broker::broker::<8, 256>(
        live,
        settings.resolver,
        gnunet_resolver_broker::native_profile()?,
        clock.clone(),
    )?;
    let mut resolver = Resolver::new(original_resolver, cleanup.clone());
    // Main already finished every original listener under the target identity.
    // No C path, private fixture or other namespace is adopted here.
    gnunet_service_runtime::private_parents(&settings.directory)?;
    let (mut store, loaded) = Store::open(
        gnunet_snapshot_host::Namespace::Namestore,
        &settings.directory,
        settings.backend,
    )?;
    let recovered = loaded.recovered_temporaries();
    let (core, generation) = Server::recover(
        &mut store,
        loaded,
        settings.core,
        gnunet_namestore_host::critical_type,
    )?;
    let rows = core.snapshot()?.rows().len();
    let mut worker = Worker::start(store)?;
    let mut observations = Observations::default();
    let mut shutdown: Option<server::Shutdown> = None;
    let mut resolver_drain = None;
    // The outer future's end releases the original Server borrow of Worker.
    // This includes Server::new failure, before any Server finally can exist.
    let outcome: Result<(), Failure> = async {
        let server = Server::new(
            core,
            &mut worker,
            generation,
            settings.native,
            server::Ports {
                options: settings.options.clone(),
                unix: settings.unix,
                clock,
            },
        )?;
        let mut owners = Owners {
            server,
            reports: reports.clone(),
            done: false,
        };
        let result: Result<(), Failure> = async {
            let stopping = poll_fn(|cx| {
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
            if stopping {
                return Ok(());
            }
            {
                let mut out = io::stdout().lock();
                writeln!(out, "READY namestore wire=0.29.1 store=rust-marked-snapshot-v1 generation={generation} rows={rows} recovered-pending={recovered} disk-workers=1")?;
                out.flush()?;
            }
            child.ready()?;
            let listeners = bound.listeners();
            let mut until = None;
            let mut alarm: Option<Pin<Box<Sleep>>> = None;
            let mut resolver_first = false;
            loop {
                let next = turn(
                    &mut owners,
                    &mut resolver,
                    &listeners,
                    &mut observations,
                    Wait {
                        signals: &mut signals,
                        reports: &reports,
                        alarm: &mut alarm,
                        until,
                        resolver_first,
                    },
                )
                .await;
                resolver_first = !resolver_first;
                match next {
                    Ok(Turn::Signal)
                        if !reports.failed()
                            && until.is_none()
                            && settings.options.shutdown == ShutdownMode::Soft =>
                    {
                        owners.server.request_shutdown(ShutdownMode::Soft);
                        let hard = Instant::now()
                            .checked_add(settings.grace)
                            .ok_or("NAMESTORE shutdown target overflow")?;
                        until = Some(hard);
                        alarm = Some(Box::pin(tokio::time::sleep_until(hard)));
                    }
                    Ok(Turn::Signal | Turn::Server(Progress::Stopped | Progress::WaitDeadline)) => {
                        break;
                    }
                    Ok(Turn::Resolver | Turn::Server(Progress::Activity)) => {}
                    Err(error) => return Err(error),
                }
                tokio::task::yield_now().await;
            }
            Ok(())
        }
        .await;
        // This original future first closes sources and then drains/joins the
        // same worker. It is never recreated after an event or a clock failure.
        let stopped = {
            let mut observe = |event| observations.observe(event, &reports);
            settle(
                owners.server.shutdown(&mut observe),
                &mut resolver,
                &reports,
                &mut resolver_drain,
            )
            .await
        };
        owners.done = true;
        drop(owners);
        shutdown = Some(stopped);
        result
    }
    .await;
    let mut fallback_worker = None;
    let mut fallback_error = None;
    if shutdown
        .as_ref()
        .is_none_or(|report| report.worker.is_none())
    {
        // Constructor failure (or an absent actual Server join receipt) cannot
        // abandon a started worker. Always wait on this exact original owner.
        let stopping = worker.shutdown(|completion| {
            let (job, result) = completion.into_parts();
            reports.debug(
                "namestore.worker.completion",
                format_args!(
                    "original NAMESTORE worker job={job:?} commit-result-present={}",
                    result.is_ok()
                ),
            );
            if let Err(cause) = result {
                observations.storage.get_or_insert(cause);
            }
        });
        match settle(stopping, &mut resolver, &reports, &mut resolver_drain).await {
            Ok(report) => fallback_worker = Some(report),
            Err(error) => fallback_error = Some(Box::new(error) as Failure),
        }
    }
    resolver.close();
    let resolver_close = cleanup.take_error();
    let original = outcome.err();
    let worker_joined = shutdown
        .as_ref()
        .is_some_and(|report| report.worker.is_some())
        || fallback_worker.is_some();
    let output = {
        let mut out = io::stdout().lock();
        writeln!(out,"STOPPED namestore actual={shutdown:?} fallback-worker={fallback_worker:?} worker-joined={worker_joined} resolver={resolver_close:?}; remote-processing=not-claimed").and_then(|()|out.flush()).err()
    };
    reports.debug("namestore.stopped",format_args!("actual NAMESTORE shutdown={shutdown:?}; fallback-worker={fallback_worker:?}; source-diagnostics={observations:?}; no-timer-quiescence-proof=true"));
    let logging = reports.take_error();
    let storage_failed = shutdown.as_ref().is_some_and(|report| {
        report.failure.is_some()
            || report
                .worker
                .as_ref()
                .is_some_and(|worker| worker.failure.is_some())
    }) || fallback_worker
        .as_ref()
        .is_some_and(|worker| worker.failure.is_some());
    if original.is_some()
        || storage_failed
        || fallback_error.is_some()
        || resolver_drain.is_some()
        || resolver_close.is_some()
        || output.is_some()
        || logging.is_some()
    {
        return Err(Box::new(Failed {
            original,
            shutdown,
            fallback_worker,
            fallback_error,
            resolver_drain,
            resolver_close,
            output,
            logging,
            observations,
        }));
    }
    Ok(())
}
