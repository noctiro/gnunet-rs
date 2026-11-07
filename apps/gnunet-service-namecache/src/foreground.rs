//! Actual NAMECACHE SERVICE and the shared original-MQ statistics producer.
use crate::{Failure, control::Signals, lifecycle::Cleanup, settings::Settings};
use gnunet_config::Configuration;
use gnunet_ipc_unix::producer::{self, Metric, Producer, Snapshot};
use gnunet_namecache::{Cache, Stats};
use gnunet_namecache_host::server::{self, Event, Progress, Server};
use gnunet_program_host::{reporting::Reporter, shared_clock::SharedClock};
use gnunet_resolver_broker::{Driver as ResolverDriver, LiveConfiguration};
use gnunet_service_runtime::{
    BoundListeners,
    clock::RuntimeClock,
    service::{Listener, ShutdownMode},
};
use gnunet_service_startup::{ParentControl, daemon::ChildReady};
use std::{
    future::{Future, poll_fn},
    io::{self, Write},
    sync::Arc,
    task::Poll,
};
use tokio::time::Instant;
static METRICS: [Metric; 4] = [
    Metric::counter(b"blocks looked up", false),
    Metric::counter(b"blocks found in cache", false),
    Metric::counter(b"blocks cached", false),
    Metric::counter(b"blocks removed", false),
];
fn snapshot(server: &Server) -> Snapshot<4> {
    let actual = server.metrics();
    Snapshot::new(*actual.values(), actual.overflowed())
}
fn observe(reports: &Reporter, event: Event) {
    match event {
        Event::Socket(gnunet_service_runtime::accepted::SocketEvent::Failed(error))
            if error.is_emfile() => {}
        Event::Socket(event) => reports.warning(
            "namecache.socket",
            format_args!("namecache socket: {event:?}"),
        ),
        Event::AdmissionIo { address, error } => reports.warning(
            "namecache.admission.io",
            format_args!("namecache original admission {address:?}: {error}"),
        ),
        Event::AdmissionFault { address, reason } => reports.warning(
            "namecache.admission.fault",
            format_args!("namecache original admission {address:?}: {reason}"),
        ),
        Event::Closed { client, cause } => reports.debug(
            "namecache.source.closed",
            format_args!("namecache source={} closed: {cause:?}", client.value()),
        ),
        _ => {}
    }
}
#[derive(Debug, Default)]
struct Failures {
    original: Option<Failure>,
    resolver: Option<Failure>,
    resolver_drain: Option<Failure>,
    statistics: Option<producer::Failure>,
    statistics_cleanup: Option<producer::Failure>,
    output: Option<io::Error>,
    publisher: Option<producer::Report<4>>,
    metrics: Option<server::Metrics>,
}
impl Failures {
    fn finish(self) -> Result<(), Failure> {
        if self.original.is_none()
            && self.resolver.is_none()
            && self.resolver_drain.is_none()
            && self.statistics.is_none()
            && self.statistics_cleanup.is_none()
            && self.output.is_none()
        {
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
            "NAMECACHE original={:?}; Resolver drain={:?}; Resolver cleanup={:?}; statistics={:?}; statistics cleanup={:?}; output={:?}; publisher={:?}; handler metrics={:?}",
            self.original,
            self.resolver_drain,
            self.resolver,
            self.statistics,
            self.statistics_cleanup,
            self.output,
            self.publisher,
            self.metrics
        )
    }
}
impl std::error::Error for Failures {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .as_deref()
            .or(self.resolver_drain.as_deref())
            .or(self.resolver.as_deref())
            .or(self
                .statistics
                .as_ref()
                .map(|e| e as &dyn std::error::Error))
            .or(self
                .statistics_cleanup
                .as_ref()
                .map(|e| e as &dyn std::error::Error))
            .or(self.output.as_ref().map(|e| e as &dyn std::error::Error))
    }
}
fn statistics_error(errors: &mut Failures, error: producer::Failure, reports: &Reporter) {
    if errors.statistics.is_none() {
        reports.warning(
            "namecache.statistics.failed",
            format_args!("NAMECACHE statistics fenced: {error}"),
        );
        errors.statistics = Some(error);
    }
}
struct Owners<'id> {
    server: Server,
    resolver: ResolverDriver<8, 256>,
    statistics: Option<Producer<'id, 4>>,
    reports: Reporter,
    cleanup: Cleanup,
    done: bool,
}
impl Drop for Owners<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.server
                .close_all(&mut |event| observe(&self.reports, event));
            if let Some(statistics) = &mut self.statistics
                && let Err(error) = statistics.abort()
            {
                self.cleanup.retain_statistics(error);
            }
            if let Err(error) = self.resolver.disconnect() {
                self.reports.warning(
                    "namecache.resolver.drop",
                    format_args!("namecache original Resolver cleanup: {error}"),
                );
                self.cleanup.retain(Box::new(error));
            }
            self.done = true;
        }
    }
}
pub(super) struct Inputs<'a> {
    pub config: &'a Configuration,
    pub settings: &'a Settings,
    pub bound: &'a BoundListeners,
    pub parent: Option<ParentControl>,
    pub clock: SharedClock,
    pub reports: Reporter,
    pub child: &'a mut ChildReady,
    pub cleanup: Cleanup,
}
enum Turn {
    Signal,
    Resolver,
    Server(Progress),
    Statistics,
    Logging,
}
async fn turn(
    owners: &mut Owners<'_>,
    signals: &mut Signals,
    listeners: &[Listener<'_>],
    until: Option<Instant>,
    cursor: &mut usize,
    errors: &mut Failures,
) -> Result<Turn, Failure> {
    let reports = owners.reports.clone();
    let (server, resolver, statistics) = (
        &mut owners.server,
        &mut owners.resolver,
        &mut owners.statistics,
    );
    let mut resolving = std::pin::pin!(resolver.drive_waiting(until, |event| reports.debug(
        "namecache.resolver.event",
        format_args!("namecache Resolver={event:?}")
    )));
    poll_fn(|cx| {
        reports.register(cx);
        if reports.failed() {
            return Poll::Ready(Ok(Turn::Logging));
        }
        if let Poll::Ready(signal) = signals.poll(cx) {
            return Poll::Ready(signal.map(|()| Turn::Signal).map_err(Into::into));
        }
        // The producer's immutable native hard is checked/registered before
        // any shared canonical-clock or Resolver wait can remain Pending.
        if let Some(statistics) = statistics
            && !statistics.is_closed()
            && let Poll::Ready(Err(error)) = statistics.poll_native_guard(cx)
        {
            statistics_error(errors, error, &reports);
        }
        for offset in 0..3 {
            // A failed guard diagnostic may have failed logging in this turn.
            if reports.failed() {
                return Poll::Ready(Ok(Turn::Logging));
            }
            let class = (*cursor + offset) % 3;
            let actual = match class {
                0 => resolving
                    .as_mut()
                    .poll(cx)
                    .map(|r| r.map(|_| Turn::Resolver).map_err(Into::into)),
                1 => server
                    .poll(cx, listeners, until, &mut |event| observe(&reports, event))
                    .map(|r| r.map(Turn::Server).map_err(Into::into)),
                _ => {
                    if let Some(statistics) = statistics {
                        if errors.statistics.is_none()
                            && !statistics.is_closed()
                            && let Err(error) = statistics.refresh(snapshot(server))
                        {
                            statistics_error(errors, error, &reports);
                        }
                        if reports.failed() {
                            return Poll::Ready(Ok(Turn::Logging));
                        }
                        if !statistics.is_closed() {
                            match statistics.poll(cx, until) {
                                Poll::Ready(Ok(_)) => Poll::Ready(Ok(Turn::Statistics)),
                                Poll::Ready(Err(error)) => {
                                    statistics_error(errors, error, &reports);
                                    Poll::Ready(Ok(Turn::Statistics))
                                }
                                Poll::Pending => Poll::Pending,
                            }
                        } else {
                            Poll::Pending
                        }
                    } else {
                        Poll::Pending
                    }
                }
            };
            if actual.is_ready() {
                *cursor = (class + 1) % 3;
                return actual;
            }
        }
        Poll::Pending
    })
    .await
}
pub(super) async fn run(input: Inputs<'_>) -> Result<(), Failure> {
    let Inputs {
        config,
        settings,
        bound,
        parent,
        clock,
        reports,
        child,
        cleanup,
    } = input;
    let runtime_clock: Arc<dyn RuntimeClock> = Arc::new(clock);
    let live = LiveConfiguration::new(config.duplicate()?);
    let (context, mut resolver) = gnunet_resolver_broker::broker::<8, 256>(
        live.clone(),
        settings.resolver,
        gnunet_resolver_broker::native_profile()?,
        runtime_clock.clone(),
    )?;
    // Retain and configure the same original Resolver context explicitly. The
    // standard SERVICE has no second PROGRAM scheduler or listener set.
    let initialized = (|| -> Result<_, Failure> {
        context.connect(config.duplicate()?)?;
        let signals = Signals::new(parent)?;
        let cache = Cache::new(settings.core)?;
        let server = Server::new(
            cache,
            settings.native,
            server::Ports {
                options: settings.options.clone(),
                unix: settings.unix,
                clock: runtime_clock.clone(),
            },
        )?;
        Ok((signals, server))
    })();
    let (mut signals, server) = match initialized {
        Ok(value) => value,
        Err(original) => {
            return Failures {
                original: Some(original),
                resolver: resolver.disconnect().err().map(|e| Box::new(e) as Failure),
                ..Default::default()
            }
            .finish();
        }
    };
    let mut statistics_instance = gnunet_ipc_unix::handle::Instance::new();
    let mut errors = Failures::default();
    let statistics = match Producer::new(
        &mut statistics_instance,
        live,
        context.resolution_context(),
        runtime_clock,
        producer::Configuration {
            subsystem: b"namecache",
            metrics: &METRICS,
            initial: snapshot(&server),
            limits: settings.statistics,
        },
    ) {
        Ok(owner) => Some(owner),
        Err(error) => {
            statistics_error(&mut errors, error, &reports);
            None
        }
    };
    let mut owners = Owners {
        server,
        resolver,
        statistics,
        reports: reports.clone(),
        cleanup,
        done: false,
    };
    let listeners = bound.listeners();
    let outcome: Result<(), Failure> = async {
        if reports.failed() {
            return Ok(());
        }
        let Stats { entries, block_bytes, metadata_bytes } = owners.server.cache_stats();
        {
            let mut out = io::stdout().lock();
            writeln!(out,
                "READY namecache wire=0.29.1 backend=volatile-memory restart-persistence=no entries={entries} block-bytes={block_bytes} metadata-bytes={metadata_bytes} workers=0",
            )?;
            out.flush()?;
        }
        child.ready()?;
        let mut stop_at = None;
        let mut cursor = 0;
        let mut turns = 0u8;
        loop {
            turns = turns.wrapping_add(1);
            if turns.is_multiple_of(64) {
                tokio::task::yield_now().await;
            }
            let next = turn(
                &mut owners, &mut signals, &listeners, stop_at, &mut cursor, &mut errors,
            ).await;
            match next {
                Ok(Turn::Logging) => break Ok(()),
                Ok(Turn::Signal)
                    if stop_at.is_none() && settings.options.shutdown == ShutdownMode::Soft =>
                {
                    owners.server.request_shutdown(ShutdownMode::Soft);
                    match Instant::now().checked_add(settings.grace) {
                        Some(deadline) => stop_at = Some(deadline),
                        None => break Err("NAMECACHE original shutdown deadline overflow".into()),
                    }
                }
                Ok(Turn::Signal | Turn::Server(Progress::Stopped | Progress::WaitDeadline)) => break Ok(()),
                Ok(Turn::Resolver | Turn::Statistics | Turn::Server(Progress::Activity)) => {},
                Err(error) => break Err(error),
            }
        }
    }.await;
    // Physical app MQ close precedes diagnostic cleanup and listener release;
    // it never needs a new clock sample or a healthy logging destination.
    let stopped = owners.server.shutdown(|event| observe(&reports, event));
    errors.original = outcome.err();
    errors.metrics = Some(owners.server.metrics());
    if errors.original.is_some() || reports.failed() {
        if let Some(statistics) = &mut owners.statistics
            && let Err(error) = statistics.abort()
        {
            errors.statistics_cleanup = Some(error);
        }
    } else if let Some(statistics) = &mut owners.statistics
        && let Err(error) =
            statistics.begin_close(snapshot(&owners.server), settings.statistics_grace)
    {
        statistics_error(&mut errors, error, &reports);
    }
    // Only the same actual producer/Resolver survive this finite final intent.
    // Native guard is independent of canonical clock and cannot renew on retry.
    while owners.statistics.as_ref().is_some_and(|s| !s.is_closed()) {
        poll_fn(|cx| {
            reports.register(cx);
            if reports.failed() {
                if let Some(statistics) = &mut owners.statistics
                    && let Err(error) = statistics.abort()
                {
                    errors.statistics_cleanup = Some(error);
                }
                return Poll::Ready(());
            }
            let mut changed = false;
            if let Some(statistics) = &mut owners.statistics {
                if let Poll::Ready(Err(error)) = statistics.poll_native_guard(cx) {
                    statistics_error(&mut errors, error, &reports);
                    changed = true;
                }
                if reports.failed() {
                    return Poll::Ready(());
                }
                if !statistics.is_closed() {
                    match statistics.poll(cx, None) {
                        Poll::Ready(Ok(_)) => changed = true,
                        Poll::Ready(Err(error)) => {
                            statistics_error(&mut errors, error, &reports);
                            changed = true;
                        }
                        Poll::Pending => {}
                    }
                }
            }
            if reports.failed() {
                return Poll::Ready(());
            }
            let resolved = {
                let mut resolving =
                    std::pin::pin!(owners.resolver.drive_waiting(None, |event| reports.debug(
                        "namecache.resolver.drain",
                        format_args!("namecache Resolver drain={event:?}"),
                    )));
                resolving.as_mut().poll(cx)
            };
            match resolved {
                Poll::Ready(Ok(_)) => changed = true,
                Poll::Ready(Err(error)) => {
                    if errors.resolver_drain.is_none() {
                        errors.resolver_drain = Some(Box::new(error));
                    }
                    if let Some(statistics) = &mut owners.statistics
                        && let Err(error) = statistics.abort()
                    {
                        errors.statistics_cleanup = Some(error);
                    }
                    changed = true;
                }
                Poll::Pending => {}
            }
            if changed || owners.statistics.as_ref().is_none_or(|s| s.is_closed()) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        tokio::task::yield_now().await;
    }
    errors.publisher = owners.statistics.as_ref().map(|s| s.report());
    errors.resolver = owners
        .resolver
        .disconnect()
        .err()
        .map(|e| Box::new(e) as Failure);
    owners.done = true;
    drop(owners);
    drop(listeners);
    drop(context);
    errors.output = {
        let mut out = io::stdout().lock();
        writeln!(out,"STOPPED namecache backend=volatile-memory local={:?} cache={:?} handler-metrics={:?} publisher={:?} workers=0 restart-persistence=no",stopped.report,stopped.cache,errors.metrics,errors.publisher).and_then(|()|out.flush()).err()
    };
    errors.finish()
}
