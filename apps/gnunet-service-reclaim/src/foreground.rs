//! Actual caller-polled SERVICE, original providers and diagnostic publisher.
use crate::{Failure, control::Signals, settings::Settings};
use gnunet_config::Configuration;
use gnunet_program_host::{policy::Level, reporting::Reporter};
use gnunet_reclaim_host::{
    EndpointSource, SystemProviders, gns, namestore,
    server::{self, Event, Progress, Server},
    statistics,
};
use gnunet_resolver_broker::{Driver as ResolverDriver, LiveConfiguration};
use gnunet_service_runtime::{
    BoundListeners,
    clock::RuntimeClock,
    service::{Listener, ShutdownMode},
};
use gnunet_service_startup::{ParentControl, daemon::ChildReady};
use std::{
    fmt,
    future::{Future, poll_fn},
    io::{self, Write},
    sync::Arc,
    task::Poll,
};
use tokio::time::Instant;
struct Notes {
    reporter: Reporter,
    cleanup: Option<Failure>,
    additional: usize,
}
impl Notes {
    fn observe(&mut self, event: Event) {
        if matches!(&event,Event::Socket(gnunet_service_runtime::accepted::SocketEvent::Failed(e)) if e.is_emfile())
        {
            return;
        }
        let warning = matches!(
            &event,
            Event::Socket(_)
                | Event::Unavailable { .. }
                | Event::BackendLost { .. }
                | Event::SystemFailed { .. }
                | Event::ProviderFailed { .. }
                | Event::Cleanup(_)
        );
        if warning {
            self.reporter
                .warning("reclaim.native.failed", format_args!("reclaim {event:?}"));
        } else {
            self.reporter
                .debug("reclaim.native.activity", format_args!("reclaim {event:?}"));
        }
        if let Event::Cleanup(error) = event {
            if self.cleanup.is_none() {
                self.cleanup = Some(Box::new(error));
            } else {
                self.additional = self.additional.saturating_add(1);
            }
        }
    }
}
#[derive(Debug, Default)]
struct Failures {
    original: Option<Failure>,
    statistics: Option<Failure>,
    statistics_cleanup: Option<Failure>,
    resolver: Option<Failure>,
    resolver_cleanup: Option<Failure>,
    cleanup: Option<Failure>,
    additional_cleanup: usize,
    output: Option<io::Error>,
    server: Option<server::Report>,
    metrics: Option<server::Metrics>,
    publisher: Option<statistics::Report>,
}
impl fmt::Display for Failures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RECLAIM original={:?}; statistics={:?}; stats cleanup={:?}; resolver={:?}; resolver cleanup={:?}; core cleanup={:?} additional={}; output={:?}; actual server={:?}; actual callback metrics={:?}; actual publisher={:?}",
            self.original,
            self.statistics,
            self.statistics_cleanup,
            self.resolver,
            self.resolver_cleanup,
            self.cleanup,
            self.additional_cleanup,
            self.output,
            self.server,
            self.metrics,
            self.publisher
        )
    }
}
impl std::error::Error for Failures {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .as_deref()
            .or(self.cleanup.as_deref())
            .or(self.statistics.as_deref())
            .or(self.statistics_cleanup.as_deref())
            .or(self.resolver.as_deref())
            .or(self.resolver_cleanup.as_deref())
            .or_else(|| {
                self.output
                    .as_ref()
                    .map(|e| e as &(dyn std::error::Error + 'static))
            })
    }
}
impl Failures {
    fn failed(&self) -> bool {
        self.original.is_some()
            || self.statistics.is_some()
            || self.statistics_cleanup.is_some()
            || self.resolver.is_some()
            || self.resolver_cleanup.is_some()
            || self.cleanup.is_some()
            || self.output.is_some()
    }
}
struct Owners<'n, 'g, 's> {
    server: Server<'n, 'g>,
    resolver: ResolverDriver<8, 256>,
    statistics: Option<statistics::Owner<'s>>,
    notes: Notes,
    done: bool,
}
impl Drop for Owners<'_, '_, '_> {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let report = self.server.close_all(&mut |e| self.notes.observe(e));
        let stats = self.statistics.as_mut().and_then(|s| s.abort().err());
        let resolver = self.resolver.disconnect();
        self.notes.reporter.warning("reclaim.cancelled",format_args!("RECLAIM caller future dropped: actual local retirement {report:?}; statistics-error={stats:?}; resolver={resolver:?}; external processing unclaimed"));
    }
}
fn statistics_error(errors: &mut Failures, error: statistics::Failure, reporter: &Reporter) {
    if errors.statistics.is_none() {
        reporter.warning(
            "reclaim.statistics.failed",
            format_args!("RECLAIM statistics fenced: {error}"),
        );
        errors.statistics = Some(Box::new(error));
    }
}
enum Turn {
    Signal,
    Activity,
    Server(Progress),
}
async fn turn(
    owners: &mut Owners<'_, '_, '_>,
    signals: &mut Signals,
    listeners: &[Listener<'_>],
    until: Option<Instant>,
    cursor: &mut usize,
    errors: &mut Failures,
) -> Result<Turn, Failure> {
    let Owners {
        server,
        resolver,
        statistics,
        notes,
        ..
    } = owners;
    let reporter = notes.reporter.clone();
    let mut resolving = std::pin::pin!(resolver.drive_waiting(until, |event| {
        match event {
            gnunet_resolver_broker::DriverEvent::Lost { .. }
            | gnunet_resolver_broker::DriverEvent::Unavailable
            | gnunet_resolver_broker::DriverEvent::SocketRetry { .. } => reporter.warning(
                "reclaim.resolver.failed",
                format_args!("RECLAIM actual Resolver {event:?}"),
            ),
            _ => reporter.debug(
                "reclaim.resolver.activity",
                format_args!("RECLAIM actual Resolver {event:?}"),
            ),
        }
    }));
    poll_fn(|cx| {
        reporter.register(cx);
        if reporter.failed() {
            return Poll::Ready(Ok(Turn::Signal));
        }
        if let Poll::Ready(result) = signals.poll(cx) {
            return Poll::Ready(result.map(|()| Turn::Signal).map_err(Into::into));
        }
        // Independent original statistics native hard is registered before any
        // canonical source/Resolver wait. Only its own diagnostic owner is fenced.
        if let Some(stats) = statistics
            && !stats.is_closed()
            && let Poll::Ready(Err(error)) = stats.poll_native_guard(cx)
        {
            statistics_error(errors, error, &reporter);
        }
        for offset in 0..3 {
            if reporter.failed() {
                return Poll::Ready(Ok(Turn::Signal));
            }
            let class = (*cursor + offset) % 3;
            let actual = match class {
                0 => resolving
                    .as_mut()
                    .poll(cx)
                    .map(|r| r.map(|_| Turn::Activity).map_err(Into::into)),
                1 => server
                    .poll(cx, listeners, until, &mut |event| notes.observe(event))
                    .map(|r| r.map(Turn::Server).map_err(Into::into)),
                _ => {
                    if let Some(stats) = statistics {
                        if errors.statistics.is_none()
                            && let Err(error) = stats.refresh(server.metrics())
                        {
                            statistics_error(errors, error, &reporter);
                        }
                        if !stats.is_closed() {
                            match stats.poll(cx, until) {
                                Poll::Ready(Ok(_)) => Poll::Ready(Ok(Turn::Activity)),
                                Poll::Ready(Err(error)) => {
                                    statistics_error(errors, error, &reporter);
                                    Poll::Ready(Ok(Turn::Activity))
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
            // A callback may fail selected logging in this same turn. Avoid new
            // provider/business IO after that fact; close happens after borrow ends.
            if reporter.failed() {
                return Poll::Ready(Ok(Turn::Signal));
            }
        }
        Poll::Pending
    })
    .await
}
pub(super) async fn run(
    config: Configuration,
    settings: Settings,
    bound: BoundListeners,
    parent: Option<ParentControl>,
    clock: Arc<dyn RuntimeClock>,
    reporter: Reporter,
    child: &mut ChildReady,
) -> Result<(), Failure> {
    let mut signals = Signals::new(parent)?;
    for failure in bound.failures() {
        reporter.warning(
            "reclaim.listener.alternate",
            format_args!("RECLAIM alternate listener {failure}"),
        );
    }
    let live = LiveConfiguration::new(config);
    let (context, resolver) = gnunet_resolver_broker::broker::<8, 256>(
        live.clone(),
        settings.resolver,
        gnunet_resolver_broker::native_profile()?,
        clock.clone(),
    )?;
    let resolution = context.resolution_context();
    let ns = EndpointSource::live(live.clone(), b"namestore", resolution.clone());
    let gns_source = EndpointSource::live(live.clone(), b"gns", resolution.clone());
    let ns_instance = namestore::Instance::new();
    let mut gns_instance = gns::Instance::new();
    // Original actual OS provider, after target UID/listeners. No entropy or
    // private-key operation is performed by source preparation of this code.
    let providers = SystemProviders::open()?;
    let server = Server::new(
        &ns_instance,
        &mut gns_instance,
        settings.core,
        settings.native,
        server::Ports {
            options: settings.options.clone(),
            unix: settings.unix,
            clock: clock.clone(),
            namestore: ns,
            gns: gns_source,
        },
        providers,
    )?;
    let mut statistics_instance = gnunet_client::statistics_handle::Instance::new();
    let mut errors = Failures::default();
    let statistics = match statistics::Owner::new(
        &mut statistics_instance,
        live,
        resolution,
        clock,
        server.metrics(),
        settings.statistics,
    ) {
        Ok(owner) => Some(owner),
        Err(error) => {
            statistics_error(&mut errors, error, &reporter);
            None
        }
    };
    let mut owners = Owners {
        server,
        resolver,
        statistics,
        notes: Notes {
            reporter: reporter.clone(),
            cleanup: None,
            additional: 0,
        },
        done: false,
    };
    let ready = (|| -> io::Result<()> {
        if reporter.failed() {
            return Err(io::Error::other(
                "RECLAIM selected logger failed before readiness; original error retained",
            ));
        }
        reporter.message(Level::INFO,"reclaim.ready",format_args!("RECLAIM actual listener/Server/OS provider owners prepared; configured NAMESTORE/GNS clients attach asynchronously"));
        if reporter.failed() {
            return Err(io::Error::other(
                "RECLAIM readiness diagnostic failed; original error retained",
            ));
        }
        let mut out = io::stdout().lock();
        writeln!(
            out,
            "READY reclaim wire=0.29.1 ipc=listening namestore=client-not-yet-attached gns=client-not-yet-attached credentials=jwt-unverified keys=ipc-only disk-workers=0"
        )?;
        out.flush()?;
        child.ready()
    })();
    let mut cursor = 0;
    let mut turns = 0u8;
    let mut stop_at = None;
    if let Err(error) = ready {
        errors.original = Some(Box::new(error));
    } else {
        let listeners = bound.listeners();
        loop {
            turns = turns.wrapping_add(1);
            if turns.is_multiple_of(64) {
                tokio::task::yield_now().await;
            }
            match turn(
                &mut owners,
                &mut signals,
                &listeners,
                stop_at,
                &mut cursor,
                &mut errors,
            )
            .await
            {
                Ok(Turn::Signal)
                    if stop_at.is_none() && settings.options.shutdown == ShutdownMode::Soft =>
                {
                    owners.server.request_shutdown(ShutdownMode::Soft);
                    stop_at = Instant::now().checked_add(settings.grace);
                    if stop_at.is_none() {
                        errors.original = Some("RECLAIM original shutdown time overflow".into());
                        break;
                    }
                }
                Ok(Turn::Signal | Turn::Server(Progress::Stopped | Progress::WaitDeadline)) => {
                    break;
                }
                Ok(Turn::Activity | Turn::Server(Progress::Activity)) => {}
                Err(error) => {
                    errors.original = Some(error);
                    break;
                }
            }
        }
    }
    // All sources are the same original owners. No clock sample is needed for
    // actual physical close/cancel; unresolved native exposure remains in Report.
    let report = owners
        .server
        .close_all(&mut |event| owners.notes.observe(event));
    errors.server = Some(report);
    errors.metrics = Some(owners.server.metrics());
    errors.cleanup = owners.notes.cleanup.take();
    errors.additional_cleanup = owners.notes.additional;
    if errors.original.is_some() || reporter.failed() {
        if let Some(stats) = &mut owners.statistics
            && let Err(error) = stats.abort()
        {
            errors.statistics_cleanup = Some(Box::new(error));
        }
    } else if let Some(stats) = &mut owners.statistics
        && let Err(error) = stats.begin_close(owners.server.metrics(), settings.statistics_grace)
    {
        statistics_error(&mut errors, error, &reporter);
    }
    // Real final delta/Destroy work drains while the same shared Resolver stays
    // alive. Finite native hard belongs to this first begin_close, never renewed.
    while owners.statistics.as_ref().is_some_and(|s| !s.is_closed()) {
        poll_fn(|cx| {
            let mut changed = false;
            reporter.register(cx);
            if reporter.failed()
                && let Some(stats) = &mut owners.statistics
                && !stats.is_closed()
            {
                if let Err(error) = stats.abort() {
                    errors.statistics_cleanup = Some(Box::new(error));
                }
                changed = true;
            }
            if let Some(stats) = &mut owners.statistics {
                if let Poll::Ready(Err(error)) = stats.poll_native_guard(cx) {
                    statistics_error(&mut errors, error, &reporter);
                    changed = true;
                }
                if !stats.is_closed() {
                    match stats.poll(cx, None) {
                        Poll::Ready(Ok(_)) => changed = true,
                        Poll::Ready(Err(error)) => {
                            statistics_error(&mut errors, error, &reporter);
                            changed = true;
                        }
                        Poll::Pending => {}
                    }
                }
            }
            let resolving = owners.resolver.drive_waiting(None, |event| {
                reporter.debug(
                    "reclaim.resolver.drain",
                    format_args!("RECLAIM actual Resolver drain {event:?}"),
                )
            });
            let mut resolving = std::pin::pin!(resolving);
            match resolving.as_mut().poll(cx) {
                Poll::Ready(Ok(_)) => changed = true,
                Poll::Ready(Err(error)) => {
                    if errors.resolver.is_none() {
                        errors.resolver = Some(Box::new(error));
                    }
                    if let Some(stats) = &mut owners.statistics
                        && let Err(error) = stats.abort()
                    {
                        errors.statistics_cleanup = Some(Box::new(error));
                    }
                    changed = true;
                }
                Poll::Pending => {}
            }
            if owners.statistics.as_ref().is_none_or(|s| s.is_closed()) || changed {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        tokio::task::yield_now().await;
    }
    errors.publisher = owners.statistics.as_ref().map(|s| s.report());
    let resolver_close = owners.resolver.disconnect();
    if let Err(error) = resolver_close {
        if errors.resolver.is_none() {
            errors.resolver = Some(Box::new(error));
        } else {
            reporter.warning(
                "reclaim.resolver.close.failed",
                format_args!("RECLAIM independent Resolver disconnect: {error}"),
            );
            errors.resolver_cleanup = Some(Box::new(error));
        }
    }
    owners.done = true;
    drop(owners);
    drop(context);
    drop(bound);
    let stopped = (|| -> io::Result<()> {
        let mut out = io::stdout().lock();
        writeln!(
            out,
            "STOPPED reclaim local={report:?} provider-owners=retired external-processing-quiescence=unclaimed callback-metrics={:?} statistics={:?}",
            errors.metrics, errors.publisher
        )?;
        out.flush()
    })();
    errors.output = stopped.err();
    if errors.failed() {
        Err(Box::new(errors))
    } else {
        Ok(())
    }
}
