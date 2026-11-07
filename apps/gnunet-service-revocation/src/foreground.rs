//! Real SERVICE owner: listener completion precedes inventory/worker creation.
use crate::{
    Failure,
    control::{Signals, Stop},
    settings::Settings,
    statistics,
};
use gnunet_client_host::{EndpointSource, LiveConfiguration};
use gnunet_config::Configuration;
use gnunet_program_host::{reporting::Reporter, shared_clock::SharedClock};
use gnunet_resolver_broker::Driver;
use gnunet_revocation_host::server::{self, Event, Progress, Server};
use gnunet_service_runtime::{BoundListeners, clock::RuntimeClock, service::ShutdownMode};
use gnunet_service_startup::{ParentControl, daemon::ChildReady};
use std::{
    future::{Future, poll_fn},
    io::{self, Write},
    sync::Arc,
    task::Poll,
};
use tokio::time::{Instant, Sleep};
#[derive(Debug, Default)]
struct Failures {
    original: Option<Failure>,
    service: Option<Failure>,
    resolver: Option<Failure>,
    resolver_cleanup: Option<Failure>,
    storage: Option<Failure>,
    verification: Option<Failure>,
    network: Option<Failure>,
    statistics: Option<Failure>,
    statistics_cleanup: Option<Failure>,
    report: Option<io::Error>,
}
impl Failures {
    fn finish(self) -> Result<(), Failure> {
        if self.original.is_none()
            && self.service.is_none()
            && self.resolver.is_none()
            && self.resolver_cleanup.is_none()
            && self.storage.is_none()
            && self.verification.is_none()
            && self.network.is_none()
            && self.statistics.is_none()
            && self.statistics_cleanup.is_none()
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
        write!(
            f,
            "REVOCATION original/independent shutdown failures: {self:?}"
        )
    }
}
impl std::error::Error for Failures {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .as_deref()
            .or(self.service.as_deref())
            .or(self.resolver.as_deref())
            .or(self.resolver_cleanup.as_deref())
            .or(self.storage.as_deref())
            .or(self.verification.as_deref())
            .or(self.network.as_deref())
            .or(self.statistics.as_deref())
    }
}
fn observe(reports: &Reporter, event: Event<'_>) {
    match event {
        Event::Socket(gnunet_service_runtime::accepted::SocketEvent::Failed(e)) => reports.warning(
            "revocation.socket.failure",
            format_args!("revocation socket failure: {e:?}"),
        ),
        Event::Socket(event) => reports.debug(
            "revocation.socket.activity",
            format_args!("revocation socket: {event:?}"),
        ),
        Event::Network(server::NetworkEvent::Port(error)) => reports.warning(
            "revocation.network.port",
            format_args!("revocation original network port: {error}"),
        ),
        Event::Network(server::NetworkEvent::Cleanup(error)) => reports.warning(
            "revocation.network.cleanup",
            format_args!("revocation independent network cleanup: {error}"),
        ),
        other => reports.debug(
            "revocation.activity",
            format_args!("revocation actual event: {other:?}"),
        ),
    }
}
struct Owners<'id, 'stats> {
    server: Server<'id>,
    resolver: Driver<64, 256>,
    statistics: Option<statistics::Owner<'stats>>,
    reports: Reporter,
    done: bool,
    resolver_closed: bool,
}
impl Drop for Owners<'_, '_> {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        self.server
            .close_all(&mut |event| observe(&self.reports, event));
        if let Some(stats) = &mut self.statistics
            && let Err(error) = stats.abort()
        {
            self.reports.warning(
                "revocation.cancelled.statistics",
                format_args!("revocation original statistics retirement: {error}"),
            );
        }
        if !self.resolver_closed {
            let result = self.resolver.disconnect();
            self.resolver_closed = true;
            self.reports.warning("revocation.cancelled.resolver",format_args!("revocation cancelled original Resolver close={result:?}; worker joins are not fabricated"));
        }
    }
}
pub(super) struct Inputs<'child> {
    pub config: Configuration,
    pub settings: Settings,
    pub bound: BoundListeners,
    pub parent: Option<ParentControl>,
    pub clock: SharedClock,
    pub reports: Reporter,
    pub child: &'child mut ChildReady,
}
enum Turn {
    Stop(Stop),
    Resolver,
    Server(Progress),
    Statistics,
    Deadline,
}
fn stats_error(slot: &mut Option<Failure>, reports: &Reporter, error: statistics::Failure) {
    reports.warning(
        "revocation.statistics.failure",
        format_args!("revocation statistics original owner failed: {error}"),
    );
    if slot.is_none() {
        *slot = Some(Box::new(error));
    }
}
fn stats_progress(reports: &Reporter, progress: statistics::Progress) {
    match progress {
        statistics::Progress::Written { counter, delta } => reports.debug(
            "revocation.statistics.written",
            format_args!("revocation original statistics coordinate={counter} magnitude={delta} locally whole-written"),
        ),
        statistics::Progress::Activity => reports.debug("revocation.statistics.activity", format_args!("revocation original statistics activity")),
        statistics::Progress::Closed => reports.debug("revocation.statistics.closed", format_args!("revocation original statistics owner physically closed")),
    }
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
    } = input;
    let runtime: Arc<dyn RuntimeClock> = Arc::new(clock);
    let live = LiveConfiguration::new(config);
    let (_context, resolver) = gnunet_resolver_broker::broker::<64, 256>(
        live.clone(),
        settings.resolver,
        gnunet_resolver_broker::native_profile()?,
        runtime.clone(),
    )?;
    let resolution = resolver.context().resolution_context();
    let mut signals = Signals::new(parent, reports.clone())?;
    let mut core = gnunet_core_client_host::Instance::new();
    let setu = gnunet_setu_client_host::Instance::new();
    let mut stats_id = gnunet_ipc_unix::handle::Instance::new();
    let (store, loaded) = gnunet_snapshot_host::backend::Store::open(
        gnunet_snapshot_host::Namespace::Revocation,
        &settings.store,
        gnunet_snapshot_host::backend::Limits {
            body_bytes: settings.limits.snapshot_bytes,
        },
    )?;
    let server = Server::recover(
        store,
        loaded,
        server::Instances {
            core: &mut core,
            setu: &setu,
        },
        server::Sources {
            core: EndpointSource::live(live.clone(), b"core", resolution.clone()),
            setu: EndpointSource::live(live.clone(), b"setu", resolution.clone()),
            core_order: settings.core_order,
        },
        settings.policy,
        settings.limits,
        server::Ports {
            options: settings.options.clone(),
            unix: settings.unix,
            clock: runtime.clone(),
        },
    )?;
    let mut errors = Failures::default();
    let statistics = match statistics::Owner::new(
        &mut stats_id,
        live,
        resolution,
        runtime,
        server.metrics(),
        settings.statistics,
    ) {
        Ok(owner) => Some(owner),
        Err(error) => {
            stats_error(&mut errors.statistics, &reports, error);
            None
        }
    };
    let mut owners = Owners {
        server,
        resolver,
        statistics,
        reports: reports.clone(),
        done: false,
        resolver_closed: false,
    };
    let listeners = bound.listeners();
    let recovered = owners.server.inventory().generation();
    // Local SERVICE readiness is the actual initialized IPC/inventory/workers,
    // not a claim that CORE/SETU attached or any remote revocation was accepted.
    let ready = if reports.failed() {
        Err(io::Error::other(
            "selected logging failed before actual REVOCATION readiness",
        ))
    } else {
        let mut out = io::stdout().lock();
        writeln!(out,"READY revocation wire=0.29.1 inventory-generation={recovered} workers=2 ipc=listening network=core,setu network-ready=actual-events-only").and_then(|()|out.flush()).and_then(|()|child.ready())
    };
    let mut stop_at = None;
    let mut stop_alarm: Option<std::pin::Pin<Box<Sleep>>> = None;
    let mut turn = 0usize;
    let mut resolver_failed = false;
    let outcome = if let Err(error) = ready {
        Err(Box::new(error) as Failure)
    } else {
        loop {
            if errors.statistics.is_none()
                && let Some(stats) = &mut owners.statistics
                && let Err(error) = stats.refresh(owners.server.metrics())
            {
                stats_error(&mut errors.statistics, &reports, error);
            }
            let next = poll_fn(|cx| {
                reports.register(cx);
                if stop_alarm
                    .as_mut()
                    .is_some_and(|alarm| alarm.as_mut().poll(cx).is_ready())
                {
                    return Poll::Ready(Ok(Turn::Deadline));
                }
                if let Some(stats) = &mut owners.statistics
                    && let Poll::Ready(Err(error)) = stats.poll_native_guard(cx)
                {
                    stats_error(&mut errors.statistics, &reports, error);
                }
                if let Poll::Ready(result) = signals.poll(cx) {
                    return Poll::Ready(
                        result
                            .map(Turn::Stop)
                            .map_err(|error| Box::new(error) as Failure),
                    );
                }
                for offset in 0..3 {
                    match (turn + offset) % 3 {
                        0 => {
                            if let Poll::Ready(result) =
                                owners.server.poll(cx, &listeners, stop_at, &mut |event| {
                                    observe(&reports, event)
                                })
                            {
                                return Poll::Ready(
                                    result.map(Turn::Server).map_err(|e| Box::new(e) as Failure),
                                );
                            }
                        }
                        1 => {
                            let mut driving =
                                std::pin::pin!(owners.resolver.drive_waiting(stop_at, |event| {
                                    reports.debug(
                                        "revocation.resolver.activity",
                                        format_args!("revocation Resolver={event:?}"),
                                    )
                                }));
                            if let Poll::Ready(result) = driving.as_mut().poll(cx) {
                                if result.is_err() {
                                    resolver_failed = true;
                                }
                                return Poll::Ready(
                                    result
                                        .map(|_| Turn::Resolver)
                                        .map_err(|e| Box::new(e) as Failure),
                                );
                            }
                        }
                        _ => {
                            if let Some(stats) = &mut owners.statistics
                                && !stats.is_closed()
                            {
                                match stats.poll(cx, stop_at) {
                                    Poll::Ready(Ok(progress)) => {
                                        stats_progress(&reports, progress);
                                        return Poll::Ready(Ok(Turn::Statistics));
                                    }
                                    Poll::Ready(Err(error)) => {
                                        stats_error(&mut errors.statistics, &reports, error);
                                        return Poll::Ready(Ok(Turn::Statistics));
                                    }
                                    Poll::Pending => {}
                                }
                            }
                        }
                    }
                }
                Poll::Pending
            })
            .await;
            turn = turn.wrapping_add(1);
            match next {
                Ok(Turn::Stop(reason))
                    if stop_at.is_none()
                        && (matches!(reason, Stop::Diagnostic)
                            || settings.options.shutdown == ShutdownMode::Soft) =>
                {
                    owners
                        .server
                        .request_shutdown(ShutdownMode::Soft, &mut |event| {
                            observe(&reports, event)
                        });
                    let Some(hard) = Instant::now().checked_add(settings.grace) else {
                        break Err("REVOCATION shutdown deadline overflow".into());
                    };
                    stop_at = Some(hard);
                    stop_alarm = Some(Box::pin(tokio::time::sleep_until(hard)));
                }
                Ok(
                    Turn::Stop(_)
                    | Turn::Deadline
                    | Turn::Server(Progress::Stopped | Progress::WaitDeadline),
                ) => break Ok(()),
                Ok(Turn::Resolver | Turn::Statistics | Turn::Server(Progress::Activity)) => {}
                Err(error) => break Err(error),
            }
        }
    };
    owners
        .server
        .close_all(&mut |event| observe(&reports, event));
    drop(listeners);
    drop(bound);
    if let Some(stats) = &mut owners.statistics {
        let result = if outcome.is_err() || resolver_failed {
            stats.abort()
        } else {
            stats.begin_close(owners.server.metrics(), settings.statistics_grace)
        };
        if let Err(error) = result {
            stats_error(&mut errors.statistics, &reports, error);
        }
    }
    // Worker shutdown is retained and polled to actual join independently of
    // every statistics/Resolver/log error. Native stats deadlines are driven
    // before this future or a canonical Resolver wait on each cleanup turn.
    let shutdown = {
        let mut joining = std::pin::pin!(owners.server.shutdown(|event| observe(&reports, event)));
        let mut finished = None;
        poll_fn(|cx| {
            reports.register(cx);
            if let Some(stats) = &mut owners.statistics
                && let Poll::Ready(Err(error)) = stats.poll_native_guard(cx)
            {
                stats_error(&mut errors.statistics, &reports, error);
            }
            if finished.is_none()
                && let Poll::Ready(result) = joining.as_mut().poll(cx)
            {
                finished = Some(result);
            }
            if let Some(stats) = &mut owners.statistics
                && !stats.is_closed()
            {
                match stats.poll(cx, None) {
                    Poll::Ready(Err(error)) => stats_error(&mut errors.statistics, &reports, error),
                    Poll::Ready(Ok(progress)) => {
                        stats_progress(&reports, progress);
                        cx.waker().wake_by_ref();
                    }
                    Poll::Pending => {}
                }
            }
            let stats_done = owners
                .statistics
                .as_ref()
                .is_none_or(statistics::Owner::is_closed);
            if stats_done && let Some(result) = finished.take() {
                return Poll::Ready(result);
            }
            if !stats_done && !owners.resolver_closed {
                let resolving = {
                    let mut driving =
                        std::pin::pin!(owners.resolver.drive_waiting(None, |event| reports.debug(
                            "revocation.resolver.cleanup",
                            format_args!("revocation cleanup Resolver={event:?}")
                        )));
                    driving.as_mut().poll(cx)
                };
                // Release the per-turn future's exclusive borrow before actual
                // clock-free retirement of this same original Resolver owner.
                if let Poll::Ready(result) = resolving {
                    match result {
                        Ok(_) => cx.waker().wake_by_ref(),
                        Err(error) => {
                            if errors.resolver.is_none() {
                                errors.resolver = Some(Box::new(error));
                            }
                            if let Some(stats) = &mut owners.statistics
                                && let Err(error) = stats.abort()
                            {
                                errors.statistics_cleanup = Some(Box::new(error));
                            }
                            if let Err(error) = owners.resolver.disconnect() {
                                errors.resolver_cleanup = Some(Box::new(error));
                            }
                            owners.resolver_closed = true;
                            // Abort closed the publisher locally; no old IO may
                            // wake another turn to observe the completed join.
                            cx.waker().wake_by_ref();
                        }
                    }
                }
            }
            Poll::Pending
        })
        .await
    };
    let statistics_report = owners.statistics.as_ref().map(statistics::Owner::report);
    if !owners.resolver_closed {
        if let Err(error) = owners.resolver.disconnect() {
            errors.resolver = Some(Box::new(error));
        }
        owners.resolver_closed = true;
    }
    owners.done = true;
    drop(owners);
    let report = {
        let mut out = io::stdout().lock();
        writeln!(out,"STOPPED revocation report={:?} statistics={statistics_report:?} remote-network-completion=not-claimed",shutdown.report).and_then(|()|out.flush())
    };
    errors.original = outcome.err();
    errors.service = shutdown.failure.map(|e| Box::new(e) as Failure);
    errors.storage = match shutdown.storage {
        Ok(stopped) => stopped
            .failure
            .map(|e| Box::new(server::Error::Storage(e)) as Failure),
        Err(error) => Some(Box::new(error) as Failure),
    };
    errors.verification = shutdown.verification.err().map(|e| Box::new(e) as Failure);
    errors.network = shutdown.network.err().map(|e| Box::new(e) as Failure);
    errors.report = report.err();
    errors.finish()
}
