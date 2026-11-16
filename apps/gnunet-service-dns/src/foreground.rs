//! Standard SERVICE owns the original helper, DNSSTUB, MQs and shared Resolver.
use crate::{
    Failure,
    settings::Settings,
    statistics::{self, Publisher},
};
use gnunet_config::Configuration;
use gnunet_dns_service_host::{
    Event, Gateway, GatewayProgress, GatewayReport, RejectedGateway, Retirement, Server, core,
};
use gnunet_program_host::{policy::Level, reporting::Reporter, shared_clock::SharedClock};
use gnunet_resolver_broker::{Driver as ResolverDriver, LiveConfiguration};
use gnunet_service_runtime::{BoundListeners, clock::RuntimeClock, service::Listener};
use gnunet_service_startup::{ControlReceiver, StopSignals as Signals};
use std::{
    future::{Future, poll_fn},
    io::{self, Write},
    sync::Arc,
    task::Poll,
    time::Duration,
};
use tokio::time::Instant;

fn observe(reports: &Reporter, event: Event<'_>) {
    match event {
        Event::Socket(gnunet_service_runtime::accepted::SocketEvent::Failed(error))
            if error.is_emfile() => {}
        Event::Socket(event) => {
            reports.warning("dns.socket", format_args!("dns listener: {event:?}"))
        }
        Event::Accepted(client) => reports.debug(
            "dns.source.accepted",
            format_args!("dns original MQ accepted: {client:?}"),
        ),
        Event::Closed {
            client,
            reason,
            queued,
        } => reports.debug(
            "dns.source.closed",
            format_args!("dns original MQ {client:?} closed: {reason}; queued={queued:?}"),
        ),
        Event::CallbackLost { effect, state } => reports.warning(
            "dns.callback.lost",
            format_args!("dns original callback lost: {effect:?} local-state={state:?}"),
        ),
        Event::PacketOutputLost {
            effect,
            exposure,
            total,
        } => reports.warning(
            "dns.packet.output.lost",
            format_args!("dns original packet output lost: {effect:?} exposure={exposure:?} packet-bytes={total}"),
        ),
        Event::Cleanup(reason) => reports.warning(
            "dns.cleanup",
            format_args!("dns independent cleanup: {reason}"),
        ),
        Event::Input(_) | Event::Queued(_) | Event::Written { .. } => {}
    }
}
#[derive(Debug, Default)]
struct Failures {
    original: Option<Failure>,
    cleanup: Option<Failure>,
    statistics: Option<statistics::Failure>,
    statistics_cleanup: Option<statistics::Failure>,
    resolver_drain: Option<Failure>,
    resolver_close: Option<Failure>,
    resolver_io: Option<io::Error>,
    resolver_connect: Option<gnunet_resolver_broker::BrokerError>,
    retirement: Option<Failure>,
    gateway: Option<GatewayReport>,
    publisher: Option<gnunet_ipc_unix::producer::Report<6>>,
}
fn gateway_failed(report: &GatewayReport) -> bool {
    report.first.is_some()
        || report.cleanup.is_some()
        || report
            .source_retirement
            .as_ref()
            .is_none_or(Retirement::has_failure)
}
impl Failures {
    fn finish(self) -> Result<(), Failure> {
        if self.original.is_none()
            && self.cleanup.is_none()
            && self.statistics.is_none()
            && self.statistics_cleanup.is_none()
            && self.resolver_drain.is_none()
            && self.resolver_close.is_none()
            && self.resolver_io.is_none()
            && self.resolver_connect.is_none()
            && self.retirement.is_none()
            && self
                .gateway
                .as_ref()
                .is_none_or(|report| !gateway_failed(report))
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
            "DNS original={:?}; cleanup={:?}; statistics={:?}; statistics cleanup={:?}; Resolver drain={:?}; Resolver close={:?}; Resolver native IO={:?}; Resolver connection={:?}; retirement={:?}; original gateway report={:?}; publisher={:?}",
            self.original,
            self.cleanup,
            self.statistics,
            self.statistics_cleanup,
            self.resolver_drain,
            self.resolver_close,
            self.resolver_io,
            self.resolver_connect,
            self.retirement,
            self.gateway,
            self.publisher
        )
    }
}
impl std::error::Error for Failures {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .as_deref()
            .or(self.cleanup.as_deref())
            .or(self
                .statistics
                .as_ref()
                .map(|e| e as &dyn std::error::Error))
            .or(self
                .statistics_cleanup
                .as_ref()
                .map(|e| e as &dyn std::error::Error))
            .or(self.resolver_drain.as_deref())
            .or(self.resolver_close.as_deref())
            .or(self
                .resolver_io
                .as_ref()
                .map(|e| e as &dyn std::error::Error))
            .or(self
                .resolver_connect
                .as_ref()
                .map(|e| e as &dyn std::error::Error))
            .or(self.retirement.as_deref())
            .or_else(|| {
                self.gateway
                    .as_ref()
                    .and_then(|report| report.first.as_ref().or(report.cleanup.as_ref()))
                    .map(|e| e as &dyn std::error::Error)
            })
    }
}
pub(super) struct Inputs {
    pub config: Configuration,
    pub settings: Settings,
    pub bound: BoundListeners,
    pub parent: Option<ControlReceiver>,
    pub clock: SharedClock,
    pub reports: Reporter,
}
struct Owners<'id, 'stats> {
    gateway: Option<Gateway<'id>>,
    statistics: Option<Publisher<'stats>>,
    stats_error: Option<statistics::Failure>,
    stats_cleanup: Option<statistics::Failure>,
    resolver: ResolverDriver<8, 256>,
    reports: Reporter,
    done: bool,
}
impl Owners<'_, '_> {
    fn statistics_failed(&mut self, error: statistics::Failure) {
        self.reports.warning(
            "dns.statistics.failure",
            format_args!("dns original statistics publisher: {error}"),
        );
        if self.stats_error.is_none() {
            self.stats_error = Some(error);
        } else if self.stats_cleanup.is_none() {
            self.stats_cleanup = Some(error);
        }
    }
    fn refresh_statistics(&mut self) {
        if self.stats_error.is_some() {
            return;
        }
        let counts = self.gateway.as_ref().map_or([0; 6], Gateway::statistics);
        if let Some(publisher) = self.statistics.as_mut()
            && let Err(error) = publisher.refresh(statistics::snapshot(counts))
        {
            self.statistics_failed(error);
        }
    }
    fn abort_statistics(&mut self) {
        if let Some(publisher) = self.statistics.as_mut()
            && let Err(error) = publisher.abort()
        {
            self.statistics_failed(error);
        }
    }
}
impl Drop for Owners<'_, '_> {
    fn drop(&mut self) {
        if !self.done {
            let reports = self.reports.clone();
            if let Some(gateway) = self.gateway.as_mut() {
                gateway.close(None, &mut |event| observe(&reports, event));
            }
            self.abort_statistics();
            let resolver = self.resolver.disconnect();
            let retirement = self
                .gateway
                .as_ref()
                .and_then(|gateway| gateway.report().source_retirement.as_ref());
            reports.warning("dns.interrupted", format_args!("dns SERVICE interrupted: packet source retirement={retirement:?}; Resolver={resolver:?}"));
        }
    }
}
enum Turn<'id> {
    Stop,
    Resolver,
    Statistics,
    Gateway(GatewayProgress<'id>),
}
async fn turn<'id>(
    owners: &mut Owners<'id, '_>,
    signals: &mut Signals,
    listeners: &[Listener<'_>],
    first: usize,
) -> Result<Turn<'id>, Failure> {
    // A temporary drive future borrows only this original Resolver. It is dropped
    // before caller cleanup/disconnect or any owned event is applied elsewhere.
    let reports = owners.reports.clone();
    let (gateway, resolver, publisher, stats_error, stats_cleanup) = (
        &mut owners.gateway,
        &mut owners.resolver,
        &mut owners.statistics,
        &mut owners.stats_error,
        &mut owners.stats_cleanup,
    );
    let gateway = gateway.as_mut().ok_or("DNS gateway not constructed")?;
    let mut resolving = std::pin::pin!(resolver.drive_waiting(None, |event| reports.debug(
        "dns.resolver.activity",
        format_args!("dns shared Resolver: {event:?}")
    )));
    poll_fn(|cx| {
        reports.register(cx);
        // Only original native deadlines are checked before any canonical-clock
        // wait. A publisher failure fences itself; it does not fail interception.
        if let Some(publisher) = publisher.as_mut()
            && !publisher.is_closed()
            && let Poll::Ready(Err(error)) = publisher.poll_native_guard(cx)
        {
            reports.warning(
                "dns.statistics.failure",
                format_args!("dns original statistics publisher: {error}"),
            );
            if stats_error.is_none() {
                *stats_error = Some(error);
            } else if stats_cleanup.is_none() {
                *stats_cleanup = Some(error);
            }
        }
        if reports.failed() {
            return Poll::Ready(Err("DNS selected diagnostic destination failed".into()));
        }
        if let Poll::Ready(signal) = signals.poll_stop(cx) {
            return Poll::Ready(signal.map(|()| Turn::Stop).map_err(Into::into));
        }
        for n in 0..3 {
            if reports.failed() {
                return Poll::Ready(Err("DNS selected diagnostic destination failed".into()));
            }
            let step = match (first + n) % 3 {
                0 => gateway
                    .poll(cx, listeners, None, &mut |event| observe(&reports, event))
                    .map(|v| v.map(Turn::Gateway).map_err(|e| Box::new(e) as Failure)),
                1 => resolving.as_mut().poll(cx).map(|v| {
                    v.map(|_| Turn::Resolver)
                        .map_err(|e| Box::new(e) as Failure)
                }),
                _ => {
                    if let Some(publisher) = publisher.as_mut()
                        && !publisher.is_closed()
                    {
                        match publisher.poll(cx, None) {
                            Poll::Ready(Err(error)) => {
                                reports.warning(
                                    "dns.statistics.failure",
                                    format_args!("dns original statistics publisher: {error}"),
                                );
                                if stats_error.is_none() {
                                    *stats_error = Some(error);
                                } else if stats_cleanup.is_none() {
                                    *stats_cleanup = Some(error);
                                }
                                Poll::Ready(Ok(Turn::Statistics))
                            }
                            Poll::Ready(Ok(_)) => Poll::Ready(Ok(Turn::Statistics)),
                            Poll::Pending => Poll::Pending,
                        }
                    } else {
                        Poll::Pending
                    }
                }
            };
            // Preserve any actual failure before observing the later diagnostic
            // latch. No following class can admit work after its logger failed.
            if step.is_ready() {
                return step;
            }
        }
        if reports.failed() {
            return Poll::Ready(Err("DNS selected diagnostic destination failed".into()));
        }
        Poll::Pending
    })
    .await
}
#[derive(Debug)]
struct Rejected {
    original: gnunet_dns_service_host::Error,
    mq: Option<gnunet_dns_service_host::Error>,
    source: Option<Retirement>,
    deadline: Option<tokio::time::error::Elapsed>,
    bound: Option<gnunet_types::Error>,
}
impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "dns composition original={}; MQ cleanup={:?}; packet source retirement={:?}; unconfirmed retirement={:?}; bound={:?}",
            self.original, self.mq, self.source, self.deadline, self.bound
        )
    }
}
impl std::error::Error for Rejected {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}
async fn rejected(
    mut rejected: RejectedGateway<'_>,
    grace: Duration,
    reports: &Reporter,
) -> Failure {
    let original = rejected.error;
    let mq = rejected
        .server
        .close_all(&mut |event| observe(reports, event));
    rejected.packets.request_stop();
    let now = Instant::now();
    let target = now.checked_add(grace);
    let until = target.unwrap_or(now);
    let outcome = tokio::time::timeout_at(
        until,
        poll_fn(|cx| {
            reports.register(cx);
            rejected.packets.poll_retirement(cx)
        }),
    )
    .await;
    let (source, deadline) = match outcome {
        Ok(exit) => (Some(exit), None),
        Err(error) => {
            let exit = poll_fn(|cx| {
                Poll::Ready(match rejected.packets.poll_retirement(cx) {
                    Poll::Ready(exit) => Some(exit),
                    Poll::Pending => None,
                })
            })
            .await;
            (exit, Some(error))
        }
    };
    if let Some(mut upstream) = rejected.upstream.take() {
        let _stopped = upstream.stop();
    }
    Box::new(Rejected {
        original,
        mq,
        source,
        deadline,
        bound: target.is_none().then_some(gnunet_types::Error::Overflow),
    })
}
pub(super) async fn run(
    input: Inputs,
    ready: impl Future<Output = Result<(), Failure>>,
) -> Result<(), Failure> {
    let Inputs {
        config,
        settings,
        bound,
        parent,
        clock,
        reports,
    } = input;
    let instance = core::Instance::new();
    let mut stats_instance = gnunet_ipc_unix::handle::Instance::new();
    let live = LiveConfiguration::new(config);
    let runtime_clock: Arc<dyn RuntimeClock> = Arc::new(clock);
    let (_context, resolver) = gnunet_resolver_broker::broker::<8, 256>(
        live.clone(),
        settings.resolver,
        gnunet_resolver_broker::native_profile()?,
        runtime_clock.clone(),
    )?;
    let mut owners = Owners {
        gateway: None,
        statistics: None,
        stats_error: None,
        stats_cleanup: None,
        resolver,
        reports: reports.clone(),
        done: false,
    };
    let grace = settings.grace;
    let listeners = bound.listeners();
    let outcome: Result<(), Failure> = async {
        let mut signals = Signals::new(parent)?;
        match statistics::new(&mut stats_instance, live, owners.resolver.context().resolution_context(), runtime_clock.clone(), settings.statistics) {
            Ok(publisher) => owners.statistics = Some(publisher),
            Err(error) => owners.statistics_failed(error),
        }
        crate::startup_check(&reports)?;
        let engine = core::Engine::new(&instance, settings.core)?;
        let server = Server::new(engine, runtime_clock, settings.native, settings.options, settings.unix)?;
        let packet_source = settings.packets.label();
        let mut upstream = gnunet_dns_service_host::Upstream::start(settings.gateway.resolver_sockets, core::MAX_DNS_BYTES)?;
        upstream.add_dns_sa(std::net::SocketAddr::new(settings.exit, 53))?;
        let packets = crate::packet_source::open(settings.packets, &mut upstream, settings.exit)?;
        let gateway = match Gateway::with_upstream(server, packets, upstream, settings.gateway) { Ok(gateway) => gateway, Err(error) => return Err(rejected(error, grace, &reports).await) };
        owners.gateway = Some(gateway);
        crate::startup_check(&reports)?;
        {
            let mut out = io::stdout().lock();
            writeln!(out, "READY dns clients={} requests={} source={packet_source} interception-setup=unacknowledged", settings.core.clients, settings.core.requests)?;
            out.flush()?;
        }
        // This exact child only reports readiness after every actual original
        // listener, Server, packet source and DNSSTUB owner exists and stdout
        // flushed. The helper protocol has no TUN/firewall setup acknowledgement.
        ready.await?;
        let mut first = 0;
        loop {
            crate::startup_check(&reports)?;
            // Gateway converts a fatal source error into close+Activity so its
            // original error can remain owned in GatewayReport. Immediately
            // enter finite cleanup; do not await an unbounded normal-turn wait
            // while that same helper is already stopping.
            if owners.gateway.as_ref().is_some_and(|gateway| gateway.report().first.is_some()) {
                break Err("DNS original gateway entered fatal retirement; original error is retained in GatewayReport".into());
            }
            owners.refresh_statistics();
            let progress = turn(&mut owners, &mut signals, &listeners, first).await?;
            first = (first + 1) % 3;
            match progress {
                Turn::Stop => break Ok(()), Turn::Resolver | Turn::Statistics => {},
                Turn::Gateway(GatewayProgress::Stopped | GatewayProgress::SourceRetired) => break Err("DNS original helper/source stopped before requested shutdown".into()),
                Turn::Gateway(GatewayProgress::PacketDropped(reason)) => reports.debug("dns.packet.discarded", format_args!("dns actual captured packet discarded: {reason}")),
                Turn::Gateway(GatewayProgress::PacketRefused { request, reason }) => reports.warning("dns.packet.refused", format_args!("dns packet-local refusal {request:?}: {reason}")),
                #[cfg(windows)]
                Turn::Gateway(GatewayProgress::RouteObservationFailed { reason }) => reports.warning("dns.route.observation", format_args!("dns interface observation failed: {reason}")),
                Turn::Gateway(GatewayProgress::ResolverRefused { request, reason }) => reports.warning("dns.resolver.refused", format_args!("dns original resolver admission refused for {request:?}: {reason}")),
                Turn::Gateway(GatewayProgress::ResolverDiscarded { native, reason }) => reports.debug("dns.resolver.discarded", format_args!("dns actual resolver datagram discarded for {native:?}: {reason}")),
                Turn::Gateway(GatewayProgress::ResolverQueued { .. } | GatewayProgress::Activity | GatewayProgress::WaitDeadline) => {},
            }
        }
    }.await;
    // No fallible early return below this point. Every failure retains the same
    // helper and original MQ/Resolver/statistics owners through retirement.
    if let Some(gateway) = owners.gateway.as_mut() {
        gateway.close(None, &mut |event| observe(&reports, event));
    }
    // Failed main work never creates a fresh statistics drain. Retire this
    // same publisher without sampling its logical clock or replacing its MQ.
    let publish_final = outcome.is_ok();
    if !publish_final || reports.failed() {
        owners.abort_statistics();
    } else {
        let counts = owners.gateway.as_ref().map_or([0; 6], Gateway::statistics);
        if let Some(publisher) = owners.statistics.as_mut()
            && let Err(error) = publisher.begin_close(statistics::snapshot(counts), grace)
        {
            owners.statistics_failed(error);
        }
    }
    if reports.failed() {
        owners.abort_statistics();
    }
    let now = Instant::now();
    let target = now.checked_add(grace);
    let until = target.unwrap_or(now);
    let mut cleanup: Option<Failure> = target
        .is_none()
        .then(|| Box::new(gnunet_types::Error::Overflow) as Failure);
    let mut resolver_error: Option<Failure> = None;
    let mut gateway_done = owners.gateway.is_none();
    let drained = tokio::time::timeout_at(
        until,
        poll_fn(|cx| {
            reports.register(cx);
            let mut activity = false;
            // Original publisher hard deadlines precede every provider/helper
            // wait. This guard performs no canonical sample or native IO.
            if let Some(publisher) = owners.statistics.as_mut()
                && !publisher.is_closed()
            {
                match publisher.poll_native_guard(cx) {
                    Poll::Ready(Err(error)) => owners.statistics_failed(error),
                    Poll::Ready(Ok(_)) => activity = true,
                    Poll::Pending => {}
                }
            }
            if reports.failed() {
                owners.abort_statistics();
            }
            // Closing Gateway polls only its original helper's exit/force-stop
            // obligations. A permanently failed Reporter must not suppress that
            // poll or manufacture local Ready progress/busy-looping.
            if !gateway_done && let Some(gateway) = owners.gateway.as_mut() {
                match gateway.poll(cx, &[], Some(until), &mut |event| observe(&reports, event)) {
                    Poll::Ready(Ok(GatewayProgress::Stopped)) => gateway_done = true,
                    Poll::Ready(Ok(GatewayProgress::WaitDeadline)) | Poll::Pending => {}
                    Poll::Ready(Ok(_)) => activity = true,
                    Poll::Ready(Err(error)) => {
                        if cleanup.is_none() {
                            cleanup = Some(Box::new(error));
                        }
                    }
                }
            }
            // A helper/old-source diagnostic can fail during the preceding
            // poll; fence before any following statistics or Resolver class.
            if reports.failed() {
                owners.abort_statistics();
            }
            if publish_final
                && !reports.failed()
                && let Some(publisher) = owners.statistics.as_mut()
                && !publisher.is_closed()
            {
                match publisher.poll(cx, Some(until)) {
                    Poll::Ready(Err(error)) => owners.statistics_failed(error),
                    Poll::Ready(Ok(_)) => activity = true,
                    Poll::Pending => {}
                }
            }
            if reports.failed() {
                owners.abort_statistics();
            }
            let stats_done = owners.statistics.as_ref().is_none_or(Publisher::is_closed);
            if gateway_done && stats_done {
                return Poll::Ready(());
            }
            if publish_final && !reports.failed() && !stats_done && resolver_error.is_none() {
                let progress = {
                    let mut resolving =
                        std::pin::pin!(owners.resolver.drive_waiting(Some(until), |event| {
                            reports.debug(
                                "dns.resolver.cleanup.activity",
                                format_args!("dns cleanup Resolver: {event:?}"),
                            )
                        }));
                    resolving.as_mut().poll(cx)
                };
                match progress {
                    Poll::Ready(Err(error)) => {
                        resolver_error = Some(Box::new(error));
                        owners.abort_statistics();
                    }
                    Poll::Ready(Ok(_)) => activity = true,
                    Poll::Pending => {}
                }
                // The drive future's borrow has ended before physical abort.
                // A diagnostic emitted by that exact poll may have failed.
                if reports.failed() {
                    owners.abort_statistics();
                }
            }
            if activity {
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        }),
    )
    .await;
    if drained.is_err() {
        // A caller timeout may win before the helper's native force-stop guard.
        // Poll it once without canonical time; absent actual exit stays unknown.
        if let Some(gateway) = owners.gateway.as_mut() {
            poll_fn(|cx| {
                let _actual =
                    gateway.poll(cx, &[], Some(until), &mut |event| observe(&reports, event));
                Poll::Ready(())
            })
            .await;
        }
    }
    let retirement = drained.err().map(|error| -> Failure { format!("dns packet source/statistics retirement unconfirmed within fixed native grace: {error}; privileged cleanup remains unclaimed").into() });
    owners.abort_statistics();
    let publisher = owners.statistics.as_ref().map(Publisher::report);
    let gateway = owners.gateway.take().map(Gateway::into_report);
    reports.message(
        Level::INFO,
        "dns.stopped",
        format_args!("STOPPED dns gateway={gateway:?} statistics={publisher:?}"),
    );
    let resolver_close = owners
        .resolver
        .disconnect()
        .err()
        .map(|e| Box::new(e) as Failure);
    let resolver_io = owners.resolver.take_io_error();
    let resolver_connect = owners.resolver.take_connect_error();
    owners.done = true;
    Failures {
        original: outcome.err(),
        cleanup,
        statistics: owners.stats_error.take(),
        statistics_cleanup: owners.stats_cleanup.take(),
        resolver_drain: resolver_error,
        resolver_close,
        resolver_io,
        resolver_connect,
        retirement,
        gateway,
        publisher,
    }
    .finish()
}
