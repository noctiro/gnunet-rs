//! Standard SERVICE owns the original helper, DNSSTUB, MQs and shared Resolver.
use crate::{Failure, settings::Settings, statistics};
use gnunet_config::Configuration;
use gnunet_dns_service_host::{Event, Gateway, GatewayProgress, Server, core};
use gnunet_program_host::{reporting::Reporter, shared_clock::SharedClock};
use gnunet_resolver_broker::LiveConfiguration;
use gnunet_service_runtime::{BoundListeners, clock::RuntimeClock};
use gnunet_service_startup::{ControlReceiver, StopSignals as Signals};
use std::{
    future::{Future, poll_fn},
    io::{self, Write},
    sync::Arc,
    task::Poll,
};
mod cleanup;
mod owners;
mod turn;
use owners::{Owners, rejected};
use turn::{TURN_CLASSES, Turn};

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
pub(super) struct Inputs {
    pub config: Configuration,
    pub settings: Settings,
    pub bound: BoundListeners,
    pub clock: SharedClock,
    pub reports: Reporter,
}
pub(super) async fn run(
    input: Inputs,
    parent: Option<ControlReceiver>,
    ready: impl Future<Output = Result<(), Failure>>,
) -> Result<(), Failure> {
    run_shared(
        input,
        ready,
        Some(Signals::new(parent)?),
        #[cfg(all(
            any(target_os = "macos", target_os = "ios"),
            feature = "apple-dns-proxy"
        ))]
        None,
    )
    .await
}
#[cfg(all(
    any(target_os = "macos", target_os = "ios"),
    feature = "apple-dns-proxy"
))]
pub(super) async fn run_provider(
    input: Inputs,
    ready: impl Future<Output = Result<(), Failure>>,
    native: &mut crate::provider::Runtime<'_>,
) -> Result<(), Failure> {
    #[cfg(target_os = "macos")]
    let signals = Some(Signals::new(None)?);
    #[cfg(target_os = "ios")]
    let signals = None;
    run_shared(input, ready, signals, Some(native)).await
}
async fn run_shared(
    input: Inputs,
    ready: impl Future<Output = Result<(), Failure>>,
    mut signals: Option<Signals>,
    #[cfg(all(
        any(target_os = "macos", target_os = "ios"),
        feature = "apple-dns-proxy"
    ))]
    mut provider: Option<&mut crate::provider::Runtime<'_>>,
) -> Result<(), Failure> {
    let Inputs {
        config,
        settings,
        bound,
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
        match statistics::new(
            &mut stats_instance,
            live,
            owners.resolver.context().resolution_context(),
            runtime_clock.clone(),
            settings.statistics,
        ) {
            Ok(publisher) => owners.statistics = Some(publisher),
            Err(error) => owners.statistics_failed(error),
        }
        crate::startup_check(&reports)?;
        let engine = core::Engine::new(&instance, settings.core)?;
        let server = Server::new(
            engine,
            runtime_clock,
            settings.native,
            settings.options,
            settings.unix,
        )?;
        let packet_source = settings.packets.label();
        #[cfg(all(any(target_os = "macos", target_os = "ios"), feature = "apple-dns-proxy"))]
        let mut upstream = match provider.as_ref() {
            Some(native) => gnunet_dns_service_host::Upstream::start_provider(
                native.session(),
                settings.gateway.resolver_sockets,
                core::MAX_DNS_BYTES,
                native.upstream_limits(),
            )?,
            None => gnunet_dns_service_host::Upstream::start(
                settings.gateway.resolver_sockets,
                core::MAX_DNS_BYTES,
            )?,
        };
        #[cfg(not(all(any(target_os = "macos", target_os = "ios"), feature = "apple-dns-proxy")))]
        let mut upstream = gnunet_dns_service_host::Upstream::start(
            settings.gateway.resolver_sockets,
            core::MAX_DNS_BYTES,
        )?;
        upstream.add_dns_sa(settings.exit)?;
        let packets = {
            let mut opening = std::pin::pin!(crate::packet_source::open(
                settings.packets,
                &mut upstream,
                settings.exit.ip(),
            ));
            poll_fn(|cx| {
                reports.register(cx);
                if let Err(error) = crate::startup_check(&reports) {
                    return Poll::Ready(Err(error));
                }
                if let Some(signals) = signals.as_mut()
                    && let Poll::Ready(stop) = signals.poll_stop(cx)
                {
                    return Poll::Ready(stop.map(|()| None).map_err(Into::into));
                }
                opening.as_mut().poll(cx).map(|result| result.map(Some))
            })
            .await?
        };
        let Some(packets) = packets else {
            return Ok(());
        };
        let gateway = match Gateway::with_upstream(server, packets, upstream, settings.gateway) {
            Ok(gateway) => gateway,
            Err(error) => return Err(rejected(error, grace, &reports).await),
        };
        owners.gateway = Some(gateway);
        crate::startup_check(&reports)?;
        if signals.is_some() {
            let mut out = io::stdout().lock();
            writeln!(
                out,
                "READY dns clients={} requests={} source={packet_source} interception-setup=unacknowledged",
                settings.core.clients,
                settings.core.requests,
            )?;
            out.flush()?;
        }
        // Listeners, Server, source and DNSSTUB exist before readiness. The
        // process path flushes its diagnostic before the original ready callback.
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
            let progress = turn::turn(
                &mut owners,
                &mut signals,
                &listeners,
                first,
                #[cfg(all(any(target_os = "macos", target_os = "ios"), feature = "apple-dns-proxy"))]
                provider.as_deref_mut(),
            ).await?;
            first = (first + 1) % TURN_CLASSES;
            match progress {
                Turn::Stop => break Ok(()),
                Turn::Resolver | Turn::Statistics => {},
                #[cfg(all(any(target_os = "macos", target_os = "ios"), feature = "apple-dns-proxy"))]
                Turn::Provider => {},
                Turn::Gateway(GatewayProgress::Stopped | GatewayProgress::SourceRetired) => {
                    break Err("DNS original helper/source stopped before requested shutdown".into());
                }
                Turn::Gateway(GatewayProgress::PacketDropped(reason)) => reports.debug(
                    "dns.packet.discarded",
                    format_args!("dns actual captured packet discarded: {reason}"),
                ),
                Turn::Gateway(GatewayProgress::PacketRefused { request, reason }) => reports.warning(
                    "dns.packet.refused",
                    format_args!("dns packet-local refusal {request:?}: {reason}"),
                ),
                #[cfg(any(target_os = "macos", target_os = "ios"))]
                Turn::Gateway(GatewayProgress::FlowStopped { flow, reason }) => reports.warning(
                    "dns.flow.stopped",
                    format_args!("dns application flow {flow:?} stopped: {reason}"),
                ),
                #[cfg(windows)]
                Turn::Gateway(GatewayProgress::RouteObservationFailed { reason }) => reports.warning(
                    "dns.route.observation",
                    format_args!("dns interface observation failed: {reason}"),
                ),
                Turn::Gateway(GatewayProgress::ResolverRefused { request, reason }) => reports.warning(
                    "dns.resolver.refused",
                    format_args!("dns original resolver admission refused for {request:?}: {reason}"),
                ),
                Turn::Gateway(GatewayProgress::ResolverDiscarded { native, reason }) => reports.debug(
                    "dns.resolver.discarded",
                    format_args!("dns actual resolver datagram discarded for {native:?}: {reason}"),
                ),
                Turn::Gateway(
                    GatewayProgress::ResolverQueued { .. }
                    | GatewayProgress::Activity
                    | GatewayProgress::WaitDeadline,
                ) => {},
            }
        }
    }.await;
    drop(listeners);
    drop(bound);
    cleanup::finish(
        &mut owners,
        &reports,
        outcome,
        grace,
        #[cfg(all(
            any(target_os = "macos", target_os = "ios"),
            feature = "apple-dns-proxy"
        ))]
        provider,
    )
    .await
}
