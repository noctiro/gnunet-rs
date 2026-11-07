//! Original MESSENGER, Resolver and statistics owners under standard SERVICE.
use crate::{
    Failure,
    control::Signals,
    lifecycle::{Cleanup, Failures, Owner},
    settings::Settings,
    statistics::Forwarder,
};
use gnunet_config::Configuration;
use gnunet_messenger_service_host::{
    EndpointSource, cadet, history,
    server::{self, Event, Progress, Server, SystemEntropy},
};
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
fn observe(reports: &Reporter, event: Event) {
    match event {
        Event::Socket(gnunet_service_runtime::accepted::SocketEvent::Failed(e))
            if e.is_emfile() => {}
        Event::Socket(e) => reports.debug("messenger.event", format_args!("messenger socket={e:?}")),
        Event::Rejected(address) => {
            reports.debug("messenger.event", format_args!("messenger rejected={address:?}"))
        }
        Event::Accepted(client) => {
            reports.debug("messenger.event", format_args!("messenger accepted source={}", client.value()))
        }
        Event::Closed { client, cause } => reports.debug("messenger.event", format_args!(
            "messenger closed source={} cause={cause:?}",
            client.value()
        )),
        Event::EntryFailed { client, reason, .. } => reports.debug("messenger.event", format_args!(
            "messenger room entry source={} failed={reason}",
            client.value()
        )),
        Event::OpenFailed { client, reason, .. } => reports.debug("messenger.event", format_args!(
            "messenger room open source={} failed={reason}",
            client.value()
        )),
        Event::Identity => {
            reports.debug("messenger.event", format_args!("messenger actual PILS public identity ready"))
        }
        Event::Queued { sequence, peer } => reports.debug("messenger.event", format_args!(
            "messenger output={sequence} peer={peer} immutable queued, no remote delivery proof"
        )),
        Event::Written { sequence, peer } => reports.debug("messenger.event", format_args!(
            "messenger output={sequence} peer={peer} local wholewritten"
        )),
        Event::Received {
            peer,
            authenticated,
        } => reports.debug("messenger.event", format_args!(
            "messenger input admitted peer={peer} authenticated={authenticated}"
        )),
        Event::CadetLost {
            epoch,
            channels,
            pending,
            cause,
        } => reports.debug("messenger.event", format_args!(
            "messenger original CADET epoch={epoch} channels={channels} pending={pending:?} cause={cause:?}"
        )),
        Event::PeerRefused { reason } => reports.debug("messenger.event", format_args!(
            "messenger original peer channel refused: {reason}"
        )),
        Event::SignAdmitted { operation } => reports.debug("messenger.event", format_args!(
            "messenger PILS original operation={operation} locally admitted, not complete"
        )),
        Event::SignWritten { operation } => reports.debug("messenger.event", format_args!(
            "messenger PILS original operation={operation} request wholewritten, result pending"
        )),
        Event::SignApplied { operation } => reports.debug("messenger.event", format_args!(
            "messenger PILS original operation={operation} actual signature verified/committed locally"
        )),
        Event::SignRejected { operation, reason } => reports.debug("messenger.event", format_args!(
            "messenger PILS original operation={operation} rejected={reason:?}"
        )),
        Event::SignDraftRetired { operation, reason } => reports.debug("messenger.event", format_args!(
            "messenger original unadmitted draft={operation:?} retired={reason}"
        )),
        Event::DependencyLost { pils } => reports.debug("messenger.event", format_args!(
            "messenger original dependency lost pils={pils}"
        )),
        Event::OutputLost { sequence, exposed } => reports.debug("messenger.event", format_args!(
            "messenger output={sequence} retired exposure={exposed:?}, remote delivery unclaimed"
        )),
        Event::History(history::Progress::Queued { generation, bytes }) => {
            reports.debug("messenger.event", format_args!(
                "messenger history attempted-generation={generation} bytes={bytes} worker-admitted, not durable"
            ))
        }
        Event::History(history::Progress::Committed { generation }) => reports.debug("messenger.event", 
            format_args!("messenger history actual committed-generation={generation}"),
        ),
    }
}
struct Owners<'c, 's, 'p, 'stats> {
    server: Server<'c, 's, 'p, SystemEntropy, 16>,
    resolver: ResolverDriver<8, 256>,
    statistics: Forwarder<'stats>,
    reports: Reporter,
    cleanup: Cleanup,
    done: bool,
}
impl Drop for Owners<'_, '_, '_, '_> {
    fn drop(&mut self) {
        if !self.done {
            self.server
                .close_all(&mut |event| observe(&self.reports, event));
            if let Some(error) = self.server.take_cleanup_error() {
                self.cleanup.retain(Owner::Server, Box::new(error));
            }
            if let Some(error) = self.statistics.close() {
                self.cleanup.retain(Owner::Statistics, error);
            }
            if let Err(error) = self.resolver.disconnect() {
                self.cleanup.retain(Owner::Resolver, Box::new(error));
            }
            // Emergency Drop closes real network owners; History's original
            // worker Drop joins admitted work. It cannot submit a new final cut.
            // Normal and error returns below always await explicit finish_history.
            self.done = true;
        }
    }
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
enum Turn {
    Signal,
    Resolver,
    Server(Progress),
    Statistics,
    Logging,
    Deadline,
}
async fn turn(
    owners: &mut Owners<'_, '_, '_, '_>,
    signals: &mut Signals,
    listeners: &[Listener<'_>],
    until: Option<Instant>,
    first: usize,
) -> Result<Turn, Failure> {
    let reports = owners.reports.clone();
    let (server, resolver, statistics) = (
        &mut owners.server,
        &mut owners.resolver,
        &mut owners.statistics,
    );
    let mut resolving = std::pin::pin!(resolver.drive_waiting(until, |event| reports.debug(
        "messenger.resolver.event",
        format_args!("messenger shared Resolver={event:?}")
    )));
    poll_fn(|cx| {
        reports.register(cx);
        if reports.failed() {
            return Poll::Ready(Ok(Turn::Logging));
        }
        if until.is_some_and(|u| Instant::now() >= u) {
            return Poll::Ready(Ok(Turn::Deadline));
        }
        if let Poll::Ready(signal) = signals.poll(cx) {
            return Poll::Ready(signal.map(|()| Turn::Signal).map_err(Into::into));
        }
        for offset in 0..3 {
            if reports.failed() {
                return Poll::Ready(Ok(Turn::Logging));
            }
            match (first + offset) % 3 {
                0 => {
                    if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                        return Poll::Ready(result.map(|_| Turn::Resolver).map_err(Into::into));
                    }
                }
                1 => {
                    if let Poll::Ready(result) =
                        server.poll(cx, listeners, until, &mut |event| observe(&reports, event))
                    {
                        return Poll::Ready(result.map(Turn::Server).map_err(Into::into));
                    }
                }
                _ => {
                    if statistics.poll(cx, until).is_ready() {
                        return Poll::Ready(Ok(Turn::Statistics));
                    }
                }
            }
        }
        Poll::Pending
    })
    .await
}
fn storage<T>(n: usize, make: impl Fn() -> T) -> Result<Vec<T>, Failure> {
    let mut v = Vec::new();
    v.try_reserve_exact(n)?;
    v.resize_with(n, make);
    Ok(v)
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
    let mut core_instance = gnunet_messenger_service_host::core::Instance::new();
    let mut history_instance = gnunet_messenger_service_host::core::Instance::new();
    let mut cadet_instance = cadet::Instance::new();
    let mut pils_instance = gnunet_pils::client::Instance::new();
    let mut statistics_instance = gnunet_ipc_unix::handle::Instance::new();
    let mut ports = storage(settings.native.rooms, cadet::PortSlot::new)?;
    let mut channels = storage(settings.native.tunnels, cadet::ChannelSlot::new)?;
    // No history worker exists during these fallible original owner constructors.
    let initialized = (|| -> Result<_, Failure> {
        context.connect(config.duplicate()?)?;
        let signals = Signals::new(parent)?;
        let cadet_source =
            EndpointSource::live(live.clone(), b"cadet", context.resolution_context());
        let pils_source = EndpointSource::live(live.clone(), b"pils", context.resolution_context());
        let entropy = SystemEntropy::open()?;
        let server = Server::<_, 16>::new(
            &mut core_instance,
            &mut cadet_instance,
            &mut pils_instance,
            &mut ports,
            &mut channels,
            settings.core,
            settings.native,
            server::Ports {
                options: settings.options.clone(),
                unix: settings.unix,
                clock: runtime_clock,
                cadet: cadet_source,
                pils: pils_source,
            },
            entropy,
        )?;
        let statistics = Forwarder::new(
            &mut statistics_instance,
            live,
            context.resolution_context(),
            reports.clone(),
        )?;
        Ok((signals, server, statistics))
    })();
    let (mut signals, server, statistics) = match initialized {
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
    let mut owners = Owners {
        server,
        resolver,
        statistics,
        reports: reports.clone(),
        cleanup,
        done: false,
    };
    let listeners = bound.listeners();
    let mut pending_history = None;
    // Transfer this one original caller borrow into recovered Core ownership.
    let mut history_domain = Some(&mut history_instance);
    let outcome: Result<(), Failure> = async {
        if reports.failed() {
            return Ok(());
        }
        owners.server.set_layout_policy(settings.layouts)?;
        // Open only after successful Server/layout construction, under the real
        // target UID. Install failures retain the same pair for explicit join.
        if let Some(directory) = settings.history_directory.as_ref() {
            pending_history = Some(history::History::open(
                history_domain.take().ok_or("MESSENGER history instance already consumed")?,
                directory, settings.core, settings.native.profile, settings.history,
            )?);
            owners.server.try_install_history(&mut pending_history)?;
        }
        let startup = Instant::now().checked_add(settings.startup)
            .ok_or("MESSENGER startup deadline overflow")?;
        let mut ready = false;
        let mut first = 0;
        let mut stop_at = None;
        loop {
            if reports.failed() {
                break Ok(());
            }
            owners.statistics.refresh(owners.server.statistics());
            if reports.failed() {
                break Ok(());
            }
            if !ready && stop_at.is_none() && owners.server.local_peer().is_some()
                && owners.server.transport_ready() && owners.server.history_ready()
            {
                {
                    let mut out = io::stdout().lock();
                    writeln!(out,
                        "READY messenger wire=0.29.1 ipc=listening pils=actual-public-identity cadet=actual-attached history={} generation={:?} recovery=trusted-owned-history producer-layout=explicit-original-and-transport workers={}",
                        if owners.server.history_generation().is_some() { "durable" } else { "volatile-explicit" },
                        owners.server.history_generation(),
                        usize::from(owners.server.history_generation().is_some()),
                    )?;
                    out.flush()?;
                }
                reports.message(
                    gnunet_program_host::policy::Level::INFO,
                    "messenger.ready",
                    format_args!("messenger actual PILS/CADET/history/listeners ready"),
                );
                if reports.failed() {
                    break Ok(());
                }
                child.ready()?;
                ready = true;
            }
            let until = stop_at.or(if ready { None } else { Some(startup) });
            let next = turn(&mut owners, &mut signals, &listeners, until, first).await;
            first = (first + 1) % 3;
            match next {
                Ok(Turn::Logging) => break Ok(()),
                Ok(Turn::Signal)
                    if stop_at.is_none() && settings.options.shutdown == ShutdownMode::Soft =>
                {
                    owners.server.request_shutdown(ShutdownMode::Soft);
                    match Instant::now().checked_add(settings.grace) {
                        Some(deadline) => stop_at = Some(deadline),
                        None => break Err("MESSENGER shutdown deadline overflow".into()),
                    }
                }
                Ok(Turn::Deadline | Turn::Server(Progress::WaitDeadline))
                    if !ready && stop_at.is_none() =>
                {
                    break Err("MESSENGER actual PILS/CADET/history startup deadline elapsed".into());
                }
                Ok(Turn::Signal | Turn::Deadline | Turn::Server(Progress::Closed | Progress::WaitDeadline)) => break Ok(()),
                Ok(Turn::Resolver | Turn::Statistics | Turn::Server(Progress::Activity)) => {},
                Err(error) => break Err(error),
            }
        }
    }.await;
    // No fresh clock sample or logger is needed for physical stop and worker join.
    let report = owners
        .server
        .close_all(&mut |event| observe(&reports, event));
    let pending_history_error = if let Some((mut history, _restored)) = pending_history.take() {
        history
            .shutdown()
            .await
            .err()
            .map(|e| Box::new(e) as Failure)
    } else {
        None
    };
    let history = owners
        .server
        .finish_history(&mut |event| observe(&reports, event))
        .await;
    let server_cleanup = owners.server.take_cleanup_error();
    let generation = owners.server.history_generation();
    let durable_cut = history.is_ok() && owners.server.history_committed();
    // Logging failure fences even new diagnostic mutations; actual cleanup must
    // still close the already owned statistics MQ without a new clock sample.
    let statistics = if reports.failed() {
        owners.statistics.close()
    } else {
        owners.statistics.refresh(owners.server.statistics());
        if reports.failed() {
            owners.statistics.close()
        } else {
            // A finite diagnostic cleanup budget is not a fabricated fsync bound.
            match Instant::now().checked_add(settings.grace) {
                Some(until) => owners.statistics.finish(&mut owners.resolver, until).await,
                None => owners.statistics.close(),
            }
        }
    };
    let statistics_report = owners.statistics.destroy_report();
    let resolver_close = owners.resolver.disconnect();
    owners.done = true;
    drop(owners);
    drop(listeners);
    drop(context);
    let output = {
        let mut out = io::stdout().lock();
        writeln!(out,"STOPPED messenger local={report:?} history={history:?} statistics-terminal={statistics_report:?} generation={generation:?} accepted-cut-committed={durable_cut} native-owners=retired remote-delivery-and-quiescence=unclaimed").and_then(|()|out.flush())
    };
    Failures {
        original: outcome.err(),
        history: history.err().map(|e| Box::new(e) as Failure),
        pending_history: pending_history_error,
        server: server_cleanup.map(|e| Box::new(e) as Failure),
        resolver: resolver_close.err().map(|e| Box::new(e) as Failure),
        statistics,
        output: output.err(),
    }
    .finish()
}
