use crate::{
    control::Signals,
    identity::{self, Dependencies},
    readiness::Ready,
    settings::{Settings, filled},
};
use gnunet_cadet::service as pure;
use gnunet_cadet_host::server::{self, CloseCause, Event, Report, Server};
use gnunet_client_host::EndpointSource;
use gnunet_pils::client::{Identity, Instance as PilsInstance};
use gnunet_program_host::{policy::Level, reporting::Reporter, service::native::Context};
use gnunet_resolver_broker::{LiveConfiguration, broker, native_profile};
use gnunet_service_runtime::{accepted::SocketEvent, clock::RuntimeClock, service::Listener};
use gnunet_types::Error as ProtocolError;
use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io::{self, Write},
    sync::Arc,
    task::Poll,
};
#[derive(Clone, Copy)]
pub(super) enum Stage {
    Application = 0,
    Identity = 1,
    Resolver = 2,
    NativeClose = 3,
    Control = 4,
    Output = 5,
    Peer = 6,
    PeerCleanup = 7,
    Statistics = 8,
}
const NAMES: [&str; 9] = [
    "application",
    "PILS identity",
    "Resolver",
    "local MQ cleanup",
    "process control",
    "readiness/diagnostic output",
    "native peer coordinator",
    "peer physical cleanup",
    "STATISTICS diagnostic source",
];
#[derive(Debug)]
pub(super) struct Failures {
    causes: [Option<Box<dyn Error>>; 9],
    extra: [usize; 9],
}
impl Failures {
    fn new() -> Self {
        Self {
            causes: std::array::from_fn(|_| None),
            extra: [0; 9],
        }
    }
    pub(super) fn record(&mut self, stage: Stage, cause: Box<dyn Error>) {
        let index = stage as usize;
        if self.causes[index].is_none() {
            self.causes[index] = Some(cause);
        } else {
            self.extra[index] = self.extra[index].saturating_add(1);
        }
    }
    pub(super) fn is_empty(&self) -> bool {
        self.causes.iter().all(Option::is_none)
    }
}
impl fmt::Display for Failures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for (index, cause) in self.causes.iter().enumerate() {
            if let Some(cause) = cause {
                if !first {
                    f.write_str("; ")?;
                }
                write!(f, "{}: {cause}", NAMES[index])?;
                if self.extra[index] != 0 {
                    write!(f, " ({} further failures at this stage)", self.extra[index])?;
                }
                first = false;
            }
        }
        Ok(())
    }
}
impl Error for Failures {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.causes
            .iter()
            .find_map(|cause| cause.as_ref().map(|cause| cause.as_ref()))
    }
}
pub(super) struct Diagnostics<'id> {
    // One Server::poll returns at most one newly Blocked event. Never close an
    // MQ by reentering its callback; retire its exact source after poll returns.
    pub(super) retire: Option<(pure::Client<'id>, ProtocolError)>,
    reporter: Reporter,
}
impl<'id> Diagnostics<'id> {
    pub(super) fn new(reporter: Reporter) -> Self {
        Self {
            retire: None,
            reporter,
        }
    }
    pub(super) fn observe(&mut self, event: Event<'id>) {
        match event {
            Event::DrainExpired(channel) => self.reporter.warning("cadet.destroy.deadline", format_args!(
                "cadet original explicit destroy client={} channel={} cause=Deadline; no peer acceptance asserted",
                channel.client().value(), channel.wire_id())),
            Event::Blocked {
                client,
                stage,
                reason,
            } => {
                if self.retire.is_none() {
                    self.retire = Some((client, reason));
                }
                self.reporter.warning("cadet.native.refusal",format_args!("cadet bounded refusal client={} stage={stage:?} reason={reason}; retire-original-mq=true", client.value()));
            }
            Event::Closed { loss, cause } => self.reporter.warning("cadet.native.refusal",format_args!(
                "cadet client-closed client={} channels={} pending={:?} exposed={} cause={cause:?}",
                loss.client.value(),
                loss.channels,
                loss.pending,
                loss.exposed
            )),
            Event::Socket(SocketEvent::Failed(error)) if error.is_emfile() => {}
            Event::Socket(SocketEvent::Failed(error))=>self.reporter.warning("cadet.socket.failed",format_args!("cadet socket failed: {error}")),
            Event::Socket(event)=>self.reporter.warning("cadet.socket.diagnostic",format_args!("cadet socket: {event:?}")),
            Event::Rejected(peer) => {
                self.reporter.warning("cadet.native.refusal",format_args!("cadet rejected unadmitted source: {peer:?}"))
            }
            Event::AdmissionFailed(error) => self.reporter.warning("cadet.native.refusal",format_args!(
                "cadet unadmitted source already closed: {error}"
            )),
            _ => {}
        }
    }
    pub(super) fn retire_refusal(
        &mut self,
        server: &mut Server<'id, '_, '_>,
        failures: &mut Failures,
    ) {
        if let Some((client, reason)) = self.retire.take()
            && let Err(error) = server.close(
                client,
                CloseCause::Fault(server::Error::Protocol(reason)),
                &mut |event| self.observe(event),
            )
        {
            failures.record(Stage::NativeClose, Box::new(error));
        }
    }
}
fn stopped(report: Report, peer_enabled: bool) -> io::Result<()> {
    let mut out = io::stdout().lock();
    writeln!(
        out,
        "STOPPED cadet accepted={} inputs={} outputs={} written-frames={} written-bytes={} closed={} local-mq-stopped=true peer-backend={} remote-effects-quiesced=not-claimed",
        report.accepted,
        report.inputs,
        report.outputs,
        report.written_frames,
        report.written_bytes,
        report.closed,
        if peer_enabled {
            "core-direct"
        } else {
            "unavailable"
        }
    )?;
    out.flush()
}
async fn application<'p>(
    settings: &Settings,
    listeners: &[Listener<'_>],
    dependencies: &mut Dependencies<'p, '_>,
    identity: Identity<'p>,
    setup: crate::peer::Setup<'_, '_>,
    failures: &mut Failures,
) -> Result<Report, Box<dyn Error>> {
    let mut instance = pure::Instance::new();
    let mut clients = filled(settings.clients, pure::ClientSlot::new())?;
    let mut ports = filled(settings.ports, pure::PortSlot::new())?;
    let mut channels = filled(settings.channels, pure::ChannelSlot::new())?;
    // Two contiguous global byte allocations, independent of channel metadata.
    // One per-MQ ingress buffer and shared source baseline/surplus slots.
    let mut ingress = filled(settings.ingress_bytes, 0_u8)?;
    let mut outgoing = filled(settings.source_bytes, 0_u8)?;
    let mut messages = Vec::new();
    messages
        .try_reserve_exact(
            settings
                .clients
                .checked_add(settings.source_buffers)
                .ok_or(ProtocolError::Overflow)?,
        )
        .map_err(|_| ProtocolError::Capacity)?;
    for bytes in ingress.chunks_exact_mut(settings.protocol.remote_payload_bytes) {
        messages.push(pure::MessageSlot::new(bytes));
    }
    for bytes in outgoing.chunks_exact_mut(settings.source_payload_bytes) {
        messages.push(pure::MessageSlot::new(bytes));
    }
    let local = *identity.peer().as_bytes();
    let service = pure::Service::new(
        &mut instance,
        local,
        &mut clients,
        &mut ports,
        &mut channels,
        &mut messages,
        settings.protocol,
    )?;
    let clock = dependencies.pils.clock();
    let mut server = Server::new(
        service,
        settings.native,
        settings.options.clone(),
        settings.unix,
        clock,
    )?;
    let result = if settings.peer.enabled {
        crate::peer::run(
            settings,
            listeners,
            dependencies,
            identity,
            &mut server,
            setup,
            failures,
        )
        .await
    } else {
        crate::local::run(
            settings,
            listeners,
            dependencies,
            identity,
            &mut server,
            setup.ready,
            failures,
        )
        .await
    };
    if let Err(error) = result {
        failures.record(
            if settings.peer.enabled {
                Stage::Peer
            } else {
                Stage::Application
            },
            error,
        );
    }
    // This caller retains application ownership through every construction and
    // startup refusal. Final physical retirement/reporting has one common owner.
    let reporter = dependencies.reporter.clone();
    let mut diagnostics = Diagnostics::new(reporter.clone());
    if let Err(error) = server.close_all(&mut |event| diagnostics.observe(event)) {
        failures.record(Stage::NativeClose, Box::new(error));
    }
    diagnostics.retire_refusal(&mut server, failures);
    if !settings.peer.enabled
        && let Err(error) = crate::local::finish(&mut server, settings.channels, &reporter)
    {
        failures.record(Stage::NativeClose, error);
    }
    // A successful peer owner already published its complete final snapshot.
    // Replacing that with the application-only subset would erase peer history.
    if !settings.peer.enabled {
        dependencies.statistics.observe(&server.statistics());
    } else {
        dependencies
            .statistics
            .observe_clients(server.clients().count());
    }
    Ok(*server.report())
}

pub(super) async fn run(context: Context<'_, Settings>) -> Result<(), Box<dyn Error>> {
    let Context {
        config,
        settings,
        listeners: bound,
        signals,
        clock,
        reports: reporter,
        readiness,
    } = context;
    let signals = Signals::new(signals);
    let mut ready = Ready::new(readiness, reporter.clone());
    let clock: Arc<dyn RuntimeClock> = Arc::new(clock);
    let live = LiveConfiguration::new(config.duplicate()?);
    let (context, resolver) = broker::<16, 256>(
        live.clone(),
        Default::default(),
        native_profile()?,
        clock.clone(),
    )?;
    let peer_endpoints = crate::peer::Endpoints {
        core: EndpointSource::live(live.clone(), b"core", context.resolution_context()),
        dht: EndpointSource::live(live.clone(), b"dht", context.resolution_context()),
        transport: EndpointSource::live(live.clone(), b"transport", context.resolution_context()),
        dh: EndpointSource::live(live.clone(), b"pils", context.resolution_context()),
        signing: EndpointSource::live(live.clone(), b"pils", context.resolution_context()),
    };
    let pils_source = EndpointSource::live(live.clone(), b"pils", context.resolution_context());
    let mut pils_instance = PilsInstance::new();
    let pils = identity::observer(&mut pils_instance, pils_source, &settings)?;
    let mut statistics_instance = gnunet_ipc_unix::handle::Instance::new();
    let statistics = crate::statistics::Owner::new(
        &mut statistics_instance,
        live,
        context.resolution_context(),
        clock.clone(),
        settings.statistics,
        reporter.clone(),
    );
    let recovery_timeout = settings
        .pils_startup_timeout
        .checked_add(settings.peer.forced_drain)
        .ok_or(ProtocolError::Overflow)?;
    let mut dependencies = Dependencies::new(
        pils,
        resolver,
        signals,
        reporter.clone(),
        statistics,
        recovery_timeout,
    );
    let mut failures = Failures::new();
    let mut report = Report::default();
    if let Some(identity) = dependencies
        .wait_identity(clock.clone(), settings.pils_startup_timeout, &mut failures)
        .await
    {
        let listeners = bound.listeners();
        match application(
            &settings,
            &listeners,
            &mut dependencies,
            identity,
            crate::peer::Setup {
                endpoints: peer_endpoints,
                ready: &mut ready,
            },
            &mut failures,
        )
        .await
        {
            Ok(actual) => report = actual,
            Err(error) => failures.record(Stage::Application, error),
        }
        drop(listeners);
    }
    // Business/peer owners returned after their original native retirement.
    // Preserve the final snapshot, then bounded real publisher drain while the
    // original Resolver is still alive. Any main/clock/logger fault aborts only
    // this same publisher without another canonical sample.
    dependencies.statistics.begin_close(
        settings.statistics_grace,
        !failures.is_empty() || reporter.failed(),
    );
    while !dependencies.statistics.is_closed() {
        let mut resolver_failure = None;
        {
            let mut resolving = std::pin::pin!(
                dependencies
                    .resolver
                    .drive_waiting(None, |event| identity::resolver_event(&reporter, event))
            );
            poll_fn(|cx| {
                reporter.register(cx);
                if reporter.failed() {
                    dependencies.statistics.abort();
                    return Poll::Ready(());
                }
                // poll() performs its original native guard before canonical IO.
                let stats = dependencies.statistics.poll(cx).is_ready();
                if reporter.failed() {
                    dependencies.statistics.abort();
                    return Poll::Ready(());
                }
                let resolved = match resolving.as_mut().poll(cx) {
                    Poll::Ready(Err(error)) => {
                        resolver_failure = Some(error);
                        true
                    }
                    Poll::Ready(Ok(_)) => true,
                    Poll::Pending => false,
                };
                if stats || resolved || dependencies.statistics.is_closed() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
        }
        if let Some(error) = resolver_failure {
            failures.record(Stage::Resolver, Box::new(error));
            dependencies.statistics.abort();
        }
        tokio::task::yield_now().await;
    }
    // Independent cleanup executes for identity/startup/output/application faults.
    dependencies.close(&mut failures);
    drop(dependencies);
    drop(context);
    // The native driver retains original listeners until this invocation returns.
    reporter.message(Level::INFO,"cadet.stopped",format_args!("CADET local MQ/dependency owners retired; remote quiescence remains separately reported"));
    if let Err(error) = stopped(report, settings.peer.enabled) {
        failures.record(Stage::Output, Box::new(error));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(Box::new(failures))
    }
}
