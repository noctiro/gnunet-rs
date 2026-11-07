//! Standard SERVICE lifecycle over the same original RPS/CADET owners.
use crate::{
    Cause,
    control::Signals,
    discovery::{self, Endpoints, Sources},
    lifecycle::{Cleanup, Resolver},
    settings::Settings,
};
use gnunet_client_host::EndpointSource;
use gnunet_config::Configuration;
use gnunet_program_host::{reporting::Reporter, shared_clock::SharedClock};
use gnunet_resolver_broker::{LiveConfiguration, broker, native_profile};
use gnunet_rps_host::server::{self, CloseCause, Event, Progress, Server};
use gnunet_service_runtime::{BoundListeners, clock::RuntimeClock, service::ShutdownMode};
use gnunet_service_startup::{ParentControl, daemon::ChildReady};
use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io::{self, Write},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};

/// These are bounded original diagnostic causes. They grant no new channel,
/// delivery, union completion or authority to a replacement native source.
#[derive(Debug, Default)]
struct Diagnostics {
    first_admission: Option<server::Error>,
    first_app_fault: Option<server::Error>,
    first_loss: Option<NativeLoss>,
    first_retry: Option<io::Error>,
    source_events: u64,
    peer_refusals: u64,
    losses: u64,
    retries: u64,
}
struct NativeLoss {
    epoch: u64,
    channels: usize,
    pending: Option<(u64, gnunet_cadet_host::TransmitKind, bool)>,
    cause: gnunet_cadet_host::LossCause,
}
impl fmt::Debug for NativeLoss {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeLoss")
            .field("epoch", &self.epoch)
            .field("channels", &self.channels)
            .field("pending", &self.pending)
            .field("cause", &self.cause)
            .finish()
    }
}
fn observe(event: Event<'_>, reports: &Reporter, diagnostics: &mut Diagnostics) {
    match event {
        Event::Socket(gnunet_service_runtime::accepted::SocketEvent::Failed(error))
            if error.is_emfile() => {}
        Event::AdmissionFailed(error) => {
            reports.warning(
                "rps.admission.failed",
                format_args!("RPS admission: {error}"),
            );
            if diagnostics.first_admission.is_none() {
                diagnostics.first_admission = Some(error);
            }
        }
        Event::Closed {
            client,
            cause: CloseCause::Fault(error),
        } => {
            reports.warning(
                "rps.app.failed",
                format_args!("RPS original app {client:?}: {error}"),
            );
            if diagnostics.first_app_fault.is_none() {
                diagnostics.first_app_fault = Some(error);
            }
        }
        Event::CadetLost { report, cause } => {
            reports.warning(
                "rps.cadet.lost",
                format_args!("RPS original CADET retirement={report:?}: {cause:?}"),
            );
            diagnostics.losses = diagnostics.losses.saturating_add(1);
            if diagnostics.first_loss.is_none() {
                diagnostics.first_loss = Some(NativeLoss {
                    epoch: report.epoch.value(),
                    channels: report.channels,
                    pending: report.pending.map(|pending| {
                        (
                            pending.transmit.value(),
                            pending.transmit.kind(),
                            pending.exposed,
                        )
                    }),
                    cause,
                });
            }
        }
        Event::CadetRetry { error, retry_after } => {
            reports.warning(
                "rps.cadet.retry",
                format_args!("RPS original CADET retry after {retry_after:?}: {error}"),
            );
            diagnostics.retries = diagnostics.retries.saturating_add(1);
            if diagnostics.first_retry.is_none() {
                diagnostics.first_retry = Some(error);
            }
        }
        Event::PeerRefused { error, .. } => {
            diagnostics.peer_refusals = diagnostics.peer_refusals.saturating_add(1);
            reports.warning(
                "rps.peer.refused",
                format_args!("RPS peer refusal: {error}"),
            );
        }
        Event::EffectTerminal(terminal) => {
            if let gnunet_rps::Completion::Unsent(error) | gnunet_rps::Completion::Lost(error) =
                terminal.completion
            {
                reports.debug(
                    "rps.effect.retired",
                    format_args!(
                        "RPS original effect {:?}: {:?}: {error}",
                        terminal.effect.id, terminal.completion
                    ),
                );
            }
        }
        Event::Accepted(_) | Event::Input(_) | Event::Queued { .. } | Event::Write { .. } => {}
        other => reports.debug("rps.activity", format_args!("RPS actual event={other:?}")),
    }
}

#[derive(Clone, Copy, Debug)]
enum StopReason {
    Signal,
    SecondSignal,
    GraceExpired,
    NativeStopped,
    Failed,
    Logger,
}
#[derive(Default)]
struct Failures {
    original: Option<Cause>,
    running: Option<server::Error>,
    resolver: Option<gnunet_resolver_broker::BrokerError>,
    cleanup: Option<server::Error>,
    resolver_close: Option<Cause>,
    source_close: Option<Cause>,
    source_close_facts: Option<SourceCloseFacts>,
    logging: Option<io::Error>,
    output: Option<io::Error>,
    report: server::Report,
    diagnostics: Diagnostics,
    reason: Option<StopReason>,
}
impl Failures {
    fn failed(&self) -> bool {
        self.original.is_some()
            || self.running.is_some()
            || self.resolver.is_some()
            || self.cleanup.is_some()
            || self.resolver_close.is_some()
            || self.source_close.is_some()
            || self.logging.is_some()
            || self.output.is_some()
    }
}
impl fmt::Debug for Failures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Failures")
            .field("original", &self.original)
            .field("running", &self.running)
            .field("resolver", &self.resolver)
            .field("cleanup", &self.cleanup)
            .field("resolver_close", &self.resolver_close)
            .field("source_close", &self.source_close)
            .field("source_close_facts", &self.source_close_facts)
            .field("logging", &self.logging)
            .field("output", &self.output)
            .field("report", &self.report)
            .field("diagnostics", &self.diagnostics)
            .field("reason", &self.reason)
            .finish()
    }
}
impl fmt::Display for Failures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RPS original lifecycle={self:?}")
    }
}
impl Error for Failures {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.running.as_ref().map(|e| e as &dyn Error))
            .or_else(|| self.resolver.as_ref().map(|e| e as &dyn Error))
            .or_else(|| self.cleanup.as_ref().map(|e| e as &dyn Error))
            .or(self.resolver_close.as_deref())
            .or_else(|| self.logging.as_ref().map(|e| e as &dyn Error))
            .or(self.source_close.as_deref())
            .or_else(|| self.output.as_ref().map(|e| e as &dyn Error))
    }
}
struct Grace {
    hard: Instant,
    alarm: Pin<Box<Sleep>>,
}
impl Grace {
    fn new(duration: Duration) -> Result<Self, Cause> {
        let hard = Instant::now()
            .checked_add(duration)
            .ok_or("RPS original shutdown target overflow")?;
        Ok(Self {
            hard,
            alarm: Box::pin(tokio::time::sleep_until(hard)),
        })
    }
    fn expired(&self) -> bool {
        Instant::now() >= self.hard
    }
    fn guard(&mut self, cx: &mut Context<'_>) -> bool {
        self.alarm.as_mut().poll(cx).is_ready() || self.expired()
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
pub(super) async fn run(input: Inputs<'_>) -> Result<(), Cause> {
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
    let mut signals = Signals::new(parent)?;
    let stopped = poll_fn(|cx| {
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
    if stopped {
        return Ok(());
    }
    let live = LiveConfiguration::new(config.duplicate()?);
    let source_clock: Arc<dyn RuntimeClock> = Arc::new(clock);
    let (context, resolver) = broker::<128, 256>(
        live.clone(),
        settings.resolver,
        native_profile()?,
        source_clock.clone(),
    )?;
    let mut resolver = Resolver::new(resolver, cleanup.clone());
    let source = EndpointSource::live(live.clone(), b"cadet", context.resolution_context());
    let endpoints = Endpoints {
        core: EndpointSource::live(live.clone(), b"core", context.resolution_context()),
        peerstore: EndpointSource::live(live.clone(), b"peerstore", context.resolution_context()),
        nse: EndpointSource::live(live, b"nse", context.resolution_context()),
    };
    let mut discovery_instances = discovery::Instances::new();
    let mut sources = Sources::new(&mut discovery_instances, endpoints, settings)?;
    let mut instance = gnunet_cadet_host::Instance::new();
    let mut ports = Vec::new();
    ports.try_reserve_exact(settings.native.groups)?;
    ports.resize_with(settings.native.groups, gnunet_cadet_host::PortSlot::new);
    let mut channels = Vec::new();
    channels.try_reserve_exact(settings.native.channels)?;
    channels.resize_with(
        settings.native.channels,
        gnunet_cadet_host::ChannelSlot::new,
    );
    let cadet = gnunet_cadet_host::Client::new(
        &mut instance,
        source,
        &mut ports,
        &mut channels,
        settings.cadet,
    )?;
    let mut rps_instance = gnunet_rps::Instance::new();
    let mut server: Option<Server<'_, '_>> = None;
    let listeners = bound.listeners();
    let mut failures = Failures::default();
    // Every fallible exit after ownership transfer reaches the same synchronous
    // shutdown below. No Drop or timer is used as its completion receipt.
    let outcome: Result<(), Cause> = async {
        let mut startup = Grace::new(settings.startup_timeout)?;
        let local = poll_fn(|cx| {
            if startup.guard(cx) {
                return Poll::Ready(Err("RPS CORE identity startup deadline elapsed".into()));
            }
            reports.register(cx);
            if reports.failed() {
                return Poll::Ready(Err(
                    "RPS selected logger failed during initialization".into()
                ));
            }
            if let Poll::Ready(result) = signals.poll(cx) {
                result?;
                return Poll::Ready(Ok(None));
            }
            if let Poll::Ready(result) = resolver.poll(cx, &reports) {
                result?;
            }
            if reports.failed() {
                return Poll::Ready(Err(
                    "RPS selected logger failed during Resolver initialization".into(),
                ));
            }
            match sources.poll_identity(cx) {
                Poll::Ready(Ok(discovery::Event::Identity { epoch, peer, .. })) => {
                    reports.debug(
                        "rps.core.identity",
                        format_args!("RPS original local identity source={epoch:?}"),
                    );
                    Poll::Ready(Ok(Some(peer)))
                }
                Poll::Ready(Ok(discovery::Event::Core(
                    gnunet_core_client_host::Progress::Unavailable(error),
                ))) => Poll::Ready(Err(Box::new(error) as Cause)),
                Poll::Ready(Ok(discovery::Event::Core(
                    gnunet_core_client_host::Progress::Capacity(_),
                ))) => Poll::Ready(Err(Box::new(gnunet_types::Error::Capacity) as Cause)),
                Poll::Ready(Ok(discovery::Event::Core(
                    gnunet_core_client_host::Progress::Closed,
                ))) => Poll::Ready(Err("RPS CORE discovery owner closed before identity".into())),
                Poll::Ready(Ok(event)) => {
                    source_notice(event, &reports, &mut failures.diagnostics);
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;
        let Some(local) = local else { return Ok(()) };
        let mut random = gnunet_rps_host::ports::NativeRandom::default();
        let core = match gnunet_rps::Service::new(
            &mut rps_instance,
            local,
            gnunet_rps_host::ports::main_group_hash(),
            settings.core,
            settings.limits,
            source_clock.sample()?.now.as_micros(),
            &mut random,
        ) {
            Ok(core) => core,
            Err(fault) => {
                return Err(Box::new(match random.take_error() {
                    Some(error) => server::Error::Entropy(error),
                    None => server::Error::Protocol(fault),
                }) as Cause);
            }
        };
        server = Some(Server::new(
            core,
            cadet,
            settings.native,
            settings.options.clone(),
            settings.access,
        )?);
        let actual = server
            .as_mut()
            .ok_or("RPS server owner missing after construction")?;
        if !Arc::ptr_eq(&actual.clock(), &source_clock) {
            return Err("RPS actual source clock mismatch".into());
        }
        let initialized = poll_fn(|cx| -> Poll<Result<bool, Cause>> {
            if startup.guard(cx) {
                return Poll::Ready(Err("RPS CADET port startup deadline elapsed".into()));
            }
            reports.register(cx);
            if reports.failed() {
                return Poll::Ready(Err(
                    "RPS selected logger failed during CADET initialization".into(),
                ));
            }
            if let Poll::Ready(result) = signals.poll(cx) {
                result?;
                return Poll::Ready(Ok(false));
            }
            if let Poll::Ready(result) = resolver.poll(cx, &reports) {
                result?;
            }
            if reports.failed() {
                return Poll::Ready(Err(
                    "RPS selected logger failed during Resolver initialization".into(),
                ));
            }
            let advanced = match actual.poll(cx, &[], Some(startup.hard), &mut |event| {
                observe(event, &reports, &mut failures.diagnostics)
            }) {
                Poll::Ready(result) => {
                    if result? == Progress::Stopped {
                        return Poll::Ready(
                            Err("RPS native owner stopped before readiness".into()),
                        );
                    }
                    true
                }
                Poll::Pending => false,
            };
            if actual.initialized() {
                Poll::Ready(Ok(true))
            } else {
                if advanced {
                    cx.waker().wake_by_ref();
                }
                Poll::Pending
            }
        })
        .await?;
        if !initialized {
            return Ok(());
        }

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
            let mut output = io::stdout().lock();
            writeln!(
                output,
                "READY rps wire=0.29.1 listeners=bound sampling=local cadet=announced"
            )?;
            output.flush()?;
        }
        child.ready()?;
        let mut grace: Option<Grace> = None;
        let mut cursor = false;
        loop {
            enum Turn {
                Activity,
                Stop,
                Expired,
                Stopped,
                Failed,
            }
            let selected: Result<Turn, Cause> = {
                let deadline = grace.as_ref().map(|g| g.hard);
                poll_fn(|cx| {
                    // Native hard first, before any canonical clock/provider IO.
                    if grace.as_mut().is_some_and(|g| g.guard(cx)) {
                        return Poll::Ready(Ok(Turn::Expired));
                    }
                    reports.register(cx);
                    if reports.failed() {
                        return Poll::Ready(Ok(Turn::Stop));
                    }
                    if let Poll::Ready(result) = signals.poll(cx) {
                        result?;
                        return Poll::Ready(Ok(Turn::Stop));
                    }
                    let mut activity = false;
                    for offset in 0..3 {
                        if grace.as_ref().is_some_and(Grace::expired) {
                            return Poll::Ready(Ok(Turn::Expired));
                        }
                        // A pending Resolver callback can fail the logger. It
                        // must fence the following live Server poll this turn.
                        if reports.failed() {
                            return Poll::Ready(Ok(Turn::Stop));
                        }
                        if (usize::from(cursor) + offset) % 3 == 0 {
                            match resolver.poll(cx, &reports) {
                                Poll::Ready(Ok(_)) => activity = true,
                                Poll::Ready(Err(error)) => {
                                    failures.resolver = Some(error);
                                    return Poll::Ready(Ok(Turn::Failed));
                                }
                                Poll::Pending => {}
                            }
                        } else if (usize::from(cursor) + offset) % 3 == 1 {
                            if grace.is_none() {
                                match sources.poll(cx) {
                                    Poll::Ready(Ok(event)) => {
                                        source_event(
                                            event,
                                            local,
                                            actual,
                                            settings,
                                            &reports,
                                            &mut failures.diagnostics,
                                        )?;
                                        activity = true;
                                    }
                                    Poll::Ready(Err(error)) => {
                                        failures.original = Some(error);
                                        return Poll::Ready(Ok(Turn::Failed));
                                    }
                                    Poll::Pending => {}
                                }
                            }
                        } else if let Poll::Ready(result) =
                            actual.poll(cx, &listeners, deadline, &mut |event| {
                                observe(event, &reports, &mut failures.diagnostics)
                            })
                        {
                            match result {
                                Ok(Progress::Activity) => activity = true,
                                Ok(Progress::WaitDeadline) => {
                                    return Poll::Ready(Ok(Turn::Expired));
                                }
                                Ok(Progress::Stopped) => return Poll::Ready(Ok(Turn::Stopped)),
                                Err(error) => {
                                    failures.running = Some(error);
                                    return Poll::Ready(Ok(Turn::Failed));
                                }
                            }
                        }
                    }
                    if activity {
                        Poll::Ready(Ok(Turn::Activity))
                    } else {
                        Poll::Pending
                    }
                })
                .await
            };
            cursor = !cursor;
            match selected? {
                Turn::Activity => {}
                Turn::Failed => {
                    failures.reason = Some(StopReason::Failed);
                    break;
                }
                Turn::Stopped => {
                    failures.reason = Some(StopReason::NativeStopped);
                    break;
                }
                Turn::Expired => {
                    failures.reason = Some(StopReason::GraceExpired);
                    break;
                }
                Turn::Stop => {
                    if reports.failed() {
                        failures.reason = Some(StopReason::Logger);
                        break;
                    }
                    if grace.is_none() && settings.options.shutdown == ShutdownMode::Soft {
                        grace = Some(Grace::new(settings.shutdown_grace)?);
                        actual.request_shutdown(ShutdownMode::Soft);
                        failures.reason = Some(StopReason::Signal);
                    } else {
                        failures.reason = Some(if grace.is_some() {
                            StopReason::SecondSignal
                        } else {
                            StopReason::Signal
                        });
                        break;
                    }
                }
            }
        }
        Ok(())
    }
    .await;
    if let Err(error) = outcome {
        failures.original = Some(error);
    }
    // Actual physical retirement is independent of canonical sampling and may
    // run after source clock, Logger, Resolver, credit or partial IO failed.
    // RPS owns no index/storage worker or detached task to join.
    if let Some(mut actual) = server.take() {
        let stopped = actual.shutdown(|event| observe(event, &reports, &mut failures.diagnostics));
        failures.report = stopped.report;
        failures.cleanup = stopped.failure;
        if !stopped.drained && failures.cleanup.is_none() {
            failures.cleanup = Some(gnunet_types::Error::NotReady.into());
        }
    }
    let closed = sources.close();
    let mut monitor_terminals: [Option<MonitorTerminal>; 2] = [None, None];
    let mut unexpected_terminal = false;
    for (index, event) in closed.peerstore_events.into_iter().enumerate() {
        monitor_terminals[index] = match event {
            Some(gnunet_peerstore_client_host::Progress::Completed {
                epoch,
                operation,
                kind,
                outcome,
            }) => Some(MonitorTerminal::Completed {
                epoch: epoch.map(|e| e.diagnostic()),
                operation: operation.diagnostic(),
                kind,
                outcome,
            }),
            Some(gnunet_peerstore_client_host::Progress::Lost {
                epoch,
                cause,
                monitor_retained,
            }) => Some(MonitorTerminal::Lost {
                epoch: epoch.map(|e| e.diagnostic()),
                cause,
                monitor_retained,
            }),
            Some(event) => {
                unexpected_terminal = true;
                source_notice(
                    discovery::Event::Peerstore {
                        event,
                        retired_credit: closed.retired_credit,
                    },
                    &reports,
                    &mut failures.diagnostics,
                );
                None
            }
            None => None,
        };
    }
    failures.source_close_facts = Some(SourceCloseFacts {
        core_closed: closed.core.as_ref().is_ok_and(Option::is_some),
        peerstore_closed: closed.peerstore.as_ref().is_ok_and(Option::is_some),
        peerstore_terminals: monitor_terminals,
        peerstore_pending: closed.peerstore_pending,
        peerstore_idle: closed.peerstore_idle,
        nse_epoch: closed.nse.epoch.map(|e| e.value()),
        nse_start_bytes: closed.nse.start_bytes,
        nse_start_written: closed.nse.start_written,
        retired_credit: closed.retired_credit,
    });
    let closing = SourceClose {
        core: closed.core.err(),
        peerstore: closed.peerstore.err(),
        undrained: closed.peerstore_undrained,
        unexpected_terminal,
    };
    if closing.core.is_some()
        || closing.peerstore.is_some()
        || closing.undrained
        || closing.unexpected_terminal
    {
        failures.source_close = Some(Box::new(closing));
    }
    resolver.close();
    failures.resolver_close = cleanup.take_error();
    failures.output = {
        let mut output = io::stdout().lock();
        writeln!(
            output,
            "STOPPED rps local={:?} sources={:?}",
            failures.report, failures.source_close_facts
        )
        .and_then(|()| output.flush())
        .err()
    };
    reports.debug(
        "rps.stopped",
        format_args!(
            "RPS actual stop={:?} reason={:?} observations={:?}",
            failures.report, failures.reason, failures.diagnostics
        ),
    );
    failures.logging = reports.take_error();
    if failures.failed() {
        Err(Box::new(failures))
    } else {
        Ok(())
    }
}

#[derive(Debug)]
struct SourceClose {
    core: Option<gnunet_core_client_host::Error>,
    peerstore: Option<gnunet_peerstore_client_host::Error>,
    undrained: bool,
    unexpected_terminal: bool,
}
impl fmt::Display for SourceClose {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            out,
            "RPS independent native-source close: core={:?}; peerstore={:?}; undrained={}; unexpected_terminal={}",
            self.core, self.peerstore, self.undrained, self.unexpected_terminal
        )
    }
}
impl Error for SourceClose {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.core
            .as_ref()
            .map(|e| e as &dyn Error)
            .or_else(|| self.peerstore.as_ref().map(|e| e as &dyn Error))
    }
}
enum MonitorTerminal {
    Completed {
        epoch: Option<u64>,
        operation: u64,
        kind: gnunet_peerstore_client_host::Kind,
        outcome: gnunet_peerstore_client_host::Outcome,
    },
    Lost {
        epoch: Option<u64>,
        cause: gnunet_peerstore_client_host::LossCause,
        monitor_retained: bool,
    },
}
impl fmt::Debug for MonitorTerminal {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Completed {
                epoch,
                operation,
                kind,
                outcome,
            } => out
                .debug_struct("Completed")
                .field("epoch", epoch)
                .field("operation", operation)
                .field("kind", kind)
                .field("outcome", outcome)
                .finish(),
            Self::Lost {
                epoch,
                cause,
                monitor_retained,
            } => out
                .debug_struct("Lost")
                .field("epoch", epoch)
                .field("cause", cause)
                .field("monitor_retained", monitor_retained)
                .finish(),
        }
    }
}
struct SourceCloseFacts {
    core_closed: bool,
    peerstore_closed: bool,
    peerstore_terminals: [Option<MonitorTerminal>; 2],
    peerstore_pending: usize,
    peerstore_idle: bool,
    nse_epoch: Option<u64>,
    nse_start_bytes: usize,
    nse_start_written: bool,
    retired_credit: bool,
}
impl fmt::Debug for SourceCloseFacts {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("SourceCloseFacts")
            .field("core_closed", &self.core_closed)
            .field("peerstore_closed", &self.peerstore_closed)
            .field("peerstore_terminals", &self.peerstore_terminals)
            .field("peerstore_pending", &self.peerstore_pending)
            .field("peerstore_idle", &self.peerstore_idle)
            .field("nse_epoch", &self.nse_epoch)
            .field("nse_start_bytes", &self.nse_start_bytes)
            .field("nse_start_written", &self.nse_start_written)
            .field("retired_credit", &self.retired_credit)
            .finish()
    }
}

fn source_event<'id>(
    event: discovery::Event<'_>,
    local: [u8; 32],
    server: &mut Server<'id, '_>,
    settings: &Settings,
    reports: &Reporter,
    diagnostics: &mut Diagnostics,
) -> Result<(), Cause> {
    match event {
        discovery::Event::Core(gnunet_core_client_host::Progress::Unavailable(error)) => {
            return Err(Box::new(error));
        }
        discovery::Event::Peerstore {
            event: gnunet_peerstore_client_host::Progress::Unavailable(error),
            ..
        } => return Err(Box::new(error)),
        discovery::Event::Nse(gnunet_nse_client_host::Progress::Unavailable(error)) => {
            return Err(Box::new(error));
        }
        discovery::Event::Core(gnunet_core_client_host::Progress::Capacity(_))
        | discovery::Event::Peerstore {
            event: gnunet_peerstore_client_host::Progress::Capacity(_),
            ..
        } => return Err(Box::new(gnunet_types::Error::Capacity)),
        discovery::Event::Core(gnunet_core_client_host::Progress::Closed)
        | discovery::Event::Peerstore {
            event: gnunet_peerstore_client_host::Progress::Closed,
            ..
        }
        | discovery::Event::Nse(gnunet_nse_client_host::Progress::Stopped { .. }) => {
            return Err("RPS native discovery source permanently closed".into());
        }
        discovery::Event::Identity {
            epoch,
            peer,
            previous,
        } => {
            if peer != local || previous.is_some_and(|p| p != local) {
                return Err(
                    "RPS actual CORE identity changed; original RPS owner must restart".into(),
                );
            }
            reports.debug(
                "rps.core.ready",
                format_args!(
                    "RPS original local identity reobserved on actual CORE source={epoch:?}"
                ),
            );
        }
        discovery::Event::PeerHint { peer, source } => {
            // These are discovery facts only. The actual CADET group/channel
            // probe is the only path to peer qualification in the RPS core.
            match source {
                discovery::Hint::Core { epoch, peer } => reports.debug(
                    "rps.discovery.core",
                    format_args!("RPS original CORE hint source={:?} peer={:?}", epoch, peer),
                ),
                discovery::Hint::Peerstore {
                    epoch,
                    operation,
                    phase,
                } => reports.debug(
                    "rps.discovery.cache",
                    format_args!(
                        "RPS original opaque cache hint source={:?} operation={:?} phase={:?}",
                        epoch, operation, phase
                    ),
                ),
            }
            match server.discover_main(peer) {
                Ok(()) => {}
                Err(server::Error::Protocol(
                    gnunet_types::Error::Capacity
                    | gnunet_types::Error::WouldBlock
                    | gnunet_types::Error::NotReady,
                )) => {
                    // A bounded hint can be refused without inventing a peer
                    // response, client acknowledgement or sampler observation.
                    reports.debug("rps.discovery.refused", format_args!("RPS discovery hint was refused by its current resource/retirement bounds"));
                }
                Err(error) => return Err(Box::new(error)),
            }
        }
        discovery::Event::Estimate(observation) => {
            let log2 = observation.estimate.log2_size.value();
            if log2.is_finite() {
                let minimum = settings.core.view_size;
                let maximum = settings
                    .limits
                    .view
                    .min(settings.limits.sampler)
                    .min(settings.native.channels)
                    .max(minimum);
                // Clamp the exponent before exp2: an observed extreme or NaN
                // deviation is never promoted to an infinite allocation target.
                let exponent = (log2 / 3.0).clamp(0.0, (maximum as f64).log2());
                let target = (exponent.exp2().ceil() as usize).clamp(minimum, maximum);
                match server.resize_all(target, target) {
                    Ok(()) => {}
                    Err(server::Error::Protocol(
                        gnunet_types::Error::Capacity
                        | gnunet_types::Error::WouldBlock
                        | gnunet_types::Error::NotReady,
                    )) => {
                        reports.debug(
                            "rps.nse.resize.refused",
                            format_args!(
                                "RPS bounded NSE-derived size target {target} was not applied"
                            ),
                        );
                    }
                    Err(error) => return Err(Box::new(error)),
                }
            } else {
                reports.debug("rps.nse.nonfinite", format_args!("RPS retained the original non-finite NSE observation without changing size targets"));
            }
        }
        other => source_notice(other, reports, diagnostics),
    }
    Ok(())
}
fn source_notice(event: discovery::Event<'_>, reports: &Reporter, diagnostics: &mut Diagnostics) {
    diagnostics.source_events = diagnostics.source_events.saturating_add(1);
    use gnunet_core_client_host::Progress as Core;
    use gnunet_nse_client_host::Progress as Nse;
    use gnunet_peerstore_client_host::Progress as Peerstore;
    match event {
        discovery::Event::Core(Core::Lost { cause, .. }) => reports.warning("rps.core.source.lost", format_args!("RPS original CORE discovery source lost: {cause:?}")),
        discovery::Event::Core(Core::ConnectRetry { error, retry_after }) => reports.warning("rps.core.retry", format_args!("RPS CORE retry after {retry_after:?}: {error}")),
        discovery::Event::Core(Core::Unavailable(error)) => reports.warning("rps.core.unavailable", format_args!("RPS CORE source unavailable: {error}")),
        discovery::Event::Peerstore { event: Peerstore::Lost { cause, .. }, retired_credit } => reports.warning("rps.peerstore.source.lost", format_args!("RPS original peerstore discovery source lost: {cause:?}; old grant retired={retired_credit}")),
        discovery::Event::Peerstore { event: Peerstore::ConnectRetry { error, retry_after }, .. } => reports.warning("rps.peerstore.retry", format_args!("RPS peerstore retry after {retry_after:?}: {error}")),
        discovery::Event::Peerstore { event: Peerstore::Unavailable(error), .. } => reports.warning("rps.peerstore.unavailable", format_args!("RPS peerstore source unavailable: {error}")),
        discovery::Event::Nse(Nse::Lost { cause, .. }) => reports.warning("rps.nse.source.lost", format_args!("RPS original NSE source lost: {cause:?}")),
        discovery::Event::Nse(Nse::Retry { error, delay }) => reports.warning("rps.nse.retry", format_args!("RPS NSE retry after {delay:?}: {error}")),
        discovery::Event::Nse(Nse::Unavailable(error)) => reports.warning("rps.nse.unavailable", format_args!("RPS NSE source unavailable: {error}")),
        discovery::Event::CreditRefused { epoch, operation, error } => reports.warning("rps.peerstore.credit.refused", format_args!("RPS original peerstore grant remains owed on {epoch:?}/{operation:?}: {error}")),
        discovery::Event::MonitorStarted { operation, expires } => reports.debug("rps.peerstore.intent", format_args!("RPS original monitor intent {operation:?} until {expires}; no service acknowledgement")),
        _ => {}
    }
}
