//! Standard SERVICE lifecycle over the same original SETU/CADET owners.
use crate::{
    Cause,
    control::Signals,
    lifecycle::{Cleanup, Resolver},
    settings::Settings,
};
use gnunet_client_host::EndpointSource;
use gnunet_config::Configuration;
use gnunet_program_host::{reporting::Reporter, shared_clock::SharedClock};
use gnunet_resolver_broker::{LiveConfiguration, broker, native_profile};
use gnunet_service_runtime::{BoundListeners, clock::RuntimeClock, service::ShutdownMode};
use gnunet_service_startup::{ParentControl, daemon::ChildReady};
use gnunet_setu_host::server::{self, CloseCause, Event, Progress, Server};
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
                "setu.admission.failed",
                format_args!("SETU admission: {error}"),
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
                "setu.app.failed",
                format_args!("SETU original app {client:?}: {error}"),
            );
            if diagnostics.first_app_fault.is_none() {
                diagnostics.first_app_fault = Some(error);
            }
        }
        Event::CadetLost { report, cause } => {
            reports.warning(
                "setu.cadet.lost",
                format_args!("SETU original CADET retirement={report:?}: {cause:?}"),
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
                "setu.cadet.retry",
                format_args!("SETU original CADET retry after {retry_after:?}: {error}"),
            );
            diagnostics.retries = diagnostics.retries.saturating_add(1);
            if diagnostics.first_retry.is_none() {
                diagnostics.first_retry = Some(error);
            }
        }
        Event::Accepted(_) | Event::Input(_) | Event::Queued(_) | Event::Write { .. } => {}
        other => reports.debug("setu.activity", format_args!("SETU actual event={other:?}")),
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
        write!(f, "SETU original lifecycle={self:?}")
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
            .ok_or("SETU original shutdown target overflow")?;
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
    let source = EndpointSource::live(live, b"cadet", context.resolution_context());
    let mut instance = gnunet_cadet_host::Instance::new();
    let mut ports = Vec::new();
    ports.try_reserve_exact(settings.native.ports)?;
    ports.resize_with(settings.native.ports, gnunet_cadet_host::PortSlot::new);
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
    let core = gnunet_setu::service::Service::new(settings.core, settings.abi)?;
    let mut server = Server::new(
        core,
        cadet,
        settings.native,
        settings.options.clone(),
        settings.access,
    )?;
    let listeners = bound.listeners();
    let mut failures = Failures::default();
    // Every fallible exit after ownership transfer reaches the same synchronous
    // shutdown below. No Drop or timer is used as its completion receipt.
    let outcome: Result<(), Cause> = async {
        if !Arc::ptr_eq(&server.clock(), &source_clock) {
            return Err("SETU actual source clock mismatch".into());
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
            writeln!(output, "READY setu wire=0.29.1 listeners=bound sets=memory")?;
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
                let mut driving =
                    std::pin::pin!(server.drive(&listeners, deadline, |event| observe(
                        event,
                        &reports,
                        &mut failures.diagnostics
                    )));
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
                    for offset in 0..2 {
                        if grace.as_ref().is_some_and(Grace::expired) {
                            return Poll::Ready(Ok(Turn::Expired));
                        }
                        // A pending Resolver callback can fail the logger. It
                        // must fence the following live Server poll this turn.
                        if reports.failed() {
                            return Poll::Ready(Ok(Turn::Stop));
                        }
                        if (usize::from(cursor) + offset) % 2 == 0 {
                            match resolver.poll(cx, &reports) {
                                Poll::Ready(Ok(_)) => activity = true,
                                Poll::Ready(Err(error)) => {
                                    failures.resolver = Some(error);
                                    return Poll::Ready(Ok(Turn::Failed));
                                }
                                Poll::Pending => {}
                            }
                        } else if let Poll::Ready(result) = driving.as_mut().poll(cx) {
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
                        server.request_shutdown(ShutdownMode::Soft);
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
    failures.original = outcome.err();
    // Actual physical retirement is independent of canonical sampling and may
    // run after source clock, Logger, Resolver, credit or partial IO failed.
    // SETU owns no index/storage worker or detached task to join.
    let stopped = server.shutdown(|event| observe(event, &reports, &mut failures.diagnostics));
    failures.report = stopped.report;
    failures.cleanup = stopped.failure;
    resolver.close();
    failures.resolver_close = cleanup.take_error();
    failures.output = {
        let mut output = io::stdout().lock();
        writeln!(output, "STOPPED setu local={:?}", failures.report)
            .and_then(|()| output.flush())
            .err()
    };
    reports.debug(
        "setu.stopped",
        format_args!(
            "SETU actual stop={:?} reason={:?} observations={:?}",
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
