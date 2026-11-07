//! Original SETI/CADET owners under explicit standard SERVICE startup.
use crate::{
    control::Signals,
    lifecycle::{Cleanup, Resolver},
    settings::{Settings, bytes, filled},
};
use gnunet_cadet_host::{self as cadet, EndpointSource};
use gnunet_config::Configuration;
use gnunet_crypto::Entropy;
use gnunet_program_host::{policy::Level, reporting::Reporter, shared_clock::SharedClock};
use gnunet_resolver_broker::{LiveConfiguration, broker, native_profile};
use gnunet_service_runtime::{
    BoundListeners, accepted::SocketEvent, clock::RuntimeClock, service::ShutdownMode,
};
use gnunet_service_startup::{ParentControl, daemon::ChildReady};
use gnunet_seti as core;
use gnunet_seti_host::{CloseCause, Error as NativeError, Event, Progress, Server};
use gnunet_types::Error as ProtocolError;
use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io::{self, Write},
    sync::Arc,
    task::Poll,
};
use tokio::time::Instant;
type Cause = Box<dyn Error>;
#[derive(Default)]
struct Random {
    first: Option<getrandom::Error>,
}
impl Entropy for Random {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), ProtocolError> {
        match getrandom::fill(bytes) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.first.get_or_insert(error);
                Err(ProtocolError::Entropy)
            }
        }
    }
}
#[derive(Debug)]
struct EntropyFailure(getrandom::Error);
impl fmt::Display for EntropyFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "original entropy source: {}", self.0)
    }
}
impl Error for EntropyFailure {}
struct Backing {
    members: Vec<u8>,
    active: Vec<u8>,
    reported: Vec<u8>,
    bloom: Vec<u8>,
    context: Vec<u8>,
}
/// Diagnostic values from an original physically retired source, not a receipt.
#[derive(Clone, Copy)]
struct BackendLoss {
    epoch: u64,
    channels: usize,
    pending: Option<(u64, cadet::TransmitKind, bool)>,
}
impl From<cadet::Loss<'_>> for BackendLoss {
    fn from(original: cadet::Loss<'_>) -> Self {
        Self {
            epoch: original.epoch.value(),
            channels: original.channels,
            pending: original
                .pending
                .map(|p| (p.transmit.value(), p.transmit.kind(), p.exposed)),
        }
    }
}
impl fmt::Debug for BackendLoss {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackendLoss")
            .field("epoch", &self.epoch)
            .field("channels", &self.channels)
            .field("pending", &self.pending)
            .finish()
    }
}
/// One actual first cause per independent diagnostic class; no per-peer arrays.
#[derive(Default)]
struct Observations {
    socket: Option<SocketEvent>,
    admission: Option<NativeError>,
    client: Option<CloseCause>,
    backend: Option<cadet::LossCause>,
    retry: Option<io::Error>,
    lost: Option<BackendLoss>,
}
impl fmt::Debug for Observations {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Observations")
            .field("socket", &self.socket)
            .field("admission", &self.admission)
            .field("client", &self.client)
            .field("backend", &self.backend)
            .field("retry", &self.retry)
            .field("lost", &self.lost)
            .finish()
    }
}
impl Observations {
    fn observe(&mut self, event: Event<'_, '_>, reports: &Reporter) {
        match event {
            Event::Socket(SocketEvent::Failed(error)) if error.is_emfile() => {}
            Event::Socket(SocketEvent::Failed(error)) => {
                reports.warning("seti.socket.failed", format_args!("SETI socket: {error:?}"));
                self.socket.get_or_insert(SocketEvent::Failed(error));
            }
            Event::Socket(event) => reports.debug("seti.socket.activity", format_args!("SETI socket: {event:?}")),
            Event::Rejected(peer) => reports.warning("seti.client.rejected", format_args!("SETI rejected: {peer:?}")),
            Event::AdmissionFailed(error) => {
                reports.warning("seti.client.admission", format_args!("SETI unadmitted source already closed: {error}"));
                self.admission.get_or_insert(error);
            }
            Event::Closed { loss, cause } => {
                let failed = matches!(&cause, CloseCause::Fault(_));
                let (level, site) = if failed { (Level::WARNING, "seti.client.failed") } else { (Level::DEBUG, "seti.client.closed") };
                reports.message(level, site, format_args!("SETI client={} pending={:?} queued={} exposed={} operations={} port={:?} cause={cause:?}",loss.client.value(),loss.pending,loss.queued,loss.exposed,loss.operations,loss.port));
                if failed { self.client.get_or_insert(cause); }
            }
            Event::BackendConnected(epoch) => reports.debug("seti.backend.connected", format_args!("actual SETI CADET epoch={}",epoch.value())),
            Event::BackendLost { report, cause } => {
                if matches!(&cause, cadet::LossCause::Requested) {
                    reports.debug("seti.backend.closed", format_args!("original SETI CADET retired={report:?} cause={cause:?}"));
                } else {
                    reports.warning("seti.backend.lost", format_args!("original SETI CADET retired={report:?} cause={cause:?}; exposed-data-replayed=false"));
                    self.backend.get_or_insert(cause);
                    self.lost.get_or_insert_with(|| report.into());
                }
            }
            Event::BackendRetry { error, retry_after } => {
                reports.warning("seti.backend.retry", format_args!("SETI CADET retry={retry_after:?} actual={error}"));
                self.retry.get_or_insert(error);
            }
            Event::PeerLost(loss) => {
                let (level, site) = if loss.expected { (Level::DEBUG, "seti.peer.closed") } else { (Level::WARNING, "seti.peer.lost") };
                reports.message(level, site, format_args!("SETI peer={} pending={:?} queued={} exposed={} delivery={:?} expected={} reason={}",loss.source.operation().value(),loss.pending,loss.queued,loss.exposed,loss.delivery,loss.expected,loss.reason));
            }
            Event::PeerRefused { channel, reason } => reports.warning("seti.peer.refused",format_args!("SETI bounded/protocol refusal channel={channel:?} reason={reason}")),
            Event::RetiredWrite { transmit, effect, complete } => reports.debug("seti.retired.write",format_args!("original SETI retired-channel write tx={transmit:?} effect={effect:?} complete={complete}; no-new-operation-progress=true")),
            _ => {}
        }
    }
}
struct Failed {
    original: Option<Cause>,
    cleanup: Option<NativeError>,
    resolver: Option<Cause>,
    output: Option<io::Error>,
    entropy: Option<EntropyFailure>,
    logging: Option<io::Error>,
    report: gnunet_seti_host::Report,
    backend: Option<BackendLoss>,
    retained: usize,
    observations: Observations,
}
impl fmt::Debug for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SETI failures")
            .field("original", &self.original)
            .field("cleanup", &self.cleanup)
            .field("resolver", &self.resolver)
            .field("output", &self.output)
            .field("entropy", &self.entropy)
            .field("logging", &self.logging)
            .field("report", &self.report)
            .field("backend", &self.backend)
            .field("retained", &self.retained)
            .field("observations", &self.observations)
            .finish()
    }
}
impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SETI actual original lifecycle: {self:?}")
    }
}
impl Error for Failed {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or(self.cleanup.as_ref().map(|e| e as _))
            .or(self.resolver.as_deref())
            .or(self.output.as_ref().map(|e| e as _))
            .or(self.entropy.as_ref().map(|e| e as _))
            .or(self.logging.as_ref().map(|e| e as _))
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
#[expect(
    clippy::too_many_lines,
    reason = "One lexical scope retains actual branded SETI/CADET slots and the same Server through unconditional physical close; protocol allocation construction is unchanged"
)]
pub(super) async fn run(input: Inputs<'_>) -> Result<(), Cause> {
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
    let early_stop = poll_fn(|cx| {
        reports.register(cx);
        Poll::Ready(match signals.poll(cx) {
            Poll::Ready(result) => result.map(|()| true),
            Poll::Pending => Ok(false),
        })
    })
    .await?;
    if early_stop {
        return Ok(());
    }
    let clock: Arc<dyn RuntimeClock> = Arc::new(shared_clock.clone());
    let live = LiveConfiguration::new(config.duplicate()?);
    let (context, original_resolver) = broker::<16, 256>(
        live.clone(),
        Default::default(),
        native_profile()?,
        clock.clone(),
    )?;
    let mut resolver = Resolver::new(original_resolver, cleanup.clone());
    let mut instance = core::Instance::new();
    let mut clients = filled(settings.native.clients, core::ClientSlot::new)?;
    let mut sets = filled(settings.sets, core::SetSlot::new)?;
    let mut listeners = filled(settings.native.listeners, core::ListenerSlot::new)?;
    let count = settings
        .element_slots
        .checked_add(settings.large_slots)
        .ok_or("element capacity overflow")?;
    let mut values = Vec::new();
    values.try_reserve_exact(count)?;
    for _ in 0..settings.element_slots {
        values.push(bytes(settings.element_bytes)?);
    }
    for _ in 0..settings.large_slots {
        values.push(bytes(settings.large_bytes)?);
    }
    let mut elements = Vec::new();
    elements.try_reserve_exact(count)?;
    for value in &mut values {
        elements.push(core::ElementSlot::new(value));
    }
    let bitmap = count.checked_add(7).ok_or("bitmap overflow")? / 8;
    let mut backing = Vec::new();
    backing.try_reserve_exact(settings.native.operations)?;
    for _ in 0..settings.native.operations {
        backing.push(Backing {
            members: bytes(bitmap)?,
            active: bytes(bitmap)?,
            reported: bytes(bitmap)?,
            bloom: bytes(settings.core.bloom_bytes)?,
            context: bytes(settings.context_bytes)?,
        });
    }
    let mut operations = Vec::new();
    operations.try_reserve_exact(settings.native.operations)?;
    for b in &mut backing {
        operations.push(core::OperationSlot::new(
            &mut b.members,
            &mut b.active,
            &mut b.reported,
            &mut b.bloom,
            &mut b.context,
        ));
    }
    let service = core::Service::new(
        &mut instance,
        &mut clients,
        &mut sets,
        &mut listeners,
        &mut elements,
        &mut operations,
        settings.core,
    )?;
    let mut cadet_domain = cadet::Instance::new();
    let mut ports = filled(settings.native.listeners, cadet::PortSlot::new)?;
    let mut channels = filled(settings.native.operations, cadet::ChannelSlot::new)?;
    let backend = cadet::Client::new(
        &mut cadet_domain,
        EndpointSource::live(live, b"cadet", context.resolution_context()),
        &mut ports,
        &mut channels,
        cadet::Limits {
            io_slice_bytes: settings.native.io_slice_bytes,
            ..cadet::Limits::default()
        },
    )?;
    let mut server = Server::new(
        service,
        backend,
        settings.native,
        settings.options.clone(),
        settings.unix,
    )?;
    let mut random = Random::default();
    let mut observations = Observations::default();
    // Every return after Server construction goes through this finally owner.
    let outcome: Result<(), Cause> = async {
        let startup_at = Instant::now()
            .checked_add(settings.startup_timeout)
            .ok_or("startup deadline overflow")?;
        let mut startup_alarm = std::pin::pin!(tokio::time::sleep_until(startup_at));
        let mut attached = false;
        loop {
            let selected = {
                let observing = |event| {
                    if matches!(&event, Event::BackendConnected(_)) {
                        attached = true;
                    }
                    observations.observe(event, &reports);
                };
                let mut connecting = std::pin::pin!(server.drive(
                    &[], &mut random, Some(startup_at), observing
                ));
                poll_fn(|cx| {
                    // Register the original native alarm before canonical or
                    // Resolver work. A ready class never rebuilds this target.
                    if startup_alarm.as_mut().poll(cx).is_ready()
                        || Instant::now() >= startup_at
                    {
                        return Poll::Ready(Err(Box::new(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "original SETI CADET attachment deadline",
                        )) as Cause));
                    }
                    reports.register(cx);
                    if reports.failed() {
                        return Poll::Ready(Ok(None));
                    }
                    if let Poll::Ready(signal) = signals.poll(cx) {
                        return Poll::Ready(signal
                            .map(|()| None)
                            .map_err(|error| Box::new(error) as Cause));
                    }
                    match resolver.poll(cx, &reports, Some(startup_at)) {
                        Poll::Ready(Err(error)) => {
                            return Poll::Ready(Err(Box::new(error) as Cause));
                        }
                        Poll::Ready(Ok(_)) => cx.waker().wake_by_ref(),
                        Poll::Pending => {}
                    }
                    // A diagnostic callback can fail while its future yields.
                    if reports.failed() {
                        return Poll::Ready(Ok(None));
                    }
                    connecting.as_mut().poll(cx).map(|result| {
                        result.map(Some).map_err(|error| Box::new(error) as Cause)
                    })
                })
                .await
            };
            match selected {
                Err(error) => return Err(error),
                Ok(None) => {
                    return Err("SETI stopped before actual CADET attachment".into());
                }
                Ok(Some(Progress::WaitDeadline)) => {
                    return Err("actual SETI CADET attachment deadline expired".into());
                }
                Ok(Some(Progress::Stopped)) => {
                    return Err("SETI stopped during actual CADET attachment".into());
                }
                Ok(Some(Progress::Activity)) => {}
            }
            if reports.failed() {
                return Ok(());
            }
            if attached {
                break;
            }
            tokio::task::yield_now().await;
        }
        // Recheck the installed stop stream after construction: no readiness
        // byte is emitted for an original request already queued at this point.
        if poll_fn(|cx| {
            reports.register(cx);
            if reports.failed() {
                return Poll::Ready(Ok(true));
            }
            Poll::Ready(match signals.poll(cx) {
                Poll::Ready(result) => result.map(|()| true),
                Poll::Pending => Ok(false),
            })
        })
        .await?
        {
            return Ok(());
        }
        {
            let mut out = io::stdout().lock();
            writeln!(out,
                "READY seti wire=0.29.1 backend=cadet-client-attached protocol=bloom result-layout=native{} hidden-tasks=0",
                gnunet_seti::Limits::default().result_layout.prefix()
            )?;
            out.flush()?;
        }
        child.ready()?;
        let listeners = bound.listeners();
        let mut stop_at = None;
        let mut stop_alarm: Option<std::pin::Pin<Box<tokio::time::Sleep>>> = None;
        loop {
            let selected = {
                let mut observing = |event| observations.observe(event, &reports);
                let mut driving = std::pin::pin!(server.drive(
                    &listeners, &mut random, stop_at, &mut observing
                ));
                poll_fn(|cx| {
                    if let Some(alarm) = &mut stop_alarm
                        && (alarm.as_mut().poll(cx).is_ready()
                            || stop_at.is_some_and(|hard| Instant::now() >= hard))
                    {
                        return Poll::Ready(Ok(Some(Progress::WaitDeadline)));
                    }
                    reports.register(cx);
                    // A permanent diagnostic failure requests stop once. It
                    // cannot repeatedly return Ready and hide old cleanup work.
                    if reports.failed() && stop_at.is_none() {
                        return Poll::Ready(Ok(None));
                    }
                    if !reports.failed()
                        && let Poll::Ready(signal) = signals.poll(cx)
                    {
                        return Poll::Ready(signal
                            .map(|()| None)
                            .map_err(|error| Box::new(error) as Cause));
                    }
                    if !reports.failed() {
                        match resolver.poll(cx, &reports, stop_at) {
                            Poll::Ready(Err(error)) => {
                                return Poll::Ready(Err(Box::new(error) as Cause));
                            }
                            Poll::Ready(Ok(_)) => cx.waker().wake_by_ref(),
                            Poll::Pending => {}
                        }
                    }
                    if reports.failed() {
                        // No new Resolver IO after a failed diagnostic, even
                        // when the original soft grace had already started.
                        resolver.close();
                        if stop_at.is_none() {
                            return Poll::Ready(Ok(None));
                        }
                    }
                    driving.as_mut().poll(cx).map(|result| {
                        result.map(Some).map_err(|error| Box::new(error) as Cause)
                    })
                })
                .await
            };
            match selected {
                Ok(None)
                    if stop_at.is_none()
                        && settings.options.shutdown == ShutdownMode::Soft =>
                {
                    server.request_shutdown(ShutdownMode::Soft);
                    let hard = Instant::now()
                        .checked_add(settings.shutdown_grace)
                        .ok_or("shutdown grace overflow")?;
                    stop_at = Some(hard);
                    stop_alarm = Some(Box::pin(tokio::time::sleep_until(hard)));
                    if reports.failed() {
                        resolver.close();
                    }
                }
                Ok(None | Some(Progress::Stopped | Progress::WaitDeadline)) => break,
                Ok(Some(Progress::Activity)) => {}
                Err(error) => return Err(error),
            }
            tokio::task::yield_now().await;
        }
        Ok(())
    }
    .await;
    let mut observing = |event| observations.observe(event, &reports);
    let stopped = server.close(&mut observing);
    resolver.close();
    let resolver_error = cleanup.take_error();
    let original = outcome.err();
    let entropy = random.first.take().map(EntropyFailure);
    let backend = stopped.backend.map(BackendLoss::from);
    let diagnostic = {
        let mut out = io::stdout().lock();
        writeln!(out,"STOPPED seti local={:?} backend={backend:?} retained={} cleanup={:?} resolver={resolver_error:?} remote-drain=not-claimed",stopped.report,stopped.retained,stopped.failure).and_then(|()|out.flush())
    };
    let output = diagnostic.err();
    reports.debug("seti.stopped",format_args!("actual SETI local={:?} backend={backend:?} retained={} source-diagnostics={observations:?}; remote-drain=not-claimed",stopped.report,stopped.retained));
    // Keep the original typed terminal report even when only diagnostics failed.
    // take_error consumes the owned IO cause, never the permanent failed latch.
    let logging = reports.take_error();
    if original.is_some()
        || stopped.failure.is_some()
        || resolver_error.is_some()
        || output.is_some()
        || entropy.is_some()
        || logging.is_some()
    {
        return Err(Box::new(Failed {
            original,
            cleanup: stopped.failure,
            resolver: resolver_error,
            output,
            entropy,
            logging,
            report: stopped.report,
            backend,
            retained: stopped.retained,
            observations,
        }));
    }
    Ok(())
}
