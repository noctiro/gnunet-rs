//! Actual accepted MQ ownership and fair SETI/CADET service coordination.
mod peer;
use gnunet_cadet_host as cadet;
use gnunet_crypto::Entropy;
use gnunet_service_runtime::{
    accepted::{AcceptState, AcceptedConnection, SocketEvent},
    clock::{ClockSubscription, RuntimeClock},
    credentials::UnixAccess,
    framing::{Accounting, Budget, Class, Framed, Limits as FrameLimits, OwnedFrame, ReadStep},
    service::{Listener, PeerAddress, ServiceOptions, ShutdownMode},
};
use gnunet_seti::{self as core, Dispatch, Request};
use gnunet_types::Error as ProtocolError;
use std::{
    fmt,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
/// Original native or protocol failure.
#[derive(Debug)]
pub enum Error {
    /// Actual local socket failure.
    Io(io::Error),
    /// Actual CADET CLIENT/source-port failure.
    Cadet(cadet::Error),
    /// Pure protocol/resource classification.
    Protocol(ProtocolError),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => e.fmt(f),
            Self::Cadet(e) => e.fmt(f),
            Self::Protocol(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Cadet(e) => Some(e),
            Self::Protocol(e) => Some(e),
        }
    }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<ProtocolError> for Error {
    fn from(e: ProtocolError) -> Self {
        Self::Protocol(e)
    }
}
impl From<cadet::Error> for Error {
    fn from(e: cadet::Error) -> Self {
        Self::Cadet(e)
    }
}
/// Original reason for an actual accepted-source stop.
#[derive(Debug)]
pub enum CloseCause {
    /// Caller explicitly stops this physical MQ.
    Requested,
    /// Clean EOF between official frames.
    Eof,
    /// Original native or domain refusal.
    Fault(Error),
    /// Explicit service shutdown.
    Shutdown,
}
impl CloseCause {
    fn classification(&self) -> ProtocolError {
        match self {
            Self::Fault(Error::Protocol(e)) => *e,
            Self::Fault(Error::Io(_) | Error::Cadet(_)) => ProtocolError::Io,
            _ => ProtocolError::Closed,
        }
    }
}
/// Synchronous committed observations, delivered without callback reentry.
pub enum Event<'id, 'cadet> {
    /// Actual native accept/initialization diagnostic.
    Socket(SocketEvent),
    /// Original unadmitted stream refused by ACL/kernel credentials.
    Rejected(PeerAddress),
    /// Actual admitted local physical MQ.
    Accepted(core::Client<'id>),
    /// Official complete input accepted on its original source.
    Input(core::Client<'id>),
    /// Original immutable IPC result admitted.
    Queued(core::Effect<'id>),
    /// Original actual native IPC write.
    Write {
        /// Exact original result/suggestion.
        effect: core::Effect<'id>,
        /// Actual positive byte count.
        bytes: usize,
        /// Whole original frame physically wrote.
        complete: bool,
    },
    /// Actual local socket retired before logical detach.
    Closed {
        /// Original pending/exposure facts.
        loss: core::ClientLoss<'id>,
        /// Original independently retained cause.
        cause: CloseCause,
    },
    /// Already-closed unadmitted stream failed initialization/admission.
    AdmissionFailed(Error),
    /// Actual original CADET MQ attached; no end-to-end acceptance claim.
    BackendConnected(cadet::Epoch<'cadet>),
    /// Actual original shared CADET MQ stopped; no channel/payload replay.
    BackendLost {
        /// Original native loss including partial-write exposure.
        report: cadet::Loss<'cadet>,
        /// Actual independently retained native cause.
        cause: cadet::LossCause,
    },
    /// Actual backend connection attempt failed; its native owner chooses retry.
    BackendRetry {
        /// Original native cause.
        error: io::Error,
        /// Original retry policy.
        retry_after: Duration,
    },
    /// Original SETI application frame actually admitted on the original CADET
    /// MQ. This grants no remote delivery or protocol-completion proof.
    PeerQueued {
        /// Original SETI immutable effect.
        effect: core::Effect<'id>,
        /// Original native transmit, including actual MQ generation.
        transmit: cadet::Transmit<'cadet>,
    },
    /// Actual CADET frame completely wrote; this is not peer receipt.
    PeerWritten(cadet::Transmit<'cadet>),
    /// Positive write on an original frame whose channel already retired. The
    /// immutable suffix still drains on its original MQ; no operation revives.
    RetiredWrite {
        /// Original native attempt.
        transmit: cadet::Transmit<'cadet>,
        /// Original SETI effect retained until actual physical settlement.
        effect: core::Effect<'id>,
        /// The complete original native frame wrote.
        complete: bool,
    },
    /// Exact original SETI channel retired after the actual CADET source stop.
    PeerLost(core::PeerLoss<'id>),
    /// Actual peer channel or source refused due to bounded/domain policy.
    PeerRefused {
        /// Original channel when known.
        channel: Option<cadet::Channel<'cadet>>,
        /// Actual reason; no success/ACK is invented.
        reason: ProtocolError,
    },
}
/// One bounded reactor result. Waiting cancellation preserves original IO.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// A real event or bounded CPU transition progressed.
    Activity,
    /// Observation deadline only; original owners remain live.
    WaitDeadline,
    /// All local MQs and all original channel mappings retired after shutdown.
    Stopped,
}
/// Explicit native metadata, syscall and source-retirement budgets.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Actual accepted MQ owner capacity.
    pub clients: usize,
    /// Logical listener-to-CADET port mapping capacity.
    pub listeners: usize,
    /// Live operation/channel mapping capacity, including rejected inbound slots.
    pub operations: usize,
    /// Complete original IPC result/request frame ceiling.
    pub frame_bytes: usize,
    /// Actual per-syscall prefix cap, nonzero.
    pub io_slice_bytes: usize,
    /// Optional finite per-operation policy; None follows C's unbounded operation.
    pub operation_lifetime: Option<Duration>,
    /// Original admitted CADET frame hard budget. Expiry actually detaches that
    /// shared MQ; it never calls written or assumes a partial suffix disappeared.
    pub send_timeout: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            clients: 16,
            listeners: 8,
            operations: 32,
            frame_bytes: 65535,
            io_slice_bytes: 65535,
            operation_lifetime: None,
            send_timeout: Duration::from_secs(30),
        }
    }
}
/// Actual local counters, without peer-application delivery claims.
#[derive(Clone, Copy, Debug, Default)]
pub struct Report {
    /// Actual admitted local MQs.
    pub accepted: u64,
    /// Actual stopped local MQs.
    pub closed: u64,
    /// Accepted complete official IPC requests.
    pub inputs: u64,
    /// Actual original IPC bytes written.
    pub written_bytes: u64,
    /// Actual original IPC frames written.
    pub written_frames: u64,
    /// Actual peer channels attached (including incoming).
    pub channels: u64,
    /// Actual completely written CADET DATA frames.
    pub peer_frames: u64,
    /// Actual original source losses.
    pub backend_losses: u64,
    /// Original immutable CADET attempts physically stopped for their hard limit.
    pub stalled: u64,
}
/// Actual cleanup report. Remote application drain is never inferred.
pub struct Close<'cadet> {
    /// Actual counters at cleanup.
    pub report: Report,
    /// Actual original backend stop report, absent only when already detached.
    pub backend: Option<cadet::Loss<'cadet>>,
    /// First independent cleanup error, after trying all physical sources.
    pub failure: Option<Error>,
    /// Original retained core metadata after cleanup; zero does not prove remote
    /// processing, only completion/retirement of this node's local ownership.
    pub retained: usize,
}
struct App<'id> {
    client: core::Client<'id>,
    io: Framed<core::Effect<'id>>,
    held: Option<(OwnedFrame, core::Effect<'id>)>,
    cursor: usize,
}
struct Listen<'id, 'cadet> {
    listener: core::Listener<'id>,
    port: Option<cadet::Port<'cadet>>,
    bound: Option<core::Port<'id>>,
    closing: bool,
}
struct Input<'id, 'cadet> {
    received: cadet::Received<'cadet>,
    offset: usize,
    end: usize,
    processing: Option<core::Delivery<'id>>,
}
struct Link<'id, 'cadet> {
    operation: Option<core::Operation<'id>>,
    channel: Option<cadet::Channel<'cadet>>,
    source: Option<core::PeerSource<'id>>,
    input: Option<Input<'id, 'cadet>>,
    close: bool,
    remote_closed: bool,
}
#[derive(Clone, Copy)]
enum Action<'id> {
    Auxiliary,
    Open(usize),
    PortOpen(usize),
    PortClose(usize),
    Data(core::Effect<'id>),
    RetiredData(core::Effect<'id>),
    Ack(usize),
    Destroy(usize),
}
struct Pending<'id, 'cadet> {
    transmit: cadet::Transmit<'cadet>,
    action: Action<'id>,
    expires: Instant,
}
struct Held<'id> {
    effect: core::Effect<'id>,
    bytes: OwnedFrame,
}
/// One caller-driven native service. Core and CADET storage have independent
/// lifetimes; moving this owner never builds self references or leaks contexts.
pub struct Server<'id, 'store, 'bytes, 'cadet, 'cstore> {
    core: core::Service<'id, 'store, 'bytes>,
    cadet: cadet::Client<'cadet, 'cstore>,
    apps: Vec<Option<App<'id>>>,
    listeners: Vec<Option<Listen<'id, 'cadet>>>,
    links: Vec<Option<Link<'id, 'cadet>>>,
    pending: Option<Pending<'id, 'cadet>>,
    held: Option<Held<'id>>,
    limits: Limits,
    options: ServiceOptions,
    unix: UnixAccess,
    accept: AcceptState,
    clock: Arc<dyn RuntimeClock>,
    subscription: Box<dyn ClockSubscription>,
    revision: u64,
    timer: Pin<Box<Sleep>>,
    shutdown: Option<ShutdownMode>,
    app_cursor: usize,
    link_cursor: usize,
    listener_cursor: usize,
    accept_cursor: usize,
    class: usize,
    retirement_cursor: u64,
    report: Report,
}
fn slots<T>(n: usize) -> Result<Vec<Option<T>>, ProtocolError> {
    let mut v = Vec::new();
    v.try_reserve_exact(n)
        .map_err(|_| ProtocolError::Capacity)?;
    v.resize_with(n, || None);
    Ok(v)
}
fn buffer(n: usize) -> Result<Vec<u8>, ProtocolError> {
    let mut v = Vec::new();
    v.try_reserve_exact(n)
        .map_err(|_| ProtocolError::Capacity)?;
    v.resize(n, 0);
    Ok(v)
}
impl<'id, 'store, 'bytes, 'cadet, 'cstore> Server<'id, 'store, 'bytes, 'cadet, 'cstore> {
    /// Construct bounded metadata only. The explicitly supplied actual CADET
    /// client is the only peer backend; its canonical clock is shared unchanged.
    pub fn new(
        core: core::Service<'id, 'store, 'bytes>,
        cadet: cadet::Client<'cadet, 'cstore>,
        limits: Limits,
        options: ServiceOptions,
        unix: UnixAccess,
    ) -> Result<Self, Error> {
        if limits.clients == 0
            || limits.operations == 0
            || limits.io_slice_bytes == 0
            || !(108..=65535).contains(&limits.frame_bytes)
            || limits.send_timeout.is_zero()
            || Instant::now().checked_add(limits.send_timeout).is_none()
            || limits
                .operation_lifetime
                .is_some_and(|d| d.is_zero() || d.as_micros() >= u128::from(u64::MAX))
        {
            return Err(ProtocolError::InvalidInput.into());
        }
        let clock = cadet.clock();
        let subscription = clock.subscribe()?;
        let revision = clock.sample()?.revision;
        Ok(Self {
            core,
            cadet,
            apps: slots(limits.clients)?,
            listeners: slots(limits.listeners)?,
            links: slots(limits.operations)?,
            pending: None,
            held: None,
            limits,
            options,
            unix,
            accept: AcceptState::default(),
            clock,
            subscription,
            revision,
            timer: Box::pin(tokio::time::sleep(Duration::ZERO)),
            shutdown: None,
            app_cursor: 0,
            link_cursor: 0,
            listener_cursor: 0,
            accept_cursor: 0,
            class: 0,
            retirement_cursor: 0,
            report: Report::default(),
        })
    }
    /// Actual immutable local counters.
    #[must_use]
    pub const fn report(&self) -> Report {
        self.report
    }
    /// Clone the canonical clock without creating another subscription.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    fn framing(&self) -> FrameLimits {
        FrameLimits {
            frame_bytes: self.limits.frame_bytes,
            ordinary: Budget {
                frames: 1,
                bytes: self.limits.frame_bytes,
            },
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: self.limits.io_slice_bytes,
        }
    }
    /// Admit one actual canonical stream after ACL and Unix kernel credentials.
    pub fn admit(
        &mut self,
        accepted: AcceptedConnection,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<Option<core::Client<'id>>, Error> {
        let (connection, address, diagnostics) = accepted.into_parts();
        for d in diagnostics {
            observe(Event::Socket(SocketEvent::Diagnostic(d)));
        }
        let allowed = match address {
            PeerAddress::Tcp(p) => self.options.access.allows(p.ip()),
            PeerAddress::Unix => self.unix.allows(&connection)?,
        };
        if !allowed {
            drop(connection);
            observe(Event::Rejected(address));
            return Ok(None);
        }
        if self.shutdown.is_some() {
            drop(connection);
            return Err(ProtocolError::Closed.into());
        }
        let index = self
            .apps
            .iter()
            .position(Option::is_none)
            .ok_or(ProtocolError::Capacity)?;
        let mut io = Framed::new(connection, self.framing())?;
        let client = match self.core.attach() {
            Ok(client) => client,
            Err(e) => {
                io.retire();
                return Err(e.into());
            }
        };
        self.apps[index] = Some(App {
            client,
            io,
            held: None,
            cursor: 0,
        });
        self.report.accepted = self.report.accepted.saturating_add(1);
        observe(Event::Accepted(client));
        Ok(Some(client))
    }
    fn stop(
        &mut self,
        index: usize,
        cause: CloseCause,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<core::ClientLoss<'id>, Error> {
        let mut app = self.apps[index]
            .take()
            .ok_or(ProtocolError::StaleGeneration)?;
        app.io.retire();
        drop(app.held.take());
        self.accept.client_closed();
        let loss = self.core.detach(app.client, cause.classification())?;
        self.report.closed = self.report.closed.saturating_add(1);
        observe(Event::Closed { loss, cause });
        Ok(loss)
    }
    /// Actual physical stop before logical detach. Does not require a clock.
    pub fn close_client(
        &mut self,
        client: core::Client<'id>,
        cause: CloseCause,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<core::ClientLoss<'id>, Error> {
        let index = self
            .apps
            .iter()
            .position(|a| a.as_ref().is_some_and(|a| a.client == client))
            .ok_or(ProtocolError::StaleGeneration)?;
        self.stop(index, cause, observe)
    }
    /// Stop admission. Soft preserves original clients until their actual close;
    /// caller must enforce its finite grace and call close() at the hard limit.
    pub fn request_shutdown(&mut self, mode: ShutdownMode) {
        if self.shutdown != Some(ShutdownMode::Immediate) {
            self.shutdown = Some(mode);
        }
    }
    fn app_input(
        &mut self,
        index: usize,
        now: u64,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<bool, Error> {
        let app = self.apps[index]
            .as_mut()
            .ok_or(ProtocolError::StaleGeneration)?;
        let Some(bytes) = app.io.frame() else {
            return Ok(false);
        };
        let result = (|| {
            let request = Request::decode(bytes)?;
            if matches!(request, Request::Evaluate { .. }) && self.links.iter().all(Option::is_some)
            {
                return Err(ProtocolError::Capacity);
            }
            if matches!(request, Request::Listen { .. })
                && self.listeners.iter().all(Option::is_some)
            {
                return Err(ProtocolError::Capacity);
            }
            let deadline = match self.limits.operation_lifetime {
                Some(d) => now
                    .checked_add(u64::try_from(d.as_micros()).map_err(|_| ProtocolError::Overflow)?)
                    .ok_or(ProtocolError::Overflow)?,
                None => u64::MAX,
            };
            self.core.dispatch(app.client, request, deadline)
        })();
        match result {
            Ok(Dispatch::Listening(listener)) => {
                let slot = self
                    .listeners
                    .iter_mut()
                    .find(|l| l.is_none())
                    .ok_or(ProtocolError::Capacity)?;
                *slot = Some(Listen {
                    listener,
                    port: None,
                    bound: None,
                    closing: false,
                });
            }
            Ok(Dispatch::Operation(operation)) => {
                if self.core.operation_info(operation)?.phase == core::Phase::Opening {
                    let slot = self
                        .links
                        .iter_mut()
                        .find(|l| l.is_none())
                        .ok_or(ProtocolError::Capacity)?;
                    *slot = Some(Link {
                        operation: Some(operation),
                        channel: None,
                        source: None,
                        input: None,
                        close: false,
                        remote_closed: false,
                    });
                }
            }
            Ok(_) => {}
            Err(ProtocolError::Unsupported) if self.options.tolerant => {}
            Err(e) => {
                self.stop(index, CloseCause::Fault(e.into()), observe)?;
                return Ok(true);
            }
        }
        let app = self.apps[index]
            .as_mut()
            .ok_or(ProtocolError::StaleGeneration)?;
        app.io.release_frame();
        self.report.inputs = self.report.inputs.saturating_add(1);
        observe(Event::Input(app.client));
        Ok(true)
    }
    fn app_output(
        &mut self,
        index: usize,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<bool, Error> {
        let app = self.apps[index]
            .as_mut()
            .ok_or(ProtocolError::StaleGeneration)?;
        if app.io.queued_frames() != 0 {
            return Ok(false);
        }
        if app.held.is_none() {
            if !self.core.client_output_ready(app.client)? {
                return Ok(false);
            }
            let mut bytes = match buffer(self.limits.frame_bytes) {
                Ok(bytes) => bytes,
                Err(e) => {
                    self.stop(index, CloseCause::Fault(e.into()), observe)?;
                    return Ok(true);
                }
            };
            let prepared = match self.core.prepare_client(app.client, &mut bytes) {
                Ok(Some(p)) => p,
                Ok(None) => return Ok(false),
                Err(e) => {
                    self.stop(index, CloseCause::Fault(e.into()), observe)?;
                    return Ok(true);
                }
            };
            let effect = prepared.effect;
            let len = prepared.bytes.len();
            bytes.truncate(len);
            app.held = Some((OwnedFrame::new(bytes), effect));
        }
        let (frame, effect) = app.held.take().ok_or(ProtocolError::NotReady)?;
        if let Err(e) = self.core.can_queue(effect) {
            self.core.reject_prepared(effect)?;
            drop(frame);
            if e == ProtocolError::Closed {
                return Ok(true);
            }
            self.stop(index, CloseCause::Fault(e.into()), observe)?;
            return Ok(true);
        }
        match app.io.enqueue_owned(frame, effect, Class::Ordinary) {
            Ok(()) => {
                self.core.queued(effect)?;
                observe(Event::Queued(effect));
                Ok(true)
            }
            Err(rejected) => {
                app.held = Some(rejected.value);
                // One original empty MQ frame budget was preconfigured; repeated
                // capacity refusal is an explicit source policy, never a fake ACK.
                let e = rejected.reason;
                self.stop(index, CloseCause::Fault(e.into()), observe)?;
                Ok(true)
            }
        }
    }
    fn poll_app(
        &mut self,
        cx: &mut Context<'_>,
        index: usize,
        now: u64,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Poll<Result<Progress, Error>> {
        if self.shutdown == Some(ShutdownMode::Immediate) {
            return Poll::Ready(
                self.stop(index, CloseCause::Shutdown, observe)
                    .map(|_| Progress::Activity),
            );
        }
        let start = self.apps[index]
            .as_ref()
            .ok_or(ProtocolError::StaleGeneration)?
            .cursor;
        for n in 0..3 {
            let class = (start + n) % 3;
            let result = match class {
                0 => {
                    let app = self.apps[index]
                        .as_mut()
                        .ok_or(ProtocolError::StaleGeneration)?;
                    match app.io.poll_write(cx) {
                        Poll::Pending => Poll::Pending,
                        Poll::Ready(Err(e)) => Poll::Ready(
                            self.stop(index, CloseCause::Fault(e.into()), observe)
                                .map(|_| Progress::Activity),
                        ),
                        Poll::Ready(Ok(w)) => {
                            self.core.exposed(w.origin)?;
                            if w.complete {
                                self.core.written(w.origin)?;
                                self.report.written_frames =
                                    self.report.written_frames.saturating_add(1);
                            }
                            self.report.written_bytes =
                                self.report.written_bytes.saturating_add(w.bytes as u64);
                            observe(Event::Write {
                                effect: w.origin,
                                bytes: w.bytes,
                                complete: w.complete,
                            });
                            Poll::Ready(Ok(Progress::Activity))
                        }
                    }
                }
                1 => {
                    if self.app_input(index, now, observe)? {
                        Poll::Ready(Ok(Progress::Activity))
                    } else {
                        let app = self.apps[index]
                            .as_mut()
                            .ok_or(ProtocolError::StaleGeneration)?;
                        match app.io.poll_read(cx) {
                            Poll::Pending => Poll::Pending,
                            Poll::Ready(Err(e)) => Poll::Ready(
                                self.stop(index, CloseCause::Fault(e.into()), observe)
                                    .map(|_| Progress::Activity),
                            ),
                            Poll::Ready(Ok(ReadStep::Eof)) => Poll::Ready(
                                self.stop(index, CloseCause::Eof, observe)
                                    .map(|_| Progress::Activity),
                            ),
                            Poll::Ready(Ok(ReadStep::Progress { .. })) => {
                                Poll::Ready(Ok(Progress::Activity))
                            }
                        }
                    }
                }
                _ => {
                    if self.app_output(index, observe)? {
                        Poll::Ready(Ok(Progress::Activity))
                    } else {
                        Poll::Pending
                    }
                }
            };
            if result.is_ready() {
                if let Some(app) = self.apps[index].as_mut() {
                    app.cursor = (class + 1) % 3;
                }
                return result;
            }
        }
        Poll::Pending
    }
    fn poll_accept(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Poll<Result<Progress, Error>> {
        if self.shutdown.is_some() || !self.accept.ready() || self.apps.iter().all(Option::is_some)
        {
            return Poll::Pending;
        }
        for n in 0..listeners.len() {
            let index = (self.accept_cursor + n) % listeners.len();
            match listeners[index].poll_canonical_connection(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(e)) => {
                    observe(Event::Socket(self.accept.failed(e)));
                    return Poll::Ready(Ok(Progress::Activity));
                }
                Poll::Ready(Ok(accepted)) => {
                    self.accept_cursor = (index + 1) % listeners.len();
                    if let Err(e) = self.admit(accepted, observe) {
                        observe(Event::AdmissionFailed(e));
                    }
                    return Poll::Ready(Ok(Progress::Activity));
                }
            }
        }
        Poll::Pending
    }
    fn operation_busy(&self, operation: core::Operation<'id>) -> bool {
        self.links.iter().enumerate().any(|(i, l)| {
            l.as_ref().is_some_and(|l| {
                l.operation == Some(operation)
                    && (l.channel.is_some()
                        || self.pending.as_ref().is_some_and(|p| match p.action {
                            Action::Open(j) | Action::Ack(j) | Action::Destroy(j) => i == j,
                            _ => false,
                        }))
            })
        }) || self
            .held
            .as_ref()
            .is_some_and(|h| h.effect.operation() == operation)
            || self.pending.as_ref().is_some_and(|p| match p.action {
                Action::Data(e) | Action::RetiredData(e) => e.operation() == operation,
                _ => false,
            })
    }
    fn retire_one(&mut self) -> Result<bool, Error> {
        let next = self
            .core
            .retained_operations()
            .filter(|op| !self.operation_busy(*op))
            .filter(|op| op.value() > self.retirement_cursor)
            .min_by_key(|op| op.value());
        let operation = next.or_else(|| {
            self.core
                .retained_operations()
                .filter(|op| !self.operation_busy(*op))
                .min_by_key(|op| op.value())
        });
        if let Some(operation) = operation {
            self.retirement_cursor = operation.value();
            match self.core.retire(operation) {
                Ok(()) => {
                    for link in &mut self.links {
                        if link
                            .as_ref()
                            .is_some_and(|l| l.operation == Some(operation))
                        {
                            *link = None;
                        }
                    }
                    return Ok(true);
                }
                Err(ProtocolError::WouldBlock) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(false)
    }
    /// Poll one fair bounded transition. No wait cancellation discards a frame,
    /// grants CADET credit or changes the original physical source generation.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        entropy: &mut impl Entropy,
        deadline: Option<Instant>,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Poll<Result<Progress, Error>> {
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        if self.shutdown.is_some()
            && self.apps.iter().all(Option::is_none)
            && self.links.iter().all(Option::is_none)
            && self.pending.is_none()
        {
            return Poll::Ready(Ok(Progress::Stopped));
        }
        match self.subscription.poll_changed(cx, self.revision) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(s)) => self.revision = s.revision,
            Poll::Pending => {}
        }
        let sample = self.clock.sample()?;
        self.revision = sample.revision;
        let now = sample.now.as_micros();
        if self.core.expire(now) != 0 {
            cx.waker().wake_by_ref();
        }
        for n in 0..5 {
            let class = (self.class + n) % 5;
            let result = match class {
                0 => {
                    let mut result = Poll::Pending;
                    for n in 0..self.apps.len() {
                        let i = (self.app_cursor + n) % self.apps.len();
                        if self.apps[i].is_some() {
                            let p = self.poll_app(cx, i, now, observe);
                            if p.is_ready() {
                                self.app_cursor = (i + 1) % self.apps.len();
                                result = p;
                                break;
                            }
                        }
                    }
                    result
                }
                1 => self.poll_cadet(cx, observe),
                2 => {
                    if self.peer_work(now, observe)? {
                        Poll::Ready(Ok(Progress::Activity))
                    } else {
                        Poll::Pending
                    }
                }
                3 => {
                    let advanced = match self.core.progress_next(entropy) {
                        Ok(Some(_)) => true,
                        Ok(None) => false,
                        Err(
                            ProtocolError::Capacity
                            | ProtocolError::Entropy
                            | ProtocolError::EntropyUnavailable,
                        ) => true,
                        Err(e) => return Poll::Ready(Err(e.into())),
                    };
                    if advanced || self.retire_one()? {
                        Poll::Ready(Ok(Progress::Activity))
                    } else {
                        Poll::Pending
                    }
                }
                _ => self.poll_accept(cx, listeners, observe),
            };
            if result.is_ready() {
                self.class = (class + 1) % 5;
                return result;
            }
        }
        let logical = self
            .core
            .retained_operations()
            .filter_map(|op| self.core.operation_info(op).ok())
            .filter(|o| {
                !matches!(
                    o.phase,
                    core::Phase::Canceled | core::Phase::Failed | core::Phase::Finished
                )
            })
            .map(|o| o.deadline)
            .filter(|d| *d != u64::MAX)
            .min();
        let mut wake = Instant::now()
            .checked_add(Duration::from_secs(60))
            .ok_or(ProtocolError::Overflow)?;
        if let Some(logical) = logical {
            wake = wake.min(
                Instant::now()
                    .checked_add(Duration::from_micros(logical.saturating_sub(now)))
                    .ok_or(ProtocolError::Overflow)?,
            );
        }
        if let Some(pending) = &self.pending {
            wake = wake.min(pending.expires);
        }
        if let Some(deadline) = deadline {
            wake = wake.min(deadline);
        }
        self.timer.as_mut().reset(wake);
        if self.timer.as_mut().poll(cx).is_ready() {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
    /// Observe one event; dropping this future preserves every original cursor.
    pub async fn drive(
        &mut self,
        listeners: &[Listener<'_>],
        entropy: &mut impl Entropy,
        deadline: Option<Instant>,
        mut observe: impl FnMut(Event<'id, 'cadet>),
    ) -> Result<Progress, Error> {
        poll_fn(|cx| self.poll(cx, listeners, entropy, deadline, &mut observe)).await
    }
    /// Independently close every actual MQ and the original shared CADET source,
    /// even when clock/configuration/entropy failed. Remote drain is not claimed.
    pub fn close(&mut self, observe: &mut impl FnMut(Event<'id, 'cadet>)) -> Close<'cadet> {
        self.shutdown = Some(ShutdownMode::Immediate);
        let mut failure = None;
        for i in 0..self.apps.len() {
            if self.apps[i].is_some()
                && let Err(e) = self.stop(i, CloseCause::Shutdown, observe)
                && failure.is_none()
            {
                failure = Some(e);
            }
        }
        let backend = match self.cadet.close() {
            Ok(report) => report,
            Err(e) => {
                if failure.is_none() {
                    failure = Some(e.into());
                }
                None
            }
        };
        if let Some(report) = backend
            && let Err(e) = self.backend_lost(report, cadet::LossCause::Requested, observe)
            && failure.is_none()
        {
            failure = Some(e);
        }
        // A permanent native close already stopped every actual source, even
        // if its pure loss callback failed; finish other channels independently.
        for i in 0..self.links.len() {
            if self.links[i].as_ref().is_some_and(|l| l.channel.is_some())
                && let Err(e) = self.finish_channel(i, ProtocolError::Closed, observe)
                && failure.is_none()
            {
                failure = Some(e);
            }
        }
        self.pending = None;
        self.held = None;
        let count = self.core.retained_operations().count();
        for _ in 0..count {
            if let Err(e) = self.retire_one()
                && failure.is_none()
            {
                failure = Some(e);
            }
        }
        Close {
            report: self.report,
            backend,
            failure,
            retained: self.core.retained_operations().count(),
        }
    }
}

#[cfg(test)]
mod tests;
