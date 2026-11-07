//! Caller-driven native CORE application and monitor clients.
//!
//! One original CLIENT attempt and common framed socket survive canceled waits.
//! Application sources and immutable wire frames have separate explicit budgets.
//! A completed local write never asserts remote application delivery.
#![forbid(unsafe_code)]

pub use gnunet_client::core::{
    ClassOrder, ConnectionEpoch, Direction, Instance, KxState, MonitorEvent, Peer, PeerClass,
    PeerId, SendCompletion, SendId, SendOutcome,
};
use gnunet_client::core::{CoreClient, Event, Monitor as PureMonitor, SendOperation, Traffic};
/// Original CLIENT configuration, protocol or native error.
pub use gnunet_client_host::ConnectError as Error;
/// Caller-selected CLIENT/Resolver domain; construction creates no resolver.
pub use gnunet_client_host::EndpointSource;
use gnunet_client_host::{
    ConnectionAttempt, Endpoint,
    resolution::{PortError, ResolutionTimer},
};
/// Canonical absolute logical time and subscription interfaces.
pub use gnunet_service_runtime::clock;
use gnunet_service_runtime::{
    clock::{ClockSubscription, RuntimeClock},
    framing::{Accounting, Budget, Class, Framed, Limits as FrameLimits, OwnedFrame, ReadStep},
};
use gnunet_types::{Error as ProtocolError, Rejected};
use gnunet_wire::official::{
    MessageHeader,
    core::{INIT_PREFIX, SEND_PREFIX, SEND_REQUEST_LEN},
};
use std::{
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
use zeroize::Zeroizing;

/// Exact owned original application bytes, erased on drop; no mutable view exists.
pub struct Message(Zeroizing<Vec<u8>>);
impl Message {
    /// Copy one complete nonempty official message sequence, without native I/O.
    pub fn copy_from(bytes: &[u8]) -> Result<Self, ProtocolError> {
        gnunet_wire::official::core::message_sequence(bytes)?;
        let mut owned = allocate(bytes.len())?;
        owned.copy_from_slice(bytes);
        Ok(Self(Zeroizing::new(owned)))
    }
    /// Freeze an existing exact message sequence without copying or reallocating.
    /// Refusal returns the unchanged original Vec; its caller retains erasure duty.
    /// Admission charges its full retained allocation capacity, including spare bytes.
    pub fn try_from_owned(bytes: Vec<u8>) -> Result<Self, Rejected<Vec<u8>>> {
        if let Err(reason) = gnunet_wire::official::core::message_sequence(&bytes) {
            return Err(Rejected {
                value: bytes,
                reason,
            });
        }
        Ok(Self(Zeroizing::new(bytes)))
    }
}
impl AsRef<[u8]> for Message {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
fn allocate(len: usize) -> Result<Vec<u8>, ProtocolError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|_| ProtocolError::Capacity)?;
    bytes.resize(len, 0);
    Ok(bytes)
}
/// Explicit native metadata, source, wire and receive bounds.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum pending original operations, at most the client's S parameter.
    pub sends: usize,
    /// Aggregate retained original allocation capacities, including spare bytes.
    pub source_bytes: usize,
    /// Maximum individual complete received or outgoing official frame.
    pub frame_bytes: usize,
    /// Aggregate retained outgoing frame metadata and wire bytes.
    pub output: Budget,
    /// Maximum bytes in one actual native I/O step, nonzero.
    pub io_slice_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            sends: 32,
            source_bytes: 1024 * 1024,
            frame_bytes: 65535,
            output: Budget {
                frames: 64,
                bytes: 1024 * 1024,
            },
            io_slice_bytes: 65535,
        }
    }
}
impl Limits {
    fn framing(self) -> FrameLimits {
        FrameLimits {
            frame_bytes: self.frame_bytes,
            ordinary: self.output,
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: self.io_slice_bytes,
        }
    }
    fn validate(self) -> Result<(), ProtocolError> {
        if self.sends == 0
            || self.source_bytes == 0
            || !(56..=65535).contains(&self.frame_bytes)
            || self.output.frames == 0
            || self.output.bytes < self.frame_bytes
            || self.io_slice_bytes == 0
        {
            return Err(ProtocolError::Capacity);
        }
        Ok(())
    }
}
/// A full owned message or an explicitly incomplete observational preview.
pub enum OwnedTraffic {
    /// Actual complete official message bytes, erased when dropped.
    Full(Message),
    /// Actual header only; no body is synthesized.
    Header(MessageHeader),
}
/// Original public event with current connection and peer generation authority.
pub enum Inbound<'a> {
    /// Actual INIT_REPLY; local is an ordinary self-loopback peer.
    Ready {
        /// Actual local peer.
        local: Peer<'a>,
        /// Last identity from a previous physical MQ, if any.
        previous_identity: Option<PeerId>,
    },
    /// Actual current remote peer.
    Connected(Peer<'a>),
    /// Actual disconnected original peer generation.
    Disconnected(Peer<'a>),
    /// Actual matching send permit. Driver retains the original operation.
    SendReady {
        /// Original logical operation.
        send: SendId<'a>,
        /// Nonzero service permission.
        capacity: u16,
    },
    /// Actual rejection of the original request.
    Rejected(SendId<'a>),
    /// Old/canceled request echo, with no new operation authority.
    IgnoredReady {
        /// Actual identity.
        peer: PeerId,
        /// Actual finite echo.
        request_id: u16,
    },
    /// Owned actual traffic, bounded by the configured complete-frame capacity.
    Traffic {
        /// Actual sender/receiver.
        peer: PeerId,
        /// Current announced peer token, if available.
        connection: Option<Peer<'a>>,
        /// Actual direction.
        direction: Direction,
        /// Full message or explicit preview.
        traffic: OwnedTraffic,
    },
    /// Redundant service self connect/disconnect.
    IgnoredSelfNotification,
}
/// Why the original physical MQ was retired.
#[derive(Debug)]
pub enum LossCause {
    /// Actual clean EOF.
    Eof,
    /// Actual socket error, including EOF during a partial frame.
    Io(io::Error),
    /// Actual invalid service response.
    Protocol(ProtocolError),
    /// A preflighted native queue could not retain its original frame.
    Resource(ProtocolError),
    /// Caller requested a new physical MQ.
    Requested,
}
/// Private-minted original CORE_SEND physical state. It describes bytes in the
/// native service MQ, never remote receipt or delivery. Copying a receipt keeps
/// the same observation; consumers deduplicate by original send and byte total.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PayloadState<'a> {
    epoch: ConnectionEpoch<'a>,
    peer: Peer<'a>,
    send: SendId<'a>,
    written: usize,
    frame_bytes: usize,
}
impl<'a> PayloadState<'a> {
    /// Original physical service MQ generation.
    #[must_use]
    pub const fn epoch(self) -> ConnectionEpoch<'a> {
        self.epoch
    }
    /// Original announced peer generation, even after disconnect/reconnect.
    #[must_use]
    pub const fn peer(self) -> Peer<'a> {
        self.peer
    }
    /// Exact original admitted source/send operation.
    #[must_use]
    pub const fn send(self) -> SendId<'a> {
        self.send
    }
    /// Cumulative bytes actually written from the original CORE_SEND frame.
    /// This includes its IPC envelope; request/control bytes are excluded.
    #[must_use]
    pub const fn written(self) -> usize {
        self.written
    }
    /// Exact complete CORE_SEND frame size, including its IPC envelope.
    #[must_use]
    pub const fn frame_bytes(self) -> usize {
        self.frame_bytes
    }
    /// Whether any actual byte of this original CORE_SEND was exposed.
    #[must_use]
    pub const fn exposed(self) -> bool {
        self.written != 0
    }
    /// Whether all bytes of this original local CORE_SEND were written.
    #[must_use]
    pub const fn complete(self) -> bool {
        self.written == self.frame_bytes
    }
}
/// One actual positive original payload write, minted only after native poll_write
/// and the pure original operation both committed this same nonzero byte range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PayloadWrite<'a> {
    state: PayloadState<'a>,
    bytes: usize,
}
impl<'a> PayloadWrite<'a> {
    /// Original cumulative physical state after this exact write.
    #[must_use]
    pub const fn state(self) -> PayloadState<'a> {
        self.state
    }
    /// This exact original positive native byte range length.
    #[must_use]
    pub const fn bytes(self) -> usize {
        self.bytes
    }
    /// Original cumulative byte offset before this exact write.
    #[must_use]
    pub const fn previous(self) -> usize {
        self.state.written - self.bytes
    }
}
/// One original action. No event asserts remote application delivery.
pub enum Progress<'a> {
    /// Attached physical stream; INIT_REPLY has not yet authorized peers.
    Connected(ConnectionEpoch<'a>),
    /// Actual service input, scoped to this physical epoch.
    Inbound {
        /// Original epoch.
        epoch: ConnectionEpoch<'a>,
        /// Actual owned event.
        event: Inbound<'a>,
    },
    /// Original owned source and terminal local result, returned exactly once.
    Finished {
        /// Original epoch.
        epoch: ConnectionEpoch<'a>,
        /// Original peer generation.
        peer: Peer<'a>,
        /// Original operation.
        send: SendId<'a>,
        /// Actual terminal physical byte state for this exact original send.
        /// Peer/connection loss does not imply zero or complete output.
        payload: PayloadState<'a>,
        /// Actual terminal result and source.
        completion: SendCompletion<Message>,
    },
    /// Stream/attempt/queues have already stopped; old results drain before reconnect.
    Lost {
        /// Original physical epoch.
        epoch: ConnectionEpoch<'a>,
        /// Actual cause.
        cause: LossCause,
    },
    /// One old peer loss notice, including the actual local loopback peer.
    PeerLost {
        /// Retired physical epoch.
        epoch: ConnectionEpoch<'a>,
        /// Original peer.
        peer: Peer<'a>,
    },
    /// Complete original input remains retained after a pure capacity refusal.
    Capacity(ConnectionEpoch<'a>),
    /// Original connection attempt failed; retained source timer controls retry.
    ConnectRetry {
        /// Actual socket cause.
        error: io::Error,
        /// Original retry delay.
        retry_after: Duration,
    },
    /// Current CLIENT endpoint could not be created.
    Unavailable(Error),
    /// One actual positive native byte transfer, scoped to its original epoch.
    Activity {
        /// Original physical epoch.
        epoch: ConnectionEpoch<'a>,
        /// Actual input bytes.
        read_bytes: usize,
        /// Actual output bytes.
        written_bytes: usize,
        /// Present only for this exact positive original CORE_SEND write.
        /// INIT and SendRequest activity cannot manufacture payload exposure.
        payload: Option<PayloadWrite<'a>>,
    },
    /// Caller-native waiting deadline elapsed; work remains owned.
    WaitDeadline,
    /// Permanent closure after old sources/notices have been returned.
    Closed,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Origin<'a> {
    Control,
    Request(SendId<'a>),
    Payload(SendId<'a>),
}
struct Pending<'a> {
    operation: Option<SendOperation<'a, Message>>,
    peer: Peer<'a>,
    epoch: ConnectionEpoch<'a>,
    size: usize,
    charge: usize,
    ready: bool,
    prepared: bool,
    written: usize,
}
// Shared CLIENT lifecycle for application and monitor. No protocol or epoch authority.
struct Physical<'a> {
    attempt: Option<ConnectionAttempt>,
    framed: Option<Framed<Origin<'a>>>,
    source: EndpointSource,
    endpoint: Option<Endpoint>,
    clock: Arc<dyn RuntimeClock>,
    subscription: Option<Box<dyn ClockSubscription>>,
    revision: u64,
    timer: Option<ResolutionTimer>,
    delay: Option<Duration>,
    backoff: u64,
    round: u64,
    port_error: Option<PortError>,
    clock_refused: bool,
    wait: Option<Pin<Box<Sleep>>>,
    limits: Limits,
}
enum ConnectionStep {
    Attached,
    Retry(io::Error, Duration),
    Unavailable(Error),
}
fn clock_error(error: ProtocolError) -> Error {
    Error::Io(PortError::mark(io::Error::other(error)))
}
impl<'a> Physical<'a> {
    fn new(source: EndpointSource, limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        let clock = source.clock();
        let subscription = clock.subscribe().map_err(clock_error)?;
        Ok(Self {
            attempt: None,
            framed: None,
            source,
            endpoint: None,
            clock,
            subscription: Some(subscription),
            revision: 0,
            timer: None,
            delay: None,
            backoff: 0,
            round: 0,
            port_error: None,
            clock_refused: false,
            wait: None,
            limits,
        })
    }
    fn stop(&mut self) {
        drop(self.attempt.take());
        self.timer = None;
        if let Some(mut framed) = self.framed.take() {
            framed.retire();
        }
        self.endpoint = None;
        self.round = 0;
        self.wait = None;
    }
    fn schedule(&mut self) -> Duration {
        let delay = Duration::from_micros(self.backoff);
        self.backoff = if self.backoff == 0 {
            1000
        } else {
            self.backoff.saturating_mul(2).min(900_000_000)
        };
        self.delay = Some(delay);
        delay
    }
    fn clock(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        if let Some(error) = &self.port_error {
            return Poll::Ready(Err(Error::Io(error.to_io())));
        }
        let result = self.poll_clock(cx);
        if let Poll::Ready(Err(error)) = &result
            && let Error::Io(error) = error
        {
            self.port_error = PortError::from_io(error).cloned();
            self.clock_refused = true;
        }
        result
    }
    fn poll_clock(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let subscription = self.subscription.as_mut().ok_or(ProtocolError::Closed)?;
        match subscription.poll_changed(cx, self.revision) {
            Poll::Ready(Err(error)) => return Poll::Ready(Err(clock_error(error))),
            Poll::Ready(Ok(sample)) => self.revision = sample.revision,
            Poll::Pending => {}
        }
        let sample = self.clock.sample().map_err(clock_error)?;
        match subscription.poll_changed(cx, sample.revision) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(clock_error(error))),
            Poll::Ready(Ok(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Pending => {
                self.revision = sample.revision;
                Poll::Ready(Ok(()))
            }
        }
    }
    fn poll_connect(&mut self, cx: &mut Context<'_>) -> Poll<Result<ConnectionStep, Error>> {
        if let Some(error) = &self.port_error {
            return Poll::Ready(Err(Error::Io(error.to_io())));
        }
        if let Some(delay) = self.delay
            && self.timer.is_none()
        {
            match self.source.timer(delay) {
                Ok(timer) => self.timer = Some(timer),
                Err(error) => return self.refuse(error),
            }
        }
        if let Some(timer) = &mut self.timer {
            match timer.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return self.refuse(error),
                Poll::Ready(Ok(())) => {
                    self.timer = None;
                    self.delay = None;
                }
            }
        }
        if self.endpoint.is_none() {
            match self.source.resolve() {
                Ok(endpoint) => self.endpoint = Some(endpoint),
                Err(error) => {
                    self.schedule();
                    return Poll::Ready(Ok(ConnectionStep::Unavailable(error)));
                }
            }
        }
        if self.attempt.is_none() {
            let round = self.round.checked_add(1).ok_or(ProtocolError::Capacity)?;
            self.attempt = Some(
                self.endpoint
                    .as_ref()
                    .ok_or(ProtocolError::NotReady)?
                    .attempt(self.round),
            );
            self.round = round;
        }
        let result = Pin::new(self.attempt.as_mut().ok_or(ProtocolError::NotReady)?).poll(cx);
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                if PortError::from_io(&error).is_some() {
                    return self.refuse(error);
                }
                drop(self.attempt.take());
                let delay = self.schedule();
                Poll::Ready(Ok(ConnectionStep::Retry(error, delay)))
            }
            Poll::Ready(Ok(connection)) => {
                self.attempt = None;
                self.framed = Some(Framed::new(connection, self.limits.framing())?);
                Poll::Ready(Ok(ConnectionStep::Attached))
            }
        }
    }
    fn refuse<T>(&mut self, error: io::Error) -> Poll<Result<T, Error>> {
        let error = PortError::mark(error);
        self.port_error = PortError::from_io(&error).cloned();
        Poll::Ready(Err(Error::Io(error)))
    }
    fn recover_ports(&mut self) -> Result<(), Error> {
        if self.port_error.is_none() {
            return Err(ProtocolError::NotReady.into());
        }
        if self.clock_refused {
            self.subscription = None;
            match self.clock.subscribe() {
                Ok(subscription) => self.subscription = Some(subscription),
                Err(error) => {
                    let error = clock_error(error);
                    if let Error::Io(cause) = &error {
                        self.port_error = PortError::from_io(cause).cloned();
                    }
                    return Err(error);
                }
            }
            self.clock_refused = false;
        } else {
            drop(self.attempt.take());
            self.timer = None;
        }
        self.port_error = None;
        Ok(())
    }
    fn poll_wait(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Option<Instant>,
    ) -> Poll<Result<(), Error>> {
        let Some(deadline) = deadline else {
            return Poll::Pending;
        };
        let timer = self
            .wait
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(deadline)));
        timer.as_mut().reset(deadline);
        timer.as_mut().poll(cx).map(Ok)
    }
}
impl Drop for Physical<'_> {
    fn drop(&mut self) {
        self.stop();
        self.subscription = None;
    }
}
/// Last native application operation which returned an error. These labels are
/// observations, never authority to resume or replace an original operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeOperation {
    /// Return an already retained source-loss observation.
    PendingLoss,
    /// Drain old original sources and peer notices before a new attachment.
    Drain,
    /// Recover an original pure terminal send.
    Finish,
    /// Sample or subscribe to the original clock.
    Clock,
    /// Advance the original CLIENT attachment.
    Connect,
    /// Admit the actual original CORE INIT frame.
    Init,
    /// Interpret one complete actual service response.
    Dispatch,
    /// Match actual SEND_READY to the retained host operation.
    SendReady,
    /// Freeze the original permitted payload once.
    SetupPayload,
    /// Attempt the original immutable native output.
    Write,
    /// Match and commit actual positive CORE_SEND write progress.
    PayloadWrite,
    /// Attempt original service input.
    Read,
    /// Retire the original physical source and pure epoch.
    Retire,
    /// Observe only the original native waiting deadline.
    Wait,
}
/// Public numeric metadata for a matching retained host send row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingContext {
    /// One-based current host row, not a wire ID or reusable capability.
    pub row: std::num::NonZeroUsize,
    /// Previously committed actual CORE_SEND bytes.
    pub written: usize,
    /// Original complete CORE_SEND frame extent.
    pub frame_bytes: usize,
}
/// Bounded error context, containing no payload, private key or authority Debug.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationContext {
    /// Actual current operation when this poll returned its original error.
    pub operation: NativeOperation,
    /// Original local physical source generation, when attached.
    pub epoch: Option<std::num::NonZeroU64>,
    /// Number of retained original host send rows.
    pub pending_count: usize,
    /// Matching original row, if lookup had succeeded.
    pub pending: Option<PendingContext>,
    /// Actual service input type, when dispatching a complete frame.
    pub input_type: Option<u16>,
    /// Actual positive native write count when payload matching failed late.
    pub io_bytes: usize,
    /// Whether that same native write completed the immutable output frame.
    pub io_complete: bool,
}
/// Reusable native CORE application client. P includes connected peers and bounded
/// unresolved-ID tombstones; S bounds original operation metadata.
pub struct Client<'a, const P: usize = 64, const S: usize = 32> {
    physical: Physical<'a>,
    core: CoreClient<'a, P, S>,
    epoch: Option<ConnectionEpoch<'a>>,
    pending: Vec<Pending<'a>>,
    source_bytes: usize,
    init_len: usize,
    init_bytes: Option<Vec<u8>>,
    pending_loss: Option<LossCause>,
    draining: bool,
    closed: bool,
    read_first: bool,
    context: Option<OperationContext>,
    context_failed: bool,
}
impl<'a, const P: usize, const S: usize> Client<'a, P, S> {
    /// Reserve source metadata and one canonical-clock subscription; perform no I/O.
    pub fn new(
        instance: &'a mut Instance,
        source: EndpointSource,
        order: ClassOrder,
        options: u32,
        types: &'a [u16],
        limits: Limits,
    ) -> Result<Self, Error> {
        if limits.sends > S {
            return Err(ProtocolError::Capacity.into());
        }
        let init_len = INIT_PREFIX
            .checked_add(types.len().checked_mul(2).ok_or(ProtocolError::Capacity)?)
            .ok_or(ProtocolError::Capacity)?;
        if init_len > limits.frame_bytes {
            return Err(ProtocolError::Capacity.into());
        }
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(limits.sends)
            .map_err(|_| ProtocolError::Capacity)?;
        let core = CoreClient::new(instance, order, options, types)?;
        let physical = Physical::new(source, limits)?;
        Ok(Self {
            physical,
            core,
            epoch: None,
            pending,
            source_bytes: 0,
            init_len,
            init_bytes: None,
            pending_loss: None,
            draining: false,
            closed: false,
            read_first: true,
            context: None,
            context_failed: false,
        })
    }
    /// Numeric context when the latest poll returned Err and no subsequent
    /// internal driver operation superseded it. Copy before source retirement.
    /// Reading it neither consumes the error nor changes any native owner.
    #[must_use]
    pub fn failure_context(&self) -> Option<OperationContext> {
        self.context_failed.then_some(self.context).flatten()
    }
    fn operation(&mut self, operation: NativeOperation, index: Option<usize>) {
        self.context_failed = false;
        self.context = Some(OperationContext {
            operation,
            epoch: self
                .epoch
                .and_then(|epoch| std::num::NonZeroU64::new(epoch.value())),
            pending_count: self.pending.len(),
            pending: index.and_then(|index| self.pending_context(index)),
            input_type: None,
            io_bytes: 0,
            io_complete: false,
        });
    }
    fn pending_context(&self, index: usize) -> Option<PendingContext> {
        let pending = self.pending.get(index)?;
        Some(PendingContext {
            row: std::num::NonZeroUsize::new(index.checked_add(1)?)?,
            written: pending.written,
            frame_bytes: SEND_PREFIX + pending.size,
        })
    }
    /// Clone the same canonical source clock; reserve no additional listener.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.physical.clock.clone()
    }
    /// Observe exact original request metadata and native source/MQ capacity.
    /// The separate body length and retained allocation charge include caller
    /// spare capacity without conflating it with wire length. This is not a
    /// reservation or wire SendReady; send still validates/admit the actual
    /// immutable source and returns it unchanged on refusal.
    pub fn request_available(
        &self,
        peer: Peer<'a>,
        body_bytes: usize,
        source_charge: usize,
    ) -> Result<bool, Error> {
        if body_bytes < 4 || source_charge < body_bytes {
            return Err(ProtocolError::InvalidInput.into());
        }
        if self.closed || self.draining {
            return Err(ProtocolError::Closed.into());
        }
        if self.epoch.is_none() {
            return Err(ProtocolError::NotReady.into());
        }
        let framed = self
            .physical
            .framed
            .as_ref()
            .ok_or(ProtocolError::NotReady)?;
        Ok(self.core.request_available(peer)?
            && self.pending.len() < self.physical.limits.sends
            && source_charge
                <= self
                    .physical
                    .limits
                    .source_bytes
                    .saturating_sub(self.source_bytes)
            && body_bytes
                .checked_add(SEND_PREFIX)
                .is_some_and(|size| size <= self.physical.limits.frame_bytes)
            && framed.capacity(SEND_REQUEST_LEN, Class::Ordinary))
    }
    /// Current announced peer, including actual local loopback.
    #[must_use]
    pub fn peer(&self, identity: PeerId) -> Option<Peer<'a>> {
        self.core.peer(identity)
    }
    /// Physical epoch; during loss draining it still identifies the old MQ.
    #[must_use]
    pub const fn epoch(&self) -> Option<ConnectionEpoch<'a>> {
        self.epoch
    }
    /// Number of original operations whose sources are still owned by this driver.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending.len()
    }
    /// Aggregate original allocation capacities currently retained.
    #[must_use]
    pub const fn source_bytes(&self) -> usize {
        self.source_bytes
    }
    /// Admit one original immutable source. Capacity refusal returns it unchanged.
    pub fn send(
        &mut self,
        peer: Peer<'a>,
        priority: u32,
        deadline: u64,
        message: Message,
    ) -> Result<SendId<'a>, Rejected<Message>> {
        let size = message.as_ref().len();
        let charge = message.0.capacity();
        let setup = (|| {
            if self.closed || self.draining {
                return Err(ProtocolError::Closed);
            }
            let epoch = self.epoch.ok_or(ProtocolError::NotReady)?;
            if self.pending.len() >= self.physical.limits.sends
                || charge
                    > self
                        .physical
                        .limits
                        .source_bytes
                        .saturating_sub(self.source_bytes)
                || size
                    .checked_add(SEND_PREFIX)
                    .ok_or(ProtocolError::Capacity)?
                    > self.physical.limits.frame_bytes
            {
                return Err(ProtocolError::Capacity);
            }
            let framed = self
                .physical
                .framed
                .as_mut()
                .ok_or(ProtocolError::NotReady)?;
            framed.reserve(SEND_REQUEST_LEN, Class::Ordinary)?;
            Ok((epoch, allocate(SEND_REQUEST_LEN)?))
        })();
        let (epoch, mut bytes) = match setup {
            Ok(v) => v,
            Err(reason) => {
                return Err(Rejected {
                    value: message,
                    reason,
                });
            }
        };
        let (operation, len) = self
            .core
            .request_send(peer, priority, deadline, message, &mut bytes)?;
        let send = operation.id();
        bytes.truncate(len);
        // The queue record and final immutable allocation were preflighted above.
        let admitted = self
            .physical
            .framed
            .as_mut()
            .ok_or(ProtocolError::NotReady)
            .and_then(|f| {
                f.enqueue_owned(
                    OwnedFrame::new(bytes),
                    Origin::Request(send),
                    Class::Ordinary,
                )
                .map_err(|r| r.reason)
            });
        self.pending.push(Pending {
            operation: Some(operation),
            peer,
            epoch,
            size,
            charge,
            ready: false,
            prepared: false,
            written: 0,
        });
        self.source_bytes += charge;
        if let Err(reason) = admitted {
            self.physical.stop();
            let _retired = self.core.connection_lost(epoch);
            self.draining = true;
            self.pending_loss = Some(LossCause::Resource(reason));
            self.physical.schedule();
        }
        Ok(send)
    }
    fn index(&self, send: SendId<'_>) -> Result<usize, ProtocolError> {
        self.pending
            .iter()
            .position(|p| p.operation.as_ref().is_some_and(|o| o.id() == send))
            .ok_or(ProtocolError::Stale)
    }
    /// Cancel exactly the original operation. A started immutable payload drains;
    /// an admitted request is never removed as there is no wire cancellation.
    pub fn cancel(&mut self, send: SendId<'a>) -> Result<Option<SendCompletion<Message>>, Error> {
        let index = self.index(send)?;
        if self.pending[index].written > 0 {
            self.core.cancel_started(send)?;
            return Ok(None);
        }
        if self.pending[index].prepared {
            let removed = self
                .physical
                .framed
                .as_mut()
                .ok_or(ProtocolError::NotReady)?
                .remove_unwritten(|origin, _| origin == Origin::Payload(send), |_, _| {});
            if removed != 1 {
                return Err(ProtocolError::Conflict.into());
            }
        }
        let operation = self.pending[index]
            .operation
            .take()
            .ok_or(ProtocolError::Stale)?;
        match self.core.cancel_unwritten(operation) {
            Ok(completion) => {
                self.source_bytes -= self.pending[index].charge;
                drop(self.pending.remove(index));
                Ok(Some(completion))
            }
            Err(rejected) => {
                self.pending[index].operation = Some(rejected.value);
                Err(rejected.reason.into())
            }
        }
    }
    fn finish_one(&mut self) -> Result<Option<Progress<'a>>, Error> {
        for index in 0..self.pending.len() {
            self.operation(NativeOperation::Finish, Some(index));
            let operation = self.pending[index]
                .operation
                .take()
                .ok_or(ProtocolError::Stale)?;
            let send = operation.id();
            match self.core.finish(operation) {
                Ok(completion) => {
                    let pending = self.pending.remove(index);
                    if pending.prepared
                        && pending.written == 0
                        && let Some(framed) = &mut self.physical.framed
                    {
                        let _removed = framed.remove_unwritten(
                            |origin, _| origin == Origin::Payload(send),
                            |_, _| {},
                        );
                    }
                    self.source_bytes -= pending.charge;
                    return Ok(Some(Progress::Finished {
                        epoch: pending.epoch,
                        peer: pending.peer,
                        send,
                        payload: PayloadState {
                            epoch: pending.epoch,
                            peer: pending.peer,
                            send,
                            written: pending.written,
                            frame_bytes: SEND_PREFIX + pending.size,
                        },
                        completion,
                    }));
                }
                Err(rejected) => {
                    self.pending[index].operation = Some(rejected.value);
                    if rejected.reason != ProtocolError::WouldBlock {
                        return Err(rejected.reason.into());
                    }
                }
            }
        }
        Ok(None)
    }
    fn retire(&mut self, cause: LossCause) -> Result<Progress<'a>, Error> {
        self.operation(NativeOperation::Retire, None);
        let epoch = self.epoch.ok_or(ProtocolError::NotReady)?;
        self.physical.stop();
        // receive() may already have retired the pure owner after malformed input.
        match self.core.connection_lost(epoch) {
            Ok(()) | Err(ProtocolError::Closed) => {}
            Err(error) => return Err(error.into()),
        }
        self.draining = true;
        self.physical.schedule();
        Ok(Progress::Lost { epoch, cause })
    }
    /// Retire only the original physical MQ. Old sources and peer notices are
    /// returned by drive before another epoch can overwrite their authority.
    pub fn reconnect(&mut self) -> Result<Progress<'a>, Error> {
        if self.draining {
            return Err(ProtocolError::Conflict.into());
        }
        self.retire(LossCause::Requested)
    }
    /// Permanently retire I/O, then drain original sources/notices through drive.
    pub fn close(&mut self) -> Result<Option<Progress<'a>>, Error> {
        self.closed = true;
        self.physical.subscription = None;
        if self.epoch.is_some() && !self.draining {
            self.retire(LossCause::Requested).map(Some)
        } else {
            self.physical.stop();
            Ok(None)
        }
    }
    /// Explicitly retry a refused CLIENT timer/Resolver port, preserving its cause
    /// until this call; no hidden source or resolver is substituted.
    pub fn recover_ports(&mut self) -> Result<(), Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        self.physical.recover_ports()
    }
    fn setup_payload(&mut self) -> Result<Option<Progress<'a>>, Error> {
        let Some(index) = self.pending.iter().position(|p| p.ready && !p.prepared) else {
            return Ok(None);
        };
        self.operation(NativeOperation::SetupPayload, Some(index));
        let len = SEND_PREFIX + self.pending[index].size;
        let framed = self
            .physical
            .framed
            .as_mut()
            .ok_or(ProtocolError::NotReady)?;
        if !framed.capacity(len, Class::Ordinary) {
            return Ok(None);
        }
        framed.reserve(len, Class::Ordinary)?;
        let mut bytes = allocate(len)?;
        let operation = self.pending[index]
            .operation
            .as_ref()
            .ok_or(ProtocolError::Stale)?;
        let prepared = self.core.prepare_payload(operation, &mut bytes)?;
        let send = prepared.send();
        if let Err(rejected) = framed.enqueue_owned(
            OwnedFrame::new(bytes),
            Origin::Payload(send),
            Class::Ordinary,
        ) {
            return self.retire(LossCause::Resource(rejected.reason)).map(Some);
        }
        self.pending[index].prepared = true;
        Ok(None)
    }
    fn dispatch(&mut self, epoch: ConnectionEpoch<'a>) -> Result<Progress<'a>, Error> {
        self.operation(NativeOperation::Dispatch, None);
        let framed = self
            .physical
            .framed
            .as_mut()
            .ok_or(ProtocolError::NotReady)?;
        let bytes = framed.frame().ok_or(ProtocolError::NotReady)?;
        if let Some(context) = self.context.as_mut() {
            context.input_type = bytes
                .get(2..4)
                .map(|kind| u16::from_be_bytes([kind[0], kind[1]]));
        }
        // Allocate owned traffic before pure receive changes any state or releases RX.
        let owned = match gnunet_client::core::Response::decode(bytes, ClassOrder::Little) {
            Ok(gnunet_client::core::Response::Traffic {
                traffic: Traffic::Full(message),
                ..
            }) => Some(Message::copy_from(message)?),
            _ => None,
        };
        let result = self.core.receive(epoch, bytes);
        let event = match result {
            Err(ProtocolError::Capacity) => return Ok(Progress::Capacity(epoch)),
            Err(error) => return self.retire(LossCause::Protocol(error)),
            Ok(event) => match event {
                Event::Ready {
                    local,
                    previous_identity,
                } => Inbound::Ready {
                    local,
                    previous_identity,
                },
                Event::Connected(peer) => Inbound::Connected(peer),
                Event::Disconnected(peer) => Inbound::Disconnected(peer),
                Event::SendReady { send, capacity } => {
                    if let Some(context) = self.context.as_mut() {
                        context.operation = NativeOperation::SendReady;
                    }
                    let index = self.index(send)?;
                    self.pending[index].ready = true;
                    Inbound::SendReady { send, capacity }
                }
                Event::Rejected(send) => Inbound::Rejected(send),
                Event::IgnoredReady { peer, request_id } => {
                    Inbound::IgnoredReady { peer, request_id }
                }
                Event::IgnoredSelfNotification => Inbound::IgnoredSelfNotification,
                Event::Traffic {
                    peer,
                    connection,
                    direction,
                    traffic,
                } => Inbound::Traffic {
                    peer,
                    connection,
                    direction,
                    traffic: match traffic {
                        Traffic::Full(_) => {
                            OwnedTraffic::Full(owned.ok_or(ProtocolError::NotReady)?)
                        }
                        Traffic::Header(header) => OwnedTraffic::Header(header),
                    },
                },
            },
        };
        if !self
            .physical
            .framed
            .as_mut()
            .ok_or(ProtocolError::NotReady)?
            .release_frame()
        {
            return Err(ProtocolError::NotReady.into());
        }
        Ok(Progress::Inbound { epoch, event })
    }
    fn write(
        &mut self,
        cx: &mut Context<'_>,
        epoch: ConnectionEpoch<'a>,
    ) -> Poll<Result<Progress<'a>, Error>> {
        self.operation(NativeOperation::Write, None);
        match self
            .physical
            .framed
            .as_mut()
            .ok_or(ProtocolError::NotReady)?
            .poll_write(cx)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(self.retire(LossCause::Io(error))),
            Poll::Ready(Ok(progress)) => {
                // Commit every actual positive write into its original pure operation
                // before any more RX, including the final byte of a canceled payload.
                let payload = if let Origin::Payload(send) = progress.origin {
                    self.operation(NativeOperation::PayloadWrite, None);
                    if let Some(context) = self.context.as_mut() {
                        context.io_bytes = progress.bytes;
                        context.io_complete = progress.complete;
                    }
                    let index = self.index(send)?;
                    let pending = self.pending_context(index);
                    if let Some(context) = self.context.as_mut() {
                        context.pending = pending;
                    }
                    self.core.payload_bytes_written(send, progress.bytes)?;
                    self.pending[index].written += progress.bytes;
                    let pending = &self.pending[index];
                    Some(PayloadWrite {
                        state: PayloadState {
                            epoch: pending.epoch,
                            peer: pending.peer,
                            send,
                            written: pending.written,
                            frame_bytes: SEND_PREFIX + pending.size,
                        },
                        bytes: progress.bytes,
                    })
                } else {
                    None
                };
                self.read_first = true;
                Poll::Ready(Ok(Progress::Activity {
                    epoch,
                    read_bytes: 0,
                    written_bytes: progress.bytes,
                    payload,
                }))
            }
        }
    }
    fn read(
        &mut self,
        cx: &mut Context<'_>,
        epoch: ConnectionEpoch<'a>,
    ) -> Poll<Result<Progress<'a>, Error>> {
        self.operation(NativeOperation::Read, None);
        match self
            .physical
            .framed
            .as_mut()
            .ok_or(ProtocolError::NotReady)?
            .poll_read(cx)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(self.retire(LossCause::Io(error))),
            Poll::Ready(Ok(ReadStep::Eof)) => Poll::Ready(self.retire(LossCause::Eof)),
            Poll::Ready(Ok(ReadStep::Progress { bytes, complete })) => {
                self.read_first = false;
                if complete {
                    Poll::Ready(self.dispatch(epoch))
                } else {
                    Poll::Ready(Ok(Progress::Activity {
                        epoch,
                        read_bytes: bytes,
                        written_bytes: 0,
                        payload: None,
                    }))
                }
            }
        }
    }
    fn poll_drive(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Option<Instant>,
    ) -> Poll<Result<Progress<'a>, Error>> {
        self.operation(NativeOperation::PendingLoss, None);
        if let Some(cause) = self.pending_loss.take() {
            return Poll::Ready(Ok(Progress::Lost {
                epoch: self.epoch.ok_or(ProtocolError::Stale)?,
                cause,
            }));
        }
        if let Some(completion) = self.finish_one()? {
            return Poll::Ready(Ok(completion));
        }
        if self.draining {
            self.operation(NativeOperation::Drain, None);
            let epoch = self.epoch.ok_or(ProtocolError::NotReady)?;
            if let Some(peer) = self.core.next_lost_peer() {
                return Poll::Ready(Ok(Progress::PeerLost { epoch, peer }));
            }
            if !self.pending.is_empty() {
                return Poll::Ready(Err(ProtocolError::Conflict.into()));
            }
            self.epoch = None;
            self.draining = false;
        }
        if self.closed {
            return Poll::Ready(Ok(Progress::Closed));
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        self.operation(NativeOperation::Clock, None);
        match self.physical.clock(cx) {
            // Observe only the existing native target while canonical time is
            // pending. This never retires an operation or advances its clock.
            Poll::Pending => {
                self.operation(NativeOperation::Wait, None);
                return self
                    .physical
                    .poll_wait(cx, deadline)
                    .map_ok(|()| Progress::WaitDeadline);
            }
            Poll::Ready(result) => result?,
        }
        if self.physical.framed.is_none() {
            self.operation(NativeOperation::Connect, None);
            if self.init_bytes.is_none() {
                self.init_bytes = Some(allocate(self.init_len)?);
            }
            match self.physical.poll_connect(cx) {
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(ConnectionStep::Retry(error, retry_after))) => {
                    return Poll::Ready(Ok(Progress::ConnectRetry { error, retry_after }));
                }
                Poll::Ready(Ok(ConnectionStep::Unavailable(error))) => {
                    return Poll::Ready(Ok(Progress::Unavailable(error)));
                }
                Poll::Ready(Ok(ConnectionStep::Attached)) => {
                    self.operation(NativeOperation::Init, None);
                    let framed = self
                        .physical
                        .framed
                        .as_mut()
                        .ok_or(ProtocolError::NotReady)?;
                    if let Err(error) = framed.reserve(self.init_len, Class::Ordinary) {
                        self.physical.stop();
                        return Poll::Ready(Err(error.into()));
                    }
                    let mut bytes = self.init_bytes.take().ok_or(ProtocolError::NotReady)?;
                    let (epoch, len) = self.core.begin(&mut bytes)?;
                    self.epoch = Some(epoch);
                    bytes.truncate(len);
                    if let Err(rejected) = framed.enqueue_owned(
                        OwnedFrame::new(bytes),
                        Origin::Control,
                        Class::Ordinary,
                    ) {
                        return Poll::Ready(self.retire(LossCause::Resource(rejected.reason)));
                    }
                    return Poll::Ready(Ok(Progress::Connected(epoch)));
                }
                Poll::Pending => {
                    self.operation(NativeOperation::Wait, None);
                    return self
                        .physical
                        .poll_wait(cx, deadline)
                        .map_ok(|()| Progress::WaitDeadline);
                }
            }
        }
        let epoch = self.epoch.ok_or(ProtocolError::NotReady)?;
        if self
            .physical
            .framed
            .as_ref()
            .is_some_and(|f| f.frame().is_some())
        {
            return Poll::Ready(self.dispatch(epoch));
        }
        if let Some(progress) = self.setup_payload()? {
            return Poll::Ready(Ok(progress));
        }
        if self.read_first {
            if let Poll::Ready(event) = self.read(cx, epoch) {
                return Poll::Ready(event);
            }
            if let Poll::Ready(event) = self.write(cx, epoch) {
                return Poll::Ready(event);
            }
        } else {
            if let Poll::Ready(event) = self.write(cx, epoch) {
                return Poll::Ready(event);
            }
            if let Poll::Ready(event) = self.read(cx, epoch) {
                return Poll::Ready(event);
            }
        }
        self.operation(NativeOperation::Wait, None);
        self.physical
            .poll_wait(cx, deadline)
            .map_ok(|()| Progress::WaitDeadline)
    }
    /// Poll one actual action directly. Cancellation/return preserves original
    /// immutable sources, request frontiers and partial native byte cursors.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Option<Instant>,
    ) -> Poll<Result<Progress<'a>, Error>> {
        self.context = None;
        self.context_failed = false;
        let result = self.poll_drive(cx, deadline);
        self.context_failed = matches!(&result, Poll::Ready(Err(_)));
        result
    }
    /// Wait for one action; canceling this future preserves attempts, cursors,
    /// immutable frames and original sources. Deadline limits only this wait.
    pub async fn drive(&mut self, deadline: Option<Instant>) -> Result<Progress<'a>, Error> {
        poll_fn(|cx| self.poll(cx, deadline)).await
    }
}
/// Caller-driven continuous CORE monitor using the same physical lifecycle owner.
pub struct Monitor<'a> {
    physical: Physical<'a>,
    core: PureMonitor<'a>,
    epoch: Option<ConnectionEpoch<'a>>,
    init_bytes: Option<Vec<u8>>,
    closed: bool,
}
/// A monitor action scoped to its actual physical epoch.
pub enum MonitorProgress<'a> {
    /// Actual attached stream; initial snapshot is pending.
    Connected(ConnectionEpoch<'a>),
    /// Actual update or initial snapshot marker.
    Inbound {
        /// Original physical epoch.
        epoch: ConnectionEpoch<'a>,
        /// Actual event.
        event: MonitorEvent,
    },
    /// Original physical MQ stopped before this event is returned.
    Lost {
        /// Original physical epoch.
        epoch: ConnectionEpoch<'a>,
        /// Actual cause.
        cause: LossCause,
    },
    /// Initial native attempt failed and source timer controls retry.
    ConnectRetry {
        /// Actual native cause.
        error: io::Error,
        /// Source retry delay.
        retry_after: Duration,
    },
    /// Current CLIENT endpoint could not be created.
    Unavailable(Error),
    /// Actual positive native I/O.
    Activity {
        /// Original physical epoch.
        epoch: ConnectionEpoch<'a>,
        /// Actual input bytes.
        read_bytes: usize,
        /// Actual output bytes.
        written_bytes: usize,
    },
    /// This waiting call's native deadline elapsed.
    WaitDeadline,
    /// Monitor permanently closed.
    Closed,
}
impl<'a> Monitor<'a> {
    /// Reserve one canonical-clock listener without creating I/O/background tasks.
    pub fn new(
        instance: &'a mut Instance,
        source: EndpointSource,
        limits: Limits,
    ) -> Result<Self, Error> {
        Ok(Self {
            physical: Physical::new(source, limits)?,
            core: PureMonitor::new(instance),
            epoch: None,
            init_bytes: None,
            closed: false,
        })
    }
    fn retire(&mut self, cause: LossCause) -> Result<MonitorProgress<'a>, Error> {
        let epoch = self.epoch.take().ok_or(ProtocolError::NotReady)?;
        self.physical.stop();
        match self.core.connection_lost(epoch) {
            Ok(_) | Err(ProtocolError::Closed) => {}
            Err(error) => return Err(error.into()),
        }
        self.physical.schedule();
        Ok(MonitorProgress::Lost { epoch, cause })
    }
    /// Cancel/reconnect by closing only this monitor's original MQ.
    pub fn reconnect(&mut self) -> Result<MonitorProgress<'a>, Error> {
        self.retire(LossCause::Requested)
    }
    /// Permanently close the original physical monitor.
    pub fn close(&mut self) -> Result<Option<MonitorProgress<'a>>, Error> {
        self.closed = true;
        self.physical.subscription = None;
        if self.epoch.is_some() {
            self.retire(LossCause::Requested).map(Some)
        } else {
            self.physical.stop();
            Ok(None)
        }
    }
    /// Recover a retained source-domain port refusal explicitly.
    pub fn recover_ports(&mut self) -> Result<(), Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        self.physical.recover_ports()
    }
    fn poll_drive(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Option<Instant>,
    ) -> Poll<Result<MonitorProgress<'a>, Error>> {
        if self.closed {
            return Poll::Ready(Ok(MonitorProgress::Closed));
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Poll::Ready(Ok(MonitorProgress::WaitDeadline));
        }
        match self.physical.clock(cx) {
            // Observe only the existing native target while canonical time is
            // pending. This never retires an operation or advances its clock.
            Poll::Pending => {
                return self
                    .physical
                    .poll_wait(cx, deadline)
                    .map_ok(|()| MonitorProgress::WaitDeadline);
            }
            Poll::Ready(result) => result?,
        }
        if self.physical.framed.is_none() {
            if self.init_bytes.is_none() {
                self.init_bytes = Some(allocate(4)?);
            }
            match self.physical.poll_connect(cx) {
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(ConnectionStep::Retry(error, retry_after))) => {
                    return Poll::Ready(Ok(MonitorProgress::ConnectRetry { error, retry_after }));
                }
                Poll::Ready(Ok(ConnectionStep::Unavailable(error))) => {
                    return Poll::Ready(Ok(MonitorProgress::Unavailable(error)));
                }
                Poll::Ready(Ok(ConnectionStep::Attached)) => {
                    let framed = self
                        .physical
                        .framed
                        .as_mut()
                        .ok_or(ProtocolError::NotReady)?;
                    if let Err(error) = framed.reserve(4, Class::Ordinary) {
                        self.physical.stop();
                        return Poll::Ready(Err(error.into()));
                    }
                    let mut bytes = self.init_bytes.take().ok_or(ProtocolError::NotReady)?;
                    let (epoch, _) = self.core.begin(&mut bytes)?;
                    self.epoch = Some(epoch);
                    if let Err(rejected) = framed.enqueue_owned(
                        OwnedFrame::new(bytes),
                        Origin::Control,
                        Class::Ordinary,
                    ) {
                        return Poll::Ready(self.retire(LossCause::Resource(rejected.reason)));
                    }
                    return Poll::Ready(Ok(MonitorProgress::Connected(epoch)));
                }
                Poll::Pending => {
                    return self
                        .physical
                        .poll_wait(cx, deadline)
                        .map_ok(|()| MonitorProgress::WaitDeadline);
                }
            }
        }
        let epoch = self.epoch.ok_or(ProtocolError::NotReady)?;
        let framed = self
            .physical
            .framed
            .as_mut()
            .ok_or(ProtocolError::NotReady)?;
        if let Some(bytes) = framed.frame() {
            match self.core.receive(epoch, bytes) {
                Ok(event) => {
                    if !framed.release_frame() {
                        return Poll::Ready(Err(ProtocolError::NotReady.into()));
                    }
                    return Poll::Ready(Ok(MonitorProgress::Inbound { epoch, event }));
                }
                Err(error) => return Poll::Ready(self.retire(LossCause::Protocol(error))),
            }
        }
        match framed.poll_write(cx) {
            Poll::Ready(Ok(progress)) => {
                return Poll::Ready(Ok(MonitorProgress::Activity {
                    epoch,
                    read_bytes: 0,
                    written_bytes: progress.bytes,
                }));
            }
            Poll::Ready(Err(error)) => return Poll::Ready(self.retire(LossCause::Io(error))),
            Poll::Pending => {}
        }
        match framed.poll_read(cx) {
            Poll::Ready(Ok(ReadStep::Eof)) => return Poll::Ready(self.retire(LossCause::Eof)),
            Poll::Ready(Err(error)) => return Poll::Ready(self.retire(LossCause::Io(error))),
            Poll::Ready(Ok(ReadStep::Progress { bytes, .. })) => {
                cx.waker().wake_by_ref();
                return Poll::Ready(Ok(MonitorProgress::Activity {
                    epoch,
                    read_bytes: bytes,
                    written_bytes: 0,
                }));
            }
            Poll::Pending => {}
        }
        self.physical
            .poll_wait(cx, deadline)
            .map_ok(|()| MonitorProgress::WaitDeadline)
    }
    /// Wait for actual monitoring progress, preserving native ownership if canceled.
    pub async fn drive(&mut self, deadline: Option<Instant>) -> Result<MonitorProgress<'a>, Error> {
        poll_fn(|cx| self.poll_drive(cx, deadline)).await
    }
}
