use crate::native::{self, Address, OwnedDatagram};
use gnunet_client_host::{
    EndpointSource,
    channel::{Channel, ConnectionStep},
};
use gnunet_service_runtime::{
    clock::{ClockSubscription, RuntimeClock},
    framing::{Accounting, Budget, Class, Limits as FrameLimits, OwnedFrame, ReadStep},
};
use gnunet_types::Error as Protocol;
use gnunet_wire::official::communicator::{Characteristics, Queue as WireQueue, Request, Response};
use std::{
    cell::Cell,
    collections::VecDeque,
    fmt,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
use zeroize::Zeroizing;
/// Stable caller-owned allocation domain. Reusing a bounded runtime slot cannot
/// make an old epoch/write/flow token belong to a new communicator allocation.
#[derive(Default)]
pub struct Instance {
    next: Cell<u64>,
}
impl Instance {
    /// Allocate no resources or native handles.
    pub const fn new() -> Self {
        Self { next: Cell::new(0) }
    }
}
#[derive(Clone, Copy)]
struct Scope<'id> {
    owner: &'id Instance,
    allocation: u64,
}
impl PartialEq for Scope<'_> {
    fn eq(&self, b: &Self) -> bool {
        std::ptr::eq(self.owner, b.owner) && self.allocation == b.allocation
    }
}
impl Eq for Scope<'_> {}
impl fmt::Debug for Scope<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Allocation").field(&self.allocation).finish()
    }
}
/// Original actually attached TRANSPORT source, local only and never on wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Epoch<'id> {
    scope: Scope<'id>,
    serial: u64,
}
/// Original immutable local output identity, distinct from opaque wire ids.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Write<'id> {
    epoch: Epoch<'id>,
    serial: u64,
}
/// Original actual bound datagram source. It is never rebound after socket loss.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketEpoch<'id> {
    scope: Scope<'id>,
}
/// Explicit original endpoint selectors. Both must share the same process clock.
pub struct Sources {
    /// Actual standard communicator service.
    pub transport: EndpointSource,
    /// Actual public PILS identity source.
    pub pils: EndpointSource,
}
/// Finite resource and operation profile, independent of C scheduler internals.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum live native address/claimed peer queues.
    pub queues: usize,
    /// Maximum actual outstanding incoming TRANSPORT callback debts.
    pub incoming: usize,
    /// Retained immutable MQ output frames, at least4.
    pub output_frames: usize,
    /// Retained immutable MQ bytes, at least two maximum frames.
    pub output_bytes: usize,
    /// Maximum bytes per native stream IO step.
    pub io_slice: usize,
    /// Actual OS datagram allowance, maximum65535; Darwin additionally2048.
    pub datagram_bytes: usize,
    /// Requested socket send/receive buffer bounds (kernel returns real values).
    pub socket_buffer: usize,
    /// Original send/IPC/callback finite lifetime.
    pub operation: Duration,
    /// Queue activity lifetime; WouldBlock/duplicate CREATE never renews it.
    pub idle: Duration,
    /// This original daemon allocation lifetime; no clock rollback renews it.
    pub lifetime: Duration,
    /// Original initial PILS/TRANSPORT readiness bound.
    pub startup: Duration,
    /// Native bounded retry after actual ENOBUFS; EAGAIN uses reactor readiness.
    pub enobufs_retry: Duration,
    /// Explicit PILS signature profile, default official metadata-only.
    pub profile: gnunet_pils::Profile,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            queues: 256,
            incoming: 64,
            output_frames: 8,
            output_bytes: 524280,
            io_slice: 65535,
            datagram_bytes: if cfg!(target_os = "macos") {
                2048
            } else {
                65535
            },
            socket_buffer: 1024 * 1024,
            operation: Duration::from_secs(30),
            idle: Duration::from_secs(300),
            lifetime: Duration::from_secs(86400),
            startup: Duration::from_secs(30),
            enobufs_retry: Duration::from_millis(1),
            profile: gnunet_pils::Profile::Reference029,
        }
    }
}
impl Limits {
    fn validate(self) -> Result<(), Fault> {
        if self.queues == 0
            || self.queues > 65535
            || self.incoming == 0
            || self.incoming > 65535
            || self.output_frames < 4
            || self.output_frames > 65535
            || self.output_bytes < 131070
            || self.io_slice == 0
            || self.socket_buffer == 0
        {
            return Err(Protocol::InvalidInput.into());
        }
        for d in [
            self.operation,
            self.idle,
            self.lifetime,
            self.startup,
            self.enobufs_retry,
        ] {
            if d.is_zero()
                || d.as_micros() > u64::MAX as u128
                || Instant::now().checked_add(d).is_none()
            {
                return Err(Protocol::InvalidInput.into());
            }
        }
        Ok(())
    }
}
/// Actual cause. No protocol completion is inferred from local exposure.
#[derive(Debug)]
pub enum Fault {
    /// Protocol/resource validation failure.
    Protocol(Protocol),
    /// Shared CLIENT/clock/configuration failure.
    Client(gnunet_client_host::ConnectError),
    /// Original native IO error.
    Io(io::Error),
    /// An original native/logical hard bound elapsed.
    Deadline,
    /// Original PILS MQ was lost or closed; no fresh identity was fabricated.
    IdentityLost,
    /// Actual original TRANSPORT EOF.
    TransportLost,
    /// Positive short datagram, which must never be suffixed/replayed.
    ShortDatagram {
        /// Complete original datagram byte count requested.
        expected: usize,
        /// Actual positive short byte count reported by the kernel.
        actual: usize,
    },
    /// Owner already physically retired.
    Closed,
}
impl From<Protocol> for Fault {
    fn from(e: Protocol) -> Self {
        Self::Protocol(e)
    }
}
impl From<gnunet_client_host::ConnectError> for Fault {
    fn from(e: gnunet_client_host::ConnectError) -> Self {
        Self::Client(e)
    }
}
impl From<io::Error> for Fault {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UNIX communicator: {self:?}")
    }
}
impl std::error::Error for Fault {}
/// Actual counts without plaintext payloads or filesystem address diagnostics.
#[derive(Clone, Copy, Debug, Default)]
pub struct Statistics {
    /// Current real queue metadata count.
    pub queues: u64,
    /// Actual complete datagram send bytes.
    pub bytes_sent: u64,
    /// Actual failed sendto attempts, including retries.
    pub network_failures: u64,
    /// Actual rejected network inputs.
    pub invalid_inputs: u64,
    /// Original incoming debts lost without callback.
    pub transport_failures: u64,
    /// Actual incoming whole IPC writes, not callbacks.
    pub incoming_written: u64,
    /// Actual matching original flow callbacks.
    pub incoming_callbacks: u64,
}
/// Actual retained packet submission state; local submission never authenticates
/// a sender or proves remote receipt/processing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendOutcome {
    /// No whole datagram was submitted.
    Unsent,
    /// One whole sendto result was observed.
    Whole {
        /// Actual complete datagram bytes.
        bytes: usize,
    },
    /// Actual permanent negative sendto result.
    Failed {
        /// Actual original raw errno, when provided by OS.
        errno: Option<i32>,
        /// Actual OS error kind.
        kind: io::ErrorKind,
    },
    /// A positive short send cannot be retried as a suffix.
    Unknown {
        /// Native returned length.
        actual: usize,
        /// Original complete datagram length.
        expected: usize,
    },
}
/// Original runtime event. No inner payload or private material is exposed.
#[derive(Debug)]
pub enum Event<'id> {
    /// Actual bound source; no peer auth.
    Bound(SocketEpoch<'id>),
    /// Actual original TRANSPORT connection attachment.
    Attached(Epoch<'id>),
    /// Immutable original MQ enqueue only.
    Queued {
        /// Original immutable output token on its actual MQ.
        write: Write<'id>,
        /// Complete retained frame byte count.
        bytes: usize,
    },
    /// Actual positive original MQ write.
    Written {
        /// Original immutable MQ write token.
        write: Write<'id>,
        /// Actual original byte count.
        bytes: usize,
        /// Whether this original local frame completed physically.
        complete: bool,
    },
    /// Real PILS public identity observation.
    Identity {
        /// Original public peer claim or PILS observation, as stated by this event.
        peer: [u8; 32],
        /// Actual public PILS HELLO signature coverage.
        coverage: gnunet_hello::SignatureCoverage,
    },
    /// Real native queue metadata advertised, not dial/auth.
    Queue {
        /// Original communicator queue id.
        id: u32,
        /// Original public peer claim or PILS observation, as stated by this event.
        peer: [u8; 32],
        /// Whether this queue came from actual network input.
        inbound: bool,
    },
    /// Original queue expired and DOWN queued.
    QueueExpired(u32),
    /// Complete native datagram submission, not peer receipt.
    DatagramSent {
        /// Original actually bound Unix socket token.
        socket: SocketEpoch<'id>,
        /// Original queue id on that MQ.
        queue: u32,
        /// Original opaque service message id.
        message_id: [u8; 8],
        /// Actual original byte count.
        bytes: usize,
    },
    /// Original actual negative send errno, retained even if bounded retry follows.
    SendError {
        /// Original queue id on that MQ.
        queue: u32,
        /// Original opaque service message id.
        message_id: [u8; 8],
        /// Original native IO error, unmodified.
        error: io::Error,
        /// Whether the same original datagram remains for bounded retry.
        retrying: bool,
    },
    /// Invalid/truncated/capacity-dropped actual network input.
    RejectedInput {
        /// Actual received datagram byte count.
        bytes: usize,
        /// Structural or capacity refusal after consuming the datagram.
        reason: Protocol,
    },
    /// Actual source-matching TRANSPORT callback.
    Received {
        /// Original actually attached MQ token.
        epoch: Epoch<'id>,
        /// Original opaque incoming callback id.
        flow_id: [u8; 8],
        /// Original public peer claim or PILS observation, as stated by this event.
        peer: [u8; 32],
    },
    /// Actual unsupported unsolicited command; never fake ACK.
    UnsupportedCommand,
    /// Actual conversion error after consuming a native datagram; not socket loss.
    RejectedSource(io::Error),
    /// Actual closed original send intent, with its immutable source/ids/outcome.
    SendRetired {
        /// Original actually attached MQ token.
        epoch: Option<Epoch<'id>>,
        /// Original actually bound Unix socket token.
        socket: SocketEpoch<'id>,
        /// Original queue id on that MQ.
        queue: u32,
        /// Original opaque service message id.
        message_id: [u8; 8],
        /// Retained actual datagram syscall outcome.
        outcome: SendOutcome,
        /// Exact actual positive bytes of the original SEND result IPC frame.
        ack_bytes: usize,
        /// Whether that complete local result frame was physically written.
        ack_written: bool,
    },
    /// Original actual flow callback debt retired after physical MQ close.
    IncomingRetired {
        /// Original actually attached MQ token.
        epoch: Option<Epoch<'id>>,
        /// Original opaque incoming callback id.
        flow_id: [u8; 8],
        /// Original public peer claim or PILS observation, as stated by this event.
        peer: [u8; 32],
        /// Whether the complete original incoming IPC frame was physically written.
        written: bool,
    },
    /// Original immutable frame retired after its physical stream was stopped.
    OutputRetired {
        /// Original output token on the physically closed MQ.
        write: Write<'id>,
        /// Actual positive byte count written before retirement.
        bytes: usize,
    },
    /// Actual source attempt failed; no new epoch exists yet.
    ConnectRetry(io::Error),
    /// One original TRANSPORT MQ physically retired; native socket/PILS remain.
    TransportLost {
        /// Exact original attached source.
        epoch: Epoch<'id>,
        /// Original native IO failure, None for actual EOF.
        cause: Option<io::Error>,
        /// Actual original retained input head, including malformed prefixes.
        input_bytes: usize,
        /// Whether that original head was a complete unreleased frame.
        held_input: bool,
        /// Retired immutable output frames.
        outputs: usize,
        /// Retired output frames with actual positive bytes.
        exposed: usize,
        /// Retired flow callback obligations.
        incoming: usize,
        /// Retired original native send intents, with their separate events.
        sends: usize,
        /// Retained source's bounded reconnect backoff, not a new lifetime.
        retry_after: Duration,
    },
    /// A consumed native input was never submitted on a replacement MQ.
    InputRetired {
        /// Original MQ at the time of retirement, if attached.
        epoch: Option<Epoch<'id>>,
        /// Same original socket capability.
        socket: SocketEpoch<'id>,
        /// Actual retained native packet size, without payload.
        bytes: usize,
    },
    /// This source's current address/queue publication prefix wholly wrote.
    Restored {
        /// Exact replacement/initial attached source.
        epoch: Epoch<'id>,
        /// Current queue announcements, not authenticated peers.
        queues: usize,
    },
    /// Closed original owners and retired exact debt.
    Closed {
        /// Count of original queued output frames retired.
        outputs: usize,
        /// Count of original frames with positive actual bytes.
        exposed: usize,
        /// Count of original incoming callback debts retired.
        incoming: usize,
        /// Count of original retained send intents retired.
        sends: usize,
    },
}
/// Actual independently retained native cleanup. Channel/PILS APIs expose no
/// independent close errno; their owner drops are reported only as retirement.
#[derive(Debug)]
pub struct Close {
    /// Original output frames retired.
    pub outputs: usize,
    /// Frames with positive actual stream bytes.
    pub exposed: usize,
    /// Original incoming callbacks no longer possible.
    pub incoming: usize,
    /// Original retained send datagrams retired.
    pub sends: usize,
    /// Actual datagram fd/name cleanup, if it was owned.
    pub datagram: Option<native::Close>,
}
impl Close {
    /// Whether observed descriptor/path cleanup had an unresolved error.
    pub fn uncertain(&self) -> bool {
        self.datagram.as_ref().is_some_and(|d| {
            d.descriptor_error.is_some()
                || matches!(
                    d.path,
                    native::PathCleanup::Unknown(_)
                        | native::PathCleanup::Replaced
                        | native::PathCleanup::UnobservedBoundName
                )
        })
    }
}
/// First failure plus independent physical cleanup, never overwritten by clock.
#[derive(Debug)]
pub struct Error {
    /// Original failure.
    pub cause: Fault,
    /// Actual original close report.
    pub cleanup: Option<Close>,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}; cleanup={:?}", self.cause, self.cleanup)
    }
}
impl std::error::Error for Error {}
impl From<Fault> for Error {
    fn from(cause: Fault) -> Self {
        Self {
            cause,
            cleanup: None,
        }
    }
}
/// One caller-driven turn. Dropping a drive future preserves every cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// Actual source or retained IO work.
    Activity,
    /// Caller wait elapsed without canceling original work.
    WaitDeadline,
    /// Explicitly closed.
    Stopped,
}
#[derive(Clone, Copy)]
struct Bound {
    until: u64,
    hard: Instant,
}
impl Bound {
    fn new(now: u64, d: Duration, parent: Self) -> Result<Self, Fault> {
        let micros = u64::try_from(d.as_micros()).map_err(|_| Protocol::Overflow)?;
        Ok(Self {
            until: now
                .checked_add(micros)
                .ok_or(Protocol::Overflow)?
                .min(parent.until),
            hard: Instant::now()
                .checked_add(d)
                .ok_or(Protocol::Overflow)?
                .min(parent.hard),
        })
    }
    fn expired(self, now: Option<u64>) -> bool {
        Instant::now() >= self.hard || now.is_some_and(|n| n >= self.until)
    }
}
#[derive(Clone, Copy)]
enum Role {
    Register,
    Address,
    Control,
    QueueSetup(u32),
    QueueDown,
    Incoming([u8; 8]),
    SendAck(u32),
    SendResult(u32),
    SendDown(u32),
}
struct Output<'id> {
    id: Write<'id>,
    bytes: usize,
    role: Role,
    bound: Bound,
}
struct Send {
    outcome: SendOutcome,
    ack_bytes: usize,
    ack_written: bool,
    message: [u8; 8],
    packet: Zeroizing<Vec<u8>>,
    bound: Bound,
    retry: Option<Instant>,
    status: Option<i32>,
}
struct Queue {
    id: u32,
    peer: [u8; 32],
    address: Address,
    idle: Bound,
    send: Option<Send>,
    inbound: bool,
    granted: bool,
    source: u64,
    announced: bool,
}
impl Queue {
    fn failed_send(&self) -> bool {
        self.send
            .as_ref()
            .is_some_and(|send| matches!(send.outcome, SendOutcome::Failed { .. }))
    }
    fn retire_send<'id>(
        &mut self,
        epoch: Option<Epoch<'id>>,
        socket: SocketEpoch<'id>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> bool {
        let Some(send) = self.send.take() else {
            return false;
        };
        observe(Event::SendRetired {
            epoch,
            socket,
            queue: self.id,
            message_id: send.message,
            outcome: send.outcome,
            ack_bytes: send.ack_bytes,
            ack_written: send.ack_written,
        });
        true
    }
}
struct Debt {
    flow: [u8; 8],
    peer: [u8; 32],
    bound: Bound,
    written: bool,
}
struct Input {
    source: Address,
    packet: Zeroizing<Vec<u8>>,
    bound: Bound,
}
fn transport_io(error: &io::Error) -> bool {
    if gnunet_client_host::resolution::PortError::from_io(error).is_some() {
        return false;
    }
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::WriteZero
    )
}
fn bytes(n: usize) -> Result<Vec<u8>, Fault> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Protocol::Capacity)?;
    v.resize(n, 0);
    Ok(v)
}
fn encode(request: Request<'_>) -> Result<OwnedFrame, Fault> {
    let mut b = bytes(request.encoded_len()?)?;
    request.encode(&mut b)?;
    Ok(OwnedFrame::new(b))
}
/// One original actual bound Unix source, one standard TRANSPORT MQ and one
/// public PILS observer. TRANSPORT replacement retains the actual socket/PILS
/// owners and only reannounces live metadata; old payload/callback debt retires.
/// Native socket, PILS-source, clock and protocol failures remain fail-closed.
/// A verified identity update changes only future datagram sender claims; each
/// already admitted SEND keeps its original immutable packet and completion debt.
pub struct Runtime<'id> {
    scope: Scope<'id>,
    socket_epoch: SocketEpoch<'id>,
    socket: Option<OwnedDatagram>,
    transport: Channel<Write<'id>>,
    pils: gnunet_pils_host::client::Client<'id, 1>,
    clock: Arc<dyn RuntimeClock>,
    subscription: Option<Box<dyn ClockSubscription>>,
    revision: u64,
    limits: Limits,
    parent: Bound,
    startup: Bound,
    mtu: usize,
    uri: Vec<u8>,
    peer: Option<[u8; 32]>,
    identity_expiration: Option<u64>,
    epoch: Option<Epoch<'id>>,
    next_epoch: u64,
    next_write: u64,
    next_queue: u32,
    next_flow: u64,
    outputs: VecDeque<Output<'id>>,
    queues: Vec<Option<Queue>>,
    debts: Vec<Option<Debt>>,
    buffer: Zeroizing<Vec<u8>>,
    input: Option<Input>,
    rx: Option<Bound>,
    pils_rx: Option<Bound>,
    registered: bool,
    address_written: bool,
    ever_ready: bool,
    restoring: bool,
    restore_fence: u64,
    whole_write: u64,
    next_address: u32,
    started: bool,
    bound_announced: bool,
    closed: bool,
    cursor: usize,
    send_cursor: usize,
    alarm: Option<Pin<Box<Sleep>>>,
    wait: Option<Pin<Box<Sleep>>>,
    statistics: Statistics,
}
impl<'id> Runtime<'id> {
    /// Construct actual bound socket after reserving all bounded metadata. No
    /// key material, private file, task, default resolver or peer authentication.
    pub fn bind(
        instance: &'id Instance,
        pils_instance: &'id mut gnunet_pils::client::Instance,
        sources: Sources,
        path: &[u8],
        limits: Limits,
    ) -> Result<Self, Error> {
        Self::construct(instance, pils_instance, sources, path, limits).map_err(Error::from)
    }
    fn construct(
        instance: &'id Instance,
        pils_instance: &'id mut gnunet_pils::client::Instance,
        sources: Sources,
        path: &[u8],
        limits: Limits,
    ) -> Result<Self, Fault> {
        // Parent native hard starts before subscriptions/config snapshots/samples.
        let started = Instant::now();
        limits.validate()?;
        let hard = started
            .checked_add(limits.lifetime)
            .ok_or(Protocol::Overflow)?;
        let allocation = instance
            .next
            .get()
            .checked_add(1)
            .ok_or(Protocol::Overflow)?;
        instance.next.set(allocation);
        let scope = Scope {
            owner: instance,
            allocation,
        };
        let clock = sources.transport.clock();
        if !Arc::ptr_eq(&clock, &sources.pils.clock()) {
            return Err(Protocol::Conflict.into());
        }
        let [transport_source, pils_source] =
            EndpointSource::snapshot_all([&sources.transport, &sources.pils])?;
        let subscription = clock.subscribe()?;
        let now = clock.sample()?.now.as_micros();
        let parent = Bound {
            until: now
                .checked_add(
                    u64::try_from(limits.lifetime.as_micros()).map_err(|_| Protocol::Overflow)?,
                )
                .ok_or(Protocol::Overflow)?,
            hard,
        };
        let startup = Bound {
            until: now
                .checked_add(
                    u64::try_from(limits.startup.as_micros()).map_err(|_| Protocol::Overflow)?,
                )
                .ok_or(Protocol::Overflow)?
                .min(parent.until),
            hard: started
                .checked_add(limits.startup)
                .ok_or(Protocol::Overflow)?
                .min(hard),
        };
        let cap = limits.datagram_bytes.min(if cfg!(target_os = "macos") {
            2048
        } else {
            65535
        });
        let mtu = gnunet_unix_communicator::payload_mtu(cap)?;
        let address = Address::new(path)?;
        let view = gnunet_unix_communicator::Address::from_path(path)?;
        let mut uri = bytes(view.encoded_len()?)?;
        view.encode(&mut uri)?;
        let mut queues = Vec::new();
        queues
            .try_reserve_exact(limits.queues)
            .map_err(|_| Protocol::Capacity)?;
        queues.resize_with(limits.queues, || None);
        let mut debts = Vec::new();
        debts
            .try_reserve_exact(limits.incoming)
            .map_err(|_| Protocol::Capacity)?;
        debts.resize_with(limits.incoming, || None);
        let mut outputs = VecDeque::new();
        outputs
            .try_reserve_exact(limits.output_frames)
            .map_err(|_| Protocol::Capacity)?;
        let buffer = Zeroizing::new(bytes(cap)?);
        let transport = Channel::new(
            transport_source,
            FrameLimits {
                frame_bytes: 65535,
                ordinary: Budget {
                    frames: limits.output_frames,
                    bytes: limits.output_bytes,
                },
                reserved: Budget::default(),
                accounting: Accounting::Retained,
                io_slice_bytes: limits.io_slice,
            },
        )?;
        let pils = gnunet_pils_host::client::Client::new(
            pils_instance,
            pils_source,
            limits.profile,
            gnunet_pils_host::client::Limits {
                pending_operations: 1,
                frame_bytes: 65535,
                io_slice_bytes: limits.io_slice,
            },
            gnunet_pils::HelloLimits {
                maximum_input_bytes: 65535,
                maximum_address_bytes: 61440,
                maximum_addresses: 256,
            },
        )?;
        // This is the first socket/device path operation in construction. If it
        // fails, native::Failure preserves independent cleanup in its Display.
        let socket = OwnedDatagram::bind(address, limits.socket_buffer, limits.socket_buffer)
            .map_err(|e| Fault::Io(io::Error::other(e)))?;
        Ok(Self {
            scope,
            socket_epoch: SocketEpoch { scope },
            socket: Some(socket),
            transport,
            pils,
            clock,
            subscription: Some(subscription),
            revision: 0,
            limits,
            parent,
            startup,
            mtu,
            uri,
            peer: None,
            identity_expiration: None,
            epoch: None,
            next_epoch: 0,
            next_write: 0,
            next_queue: 0,
            next_flow: 0,
            outputs,
            queues,
            debts,
            buffer,
            input: None,
            rx: None,
            pils_rx: None,
            registered: false,
            address_written: false,
            ever_ready: false,
            restoring: false,
            restore_fence: 0,
            whole_write: 0,
            next_address: 0,
            started: false,
            bound_announced: false,
            closed: false,
            cursor: 0,
            send_cursor: 0,
            alarm: None,
            wait: None,
            statistics: Statistics::default(),
        })
    }
    /// Snapshot local counts; no remote success/durability is implied.
    pub fn statistics(&self) -> Statistics {
        self.statistics
    }
    /// Actual bound-source token, unchanged for its entire ownership.
    pub fn socket_epoch(&self) -> SocketEpoch<'id> {
        self.socket_epoch
    }
    /// Complete inner MTU advertised and enforced for both independent layers.
    pub fn mtu(&self) -> usize {
        self.mtu
    }
    /// Ready only after actual PILS identity and whole registration/address writes.
    pub fn ready(&self) -> bool {
        !self.closed && self.peer.is_some() && self.registered && self.address_written
    }
    /// Last actual public identity; datagram coverage remains unauthenticated.
    pub fn peer(&self) -> Option<[u8; 32]> {
        self.peer
    }
    fn operation(&self, now: u64) -> Result<Bound, Fault> {
        Bound::new(now, self.limits.operation, self.parent)
    }
    fn room(&self, frames: usize, bytes: usize) -> bool {
        self.epoch.is_some()
            && self.outputs.len().saturating_add(frames) <= self.limits.output_frames
            && self.transport.framing().is_some_and(|f| {
                bytes <= self.limits.output_bytes.saturating_sub(f.charged_bytes())
            })
    }
    fn enqueue(
        &mut self,
        frame: OwnedFrame,
        role: Role,
        bound: Bound,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Fault> {
        let epoch = self.epoch.ok_or(Protocol::NotReady)?;
        let serial = self.next_write.checked_add(1).ok_or(Protocol::Overflow)?;
        let id = Write { epoch, serial };
        let len = frame.len();
        if !self.room(1, len) {
            return Err(Protocol::WouldBlock.into());
        }
        self.transport
            .framing_mut()
            .ok_or(Protocol::NotReady)?
            .enqueue_owned(frame, id, Class::Ordinary)
            .map_err(|e| e.reason)?;
        self.next_write = serial;
        if self.restoring
            && matches!(
                role,
                Role::Register
                    | Role::Address
                    | Role::QueueSetup(_)
                    | Role::QueueDown
                    | Role::SendDown(_)
            )
        {
            self.restore_fence = serial;
        }
        self.outputs.push_back(Output {
            id,
            bytes: 0,
            role,
            bound,
        });
        observe(Event::Queued {
            write: id,
            bytes: len,
        });
        Ok(())
    }
    fn queue_wire(&self, q: &Queue, credit: u64) -> WireQueue {
        WireQueue {
            id: q.id,
            peer: q.peer,
            network: 1,
            mtu: self.mtu as u32,
            length: credit,
            priority: 0,
            status: u32::from(q.inbound),
        }
    }
    fn queue_new(
        &mut self,
        address: Address,
        peer: [u8; 32],
        inbound: bool,
        now: u64,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<usize, Fault> {
        let index = self
            .queues
            .iter()
            .position(Option::is_none)
            .ok_or(Protocol::Capacity)?;
        let id = self.next_queue.checked_add(1).ok_or(Protocol::Overflow)?;
        let idle = Bound::new(now, self.limits.idle, self.parent)?;
        let q = Queue {
            id,
            peer,
            address,
            idle,
            send: None,
            inbound,
            granted: false,
            source: self.epoch.ok_or(Protocol::NotReady)?.serial,
            announced: false,
        };
        let view = gnunet_unix_communicator::Address::from_path(q.address.path())?;
        let mut uri = bytes(view.encoded_len()?)?;
        view.encode(&mut uri)?;
        let output = encode(Request::QueueSetup(self.queue_wire(&q, 1), &uri))?;
        let bound = self.operation(now)?;
        self.enqueue(output, Role::QueueSetup(id), bound, observe)?;
        self.next_queue = id;
        self.queues[index] = Some(q);
        self.statistics.queues += 1;
        observe(Event::Queue { id, peer, inbound });
        Ok(index)
    }
    fn announce_queue(
        &mut self,
        index: usize,
        now: u64,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Fault> {
        let epoch = self.epoch.ok_or(Protocol::NotReady)?;
        let q = self.queues[index].as_ref().ok_or(Protocol::Stale)?;
        if !self.registered || q.source == epoch.serial || q.idle.expired(Some(now)) {
            return Ok(false);
        }
        if q.send.is_some() {
            return Err(Protocol::Conflict.into());
        }
        let id = self.next_queue.checked_add(1).ok_or(Protocol::Overflow)?;
        let view = gnunet_unix_communicator::Address::from_path(q.address.path())?;
        let mut uri = bytes(view.encoded_len()?)?;
        view.encode(&mut uri)?;
        let mut wire = self.queue_wire(q, 1);
        wire.id = id;
        let request = Request::QueueSetup(wire, &uri);
        if !self.room(1, request.encoded_len()?) {
            return Ok(false);
        }
        let (peer, inbound) = (q.peer, q.inbound);
        self.enqueue(
            encode(request)?,
            Role::QueueSetup(id),
            self.operation(now)?,
            observe,
        )?;
        let q = self.queues[index].as_mut().ok_or(Protocol::Stale)?;
        q.id = id;
        q.source = epoch.serial;
        q.announced = false;
        q.granted = false;
        self.next_queue = id;
        observe(Event::Queue { id, peer, inbound });
        Ok(true)
    }
    fn reannounce(
        &mut self,
        now: u64,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Fault> {
        let Some(epoch) = self.epoch.filter(|_| self.registered) else {
            return Ok(false);
        };
        if let Some(index) = self
            .queues
            .iter()
            .position(|q| q.as_ref().is_some_and(|q| q.source != epoch.serial))
        {
            return self.announce_queue(index, now, observe);
        }
        if self.restoring
            && self.ready()
            && self.queues.iter().flatten().all(|q| q.announced)
            && self.restore_fence != 0
            && self.whole_write >= self.restore_fence
        {
            self.restoring = false;
            observe(Event::Restored {
                epoch,
                queues: self.queues.iter().flatten().count(),
            });
            return Ok(true);
        }
        Ok(false)
    }
    fn retire_transport(
        &mut self,
        observe: &mut impl FnMut(Event<'id>),
    ) -> (usize, usize, usize, usize) {
        let outputs = self.outputs.len();
        let exposed = self.outputs.iter().filter(|o| o.bytes != 0).count();
        let incoming = self.debts.iter().flatten().count();
        let mut sends = 0;
        for output in &self.outputs {
            observe(Event::OutputRetired {
                write: output.id,
                bytes: output.bytes,
            });
        }
        for debt in self.debts.iter_mut().filter_map(Option::take) {
            observe(Event::IncomingRetired {
                epoch: self.epoch,
                flow_id: debt.flow,
                peer: debt.peer,
                written: debt.written,
            });
        }
        for slot in &mut self.queues {
            let Some(queue) = slot.as_mut() else {
                continue;
            };
            let failed = queue.failed_send();
            if queue.retire_send(self.epoch, self.socket_epoch, observe) {
                sends += 1;
                // poll_send is one atomic nonblocking syscall: Pending owns no
                // in-flight native write. This cancels only the original intent;
                // actual Whole/Failed/Unknown facts remain separate below.
            }
            // A failed native destination is not live metadata to reannounce
            // after MQ replacement, even if its original DOWN was not written.
            if failed {
                *slot = None;
                self.statistics.queues -= 1;
                continue;
            }
            queue.granted = false;
            queue.announced = false;
        }
        if let Some(input) = self.input.take() {
            observe(Event::InputRetired {
                epoch: self.epoch,
                socket: self.socket_epoch,
                bytes: input.packet.len(),
            });
        }
        self.statistics.transport_failures = self
            .statistics
            .transport_failures
            .saturating_add(incoming as u64);
        self.outputs.clear();
        self.rx = None;
        self.epoch = None;
        self.registered = false;
        self.address_written = false;
        self.started = false;
        self.restoring = false;
        self.restore_fence = 0;
        self.whole_write = 0;
        (outputs, exposed, incoming, sends)
    }
    fn transport_lost(
        &mut self,
        cause: Option<io::Error>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Fault> {
        let epoch = self.epoch.ok_or(Protocol::Stale)?;
        let (input_bytes, held_input) = self.transport.framing().map_or((0, false), |f| {
            (f.read_progress_bytes(), f.frame().is_some())
        });
        // Physical retirement precedes all callback/original-byte retirement.
        // Native socket, identity, clock, queue addresses/idle and parent bounds
        // are untouched. Channel retains its original source and retry owner.
        self.transport.detach();
        let (outputs, exposed, incoming, sends) = self.retire_transport(observe);
        let retry_after = self.transport.schedule_retry()?;
        observe(Event::TransportLost {
            epoch,
            cause,
            input_bytes,
            held_input,
            outputs,
            exposed,
            incoming,
            sends,
            retry_after,
        });
        Ok(())
    }
    fn clock(&mut self, cx: &mut Context<'_>) -> Result<Option<u64>, Fault> {
        let sub = self.subscription.as_mut().ok_or(Protocol::Closed)?;
        match sub.poll_changed(cx, self.revision) {
            Poll::Ready(Err(e)) => return Err(e.into()),
            Poll::Ready(Ok(s)) => self.revision = s.revision,
            Poll::Pending => {}
        }
        let sample = self.clock.sample()?;
        match sub.poll_changed(cx, sample.revision) {
            Poll::Ready(Err(e)) => Err(e.into()),
            Poll::Ready(Ok(_)) => {
                cx.waker().wake_by_ref();
                Ok(None)
            }
            Poll::Pending => {
                self.revision = sample.revision;
                Ok(Some(sample.now.as_micros()))
            }
        }
    }
    fn earliest(&self) -> Instant {
        let mut target = self.parent.hard;
        if !self.ever_ready {
            target = target.min(self.startup.hard)
        }
        for out in &self.outputs {
            target = target.min(out.bound.hard)
        }
        for q in self.queues.iter().flatten() {
            if q.send.is_none() && q.idle.hard > Instant::now() {
                target = target.min(q.idle.hard);
            }
            if let Some(s) = &q.send {
                target = target.min(s.bound.hard);
                if let Some(retry) = s.retry {
                    target = target.min(retry)
                }
            }
        }
        if let Some(rx) = self.pils_rx {
            target = target.min(rx.hard);
        }
        if let Some(rx) = self.rx {
            target = target.min(rx.hard);
        }
        for d in self.debts.iter().flatten() {
            target = target.min(d.bound.hard)
        }
        if let Some(i) = &self.input {
            target = target.min(i.bound.hard)
        }
        target
    }
    fn alarm(&mut self, cx: &mut Context<'_>) {
        let target = self
            .earliest()
            .min(Instant::now() + Duration::from_millis(100));
        let alarm = self
            .alarm
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(target)));
        alarm.as_mut().reset(target);
        let _ready = alarm.as_mut().poll(cx);
    }
    fn expire(
        &mut self,
        now: Option<u64>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Fault> {
        if self.pils_rx.is_some_and(|b| b.expired(now))
            || self.rx.is_some_and(|b| b.expired(now))
            || self.parent.expired(now)
            || (!self.ever_ready && self.startup.expired(now))
            || self
                .identity_expiration
                .is_some_and(|e| now.is_some_and(|n| n >= e))
            || self.outputs.iter().any(|o| o.bound.expired(now))
            || self.debts.iter().flatten().any(|d| d.bound.expired(now))
            || self.input.as_ref().is_some_and(|i| i.bound.expired(now))
            || self
                .queues
                .iter()
                .flatten()
                .any(|q| q.send.as_ref().is_some_and(|s| s.bound.expired(now)))
        {
            return Err(Fault::Deadline);
        }
        for index in 0..self.queues.len() {
            let Some(q) = &self.queues[index] else {
                continue;
            };
            if q.send.is_some() || !q.idle.expired(now) {
                continue;
            }
            let current = self.epoch.is_some_and(|epoch| q.source == epoch.serial);
            let id = q.id;
            if current {
                if !q.announced || !self.room(1, 40) {
                    continue;
                }
                let Some(now) = now else { continue };
                self.enqueue(
                    encode(Request::QueueDown(id, q.peer))?,
                    Role::QueueDown,
                    self.operation(now)?,
                    observe,
                )?;
            }
            self.queues[index] = None;
            self.statistics.queues -= 1;
            observe(Event::QueueExpired(id));
            return Ok(true);
        }
        Ok(false)
    }
    fn poll_pils(
        &mut self,
        cx: &mut Context<'_>,
        now: u64,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<(), Fault>> {
        use gnunet_pils_host::client::Progress as P;
        let result = {
            let mut future = std::pin::pin!(self.pils.drive(None));
            future.as_mut().poll(cx)
        };
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(P::Inbound(gnunet_pils::client::Inbound::Identity {
                identity,
                ..
            }))) => {
                self.pils_rx = None;
                let peer = *identity.peer().as_bytes();
                // Registration, addresses, remote queue IDs and incoming FC
                // callbacks contain no local PID. Their actual MQ/socket remain
                // the same. Original SEND packets already captured their sender;
                // do not rewrite, requeue or retire those bytes on a new PID.
                self.peer = Some(peer);
                self.identity_expiration = Some(identity.expiration().as_micros());
                observe(Event::Identity {
                    peer,
                    coverage: identity.coverage(),
                });
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(P::Activity { read_bytes, .. })) => {
                if read_bytes != 0 && self.pils_rx.is_none() {
                    self.pils_rx = Some(self.operation(now)?);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(P::Inbound(_))) => {
                self.pils_rx = None;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(P::Lost { .. } | P::Closed)) => Poll::Ready(Err(Fault::IdentityLost)),
            Poll::Ready(Ok(P::Unavailable(e))) => Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(P::ConnectRetry { error, .. })) => {
                observe(Event::ConnectRetry(error));
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
        }
    }
    fn poll_connect(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<(), Fault>> {
        if self.epoch.is_some() {
            return Poll::Pending;
        }
        match self.transport.poll_connect(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(ConnectionStep::Attached)) => {
                let serial = self.next_epoch.checked_add(1).ok_or(Protocol::Overflow)?;
                let epoch = Epoch {
                    scope: self.scope,
                    serial,
                };
                self.next_epoch = serial;
                self.epoch = Some(epoch);
                self.restoring = true;
                self.restore_fence = 0;
                self.whole_write = 0;
                observe(Event::Attached(epoch));
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(ConnectionStep::Retry { error, .. })) => {
                observe(Event::ConnectRetry(error));
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(ConnectionStep::Unavailable(e))) => Poll::Ready(Err(e.into())),
        }
    }
    fn setup(&mut self, now: u64, observe: &mut impl FnMut(Event<'id>)) -> Result<bool, Fault> {
        if !self.started && self.epoch.is_some() && self.peer.is_some() {
            let a = encode(Request::Register {
                characteristics: Characteristics::Reliable,
                can_burst: false,
                prefix: b"unix",
            })?;
            let address = self.next_address.checked_add(1).ok_or(Protocol::Overflow)?;
            let b = encode(Request::AddAddress {
                id: address,
                validity: u64::MAX,
                network: 1,
                address: &self.uri,
            })?;
            let bound = self.operation(now)?;
            self.enqueue(a, Role::Register, bound, observe)?;
            self.enqueue(b, Role::Address, bound, observe)?;
            self.next_address = address;
            self.started = true;
            return Ok(true);
        }
        Ok(false)
    }
    fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<(), Fault>> {
        if self.outputs.is_empty() {
            return Poll::Pending;
        }
        match self
            .transport
            .framing_mut()
            .ok_or(Protocol::NotReady)?
            .poll_write(cx)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) if transport_io(&e) => {
                self.transport_lost(Some(e), observe)?;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(w)) => {
                let out = self.outputs.front_mut().ok_or(Protocol::Stale)?;
                if out.id != w.origin {
                    return Poll::Ready(Err(Protocol::Stale.into()));
                }
                out.bytes = out.bytes.checked_add(w.bytes).ok_or(Protocol::Overflow)?;
                if let Role::SendResult(id) = out.role {
                    let send = self
                        .queues
                        .iter_mut()
                        .flatten()
                        .find(|q| q.id == id)
                        .and_then(|q| q.send.as_mut())
                        .ok_or(Protocol::Stale)?;
                    send.ack_bytes = send
                        .ack_bytes
                        .checked_add(w.bytes)
                        .ok_or(Protocol::Overflow)?;
                    if w.complete {
                        send.ack_written = true;
                    }
                }
                observe(Event::Written {
                    write: w.origin,
                    bytes: w.bytes,
                    complete: w.complete,
                });
                if w.complete {
                    let out = self.outputs.pop_front().ok_or(Protocol::Stale)?;
                    self.whole_write = out.id.serial;
                    match out.role {
                        Role::Register => self.registered = true,
                        Role::Address => {
                            self.address_written = true;
                            if self.registered {
                                self.ever_ready = true;
                                self.transport.reset_backoff();
                            }
                        }
                        Role::QueueSetup(id) => {
                            let q = self
                                .queues
                                .iter_mut()
                                .flatten()
                                .find(|q| q.id == id)
                                .ok_or(Protocol::Stale)?;
                            if Some(q.source) != self.epoch.map(|epoch| epoch.serial) {
                                return Poll::Ready(Err(Protocol::Stale.into()));
                            }
                            if q.send.is_some() || q.announced {
                                return Poll::Ready(Err(Protocol::Conflict.into()));
                            }
                            q.announced = true;
                            q.granted = true;
                        }
                        Role::Incoming(flow) => {
                            let debt = self
                                .debts
                                .iter_mut()
                                .flatten()
                                .find(|d| d.flow == flow)
                                .ok_or(Protocol::Stale)?;
                            debt.written = true;
                            self.statistics.incoming_written =
                                self.statistics.incoming_written.saturating_add(1)
                        }
                        Role::SendAck(id) => {
                            let q = self
                                .queues
                                .iter_mut()
                                .flatten()
                                .find(|q| q.id == id)
                                .ok_or(Protocol::Stale)?;
                            q.send = None;
                            q.granted = true
                        }
                        Role::SendDown(id) => {
                            let index = self
                                .queues
                                .iter()
                                .position(|q| q.as_ref().is_some_and(|q| q.id == id))
                                .ok_or(Protocol::Stale)?;
                            let q = self.queues[index].as_mut().ok_or(Protocol::Stale)?;
                            if !q.failed_send() {
                                return Poll::Ready(Err(Protocol::Conflict.into()));
                            }
                            q.retire_send(self.epoch, self.socket_epoch, observe);
                            self.queues[index] = None;
                            self.statistics.queues -= 1;
                        }
                        Role::Control | Role::QueueDown | Role::SendResult(_) => {}
                    }
                }
                Poll::Ready(Ok(()))
            }
        }
    }
    fn dispatch(&mut self, now: u64, observe: &mut impl FnMut(Event<'id>)) -> Result<bool, Fault> {
        if !self.registered {
            return Ok(false);
        }
        // A held complete RX remains on this original MQ while capacity-bound;
        // writes and existing callbacks continue to drain independently.
        let f = self.transport.framing().ok_or(Protocol::NotReady)?;
        let Some(frame) = f.frame() else {
            return Ok(false);
        };
        let response = Response::decode(frame)?;
        if !matches!(response, Response::Received(..)) && !self.room(3, 131070) {
            return Ok(false);
        }
        match response {
            Response::Create(request, peer, address) => {
                let request_id = request;
                let remote_peer = peer;
                let existing = gnunet_unix_communicator::Address::decode(address)
                    .and_then(|v| Address::new(v.path()).map_err(|_| Protocol::InvalidInput));
                let found = existing.as_ref().ok().and_then(|a| {
                    self.queues.iter().position(|q| {
                        q.as_ref()
                            .is_some_and(|q| q.peer == remote_peer && q.address == *a)
                    })
                });
                if found.is_some_and(|index| {
                    self.queues[index].as_ref().is_some_and(Queue::failed_send)
                }) {
                    // Keep this actual CREATE and its original RX deadline
                    // until ACK/DOWN drains. It must not revive the old QID.
                    return Ok(false);
                }
                let room = self.queues.iter().any(Option::is_none);
                // Address is already owned before releasing the frame. No false
                // connection existence/authentication follows from local create.
                self.transport
                    .framing_mut()
                    .ok_or(Protocol::NotReady)?
                    .release_frame();
                self.rx = None;
                let accepted = if let Some(index) = found {
                    if self.queues[index].as_ref().ok_or(Protocol::Stale)?.source
                        != self.epoch.ok_or(Protocol::NotReady)?.serial
                    {
                        self.announce_queue(index, now, observe)?;
                    }
                    true
                } else if room {
                    match existing {
                        Ok(a) => {
                            self.queue_new(a, remote_peer, false, now, observe)?;
                            true
                        }
                        Err(_) => false,
                    }
                } else {
                    false
                };
                self.enqueue(
                    encode(Request::Created(request_id, accepted))?,
                    Role::Control,
                    self.operation(now)?,
                    observe,
                )?;
                return Ok(true);
            }
            Response::Send(id, message_id, peer, message) => {
                let Some(index) = self.queues.iter().position(|q| {
                    q.as_ref().is_some_and(|q| {
                        q.id == id
                            && q.peer == peer
                            && q.announced
                            && !q.failed_send()
                            && Some(q.source) == self.epoch.map(|epoch| epoch.serial)
                    })
                }) else {
                    // A SEND may already be in flight when its original queue
                    // expires. Official API reports GNUNET_NO, without inventing
                    // a network write or binding this id to a new address.
                    let rejected = encode(Request::Sent {
                        message_id,
                        queue: id,
                        peer,
                        status: 0,
                    })?;
                    let bound = self.rx.unwrap_or(self.operation(now)?);
                    self.transport
                        .framing_mut()
                        .ok_or(Protocol::NotReady)?
                        .release_frame();
                    self.rx = None;
                    self.enqueue(rejected, Role::Control, bound, observe)?;
                    return Ok(true);
                };
                let q = self.queues[index].as_ref().ok_or(Protocol::Stale)?;
                if !q.granted || q.send.is_some() || message.len() > self.mtu {
                    return Err(Protocol::Malformed.into());
                }
                let mut packet = Zeroizing::new(bytes(gnunet_unix_communicator::encoded_len(
                    message, self.mtu,
                )?)?);
                gnunet_unix_communicator::encode(
                    self.peer.ok_or(Protocol::NotReady)?,
                    message,
                    self.mtu,
                    &mut packet,
                )?;
                let send = Send {
                    outcome: SendOutcome::Unsent,
                    ack_bytes: 0,
                    ack_written: false,
                    message: message_id,
                    packet,
                    bound: self.operation(now)?,
                    retry: None,
                    status: None,
                };
                let q = self.queues[index].as_mut().ok_or(Protocol::Stale)?;
                q.send = Some(send);
                q.granted = false;
            }
            Response::Received(flow, peer) => {
                let index = self
                    .debts
                    .iter()
                    .position(|d| {
                        d.as_ref()
                            .is_some_and(|d| d.flow == flow && d.peer == peer && d.written)
                    })
                    .ok_or(Protocol::Stale)?;
                self.debts[index] = None;
                self.statistics.incoming_callbacks =
                    self.statistics.incoming_callbacks.saturating_add(1);
                observe(Event::Received {
                    epoch: self.epoch.ok_or(Protocol::NotReady)?,
                    flow_id: flow,
                    peer,
                });
            }
            Response::Backchannel(..) | Response::Burst(..) | Response::Unknown(_) => {
                observe(Event::UnsupportedCommand);
            }
        }
        self.transport
            .framing_mut()
            .ok_or(Protocol::NotReady)?
            .release_frame();
        self.rx = None;
        Ok(true)
    }
    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        now: u64,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<(), Fault>> {
        if self.epoch.is_none() || !self.registered {
            return Poll::Pending;
        }
        let f = self.transport.framing_mut().ok_or(Protocol::NotReady)?;
        if f.frame().is_some() {
            return Poll::Pending;
        }
        match f.poll_read(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) if transport_io(&e) => {
                self.transport_lost(Some(e), observe)?;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(ReadStep::Eof)) => {
                self.transport_lost(None, observe)?;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(ReadStep::Progress { bytes, .. })) => {
                if bytes != 0 && self.rx.is_none() {
                    self.rx = Some(self.operation(now)?);
                }
                Poll::Ready(Ok(()))
            }
        }
    }
    fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        now: u64,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<(), Fault>> {
        let epoch = self.epoch.map(|epoch| epoch.serial);
        for step in 0..self.queues.len() {
            let index = (self.send_cursor + step) % self.queues.len();
            let Some(q) = &mut self.queues[index] else {
                continue;
            };
            if !q.announced || Some(q.source) != epoch {
                continue;
            }
            let Some(send) = &mut q.send else { continue };
            if send.status.is_some() {
                continue;
            }
            if send.retry.is_some_and(|t| Instant::now() < t) {
                continue;
            }
            send.retry = None;
            let result = self.socket.as_mut().ok_or(Protocol::Closed)?.poll_send(
                cx,
                &q.address,
                &send.packet,
            );
            match result {
                Poll::Pending => {}
                Poll::Ready(Ok(n)) => {
                    if n != send.packet.len() {
                        send.outcome = SendOutcome::Unknown {
                            expected: send.packet.len(),
                            actual: n,
                        };
                        return Poll::Ready(Err(Fault::ShortDatagram {
                            expected: send.packet.len(),
                            actual: n,
                        }));
                    }
                    send.status = Some(1);
                    send.outcome = SendOutcome::Whole { bytes: n };
                    q.idle = Bound::new(now, self.limits.idle, self.parent)?;
                    self.statistics.bytes_sent =
                        self.statistics.bytes_sent.saturating_add(n as u64);
                    observe(Event::DatagramSent {
                        socket: self.socket_epoch,
                        queue: q.id,
                        message_id: send.message,
                        bytes: n,
                    });
                    self.send_cursor = (index + 1) % self.queues.len();
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(error)) => {
                    self.statistics.network_failures =
                        self.statistics.network_failures.saturating_add(1);
                    let retrying = error.raw_os_error() == Some(libc::ENOBUFS)
                        || error.kind() == io::ErrorKind::Interrupted;
                    if retrying {
                        send.retry = Some(
                            Instant::now()
                                .checked_add(self.limits.enobufs_retry)
                                .ok_or(Protocol::Overflow)?
                                .min(send.bound.hard),
                        )
                    } else {
                        send.status = Some(-1);
                        send.outcome = SendOutcome::Failed {
                            errno: error.raw_os_error(),
                            kind: error.kind(),
                        };
                    }
                    observe(Event::SendError {
                        queue: q.id,
                        message_id: send.message,
                        error,
                        retrying,
                    });
                    self.send_cursor = (index + 1) % self.queues.len();
                    return Poll::Ready(Ok(()));
                }
            }
        }
        Poll::Pending
    }
    fn send_results(
        &mut self,
        now: u64,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Fault> {
        let Some(index) = self.queues.iter().position(|q| {
            q.as_ref()
                .is_some_and(|q| q.send.as_ref().is_some_and(|s| s.status.is_some()))
        }) else {
            return Ok(false);
        };
        if !self.room(2, 116) {
            return Ok(false);
        }
        let q = self.queues[index].as_ref().ok_or(Protocol::Stale)?;
        let s = q.send.as_ref().ok_or(Protocol::Stale)?;
        let (id, peer, mid, status, bound) = (
            q.id,
            q.peer,
            s.message,
            s.status.ok_or(Protocol::Stale)?,
            s.bound,
        );
        // Both normal services discard a queue after a negative SEND result.
        // Return credit only for success. Failure keeps the original send and
        // its exposure facts until DOWN is wholly written; no old payload or
        // queue id is carried into a subsequent CREATE or source replacement.
        let (update, role) = if status == 1 {
            (
                encode(Request::QueueUpdate(self.queue_wire(q, 1)))?,
                Role::SendAck(id),
            )
        } else {
            (encode(Request::QueueDown(id, peer))?, Role::SendDown(id))
        };
        let ack = encode(Request::Sent {
            message_id: mid,
            queue: id,
            peer,
            status,
        })?;
        self.enqueue(ack, Role::SendResult(id), bound, observe)?;
        self.enqueue(update, role, bound, observe)?;
        // Mark as pending immutable result, avoiding duplicate ACK enqueue.
        let q = self.queues[index].as_mut().ok_or(Protocol::Stale)?;
        q.send.as_mut().ok_or(Protocol::Stale)?.status = None;
        q.send.as_mut().ok_or(Protocol::Stale)?.retry = Some(self.parent.hard);
        let _original_now = now;
        Ok(true)
    }
    fn poll_network(
        &mut self,
        cx: &mut Context<'_>,
        now: u64,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<(), Fault>> {
        if !self.ready() || self.input.is_some() || !self.debts.iter().any(Option::is_none) {
            return Poll::Pending;
        }
        match self
            .socket
            .as_mut()
            .ok_or(Protocol::Closed)?
            .poll_receive(cx, &mut self.buffer)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(received)) => {
                if received.truncated || received.ancillary_truncated || received.source.is_none() {
                    if let Some(error) = received.source_error {
                        observe(Event::RejectedSource(error));
                    }
                    self.statistics.invalid_inputs =
                        self.statistics.invalid_inputs.saturating_add(1);
                    observe(Event::RejectedInput {
                        bytes: received.bytes,
                        reason: Protocol::Malformed,
                    });
                    return Poll::Ready(Ok(()));
                }
                let n = received.bytes;
                if n > self.buffer.len() {
                    return Poll::Ready(Err(Protocol::Overflow.into()));
                }
                if let Err(reason) =
                    gnunet_unix_communicator::Datagram::decode(&self.buffer[..n], self.mtu)
                {
                    self.statistics.invalid_inputs =
                        self.statistics.invalid_inputs.saturating_add(1);
                    observe(Event::RejectedInput { bytes: n, reason });
                    return Poll::Ready(Ok(()));
                }
                let mut packet = Zeroizing::new(bytes(n)?);
                packet.copy_from_slice(&self.buffer[..n]);
                let source = received.source.ok_or(Protocol::Malformed)?;
                self.input = Some(Input {
                    source,
                    packet,
                    bound: self.operation(now)?,
                });
                Poll::Ready(Ok(()))
            }
        }
    }
    fn incoming(&mut self, now: u64, observe: &mut impl FnMut(Event<'id>)) -> Result<bool, Fault> {
        if self.input.is_none() || !self.ready() || !self.room(2, 131070) {
            return Ok(false);
        }
        let input = self.input.as_ref().ok_or(Protocol::Stale)?;
        let data = gnunet_unix_communicator::Datagram::decode(&input.packet, self.mtu)?;
        let peer = data.claimed_sender;
        let found = self.queues.iter().position(|q| {
            q.as_ref()
                .is_some_and(|q| q.peer == peer && q.address == input.source)
        });
        let Some(index) = found else {
            if !self.queues.iter().any(Option::is_none) {
                let input = self.input.take().ok_or(Protocol::Stale)?;
                self.statistics.invalid_inputs = self.statistics.invalid_inputs.saturating_add(1);
                observe(Event::RejectedInput {
                    bytes: input.packet.len(),
                    reason: Protocol::Capacity,
                });
                return Ok(true);
            }
            let address = Address::new(input.source.path())?;
            self.queue_new(address, peer, true, now, observe)?;
            return Ok(true);
        };
        let queue = self.queues[index].as_ref().ok_or(Protocol::Stale)?;
        if queue.failed_send() {
            // Keep the original received datagram while the failed outgoing
            // queue retires; the next turn can advertise a fresh queue.
            return Ok(false);
        }
        if queue.source != self.epoch.ok_or(Protocol::NotReady)?.serial {
            return self.announce_queue(index, now, observe);
        }
        if !queue.announced {
            return Ok(false);
        }
        let debt = self
            .debts
            .iter()
            .position(Option::is_none)
            .ok_or(Protocol::Capacity)?;
        let seq = self.next_flow.checked_add(1).ok_or(Protocol::Overflow)?;
        let flow = seq.to_be_bytes();
        let frame = encode(Request::Incoming {
            flow_control: true,
            flow_id: flow,
            validity: u64::MAX,
            peer,
            neighbour: [0; 32],
            message: data.message,
        })?;
        let input = self.input.take().ok_or(Protocol::Stale)?;
        self.enqueue(frame, Role::Incoming(flow), input.bound, observe)?;
        self.next_flow = seq;
        self.debts[debt] = Some(Debt {
            flow,
            peer,
            bound: input.bound,
            written: false,
        });
        self.queues[index].as_mut().ok_or(Protocol::Stale)?.idle =
            Bound::new(now, self.limits.idle, self.parent)?;
        Ok(true)
    }
    fn step(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<Instant>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Fault>> {
        if self.closed {
            return Poll::Ready(Ok(Progress::Stopped));
        }
        let expired = self.expire(None, observe)?;
        self.alarm(cx); // Native hard independent of a racing/failed logical clock.
        if expired {
            return Poll::Ready(Ok(Progress::Activity));
        }
        let Some(now) = self.clock(cx)? else {
            return Poll::Pending;
        };
        let expired = self.expire(Some(now), observe)?;
        self.alarm(cx);
        if expired {
            return Poll::Ready(Ok(Progress::Activity));
        }
        match self.transport.poll_clock(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(())) => {}
        }
        if !self.bound_announced {
            self.bound_announced = true;
            observe(Event::Bound(self.socket_epoch));
            return Poll::Ready(Ok(Progress::Activity));
        }
        if self.setup(now, observe)?
            || self.incoming(now, observe)?
            || self.send_results(now, observe)?
            || self.dispatch(now, observe)?
        {
            return Poll::Ready(Ok(Progress::Activity));
        }
        for offset in 0..7 {
            let index = (self.cursor + offset) % 7;
            let result = match index {
                0 => self.poll_pils(cx, now, observe),
                1 => self.poll_connect(cx, observe),
                2 => self.poll_write(cx, observe),
                3 => self.poll_read(cx, now, observe),
                4 => self.poll_send(cx, now, observe),
                5 => self.poll_network(cx, now, observe),
                _ => match self.reannounce(now, observe) {
                    Ok(true) => Poll::Ready(Ok(())),
                    Ok(false) => Poll::Pending,
                    Err(error) => Poll::Ready(Err(error)),
                },
            };
            if let Poll::Ready(result) = result {
                self.cursor = (index + 1) % 7;
                result?;
                return Poll::Ready(Ok(Progress::Activity));
            }
        }
        if let Some(target) = wait {
            let timer = self
                .wait
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(target)));
            timer.as_mut().reset(target);
            if timer.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Ok(Progress::WaitDeadline));
            }
        }
        Poll::Pending
    }
    /// Poll one bounded fair turn. Every fatal error first physically closes the
    /// actual socket/MQs without sampling a clock, then returns original cause.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<Instant>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        match self.step(cx, wait, observe) {
            Poll::Ready(Err(cause)) => {
                let cleanup = self.close(observe);
                Poll::Ready(Err(Error {
                    cause,
                    cleanup: Some(cleanup),
                }))
            }
            Poll::Ready(Ok(p)) => Poll::Ready(Ok(p)),
            Poll::Pending => Poll::Pending,
        }
    }
    /// Cancellation of this future preserves retained original bytes/cursors.
    pub async fn drive(
        &mut self,
        wait: Option<Instant>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<Progress, Error> {
        poll_fn(|cx| self.poll(cx, wait, observe)).await
    }
    /// Immediate physical cancellation. UNIX has no private wire CANCEL/ACK.
    /// No uncertain old callback/send/stream debt is retagged into another MQ.
    pub fn close(&mut self, observe: &mut impl FnMut(Event<'id>)) -> Close {
        // Stop physical owners before retiring exact original byte/callback debt.
        self.transport.close();
        let _canceled = self.pils.close();
        let datagram = self.socket.take().map(|mut socket| socket.close());
        let (outputs, exposed, incoming, sends) = self.retire_transport(observe);
        for row in &mut self.queues {
            *row = None;
        }
        self.pils_rx = None;
        self.subscription = None;
        self.alarm = None;
        self.wait = None;
        self.epoch = None;
        self.peer = None;
        self.statistics.queues = 0;
        self.closed = true;
        observe(Event::Closed {
            outputs,
            exposed,
            incoming,
            sends,
        });
        Close {
            outputs,
            exposed,
            incoming,
            sends,
            datagram,
        }
    }
}
impl Drop for Runtime<'_> {
    fn drop(&mut self) {
        if !self.closed {
            let _actual = self.close(&mut |_| {});
        }
    }
}

#[cfg(test)]
mod tests;
