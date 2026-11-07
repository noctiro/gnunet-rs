//! Caller-driven native CADET application SERVICE streams.
//!
//! This owner attaches only actual accepted MQs. Ordinary application traffic,
//! original partial cursors and immutable output effects are owned here; real
//! remote channel/tunnel work remains an explicit external peer coordinator.
use crate::management;
use gnunet_cadet::{peer, service as core};
/// Shared actual kernel Unix credential admission policy.
pub use gnunet_service_runtime::credentials::UnixAccess;
use gnunet_service_runtime::{
    accepted::{AcceptState, AcceptedConnection, SocketEvent},
    clock::{ClockSubscription, RuntimeClock},
    framing::{Accounting, Budget, Class, Framed, Limits as FrameLimits, OwnedFrame, ReadStep},
    service::{Listener, PeerAddress, ServiceOptions, ShutdownMode},
};
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
use gnunet_wire::official::{MessageHeader, cadet::Request};
use std::{
    fmt,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::time::{Instant, Sleep};

/// Original native or pure-service cause, without replacement by success.
#[derive(Debug)]
pub enum Error {
    /// Actual native transport/credential failure with its original errno.
    Io(io::Error),
    /// Official framing, original owner or explicit resource refusal.
    Protocol(ProtocolError),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "CADET application service IO: {error}"),
            Self::Protocol(error) => write!(f, "CADET application service: {error}"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Protocol(error) => Some(error),
        }
    }
}
impl From<ProtocolError> for Error {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}
/// Original reason for physically closing one actual accepted MQ.
#[derive(Debug)]
pub enum CloseCause {
    /// Actual clean socket EOF between complete frames.
    Eof,
    /// Actual original read, write, protocol or owner fault.
    Fault(Error),
    /// Explicit caller retirement of this exact original MQ.
    Requested,
    /// Explicit immediate local service shutdown.
    Shutdown,
}
/// Explicit bounded native storage and one-operation IO quantum.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum retained actual accepted socket owners. Match the supplied pure
    /// service's client table; extra native capacity cannot create pure clients.
    pub clients: usize,
    /// Maximum bytes in one actual native read/write, nonzero.
    pub io_slice_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            clients: 128,
            io_slice_bytes: 65535,
        }
    }
}
impl Limits {
    fn framing(self) -> FrameLimits {
        FrameLimits {
            frame_bytes: 65535,
            ordinary: Budget {
                frames: 1,
                bytes: 65535,
            },
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: self.io_slice_bytes,
        }
    }
}
/// Resource stage whose original work remains retained for retry or explicit close.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockedAt {
    /// Complete original native input has not been accepted by the pure service.
    Input,
    /// Original output intent or already frozen rejected frame is still retained.
    Output,
}
/// Synchronous actual native/service observations. A callback must not reenter
/// this owner. No event claims peer-channel or remote application delivery.
pub enum Event<'id> {
    /// Canonical native acceptance diagnostics in original syscall order.
    Socket(SocketEvent),
    /// One original explicit-Destroy drain expired. No send ACK or successful
    /// remote delivery is inferred; its actual channel enters normal retirement.
    DrainExpired(core::Channel<'id>),
    /// Actual management query/output/loss; ordinary application origins remain separate.
    Management(management::Event<'id>),
    /// Address/Unix credentials rejected an unadmitted physical stream.
    Rejected(PeerAddress),
    /// Original admission failure; its unadmitted stream is already closed.
    AdmissionFailed(Error),
    /// Actual socket passed policy and attached its original pure MQ generation.
    Accepted {
        /// Original actual accepted source, never reconstructed from a raw integer.
        client: core::Client<'id>,
        /// Address of that original socket.
        peer: PeerAddress,
    },
    /// Actual complete CLIENT request accepted by its original pure source.
    Input {
        /// Exact original accepted source.
        client: core::Client<'id>,
        /// Actual local service result; source credit and peer proof remain separate.
        event: core::Event<'id>,
    },
    /// TOLERANT discarded only an unknown official outer message type.
    IgnoredUnknown {
        /// Original actual accepted source.
        client: core::Client<'id>,
        /// Actual unknown raw wire type.
        message_type: u16,
    },
    /// Original resource refusal retained its complete input, output intent or
    /// frozen rejected frame. Repeated unchanged refusal emits no busy-loop event.
    Blocked {
        /// Original actual accepted source.
        client: core::Client<'id>,
        /// Original retained stage.
        stage: BlockedAt,
        /// Actual bounded refusal, never a fabricated acknowledgement.
        reason: ProtocolError,
    },
    /// One real own-peer incoming endpoint bound to a registered application.
    LocalBound(core::Channel<'id>),
    /// Exact immutable ordinary IPC frame admitted to its original MQ FIFO.
    Queued(core::Output<'id>),
    /// One actual positive original write, before any later input processing.
    Write {
        /// Original immutable frame and exact accepted-MQ generation.
        output: core::Output<'id>,
        /// Actual bytes in this one syscall.
        bytes: usize,
        /// Whether this original frame really finished writing.
        complete: bool,
    },
    /// Original socket and partial cursors stopped before pure detach. Remote
    /// peer cleanup remains explicit through the original core effect ports.
    Closed {
        /// Original pure retirement facts, including pending output/exposure.
        loss: core::Loss<'id>,
        /// Original closure cause preserved without an outcome substitution.
        cause: CloseCause,
    },
}
/// One bounded native/scheduling step, without implicit peer/backend success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// One actual bounded local IO, dispatch, output or loopback step.
    Activity,
    /// One actual accepted stream attached.
    Accepted,
    /// Observation deadline ended; original cursors and work remain owned.
    WaitDeadline,
    /// All local MQs stopped after shutdown. External peer cleanup is independent
    /// and can still be driven through this owner's explicit peer-effect methods.
    Stopped,
}
/// Actual native counters. These are not peer-delivery or application-work receipts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Report {
    /// Actual accepted MQ generations attached.
    pub accepted: u64,
    /// Complete official application or management CLIENT frames admitted.
    pub inputs: u64,
    /// Unknown outer frames ignored only under explicit TOLERANT policy.
    pub ignored: u64,
    /// Immutable original frames admitted for actual local socket output.
    pub outputs: u64,
    /// Original frames that actually finished writing.
    pub written_frames: u64,
    /// Actual positive native write bytes.
    pub written_bytes: u64,
    /// Actual positive native read bytes.
    pub read_bytes: u64,
    /// Actual admitted physical MQs closed.
    pub closed: u64,
    /// Original finite explicit-Destroy drains that actually expired.
    pub destroy_timeouts: u64,
}
#[derive(Clone, Copy)]
enum Origin<'id> {
    Application(core::Output<'id>),
    Management(management::Output<'id>),
}
struct Stopped<'id> {
    loss: core::Loss<'id>,
    management: Option<management::Report<'id>>,
}
#[derive(Clone, Copy)]
struct Drain<'id> {
    channel: core::Channel<'id>,
    expires: AbsoluteTime,
    hard: Instant,
}
// Native local policy, not a field or acknowledgement on the public wire.
const DESTROY_DRAIN: Duration = Duration::from_secs(120);
struct Peer<'id> {
    client: core::Client<'id>,
    framed: Framed<Origin<'id>>,
    // Unexpected enqueue rejection retains the exact original immutable body;
    // pure output must never be regenerated after its shared payload was freed.
    held: Option<(OwnedFrame, Origin<'id>)>,
    input_blocked: Option<ProtocolError>,
    output_blocked: Option<ProtocolError>,
    cursor: u8,
    application: bool,
    management: Option<management::Stream<'id>>,
}
/// Native application listener driver over one already constructed pure service.
/// Startup/Activation/BoundListeners remain caller-owned; this opens no listener,
/// resolver, task or thread. Transfer a service with no preattached MQs here.
/// Each peer holds one RX buffer and at most one immutable pending output.
/// A classified manager may additionally retain one explicitly bounded snapshot.
pub struct Server<'id, 'slots, 'bytes> {
    // Physical owners drop before pure state. Drop also explicitly retires every
    // stream before detaching its original pure source.
    peers: Vec<Option<Peer<'id>>>,
    core: core::Service<'id, 'slots, 'bytes>,
    limits: Limits,
    options: ServiceOptions,
    unix: UnixAccess,
    clock: Arc<dyn RuntimeClock>,
    accept: AcceptState,
    cursor: usize,
    listener_cursor: usize,
    class_cursor: u8,
    shutdown: Option<ShutdownMode>,
    wait: Option<Pin<Box<Sleep>>>,
    wake: Option<Waker>,
    report: Report,
    management: Option<management::Limits>,
    next_query: u64,
    management_cursor: usize,
    drains: Vec<Option<Drain<'id>>>,
    drain_clock: Box<dyn ClockSubscription>,
    drain_revision: u64,
    drain_timer: Option<Pin<Box<Sleep>>>,
}
impl<'id, 'slots, 'bytes> Server<'id, 'slots, 'bytes> {
    /// Reserve native metadata before admitting any socket. The caller supplies
    /// actual identity/configured ACLs/Unix policy and one shared clock domain.
    pub fn new(
        service: core::Service<'id, 'slots, 'bytes>,
        limits: Limits,
        options: ServiceOptions,
        unix: UnixAccess,
        clock: Arc<dyn RuntimeClock>,
    ) -> Result<Self, Error> {
        if limits.clients == 0 || limits.io_slice_bytes == 0 {
            return Err(ProtocolError::InvalidInput.into());
        }
        limits.framing().validate()?;
        let drain_clock = clock.subscribe()?;
        let drain_revision = clock.sample()?.revision;
        let mut drains = Vec::new();
        drains
            .try_reserve_exact(service.channel_capacity())
            .map_err(|_| ProtocolError::Capacity)?;
        drains.resize(service.channel_capacity(), None);
        let mut peers = Vec::new();
        peers
            .try_reserve_exact(limits.clients)
            .map_err(|_| ProtocolError::Capacity)?;
        peers.resize_with(limits.clients, || None);
        Ok(Self {
            peers,
            core: service,
            limits,
            options,
            unix,
            clock,
            accept: AcceptState::default(),
            cursor: 0,
            listener_cursor: 0,
            class_cursor: 0,
            shutdown: None,
            wait: None,
            wake: None,
            report: Report::default(),
            management: None,
            next_query: 0,
            management_cursor: 0,
            drains,
            drain_clock,
            drain_revision,
            drain_timer: None,
        })
    }
    /// Same original shared clock for an explicit external peer coordinator.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    /// Current local peer identity supplied by the identity owner.
    #[must_use]
    pub fn local_peer(&self) -> [u8; 32] {
        self.core.local_peer()
    }
    /// Retire identity-bound logical channels without closing application MQs
    /// or changing retained native cursors. External peer effects remain debts.
    pub fn retire_identity_channels(&mut self) -> Result<(), ProtocolError> {
        self.core.retire_identity_channels()?;
        self.changed();
        Ok(())
    }
    /// Rebind registered listeners after actual peer retirement. Frozen native
    /// frames stay on their original MQ with their original write bounds.
    pub fn rebind_local_peer(&mut self, peer: [u8; 32]) -> Result<(), ProtocolError> {
        self.core.rebind_local_peer(peer)?;
        self.changed();
        Ok(())
    }
    /// Read the pure application's cut barrier without dispatching or consuming
    /// any peer-close effect. Independent native retirement remains external.
    #[must_use]
    pub fn identity_channels_retired(&self) -> bool {
        self.core.identity_channels_retired()
    }
    /// Snapshot actual native counters without granting any protocol authority.
    #[must_use]
    pub const fn report(&self) -> &Report {
        &self.report
    }
    /// Enumerate only actual currently attached native MQ generations.
    pub fn clients(&self) -> impl Iterator<Item = core::Client<'id>> + '_ {
        self.peers.iter().flatten().map(|peer| peer.client)
    }
    /// Current exact local endpoint state; no output/write receipt is created.
    pub fn channel_info(
        &self,
        channel: core::Channel<'id>,
    ) -> Result<core::ChannelInfo, ProtocolError> {
        self.core.channel_info(channel)
    }
    /// Exact currently owned logical registration bytes.
    /// Match only an actually registered local listener's official challenge.
    #[must_use]
    pub fn resolve_port_challenge(&self, challenge: &[u8; 64]) -> Option<[u8; 64]> {
        self.core.resolve_port_challenge(challenge)
    }
    /// Actual currently owned logical port bytes; stale owner handles refuse.
    pub fn port_hash(&self, port: core::Port<'id>) -> Result<[u8; 64], ProtocolError> {
        self.core.port_hash(port)
    }
    /// Original still-retained source bytes, before real output/peer ownership transfer.
    pub fn message_bytes(&self, message: core::Message<'id>) -> Result<&[u8], ProtocolError> {
        self.core.message_bytes(message)
    }
    /// Enable an explicit actual snapshot provider. Node invokes this only
    /// when it owns the Book/controller/channel directory. No END is produced.
    pub fn enable_management(
        &mut self,
        mut limits: management::Limits,
    ) -> Result<(), ProtocolError> {
        limits.validate()?;
        // Known slow management MQs leave one ordinary admission slot whenever
        // the caller configured more than one native client slot.
        limits.queries = limits
            .queries
            .min(self.limits.clients.saturating_sub(1).max(1));
        if self.management == Some(limits) {
            return Ok(());
        }
        if self.peers.iter().flatten().any(|p| p.management.is_some()) {
            return Err(ProtocolError::WouldBlock);
        }
        self.management = Some(limits);
        self.changed();
        Ok(())
    }
    /// One original query awaiting its actual complete provider capture. Calls
    /// rotate across MQs; another slow query/output cannot own this cursor.
    pub fn pending_management(&mut self) -> Option<management::Query<'id>> {
        for offset in 0..self.peers.len() {
            let i = (self.management_cursor + offset) % self.peers.len();
            if let Some(query) = self.peers[i]
                .as_ref()
                .and_then(|p| p.management.as_ref())
                .and_then(management::Stream::awaiting)
            {
                self.management_cursor = (i + 1) % self.peers.len();
                return Some(query);
            }
        }
        None
    }
    /// Bind this exact completed actual snapshot to its original MQ/query. A
    /// stale source or mismatched kind cannot replace a current query or emit END.
    pub fn bind_management(
        &mut self,
        query: management::Query<'id>,
        snapshot: management::Snapshot,
    ) -> Result<(), ProtocolError> {
        let limits = self.management.ok_or(ProtocolError::Unsupported)?;
        if snapshot.bytes() > limits.snapshot_bytes || snapshot.records() > limits.records {
            return Err(ProtocolError::Capacity);
        }
        let peer = self
            .peers
            .iter_mut()
            .flatten()
            .find(|p| p.client == query.client())
            .ok_or(ProtocolError::StaleGeneration)?;
        peer.management
            .as_mut()
            .ok_or(ProtocolError::StaleGeneration)?
            .bind(query, snapshot)?;
        self.changed();
        Ok(())
    }
    /// Actual current/last management progress on this exact still-attached
    /// MQ. This readonly view cannot turn a pending query into an END receipt.
    pub fn management_report(
        &self,
        client: core::Client<'id>,
    ) -> Result<Option<management::Report<'id>>, ProtocolError> {
        let peer = self
            .peers
            .iter()
            .flatten()
            .find(|p| p.client == client)
            .ok_or(ProtocolError::StaleGeneration)?;
        Ok(peer
            .management
            .as_ref()
            .and_then(management::Stream::report))
    }
    fn accept_management(
        &mut self,
        index: usize,
        kind: management::Kind,
    ) -> Result<management::Query<'id>, ProtocolError> {
        let limits = self.management.ok_or(ProtocolError::Unsupported)?;
        let peer = self.peers[index]
            .as_ref()
            .ok_or(ProtocolError::StaleGeneration)?;
        if peer.application {
            return Err(ProtocolError::Unsupported);
        }
        if peer.management.is_none()
            && self
                .peers
                .iter()
                .flatten()
                .filter(|p| p.management.is_some())
                .count()
                >= limits.queries
        {
            return Err(ProtocolError::Capacity);
        }
        let serial = self
            .next_query
            .checked_add(1)
            .ok_or(ProtocolError::Overflow)?;
        let query = management::Query::new(peer.client, serial, kind);
        let peer = self.peers[index]
            .as_mut()
            .ok_or(ProtocolError::StaleGeneration)?;
        let stream = peer.management.get_or_insert_with(management::Stream::new);
        stream.request(query)?;
        self.next_query = serial;
        Ok(query)
    }
    fn queued(origin: Origin<'id>, observe: &mut impl FnMut(Event<'id>)) {
        match origin {
            Origin::Application(output) => observe(Event::Queued(output)),
            Origin::Management(output) => {
                observe(Event::Management(management::Event::Queued(output)))
            }
        }
    }
    fn changed(&mut self) {
        if let Some(wake) = self.wake.take() {
            wake.wake();
        }
    }
    /// Admit an actual canonically accepted stream supplied by the runtime.
    /// ACL/credentials and all framing allocations precede pure `attach()`.
    /// Rejection closes only this original stream; no pure client is minted.
    pub fn admit(
        &mut self,
        accepted: AcceptedConnection,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<Option<core::Client<'id>>, Error> {
        let (connection, address, diagnostics) = accepted.into_parts();
        for diagnostic in diagnostics {
            observe(Event::Socket(SocketEvent::Diagnostic(diagnostic)));
        }
        let allowed = match address {
            PeerAddress::Tcp(address) => self.options.access.allows(address.ip()),
            PeerAddress::Unix => self.unix.allows(&connection).map_err(Error::Io)?,
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
        let Some(index) = self.peers.iter().position(Option::is_none) else {
            drop(connection);
            return Err(ProtocolError::Capacity.into());
        };
        let mut framed = Framed::new(connection, self.limits.framing())?;
        let client = match self.core.attach() {
            Ok(client) => client,
            Err(error) => {
                framed.retire();
                return Err(error.into());
            }
        };
        self.peers[index] = Some(Peer {
            client,
            framed,
            held: None,
            input_blocked: None,
            output_blocked: None,
            cursor: 0,
            application: false,
            management: None,
        });
        self.report.accepted = self.report.accepted.saturating_add(1);
        observe(Event::Accepted {
            client,
            peer: address,
        });
        self.changed();
        Ok(Some(client))
    }
    fn stop_index(&mut self, index: usize) -> Result<Stopped<'id>, Error> {
        let mut peer = self.peers[index]
            .take()
            .ok_or(ProtocolError::StaleGeneration)?;
        let management = peer
            .management
            .as_ref()
            .and_then(management::Stream::stopped);
        peer.framed.retire();
        drop(peer.held.take());
        self.accept.client_closed();
        self.report.closed = self.report.closed.saturating_add(1);
        let loss = self.core.detach(peer.client)?;
        for slot in &mut self.drains {
            if slot.is_some_and(|d| d.channel.client() == peer.client) {
                *slot = None;
            }
        }
        self.changed();
        Ok(Stopped { loss, management })
    }
    fn close_index(
        &mut self,
        index: usize,
        cause: CloseCause,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<core::Loss<'id>, Error> {
        let stopped = self.stop_index(index)?;
        if let Some(report) = stopped.management {
            observe(Event::Management(management::Event::Stopped(report)));
        }
        observe(Event::Closed {
            loss: stopped.loss,
            cause,
        });
        Ok(stopped.loss)
    }
    /// Official observations from the original application service domain.
    #[must_use]
    pub fn statistics(&self) -> gnunet_cadet::statistics::Snapshot {
        self.core
            .statistics()
            .with_native_clients(self.peers.iter().filter(|p| p.is_some()).count())
    }
    /// Physically stop one exact original native MQ, then detach it and return
    /// original pending/exposure facts. Useful for explicitly retiring a source
    /// whose retained resource refusal cannot progress under caller policy.
    pub fn close(
        &mut self,
        client: core::Client<'id>,
        cause: CloseCause,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<core::Loss<'id>, Error> {
        let index = self
            .peers
            .iter()
            .position(|peer| peer.as_ref().is_some_and(|peer| peer.client == client))
            .ok_or(ProtocolError::StaleGeneration)?;
        self.close_index(index, cause, observe)
    }
    /// Physically retire all currently accepted MQs without sampling a clock.
    /// Every successful original detach emits its exact Loss. A refused pure
    /// cleanup is retained as first error while the remaining sockets still stop.
    pub fn close_all(&mut self, observe: &mut impl FnMut(Event<'id>)) -> Result<(), Error> {
        self.request_shutdown(ShutdownMode::Immediate);
        let mut first = None;
        for index in 0..self.peers.len() {
            if self.peers[index].is_some()
                && let Err(error) = self.close_index(index, CloseCause::Shutdown, observe)
                && first.is_none()
            {
                first = Some(error);
            }
        }
        match first {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
    /// Stop accepting. Immediate closes one actual MQ per bounded poll; Soft
    /// keeps existing applications usable until they close or the caller retires
    /// them explicitly. Neither mode pretends external peer work has settled.
    pub fn request_shutdown(&mut self, mode: ShutdownMode) {
        if self.shutdown != Some(ShutdownMode::Immediate) {
            self.shutdown = Some(mode);
        }
        self.changed();
    }
    fn mark_blocked(
        peer: &mut Peer<'id>,
        stage: BlockedAt,
        reason: ProtocolError,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Progress> {
        let previous = match stage {
            BlockedAt::Input => &mut peer.input_blocked,
            BlockedAt::Output => &mut peer.output_blocked,
        };
        if *previous == Some(reason) {
            return Poll::Pending;
        }
        *previous = Some(reason);
        observe(Event::Blocked {
            client: peer.client,
            stage,
            reason,
        });
        Poll::Ready(Progress::Activity)
    }
    fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        index: usize,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        let Some(peer) = self.peers[index].as_mut() else {
            return Poll::Pending;
        };
        let progress = match peer.framed.poll_write(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => {
                return Poll::Ready(
                    self.close_index(index, CloseCause::Fault(Error::Io(error)), observe)
                        .map(|_| Progress::Activity),
                );
            }
            Poll::Ready(Ok(progress)) => progress,
        };
        self.report.written_bytes = self
            .report
            .written_bytes
            .saturating_add(progress.bytes as u64);
        if progress.complete {
            self.report.written_frames = self.report.written_frames.saturating_add(1);
        }
        let settled = match progress.origin {
            Origin::Application(output) => self
                .core
                .exposed(output)
                .and_then(|()| {
                    if progress.complete {
                        self.core.written(output)
                    } else {
                        Ok(())
                    }
                })
                .map(|()| None),
            Origin::Management(output) => self.peers[index]
                .as_mut()
                .and_then(|p| p.management.as_mut())
                .ok_or(ProtocolError::StaleGeneration)
                .and_then(|stream| stream.written(output, progress.bytes, progress.complete))
                .map(Some),
        };
        let (report, stopped) = match settled {
            Ok(report) => (report, None),
            Err(reason) => match self.stop_index(index) {
                Ok(stopped) => (None, Some((stopped, reason))),
                Err(error) => return Poll::Ready(Err(error)),
            },
        };
        // Actual effects precede callbacks, including every partial management
        // write. Opaque origins never cross application/management ownership.
        match progress.origin {
            Origin::Application(output) => observe(Event::Write {
                output,
                bytes: progress.bytes,
                complete: progress.complete,
            }),
            Origin::Management(output) => {
                if let Some(report) = report {
                    observe(Event::Management(management::Event::Write {
                        output,
                        bytes: progress.bytes,
                        complete: progress.complete,
                        report,
                    }));
                }
            }
        }
        if let Some((stopped, reason)) = stopped {
            if let Some(report) = stopped.management {
                observe(Event::Management(management::Event::Stopped(report)));
            }
            observe(Event::Closed {
                loss: stopped.loss,
                cause: CloseCause::Fault(reason.into()),
            });
        }
        Poll::Ready(Ok(Progress::Activity))
    }
    fn destroy_bound(&self) -> Result<(AbsoluteTime, Instant), ProtocolError> {
        let hard = Instant::now()
            .checked_add(DESTROY_DRAIN)
            .ok_or(ProtocolError::Overflow)?;
        let expires = AbsoluteTime::from_micros(
            self.clock
                .sample()?
                .now
                .as_micros()
                .checked_add(120_000_000)
                .filter(|v| *v != u64::MAX)
                .ok_or(ProtocolError::Overflow)?,
        );
        if Instant::now() >= hard {
            return Err(ProtocolError::Deadline);
        }
        Ok((expires, hard))
    }
    fn register_drain(
        &mut self,
        channel: core::Channel<'id>,
        bound: (AbsoluteTime, Instant),
    ) -> Result<(), ProtocolError> {
        if self.drains.iter().flatten().any(|d| d.channel == channel) {
            return Ok(());
        }
        // The table was reserved before native admission, one row per pure
        // channel. Old generations are removed before any subsequent dispatch.
        let slot = self
            .drains
            .iter_mut()
            .find(|d| d.is_none())
            .ok_or(ProtocolError::Conflict)?;
        *slot = Some(Drain {
            channel,
            expires: bound.0,
            hard: bound.1,
        });
        Ok(())
    }
    fn poll_drains(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        if self.drains.iter().all(Option::is_none) {
            self.drain_timer = None;
            return Ok(false);
        }
        // Native expiry wins before any possibly failing clock provider.
        let mut native_change = false;
        for slot in &mut self.drains {
            let Some(drain) = *slot else {
                continue;
            };
            if !self
                .core
                .channel_info(drain.channel)
                .is_ok_and(|i| i.draining)
            {
                *slot = None;
                native_change = true;
                continue;
            }
            if Instant::now() >= drain.hard {
                self.core.expire_destroy(drain.channel)?;
                *slot = None;
                self.report.destroy_timeouts = self.report.destroy_timeouts.saturating_add(1);
                observe(Event::DrainExpired(drain.channel));
                native_change = true;
            }
        }
        if native_change {
            return Ok(true);
        }
        if let Poll::Ready(result) = self.drain_clock.poll_changed(cx, self.drain_revision) {
            self.drain_revision = result?.revision;
        }
        let sample = self.clock.sample()?;
        self.drain_revision = sample.revision;
        let mut changed = false;
        for slot in &mut self.drains {
            let Some(drain) = *slot else {
                continue;
            };
            if !self
                .core
                .channel_info(drain.channel)
                .is_ok_and(|i| i.draining)
            {
                *slot = None;
                changed = true;
                continue;
            }
            if Instant::now() >= drain.hard || sample.now >= drain.expires {
                self.core.expire_destroy(drain.channel)?;
                *slot = None;
                self.report.destroy_timeouts = self.report.destroy_timeouts.saturating_add(1);
                observe(Event::DrainExpired(drain.channel));
                changed = true;
            }
        }
        let target = self.drains.iter().flatten().map(|d| d.hard).min();
        if let Some(target) = target {
            let timer = self
                .drain_timer
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(target)));
            timer.as_mut().reset(target);
            if timer.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        } else {
            self.drain_timer = None;
        }
        Ok(changed)
    }
    fn poll_input(
        &mut self,
        cx: &mut Context<'_>,
        index: usize,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        let Some(peer) = self.peers[index].as_ref() else {
            return Poll::Pending;
        };
        let client = peer.client;
        if peer
            .management
            .as_ref()
            .is_some_and(management::Stream::active)
            && peer.framed.frame().is_some()
        {
            return Poll::Pending;
        }
        if let Some(bytes) = peer.framed.frame() {
            let query = match management::decode_query(bytes) {
                Ok(query) => query,
                Err(reason) => {
                    return Poll::Ready(
                        self.close_index(index, CloseCause::Fault(reason.into()), observe)
                            .map(|_| Progress::Activity),
                    );
                }
            };
            if let Some(kind) = query {
                match self.accept_management(index, kind) {
                    Ok(query) => {
                        let peer = self.peers[index]
                            .as_mut()
                            .ok_or(ProtocolError::StaleGeneration)?;
                        peer.framed.release_frame();
                        peer.input_blocked = None;
                        self.report.inputs = self.report.inputs.saturating_add(1);
                        observe(Event::Management(management::Event::Requested(query)));
                        return Poll::Ready(Ok(Progress::Activity));
                    }
                    Err(reason @ (ProtocolError::Capacity | ProtocolError::WouldBlock)) => {
                        return Self::mark_blocked(
                            self.peers[index]
                                .as_mut()
                                .ok_or(ProtocolError::StaleGeneration)?,
                            BlockedAt::Input,
                            reason,
                            observe,
                        )
                        .map(Ok);
                    }
                    Err(reason) => {
                        return Poll::Ready(
                            self.close_index(index, CloseCause::Fault(reason.into()), observe)
                                .map(|_| Progress::Activity),
                        );
                    }
                }
            }
            if self.peers[index]
                .as_ref()
                .is_some_and(|p| p.management.is_some())
            {
                return Poll::Ready(
                    self.close_index(
                        index,
                        CloseCause::Fault(ProtocolError::Unsupported.into()),
                        observe,
                    )
                    .map(|_| Progress::Activity),
                );
            }
            let bytes = self.peers[index]
                .as_ref()
                .and_then(|p| p.framed.frame())
                .ok_or(ProtocolError::StaleGeneration)?;
            enum Dispatch<'id> {
                Input(core::Event<'id>),
                Ignored(u16),
                Refused(ProtocolError),
            }
            let dispatch = match Request::decode(bytes) {
                Ok(request) => {
                    // Capture before this original Destroy admission; duplicates
                    // never replace the first row's targets. No phase renews it.
                    let bound = if matches!(request, Request::ChannelDestroy { .. }) {
                        Some(self.destroy_bound()?)
                    } else {
                        None
                    };
                    match self.core.receive(client, request) {
                        Ok(event) => {
                            if let core::Event::ChannelDraining(channel) = event {
                                self.register_drain(
                                    channel,
                                    bound.ok_or(ProtocolError::Conflict)?,
                                )?;
                            }
                            Dispatch::Input(event)
                        }
                        Err(error) => Dispatch::Refused(error),
                    }
                }
                Err(ProtocolError::Unsupported) if self.options.tolerant => {
                    match MessageHeader::decode(bytes) {
                        Ok(header) => Dispatch::Ignored(header.message_type().value()),
                        Err(error) => Dispatch::Refused(error),
                    }
                }
                Err(error) => Dispatch::Refused(error),
            };
            let event = match dispatch {
                Dispatch::Refused(
                    reason @ (ProtocolError::Capacity | ProtocolError::WouldBlock),
                ) => {
                    let Some(peer) = self.peers[index].as_mut() else {
                        return Poll::Ready(Err(ProtocolError::StaleGeneration.into()));
                    };
                    return Self::mark_blocked(peer, BlockedAt::Input, reason, observe).map(Ok);
                }
                Dispatch::Refused(error) => {
                    return Poll::Ready(
                        self.close_index(index, CloseCause::Fault(error.into()), observe)
                            .map(|_| Progress::Activity),
                    );
                }
                Dispatch::Input(event) => {
                    self.report.inputs = self.report.inputs.saturating_add(1);
                    Event::Input { client, event }
                }
                Dispatch::Ignored(message_type) => {
                    self.report.ignored = self.report.ignored.saturating_add(1);
                    Event::IgnoredUnknown {
                        client,
                        message_type,
                    }
                }
            };
            let Some(peer) = self.peers[index].as_mut() else {
                return Poll::Ready(Err(ProtocolError::StaleGeneration.into()));
            };
            peer.input_blocked = None;
            if matches!(event, Event::Input { .. }) {
                peer.application = true;
            }
            // Pure acceptance and native input release precede user callbacks;
            // catching a callback panic cannot replay the same accepted frame.
            peer.framed.release_frame();
            observe(event);
            return Poll::Ready(Ok(Progress::Activity));
        }
        let Some(peer) = self.peers[index].as_mut() else {
            return Poll::Pending;
        };
        match peer.framed.poll_read(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(
                self.close_index(index, CloseCause::Fault(Error::Io(error)), observe)
                    .map(|_| Progress::Activity),
            ),
            Poll::Ready(Ok(ReadStep::Eof)) => Poll::Ready(
                self.close_index(index, CloseCause::Eof, observe)
                    .map(|_| Progress::Activity),
            ),
            Poll::Ready(Ok(ReadStep::Progress { bytes, .. })) => {
                self.report.read_bytes = self.report.read_bytes.saturating_add(bytes as u64);
                Poll::Ready(Ok(Progress::Activity))
            }
        }
    }
    fn poll_output(
        &mut self,
        index: usize,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        let Some(peer) = self.peers[index].as_mut() else {
            return Poll::Pending;
        };
        if let Some((frame, output)) = peer.held.take() {
            match peer.framed.enqueue_owned(frame, output, Class::Ordinary) {
                Ok(()) => {
                    peer.output_blocked = None;
                    self.report.outputs = self.report.outputs.saturating_add(1);
                    Self::queued(output, observe);
                    return Poll::Ready(Ok(Progress::Activity));
                }
                Err(rejected) => {
                    let reason = rejected.reason;
                    peer.held = Some(rejected.value);
                    if matches!(reason, ProtocolError::Capacity | ProtocolError::WouldBlock) {
                        return Self::mark_blocked(peer, BlockedAt::Output, reason, observe)
                            .map(Ok);
                    }
                    return Poll::Ready(
                        self.close_index(index, CloseCause::Fault(reason.into()), observe)
                            .map(|_| Progress::Activity),
                    );
                }
            }
        }
        if peer.framed.queued_frames() != 0 {
            return Poll::Pending;
        }
        if peer.management.is_some() {
            return self.poll_management_output(index, observe);
        }
        let client = peer.client;
        let needed = match self.core.next_output_len(client) {
            Ok(Some(needed)) => needed,
            Ok(None) => return Poll::Pending,
            Err(error) => {
                return Poll::Ready(
                    self.close_index(index, CloseCause::Fault(error.into()), observe)
                        .map(|_| Progress::Activity),
                );
            }
        };
        // Both FIFO metadata and final body allocation precede irreversible
        // service prepare/free. No fallible payload copy follows that commit.
        if let Err(reason) = peer.framed.reserve(needed, Class::Ordinary) {
            if matches!(reason, ProtocolError::Capacity | ProtocolError::WouldBlock) {
                return Self::mark_blocked(peer, BlockedAt::Output, reason, observe).map(Ok);
            }
            return Poll::Ready(
                self.close_index(index, CloseCause::Fault(reason.into()), observe)
                    .map(|_| Progress::Activity),
            );
        }
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(needed).is_err() {
            return Self::mark_blocked(peer, BlockedAt::Output, ProtocolError::Capacity, observe)
                .map(Ok);
        }
        bytes.resize(needed, 0);
        let prepared = match self.core.prepare_output(client, &mut bytes) {
            Ok(Some(prepared)) => prepared,
            Ok(None) => {
                drop(OwnedFrame::new(bytes));
                return Poll::Pending;
            }
            Err(reason @ (ProtocolError::Capacity | ProtocolError::WouldBlock)) => {
                drop(OwnedFrame::new(bytes));
                return Self::mark_blocked(peer, BlockedAt::Output, reason, observe).map(Ok);
            }
            Err(error) => {
                drop(OwnedFrame::new(bytes));
                return Poll::Ready(
                    self.close_index(index, CloseCause::Fault(error.into()), observe)
                        .map(|_| Progress::Activity),
                );
            }
        };
        let output = Origin::Application(prepared.output());
        let length = prepared.bytes().len();
        bytes.truncate(length);
        let frame = OwnedFrame::new(bytes);
        match peer.framed.enqueue_owned(frame, output, Class::Ordinary) {
            Ok(()) => {
                peer.output_blocked = None;
                self.report.outputs = self.report.outputs.saturating_add(1);
                Self::queued(output, observe);
                Poll::Ready(Ok(Progress::Activity))
            }
            Err(rejected) => {
                let reason = rejected.reason;
                peer.held = Some(rejected.value);
                if matches!(reason, ProtocolError::Capacity | ProtocolError::WouldBlock) {
                    Self::mark_blocked(peer, BlockedAt::Output, reason, observe).map(Ok)
                } else {
                    Poll::Ready(
                        self.close_index(index, CloseCause::Fault(reason.into()), observe)
                            .map(|_| Progress::Activity),
                    )
                }
            }
        }
    }
    fn poll_management_output(
        &mut self,
        index: usize,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        let peer = self.peers[index]
            .as_mut()
            .ok_or(ProtocolError::StaleGeneration)?;
        let stream = peer
            .management
            .as_ref()
            .ok_or(ProtocolError::StaleGeneration)?;
        let needed = match stream.next_len()? {
            Some(n) => n,
            None => return Poll::Pending,
        };
        if let Err(reason) = peer.framed.reserve(needed, Class::Ordinary) {
            if matches!(reason, ProtocolError::Capacity | ProtocolError::WouldBlock) {
                return Self::mark_blocked(peer, BlockedAt::Output, reason, observe).map(Ok);
            }
            return Poll::Ready(
                self.close_index(index, CloseCause::Fault(reason.into()), observe)
                    .map(|_| Progress::Activity),
            );
        }
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(needed).is_err() {
            return Self::mark_blocked(peer, BlockedAt::Output, ProtocolError::Capacity, observe)
                .map(Ok);
        }
        bytes.resize(needed, 0);
        let output = peer
            .management
            .as_mut()
            .ok_or(ProtocolError::StaleGeneration)?
            .prepare(&mut bytes)?;
        let origin = Origin::Management(output);
        let frame = OwnedFrame::new(bytes);
        match peer.framed.enqueue_owned(frame, origin, Class::Ordinary) {
            Ok(()) => {
                peer.output_blocked = None;
                self.report.outputs = self.report.outputs.saturating_add(1);
                Self::queued(origin, observe);
                Poll::Ready(Ok(Progress::Activity))
            }
            Err(rejected) => {
                let reason = rejected.reason;
                peer.held = Some(rejected.value);
                if matches!(reason, ProtocolError::Capacity | ProtocolError::WouldBlock) {
                    Self::mark_blocked(peer, BlockedAt::Output, reason, observe).map(Ok)
                } else {
                    Poll::Ready(
                        self.close_index(index, CloseCause::Fault(reason.into()), observe)
                            .map(|_| Progress::Activity),
                    )
                }
            }
        }
    }
    fn poll_peer(
        &mut self,
        cx: &mut Context<'_>,
        index: usize,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        let Some(peer) = &self.peers[index] else {
            return Poll::Pending;
        };
        if self.shutdown == Some(ShutdownMode::Immediate) {
            return Poll::Ready(
                self.close_index(index, CloseCause::Shutdown, observe)
                    .map(|_| Progress::Activity),
            );
        }
        let cursor = peer.cursor;
        for offset in 0..3 {
            let class = (cursor + offset) % 3;
            let result = match class {
                0 => self.poll_write(cx, index, observe),
                1 => self.poll_input(cx, index, observe),
                _ => self.poll_output(index, observe),
            };
            if result.is_ready() {
                if let Some(peer) = self.peers[index].as_mut() {
                    peer.cursor = (class + 1) % 3;
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
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        if self.shutdown.is_some() || !self.accept.ready() || self.peers.iter().all(Option::is_some)
        {
            return Poll::Pending;
        }
        for offset in 0..listeners.len() {
            let index = (self.listener_cursor + offset) % listeners.len();
            match listeners[index].poll_canonical_connection(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(error)) => {
                    self.listener_cursor = (index + 1) % listeners.len();
                    observe(Event::Socket(self.accept.failed(error)));
                    return Poll::Ready(Ok(Progress::Activity));
                }
                Poll::Ready(Ok(accepted)) => {
                    self.listener_cursor = (index + 1) % listeners.len();
                    return match self.admit(accepted, observe) {
                        Ok(Some(_)) => Poll::Ready(Ok(Progress::Accepted)),
                        Ok(None) => Poll::Ready(Ok(Progress::Activity)),
                        Err(error) => {
                            observe(Event::AdmissionFailed(error));
                            Poll::Ready(Ok(Progress::Activity))
                        }
                    };
                }
            }
        }
        Poll::Pending
    }
    /// Poll one bounded fair local step. Retained input or output refusal does
    /// not block other MQs. Deadline expiration cancels only observation. This
    /// method never consumes or invents a remote peer operation.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        deadline: Option<Instant>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            self.wait = None;
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        self.wake = Some(cx.waker().clone());
        if self.shutdown.is_some() && self.peers.iter().all(Option::is_none) {
            self.wait = None;
            return Poll::Ready(Ok(Progress::Stopped));
        }
        if self.poll_drains(cx, observe)? {
            return Poll::Ready(Ok(Progress::Activity));
        }
        for offset in 0..3 {
            let class = (self.class_cursor + offset) % 3;
            let result = match class {
                0 if self.shutdown != Some(ShutdownMode::Immediate) => match self.core.progress() {
                    Ok(Some(channel)) => {
                        observe(Event::LocalBound(channel));
                        Poll::Ready(Ok(Progress::Activity))
                    }
                    Ok(None) | Err(ProtocolError::Capacity) => Poll::Pending,
                    Err(error) => Poll::Ready(Err(error.into())),
                },
                1 => {
                    let mut ready = Poll::Pending;
                    for offset in 0..self.peers.len() {
                        let index = (self.cursor + offset) % self.peers.len();
                        let result = self.poll_peer(cx, index, observe);
                        if result.is_ready() {
                            self.cursor = (index + 1) % self.peers.len();
                            ready = result;
                            break;
                        }
                    }
                    ready
                }
                2 => self.poll_accept(cx, listeners, observe),
                _ => Poll::Pending,
            };
            if result.is_ready() {
                self.class_cursor = (class + 1) % 3;
                return result;
            }
        }
        if let Some(deadline) = deadline {
            let timer = self
                .wait
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(deadline)));
            timer.as_mut().reset(deadline);
            if timer.as_mut().poll(cx).is_ready() {
                self.wait = None;
                return Poll::Ready(Ok(Progress::WaitDeadline));
            }
        } else {
            self.wait = None;
        }
        Poll::Pending
    }
    /// Observe original work until one local step/deadline. Dropping this future
    /// preserves accepted sockets, partial cursors, held inputs and frozen output.
    pub async fn drive(
        &mut self,
        listeners: &[Listener<'_>],
        deadline: Option<Instant>,
        mut observe: impl FnMut(Event<'id>),
    ) -> Result<Progress, Error> {
        poll_fn(|cx| self.poll(cx, listeners, deadline, &mut observe)).await
    }
    /// Stop/drain the actual local MQs under explicit shutdown policy. This
    /// future can be canceled and resumed. The returned native counters do not
    /// assert external peer/tunnel quiescence; drive remaining close/open effects.
    pub async fn shutdown(
        &mut self,
        mode: ShutdownMode,
        mut observe: impl FnMut(Event<'id>),
    ) -> Result<Report, Error> {
        self.request_shutdown(mode);
        loop {
            if self.drive(&[], None, &mut observe).await? == Progress::Stopped {
                return Ok(self.report);
            }
        }
    }
    /// Retry retained input/output after the caller changed an external resource
    /// policy. This wakes only the current observer, without recreating any frame.
    pub fn retry_retained(&mut self) {
        self.changed();
    }
    /// Request the configured service shutdown lifetime explicitly.
    pub fn request_configured_shutdown(&mut self) {
        self.request_shutdown(self.options.shutdown);
    }

    /// Dispatch one original actual remote-open effect without success/credit.
    pub fn next_open(&mut self) -> Option<core::Open<'id>> {
        self.core.next_open()
    }
    /// Observe the original dispatched opening job that must actually stop.
    #[must_use]
    pub fn canceling_open(&self) -> Option<core::Open<'id>> {
        self.core.canceling_open()
    }
    /// Commit original canceled/failed remote-open work only after it actually stopped.
    pub fn open_failed(&mut self, open: core::Open<'id>) -> Result<(), ProtocolError> {
        let result = self.core.open_failed(open);
        if result.is_ok() {
            self.changed();
        }
        result
    }
    /// Bind a real outgoing Ready peer owner with the exact expected endpoint.
    pub fn peer_opened<'peer>(
        &mut self,
        open: core::Open<'id>,
        owner: &mut peer::ChannelOwner<'peer, '_, '_>,
    ) -> Result<core::Binding<'id, 'peer>, ProtocolError> {
        let result = self.core.peer_opened(open, owner);
        if result.is_ok() {
            self.changed();
        }
        result
    }
    /// Bind a real incoming Ready listener owner to an actual registered port.
    pub fn accept_peer<'peer>(
        &mut self,
        owner: &mut peer::ChannelOwner<'peer, '_, '_>,
    ) -> Result<core::Binding<'id, 'peer>, ProtocolError> {
        let result = self.core.accept_peer(owner);
        if result.is_ok() {
            self.changed();
        }
        result
    }
    /// Consume a matching original diagnostic selector immediately before the
    /// actual peer owner discards that prepared plaintext, before encryption/IO.
    pub fn consume_peer_drop(
        &mut self,
        channel: core::Channel<'id>,
        message_type_bytes: [u8; 2],
    ) -> Result<bool, ProtocolError> {
        let dropped = self.core.consume_peer_drop(channel, message_type_bytes)?;
        if dropped {
            self.changed();
        }
        Ok(dropped)
    }
    /// Preview original retained outgoing bytes for actual peer admission.
    #[must_use]
    pub fn next_send(&self) -> Option<core::Sending<'id, '_>> {
        self.core.next_send()
    }
    /// Filter only the oldest original queued payload of each ready channel.
    /// This readonly selection grants no peer copy, credit or native outcome.
    #[must_use]
    pub fn next_send_where(
        &self,
        eligible: impl FnMut(&core::Sending<'id, '_>) -> bool,
    ) -> Option<core::Sending<'id, '_>> {
        self.core.next_send_where(eligible)
    }
    /// Associate only the actual peer copy of the same original bytes and claim.
    pub fn send_admitted<'peer>(
        &mut self,
        effect: core::Send<'id>,
        binding: core::Binding<'id, 'peer>,
        owner: &peer::ChannelOwner<'peer, '_, '_>,
        send: peer::Send<'peer>,
    ) -> Result<core::Admitted<'id, 'peer>, ProtocolError> {
        let result = self.core.send_admitted(effect, binding, owner, send);
        if result.is_ok() {
            self.changed();
        }
        result
    }
    /// Observe that exact peer owner's actual original send outcome.
    pub fn send_completed<'peer>(
        &mut self,
        admitted: core::Admitted<'id, 'peer>,
        owner: &peer::ChannelOwner<'peer, '_, '_>,
    ) -> Result<peer::Outcome, ProtocolError> {
        let result = self.core.send_completed(admitted, owner);
        if result.is_ok() {
            self.changed();
        }
        result
    }
    /// Copy/handoff one actual peer in-order delivery to its original MQ.
    pub fn receive_peer<'peer>(
        &mut self,
        binding: core::Binding<'id, 'peer>,
        owner: &mut peer::ChannelOwner<'peer, '_, '_>,
    ) -> Result<core::PeerDelivery<'id, 'peer>, ProtocolError> {
        let result = self.core.receive_peer(binding, owner);
        if result.is_ok()
            || matches!(
                result,
                Err(ProtocolError::Closed | ProtocolError::TooLarge | ProtocolError::Malformed)
            )
        {
            self.changed();
        }
        result
    }
    /// Preview an actual local application's explicit receive_done peer effect.
    #[must_use]
    pub fn next_receive_done(&self) -> Option<core::ReceiveDone<'id>> {
        self.core.next_receive_done()
    }
    /// Release only its original actual peer delivery after the real app ACK.
    pub fn peer_receive_done<'peer>(
        &mut self,
        effect: core::ReceiveDone<'id>,
        delivery: core::PeerDelivery<'id, 'peer>,
        owner: &mut peer::ChannelOwner<'peer, '_, '_>,
    ) -> Result<(), ProtocolError> {
        let result = self.core.peer_receive_done(effect, delivery, owner);
        if result.is_ok() {
            self.changed();
        }
        result
    }
    /// Dispatch one original actual remote-close effect; retain it until settlement.
    pub fn next_close(&mut self) -> Option<core::Close<'id>> {
        self.core.next_close()
    }
    /// Release local binding metadata only after real peer and physical retirement.
    pub fn peer_closed<'peer>(
        &mut self,
        effect: core::Close<'id>,
        binding: core::Binding<'id, 'peer>,
        owner: &peer::ChannelOwner<'peer, '_, '_>,
    ) -> Result<(), ProtocolError> {
        let result = self.core.peer_closed(effect, binding, owner);
        if result.is_ok() {
            self.changed();
        }
        result
    }
    /// Observe actual backend channel loss, preserving real local destroy work.
    pub fn peer_lost<'peer>(
        &mut self,
        binding: core::Binding<'id, 'peer>,
        owner: &peer::ChannelOwner<'peer, '_, '_>,
    ) -> Result<(), ProtocolError> {
        let result = self.core.peer_lost(binding, owner);
        if result.is_ok() {
            self.changed();
        }
        result
    }
}
impl Drop for Server<'_, '_, '_> {
    fn drop(&mut self) {
        // Retire every original physical cursor before any pure source loss.
        for peer in self.peers.iter_mut().flatten() {
            peer.framed.retire();
            drop(peer.held.take());
        }
        for peer in self.peers.iter_mut().filter_map(Option::take) {
            let _original_detach = self.core.detach(peer.client);
        }
        // Explicit shutdown/close is required to observe each original Loss and
        // to drive external peer cleanup. Drop never invents peer completion.
    }
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
