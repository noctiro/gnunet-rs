//! One original TRANSPORT MQ, up to two real sockets and bounded authenticated peers.
#[cfg(feature = "pils-client")]
use crate::driver::Time;
use crate::{
    discovery::{self, Discovered},
    driver::Capacity,
    replay::{Journal, JournalError},
    socket::{DatagramSocket, Profile, Receipt, SocketError},
    transport::{self, Event, Queue},
};
use gnunet_crypto::Entropy;
use gnunet_service_runtime::{
    connection::Connection,
    framing::{Accounting, Budget, Class, Framed, Limits, OwnedFrame, ReadStep},
};
use gnunet_types::Error;
use gnunet_udp_communicator_core::{
    Identity, PeerId, handshake,
    receive::{MAX_NEW_KEY_IDS, Policy as RxPolicy, Received, Receiver},
    send::{Grant, Mode, Policy as TxPolicy, Sender},
    wire::Ack,
};
use std::{
    collections::VecDeque,
    io,
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};
use zeroize::Zeroizing;

/// Original native/domain failure. No branch creates a successful send callback.
#[derive(Debug)]
pub enum Failure {
    /// Protocol, current-key, clock or explicit bounded resource refusal.
    Core(Error),
    /// Actual original UDP syscall/source failure.
    Native(SocketError),
    /// Actual original TRANSPORT MQ failure.
    Transport(io::Error),
    /// Actual clean EOF of the original TRANSPORT MQ; no UDP socket was rebound.
    TransportEof,
    /// Original MQ failure plus independent retirement-metadata failure.
    TransportRetirement {
        /// Actual IO cause; None means clean EOF.
        original: Option<io::Error>,
        /// Actual bounded bookkeeping failure; recovery cannot proceed.
        cleanup: Error,
    },
    /// Original identity-bound durable journal failure.
    History(JournalError),
    /// Actual public burst construction/clock/native failure.
    BurstStart(gnunet_nat_burst_host::Error),
    /// Owned original burst command and actual terminal cause.
    Burst(burst::Failure),
}
impl From<Error> for Failure {
    fn from(value: Error) -> Self {
        Self::Core(value)
    }
}
impl From<SocketError> for Failure {
    fn from(value: SocketError) -> Self {
        Self::Native(value)
    }
}
impl From<JournalError> for Failure {
    fn from(value: JournalError) -> Self {
        Self::History(value)
    }
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UDP communicator: {self:?}")
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Core(e) => Some(e),
            Self::Native(e) => Some(e),
            Self::Transport(e) => Some(e),
            Self::TransportEof => None,
            Self::TransportRetirement { original, cleanup } => original
                .as_ref()
                .map(|error| error as &(dyn std::error::Error + 'static))
                .or(Some(cleanup)),
            Self::History(e) => Some(e),
            Self::BurstStart(e) => Some(e),
            Self::Burst(e) => Some(e),
        }
    }
}
/// Local resource and rotation policy, not a new wire negotiation.
#[derive(Clone, Copy, Debug)]
pub struct Configuration {
    /// Current verified local public peer; must match every supplied key/journal.
    pub local: PeerId,
    /// Maximum simultaneous authenticated incoming peer owners.
    pub peers: usize,
    /// Maximum simultaneous outgoing (peer,address) owners.
    pub endpoints: usize,
    /// Original retained MQ effect and syscall capacities.
    pub capacity: Capacity,
    /// Rotation/liveness/cache template. Each endpoint uses its actual socket's
    /// standard datagram size, overriding only this template's datagram_bytes.
    pub transmit: TxPolicy,
}
/// Original input requiring address classification, without added wire metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressUse {
    /// Original TRANSPORT CREATE; refusal queues its negative CREATED reply.
    Create {
        /// Original opaque request identifier.
        request: [u8; 4],
    },
    /// Authenticated initial exchange, before durable replay admission.
    Initial,
    /// Authenticated BOX, before consuming its original KID.
    Boxed,
    /// Source-bound signed discovery hint, without queue admission.
    Discovery,
    /// Unauthenticated passive public burst probe.
    Probe,
}
/// One actual progress step. Bytes written locally never prove remote delivery.
#[derive(Debug)]
pub enum Activity {
    /// This address was refused by the caller-owned classifier. Other endpoints,
    /// the shared socket and MQ remain active; no fallback category is invented.
    ClassificationFailed {
        /// Original peer value; the operation states its authentication scope.
        peer: PeerId,
        /// Exact requested address or kernel-reported datagram source.
        target: SocketAddr,
        /// Original input whose admission was refused.
        operation: AddressUse,
        /// Original provider cause, retained without conversion to a wire error.
        error: io::Error,
    },
    /// The queued native send failed and its intended endpoint is retiring;
    /// the original shared socket remains owned. This attributes no remote fault.
    SendError {
        /// Index of the original owned socket.
        socket: usize,
        /// Intended public destination, not authentication of the error source.
        peer: PeerId,
        /// Exact original native destination.
        target: SocketAddr,
        /// Original native cause; the failed packet is never retried.
        error: io::Error,
    },
    /// Isolated receive failure; the original shared socket remains active.
    ReceiveError {
        /// Index of the original owned socket.
        socket: usize,
        /// Original native cause; no peer or packet is inferred.
        error: io::Error,
    },
    /// Original socket or MQ made positive native progress.
    Io,
    /// One retained original effect entered MQ framing, not remote admission.
    Admitted,
    /// Whole original registration frame actually wrote locally.
    Registered,
    /// Original TRANSPORT command, local send failure or retained ACK work advanced.
    Command,
    /// One original atomic UDP datagram wholly transferred.
    NativeSent {
        /// Actual destination public peer.
        peer: PeerId,
        /// Actual original numeric target.
        target: SocketAddr,
        /// Prepared cryptographic packet mode.
        mode: Mode,
        /// Actual whole datagram extent.
        bytes: usize,
    },
    /// One authenticated original datagram reached the bounded effect owner.
    Incoming {
        /// Actual authenticated sender.
        peer: PeerId,
        /// Original kernel-reported source, not authentication of IP ownership.
        source: SocketAddr,
        /// BOX rather than initial KX.
        boxed: bool,
        /// Original ciphertext extent.
        bytes: usize,
    },
    /// One unusable input was explicitly consumed, with no payload/ACK admitted.
    Discarded(Error),
    /// One original endpoint and its queues retired.
    Retired,
    /// One interface/group/timer observation advanced, without session credit.
    Discovery,
    /// One actual96-byte LAN datagram wholly transferred on the original socket.
    DiscoverySent {
        /// Original numeric broadcast/multicast target.
        target: SocketAddr,
    },
    /// One original optional discovery operation retired without disturbing
    /// encrypted endpoints or their shared socket. No send/leave is implied.
    DiscoveryFailed {
        /// Original bound socket slot.
        socket: usize,
        /// Exact original interface operation and intended destination.
        operation: discovery::Operation,
        /// Original local refusal, expiry or native error.
        error: SocketError,
    },
    /// One source-bound signature hint is available through take_discovered.
    /// This is not TRANSPORT address validation or an authenticated queue.
    Discovered,
    /// Actual public burst progress, never authentication or delivery.
    Burst,
    /// One bounded current-source endpoint reannouncement step advanced.
    Restoring,
    /// Registration and all surviving queue reannouncements wholly wrote on the
    /// replacement MQ. This is a local write fact, not peer delivery or validation.
    Restored,
    /// Original physical owners fully drained or explicitly retired locally.
    Closed,
}
pub mod burst;
mod discovery_io;
pub use discovery_io::InterfaceUpdate;
mod identity;
mod incoming;
mod recovery;
mod transmit;
pub use identity::Retirement as IdentityRetirement;
pub use recovery::{Callback, EffectMeta, Retired, TransportLoss};

/// Original local-address frame identity. This is not a peer/NAT-validation
/// capability and cannot be reconstructed from its diagnostic sequence.
pub struct Publication {
    source: Arc<recovery::PublicationSource>,
    sequence: u64,
}
impl std::fmt::Debug for Publication {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Publication")
            .field("sequence", &self.sequence)
            .finish_non_exhaustive()
    }
}
/// Physical local write fact for an original address announcement/withdrawal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationState {
    /// Original frame remains in this owner, possibly partially exposed.
    Pending,
    /// The entire original frame actually wrote on its original MQ.
    Written,
    /// MQ retired without a whole-write receipt; not proof of zero exposure.
    Retired,
}
#[derive(Clone, Copy)]
struct WriteOrigin {
    kind: Origin,
    sequence: u64,
}
#[derive(Clone, Copy)]
enum Origin {
    Register,
    Effect,
}
struct Effect {
    frame: OwnedFrame,
    origin: Origin,
    sequence: u64,
}
struct Peer {
    id: PeerId,
    generation: u64,
    receiver: Receiver,
    last_rx: u64,
}
struct Endpoint {
    peer: PeerId,
    generation: u64,
    source_generation: u64,
    socket: usize,
    target: SocketAddr,
    network: u32,
    address: String,
    sender: Sender,
    kx: u32,
    boxed: Option<u32>,
    last_ack: u64,
    retiring: bool,
}
struct Completion {
    endpoint: usize,
    generation: u64,
    operation: u64,
    peer: PeerId,
    target: SocketAddr,
    mode: Mode,
    success: OwnedFrame,
    failure: OwnedFrame,
}
#[derive(Clone, Copy)]
struct Kid {
    value: [u8; 32],
    peer: usize,
    generation: u64,
}
struct AckWork {
    peer: PeerId,
    ack: Ack,
    cursor: usize,
    watermark: u64,
    release_input: bool,
}
/// Retained original native owner. Waiting cancellation does not recreate sockets,
/// nonce owners, MQ frames, authenticated peers or replay namespaces.
pub struct Communicator<'id> {
    configuration: Configuration,
    identity_phase: identity::Phase,
    sockets: Vec<DatagramSocket>,
    defaults: usize,
    burst: Option<burst::Port<'id>>,
    io: Framed<WriteOrigin>,
    publication_owner: Arc<()>,
    publication_source: Arc<recovery::PublicationSource>,
    transport_attached: bool,
    restoring: bool,
    restore_cursor: usize,
    restore_fence: u64,
    pending_mq: Option<EffectMeta>,
    loss: recovery::Ledger,
    loss_observed: bool,
    next_effect: u64,
    written_effect: u64,
    peers: Vec<Option<Peer>>,
    endpoints: Vec<Option<Endpoint>>,
    index: Vec<Kid>,
    effects: VecDeque<Effect>,
    effect_bytes: usize,
    completions: Vec<Option<Completion>>,
    ack: Option<AckWork>,
    scratch: Zeroizing<Vec<u8>>,
    peer_serial: u64,
    endpoint_serial: u64,
    next_queue: u32,
    last_clock: u64,
    turn: usize,
    tx_cursor: usize,
    rx_cursor: usize,
    maintenance_cursor: usize,
    registered: bool,
    discovery: Option<discovery::State>,
    closing: bool,
    closed: bool,
}
fn buffer(size: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size).map_err(|_| Error::Capacity)?;
    bytes.resize(size, 0);
    Ok(bytes)
}
fn frozen(
    size: usize,
    encode: impl FnOnce(&mut [u8]) -> Result<usize, Error>,
) -> Result<OwnedFrame, Error> {
    freeze(buffer(size)?, encode)
}
fn freeze(
    mut bytes: Vec<u8>,
    encode: impl FnOnce(&mut [u8]) -> Result<usize, Error>,
) -> Result<OwnedFrame, Error> {
    let n = encode(&mut bytes)?;
    if n > bytes.len() {
        return Err(Error::Malformed);
    }
    bytes.truncate(n);
    Ok(OwnedFrame::new(bytes))
}
impl<'id> Communicator<'id> {
    /// Adopt one already connected MQ and one or two original sockets (at most
    /// one per family). This allocates bounded metadata but submits no IO. On
    /// refusal the adopted unsubmitted descriptor owners physically drop.
    pub fn new(
        connection: Connection,
        sockets: Vec<DatagramSocket>,
        configuration: Configuration,
        now: u64,
    ) -> Result<Self, Failure> {
        let capacity = configuration.capacity;
        if sockets.is_empty()
            || sockets.len() > 2
            || configuration.peers == 0
            || configuration.endpoints == 0
            || capacity.frames < 4
            || capacity.bytes < 65535
            || capacity.io_slice == 0
            || configuration.transmit.secrets < 2
            || configuration.transmit.maximum_secret_bytes == 0
            || configuration.transmit.acknowledgement_timeout_us == 0
            || configuration.transmit.rekey_after_bytes
                >= configuration.transmit.maximum_secret_bytes
        {
            return Err(Error::InvalidInput.into());
        }
        if sockets.len() == 2 && sockets[0].profile() == sockets[1].profile() {
            return Err(Error::InvalidInput.into());
        }
        configuration
            .endpoints
            .checked_mul(2)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or(Error::Capacity)?;
        let mut peers = Vec::new();
        peers
            .try_reserve_exact(configuration.peers)
            .map_err(|_| Error::Capacity)?;
        peers.resize_with(configuration.peers, || None);
        let mut endpoints = Vec::new();
        endpoints
            .try_reserve_exact(configuration.endpoints)
            .map_err(|_| Error::Capacity)?;
        endpoints.resize_with(configuration.endpoints, || None);
        let mut effects = VecDeque::new();
        effects
            .try_reserve_exact(capacity.frames)
            .map_err(|_| Error::Capacity)?;
        let mut completions = Vec::new();
        completions
            .try_reserve_exact(sockets.len())
            .map_err(|_| Error::Capacity)?;
        completions.resize_with(sockets.len(), || None);
        let scratch = Zeroizing::new(buffer(65536)?);
        let io = Framed::new(
            connection,
            Limits {
                frame_bytes: 65535,
                ordinary: Budget {
                    frames: 1,
                    bytes: 65535,
                },
                reserved: Budget::default(),
                accounting: Accounting::Retained,
                io_slice_bytes: capacity.io_slice,
            },
        )?;
        let loss = recovery::Ledger::new(
            capacity
                .frames
                .checked_add(2)
                .and_then(|n| n.checked_add(configuration.endpoints))
                .and_then(|n| n.checked_add(sockets.len().checked_mul(2)?))
                .ok_or(Error::Overflow)?,
        )?;
        let publication_owner = Arc::new(());
        let publication_source = Arc::new(recovery::PublicationSource::new(
            1,
            publication_owner.clone(),
        ));
        let mut owner = Self {
            configuration,
            identity_phase: identity::Phase::Active,
            defaults: sockets.len(),
            burst: None,
            sockets,
            io,
            publication_owner,
            publication_source,
            transport_attached: true,
            restoring: false,
            restore_cursor: 0,
            restore_fence: 0,
            pending_mq: None,
            loss,
            loss_observed: false,
            next_effect: 0,
            written_effect: 0,
            peers,
            endpoints,
            index: Vec::new(),
            effects,
            effect_bytes: 0,
            completions,
            ack: None,
            scratch,
            peer_serial: 0,
            endpoint_serial: 0,
            next_queue: 1,
            last_clock: now,
            turn: 0,
            tx_cursor: 0,
            rx_cursor: 0,
            maintenance_cursor: 0,
            registered: false,
            discovery: None,
            closing: false,
            closed: false,
        };
        owner.push(
            frozen(16, |out| transport::register(false, out))?,
            Origin::Register,
        )?;
        Ok(owner)
    }
    /// Admit the exact official local address frame. `validity` is the original
    /// TRANSPORT wire validity in microseconds, not a freshly sampled lifetime.
    /// The ticket distinguishes local enqueue from an actual whole MQ write.
    pub fn advertise(
        &mut self,
        id: u32,
        address: &[u8],
        network: u32,
        validity: u64,
    ) -> Result<Publication, Error> {
        if self.closed || self.closing {
            return Err(Error::Closed);
        }
        if !self.transport_ready() {
            return Err(Error::WouldBlock);
        }
        transport::parse_address(address)?;
        let size = 21usize.checked_add(address.len()).ok_or(Error::Overflow)?;
        if !self.room(1, size) {
            return Err(Error::WouldBlock);
        }
        let frame = frozen(size, |out| {
            transport::address_add(id, address, network, validity, out)
        })?;
        self.push(frame, Origin::Effect)?;
        Ok(Publication {
            source: self.publication_source.clone(),
            sequence: self.next_effect,
        })
    }
    /// Admit withdrawal of only the caller's original address identifier.
    pub fn withdraw(&mut self, id: u32) -> Result<Publication, Error> {
        if self.closed || self.closing {
            return Err(Error::Closed);
        }
        if !self.transport_ready() {
            return Err(Error::WouldBlock);
        }
        if !self.room(1, 8) {
            return Err(Error::WouldBlock);
        }
        self.push(
            frozen(8, |out| transport::address_remove(id, out))?,
            Origin::Effect,
        )?;
        Ok(Publication {
            source: self.publication_source.clone(),
            sequence: self.next_effect,
        })
    }
    /// Observe only this original manager's source-bound ticket. Retirement is
    /// not republication authority; Written is not validation or a remote ACK.
    pub fn publication(&self, ticket: &Publication) -> Result<PublicationState, Error> {
        if !Arc::ptr_eq(&self.publication_owner, &ticket.source.owner) {
            return Err(Error::Stale);
        }
        ticket.source.state(ticket.sequence)
    }
    /// Actual whole local registration write; not a TRANSPORT or peer ACK.
    #[must_use]
    pub const fn is_registered(&self) -> bool {
        self.registered
    }
    /// Original actual local socket addresses, including assigned ports.
    pub fn local_addresses(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.sockets
            .iter()
            .take(self.defaults)
            .map(DatagramSocket::local_address)
    }
    /// Actual number of retained incoming authenticated peer owners.
    #[must_use]
    pub fn peers(&self) -> usize {
        self.peers.iter().flatten().count()
    }
    /// Actual number of retained outgoing peer/address owners.
    #[must_use]
    pub fn endpoints(&self) -> usize {
        self.endpoints.iter().flatten().count()
    }
    /// Drive one original bounded work item. Classifier supplies the real current
    /// network classification for each newly admitted numeric endpoint.
    pub fn poll_step(
        &mut self,
        cx: &mut Context<'_>,
        identity: &Identity,
        journal: &mut Journal,
        now: u64,
        entropy: &mut impl Entropy,
        classify: &mut impl FnMut(SocketAddr) -> io::Result<u32>,
    ) -> Poll<Result<Activity, Failure>> {
        self.poll_inner(cx, identity, journal, now, entropy, classify)
    }
    /// Bind every step to the original actual current native PILS observation.
    #[cfg(feature = "pils-client")]
    #[expect(
        clippy::too_many_arguments,
        reason = "Explicit original PILS, journal, entropy and network-classification ports retain independent ownership"
    )]
    pub fn poll_bound<'a, const O: usize>(
        &mut self,
        cx: &mut Context<'_>,
        binding: &crate::identity::IdentityEpoch<'a>,
        source: &gnunet_pils_host::client::Client<'a, O>,
        journal: &mut Journal,
        time: Time,
        entropy: &mut impl Entropy,
        classify: &mut impl FnMut(SocketAddr) -> io::Result<u32>,
    ) -> Poll<Result<Activity, Failure>> {
        if self.closing {
            return self.poll_close(cx);
        }
        if self.identity_phase != identity::Phase::Active {
            return Poll::Pending;
        }
        if let Some(error) = self.poll_native_guard(cx) {
            return Poll::Ready(Err(error));
        }
        let identity = match binding.current_native(source, time.utc) {
            Ok(identity) => identity,
            Err(error) => {
                self.close();
                return Poll::Ready(Err(error.into()));
            }
        };
        self.poll_inner(cx, identity, journal, time.now, entropy, classify)
    }
    /// Begin same-owner queue/native teardown. It never regenerates a datagram or
    /// replenishes ACK credit; caller continues poll_step/poll_bound to Closed.
    pub fn finish(&mut self) -> Result<(), Error> {
        if self.closed {
            return Ok(());
        }
        if self.closing {
            return Ok(());
        }
        if !self.transport_attached {
            self.close();
            return Ok(());
        }
        for index in 0..self.completions.len() {
            if let Some(completion) = self.completions[index].take() {
                drop(self.sockets[index].cancel_send());
                self.push(completion.failure, Origin::Effect)?;
            }
        }
        self.cancel_burst();
        self.closing = true;
        if let Some(discovery) = self.discovery.as_mut() {
            discovery.pending = [None, None];
        }
        for socket in &mut self.sockets {
            socket.close();
        }
        if let Some(work) = self.ack.take()
            && work.release_input
            && !self.io.release_frame()
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
    /// Immediate physical retirement, never successful draining or remote delivery.
    pub fn close(&mut self) {
        self.cancel_burst();
        self.io.retire();
        self.publication_source.retire();
        self.transport_attached = false;
        self.pending_mq = None;
        for socket in &mut self.sockets {
            socket.close();
        }
        for peer in self.peers.iter_mut().flatten() {
            peer.receiver.close();
        }
        for endpoint in self.endpoints.iter_mut().flatten() {
            endpoint.sender.close();
        }
        self.peers.iter_mut().for_each(|p| *p = None);
        self.endpoints.iter_mut().for_each(|p| *p = None);
        self.index.clear();
        self.effects.clear();
        self.effect_bytes = 0;
        self.completions.iter_mut().for_each(|p| *p = None);
        self.ack = None;
        self.closing = true;
        self.closed = true;
    }
    /// No original native/MQ data, queue or peer owner remains active.
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        self.closed
            && self.effects.is_empty()
            && self.io.queued_frames() == 0
            && self.completions.iter().all(Option::is_none)
            && self.sockets.iter().all(DatagramSocket::is_quiescent)
    }
    /// Earliest finite original liveness target; no timer/task is created here.
    #[must_use]
    pub fn next_wakeup(&self) -> Option<u64> {
        if self.closing || self.closed {
            return None;
        }
        let lifetime = self.configuration.transmit.acknowledgement_timeout_us;
        self.endpoints
            .iter()
            .flatten()
            .filter_map(|endpoint| endpoint.last_ack.checked_add(lifetime))
            .chain(
                self.peers
                    .iter()
                    .flatten()
                    .filter(|peer| {
                        !self
                            .endpoints
                            .iter()
                            .flatten()
                            .any(|endpoint| endpoint.peer == peer.id)
                    })
                    .filter_map(|peer| peer.last_rx.checked_add(lifetime)),
            )
            // Already-due retirement is synchronously considered on every
            // step. If its MQ effects are backpressured, wait for that actual
            // MQ waker rather than repeatedly arming an elapsed clock alarm.
            .filter(|target| *target > self.last_clock && *target != u64::MAX)
            .chain(
                self.discovery
                    .as_ref()
                    .filter(|_| self.transport_attached && !self.restoring)
                    .and_then(|state| state.next_wakeup(self.last_clock)),
            )
            .min()
    }
}
#[derive(Debug)]
enum EndpointPlanError {
    Protocol(Error),
    Classification(io::Error),
}
impl From<Error> for EndpointPlanError {
    fn from(error: Error) -> Self {
        Self::Protocol(error)
    }
}
impl std::fmt::Display for EndpointPlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UDP endpoint preparation: {self:?}")
    }
}
impl std::error::Error for EndpointPlanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::Protocol(error) => error,
            Self::Classification(error) => error,
        })
    }
}
struct EndpointPlan {
    index: usize,
    endpoint: Endpoint,
    frame: OwnedFrame,
    next_queue: u32,
}
#[expect(
    clippy::large_enum_variant,
    reason = "Keep the original inline endpoint preflight owner: boxing adds an allocation/failure boundary; Live/Retiring create no plan or heap owner"
)]
enum EndpointAdmission {
    Live,
    Retiring,
    New(EndpointPlan),
}
impl<'id> Communicator<'id> {
    fn room(&self, frames: usize, bytes: usize) -> bool {
        self.room_without(frames, bytes, None)
    }
    fn room_without(&self, frames: usize, bytes: usize, completion: Option<usize>) -> bool {
        let held = self
            .completions
            .iter()
            .enumerate()
            .filter(|(index, value)| value.is_some() && Some(*index) != completion)
            .count();
        let identities = self
            .next_effect
            .checked_add(u64::try_from(held * 2).unwrap_or(u64::MAX))
            .and_then(|n| n.checked_add(u64::try_from(frames).unwrap_or(u64::MAX)))
            .is_some();
        identities
            && self
                .effects
                .len()
                .checked_add(held * 2)
                .and_then(|n| n.checked_add(frames))
                .is_some_and(|n| n <= self.configuration.capacity.frames)
            && self
                .effect_bytes
                .checked_add(held * 104)
                .and_then(|n| n.checked_add(bytes))
                .is_some_and(|n| n <= self.configuration.capacity.bytes)
    }
    fn push(&mut self, frame: OwnedFrame, origin: Origin) -> Result<(), Error> {
        if !self.room(1, frame.len()) {
            return Err(Error::WouldBlock);
        }
        let sequence = self.next_effect.checked_add(1).ok_or(Error::Overflow)?;
        self.effect_bytes += frame.len();
        self.effects.push_back(Effect {
            frame,
            origin,
            sequence,
        });
        self.next_effect = sequence;
        self.publication_source.issued(sequence);
        Ok(())
    }
    fn socket_for(&self, target: SocketAddr) -> Option<usize> {
        self.sockets.iter().take(self.defaults).position(|socket| {
            match (socket.profile(), target) {
                (Profile::Ipv4, SocketAddr::V4(_)) => true,
                (Profile::Ipv6, SocketAddr::V6(value)) => value.ip().to_ipv4_mapped().is_none(),
                _ => false,
            }
        })
    }
    fn endpoint(&self, peer: PeerId, target: SocketAddr) -> Option<usize> {
        self.endpoints.iter().position(|entry| {
            entry
                .as_ref()
                .is_some_and(|entry| entry.peer == peer && entry.target == target)
        })
    }
    fn peer_index(&self, peer: PeerId) -> Option<usize> {
        self.peers
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|entry| entry.id == peer))
    }
    fn queue_for(endpoint: &Endpoint, id: u32, length: u64, boxed: bool) -> Result<Queue, Error> {
        Ok(Queue {
            id,
            peer: endpoint.peer,
            network: endpoint.network,
            mtu: u32::try_from(if boxed {
                endpoint.sender.boxed_mtu()
            } else {
                endpoint.sender.initial_mtu()
            })
            .map_err(|_| Error::TooLarge)?,
            length,
            priority: u32::from(boxed),
        })
    }
    fn prepare_endpoint(
        &self,
        peer: PeerId,
        target: SocketAddr,
        now: u64,
        classify: &mut impl FnMut(SocketAddr) -> io::Result<u32>,
    ) -> Result<EndpointAdmission, EndpointPlanError> {
        if let Some(index) = self.endpoint(peer, target) {
            return if self.endpoints[index]
                .as_ref()
                .is_some_and(|endpoint| endpoint.retiring)
            {
                Ok(EndpointAdmission::Retiring)
            } else {
                Ok(EndpointAdmission::Live)
            };
        }
        let socket = self.socket_for(target).ok_or(Error::InvalidInput)?;
        self.prepare_endpoint_on(peer, target, socket, now, classify)
    }
    fn prepare_endpoint_on(
        &self,
        peer: PeerId,
        target: SocketAddr,
        socket: usize,
        now: u64,
        classify: &mut impl FnMut(SocketAddr) -> io::Result<u32>,
    ) -> Result<EndpointAdmission, EndpointPlanError> {
        let original = self
            .sockets
            .get(socket)
            .filter(|socket| !socket.is_closed())
            .ok_or(Error::Closed)?;
        self.prepare_endpoint_profile(peer, target, socket, original.profile(), now, classify)
    }
    fn prepare_endpoint_profile(
        &self,
        peer: PeerId,
        target: SocketAddr,
        socket: usize,
        profile: Profile,
        now: u64,
        classify: &mut impl FnMut(SocketAddr) -> io::Result<u32>,
    ) -> Result<EndpointAdmission, EndpointPlanError> {
        if let Some(endpoint) =
            self.endpoints.iter().flatten().find(|entry| {
                entry.peer == peer && entry.target == target && entry.socket == socket
            })
        {
            return if endpoint.retiring {
                Ok(EndpointAdmission::Retiring)
            } else {
                Ok(EndpointAdmission::Live)
            };
        }
        if !matches!((profile, target), (Profile::Ipv4, SocketAddr::V4(_)))
            && !matches!((profile,target),(Profile::Ipv6,SocketAddr::V6(address)) if address.ip().to_ipv4_mapped().is_none())
        {
            return Err(Error::InvalidInput.into());
        }
        let index = self
            .endpoints
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let generation = self.endpoint_serial.checked_add(1).ok_or(Error::Overflow)?;
        let id = self.next_queue;
        let next_queue = id.checked_add(1).ok_or(Error::Overflow)?;
        let network = classify(target).map_err(EndpointPlanError::Classification)?;
        let mut policy = self.configuration.transmit;
        policy.datagram_bytes = profile.datagram_bytes();
        let sender = Sender::new(self.configuration.local, peer, policy, now)?;
        let address = transport::address(target);
        let endpoint = Endpoint {
            peer,
            generation,
            source_generation: self.publication_source.generation,
            socket,
            target,
            network,
            address,
            sender,
            kx: id,
            boxed: None,
            last_ack: now,
            retiring: false,
        };
        let queue = Self::queue_for(&endpoint, id, u64::MAX, false)?;
        let frame = frozen(65 + endpoint.address.len(), |out| {
            queue.setup(endpoint.address.as_bytes(), out)
        })?;
        Ok(EndpointAdmission::New(EndpointPlan {
            index,
            endpoint,
            frame,
            next_queue,
        }))
    }
    fn commit_endpoint(&mut self, plan: EndpointPlan) -> Result<(), Error> {
        if self.endpoints[plan.index].is_some() {
            return Err(Error::Stale);
        }
        self.push(plan.frame, Origin::Effect)?;
        if self.restoring {
            self.restore_fence = self.next_effect;
        }
        self.next_queue = plan.next_queue;
        self.endpoint_serial = plan.endpoint.generation;
        self.endpoints[plan.index] = Some(plan.endpoint);
        Ok(())
    }
    fn index_peer(&mut self, index: usize) {
        let generation = self.peers[index].as_ref().map(|peer| peer.generation);
        self.index.retain(|entry| entry.peer != index);
        if let (Some(generation), Some(peer)) = (generation, self.peers[index].as_ref()) {
            for kid in peer.receiver.key_ids() {
                self.index.push(Kid {
                    value: *kid,
                    peer: index,
                    generation,
                });
            }
        }
        self.index.sort_unstable_by(|a, b| {
            a.value
                .cmp(&b.value)
                .then(a.peer.cmp(&b.peer))
                .then(a.generation.cmp(&b.generation))
        });
    }
    fn command(
        &mut self,
        identity: &Identity,
        journal: &mut Journal,
        now: u64,
        entropy: &mut impl Entropy,
        classify: &mut impl FnMut(SocketAddr) -> io::Result<u32>,
    ) -> Result<Option<Activity>, Failure> {
        if self.ack.as_ref().is_some_and(|work| work.release_input) {
            return Ok(None);
        }
        let Some(bytes) = self.io.frame() else {
            return Ok(None);
        };
        if let Event::Burst {
            peer,
            rtt_us,
            address,
        } = Event::decode(bytes)?
        {
            let ip = std::str::from_utf8(address)
                .ok()
                .and_then(|text| text.parse::<std::net::IpAddr>().ok())
                .ok_or(Error::InvalidInput);
            let result = ip
                .map_err(Failure::Core)
                .and_then(|ip| self.burst_command(peer, rtt_us, ip));
            if result.is_err() {
                self.close();
            }
            return result;
        }
        if !self.room(3, 1024) {
            return Ok(None);
        }
        let frame = OwnedFrame::copy_from(bytes)?;
        let mut activity = Activity::Command;
        match Event::decode(frame.bytes())? {
            Event::Create {
                request,
                peer,
                address,
            } => {
                let target = transport::parse_address(address);
                let plan = target
                    .map_err(EndpointPlanError::Protocol)
                    .and_then(|target| self.prepare_endpoint(peer, target, now, classify));
                match plan {
                    Ok(EndpointAdmission::New(plan)) => {
                        let reply = frozen(8, |out| transport::created(request, true, out))?;
                        self.commit_endpoint(plan)?;
                        self.push(reply, Origin::Effect)?;
                    }
                    Ok(EndpointAdmission::Live) => self.push(
                        frozen(8, |out| transport::created(request, true, out))?,
                        Origin::Effect,
                    )?,
                    Ok(EndpointAdmission::Retiring) => self.push(
                        frozen(8, |out| transport::created(request, false, out))?,
                        Origin::Effect,
                    )?,
                    Err(EndpointPlanError::Protocol(
                        Error::InvalidInput
                        | Error::NotReady
                        | Error::Capacity
                        | Error::TooLarge
                        | Error::Authentication,
                    )) => self.push(
                        frozen(8, |out| transport::created(request, false, out))?,
                        Origin::Effect,
                    )?,
                    Err(EndpointPlanError::Classification(error)) => {
                        self.push(
                            frozen(8, |out| transport::created(request, false, out))?,
                            Origin::Effect,
                        )?;
                        activity = Activity::ClassificationFailed {
                            peer,
                            target: transport::parse_address(address)?,
                            operation: AddressUse::Create { request },
                            error,
                        };
                    }
                    Err(EndpointPlanError::Protocol(error)) => return Err(error.into()),
                }
            }
            Event::Send {
                qid,
                mid,
                peer,
                message,
            } => {
                let endpoint = self.endpoints.iter().position(|entry| {
                    entry.as_ref().is_some_and(|entry| {
                        !entry.retiring
                            && entry.source_generation == self.publication_source.generation
                            && entry.peer == peer
                            && (entry.kx == qid || entry.boxed == Some(qid))
                    })
                });
                let success = frozen(52, |out| transport::sent(qid, mid, peer, true, out))?;
                let failure = frozen(52, |out| transport::sent(qid, mid, peer, false, out))?;
                let Some(index) = endpoint else {
                    self.push(failure, Origin::Effect)?;
                    if !self.io.release_frame() {
                        return Err(Error::Stale.into());
                    }
                    return Ok(Some(Activity::Command));
                };
                let endpoint = self.endpoints[index].as_mut().ok_or(Error::Stale)?;
                let socket = endpoint.socket;
                if self.sockets[socket].has_pending_send() {
                    return Ok(None);
                }
                let packet = if endpoint.kx == qid {
                    let (stamp, _) = journal.reserve_monotime(1, 1)?;
                    endpoint
                        .sender
                        .initial(identity, message, stamp, now, entropy)
                } else {
                    match endpoint.sender.boxed(identity, message, now, entropy) {
                        Err(Error::NotReady) if message.len() <= endpoint.sender.initial_mtu() => {
                            let (stamp, _) = journal.reserve_monotime(1, 1)?;
                            endpoint
                                .sender
                                .initial(identity, message, stamp, now, entropy)
                        }
                        result => result,
                    }
                };
                match packet {
                    Ok(packet) => {
                        let operation = packet.operation();
                        let mode = packet.mode();
                        let completion = Completion {
                            endpoint: index,
                            generation: endpoint.generation,
                            operation,
                            peer,
                            target: endpoint.target,
                            mode,
                            success,
                            failure,
                        };
                        match self.sockets[socket].queue(endpoint.target, packet) {
                            Ok(()) => self.completions[socket] = Some(completion),
                            Err(rejected) => {
                                drop(rejected.value);
                                self.fail_endpoint_send(index, completion.failure)?;
                            }
                        }
                    }
                    Err(
                        Error::TooLarge
                        | Error::NotReady
                        | Error::Capacity
                        | Error::Entropy
                        | Error::Timeout,
                    ) => self.fail_endpoint_send(index, failure)?,
                    Err(error) => return Err(error.into()),
                }
            }
            Event::Backchannel { peer, ack } => {
                if self.ack.is_some() {
                    return Ok(None);
                }
                self.ack = Some(AckWork {
                    peer,
                    ack,
                    cursor: 0,
                    watermark: self.endpoint_serial,
                    release_input: true,
                });
                return Ok(Some(Activity::Command));
            }
            Event::IncomingCompleted { .. } | Event::Burst { .. } | Event::Unknown(_) => {}
        }
        if !self.io.release_frame() {
            return Err(Error::Stale.into());
        }
        Ok(Some(activity))
    }
    fn acknowledge(&mut self, now: u64) -> Result<Option<Activity>, Failure> {
        let Some(mut work) = self.ack.take() else {
            return Ok(None);
        };
        if work.cursor == self.endpoints.len() {
            if work.release_input && !self.io.release_frame() {
                return Err(Error::Stale.into());
            }
            return Ok(Some(Activity::Command));
        }
        let index = work.cursor;
        let eligible = self.endpoints[index].as_ref().is_some_and(|endpoint| {
            !endpoint.retiring
                && endpoint.peer == work.peer
                && endpoint.generation <= work.watermark
                && now.saturating_sub(endpoint.last_ack)
                    < self.configuration.transmit.acknowledgement_timeout_us
        });
        if !eligible {
            work.cursor += 1;
            self.ack = Some(work);
            return Ok(Some(Activity::Command));
        }
        if self.endpoints[index].as_ref().is_some_and(|endpoint| {
            endpoint.source_generation != self.publication_source.generation
        }) {
            let endpoint = self.endpoints[index].as_mut().ok_or(Error::Stale)?;
            // A valid grant still belongs to this exact retained Sender. Its
            // future SETUP includes the resulting total; no old-QID UPDATE is
            // emitted on the replacement source.
            match endpoint.sender.acknowledge(work.peer, work.ack, now)? {
                Grant::Increased { .. } | Grant::Unchanged => endpoint.last_ack = now,
                Grant::Unknown => {}
            }
            work.cursor += 1;
            self.ack = Some(work);
            return Ok(Some(Activity::Command));
        }
        let size = self.endpoints[index].as_ref().map_or(64, |endpoint| {
            if endpoint.boxed.is_some() {
                64
            } else {
                65 + endpoint.address.len()
            }
        });
        if !self.room(1, size) {
            self.ack = Some(work);
            return Ok(None);
        }
        let bytes = buffer(size)?;
        let fresh = self.next_queue;
        let next = fresh.checked_add(1).ok_or(Error::Overflow)?;
        let endpoint = self.endpoints[index].as_mut().ok_or(Error::Stale)?;
        let grant = endpoint.sender.acknowledge(work.peer, work.ack, now)?;
        let new_setup = endpoint.boxed.is_none() && matches!(grant, Grant::Increased { .. });
        let frame = match grant {
            Grant::Increased { delta, .. } => {
                endpoint.last_ack = now;
                let id = endpoint.boxed.unwrap_or(fresh);
                let queue = Self::queue_for(endpoint, id, u64::from(delta), true)?;
                let is_new = endpoint.boxed.is_none();
                let frame = freeze(bytes, |out| {
                    if is_new {
                        queue.setup(endpoint.address.as_bytes(), out)
                    } else {
                        queue.update(out)
                    }
                })?;
                if is_new {
                    endpoint.boxed = Some(id);
                    self.next_queue = next;
                }
                Some(frame)
            }
            Grant::Unchanged => {
                endpoint.last_ack = now;
                None
            }
            Grant::Unknown => None,
        };
        if let Some(frame) = frame {
            self.push(frame, Origin::Effect)?;
            if self.restoring && new_setup {
                self.restore_fence = self.next_effect;
            }
        }
        work.cursor += 1;
        self.ack = Some(work);
        Ok(Some(Activity::Command))
    }
}

#[cfg(test)]
mod tests;
impl<'id> Communicator<'id> {}
impl<'id> Communicator<'id> {
    fn admit_effect(&mut self) -> Result<Option<Activity>, Failure> {
        let Some(effect) = self.effects.front() else {
            return Ok(None);
        };
        if !self.io.capacity(effect.frame.len(), Class::Ordinary) {
            return Ok(None);
        }
        self.io.reserve(effect.frame.len(), Class::Ordinary)?;
        let effect = self.effects.pop_front().ok_or(Error::Stale)?;
        let metadata = EffectMeta::from_frame(&effect.frame, effect.sequence)?;
        self.effect_bytes -= effect.frame.len();
        self.io
            .enqueue_owned(
                effect.frame,
                WriteOrigin {
                    kind: effect.origin,
                    sequence: effect.sequence,
                },
                Class::Ordinary,
            )
            .map_err(|rejected| rejected.reason)?;
        self.pending_mq = Some(metadata);
        Ok(Some(Activity::Admitted))
    }
    fn write(&mut self, cx: &mut Context<'_>) -> Poll<Result<Activity, Failure>> {
        match self.io.poll_write(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.transport_failed(Some(error)))),
            Poll::Ready(Ok(progress)) => {
                let metadata = self.pending_mq.as_mut().ok_or(Error::Stale)?;
                if metadata.sequence != progress.origin.sequence {
                    return Poll::Ready(Err(Error::Stale.into()));
                }
                metadata.written_bytes = metadata
                    .written_bytes
                    .checked_add(progress.bytes)
                    .ok_or(Error::Overflow)?;
                if metadata.written_bytes > metadata.total_bytes {
                    return Poll::Ready(Err(Error::Stale.into()));
                }
                let activity = if progress.complete {
                    self.pending_mq = None;
                    // Framing preserves FIFO and the exact opaque original
                    // origin even through partial native writes.
                    if progress.origin.sequence <= self.written_effect {
                        self.close();
                        return Poll::Ready(Err(Error::Stale.into()));
                    }
                    self.written_effect = progress.origin.sequence;
                    self.publication_source.written(progress.origin.sequence);
                    if matches!(progress.origin.kind, Origin::Register) {
                        self.registered = true;
                        Activity::Registered
                    } else {
                        Activity::Io
                    }
                } else {
                    Activity::Io
                };
                Poll::Ready(Ok(activity))
            }
        }
    }
    fn maintenance(&mut self, now: Option<u64>) -> Result<Option<Activity>, Failure> {
        let lifetime = self.configuration.transmit.acknowledgement_timeout_us;
        for offset in 0..self.endpoints.len() {
            let index = (self.maintenance_cursor + offset) % self.endpoints.len();
            let expired = self.endpoints[index].as_ref().is_some_and(|endpoint| {
                endpoint.retiring
                    || self.closing
                    || now.is_some_and(|now| now.saturating_sub(endpoint.last_ack) >= lifetime)
            });
            if expired && let Some(activity) = self.retire_endpoint(index)? {
                self.maintenance_cursor = (index + 1) % self.endpoints.len();
                return Ok(Some(activity));
            }
        }
        for index in 0..self.peers.len() {
            let eligible = self.peers[index].as_ref().is_some_and(|peer| {
                !self
                    .endpoints
                    .iter()
                    .flatten()
                    .any(|endpoint| endpoint.peer == peer.id)
                    && (self.closing
                        || now.is_some_and(|now| now.saturating_sub(peer.last_rx) >= lifetime))
            });
            if eligible {
                let mut peer = self.peers[index].take().ok_or(Error::Stale)?;
                peer.receiver.close();
                self.index.retain(|entry| entry.peer != index);
                return Ok(Some(Activity::Retired));
            }
        }
        Ok(None)
    }
    /// Drain only already-admitted publication/effect frames on the original MQ.
    /// This performs no clock sample, socket receive, encryption, key borrow or
    /// new command admission. Callers can enqueue bounded address withdrawals
    /// before `finish`, then retain this same output owner until write or close.
    pub fn poll_publications(&mut self, cx: &mut Context<'_>) -> Poll<Result<Activity, Failure>> {
        if self.closed {
            return Poll::Ready(Ok(Activity::Closed));
        }
        if self.closing {
            return self.poll_close(cx);
        }
        if !self.transport_attached {
            return Poll::Pending;
        }
        if let Some(activity) = self.admit_effect()? {
            return Poll::Ready(Ok(activity));
        }
        self.write(cx)
    }
    /// Clock/key/journal-free continuation of the same original local shutdown.
    /// Call `finish` once first. No socket receive, encryption, replay admission
    /// or new TRANSPORT command is started here.
    pub fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<Result<Activity, Failure>> {
        if self.closed {
            return Poll::Ready(Ok(Activity::Closed));
        }
        if !self.closing {
            return Poll::Ready(Err(Error::NotReady.into()));
        }
        for offset in 0..3 {
            let step = (self.turn + offset) % 3;
            let activity = match step {
                0 => self.admit_effect()?,
                1 => match self.write(cx) {
                    Poll::Ready(result) => Some(result?),
                    Poll::Pending => None,
                },
                _ => self.maintenance(None)?,
            };
            if let Some(activity) = activity {
                self.turn = (step + 1) % 3;
                return Poll::Ready(Ok(activity));
            }
        }
        if self.effects.is_empty()
            && self.io.queued_frames() == 0
            && self.endpoints.iter().all(Option::is_none)
            && self.peers.iter().all(Option::is_none)
            && self.completions.iter().all(Option::is_none)
        {
            match self.io.poll_shutdown(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => {
                    self.close();
                    return Poll::Ready(Err(Failure::Transport(error)));
                }
                Poll::Ready(Ok(())) => {}
            }
            self.io.retire();
            self.publication_source.retire();
            self.transport_attached = false;
            self.closed = true;
            return Poll::Ready(Ok(Activity::Closed));
        }
        Poll::Pending
    }
    fn poll_inner(
        &mut self,
        cx: &mut Context<'_>,
        identity: &Identity,
        journal: &mut Journal,
        now: u64,
        entropy: &mut impl Entropy,
        classify: &mut impl FnMut(SocketAddr) -> io::Result<u32>,
    ) -> Poll<Result<Activity, Failure>> {
        if self.closing {
            return self.poll_close(cx);
        }
        if self.closed {
            return Poll::Ready(Err(Error::Closed.into()));
        }
        if self.identity_phase != identity::Phase::Active {
            return Poll::Pending;
        }
        if let Some(error) = self.poll_native_guard(cx) {
            return Poll::Ready(Err(error));
        }
        if identity.peer() != self.configuration.local
            || journal.local_peer() != self.configuration.local
        {
            self.close();
            return Poll::Ready(Err(Error::Authentication.into()));
        }
        if now < self.last_clock {
            return Poll::Ready(Err(Error::TimeUncertain.into()));
        }
        self.last_clock = now;
        match journal.quiescent() {
            Ok(true) => {}
            Ok(false) => return Poll::Ready(Err(Error::OutcomeUnknown.into())),
            Err(error) => return Poll::Ready(Err(error.into())),
        }
        if !self.transport_attached {
            return match self.expire_detached(now)? {
                Some(activity) => Poll::Ready(Ok(activity)),
                None => Poll::Pending,
            };
        }
        for offset in 0..10 {
            let step = (self.turn + offset) % 10;
            let activity = match step {
                0 => match self.transmit(cx, now) {
                    Poll::Ready(result) => Some(result?),
                    Poll::Pending => None,
                },
                1 => self.admit_effect()?,
                2 => match self.write(cx) {
                    Poll::Ready(result) => Some(result?),
                    Poll::Pending => None,
                },
                3 if !self.registered => None,
                3 => {
                    if self.io.frame().is_some() {
                        self.command(identity, journal, now, entropy, classify)?
                    } else {
                        match self.io.poll_read(cx) {
                            Poll::Pending => None,
                            Poll::Ready(Ok(ReadStep::Progress { .. })) => Some(Activity::Io),
                            Poll::Ready(Ok(ReadStep::Eof)) => {
                                return Poll::Ready(Err(self.transport_failed(None)));
                            }
                            Poll::Ready(Err(error)) => {
                                return Poll::Ready(Err(self.transport_failed(Some(error))));
                            }
                        }
                    }
                }
                4 => {
                    let mut activity = None;
                    for offset in 0..self.sockets.len() {
                        let socket = (self.rx_cursor + offset) % self.sockets.len();
                        if self.sockets[socket].is_closed() {
                            continue;
                        }
                        match self.sockets[socket].poll_receive(cx) {
                            Poll::Pending => {}
                            Poll::Ready(Err(SocketError::Io(error)))
                                if gnunet_native::network::isolated_datagram_receive_error(
                                    &error,
                                ) =>
                            {
                                self.rx_cursor = (socket + 1) % self.sockets.len();
                                activity = Some(Activity::ReceiveError { socket, error });
                                break;
                            }
                            Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                            Poll::Ready(Ok(receipt)) => {
                                if let Some(progress) = self
                                    .incoming(socket, identity, journal, receipt, now, classify)?
                                {
                                    self.rx_cursor = (socket + 1) % self.sockets.len();
                                    activity = Some(progress);
                                    break;
                                }
                            }
                        }
                    }
                    activity
                }
                5 => self.acknowledge(now)?,
                6 => self.maintenance(Some(now))?,
                7 => self.discovery_step(cx, identity, now)?,
                8 => match self.burst_step(cx, now, classify) {
                    Ok(activity) => activity,
                    Err(error) => {
                        self.close();
                        return Poll::Ready(Err(error));
                    }
                },
                _ if self.restoring => self.restore_endpoint(now)?,
                _ => None,
            };
            if let Some(activity) = activity {
                self.turn = (step + 1) % 10;
                return Poll::Ready(Ok(activity));
            }
        }
        Poll::Pending
    }
}
