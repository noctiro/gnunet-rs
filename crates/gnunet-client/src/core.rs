//! Typed owner for official CORE application/monitor IPC, without service logic.
//! Pure layouts live in `gnunet_wire::official::core` and are re-exported here.
use gnunet_types::{Error, Rejected};
pub use gnunet_wire::official::core::{
    ClassOrder, Direction, FULL_INBOUND, FULL_OUTBOUND, HEADER_INBOUND, HEADER_OUTBOUND, KxState,
    MAX_SEND_BYTES, MessageTypes, PeerClass, PeerId, Request, Response, Traffic,
};
use gnunet_wire::official::core::{
    REMOTE_REQUEST_LIMIT, SEND_PREFIX, SEND_REQUEST_LEN, message_sequence,
};

/// Stable, non-zero-sized brand storage for one application or monitor client.
#[derive(Debug)]
pub struct Instance {
    _marker: u8,
}
impl Instance {
    /// Fresh client identity; keep outside the client while any token exists.
    #[must_use]
    pub const fn new() -> Self {
        Self { _marker: 0 }
    }
}
impl Default for Instance {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Clone, Copy, Debug)]
struct Key<'a> {
    owner: &'a Instance,
    epoch: u64,
    slot: usize,
    generation: u64,
}
impl PartialEq for Key<'_> {
    fn eq(&self, other: &Self) -> bool {
        ::core::ptr::eq(self.owner, other.owner)
            && self.epoch == other.epoch
            && self.slot == other.slot
            && self.generation == other.generation
    }
}
impl Eq for Key<'_> {}
/// Original physical CORE service connection, never a serialized request field.
#[derive(Clone, Copy, Debug)]
pub struct ConnectionEpoch<'a> {
    owner: &'a Instance,
    value: u64,
}
impl PartialEq for ConnectionEpoch<'_> {
    fn eq(&self, other: &Self) -> bool {
        ::core::ptr::eq(self.owner, other.owner) && self.value == other.value
    }
}
impl Eq for ConnectionEpoch<'_> {}
impl ConnectionEpoch<'_> {
    /// Diagnostic local generation; a value alone is not authority.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.value
    }
}
/// Current peer generation, including the local loopback peer from INIT_REPLY.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Peer<'a> {
    key: Key<'a>,
    identity: PeerId,
    class: PeerClass,
}
impl Peer<'_> {
    /// Official identity from the actual service notification.
    #[must_use]
    pub const fn identity(self) -> PeerId {
        self.identity
    }
    /// Informational peer class.
    #[must_use]
    pub const fn class(self) -> PeerClass {
        self.class
    }
}
/// Original local send operation, distinct from its finite wire correlation value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendId<'a>(Key<'a>);
/// Retained payload source for an original operation. It may be a host Vec/Box,
/// a borrowed no_std slice or another AsRef source. Request admission locks only
/// metadata/length; the body is prepared once after READY and may be generated then.
/// No Clone or mutable access to the source is provided by this owner.
#[must_use = "retain the operation until completion or explicit cancellation"]
pub struct SendOperation<'a, T> {
    id: SendId<'a>,
    source: T,
}
impl<'a, T> SendOperation<'a, T> {
    /// Stable route to the original operation, without exposing a wire permit.
    #[must_use]
    pub const fn id(&self) -> SendId<'a> {
        self.id
    }
}
/// One encoded immutable payload frame. Keep this lease through partial writes.
/// Encoding cannot be repeated for the same operation after this is admitted.
#[must_use = "retain the original immutable frame across partial or canceled IO waits"]
pub struct PreparedFrame<'owner, 'frame> {
    send: SendId<'owner>,
    bytes: &'frame [u8],
}
impl<'owner> PreparedFrame<'owner, '_> {
    /// Original local operation for actual write progress.
    #[must_use]
    pub const fn send(&self) -> SendId<'owner> {
        self.send
    }
    /// Frozen original bytes. Their backing output cannot be mutated during this lease.
    #[must_use]
    pub const fn bytes(&self) -> &[u8] {
        self.bytes
    }
}
/// A local operation result; there is no remote application-delivery ACK in this IPC.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendOutcome {
    /// All original CORE_SEND bytes were actually written to the service socket.
    Written,
    /// The matching READY explicitly rejected the request with size zero.
    Rejected,
    /// The host canceled before transmitting any CORE_SEND byte.
    CancelledBeforePayload,
    /// A started original frame drained after local cancellation; delivery is uncertain.
    CancelledAfterWrite,
    /// The original peer generation disappeared.
    PeerDisconnected,
    /// The original service socket was retired, possibly after partial IO.
    ConnectionLost,
}
/// Return original owned source and its actual local result together.
pub struct SendCompletion<T> {
    /// Original caller-owned payload source, not a new copy or regenerated view.
    pub source: T,
    /// Local result, distinct from network/application delivery.
    pub outcome: SendOutcome,
}
/// One application event. Borrowed traffic survives only its input frame's lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event<'owner, 'frame> {
    /// Genuine INIT_REPLY; the service's local identity is a loopback peer.
    Ready {
        /// Current local peer generation.
        local: Peer<'owner>,
        /// Last observed identity on a previous connection, if any.
        previous_identity: Option<PeerId>,
    },
    /// A remote peer is available.
    Connected(Peer<'owner>),
    /// A remote peer disappeared.
    Disconnected(Peer<'owner>),
    /// Matching send permission; the original operation owns its payload source.
    SendReady {
        /// Original local operation.
        send: SendId<'owner>,
        /// Nonzero permitted bytes, at least the original requested size.
        capacity: u16,
    },
    /// Matching zero-size READY; consume the retained operation with `finish`.
    Rejected(SendId<'owner>),
    /// READY for a canceled/superseded or already handled original request.
    IgnoredReady {
        /// Current peer identity.
        peer: PeerId,
        /// Original echoed finite wire correlation number.
        request_id: u16,
    },
    /// An actual full message or explicitly incomplete observational preview.
    Traffic {
        /// Sender for inbound, receiver for outbound.
        peer: PeerId,
        /// Current app peer when announced; observational options can expose others.
        connection: Option<Peer<'owner>>,
        /// Direction selected by the actual response identifier.
        direction: Direction,
        /// Full message or header-only preview; no synthetic payload is supplied.
        traffic: Traffic<'frame>,
    },
    /// C's redundant self connect/disconnect notification is ignored.
    IgnoredSelfNotification,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Offline,
    Initializing,
    Ready,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum PeerPhase {
    Empty,
    Connected,
    LostNotice,
    // Retain unresolved finite request IDs across peer generations on this MQ.
    Dormant,
}
#[derive(Clone, Copy)]
struct PeerSlot<'a> {
    generation: u64,
    epoch: u64,
    identity: PeerId,
    class: PeerClass,
    phase: PeerPhase,
    issued: u64,
    ready_frontier: u64,
    active: Option<SendId<'a>>,
}
impl PeerSlot<'_> {
    const EMPTY: Self = Self {
        generation: 0,
        epoch: 0,
        identity: PeerId([0; 32]),
        class: PeerClass::UNKNOWN,
        phase: PeerPhase::Empty,
        issued: 0,
        ready_frontier: 0,
        active: None,
    };
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum SendPhase {
    AwaitReady,
    Ready,
    Rejected,
    Payload,
}
#[derive(Clone, Copy)]
struct SendRecord<'a> {
    peer: Peer<'a>,
    serial: u64,
    size: u16,
    priority: u32,
    deadline: u64,
    phase: SendPhase,
    written: usize,
    cancelled: bool,
    peer_lost: bool,
    connection_lost: bool,
}
impl SendRecord<'_> {
    fn outcome(self) -> Option<SendOutcome> {
        if self.connection_lost {
            return Some(SendOutcome::ConnectionLost);
        }
        if self.phase == SendPhase::Rejected {
            return Some(SendOutcome::Rejected);
        }
        if self.phase != SendPhase::Payload || (self.peer_lost && self.written == 0) {
            return self.peer_lost.then_some(SendOutcome::PeerDisconnected);
        }
        if self.written != SEND_PREFIX + usize::from(self.size) {
            return None;
        }
        Some(if self.cancelled {
            SendOutcome::CancelledAfterWrite
        } else if self.peer_lost {
            SendOutcome::PeerDisconnected
        } else {
            SendOutcome::Written
        })
    }
}
#[derive(Clone, Copy)]
struct SendSlot<'a> {
    generation: u64,
    record: Option<SendRecord<'a>>,
}
impl SendSlot<'_> {
    const EMPTY: Self = Self {
        generation: 0,
        record: None,
    };
}

/// One bounded application client. P includes the local loopback peer, live peers
/// and unresolved per-PID request frontiers across same-MQ peer generations.
/// S bounds original send metadata. Capacity may require explicit physical MQ
/// retirement; unsettled ID tombstones are never silently evicted. Actual sockets,
/// immutable frames and retries are host-owned.
pub struct CoreClient<'a, const P: usize, const S: usize> {
    instance: &'a Instance,
    options: u32,
    types: &'a [u16],
    order: ClassOrder,
    epoch: u64,
    phase: Phase,
    last_identity: Option<PeerId>,
    peers: [PeerSlot<'a>; P],
    sends: [SendSlot<'a>; S],
}
impl<'a, const P: usize, const S: usize> CoreClient<'a, P, S> {
    /// Select bounded metadata, current class ABI and subscriptions. No IO occurs.
    pub fn new(
        instance: &'a mut Instance,
        order: ClassOrder,
        options: u32,
        types: &'a [u16],
    ) -> Result<Self, Error> {
        if P == 0 || S == 0 {
            return Err(Error::Capacity);
        }
        if options & !gnunet_wire::official::core::OPTIONS != 0 {
            return Err(Error::Unsupported);
        }
        if types.len() > (usize::from(u16::MAX) - 8) / 2 {
            return Err(Error::TooLarge);
        }
        Ok(Self {
            instance,
            options,
            types,
            order,
            epoch: 0,
            phase: Phase::Offline,
            last_identity: None,
            peers: [PeerSlot::EMPTY; P],
            sends: [SendSlot::EMPTY; S],
        })
    }
    /// Admit INIT on a real connected MQ. The host must retain its exact frame
    /// before waiting. Only an actual INIT_REPLY authorizes application operations.
    pub fn begin(&mut self, output: &mut [u8]) -> Result<(ConnectionEpoch<'a>, usize), Error> {
        if self.phase != Phase::Offline {
            return Err(Error::Conflict);
        }
        let epoch = self.epoch.checked_add(1).ok_or(Error::Capacity)?;
        let len = Request::Init {
            options: self.options,
            types: MessageTypes::new(self.types),
        }
        .encode(output)?;
        self.epoch = epoch;
        self.phase = Phase::Initializing;
        Ok((
            ConnectionEpoch {
                owner: self.instance,
                value: epoch,
            },
            len,
        ))
    }
    fn epoch_valid(&self, epoch: ConnectionEpoch<'_>) -> Result<(), Error> {
        if !::core::ptr::eq(self.instance, epoch.owner) || epoch.value != self.epoch {
            Err(Error::Stale)
        } else if self.phase == Phase::Offline {
            Err(Error::Closed)
        } else {
            Ok(())
        }
    }
    fn peer_at(&self, index: usize) -> Peer<'a> {
        let slot = &self.peers[index];
        Peer {
            key: Key {
                owner: self.instance,
                epoch: slot.epoch,
                slot: index,
                generation: slot.generation,
            },
            identity: slot.identity,
            class: slot.class,
        }
    }
    fn peer_index(&self, peer: Peer<'_>) -> Result<usize, Error> {
        if self.phase != Phase::Ready
            || !::core::ptr::eq(self.instance, peer.key.owner)
            || peer.key.epoch != self.epoch
        {
            return Err(Error::Stale);
        }
        let slot = self.peers.get(peer.key.slot).ok_or(Error::Stale)?;
        if slot.phase != PeerPhase::Connected
            || slot.generation != peer.key.generation
            || slot.identity != peer.identity
        {
            return Err(Error::Stale);
        }
        Ok(peer.key.slot)
    }
    /// Find a currently available peer, including local self-loopback.
    #[must_use]
    pub fn peer(&self, identity: PeerId) -> Option<Peer<'a>> {
        self.peers
            .iter()
            .position(|p| p.phase == PeerPhase::Connected && p.identity == identity)
            .map(|index| self.peer_at(index))
    }
    fn add_peer(&mut self, identity: PeerId, class: PeerClass) -> Result<Peer<'a>, Error> {
        if self.peer(identity).is_some() {
            return Err(Error::Malformed);
        }
        let index = self
            .peers
            .iter()
            .position(|p| p.phase == PeerPhase::Dormant && p.identity == identity)
            .or_else(|| {
                self.peers
                    .iter()
                    .position(|p| p.phase == PeerPhase::Empty && p.generation < u64::MAX)
            })
            .ok_or(Error::Capacity)?;
        let slot = &mut self.peers[index];
        let (issued, ready_frontier) = if slot.phase == PeerPhase::Dormant {
            (slot.issued, slot.ready_frontier)
        } else {
            (0, 0)
        };
        let generation = slot.generation.checked_add(1).ok_or(Error::Capacity)?;
        *slot = PeerSlot {
            generation,
            epoch: self.epoch,
            identity,
            class,
            phase: PeerPhase::Connected,
            issued,
            ready_frontier,
            active: None,
        };
        Ok(self.peer_at(index))
    }
    /// Process one complete actual response. Unknown/malformed input retires the
    /// connection; capacity refusal requires the host to retain/retry its input.
    pub fn receive<'frame>(
        &mut self,
        epoch: ConnectionEpoch<'_>,
        input: &'frame [u8],
    ) -> Result<Event<'a, 'frame>, Error> {
        self.epoch_valid(epoch)?;
        let result =
            Response::decode(input, self.order).and_then(|response| self.response(response));
        if matches!(
            result,
            Err(Error::Malformed | Error::Truncated | Error::InvalidInput | Error::Unsupported)
        ) {
            self.retire();
        }
        result
    }
    fn response<'frame>(&mut self, response: Response<'frame>) -> Result<Event<'a, 'frame>, Error> {
        if let Response::InitReply { identity, class } = response {
            if self.phase != Phase::Initializing {
                return Err(Error::Malformed);
            }
            let local = self.add_peer(identity, class)?;
            let previous_identity = self.last_identity;
            self.last_identity = Some(identity);
            self.phase = Phase::Ready;
            return Ok(Event::Ready {
                local,
                previous_identity,
            });
        }
        if self.phase != Phase::Ready {
            return Err(Error::Malformed);
        }
        match response {
            Response::Connected { peer, class } => {
                if Some(peer) == self.last_identity {
                    return Ok(Event::IgnoredSelfNotification);
                }
                Ok(Event::Connected(self.add_peer(peer, class)?))
            }
            Response::Disconnected(identity) => {
                if Some(identity) == self.last_identity {
                    return Ok(Event::IgnoredSelfNotification);
                }
                let peer = self.peer(identity).ok_or(Error::Malformed)?;
                let slot = &mut self.peers[peer.key.slot];
                slot.phase = if slot.issued == slot.ready_frontier {
                    PeerPhase::Empty
                } else {
                    PeerPhase::Dormant
                };
                slot.active = None;
                for send in &mut self.sends {
                    if let Some(record) = &mut send.record
                        && record.peer == peer
                        && record.outcome().is_none()
                    {
                        record.peer_lost = true;
                    }
                }
                Ok(Event::Disconnected(peer))
            }
            Response::SendReady {
                peer,
                request_id,
                size,
            } => self.ready(peer, request_id, size),
            Response::Traffic {
                direction,
                peer,
                traffic,
            } => {
                let observation = match direction {
                    Direction::Inbound => self.options & (FULL_INBOUND | HEADER_INBOUND),
                    Direction::Outbound => self.options & (FULL_OUTBOUND | HEADER_OUTBOUND),
                };
                if observation == 0 && direction == Direction::Outbound {
                    return Err(Error::Malformed);
                }
                let connection = self.peer(peer);
                if observation == 0 && connection.is_none() {
                    return Err(Error::Malformed);
                }
                if matches!(traffic, Traffic::Header(_)) && observation == 0 {
                    return Err(Error::Malformed);
                }
                Ok(Event::Traffic {
                    peer,
                    connection,
                    direction,
                    traffic,
                })
            }
            _ => Err(Error::Unsupported),
        }
    }
    fn ready(
        &mut self,
        identity: PeerId,
        request_id: u16,
        size: u16,
    ) -> Result<Event<'a, 'static>, Error> {
        let index = self
            .peers
            .iter()
            .position(|p| {
                p.identity == identity
                    && matches!(p.phase, PeerPhase::Connected | PeerPhase::Dormant)
            })
            .ok_or(Error::Malformed)?;
        let issued = self.peers[index].issued;
        let distance = u64::from((issued as u16).wrapping_sub(request_id));
        let serial = issued.saturating_sub(distance);
        let ignore = Event::IgnoredReady {
            peer: identity,
            request_id,
        };
        if serial == 0 || serial <= self.peers[index].ready_frontier {
            return Ok(ignore);
        }
        let active = self.peers[index].active;
        let record_index = match active {
            Some(id) => Some(self.send_index(id)?),
            None => None,
        };
        if let Some(slot_index) = record_index {
            let record = self.sends[slot_index].record.ok_or(Error::Stale)?;
            if record.serial == serial && record.phase == SendPhase::AwaitReady {
                if size != 0 && size < record.size {
                    return Err(Error::Malformed);
                }
                self.peers[index].ready_frontier = serial;
                self.sends[slot_index]
                    .record
                    .as_mut()
                    .ok_or(Error::Stale)?
                    .phase = if size == 0 {
                    SendPhase::Rejected
                } else {
                    SendPhase::Ready
                };
                let send = active.ok_or(Error::Stale)?;
                return Ok(if size == 0 {
                    Event::Rejected(send)
                } else {
                    Event::SendReady {
                        send,
                        capacity: size,
                    }
                });
            }
        }
        // A real ordered READY also retires older canceled requests' possible replies.
        self.peers[index].ready_frontier = serial;
        if self.peers[index].phase == PeerPhase::Dormant && serial == issued {
            self.peers[index].phase = PeerPhase::Empty;
        }
        Ok(ignore)
    }
    fn remote_body(&self, peer: PeerId, messages: &[u8]) -> Result<(), Error> {
        if Some(peer) == self.last_identity {
            return Ok(());
        }
        if messages.len() > REMOTE_REQUEST_LIMIT {
            return Err(Error::TooLarge);
        }
        let mut rest = messages;
        while !rest.is_empty() {
            let (frame, tail) = gnunet_wire::official::Frame::decode_prefix(rest)?;
            // queue_request permits equality for the aggregate, but the actual
            // normal C transmission loop asserts strict inequality per message.
            if frame.encoded_len() >= REMOTE_REQUEST_LIMIT {
                return Err(Error::TooLarge);
            }
            rest = tail;
        }
        Ok(())
    }
    // Exact original peer/frontier/send-slot check shared with admission. This
    // grants no service READY permit and reserves no metadata or source bytes.
    fn request_slot(&self, peer: Peer<'_>) -> Result<(usize, usize, u64), Error> {
        let peer_index = self.peer_index(peer)?;
        if self.peers[peer_index].active.is_some() {
            return Err(Error::WouldBlock);
        }
        let serial = self.peers[peer_index]
            .issued
            .checked_add(1)
            .ok_or(Error::Capacity)?;
        if serial - self.peers[peer_index].ready_frontier > u64::from(u16::MAX) {
            return Err(Error::WouldBlock);
        }
        let index = self
            .sends
            .iter()
            .position(|slot| slot.record.is_none() && slot.generation < u64::MAX)
            .ok_or(Error::Capacity)?;
        Ok((peer_index, index, serial))
    }
    /// Observe whether this exact current peer can admit request metadata now.
    /// This read-only capacity observation is not a reservation, wire SendReady,
    /// physical write or remote acknowledgement. Actual request_send still
    /// validates the immutable source and may refuse without consuming it.
    pub fn request_available(&self, peer: Peer<'_>) -> Result<bool, Error> {
        match self.request_slot(peer) {
            Ok(_) => Ok(true),
            Err(Error::WouldBlock | Error::Capacity) => Ok(false),
            Err(error) => Err(error),
        }
    }
    /// Admit a request and retain its source. Only metadata/length is fixed now;
    /// body bytes are frozen exactly once by `prepare_payload` after matching READY.
    /// Preflight the host MQ before calling; the admitted request must drain even
    /// if this operation is canceled, because there is no wire cancellation.
    pub fn request_send<T: AsRef<[u8]>>(
        &mut self,
        peer: Peer<'a>,
        priority: u32,
        deadline: u64,
        source: T,
        output: &mut [u8],
    ) -> Result<(SendOperation<'a, T>, usize), Rejected<T>> {
        if output.len() < SEND_REQUEST_LEN {
            return Err(Rejected {
                value: source,
                reason: Error::Capacity,
            });
        }
        let prepared = (|| {
            let (peer_index, index, serial) = self.request_slot(peer)?;
            let messages = source.as_ref();
            message_sequence(messages)?;
            self.remote_body(peer.identity, messages)?;
            let size = u16::try_from(messages.len()).map_err(|_| Error::TooLarge)?;
            let len = Request::SendRequest {
                peer: peer.identity,
                priority,
                deadline,
                size,
                request_id: serial as u16,
            }
            .encode(output)?;
            Ok((peer_index, index, serial, size, len))
        })();
        let (peer_index, index, serial, size, len) = match prepared {
            Ok(value) => value,
            Err(reason) => {
                return Err(Rejected {
                    value: source,
                    reason,
                });
            }
        };
        let slot = &mut self.sends[index];
        slot.generation += 1;
        slot.record = Some(SendRecord {
            peer,
            serial,
            size,
            priority,
            deadline,
            phase: SendPhase::AwaitReady,
            written: 0,
            cancelled: false,
            peer_lost: false,
            connection_lost: false,
        });
        let id = SendId(Key {
            owner: self.instance,
            epoch: self.epoch,
            slot: index,
            generation: slot.generation,
        });
        self.peers[peer_index].issued = serial;
        self.peers[peer_index].active = Some(id);
        Ok((SendOperation { id, source }, len))
    }
    fn send_index(&self, id: SendId<'_>) -> Result<usize, Error> {
        if !::core::ptr::eq(self.instance, id.0.owner) {
            return Err(Error::Stale);
        }
        let slot = self.sends.get(id.0.slot).ok_or(Error::Stale)?;
        let record = slot.record.ok_or(Error::Stale)?;
        if slot.generation != id.0.generation || record.peer.key.epoch != id.0.epoch {
            return Err(Error::Stale);
        }
        Ok(id.0.slot)
    }
    /// Freeze the source's current complete body once. A source whose AsRef view
    /// changes length is rejected; same-length deferred generation is supported.
    /// The returned immutable frame, not T, is the authority for later IO.
    pub fn prepare_payload<'frame, T: AsRef<[u8]>>(
        &mut self,
        operation: &SendOperation<'a, T>,
        output: &'frame mut [u8],
    ) -> Result<PreparedFrame<'a, 'frame>, Error> {
        let index = self.send_index(operation.id)?;
        let record = self.sends[index].record.ok_or(Error::Stale)?;
        if record.outcome().is_some() {
            return Err(Error::Closed);
        }
        if record.phase != SendPhase::Ready {
            return Err(Error::NotReady);
        }
        self.peer_index(record.peer)?;
        if output.len() < SEND_PREFIX + usize::from(record.size) {
            return Err(Error::Capacity);
        }
        let messages = operation.source.as_ref();
        if messages.len() != usize::from(record.size) {
            return Err(Error::InvalidInput);
        }
        self.remote_body(record.peer.identity, messages)?;
        let len = Request::Send {
            peer: record.peer.identity,
            priority: record.priority,
            deadline: record.deadline,
            messages,
        }
        .encode(output)?;
        self.sends[index].record.as_mut().ok_or(Error::Stale)?.phase = SendPhase::Payload;
        Ok(PreparedFrame {
            send: operation.id,
            bytes: &output[..len],
        })
    }
    /// Report actual nonzero bytes written from the retained original payload frame.
    pub fn payload_bytes_written(
        &mut self,
        id: SendId<'_>,
        count: usize,
    ) -> Result<Option<SendOutcome>, Error> {
        let index = self.send_index(id)?;
        let record = self.sends[index].record.as_mut().ok_or(Error::Stale)?;
        if record.outcome().is_some() {
            return Err(Error::Closed);
        }
        if record.phase != SendPhase::Payload {
            return Err(Error::NotReady);
        }
        let remaining = SEND_PREFIX + usize::from(record.size) - record.written;
        if count == 0 || count > remaining {
            return Err(Error::InvalidInput);
        }
        record.written += count;
        Ok(record.outcome())
    }
    /// Mark cancellation after a partial payload write. Keep the original frame
    /// and operation until drained, or retire the entire physical service MQ.
    pub fn cancel_started(&mut self, id: SendId<'_>) -> Result<(), Error> {
        let index = self.send_index(id)?;
        let record = self.sends[index].record.as_mut().ok_or(Error::Stale)?;
        if record.phase != SendPhase::Payload || record.written == 0 || record.outcome().is_some() {
            return Err(Error::Conflict);
        }
        record.cancelled = true;
        Ok(())
    }
    fn remove_send(&mut self, index: usize, id: SendId<'_>) {
        if let Some(record) = self.sends[index].record {
            let peer = &mut self.peers[record.peer.key.slot];
            if peer.active == Some(id) {
                peer.active = None;
            }
        }
        self.sends[index].record = None;
    }
    /// Cancel before any payload byte. The host must first remove any wholly
    /// unwritten prepared payload frame; an already admitted request still drains.
    pub fn cancel_unwritten<T>(
        &mut self,
        operation: SendOperation<'a, T>,
    ) -> Result<SendCompletion<T>, Rejected<SendOperation<'a, T>>> {
        let result = (|| {
            let index = self.send_index(operation.id)?;
            let record = self.sends[index].record.ok_or(Error::Stale)?;
            if record.outcome().is_some() || record.written != 0 {
                return Err(Error::Conflict);
            }
            Ok(index)
        })();
        match result {
            Err(reason) => Err(Rejected {
                value: operation,
                reason,
            }),
            Ok(index) => {
                self.remove_send(index, operation.id);
                Ok(SendCompletion {
                    source: operation.source,
                    outcome: SendOutcome::CancelledBeforePayload,
                })
            }
        }
    }
    /// Consume a terminal original operation and recover its source once.
    pub fn finish<T>(
        &mut self,
        operation: SendOperation<'a, T>,
    ) -> Result<SendCompletion<T>, Rejected<SendOperation<'a, T>>> {
        let result = (|| {
            let index = self.send_index(operation.id)?;
            let outcome = self.sends[index]
                .record
                .ok_or(Error::Stale)?
                .outcome()
                .ok_or(Error::WouldBlock)?;
            Ok((index, outcome))
        })();
        match result {
            Err(reason) => Err(Rejected {
                value: operation,
                reason,
            }),
            Ok((index, outcome)) => {
                self.remove_send(index, operation.id);
                Ok(SendCompletion {
                    source: operation.source,
                    outcome,
                })
            }
        }
    }
    /// Retire the failed original socket. Pending results remain recoverable;
    /// peer disconnect notices can be drained before their slots are reused.
    pub fn connection_lost(&mut self, epoch: ConnectionEpoch<'_>) -> Result<(), Error> {
        self.epoch_valid(epoch)?;
        self.retire();
        Ok(())
    }
    fn retire(&mut self) {
        self.phase = Phase::Offline;
        for peer in &mut self.peers {
            if peer.phase == PeerPhase::Connected {
                peer.phase = PeerPhase::LostNotice;
            } else if peer.phase == PeerPhase::Dormant {
                peer.phase = PeerPhase::Empty;
            }
            peer.active = None;
        }
        for send in &mut self.sends {
            if let Some(record) = &mut send.record
                && record.outcome().is_none()
            {
                record.connection_lost = true;
            }
        }
    }
    /// Drain each actual service-loss peer notification once, including local self.
    pub fn next_lost_peer(&mut self) -> Option<Peer<'a>> {
        let index = self
            .peers
            .iter()
            .position(|p| p.phase == PeerPhase::LostNotice)?;
        let peer = self.peer_at(index);
        self.peers[index].phase = PeerPhase::Empty;
        Some(peer)
    }
}

/// One continuous monitor event. Snapshot completion does not terminate monitoring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MonitorEvent {
    /// Actual peer/KX state and its original absolute timeout.
    Update {
        /// Peer identity from the service.
        peer: PeerId,
        /// Informational state, including future numeric values.
        state: KxState,
        /// Absolute timeout, including FOREVER.
        timeout: u64,
    },
    /// Actual state11/zeropeer/FOREVER marker ended the initial snapshot.
    SnapshotFinished,
    /// Actual service connection loss, represented locally rather than a wire END.
    ServiceLost,
}
/// Standalone current CORE monitor owner. Cancellation closes its physical MQ;
/// there is no invented UNWATCH or per-peer monitor request identifier.
pub struct Monitor<'a> {
    instance: &'a Instance,
    epoch: u64,
    online: bool,
    snapshot: bool,
}
impl<'a> Monitor<'a> {
    /// Attach unique identity storage; creates no native connection.
    #[must_use]
    pub const fn new(instance: &'a mut Instance) -> Self {
        Self {
            instance,
            epoch: 0,
            online: false,
            snapshot: false,
        }
    }
    /// Admit a real monitor request on a connected socket; INIT is not needed.
    pub fn begin(&mut self, output: &mut [u8]) -> Result<(ConnectionEpoch<'a>, usize), Error> {
        if self.online {
            return Err(Error::Conflict);
        }
        let epoch = self.epoch.checked_add(1).ok_or(Error::Capacity)?;
        let len = Request::Monitor.encode(output)?;
        self.epoch = epoch;
        self.online = true;
        self.snapshot = true;
        Ok((
            ConnectionEpoch {
                owner: self.instance,
                value: epoch,
            },
            len,
        ))
    }
    fn check(&self, epoch: ConnectionEpoch<'_>) -> Result<(), Error> {
        if !::core::ptr::eq(self.instance, epoch.owner) || self.epoch != epoch.value {
            Err(Error::Stale)
        } else if !self.online {
            Err(Error::Closed)
        } else {
            Ok(())
        }
    }
    /// Consume actual monitor bytes. Class byte order is irrelevant to type79.
    pub fn receive(
        &mut self,
        epoch: ConnectionEpoch<'_>,
        bytes: &[u8],
    ) -> Result<MonitorEvent, Error> {
        self.check(epoch)?;
        let result = (|| {
            let Response::Monitor {
                state,
                peer,
                timeout,
            } = Response::decode(bytes, ClassOrder::Little)?
            else {
                return Err(Error::Unsupported);
            };
            if state == KxState::SNAPSHOT_FINISHED {
                if !self.snapshot || peer.0 != [0; 32] || timeout != u64::MAX {
                    return Err(Error::Malformed);
                }
                self.snapshot = false;
                return Ok(MonitorEvent::SnapshotFinished);
            }
            Ok(MonitorEvent::Update {
                state,
                peer,
                timeout,
            })
        })();
        if result.is_err() {
            self.online = false;
        }
        result
    }
    /// Cancel/loss of this actual connection. Host closes only that original MQ;
    /// an optional later `begin` creates a new epoch and a fresh initial snapshot.
    pub fn connection_lost(&mut self, epoch: ConnectionEpoch<'_>) -> Result<MonitorEvent, Error> {
        self.check(epoch)?;
        self.online = false;
        Ok(MonitorEvent::ServiceLost)
    }
}
