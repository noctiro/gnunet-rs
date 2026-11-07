//! Sans-I/O ownership for the current public TRANSPORT client boundary.
use super::{PeerId, RECEIVE_WINDOW, Request, Response, SEND_WINDOW, Start};
use gnunet_types::Error;

/// Stable caller-owned identity for one client instance. It is not a wire value.
/// Keep this storage outside the client; moving the client does not move its brand.
#[derive(Debug)]
pub struct Instance {
    _marker: u8,
}
impl Instance {
    /// Fresh non-zero-sized identity storage.
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
        core::ptr::eq(self.owner, other.owner)
            && self.epoch == other.epoch
            && self.slot == other.slot
            && self.generation == other.generation
    }
}
impl Eq for Key<'_> {}

/// One original physical service connection, branded to its client instance.
#[derive(Clone, Copy, Debug)]
pub struct ConnectionEpoch<'a> {
    owner: &'a Instance,
    serial: u64,
}
impl PartialEq for ConnectionEpoch<'_> {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.owner, other.owner) && self.serial == other.serial
    }
}
impl Eq for ConnectionEpoch<'_> {}
impl ConnectionEpoch<'_> {
    /// Diagnostic local generation; never serialized or sufficient as authority.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.serial
    }
}
/// A peer announced on one original connection and generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Peer<'a> {
    key: Key<'a>,
    identity: PeerId,
}
impl Peer<'_> {
    /// Official peer identity, without a claim of CORE authentication.
    #[must_use]
    pub const fn identity(self) -> PeerId {
        self.identity
    }
}
/// Original local SEND operation. It is never a service-side message identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendId<'a>(Key<'a>);
/// Original received message awaiting explicit application processing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveId<'a>(Key<'a>);
/// A local SEND outcome. None of these asserts remote application delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendOutcome {
    /// The entire original IPC envelope was actually written to its socket.
    Written,
    /// The host removed the original envelope before transmitting any byte.
    CancelledUnsent,
    /// Cancellation suppressed completion while an admitted frame drained.
    /// TRANSPORT might have processed the message; cancellation cannot retract it.
    CancelledAfterWrite,
    /// The peer disappeared before this frame finished its local write.
    PeerDisconnected,
    /// The original service connection was retired, possibly after partial IO.
    ConnectionLost,
}
/// One decoded event. A receive token is not automatically acknowledged on Drop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event<'owner, 'frame> {
    /// A newly announced peer, initially with four SEND credits.
    Connected(Peer<'owner>),
    /// One peer disappeared. Other peers on this MQ remain independent.
    Disconnected(Peer<'owner>),
    /// A real SEND_OK returned one unit of flow-control credit.
    SendCredit(Peer<'owner>),
    /// A returned unit belongs to a retired generation, or the peer is absent.
    /// It never grants credit to a later same-identity generation.
    LateSendCredit(PeerId),
    /// Application processing owns this credit until `complete_receive` is called.
    Received {
        /// Original current peer generation.
        peer: Peer<'owner>,
        /// Original processing token, consumed once by `complete_receive`.
        receive: ReceiveId<'owner>,
        /// Borrowed complete inner message, without retaining the caller's buffer.
        message: &'frame [u8],
    },
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum PeerState {
    Empty,
    Connected,
    LostNotice,
}
#[derive(Clone, Copy)]
struct PeerSlot {
    generation: u64,
    epoch: u64,
    identity: PeerId,
    state: PeerState,
    credit: u32,
}
impl PeerSlot {
    const EMPTY: Self = Self {
        generation: 0,
        epoch: 0,
        identity: PeerId([0; 32]),
        state: PeerState::Empty,
        credit: 0,
    };
}
#[derive(Clone, Copy)]
struct SendRecord<'a> {
    peer: Peer<'a>,
    len: usize,
    written: usize,
    cancelled: bool,
    peer_lost: bool,
    connection_lost: bool,
    deferred_refund: bool,
}
impl SendRecord<'_> {
    fn outcome(self) -> Option<SendOutcome> {
        if self.connection_lost {
            Some(SendOutcome::ConnectionLost)
        } else if self.cancelled && self.written == 0 {
            Some(SendOutcome::CancelledUnsent)
        } else if self.written != self.len {
            None
        } else if self.cancelled {
            Some(SendOutcome::CancelledAfterWrite)
        } else if self.peer_lost {
            Some(SendOutcome::PeerDisconnected)
        } else {
            Some(SendOutcome::Written)
        }
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
#[derive(Clone, Copy)]
struct ReceiveSlot<'a> {
    generation: u64,
    peer: Option<Peer<'a>>,
}
impl ReceiveSlot<'_> {
    const EMPTY: Self = Self {
        generation: 0,
        peer: None,
    };
}
#[derive(Clone, Copy)]
struct RefundAccount {
    used: bool,
    identity: PeerId,
    retired: u32,
    deferred: u32,
}
impl RefundAccount {
    const EMPTY: Self = Self {
        used: false,
        identity: PeerId([0; 32]),
        retired: 0,
        deferred: 0,
    };
}

/// One allocation-free client owner. P bounds peers, S original local SENDs, R
/// unprocessed receives and D identities with unresolved refund ownership.
/// Accounts are reserved before SEND admission, so disconnect processing never
/// needs new storage or blocks later credits. The host owns sockets/framed IO.
///
/// Enqueue complete immutable encoded frames in original order. Actual write
/// progress must be reported with `send_bytes_written` before processing further
/// service frames, so a zero cursor really is unwritten. Dropping a waiting future
/// must not drop its socket, cursor or unfinished frame. The same owner can move.
/// Instance storage cannot be reset while its capabilities remain borrowed.
pub struct TransportClient<'a, const P: usize, const S: usize, const R: usize, const D: usize = P> {
    instance: &'a Instance,
    start: Start,
    epoch: u64,
    online: bool,
    peers: [PeerSlot; P],
    sends: [SendSlot<'a>; S],
    receives: [ReceiveSlot<'a>; R],
    refunds: [RefundAccount; D],
}
impl<'a, const P: usize, const S: usize, const R: usize, const D: usize>
    TransportClient<'a, P, S, R, D>
{
    /// Reserve a unique instance and finite resources. R must admit the current
    /// service's initial four-message receive window for every admitted peer.
    pub fn new(instance: &'a mut Instance, start: Start) -> Result<Self, Error> {
        start.validate()?;
        if P == 0 || S == 0 || R < P.checked_mul(RECEIVE_WINDOW).ok_or(Error::Overflow)? {
            return Err(Error::Capacity);
        }
        Ok(Self {
            instance,
            start,
            epoch: 0,
            online: false,
            peers: [PeerSlot::EMPTY; P],
            sends: [SendSlot::EMPTY; S],
            receives: [ReceiveSlot::EMPTY; R],
            refunds: [RefundAccount::EMPTY; D],
        })
    }
    /// Admit START on a genuinely connected original socket. Copy/retain these
    /// bytes before IO; this registers a client, not an authenticated session.
    /// A rejected output/epoch leaves both the client and output unchanged.
    pub fn begin(&mut self, output: &mut [u8]) -> Result<(ConnectionEpoch<'a>, usize), Error> {
        if self.online {
            return Err(Error::Conflict);
        }
        let epoch = self.epoch.checked_add(1).ok_or(Error::Capacity)?;
        let len = Request::Start(self.start).encode(output)?;
        self.epoch = epoch;
        self.online = true;
        Ok((
            ConnectionEpoch {
                owner: self.instance,
                serial: epoch,
            },
            len,
        ))
    }
    fn check_epoch(&self, epoch: ConnectionEpoch<'_>) -> Result<(), Error> {
        if !core::ptr::eq(self.instance, epoch.owner) || self.epoch != epoch.serial {
            Err(Error::Stale)
        } else if !self.online {
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
        }
    }
    fn peer_slot(&self, peer: Peer<'_>) -> Result<usize, Error> {
        if !self.online
            || !core::ptr::eq(self.instance, peer.key.owner)
            || peer.key.epoch != self.epoch
        {
            return Err(Error::Stale);
        }
        let slot = self.peers.get(peer.key.slot).ok_or(Error::Stale)?;
        if slot.state != PeerState::Connected
            || slot.generation != peer.key.generation
            || slot.identity != peer.identity
        {
            return Err(Error::Stale);
        }
        Ok(peer.key.slot)
    }
    /// Find a currently announced peer, without creating a connection or event.
    #[must_use]
    pub fn peer(&self, identity: PeerId) -> Option<Peer<'a>> {
        self.peers
            .iter()
            .position(|p| p.state == PeerState::Connected && p.identity == identity)
            .map(|index| self.peer_at(index))
    }
    /// Remaining official send credit; this is independent of local queue capacity.
    pub fn send_credit(&self, peer: Peer<'_>) -> Result<u32, Error> {
        Ok(self.peers[self.peer_slot(peer)?].credit)
    }
    fn refund_index(&self, identity: PeerId) -> Option<usize> {
        self.refunds
            .iter()
            .position(|r| r.used && r.identity == identity)
    }
    fn release_refund(&mut self, index: usize) {
        let account = self.refunds[index];
        if account.retired == 0
            && account.deferred == 0
            && self
                .peer(account.identity)
                .is_none_or(|p| self.peers[p.key.slot].credit == SEND_WINDOW)
        {
            self.refunds[index] = RefundAccount::EMPTY;
        }
    }
    /// Decode/process one original service frame. Malformed/unknown input retires
    /// this MQ; local capacity refusal retains the frame for retry and sends no ACK.
    pub fn receive<'frame>(
        &mut self,
        epoch: ConnectionEpoch<'_>,
        bytes: &'frame [u8],
    ) -> Result<Event<'a, 'frame>, Error> {
        self.check_epoch(epoch)?;
        let result = Response::decode(bytes).and_then(|response| self.response(response));
        if matches!(
            result,
            Err(Error::Malformed | Error::Truncated | Error::InvalidInput | Error::Unsupported)
        ) {
            self.retire_connection();
        }
        result
    }
    fn response<'frame>(&mut self, response: Response<'frame>) -> Result<Event<'a, 'frame>, Error> {
        match response {
            Response::Connected(identity) => {
                if self.peer(identity).is_some() {
                    return Err(Error::Malformed);
                }
                let index = self
                    .peers
                    .iter()
                    .position(|p| p.state == PeerState::Empty && p.generation < u64::MAX)
                    .ok_or(Error::Capacity)?;
                let slot = &mut self.peers[index];
                slot.generation += 1;
                slot.epoch = self.epoch;
                slot.identity = identity;
                slot.state = PeerState::Connected;
                slot.credit = SEND_WINDOW;
                Ok(Event::Connected(self.peer_at(index)))
            }
            Response::Disconnected(identity) => {
                let peer = self.peer(identity).ok_or(Error::Malformed)?;
                let outstanding = SEND_WINDOW
                    .checked_sub(self.peers[peer.key.slot].credit)
                    .ok_or(Error::Malformed)?;
                let deferred = u32::try_from(
                    self.sends
                        .iter()
                        .filter(|s| {
                            s.record.is_some_and(|r| {
                                r.peer == peer && r.outcome().is_none() && r.written == 0
                            })
                        })
                        .count(),
                )
                .map_err(|_| Error::Capacity)?;
                let committed = outstanding.checked_sub(deferred).ok_or(Error::Malformed)?;
                let account = self.refund_index(identity);
                let update = if outstanding > 0 {
                    let index = account.ok_or(Error::Malformed)?;
                    let current = self.refunds[index];
                    Some((
                        index,
                        current
                            .retired
                            .checked_add(committed)
                            .ok_or(Error::Capacity)?,
                        current
                            .deferred
                            .checked_add(deferred)
                            .ok_or(Error::Capacity)?,
                    ))
                } else {
                    None
                };
                self.peers[peer.key.slot].state = PeerState::Empty;
                if let Some((index, retired, deferred)) = update {
                    self.refunds[index].retired = retired;
                    self.refunds[index].deferred = deferred;
                }
                for slot in &mut self.receives {
                    if slot.peer == Some(peer) {
                        slot.peer = None;
                    }
                }
                for slot in &mut self.sends {
                    if let Some(record) = &mut slot.record
                        && record.peer == peer
                        && record.outcome().is_none()
                    {
                        record.peer_lost = true;
                        record.deferred_refund = record.written == 0;
                    }
                }
                if let Some(index) = account {
                    self.release_refund(index);
                }
                Ok(Event::Disconnected(peer))
            }
            Response::SendCredit(identity) => {
                let account = self.refund_index(identity);
                if let Some(index) = account
                    && self.refunds[index].retired > 0
                {
                    self.refunds[index].retired -= 1;
                    self.release_refund(index);
                    return Ok(Event::LateSendCredit(identity));
                }
                let Some(peer) = self.peer(identity) else {
                    return Ok(Event::LateSendCredit(identity));
                };
                let slot = &mut self.peers[peer.key.slot];
                if slot.credit >= SEND_WINDOW {
                    return Err(Error::Malformed);
                }
                slot.credit += 1;
                if let Some(index) = account {
                    self.release_refund(index);
                }
                Ok(Event::SendCredit(peer))
            }
            Response::Received {
                peer: identity,
                message,
            } => {
                if self.start.options & 2 == 0 {
                    return Err(Error::Malformed);
                }
                let peer = self.peer(identity).ok_or(Error::Malformed)?;
                let index = self
                    .receives
                    .iter()
                    .position(|s| s.peer.is_none() && s.generation < u64::MAX)
                    .ok_or(Error::Capacity)?;
                let slot = &mut self.receives[index];
                slot.generation += 1;
                slot.peer = Some(peer);
                let receive = ReceiveId(Key {
                    owner: self.instance,
                    epoch: self.epoch,
                    slot: index,
                    generation: slot.generation,
                });
                Ok(Event::Received {
                    peer,
                    receive,
                    message,
                })
            }
        }
    }
    /// Encode/reserve one original SEND with explicit per-peer backpressure.
    /// The host must retain the entire immutable frame until written or canceled
    /// before its first byte. A short output never consumes credit or an ID.
    pub fn prepare_send(
        &mut self,
        peer: Peer<'a>,
        priority: u32,
        message: &[u8],
        output: &mut [u8],
    ) -> Result<(SendId<'a>, usize), Error> {
        let peer_index = self.peer_slot(peer)?;
        if self.peers[peer_index].credit == 0 {
            return Err(Error::WouldBlock);
        }
        let index = self
            .sends
            .iter()
            .position(|s| s.record.is_none() && s.generation < u64::MAX)
            .ok_or(Error::Capacity)?;
        let account = self
            .refund_index(peer.identity)
            .or_else(|| self.refunds.iter().position(|r| !r.used))
            .ok_or(Error::Capacity)?;
        let refund = self.refunds[account];
        refund
            .retired
            .checked_add(refund.deferred)
            .and_then(|n| n.checked_add(SEND_WINDOW - self.peers[peer_index].credit))
            .and_then(|n| n.checked_add(1))
            .ok_or(Error::Capacity)?;
        let len = Request::Send {
            peer: peer.identity,
            priority,
            message,
        }
        .encode(output)?;
        let slot = &mut self.sends[index];
        slot.generation += 1;
        slot.record = Some(SendRecord {
            peer,
            len,
            written: 0,
            cancelled: false,
            peer_lost: false,
            connection_lost: false,
            deferred_refund: false,
        });
        let id = SendId(Key {
            owner: self.instance,
            epoch: self.epoch,
            slot: index,
            generation: slot.generation,
        });
        self.peers[peer_index].credit -= 1;
        if !self.refunds[account].used {
            self.refunds[account] = RefundAccount {
                used: true,
                identity: peer.identity,
                retired: 0,
                deferred: 0,
            };
        }
        Ok((id, len))
    }
    fn send_index(&self, id: SendId<'_>) -> Result<usize, Error> {
        if !core::ptr::eq(self.instance, id.0.owner) {
            return Err(Error::Stale);
        }
        let slot = self.sends.get(id.0.slot).ok_or(Error::Stale)?;
        let record = slot.record.ok_or(Error::Stale)?;
        if slot.generation != id.0.generation || record.peer.key.epoch != id.0.epoch {
            return Err(Error::Stale);
        }
        Ok(id.0.slot)
    }
    /// Report each actual nonzero native write before processing service frames,
    /// retaining the original cursor. This includes an old generation whose first
    /// byte is written after DISCONNECT. A zero cursor must mean truly unwritten.
    /// A complete write is local IO completion only; SEND_OK remains separate.
    pub fn send_bytes_written(
        &mut self,
        id: SendId<'_>,
        bytes: usize,
    ) -> Result<Option<SendOutcome>, Error> {
        let index = self.send_index(id)?;
        let record = self.sends[index].record.ok_or(Error::Stale)?;
        if record.outcome().is_some() {
            return Err(Error::Closed);
        }
        if bytes == 0 || bytes > record.len - record.written {
            return Err(Error::InvalidInput);
        }
        if record.deferred_refund {
            let account = self
                .refund_index(record.peer.identity)
                .ok_or(Error::Stale)?;
            let deferred = self.refunds[account]
                .deferred
                .checked_sub(1)
                .ok_or(Error::Stale)?;
            let retired = self.refunds[account]
                .retired
                .checked_add(1)
                .ok_or(Error::Capacity)?;
            self.refunds[account].deferred = deferred;
            self.refunds[account].retired = retired;
        }
        let record = self.sends[index].record.as_mut().ok_or(Error::Stale)?;
        record.deferred_refund = false;
        record.written += bytes;
        Ok(record.outcome())
    }
    /// Cancel only after the host removed this exact wholly unwritten frame.
    /// A current generation's unit is restored locally. For a retired generation,
    /// release only its deferred promise; never grant a new peer generation credit.
    /// No cancellation request exists on the wire.
    pub fn cancel_unwritten(&mut self, id: SendId<'_>) -> Result<(), Error> {
        let index = self.send_index(id)?;
        let record = self.sends[index].record.ok_or(Error::Stale)?;
        if record.outcome().is_some() || record.written != 0 {
            return Err(Error::Conflict);
        }
        let account = self
            .refund_index(record.peer.identity)
            .ok_or(Error::Stale)?;
        if record.deferred_refund {
            self.refunds[account].deferred = self.refunds[account]
                .deferred
                .checked_sub(1)
                .ok_or(Error::Stale)?;
        } else {
            let peer_index = self.peer_slot(record.peer)?;
            self.peers[peer_index].credit = self.peers[peer_index]
                .credit
                .checked_add(1)
                .filter(|credit| *credit <= SEND_WINDOW)
                .ok_or(Error::Malformed)?;
        }
        let record = self.sends[index].record.as_mut().ok_or(Error::Stale)?;
        record.cancelled = true;
        record.deferred_refund = false;
        self.release_refund(account);
        Ok(())
    }
    /// Suppress local completion after at least one byte was written. The host
    /// must finish the same frame or retire the whole connection; no credit is
    /// restored and no wire bytes can be retracted.
    pub fn cancel_started(&mut self, id: SendId<'_>) -> Result<(), Error> {
        let index = self.send_index(id)?;
        let record = self.sends[index].record.as_mut().ok_or(Error::Stale)?;
        if record.outcome().is_some() || record.written == 0 {
            return Err(Error::Conflict);
        }
        record.cancelled = true;
        Ok(())
    }
    /// Remaining physical bytes of the original frame, not a network delivery count.
    pub fn send_remaining(&self, id: SendId<'_>) -> Result<usize, Error> {
        let record = self.sends[self.send_index(id)?]
            .record
            .ok_or(Error::Stale)?;
        Ok(record.len - record.written)
    }
    /// Consume a terminal local result and return that operation's slot exactly once.
    /// Pending operations return WouldBlock without retiring anything.
    pub fn take_send_result(&mut self, id: SendId<'_>) -> Result<SendOutcome, Error> {
        let index = self.send_index(id)?;
        let result = self.sends[index]
            .record
            .ok_or(Error::Stale)?
            .outcome()
            .ok_or(Error::WouldBlock)?;
        self.sends[index].record = None;
        Ok(result)
    }
    /// Admit one RECV_OK(delta=1) after real application processing. No Drop path
    /// sends credit. Preflight the host MQ capacity before calling, then retain
    /// these exact bytes across canceled write futures. Double/foreign/old tokens fail.
    pub fn complete_receive(
        &mut self,
        id: ReceiveId<'_>,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        if !self.online || !core::ptr::eq(self.instance, id.0.owner) || id.0.epoch != self.epoch {
            return Err(Error::Stale);
        }
        let slot = self.receives.get(id.0.slot).ok_or(Error::Stale)?;
        if slot.generation != id.0.generation {
            return Err(Error::Stale);
        }
        let peer = slot.peer.ok_or(Error::Stale)?;
        self.peer_slot(peer)?;
        let len = Request::ReceiveContinue {
            peer: peer.identity,
            increase: 1,
        }
        .encode(output)?;
        self.receives[id.0.slot].peer = None;
        Ok(len)
    }
    /// Retire an actual failed/closed original connection. Each pending send keeps
    /// a retrievable ConnectionLost outcome. Caller reconnect scheduling is separate.
    pub fn connection_lost(&mut self, epoch: ConnectionEpoch<'_>) -> Result<(), Error> {
        self.check_epoch(epoch)?;
        self.retire_connection();
        Ok(())
    }
    fn retire_connection(&mut self) {
        self.online = false;
        self.refunds.fill(RefundAccount::EMPTY);
        for peer in &mut self.peers {
            if peer.state == PeerState::Connected {
                peer.state = PeerState::LostNotice;
            }
        }
        for receive in &mut self.receives {
            receive.peer = None;
        }
        for send in &mut self.sends {
            if let Some(record) = &mut send.record
                && record.outcome().is_none()
            {
                record.connection_lost = true;
            }
        }
    }
    /// Drain each connection-loss peer notification once before reusing its slot.
    /// A wire DISCONNECT is delivered directly by `receive`, not duplicated here.
    pub fn next_lost_peer(&mut self) -> Option<Peer<'a>> {
        let index = self
            .peers
            .iter()
            .position(|p| p.state == PeerState::LostNotice)?;
        let peer = self.peer_at(index);
        self.peers[index].state = PeerState::Empty;
        Some(peer)
    }
}
