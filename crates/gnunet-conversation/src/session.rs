use crate::{
    Peer, Port, crypto,
    wire::{ClientControl, Message, PeerControl},
};
use alloc::{collections::VecDeque, vec::Vec};
use core::{marker::PhantomData, mem::size_of};
use gnunet_identity::SecretKey;
use gnunet_types::Error;
#[cfg(test)]
mod identity_tests;
mod types;
pub use types::*;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Idle,
    Listener,
    Outgoing,
}
struct Call<'id> {
    id: CallId<'id>,
    cid: u32,
    peer: Peer,
    // RingInfo is authenticated against the local peer observed when this
    // channel was accepted. A later Line identity update cannot relabel it.
    local_peer: Peer,
    phase: Phase,
    source: Option<Source>,
    opening: bool,
    channel_ready: bool,
    setup_deadline: u64,
    close_deadline: Option<u64>,
    suspended_local: bool,
    suspended_remote: bool,
    last_delivery: Option<u64>,
    debt: usize,
    gone: bool,
    close_queued: bool,
    reason: Option<EndReason>,
    failure: Option<Error>,
    ring_written: bool,
    remote_pickup: bool,
    local_pickup_written: bool,
    remote_hangup: bool,
    local_hangup_written: bool,
    notify_hangup: bool,
    peer_last: Option<EffectId<'id>>,
    credit_last: Option<EffectId<'id>>,
}
/// One real local client Line with independently bounded native-channel owners.
/// This value performs no physical I/O and must never outlive its original IPC.
/// The host checks current identity, cancellation and original native deadlines
/// immediately before every syscall, not merely before polling this core.
pub struct Session<'id> {
    domain: Domain<'id>,
    identity: Identity,
    limits: Limits,
    mode: Mode,
    port: Option<Port>,
    port_source: Option<Source>,
    port_ready: bool,
    port_gone: bool,
    port_closing: bool,
    client_closing: bool,
    client_closed: bool,
    calls: Vec<Option<Call<'id>>>,
    effects: VecDeque<Effect<'id>>,
    port_last: Option<EffectId<'id>>,
    client_last: Option<EffectId<'id>>,
    next_call: u64,
    next_effect: u64,
    next_cid: u64,
    normal_effects: usize,
    metadata_bytes: usize,
    queued_bytes: usize,
    failure: Option<Error>,
    last_now: u64,
    _brand: PhantomData<&'id mut Instance>,
}
impl<'id> Session<'id> {
    /// Fallibly reserve finite metadata for one actual IPC owner. Caller and
    /// native output buffers, terminal receipts and crypto stack are separate.
    pub fn new(
        _instance: &'id mut Instance,
        identity: Identity,
        limits: Limits,
        now: u64,
    ) -> Result<Self, Error> {
        let limits = limits.validate()?;
        let mut calls = Vec::new();
        calls
            .try_reserve_exact(limits.calls)
            .map_err(|_| Error::Capacity)?;
        calls.resize_with(limits.calls, || None);
        let slots = limits
            .effects
            .checked_add(limits.calls)
            .and_then(|n| n.checked_add(2))
            .ok_or(Error::Overflow)?;
        let mut effects = VecDeque::new();
        effects
            .try_reserve_exact(slots)
            .map_err(|_| Error::Capacity)?;
        let metadata_bytes = calls
            .capacity()
            .checked_mul(size_of::<Option<Call<'id>>>())
            .and_then(|n| {
                effects
                    .capacity()
                    .checked_mul(size_of::<Effect<'id>>())
                    .and_then(|m| n.checked_add(m))
            })
            .ok_or(Error::Overflow)?;
        if metadata_bytes > limits.retained_bytes {
            return Err(Error::Capacity);
        }
        Ok(Self {
            domain: Domain(_instance),
            identity,
            limits,
            mode: Mode::Idle,
            port: None,
            port_source: None,
            port_ready: false,
            port_gone: false,
            port_closing: false,
            client_closing: false,
            client_closed: false,
            calls,
            effects,
            port_last: None,
            client_last: None,
            next_call: 1,
            next_effect: 1,
            next_cid: 0,
            normal_effects: 0,
            metadata_bytes,
            queued_bytes: 0,
            failure: None,
            last_now: now,
            _brand: PhantomData,
        })
    }
    /// Original immutable limits.
    pub const fn limits(&self) -> Limits {
        self.limits
    }
    /// Current actual local identity assertion, never a caller ego key.
    pub const fn identity(&self) -> Identity {
        self.identity
    }
    /// Apply a fresh verified identity from the same original observer MQ.
    /// The native owner must check the actual branded source, not just its
    /// numeric epoch. Existing channels retain their original RingInfo target,
    /// source, effects and deadlines. This performs no reconnect or replay and
    /// does not attest to CADET reachability under the new identity.
    pub fn rebind_identity(&mut self, previous: &Identity, next: Identity) -> Result<(), Error> {
        self.live(previous)?;
        if previous.epoch() != next.epoch() {
            return Err(Error::StaleGeneration);
        }
        self.identity = next;
        Ok(())
    }
    /// Actual retained core-owned metadata/payload capacities.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        self.metadata_bytes
            .checked_add(self.queued_bytes)
            .ok_or(Error::Overflow)
    }
    /// First independent Line failure, preserved during cancellation and cleanup.
    pub const fn failure(&self) -> Option<Error> {
        self.failure
    }
    /// Original effect count, including admitted/cancelled debts and close work.
    pub fn pending_effects(&self) -> usize {
        self.effects.len()
    }
    /// Actual native/local close evidence and absence of all retained debts.
    pub fn is_quiescent(&self) -> bool {
        self.client_closed
            && self.port.is_none()
            && self.effects.is_empty()
            && self.calls.iter().flatten().all(|c| c.gone && c.debt == 0)
    }
    /// Protocol phase of exactly the original call.
    pub fn phase(&self, id: CallId<'id>) -> Result<Phase, Error> {
        Ok(self.call(id)?.phase)
    }
    /// Opaque local CID, never a high-bit authorization token.
    pub fn cid(&self, id: CallId<'id>) -> Result<u32, Error> {
        Ok(self.call(id)?.cid)
    }
    /// Immediate physical retirement fence for a native original channel.
    pub fn retirement_required(&self, id: CallId<'id>) -> Result<bool, Error> {
        Ok(matches!(
            self.call(id)?.phase,
            Phase::Closing | Phase::Closed
        ))
    }
    /// Bind the actual native port/source before OpenPort can settle Written.
    pub fn attach_port(&mut self, source: Source) -> Result<(), Error> {
        if self.mode != Mode::Listener || self.port.is_none() || self.port_source.is_some() {
            return Err(Error::NotReady);
        }
        self.port_source = Some(source);
        Ok(())
    }
    /// Bind the actual native Channel returned for the original outgoing open.
    /// A late channel after cancel is still retained and must be retired.
    pub fn attach_channel(&mut self, id: CallId<'id>, source: Source) -> Result<(), Error> {
        let c = self.call_mut(id)?;
        if !c.opening || c.source.is_some() {
            return Err(Error::NotReady);
        }
        c.source = Some(source);
        Ok(())
    }
    fn live(&self, current: &Identity) -> Result<(), Error> {
        if self.identity != *current {
            return Err(Error::StaleGeneration);
        }
        if self.client_closing {
            return Err(Error::Closed);
        }
        Ok(())
    }
    fn call(&self, id: CallId<'id>) -> Result<&Call<'id>, Error> {
        self.calls
            .get(id.slot)
            .and_then(Option::as_ref)
            .filter(|c| c.id == id)
            .ok_or(Error::StaleGeneration)
    }
    fn call_mut(&mut self, id: CallId<'id>) -> Result<&mut Call<'id>, Error> {
        self.calls
            .get_mut(id.slot)
            .and_then(Option::as_mut)
            .filter(|c| c.id == id)
            .ok_or(Error::StaleGeneration)
    }
    fn by_cid(&self, cid: u32) -> Option<CallId<'id>> {
        self.calls
            .iter()
            .flatten()
            .find(|c| c.cid == cid)
            .map(|c| c.id)
    }
    fn vacant(&self) -> Result<usize, Error> {
        self.calls
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)
    }
    fn deadline(now: u64, duration: u64) -> Result<u64, Error> {
        let n = now.checked_add(duration).ok_or(Error::Overflow)?;
        if n == u64::MAX {
            return Err(Error::Overflow);
        }
        Ok(n)
    }
    fn new_call(
        &self,
        slot: usize,
        cid: u32,
        peer: Peer,
        phase: Phase,
        source: Option<Source>,
        now: u64,
    ) -> Result<Call<'id>, Error> {
        self.next_call.checked_add(1).ok_or(Error::Overflow)?;
        self.next_effect
            .checked_add(
                u64::try_from(self.limits.calls.checked_add(2).ok_or(Error::Overflow)?)
                    .map_err(|_| Error::Overflow)?,
            )
            .ok_or(Error::Overflow)?;
        Ok(Call {
            id: CallId {
                serial: self.next_call,
                domain: self.domain,
                slot,
                brand: PhantomData,
            },
            cid,
            peer,
            local_peer: *self.identity.peer(),
            phase,
            source,
            opening: phase == Phase::Opening,
            channel_ready: phase == Phase::AwaitRing,
            setup_deadline: Self::deadline(now, self.limits.ring_timeout)?,
            close_deadline: None,
            suspended_local: false,
            suspended_remote: false,
            last_delivery: None,
            debt: 0,
            gone: false,
            close_queued: false,
            reason: None,
            failure: None,
            ring_written: false,
            remote_pickup: false,
            local_pickup_written: false,
            remote_hangup: false,
            local_hangup_written: false,
            notify_hangup: false,
            peer_last: None,
            credit_last: None,
        })
    }
    fn frame(&self, message: Message<'_>, peer: bool) -> Result<Vec<u8>, Error> {
        let n = message.encoded_len()?;
        if n > self.limits.frame_bytes || (peer && n > 64348) {
            return Err(Error::TooLarge);
        }
        if n > self.limits.queued_bytes {
            return Err(Error::Capacity);
        }
        let predicted = self.queued_bytes.checked_add(n).ok_or(Error::Overflow)?;
        if predicted > self.limits.queued_bytes
            || self
                .metadata_bytes
                .checked_add(predicted)
                .ok_or(Error::Overflow)?
                > self.limits.retained_bytes
        {
            return Err(Error::WouldBlock);
        }
        let mut frame = Vec::new();
        frame.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
        if frame.capacity() > self.limits.queued_bytes
            || self
                .metadata_bytes
                .checked_add(self.queued_bytes)
                .and_then(|n| n.checked_add(frame.capacity()))
                .ok_or(Error::Overflow)?
                > self.limits.retained_bytes
        {
            return Err(Error::Capacity);
        }
        frame.resize(n, 0);
        message.encode(&mut frame)?;
        Ok(frame)
    }
    fn client_frame(&self, call: CallId<'id>, message: Message<'_>) -> Result<Action<'id>, Error> {
        Ok(Action::ClientFrame {
            call,
            frame: self.frame(message, false)?,
        })
    }
    fn peer_frame(&self, call: CallId<'id>, message: Message<'_>) -> Result<Action<'id>, Error> {
        Ok(Action::PeerFrame {
            call,
            frame: self.frame(message, true)?,
        })
    }
    fn batch(&mut self, actions: [Option<Action<'id>>; 3], now: u64) -> Result<(), Error> {
        let count = actions.iter().flatten().count();
        let normal = self.normal_effects;
        let new_normal = actions.iter().flatten().filter(|a| !a.close()).count();
        if new_normal > self.limits.effects {
            return Err(Error::Capacity);
        }
        if normal.checked_add(new_normal).ok_or(Error::Overflow)? > self.limits.effects
            || self
                .effects
                .len()
                .checked_add(count)
                .ok_or(Error::Overflow)?
                > self.effects.capacity()
        {
            return Err(Error::WouldBlock);
        }
        let bytes = actions.iter().flatten().try_fold(0usize, |n, a| {
            n.checked_add(a.bytes()).ok_or(Error::Overflow)
        })?;
        if bytes > self.limits.queued_bytes {
            return Err(Error::Capacity);
        }
        let total = self
            .queued_bytes
            .checked_add(bytes)
            .ok_or(Error::Overflow)?;
        if total > self.limits.queued_bytes
            || self
                .metadata_bytes
                .checked_add(total)
                .ok_or(Error::Overflow)?
                > self.limits.retained_bytes
        {
            return Err(Error::WouldBlock);
        }
        self.next_effect
            .checked_add(
                u64::try_from(
                    count
                        .checked_add(self.limits.calls)
                        .and_then(|n| n.checked_add(2))
                        .ok_or(Error::Overflow)?,
                )
                .map_err(|_| Error::Overflow)?,
            )
            .ok_or(Error::Overflow)?;
        let deadline = Self::deadline(now, self.limits.write_timeout)?;
        for action in actions.iter().flatten() {
            if let Some(id) = action.call() {
                self.call(id)?
                    .debt
                    .checked_add(count)
                    .ok_or(Error::Overflow)?;
            }
        }
        let mut client_predecessor = None;
        for action in actions.into_iter().flatten() {
            let credit_predecessor = if matches!(action, Action::ReceiveDone { .. }) {
                client_predecessor
            } else {
                None
            };
            let is_client = matches!(action, Action::ClientFrame { .. });
            let id = self.append_effect(action, deadline, credit_predecessor)?;
            client_predecessor = if is_client { Some(id) } else { None };
        }
        self.queued_bytes = total;
        self.last_now = self.last_now.max(now);
        Ok(())
    }
    /// Admit one actual complete local message. Unknown/stale CIDs are ignored;
    /// malformed direction/state returns its actual error without partial state.
    /// The native owner drops that original IPC on a protocol error.
    pub fn client_request(
        &mut self,
        current: &Identity,
        message: Message<'_>,
        now: u64,
        utc: u64,
    ) -> Result<RequestOutcome<'id>, Error> {
        self.live(current)?;
        match message {
            Message::Register { port, .. } => {
                if self.mode != Mode::Idle {
                    return Err(Error::Malformed);
                }
                self.batch([Some(Action::OpenPort { port: *port }), None, None], now)?;
                self.mode = Mode::Listener;
                self.port = Some(*port);
                Ok(RequestOutcome::Admitted)
            }
            Message::Call {
                target,
                port,
                private_key,
                ..
            } => {
                if self.mode != Mode::Idle {
                    return Err(Error::Malformed);
                }
                if utc == u64::MAX {
                    return Err(Error::TimeUncertain);
                }
                let slot = self.vacant()?;
                let key = SecretKey::from_serialized(private_key)?;
                let expiration = Self::deadline(utc, self.limits.ring_timeout)?;
                let signed = crypto::SignedRing::sign(&key, port, target, expiration)?;
                let call = self.new_call(slot, 0, *target, Phase::Opening, None, now)?;
                let id = call.id;
                let frame = self.peer_frame(
                    id,
                    Message::PeerRing {
                        reserved: 0,
                        expiration,
                        public_key: signed.public_key(),
                        signature: signed.signature(),
                    },
                )?;
                self.calls[slot] = Some(call);
                let result = self.batch(
                    [
                        Some(Action::OpenChannel {
                            call: id,
                            target: *target,
                            port: *port,
                        }),
                        Some(frame),
                        None,
                    ],
                    now,
                );
                if let Err(error) = result {
                    self.calls[slot] = None;
                    return Err(error);
                }
                self.next_call += 1;
                self.mode = Mode::Outgoing;
                Ok(RequestOutcome::Calling(id))
            }
            Message::Control { action, cid } => self.client_control(action, cid, now),
            Message::Audio { cid, data } => {
                let Some(id) = self.by_cid(cid) else {
                    return Ok(RequestOutcome::Ignored);
                };
                let c = self.call(id)?;
                if matches!(c.phase, Phase::Closing | Phase::Closed) {
                    return Ok(RequestOutcome::Ignored);
                }
                if c.phase != Phase::Connected || c.suspended_local {
                    return Err(Error::Malformed);
                }
                let frame = self.peer_frame(id, Message::PeerAudio(data))?;
                self.batch([Some(frame), None, None], now)?;
                Ok(RequestOutcome::Admitted)
            }
            _ => Err(Error::Malformed),
        }
    }
    fn client_control(
        &mut self,
        action: ClientControl,
        cid: u32,
        now: u64,
    ) -> Result<RequestOutcome<'id>, Error> {
        let Some(id) = self.by_cid(cid) else {
            return Ok(RequestOutcome::Ignored);
        };
        let c = self.call(id)?;
        if matches!(c.phase, Phase::Closing | Phase::Closed) {
            return Ok(RequestOutcome::Ignored);
        }
        if matches!(
            c.phase,
            Phase::Opening | Phase::AwaitRing | Phase::Ringing | Phase::Calling
        ) && now >= c.setup_deadline
        {
            return Err(Error::Timeout);
        }
        let peer_action = match action {
            ClientControl::PickUp if self.mode == Mode::Listener && c.phase == Phase::Ringing => {
                PeerControl::PickUp
            }
            ClientControl::HangUp if c.phase != Phase::AwaitRing => PeerControl::HangUp,
            ClientControl::Suspend if c.phase == Phase::Connected && !c.suspended_local => {
                PeerControl::Suspend
            }
            ClientControl::Resume if c.phase == Phase::Connected && c.suspended_local => {
                PeerControl::Resume
            }
            _ => return Err(Error::Malformed),
        };
        let frame = self.peer_frame(id, Message::PeerControl(peer_action))?;
        if action == ClientControl::HangUp {
            // Preflight ordinary output before changing/suppressing anything.
            self.batch([Some(frame), None, None], now)?;
            let keep = self.effects.back().map(|e| e.id);
            self.begin_close(id, EndReason::LocalHangUp, now, keep)?;
        } else {
            self.batch([Some(frame), None, None], now)?;
            let c = self.call_mut(id)?;
            match action {
                ClientControl::PickUp => c.phase = Phase::Connected,
                ClientControl::Suspend => c.suspended_local = true,
                ClientControl::Resume => c.suspended_local = false,
                _ => {}
            }
        }
        Ok(RequestOutcome::Admitted)
    }
    /// Bind one actual incoming Channel on this Line's real ready port. A late
    /// rejected native Channel remains the caller's responsibility to destroy.
    pub fn incoming(
        &mut self,
        current: &Identity,
        port_source: Source,
        channel_source: Source,
        peer: Peer,
        now: u64,
    ) -> Result<CallId<'id>, Error> {
        self.live(current)?;
        if self.mode != Mode::Listener
            || !self.port_ready
            || self.port_closing
            || self.port_source != Some(port_source)
        {
            return Err(Error::NotReady);
        }
        let slot = self.vacant()?;
        let cid = u32::try_from(self.next_cid).map_err(|_| Error::Overflow)?;
        let call = self.new_call(slot, cid, peer, Phase::AwaitRing, Some(channel_source), now)?;
        let id = call.id;
        self.calls[slot] = Some(call);
        self.next_call += 1;
        self.next_cid += 1;
        self.last_now = self.last_now.max(now);
        Ok(id)
    }
    /// Classify one complete frame from exactly the original native channel and
    /// delivery. The native owner keeps its real input credit until ReceiveDone
    /// is actually applied or that original Channel is physically retired.
    #[expect(
        clippy::too_many_arguments,
        reason = "Every receive carries its original identity, call, source, delivery and message plus independent monotonic and UTC observations; no raw CID or ambient authority replaces these bindings"
    )]
    pub fn receive(
        &mut self,
        current: &Identity,
        id: CallId<'id>,
        source: Source,
        delivery: u64,
        message: Message<'_>,
        now: u64,
        utc: u64,
    ) -> Result<(), Error> {
        self.live(current)?;
        let c = self.call(id)?;
        if c.source != Some(source) || c.gone {
            return Err(Error::StaleGeneration);
        }
        if c.last_delivery.is_some_and(|old| delivery <= old) {
            return Err(Error::Replay);
        }
        let cid = c.cid;
        let credit = Action::ReceiveDone { call: id, delivery };
        match message {
            Message::PeerRing {
                expiration,
                public_key,
                signature,
                ..
            } => {
                if self.mode != Mode::Listener
                    || c.phase != Phase::AwaitRing
                    || now >= c.setup_deadline
                {
                    return Err(Error::Malformed);
                }
                let port = self.port.as_ref().ok_or(Error::NotReady)?;
                let checked =
                    crypto::verify(public_key, signature, port, &c.local_peer, expiration, utc)?;
                let remaining = expiration.checked_sub(utc).ok_or(Error::Timeout)?;
                let deadline = Self::deadline(now, remaining.min(self.limits.ring_timeout))?
                    .min(c.setup_deadline);
                let frame = self.client_frame(
                    id,
                    Message::Ring {
                        cid,
                        public_key: checked.public_key(),
                    },
                )?;
                self.batch([Some(frame), Some(credit), None], now)?;
                let c = self.call_mut(id)?;
                c.phase = Phase::Ringing;
                c.setup_deadline = deadline;
            }
            Message::PeerControl(PeerControl::PickUp) => {
                if self.mode != Mode::Outgoing
                    || c.phase != Phase::Calling
                    || !c.ring_written
                    || now >= c.setup_deadline
                {
                    return Err(Error::Malformed);
                }
                let frame = self.client_frame(
                    id,
                    Message::Control {
                        action: ClientControl::PickedUp,
                        cid,
                    },
                )?;
                self.batch([Some(frame), Some(credit), None], now)?;
                let c = self.call_mut(id)?;
                c.phase = Phase::Connected;
                c.remote_pickup = true;
            }
            Message::PeerControl(PeerControl::HangUp) => {
                if c.phase == Phase::AwaitRing {
                    return Err(Error::Malformed);
                }
                if matches!(c.phase, Phase::Closing | Phase::Closed) {
                    self.batch([Some(credit), None, None], now)?;
                } else {
                    let frame = self.client_frame(
                        id,
                        Message::Control {
                            action: ClientControl::HangUp,
                            cid,
                        },
                    )?;
                    self.batch([Some(frame), Some(credit), None], now)?;
                    let keep = self.effects.iter().rev().nth(1).map(|e| e.id);
                    // Both newly admitted notification and credit are retained.
                    self.begin_close(id, EndReason::RemoteHangUp, now, keep)?;
                    if let Some(last) = self.effects.iter_mut().rev().find(|e| matches!(e.action, Action::ReceiveDone { call, delivery: d } if call == id && d == delivery)) { last.cancelled = false; }
                }
                self.call_mut(id)?.remote_hangup = true;
            }
            Message::PeerControl(action @ (PeerControl::Suspend | PeerControl::Resume)) => {
                if c.phase != Phase::Connected
                    || (action == PeerControl::Suspend) == c.suspended_remote
                {
                    return Err(Error::Malformed);
                }
                let local = if action == PeerControl::Suspend {
                    ClientControl::Suspend
                } else {
                    ClientControl::Resume
                };
                let frame = self.client_frame(id, Message::Control { action: local, cid })?;
                self.batch([Some(frame), Some(credit), None], now)?;
                self.call_mut(id)?.suspended_remote = action == PeerControl::Suspend;
            }
            Message::PeerAudio(data) => {
                if c.phase != Phase::Connected {
                    return Err(Error::Malformed);
                }
                if c.suspended_local || c.suspended_remote {
                    self.batch([Some(credit), None, None], now)?;
                } else {
                    let frame = self.client_frame(id, Message::Audio { cid, data })?;
                    self.batch([Some(frame), Some(credit), None], now)?;
                }
            }
            _ => return Err(Error::Malformed),
        }
        self.call_mut(id)?.last_delivery = Some(delivery);
        Ok(())
    }
    fn suppress(&mut self, id: CallId<'id>, keep: Option<EffectId<'id>>) {
        for e in &mut self.effects {
            if e.action.call() == Some(id) && !e.action.close() && Some(e.id) != keep {
                e.cancelled = true;
            }
        }
    }
    fn effect_index(&self, id: EffectId<'id>) -> Result<usize, Error> {
        if id.domain != self.domain {
            return Err(Error::StaleGeneration);
        }
        self.effects
            .binary_search_by_key(&id.serial, |e| e.id.serial)
            .map_err(|_| Error::StaleGeneration)
    }
    fn eligible(&self, e: &Effect<'id>) -> bool {
        e.predecessors
            .iter()
            .flatten()
            .all(|p| self.effect_index(*p).is_err())
    }
    fn append_effect(
        &mut self,
        action: Action<'id>,
        deadline: u64,
        credit_predecessor: Option<EffectId<'id>>,
    ) -> Result<EffectId<'id>, Error> {
        let id = EffectId {
            serial: self.next_effect,
            domain: self.domain,
            brand: PhantomData,
        };
        let next = self.next_effect.checked_add(1).ok_or(Error::Overflow)?;
        let previous = match &action {
            Action::OpenPort { .. } | Action::ClosePort { .. } => self.port_last,
            Action::ClientFrame { .. } | Action::CloseClient => self.client_last,
            Action::ReceiveDone { call, .. } => self.call(*call)?.credit_last,
            _ => action
                .call()
                .map(|c| self.call(c).map(|c| c.peer_last))
                .transpose()?
                .flatten(),
        };
        // Input credit is independent of outgoing channel credit; placing it
        // behind a blocked send could deadlock a full-duplex audio channel.
        let other = match &action {
            Action::CloseChannel { call } => self.call(*call)?.credit_last,
            _ => credit_predecessor,
        };
        if let Some(call) = action.call() {
            self.call_mut(call)?.debt += 1;
        }
        match &action {
            Action::OpenPort { .. } | Action::ClosePort { .. } => self.port_last = Some(id),
            Action::ClientFrame { .. } | Action::CloseClient => self.client_last = Some(id),
            Action::ReceiveDone { call, .. } => self.call_mut(*call)?.credit_last = Some(id),
            _ => {
                if let Some(call) = action.call() {
                    self.call_mut(call)?.peer_last = Some(id);
                }
            }
        }
        if !action.close() {
            self.normal_effects += 1;
        }
        self.effects.push_back(Effect {
            id,
            action,
            deadline,
            admitted: false,
            cancelled: false,
            predecessors: [previous, other],
        });
        self.next_effect = next;
        Ok(id)
    }
    fn push_close(&mut self, action: Action<'id>, deadline: u64) -> Result<(), Error> {
        if self.effects.len() == self.effects.capacity() {
            self.failure.get_or_insert(Error::Capacity);
            return Err(Error::Capacity);
        }
        self.append_effect(action, deadline, None)?;
        Ok(())
    }
    fn begin_close(
        &mut self,
        id: CallId<'id>,
        reason: EndReason,
        now: u64,
        keep: Option<EffectId<'id>>,
    ) -> Result<(), Error> {
        let hard = match Self::deadline(now, self.limits.close_timeout) {
            Ok(hard) => hard,
            Err(error) => {
                self.failure.get_or_insert(error);
                now
            }
        };
        let c = self.call_mut(id)?;
        c.reason.get_or_insert(reason);
        if c.close_queued {
            return Ok(());
        }
        c.close_deadline = Some(hard);
        c.phase = if c.gone {
            Phase::Closed
        } else {
            Phase::Closing
        };
        if !self.client_closing {
            self.suppress(id, keep);
        }
        self.push_close(Action::CloseChannel { call: id }, hard)?;
        self.call_mut(id)?.close_queued = true;
        Ok(())
    }
    /// Original oldest queued effect. Small single-owner drivers can drain
    /// this in FIFO order; multi-channel hosts should use the bounded scan to
    /// prevent unrelated channel backpressure blocking eligible native work.
    pub fn effect(&self) -> Option<&Effect<'id>> {
        self.effects.front()
    }
    /// Check at most `budget` candidates (at most two logarithmic predecessor
    /// lookups each). Exact ID lookups use sorted monotonic serials. An invalid
    /// or retired cursor resumes strictly after its serial; End remains End
    /// until explicit reset. Appends cannot extend this round's frozen fence.
    pub fn scan_effect(
        &self,
        scan: &mut EffectScan,
        budget: usize,
    ) -> Result<EffectScanStep<'_, 'id>, Error> {
        if budget == 0 {
            return Err(Error::InvalidInput);
        }
        let fence = *scan
            .fence
            .get_or_insert_with(|| self.effects.back().map_or(0, |e| e.id.serial));
        let mut at = self.effects.partition_point(|e| e.id.serial <= scan.after);
        for _ in 0..budget {
            let Some(e) = self.effects.get(at).filter(|e| e.id.serial <= fence) else {
                scan.after = fence;
                return Ok(EffectScanStep::End);
            };
            scan.after = e.id.serial;
            at += 1;
            if !e.admitted && self.eligible(e) {
                return Ok(EffectScanStep::Ready(e));
            }
        }
        if self.effects.get(at).is_none_or(|e| e.id.serial > fence) {
            scan.after = fence;
            Ok(EffectScanStep::End)
        } else {
            Ok(EffectScanStep::Pending)
        }
    }
    /// Admit an original eligible head of its semantic owner. Admission grants
    /// no physical outcome and never bypasses original IPC/channel FIFO.
    pub fn admit_effect(&mut self, id: EffectId<'id>) -> Result<(), Error> {
        let at = self.effect_index(id)?;
        let e = self.effects.get(at).ok_or(Error::StaleGeneration)?;
        if e.admitted {
            return Err(Error::Replay);
        }
        if e.cancelled {
            return Err(Error::Cancelled);
        }
        if !self.eligible(e) {
            return Err(Error::NotReady);
        }
        self.effects
            .get_mut(at)
            .ok_or(Error::StaleGeneration)?
            .admitted = true;
        Ok(())
    }
    /// Clock-free original source/cancel gate plus caller-supplied current hard
    /// time. Check again immediately before every real native syscall. Returning
    /// false never proves an admitted operation Unsent; settle its actual fact.
    /// Physical Close actions remain allowed after any source/deadline failure.
    pub fn effect_io_allowed(
        &self,
        id: EffectId<'id>,
        current: &Identity,
        now: u64,
    ) -> Result<bool, Error> {
        let at = self.effect_index(id)?;
        let e = self.effects.get(at).ok_or(Error::StaleGeneration)?;
        if !self.eligible(e) {
            return Ok(false);
        }
        if e.action.close() {
            return Ok(true);
        }
        if e.cancelled || self.identity != *current || now >= e.deadline {
            return Ok(false);
        }
        if let Some(call) = e.action.call() {
            let c = self.call(call)?;
            if matches!(
                c.phase,
                Phase::Opening | Phase::AwaitRing | Phase::Ringing | Phase::Calling
            ) && now >= c.setup_deadline
            {
                return Ok(false);
            }
            if matches!(
                e.action,
                Action::PeerFrame { .. } | Action::ReceiveDone { .. }
            ) && (c.gone || !c.channel_ready || c.source.is_none())
            {
                return Ok(false);
            }
        }
        Ok(!self.client_closed)
    }
    /// Settle the real original effect. No clock/provider is called and no new
    /// frame is allocated. Terminal payload ownership is transferred unchanged.
    /// A Written open requires the actual attached native port/Channel owner.
    pub fn complete_effect(
        &mut self,
        id: EffectId<'id>,
        completion: Completion,
        now: u64,
    ) -> Result<Terminal<'id>, Error> {
        let at = self.effect_index(id)?;
        let e = self.effects.get(at).ok_or(Error::StaleGeneration)?;
        if !self.eligible(e) {
            return Err(Error::NotReady);
        }
        if completion == Completion::Processed && !matches!(e.action, Action::ReceiveDone { .. }) {
            return Err(Error::InvalidInput);
        }
        if completion == Completion::Written && !e.admitted {
            return Err(Error::NotReady);
        }
        if let Some(call) = e.action.call() {
            let c = self.call(call)?;
            if c.debt == 0 {
                return Err(Error::Malformed);
            }
            if completion == Completion::Written
                && matches!(e.action, Action::OpenChannel { .. })
                && c.source.is_none()
            {
                return Err(Error::NotReady);
            }
        }
        if completion == Completion::Written
            && matches!(e.action, Action::OpenPort { .. })
            && self.port_source.is_none()
        {
            return Err(Error::NotReady);
        }
        let e = self.effects.remove(at).ok_or(Error::StaleGeneration)?;
        self.queued_bytes -= e.action.bytes();
        if !e.action.close() {
            self.normal_effects -= 1;
        }
        if let Some(call) = e.action.call() {
            let fault = match completion {
                Completion::Written | Completion::Processed => None,
                Completion::Unsent(error) | Completion::Lost { reason: error, .. } => Some(error),
            };
            let c = self.call_mut(call)?;
            c.debt -= 1;
            if let Some(error) = fault {
                c.failure.get_or_insert(error);
            }
            match (&e.action, completion) {
                (Action::OpenChannel { .. }, Completion::Written) => {
                    c.opening = false;
                    c.channel_ready = !c.gone;
                    if c.phase == Phase::Opening {
                        c.phase = Phase::Calling;
                    }
                }
                (Action::OpenChannel { .. }, _) => {
                    c.opening = false;
                    if c.source.is_none() && matches!(completion, Completion::Unsent(_)) {
                        c.gone = true;
                    }
                }
                (Action::PeerFrame { frame, .. }, Completion::Written) => {
                    match Message::decode(frame) {
                        Ok(Message::PeerRing { .. }) => c.ring_written = true,
                        Ok(Message::PeerControl(PeerControl::PickUp)) => {
                            c.local_pickup_written = true
                        }
                        Ok(Message::PeerControl(PeerControl::HangUp)) => {
                            c.local_hangup_written = true
                        }
                        _ => {}
                    }
                }
                (Action::CloseChannel { .. }, Completion::Written) => {
                    c.gone = true;
                    c.phase = Phase::Closed;
                    c.channel_ready = false;
                }
                (Action::CloseChannel { .. }, _) if c.gone => c.phase = Phase::Closed,
                _ => {}
            }
            if let Some(error) = fault
                && !e.action.close()
            {
                self.begin_close(call, EndReason::Failed(error), now, None)?;
            }
        } else {
            match (&e.action, completion) {
                (Action::OpenPort { .. }, Completion::Written) => {
                    self.port_ready = !self.port_closing && !self.port_gone
                }
                (Action::ClosePort { .. }, Completion::Written) => {
                    self.port = None;
                    self.port_source = None;
                    self.port_ready = false;
                }
                (Action::CloseClient, Completion::Written) => self.client_closed = true,
                (Action::ClosePort { .. }, _) if self.port_gone => {
                    self.port = None;
                    self.port_source = None;
                    self.port_ready = false;
                }
                (_, Completion::Unsent(error) | Completion::Lost { reason: error, .. }) => {
                    self.failure.get_or_insert(error);
                    if matches!(e.action, Action::OpenPort { .. }) {
                        if self.port_source.is_none() && matches!(completion, Completion::Unsent(_))
                        {
                            self.port_gone = true;
                        }
                        self.cancel(error, now)?;
                    }
                }
                _ => {}
            }
        }
        self.last_now = self.last_now.max(now);
        Ok(Terminal {
            id,
            action: e.action,
            completion,
        })
    }
    /// Record actual original Channel disappearance. EOF is retained as its
    /// original error; it never becomes a remote pickup or peer HangUp741.
    /// No allocation or clock provider is needed to retain this terminal fact.
    pub fn peer_lost(
        &mut self,
        id: CallId<'id>,
        source: Source,
        reason: Error,
    ) -> Result<(), Error> {
        let notify = !self.client_closing;
        let now = self.last_now;
        let c = self.call_mut(id)?;
        if c.source != Some(source) {
            return Err(Error::StaleGeneration);
        }
        if c.gone {
            return Err(Error::Replay);
        }
        let active = !matches!(c.phase, Phase::AwaitRing | Phase::Closing | Phase::Closed);
        c.gone = true;
        c.channel_ready = false;
        c.failure.get_or_insert(reason);
        c.notify_hangup |= notify && active;
        self.begin_close(id, EndReason::Failed(reason), now, None)
    }
    /// A known native MQ loss retires only its original port/Channel sources.
    /// It does not reconnect or replay a ringing/audio intent on a new source.
    pub fn source_lost(&mut self, source: Source, reason: Error) -> Result<(), Error> {
        let port_lost = self.port_source == Some(source);
        if port_lost {
            self.port_ready = false;
            self.port_gone = true;
            self.failure.get_or_insert(reason);
        }
        for index in 0..self.calls.len() {
            let id = self.calls[index]
                .as_ref()
                .filter(|c| c.source == Some(source) && !c.gone)
                .map(|c| c.id);
            if let Some(id) = id {
                self.peer_lost(id, source, reason)?;
            }
        }
        if port_lost {
            self.cancel(reason, self.last_now)?;
        }
        Ok(())
    }
    /// Record that this actual local IPC is already physically gone before
    /// cancelling remaining original native channels and effects.
    pub fn client_lost(&mut self, reason: Error, now: u64) -> Result<(), Error> {
        self.client_closed = true;
        self.failure.get_or_insert(reason);
        self.cancel(reason, now)
    }
    /// Cancel this original Line. Physical retirement must happen first in the
    /// host; pending/admitted effects and their real outcomes remain retained.
    /// Queue space for every original close was reserved at construction.
    pub fn cancel(&mut self, reason: Error, now: u64) -> Result<(), Error> {
        if self.client_closing {
            return Ok(());
        }
        self.client_closing = true;
        self.port_ready = false;
        for e in &mut self.effects {
            if !e.action.close() {
                e.cancelled = true;
            }
        }
        for index in 0..self.calls.len() {
            let id = self.calls[index].as_ref().map(|c| c.id);
            if let Some(id) = id {
                self.call_mut(id)?.notify_hangup = false;
                self.begin_close(id, EndReason::Cancelled(reason), now, None)?;
            }
        }
        let deadline = Self::deadline(now, self.limits.close_timeout).unwrap_or(now);
        if let Some(port) = self.port
            && !self.port_closing
        {
            self.push_close(Action::ClosePort { port }, deadline)?;
            self.port_closing = true;
        }
        self.push_close(Action::CloseClient, deadline)?;
        self.last_now = self.last_now.max(now);
        Ok(())
    }
    /// Observe known identity source loss and fence all subsequent normal I/O.
    /// The native owner physically retires the old MQs before settling debts.
    pub fn identity_lost(&mut self, reason: Error, now: u64) -> Result<(), Error> {
        self.failure.get_or_insert(reason);
        self.cancel(reason, now)
    }
    /// Advance at most one deferred local HangUp notification. This allocation
    /// is separate from retaining the original source-loss fact. Resource
    /// pressure does not erase that fact or turn EOF into a peer message.
    pub fn progress(&mut self, now: u64) -> Result<bool, Error> {
        let pending = self
            .calls
            .iter()
            .flatten()
            .find(|c| c.notify_hangup)
            .map(|c| (c.id, c.cid));
        let Some((id, cid)) = pending else {
            return Ok(false);
        };
        if self.client_closing {
            self.call_mut(id)?.notify_hangup = false;
            return Ok(true);
        }
        let frame = self.client_frame(
            id,
            Message::Control {
                action: ClientControl::HangUp,
                cid,
            },
        )?;
        self.batch([Some(frame), None, None], now)?;
        self.call_mut(id)?.notify_hangup = false;
        Ok(true)
    }
    /// Expire original setup/output intents without refreshing any hard bound.
    /// Connected calls have no invented protocol duration; the native parent's
    /// original lifetime/cancel guard remains authoritative for ongoing calls.
    pub fn tick(&mut self, now: u64) -> Result<(), Error> {
        self.last_now = self.last_now.max(now);
        for index in 0..self.calls.len() {
            let id = self.calls[index]
                .as_ref()
                .filter(|c| {
                    matches!(
                        c.phase,
                        Phase::Opening | Phase::AwaitRing | Phase::Ringing | Phase::Calling
                    ) && now >= c.setup_deadline
                })
                .map(|c| c.id);
            if let Some(id) = id {
                self.begin_close(id, EndReason::Failed(Error::Timeout), now, None)?;
            }
        }
        let expired = self
            .effects
            .front()
            .filter(|e| !e.action.close() && now >= e.deadline)
            .and_then(|e| e.action.call());
        if let Some(id) = expired {
            self.begin_close(id, EndReason::Failed(Error::Deadline), now, None)?;
        }
        Ok(())
    }
    /// Earliest original retained intent deadline. Native cleanup may continue
    /// after it only to retire physical resources and report undrained debt.
    pub fn next_deadline(&self) -> Option<u64> {
        self.effects
            .iter()
            .map(|e| e.deadline)
            .chain(self.calls.iter().flatten().filter_map(|c| match c.phase {
                Phase::Opening | Phase::AwaitRing | Phase::Ringing | Phase::Calling => {
                    Some(c.setup_deadline)
                }
                Phase::Closing => c.close_deadline,
                _ => None,
            }))
            .min()
    }
    /// Remove a fully retired original owner after all original outcomes and
    /// required local notifications have been observed. No CID is ever reused.
    pub fn take_report(&mut self, id: CallId<'id>) -> Result<Option<CallReport<'id>>, Error> {
        let c = self.call(id)?;
        if !c.gone || c.debt != 0 || c.notify_hangup {
            return Ok(None);
        }
        let report = CallReport {
            call: id,
            cid: c.cid,
            peer: c.peer,
            reason: c.reason.ok_or(Error::NotReady)?,
            failure: c.failure,
            ring_written: c.ring_written,
            remote_pickup: c.remote_pickup,
            local_pickup_written: c.local_pickup_written,
            remote_hangup: c.remote_hangup,
            local_hangup_written: c.local_hangup_written,
        };
        let slot = id.slot;
        self.calls[slot] = None;
        Ok(Some(report))
    }
}

#[cfg(test)]
mod tests;
