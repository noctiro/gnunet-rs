//! Explicit DV ports into the existing TRANSPORT engine. No method here performs
//! authentication, native IO or durable work. The host port must consume the
//! actual actor's private grant; raw bytes alone never mint that grant.
use super::*;

#[cfg(test)]
mod control_tests;
use crate::dv;
use gnunet_types::{Duration, Rejected};
mod rx;
mod tx;
pub(super) use rx::HeldSource;
use rx::RxBook;
pub use rx::{InboxPacket, NativeInput};
use tx::TxBook;
pub(super) use tx::VirtualPlan;
pub use tx::{
    FlowDiagnostic, JobDiagnostic, PathId, QueueDiagnostic, StagedSend, TransferCancellation,
    TransferDiagnostic, TransferId, TransferOutcome, TransferState, VirtualAttempt, VirtualId,
    VirtualPacket,
};

/// One caller-adopted actual local DV source. Not a remote peer or queue.
#[derive(Clone, Debug)]
pub struct Source {
    instance: Arc<()>,
    serial: u64,
}
impl PartialEq for Source {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.instance, &other.instance) && self.serial == other.serial
    }
}
impl Eq for Source {}
/// Exact current direct queue generation, minted only by this Engine.
#[derive(Clone, Debug)]
pub struct DirectQueue {
    owner: ClientId,
    peer: PeerId,
    queue: u32,
    route: u64,
}
impl PartialEq for DirectQueue {
    fn eq(&self, other: &Self) -> bool {
        self.owner == other.owner
            && self.peer == other.peer
            && self.queue == other.queue
            && self.route == other.route
    }
}
impl Eq for DirectQueue {}
impl DirectQueue {
    /// Original communicator MQ identity.
    pub fn owner(&self) -> &ClientId {
        &self.owner
    }
    /// Actual direct destination, distinct from a decrypted BOX sender.
    pub const fn peer(&self) -> PeerId {
        self.peer
    }
    /// Original communicator-local queue number.
    pub const fn queue(&self) -> u32 {
        self.queue
    }
}
/// Original physical ingress debt. Non-Clone; only its owning actor can return
/// it. A decoded sender must never replace carrier in the physical1203 callback.
#[derive(Debug)]
pub struct Ingress {
    source: Source,
    serial: u64,
}
/// Borrowed-owner lookup identity. Cloning it neither consumes nor releases the
/// original physical FC debt; only the non-Clone Ingress can finish that debt.
#[derive(Clone, Debug)]
pub struct IngressId {
    source: Source,
    serial: u64,
}
impl Ingress {
    /// Exact original local source lease, not a new authentication receipt.
    pub fn source(&self) -> &Source {
        &self.source
    }
    /// Read-only identity for same-grant delivery while Actor keeps original J.
    pub fn id(&self) -> IngressId {
        IngressId {
            source: self.source.clone(),
            serial: self.serial,
        }
    }
}
impl IngressId {
    /// Same original local source, with no physical ACK completion authority.
    pub fn source(&self) -> &Source {
        &self.source
    }
}
/// Borrowed complete frame, with its exact physical source and reserved debt.
pub struct Incoming<'a> {
    /// Original actual direct queue, not an invented DV queue.
    pub queue: DirectQueue,
    /// Move this value into the actual actor's original J.
    pub origin: Ingress,
    /// Original complete1218/1219 frame, excluding communicator1202 prefix.
    pub message: &'a [u8],
}
/// Local admission result, never a remote application acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Delivery {
    /// Existing Flow/control/fragment handler admitted this original inner frame.
    Accepted,
    /// The same original grant was already admitted; it must not be delivered twice.
    AlreadyAccepted,
}
/// Actual disposition of the original communicator FC debt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngressEnd {
    /// Actual1203 frame was queued to the original current communicator MQ.
    AckQueued,
    /// Original input requested no FC acknowledgement.
    NoAck,
    /// Original MQ is gone; no acknowledgement was retagged to a replacement.
    OriginalSourceGone,
}
/// Exact one-shot local1209 identity, never an on-wire extension.
#[derive(Clone, Debug)]
pub struct SendId {
    instance: Arc<()>,
    mid: [u8; 8],
}
impl PartialEq for SendId {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.instance, &other.instance) && self.mid == other.mid
    }
}
impl Eq for SendId {}
/// Preflighted immutable1209 body. No queue grant or byte exposure yet.
#[must_use = "admit to the same physical MQ, or discard without committing"]
pub struct PreparedSend {
    queue: DirectQueue,
    mid: [u8; 8],
    bytes: Vec<u8>,
    debit: u64,
    expires: u64,
}
impl PreparedSend {
    /// Complete actual1209 IPC frame length.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    /// IPC frames always contain the header and48-byte SEND prefix.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
    /// Exact physical owner fixed at preparation.
    pub fn owner(&self) -> &ClientId {
        &self.queue.owner
    }
}
/// Real communicator result, separate from any local IPC write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketOutcome {
    /// Original1210 status1 reported the original complete packet written.
    Written,
    /// Original1210 reported a failure. Packet exposure is not recoverable from it.
    Failed(u32),
    /// Original physical MQ was closed, without a terminal packet callback.
    SourceLost,
}
/// Accumulated actual physical facts. Never a target/CORE processing receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendState {
    /// Actual positive bytes of this original1209 IPC frame reached its MQ.
    pub ipc_exposed: bool,
    /// Complete original1209 frame reached the original communicator MQ.
    pub ipc_written: bool,
    /// Actual original communicator callback or physical MQ loss.
    pub packet: Option<PacketOutcome>,
}
struct IngressRow {
    source: Source,
    serial: u64,
    owner: ClientId,
    carrier: PeerId,
    flow: Option<[u8; 8]>,
    admitted: bool,
    delivered: bool,
    failure: Option<Error>,
    pending: Option<Zeroizing<Vec<u8>>>,
}
struct Virtual {
    source: Source,
    peer: PeerId,
    until: u64,
}
struct SendRow {
    parent: Option<(TransferId, Span)>,
    id: SendId,
    queue: DirectQueue,
    debit: u64,
    queue_debit: bool,
    state: SendState,
}
pub(super) struct Book {
    tx: TxBook,
    rx: RxBook,
    source: Option<Source>,
    retiring: bool,
    serial: u64,
    ingresses: Vec<IngressRow>,
    virtuals: Vec<Virtual>,
    sends: Vec<SendRow>,
}
impl Book {
    pub(super) fn new(limits: Limits) -> Result<Self, Error> {
        let mut ingresses = Vec::new();
        let mut virtuals = Vec::new();
        let mut sends = Vec::new();
        ingresses
            .try_reserve_exact(limits.messages)
            .map_err(|_| Error::Capacity)?;
        virtuals
            .try_reserve_exact(limits.peers)
            .map_err(|_| Error::Capacity)?;
        sends
            .try_reserve_exact(limits.messages)
            .map_err(|_| Error::Capacity)?;
        Ok(Self {
            tx: TxBook::new(limits)?,
            rx: RxBook::new(limits)?,
            source: None,
            retiring: false,
            serial: 0,
            ingresses,
            virtuals,
            sends,
        })
    }
    fn next(&mut self) -> Result<u64, Error> {
        let next = self.serial.checked_add(1).ok_or(Error::Overflow)?;
        self.serial = next;
        Ok(next)
    }
    pub(super) fn has_peer(&self, peer: PeerId, now: u64) -> bool {
        self.virtuals
            .iter()
            .any(|v| v.peer == peer && v.until > now && self.source.as_ref() == Some(&v.source))
    }
    pub(super) fn expire(&mut self, now: u64) {
        self.virtuals.retain(|v| v.until > now);
    }
    pub(super) fn source_lost(&mut self, owner: &ClientId) {
        let mut i = 0;
        while i < self.sends.len() {
            if &self.sends[i].queue.owner == owner && self.sends[i].state.packet.is_none() {
                self.sends[i].state.packet = Some(PacketOutcome::SourceLost);
                if let Some((parent, span)) = self.sends[i].parent.clone() {
                    let state = self.sends[i].state;
                    self.transfer_packet(&parent, span, state);
                    self.sends.swap_remove(i);
                    self.settle_retired_transfer(&parent);
                    continue;
                }
            }
            i += 1;
        }
    }
    pub(super) fn sent(
        &mut self,
        owner: &ClientId,
        peer: PeerId,
        queue: u32,
        mid: [u8; 8],
        status: u32,
    ) {
        let Some(i) = self.sends.iter().position(|r| {
            r.queue.owner == *owner
                && r.queue.peer == peer
                && r.queue.queue == queue
                && r.id.mid == mid
        }) else {
            return;
        };
        if self.sends[i].state.packet.is_none() {
            self.sends[i].state.packet = Some(if status == 1 {
                PacketOutcome::Written
            } else {
                PacketOutcome::Failed(status)
            });
            if let Some((parent, span)) = self.sends[i].parent.clone() {
                let state = self.sends[i].state;
                self.transfer_packet(&parent, span, state);
                self.sends.swap_remove(i);
                self.settle_retired_transfer(&parent);
            }
        }
    }
}
impl Engine {
    /// Adopt a new actual actor/local-identity epoch. This explicit trust port
    /// opens no source and proves no remote identity by itself.
    pub fn dv_attach_source(&mut self, actual_local: PeerId) -> Result<Source, Error> {
        if actual_local != self.identity {
            return Err(Error::Authentication);
        }
        if self.dv_bridge.source.is_some() {
            return Err(Error::Conflict);
        }
        let source = Source {
            instance: self.instance.clone(),
            serial: self.dv_bridge.next()?,
        };
        self.dv_bridge.retiring = false;
        self.dv_bridge.source = Some(source.clone());
        Ok(source)
    }
    /// Stop new DV work and withdraw virtual visibility, but retain the original
    /// owner gate until its actual native/FC/worker obligations are settled.
    pub fn dv_begin_retire_source(&mut self, source: &Source) -> Result<(), Error> {
        if self.dv_bridge.source.as_ref() != Some(source)
            || !Arc::ptr_eq(&source.instance, &self.instance)
        {
            return Err(Error::Stale);
        }
        self.dv_bridge.retiring = true;
        self.monitor.retire_source(source);
        self.dv_discard_assemblies(source);
        self.dv_bridge.virtuals.retain(|v| &v.source != source);
        self.dv_bridge.retire_tx_source(source);
        for p in 0..self.peers.len() {
            self.refresh(self.peers[p].id)?;
        }
        Ok(())
    }
    /// Original retained local debts, without synthesizing a worker/native fact.
    pub fn dv_source_debts(&self, source: &Source) -> usize {
        self.dv_bridge
            .ingresses
            .iter()
            .filter(|r| &r.source == source)
            .count()
            + self.dv_bridge.tx_debts(source)
            + self
                .held
                .iter()
                .filter(|h| h.dv.as_ref().is_some_and(|d| &d.source == source))
                .count()
    }
    /// Retire the SAME source after its actual actor/PILS/source owner stopped.
    /// Original physical ingress and SEND debts remain until their own outcome.
    pub fn dv_retire_source(&mut self, source: &Source) -> Result<(), Error> {
        if self.dv_bridge.source.as_ref() != Some(source)
            || !Arc::ptr_eq(&source.instance, &self.instance)
        {
            return Err(Error::Stale);
        }
        if self.dv_source_debts(source) != 0 {
            return Err(Error::NotReady);
        }
        self.dv_discard_assemblies(source);
        self.monitor.retire_source(source);
        self.dv_bridge.source = None;
        self.dv_bridge.retiring = false;
        self.dv_bridge.virtuals.retain(|v| &v.source != source);
        for p in 0..self.peers.len() {
            self.refresh(self.peers[p].id)?;
        }
        Ok(())
    }
    pub(in crate::engine) fn dv_check_source(&self, source: &Source) -> Result<(), Error> {
        if !self.dv_bridge.retiring
            && self.dv_bridge.source.as_ref() == Some(source)
            && Arc::ptr_eq(&source.instance, &self.instance)
        {
            Ok(())
        } else {
            Err(Error::Stale)
        }
    }
    pub(in crate::engine) fn dv_flow_in_use(
        &self,
        owner: &ClientId,
        peer: PeerId,
        flow: [u8; 8],
    ) -> bool {
        self.dv_bridge
            .ingresses
            .iter()
            .any(|r| r.owner == *owner && r.carrier == peer && r.flow == Some(flow))
            || self
                .held
                .iter()
                .any(|h| h.owner == *owner && h.peer == peer && h.token == Some(flow))
    }
    /// Active source means the native owner must offer1218/1219 to its real DV
    /// actor before ordinary receive_at, preserving the complete original RX.
    pub fn dv_source_active(&self) -> bool {
        self.dv_bridge.source.is_some()
    }
    fn dv_discard_assemblies(&mut self, source: &Source) {
        let mut i = 0;
        while i < self.assemblies.len() {
            if self.assemblies[i].source.as_ref() == Some(source) {
                self.buffered -= self.assemblies.remove(i).charge();
            } else {
                i += 1;
            }
        }
    }
    /// Business admission state, separate from the original retirement gate.
    pub fn dv_accepting(&self) -> bool {
        self.dv_bridge.source.is_some() && !self.dv_bridge.retiring
    }

    /// Actual business admission state, distinct from a retained cleanup gate.
    pub fn dv_source_accepting(&self) -> bool {
        self.dv_accepting()
    }
    /// Original source for native first-byte attribution, without minting one.
    pub fn dv_current_source(&self) -> Option<&Source> {
        self.dv_bridge.source.as_ref()
    }

    fn dv_queue_index(&self, queue: &DirectQueue, now: u64) -> Result<usize, Error> {
        if !Arc::ptr_eq(&queue.owner.instance, &self.instance) {
            return Err(Error::Stale);
        }
        self.routes
            .iter()
            .position(|r| {
                r.serial == queue.route
                    && r.owner == queue.owner
                    && r.description.peer == queue.peer
                    && r.description.id == queue.queue
                    && r.valid_until > now
                    && self.client(&r.owner).is_ok()
            })
            .ok_or(Error::Stale)
    }
    /// Mint only from an actual current validated direct route. Numeric peer/qid
    /// alone cannot be rebound after teardown or physical source replacement.
    pub fn dv_direct_queue(
        &self,
        owner: &ClientId,
        peer: PeerId,
        queue: u32,
        times: Times,
    ) -> Result<DirectQueue, Error> {
        self.validate_times(times)?;
        let c = self.client(owner)?;
        if self.clients[c].role != Role::Communicator {
            return Err(Error::PermissionDenied);
        }
        let route = self
            .routes
            .iter()
            .find(|r| {
                r.owner == *owner
                    && r.description.peer == peer
                    && r.description.id == queue
                    && r.valid_until > times.monotonic().0
            })
            .ok_or(Error::NotReady)?;
        Ok(DirectQueue {
            owner: owner.clone(),
            peer,
            queue,
            route: route.serial,
        })
    }
    /// Inspect current direct routes without heap allocation. Each returned
    /// lease is revalidated at actual queue admission.
    pub fn dv_direct_queues(&self, times: Times) -> impl Iterator<Item = DirectQueue> + '_ {
        let valid = self.validate_times(times).is_ok();
        self.routes
            .iter()
            .filter(move |r| {
                valid && r.valid_until > times.monotonic().0 && self.client(&r.owner).is_ok()
            })
            .map(|r| DirectQueue {
                owner: r.owner.clone(),
                peer: r.description.peer,
                queue: r.description.id,
                route: r.serial,
            })
    }
    /// Reserve only bounded original FC metadata. The native input is NOT yet
    /// consumed. On actual actor refusal call dv_abort_incoming and retain RX.
    pub fn dv_prepare_incoming<'a>(
        &mut self,
        source: &Source,
        owner: &ClientId,
        input: &'a [u8],
        times: Times,
    ) -> Result<Incoming<'a>, Error> {
        self.dv_check_source(source)?;
        self.validate_times(times)?;
        let c = self.client(owner)?;
        if self.clients[c].role != Role::Communicator {
            return Err(Error::PermissionDenied);
        }
        let communicator::Request::Incoming {
            flow_control,
            flow_id,
            peer,
            message,
            ..
        } = communicator::Request::decode(input)?
        else {
            return Err(Error::Unsupported);
        };
        if !matches!(
            Frame::decode(message)?.header().message_type().value(),
            dv::LEARN_TYPE | dv::BOX_TYPE
        ) {
            return Err(Error::Unsupported);
        }
        if self.dv_bridge.ingresses.len() == self.limits.messages {
            return Err(Error::Capacity);
        }
        if flow_control && self.dv_flow_in_use(owner, peer, flow_id) {
            return Err(Error::Conflict);
        }
        let route = self
            .routes
            .iter()
            .find(|r| {
                r.owner == *owner
                    && r.description.peer == peer
                    && r.valid_until > times.monotonic().0
            })
            .ok_or(Error::NotReady)?;
        let queue = DirectQueue {
            owner: owner.clone(),
            peer,
            queue: route.description.id,
            route: route.serial,
        };
        let serial = self.dv_bridge.next()?;
        self.time_at(times)?;
        self.dv_bridge.ingresses.push(IngressRow {
            source: source.clone(),
            serial,
            owner: owner.clone(),
            carrier: peer,
            flow: flow_control.then_some(flow_id),
            admitted: false,
            delivered: false,
            failure: None,
            pending: None,
        });
        Ok(Incoming {
            queue,
            origin: Ingress {
                source: source.clone(),
                serial,
            },
            message,
        })
    }
    fn dv_ingress_index(&self, origin: &Ingress) -> Result<usize, Error> {
        self.dv_ingress_id(&origin.id())
    }
    fn dv_ingress_id(&self, origin: &IngressId) -> Result<usize, Error> {
        if !Arc::ptr_eq(&origin.source.instance, &self.instance) {
            return Err(Error::Stale);
        }
        self.dv_bridge
            .ingresses
            .iter()
            .position(|r| r.source == origin.source && r.serial == origin.serial)
            .ok_or(Error::Stale)
    }
    /// Actual native actor admission occurred for this original prepared input.
    /// This trusted port grants no authentication or processing success.
    pub fn dv_input_admitted(&mut self, id: &IngressId) -> Result<(), Error> {
        let i = self.dv_ingress_id(id)?;
        if self.dv_bridge.ingresses[i].admitted {
            return Err(Error::Conflict);
        }
        self.dv_bridge.ingresses[i].admitted = true;
        Ok(())
    }
    /// Zero-admission callback returned its original opaque metadata separately.
    /// Read-only identity can retire only a never-admitted reservation, not FC.
    pub fn dv_abort_prepared(&mut self, id: &IngressId) -> Result<(), Error> {
        let i = self.dv_ingress_id(id)?;
        if self.dv_bridge.ingresses[i].admitted {
            return Err(Error::Conflict);
        }
        self.dv_bridge.ingresses.swap_remove(i);
        Ok(())
    }
    /// Actor did NOT admit this original. No ACK or success; caller retains the
    /// same complete RX frame and may wait for an actual capacity wakeup.
    pub fn dv_abort_incoming(&mut self, origin: Ingress) -> Result<(), Rejected<Ingress>> {
        match self.dv_ingress_index(&origin) {
            Ok(i) => {
                let row = self.dv_bridge.ingresses.swap_remove(i);
                if let Some(body) = row.pending {
                    self.buffered -= body.len();
                }
                Ok(())
            }
            Err(reason) => Err(Rejected {
                reason,
                value: origin,
            }),
        }
    }
    /// Consume the real actor's original J after termination. Allocation refusal
    /// preserves it; an old source is never acknowledged on a new ClientId.
    pub fn dv_finish_incoming(&mut self, origin: Ingress) -> Result<IngressEnd, Rejected<Ingress>> {
        let result = (|| {
            let i = self.dv_ingress_index(&origin)?;
            let r = &self.dv_bridge.ingresses[i];
            if self.client(&r.owner).is_err() {
                return Ok((i, IngressEnd::OriginalSourceGone));
            }
            let end = if let Some(flow) = r.flow {
                self.ack(r.owner.clone(), r.carrier, flow)?;
                IngressEnd::AckQueued
            } else {
                IngressEnd::NoAck
            };
            Ok((i, end))
        })();
        match result {
            Ok((i, end)) => {
                let row = self.dv_bridge.ingresses.swap_remove(i);
                if let Some(body) = row.pending {
                    self.buffered -= body.len();
                }
                Ok(end)
            }
            Err(reason) => Err(Rejected {
                reason,
                value: origin,
            }),
        }
    }
    /// Install only a current actual actor route/proof duration, translated from
    /// its original native hard target AFTER sampling Engine Times. This port
    /// does not validate a raw caller assertion. The actual host uses Granted.
    pub fn dv_virtual_peer(
        &mut self,
        source: &Source,
        peer: PeerId,
        remaining: Duration,
        times: Times,
    ) -> Result<(), Error> {
        self.dv_check_source(source)?;
        self.validate_times(times)?;
        if remaining.0 == 0 || remaining.0 == u64::MAX {
            return Err(Error::Deadline);
        }
        let until = times
            .monotonic()
            .0
            .checked_add(remaining.0)
            .filter(|t| *t != u64::MAX)
            .ok_or(Error::Overflow)?;
        let old = self
            .dv_bridge
            .virtuals
            .iter()
            .position(|v| v.source == *source && v.peer == peer);
        if old.is_none() && self.dv_bridge.virtuals.len() == self.limits.peers {
            return Err(Error::Capacity);
        }
        let p = self.ensure_peer(peer, times.monotonic().0)?;
        let mut notify = Vec::new();
        if !self.peers[p].connected {
            let count = self.clients.iter().filter(|c| c.role == Role::Core).count();
            if self
                .output
                .len()
                .checked_add(count)
                .is_none_or(|n| n > self.limits.messages + self.limits.control_messages)
            {
                return Err(Error::WouldBlock);
            }
            notify
                .try_reserve_exact(count)
                .map_err(|_| Error::Capacity)?;
            for client in self.clients.iter().filter(|c| c.role == Role::Core) {
                let mut bytes = message(0, 40)?;
                CoreResponse::Connected(peer).encode(&mut bytes)?;
                notify.push(Output::Frame {
                    client: client.id.clone(),
                    bytes,
                });
            }
        }
        self.time_at(times)?;
        if let Some(i) = old {
            self.dv_bridge.virtuals[i].until = until;
        } else {
            self.dv_bridge.virtuals.push(Virtual {
                source: source.clone(),
                peer,
                until,
            });
        }
        self.output.extend(notify);
        self.peers[p].connected = true;
        self.peers[p].flow_dirty = true;
        Ok(())
    }
    /// Trusted-host port: deliver only immutable bytes borrowed from the actual
    /// private box_admission::Granted, with its exact original physical Ingress.
    /// Reuses existing Flow, reliable ACK, fragment and CORE allocation state.
    /// The host must check grant target/local source before calling this method.
    pub fn dv_deliver(
        &mut self,
        origin: &IngressId,
        peer: PeerId,
        input: &[u8],
        times: Times,
        signer: &mut impl Signer,
    ) -> Result<Delivery, Error> {
        self.dv_check_source(&origin.source)?;
        let i = self.dv_ingress_id(origin)?;
        if !self.dv_bridge.ingresses[i].admitted {
            return Err(Error::NotReady);
        }
        if self.dv_bridge.ingresses[i].delivered {
            return Ok(Delivery::AlreadyAccepted);
        }
        if let Some(reason) = self.dv_bridge.ingresses[i].failure {
            return Err(reason);
        }

        self.validate_times(times)?;
        if signer.identity() != self.identity {
            return Err(Error::Authentication);
        }
        if matches!(
            Frame::decode(input)?.header().message_type().value(),
            dv::LEARN_TYPE | dv::BOX_TYPE | 1303
        ) {
            return Err(Error::Unsupported);
        }
        // A genuine authenticated BOX can carry FLOW, acknowledgements or a
        // response to our original direct challenge before a reverse DV route
        // exists. Dispatch control without promoting the sender to connected;
        // final payload delivery separately requires a current usable route.
        self.time_at(times)?;
        let result = (|| -> Result<(), Error> {
            // An outer reassembly/reliable envelope is consumed only once. If its
            // final same-peer handler is blocked, retain the actual completed body
            // under this original ingress, rather than replaying a last fragment.
            let retained = self.dv_bridge.ingresses[i].pending.take();
            if retained.is_none() && Frame::decode(input)?.header().message_type().value() == 1216 {
                let inner = p2p::Reliable::decode(input)?.message;
                if self
                    .buffered
                    .checked_add(inner.len())
                    .is_none_or(|n| n > self.limits.bytes)
                {
                    return Err(Error::Capacity);
                }
            }
            let step = if let Some(body) = retained {
                self.buffered -= body.len();
                self.dv_dispatch_retained(i, peer, body, times, signer)?
            } else {
                match self.network_peer(None, peer, input, 0, times, signer)? {
                    NetworkStep::OwnedMessage(body, _) => {
                        self.dv_dispatch_retained(i, peer, body, times, signer)?
                    }
                    other => other,
                }
            };
            match step {
                NetworkStep::LocalFailure(e) => return Err(e),
                NetworkStep::Processed(_) => {}
                NetworkStep::OwnedMessage(_, _) | NetworkStep::Diverted => {
                    return Err(Error::Malformed);
                }
            }
            Ok(())
        })();
        if let Err(reason) = result {
            if !matches!(
                reason,
                Error::WouldBlock | Error::NotReady | Error::Capacity
            ) {
                self.dv_bridge.ingresses[i].failure = Some(reason);
            }
            return Err(reason);
        }
        self.dv_bridge.ingresses[i].delivered = true;
        Ok(Delivery::Accepted)
    }
    fn dv_dispatch_retained(
        &mut self,
        i: usize,
        peer: PeerId,
        body: Zeroizing<Vec<u8>>,
        times: Times,
        signer: &mut impl Signer,
    ) -> Result<NetworkStep, Error> {
        // The completing assembly just released >=body.len() charge. Reliable
        // envelopes may require a fresh bounded retained-body reservation.
        let charged = self
            .buffered
            .checked_add(body.len())
            .ok_or(Error::Overflow)?;
        if charged > self.limits.bytes {
            // An invariant violation is terminal, not a retry of a consumed
            // fragment. Normal reliable preflight and assembly charge ensure fit.
            return Err(Error::TooLarge);
        }
        let result = self.network_peer(None, peer, &body, 0, times, signer);
        if matches!(
            result,
            Err(Error::WouldBlock | Error::NotReady | Error::Capacity)
                | Ok(NetworkStep::LocalFailure(
                    Error::WouldBlock | Error::NotReady | Error::Capacity
                ))
        ) {
            self.buffered = self
                .buffered
                .checked_add(body.len())
                .ok_or(Error::Overflow)?;
            self.dv_bridge.ingresses[i].pending = Some(body);
        }
        result
    }
    /// Prepare one whole already-created DV packet for its ACTUAL selected
    /// direct queue. Larger packets explicitly require the shared fragmentation
    /// path; this method never invents a queue or silently truncates/reseals.
    pub fn dv_prepare_send(
        &self,
        queue: &DirectQueue,
        input: &[u8],
        without_fc: bool,
        remaining: Duration,
        times: Times,
    ) -> Result<PreparedSend, Error> {
        self.validate_times(times)?;
        let q = self.dv_queue_index(queue, times.monotonic().0)?;
        let frame = Frame::decode(input)?;
        if !matches!(
            frame.header().message_type().value(),
            dv::LEARN_TYPE | dv::BOX_TYPE
        ) {
            return Err(Error::Unsupported);
        }
        if input.len()
            > (self.routes[q].description.mtu as usize).min(communicator::MAX_INCOMING_MESSAGE_LEN)
        {
            return Err(Error::TooLarge);
        }
        if !self.routes[q].unlimited && self.routes[q].available == 0 {
            return Err(Error::WouldBlock);
        }
        if self.dv_bridge.sends.len() == self.limits.messages
            || self.attempts.len() >= self.limits.messages + self.limits.control_messages
        {
            return Err(Error::Capacity);
        }
        let p = self
            .peers
            .iter()
            .position(|p| p.id == queue.peer)
            .ok_or(Error::Stale)?;
        let debit = if without_fc {
            0
        } else {
            u64::try_from(input.len()).map_err(|_| Error::Overflow)?
        };
        let used = self.peers[p]
            .outbound_used
            .checked_add(debit)
            .ok_or(Error::Overflow)?;
        if used > self.peers[p].outbound_window && !without_fc {
            return Err(Error::WouldBlock);
        }
        let expires = times
            .monotonic()
            .0
            .checked_add(remaining.0)
            .filter(|t| *t != u64::MAX && remaining.0 > 0)
            .ok_or(Error::Deadline)?;
        let mid = self
            .message_serial
            .checked_add(1)
            .ok_or(Error::Overflow)?
            .to_be_bytes();
        let mut bytes = message(1209, communicator::SEND_PREFIX_LEN + input.len())?;
        bytes[4..8].copy_from_slice(&queue.queue.to_be_bytes());
        bytes[8..16].copy_from_slice(&mid);
        bytes[16..48].copy_from_slice(&queue.peer.0);
        bytes[48..].copy_from_slice(input);
        Ok(PreparedSend {
            queue: queue.clone(),
            mid,
            bytes,
            debit,
            expires,
        })
    }
    /// Commit immediately before the already-reserved actual native enqueue.
    /// On zero-admission enqueue failure dv_unsent rolls back this exact debit.
    pub fn dv_commit_send(
        &mut self,
        prepared: PreparedSend,
        times: Times,
    ) -> Result<(SendId, ClientId, Vec<u8>), Rejected<PreparedSend>> {
        let checked = (|| {
            self.validate_times(times)?;
            let q = self.dv_queue_index(&prepared.queue, times.monotonic().0)?;
            if prepared.mid
                != self
                    .message_serial
                    .checked_add(1)
                    .ok_or(Error::Overflow)?
                    .to_be_bytes()
                || times.monotonic().0 >= prepared.expires
            {
                return Err(Error::Stale);
            }
            if self.dv_bridge.sends.len() == self.limits.messages
                || self.attempts.len() >= self.limits.messages + self.limits.control_messages
            {
                return Err(Error::Capacity);
            }
            if !self.routes[q].unlimited && self.routes[q].available == 0 {
                return Err(Error::WouldBlock);
            }
            let p = self
                .peers
                .iter()
                .position(|p| p.id == prepared.queue.peer)
                .ok_or(Error::Stale)?;
            let used = self.peers[p]
                .outbound_used
                .checked_add(prepared.debit)
                .ok_or(Error::Overflow)?;
            if prepared.debit != 0 && used > self.peers[p].outbound_window {
                return Err(Error::WouldBlock);
            }
            self.routes[q]
                .inflight
                .checked_add(1)
                .ok_or(Error::Overflow)?;
            self.time_at(times)?;
            Ok((q, p, used))
        })();
        let (q, p, used) = match checked {
            Ok(v) => v,
            Err(reason) => {
                return Err(Rejected {
                    reason,
                    value: prepared,
                });
            }
        };
        let id = SendId {
            instance: self.instance.clone(),
            mid: prepared.mid,
        };
        self.routes[q].inflight += 1;
        if !self.routes[q].unlimited {
            self.routes[q].available -= 1;
        }
        self.peers[p].outbound_used = used;
        self.message_serial = u64::from_be_bytes(prepared.mid);
        self.attempts.push(Attempt {
            owner: prepared.queue.owner.clone(),
            peer: prepared.queue.peer,
            queue: prepared.queue.queue,
            route: prepared.queue.route,
            message_id: prepared.mid,
            retired: false,
            remote_record: None,
            bytes: prepared.bytes.len() - communicator::SEND_PREFIX_LEN,
            expires: prepared.expires,
        });
        self.dv_bridge.sends.push(SendRow {
            parent: None,
            id: id.clone(),
            queue: prepared.queue.clone(),
            debit: prepared.debit,
            queue_debit: !self.routes[q].unlimited,
            state: SendState {
                ipc_exposed: false,
                ipc_written: false,
                packet: None,
            },
        });
        Ok((id, prepared.queue.owner, prepared.bytes))
    }
    fn dv_send_index(&self, id: &SendId) -> Result<usize, Error> {
        if !Arc::ptr_eq(&id.instance, &self.instance) {
            return Err(Error::Stale);
        }
        self.dv_bridge
            .sends
            .iter()
            .position(|r| r.id == *id)
            .ok_or(Error::Stale)
    }
    /// Original native1209 byte callback, not a packet send acknowledgement.
    pub fn dv_ipc_progress(
        &mut self,
        id: &SendId,
        bytes: usize,
        complete: bool,
    ) -> Result<(), Error> {
        let i = self.dv_send_index(id)?;
        if bytes == 0 {
            return Err(Error::InvalidInput);
        }
        self.dv_bridge.sends[i].state.ipc_exposed = true;
        self.dv_bridge.sends[i].state.ipc_written |= complete;
        if let Some((parent, _)) = &self.dv_bridge.sends[i].parent
            && let Some(t) = self
                .dv_bridge
                .tx
                .transfers
                .iter_mut()
                .find(|t| &t.id == parent)
        {
            t.state.exposed = true;
        }
        Ok(())
    }
    /// Read retained actual facts without retiring its original callback row.
    pub fn dv_send_state(&self, id: &SendId) -> Result<SendState, Error> {
        Ok(self.dv_bridge.sends[self.dv_send_index(id)?].state)
    }
    /// Original physical owner, also available after its actual source is lost.
    pub fn dv_send_owner(&self, id: &SendId) -> Result<&ClientId, Error> {
        Ok(&self.dv_bridge.sends[self.dv_send_index(id)?].queue.owner)
    }
    /// Actual native queue admission failed with zero exposure. No packet was
    /// admitted; restore only this original unspent queue/Flow debit.
    pub fn dv_unsent(&mut self, id: SendId) -> Result<(), Error> {
        let i = self.dv_send_index(&id)?;
        let row = &self.dv_bridge.sends[i];
        if row.state.ipc_exposed || row.state.packet.is_some() {
            return Err(Error::Conflict);
        }
        if let Some(q) = self.routes.iter_mut().find(|q| q.serial == row.queue.route) {
            q.inflight = q.inflight.checked_sub(1).ok_or(Error::Overflow)?;
            if row.queue_debit && !q.unlimited {
                q.available = q.available.checked_add(1).ok_or(Error::Overflow)?;
            }
        }
        if let Some(p) = self.peers.iter_mut().find(|p| p.id == row.queue.peer) {
            p.outbound_used = p
                .outbound_used
                .checked_sub(row.debit)
                .ok_or(Error::Overflow)?;
        }
        self.attempts.retain(|a| a.message_id != id.mid);
        self.dv_bridge.sends.swap_remove(i);
        Ok(())
    }
    /// Retire only an actual original terminal packet/source fact. The bounded
    /// existing Engine completed-attempt table remains its callback tombstone.
    pub fn dv_take_send(&mut self, id: SendId) -> Result<SendState, Rejected<SendId>> {
        let result = self.dv_send_index(&id).and_then(|i| {
            self.dv_bridge.sends[i]
                .state
                .packet
                .map(|_| i)
                .ok_or(Error::NotReady)
        });
        match result {
            Ok(i) => Ok(self.dv_bridge.sends.swap_remove(i).state),
            Err(reason) => Err(Rejected { reason, value: id }),
        }
    }
}
