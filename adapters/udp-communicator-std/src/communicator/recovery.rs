//! Original TRANSPORT-source publication facts and bounded retirement metadata.
//! Loss records retain no payload, key, replacement authority or synthetic callback.
use super::PublicationState;
use gnunet_service_runtime::framing::OwnedFrame;
use gnunet_types::Error;
use gnunet_wire::official::{Frame, message_type as mt};
use std::{
    net::SocketAddr,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

/// Facts shared only with tickets issued on this exact original MQ generation.
/// The parent separately checks its immutable communicator brand. Atomic values
/// are diagnostic/write facts; they never publish ownership of a frame or key.
pub(super) struct PublicationSource {
    pub(super) owner: std::sync::Arc<()>,
    pub(super) generation: u64,
    issued: AtomicU64,
    written: AtomicU64,
    retired: AtomicBool,
}
impl PublicationSource {
    pub(super) fn new(generation: u64, owner: std::sync::Arc<()>) -> Self {
        Self {
            owner,
            generation,
            issued: AtomicU64::new(0),
            written: AtomicU64::new(0),
            retired: AtomicBool::new(false),
        }
    }
    /// Parent admission supplies an already checked, never-reused sequence.
    pub(super) fn issued(&self, sequence: u64) {
        self.issued.fetch_max(sequence, Ordering::Relaxed);
    }
    /// The original FIFO writer calls this only after the actual whole write.
    pub(super) fn written(&self, sequence: u64) {
        self.written.fetch_max(sequence, Ordering::Relaxed);
    }
    pub(super) fn retire(&self) {
        self.retired.store(true, Ordering::Relaxed);
    }
    /// A historical whole write remains Written after its MQ has retired.
    pub(super) fn state(&self, sequence: u64) -> Result<PublicationState, Error> {
        if sequence == 0 || sequence > self.issued.load(Ordering::Relaxed) {
            return Err(Error::Stale);
        }
        if sequence <= self.written.load(Ordering::Relaxed) {
            Ok(PublicationState::Written)
        } else if self.retired.load(Ordering::Relaxed) {
            Ok(PublicationState::Retired)
        } else {
            Ok(PublicationState::Pending)
        }
    }
}

/// Original local1210 callback fields, without callback or delivery authority.
#[derive(Clone, Copy, Debug)]
pub struct Callback {
    /// Original numeric queue identifier on the retired MQ.
    pub qid: u32,
    /// Original opaque message identifier bytes.
    pub mid: [u8; 8],
    /// Original callback destination peer.
    pub peer: [u8; 32],
    /// Actual immutable callback status, not evidence of peer delivery.
    pub success: bool,
}

/// Exact original local effect metadata; arbitrary payload bytes are omitted.
#[derive(Clone, Copy, Debug)]
pub struct EffectMeta {
    /// Parent-assigned original effect sequence.
    pub sequence: u64,
    /// Actual complete original frame's official message type.
    pub message_type: u16,
    /// Immutable full frame extent, including its standard header.
    pub total_bytes: usize,
    /// Actual positive write prefix; the parent updates from WriteProgress only.
    pub written_bytes: usize,
    /// Present only for an exact original1210 send callback.
    pub callback: Option<Callback>,
}
fn array<const N: usize>(bytes: &[u8], at: usize) -> Result<[u8; N], Error> {
    bytes
        .get(at..at.checked_add(N).ok_or(Error::Overflow)?)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Malformed)
}
impl EffectMeta {
    pub(super) fn from_frame(frame: &OwnedFrame, sequence: u64) -> Result<Self, Error> {
        if sequence == 0 {
            return Err(Error::Stale);
        }
        let bytes = frame.bytes();
        let message_type = Frame::decode(bytes)?.header().message_type().value();
        let callback = if message_type == mt::TRANSPORT_SEND_MSG_ACK.value() {
            if bytes.len() != 52 {
                return Err(Error::Malformed);
            }
            let success = match i32::from_be_bytes(array(bytes, 4)?) {
                1 => true,
                -1 => false,
                _ => return Err(Error::Malformed),
            };
            Some(Callback {
                qid: u32::from_be_bytes(array(bytes, 16)?),
                mid: array(bytes, 8)?,
                peer: array(bytes, 20)?,
                success,
            })
        } else {
            None
        };
        Ok(Self {
            sequence,
            message_type,
            total_bytes: bytes.len(),
            written_bytes: 0,
            callback,
        })
    }
}

/// One actual original operation retired with its physical TRANSPORT source.
/// These metadata are observations, never callbacks sent on a replacement MQ.
#[derive(Clone, Copy, Debug)]
pub enum Retired {
    /// Original queued/partially written MQ frame.
    Mq(EffectMeta),
    /// A complete old MQ SEND command retained before local native admission.
    /// No native write or callback outcome is inferred from this observation.
    IncomingPending {
        /// Original command queue identifier.
        qid: u32,
        /// Original opaque command message identifier.
        mid: [u8; 8],
        /// Original requested peer.
        peer: [u8; 32],
        /// Original requested inner-message extent, without its payload.
        bytes: usize,
    },
    /// Original immutable UDP packet canceled before a known whole native send.
    NativePending {
        /// Original prepared datagram operation identifier.
        operation: u64,
        /// Original destination peer.
        peer: [u8; 32],
        /// Original numeric UDP destination.
        target: SocketAddr,
        /// Immutable original ciphertext extent.
        bytes: usize,
        /// Original queue identifier on the retired TRANSPORT source.
        qid: u32,
        /// Original opaque message identifier.
        mid: [u8; 8],
    },
    /// Original interface-discovery datagram retired with the source.
    DiscoveryPending {
        /// Original retained socket slot.
        socket: usize,
        /// Original prepared discovery operation identifier.
        operation: u64,
        /// Original numeric broadcast/multicast destination.
        target: SocketAddr,
    },
}

/// Borrowed actual original-source facts, without private frame/key material.
#[derive(Debug)]
pub struct TransportLoss<'a> {
    /// Original physical TRANSPORT source generation.
    pub generation: u64,
    /// Original registration was wholly written locally; not a service ACK.
    pub registered: bool,
    /// The original source retained an unreleased input frame.
    pub held_input: bool,
    /// Actual original head read progress, including an incomplete frame.
    pub input_bytes: usize,
    /// Original backchannel ACK work was still retained.
    pub held_ack: bool,
    /// Actual retired operations, bounded before any loss was observed.
    pub retired: &'a [Retired],
}

#[derive(Clone, Copy)]
struct Source {
    generation: u64,
    registered: bool,
    held_input: bool,
    input_bytes: usize,
    held_ack: bool,
}
/// Preallocated single-loss ledger. No loss, push, view or clear allocates.
/// Parent clears it only after observing the old loss and completing the new
/// physical attachment; a second begin cannot overwrite unconsumed facts.
pub(super) struct Ledger {
    source: Option<Source>,
    records: Vec<Retired>,
    maximum: usize,
}
impl Ledger {
    pub(super) fn new(max_records: usize) -> Result<Self, Error> {
        if max_records == 0 {
            return Err(Error::InvalidInput);
        }
        max_records
            .checked_mul(core::mem::size_of::<Retired>())
            .ok_or(Error::Overflow)?;
        let mut records = Vec::new();
        records
            .try_reserve_exact(max_records)
            .map_err(|_| Error::Capacity)?;
        Ok(Self {
            source: None,
            records,
            maximum: max_records,
        })
    }
    pub(super) fn begin(
        &mut self,
        generation: u64,
        registered: bool,
        held_input: bool,
        input_bytes: usize,
        held_ack: bool,
    ) -> Result<(), Error> {
        if self.source.is_some() || !self.records.is_empty() {
            return Err(Error::Conflict);
        }
        self.source = Some(Source {
            generation,
            registered,
            held_input,
            input_bytes,
            held_ack,
        });
        Ok(())
    }
    pub(super) fn push(&mut self, record: Retired) -> Result<(), Error> {
        if self.source.is_none() {
            return Err(Error::NotReady);
        }
        if self.records.len() >= self.maximum || self.records.len() >= self.records.capacity() {
            return Err(Error::Capacity);
        }
        self.records.push(record);
        Ok(())
    }
    pub(super) fn view(&self) -> Option<TransportLoss<'_>> {
        self.source.map(|source| TransportLoss {
            generation: source.generation,
            registered: source.registered,
            held_input: source.held_input,
            input_bytes: source.input_bytes,
            held_ack: source.held_ack,
            retired: &self.records,
        })
    }
    pub(super) fn clear(&mut self) {
        self.records.clear();
        self.source = None;
    }
}

use super::{
    Activity, Communicator, Failure, Origin, frozen,
    transport::{self, Event},
};
use gnunet_service_runtime::{
    connection::Connection,
    framing::{Accounting, Budget, Framed, Limits},
};
use std::{io, sync::Arc};

impl<'id> Communicator<'id> {
    /// Whether the current physical TRANSPORT MQ remains attached. A false
    /// value does not mean that the original UDP sockets or keys were closed.
    #[must_use]
    pub fn transport_attached(&self) -> bool {
        self.transport_attached
    }
    /// Actual source generation; no numeric identifier confers source authority.
    #[must_use]
    pub fn transport_generation(&self) -> u64 {
        self.publication_source.generation
    }
    /// The current registration and every restored queue have wholly written.
    /// Local readiness is not proof of a remote acknowledgement or validation.
    #[must_use]
    pub fn transport_ready(&self) -> bool {
        self.transport_attached
            && self.registered
            && !self.restoring
            && !self.closing
            && !self.closed
            && self.identity_phase == super::identity::Phase::Active
    }
    /// Whether this owner has physically closed, including on a fatal cleanup
    /// failure. Such an owner can never be reattached.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed
    }
    /// Observe the exact retired source before replacing it. The borrowed
    /// metadata contain no payload, key or callback authority. Observation does
    /// not change a historical publication ticket or replenish any credit.
    pub fn transport_loss(&mut self) -> Option<TransportLoss<'_>> {
        if self.loss.view().is_some() {
            self.loss_observed = true;
        }
        self.loss.view()
    }
    /// Adopt a newly connected standard TRANSPORT MQ after observing the old
    /// loss. The same socket, receiver, sender, replay journal and native clock
    /// origin remain in force. Only standard REGISTER and fresh queue SETUPs
    /// are generated; old input, callbacks, payload and MIDs are never replayed.
    pub fn reconnect(&mut self, connection: Connection) -> Result<(), Failure> {
        if self.closed || self.closing || self.identity_phase != super::identity::Phase::Active {
            return Err(Error::Closed.into());
        }
        if self.transport_attached || !self.loss_observed || self.loss.view().is_none() {
            return Err(Error::NotReady.into());
        }
        let generation = self
            .publication_source
            .generation
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        self.next_effect.checked_add(1).ok_or(Error::Overflow)?;
        let frame = frozen(16, |out| transport::register(self.burst.is_some(), out))?;
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
                io_slice_bytes: self.configuration.capacity.io_slice,
            },
        )?;
        let source = Arc::new(PublicationSource::new(
            generation,
            self.publication_owner.clone(),
        ));
        // All fallible preparation precedes the new physical-source commit.
        // The old FIFO/packet owners have already been explicitly retired.
        if !self.effects.is_empty() || self.pending_mq.is_some() || self.effect_bytes != 0 {
            return Err(Error::Stale.into());
        }
        self.io = io;
        self.publication_source = source;
        self.transport_attached = true;
        self.registered = false;
        self.restoring = true;
        self.restore_cursor = 0;
        self.push(frame, Origin::Register)?;
        self.restore_fence = self.next_effect;
        self.loss.clear();
        self.loss_observed = false;
        Ok(())
    }
    pub(super) fn transport_failed(&mut self, original: Option<io::Error>) -> Failure {
        if let Err(cleanup) = self.retire_transport() {
            self.close();
            return Failure::TransportRetirement { original, cleanup };
        }
        match original {
            Some(error) => Failure::Transport(error),
            None => Failure::TransportEof,
        }
    }
    pub(super) fn retire_transport(&mut self) -> Result<(), Error> {
        if self.closed || self.closing || !self.transport_attached {
            return Err(Error::Closed);
        }
        self.loss.begin(
            self.publication_source.generation,
            self.registered,
            self.io.frame().is_some(),
            self.io.read_progress_bytes(),
            self.ack.is_some(),
        )?;
        if let Some(metadata) = self.pending_mq {
            self.loss.push(Retired::Mq(metadata))?;
        }
        for effect in &self.effects {
            self.loss.push(Retired::Mq(EffectMeta::from_frame(
                &effect.frame,
                effect.sequence,
            )?))?;
        }
        if let Some(bytes) = self.io.frame()
            && let Ok(Event::Send {
                qid,
                mid,
                peer,
                message,
            }) = Event::decode(bytes)
        {
            self.loss.push(Retired::IncomingPending {
                qid,
                mid,
                peer,
                bytes: message.len(),
            })?;
        }
        // Native datagrams are still unexposed at this point. Cancellation
        // consumes the original immutable packet and burns its prepared nonce;
        // it never rolls back Sender state or fabricates an old MQ callback.
        for (index, completion) in self.completions.iter().enumerate() {
            let Some(completion) = completion else {
                continue;
            };
            let (target, packet) = self.sockets[index].pending().ok_or(Error::Stale)?;
            if packet.operation() != completion.operation || target != completion.target {
                return Err(Error::Stale);
            }
            let callback = EffectMeta::from_frame(&completion.failure, 1)?
                .callback
                .ok_or(Error::Stale)?;
            self.loss.push(Retired::NativePending {
                operation: completion.operation,
                peer: completion.peer,
                target,
                bytes: packet.bytes().len(),
                qid: callback.qid,
                mid: callback.mid,
            })?;
        }
        if let Some(state) = &self.discovery {
            for (socket, pending) in state.pending.iter().enumerate() {
                if let Some((operation, target)) = pending {
                    self.loss.push(Retired::DiscoveryPending {
                        socket,
                        operation: *operation,
                        target: *target,
                    })?;
                }
            }
        }
        // The loss ledger was completely populated without allocation before
        // any source metadata or packet was dropped.
        self.io.retire();
        self.publication_source.retire();
        self.transport_attached = false;
        self.registered = false;
        self.restoring = false;
        self.restore_cursor = 0;
        self.pending_mq = None;
        self.effects.clear();
        self.effect_bytes = 0;
        for (index, completion) in self.completions.iter_mut().enumerate() {
            if completion.take().is_some() {
                drop(self.sockets[index].cancel_send());
            }
        }
        if let Some(state) = &mut self.discovery {
            state.pending = [None, None];
        }
        for socket in self.sockets.iter_mut().take(self.defaults) {
            socket.cancel_discovery();
        }
        self.transport_lost_burst();
        // The remaining authenticated ACK work keeps its cursor/watermark and
        // already-applied native grants. It cannot release a new source input;
        // unannounced endpoints absorb grants without old-source MQ effects.
        if let Some(work) = &mut self.ack {
            work.release_input = false;
        }
        self.loss_observed = false;
        Ok(())
    }
    pub(super) fn drop_detached_endpoint(&mut self, index: usize) -> Result<Activity, Failure> {
        let mut endpoint = self.endpoints[index].take().ok_or(Error::Stale)?;
        endpoint.sender.close();
        let socket = endpoint.socket;
        if socket >= self.defaults
            && !self
                .endpoints
                .iter()
                .flatten()
                .any(|other| other.socket == socket)
        {
            self.sockets[socket].close();
        }
        Ok(Activity::Retired)
    }
    pub(super) fn expire_detached(&mut self, now: u64) -> Result<Option<Activity>, Failure> {
        let lifetime = self.configuration.transmit.acknowledgement_timeout_us;
        if let Some(index) = self.endpoints.iter().position(|entry| {
            entry.as_ref().is_some_and(|endpoint| {
                endpoint.retiring || now.saturating_sub(endpoint.last_ack) >= lifetime
            })
        }) {
            return self.drop_detached_endpoint(index).map(Some);
        }
        for index in 0..self.peers.len() {
            let expired = self.peers[index].as_ref().is_some_and(|peer| {
                now.saturating_sub(peer.last_rx) >= lifetime
                    && !self
                        .endpoints
                        .iter()
                        .flatten()
                        .any(|endpoint| endpoint.peer == peer.id)
            });
            if expired {
                let mut peer = self.peers[index].take().ok_or(Error::Stale)?;
                peer.receiver.close();
                self.index.retain(|entry| entry.peer != index);
                return Ok(Some(Activity::Retired));
            }
        }
        Ok(None)
    }
    pub(super) fn restore_endpoint(&mut self, now: u64) -> Result<Option<Activity>, Failure> {
        if !self.registered {
            return Ok(None);
        }
        let lifetime = self.configuration.transmit.acknowledgement_timeout_us;
        // Expiration keeps the original target. Previously announced queues
        // require normal DOWN; not-yet-announced endpoints need no new MQ frame.
        if let Some(index) = self.endpoints.iter().position(|entry| {
            entry.as_ref().is_some_and(|endpoint| {
                endpoint.retiring || now.saturating_sub(endpoint.last_ack) >= lifetime
            })
        }) {
            return self.retire_endpoint(index);
        }
        if self.restore_cursor == self.endpoints.len() {
            if self.written_effect >= self.restore_fence {
                self.restoring = false;
                return Ok(Some(Activity::Restored));
            }
            return Ok(None);
        }
        let index = self.restore_cursor;
        let Some(endpoint) = self.endpoints[index].as_ref() else {
            self.restore_cursor += 1;
            return Ok(Some(Activity::Restoring));
        };
        if endpoint.source_generation == self.publication_source.generation {
            self.restore_cursor += 1;
            return Ok(Some(Activity::Restoring));
        }
        let needs_box = endpoint.boxed.is_some() || endpoint.sender.available() != 0;
        let count = 1 + usize::from(needs_box);
        let bytes = count
            .checked_mul(65 + endpoint.address.len())
            .ok_or(Error::Overflow)?;
        if !self.room(count, bytes) {
            return Ok(None);
        }
        let kx = self.next_queue;
        let next = kx
            .checked_add(u32::try_from(count).map_err(|_| Error::Overflow)?)
            .ok_or(Error::Overflow)?;
        let queue = Self::queue_for(endpoint, kx, u64::MAX, false)?;
        let initial = frozen(65 + endpoint.address.len(), |out| {
            queue.setup(endpoint.address.as_bytes(), out)
        })?;
        let boxed = if needs_box {
            let queue = Self::queue_for(
                endpoint,
                kx.checked_add(1).ok_or(Error::Overflow)?,
                endpoint.sender.available(),
                true,
            )?;
            Some(frozen(65 + endpoint.address.len(), |out| {
                queue.setup(endpoint.address.as_bytes(), out)
            })?)
        } else {
            None
        };
        // No native ACK/key/clock state is mutated. The fresh SETUP's q_len is
        // the actual remaining message count, never a previous update delta.
        self.push(initial, Origin::Effect)?;
        if let Some(frame) = boxed {
            self.push(frame, Origin::Effect)?;
        }
        let endpoint = self.endpoints[index].as_mut().ok_or(Error::Stale)?;
        endpoint.source_generation = self.publication_source.generation;
        endpoint.kx = kx;
        endpoint.boxed = (count == 2).then_some(kx + 1);
        self.next_queue = next;
        self.restore_fence = self.next_effect;
        self.restore_cursor += 1;
        Ok(Some(Activity::Restoring))
    }
}
