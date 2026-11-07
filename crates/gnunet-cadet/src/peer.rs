//! Bounded reliable channel endpoints inside an authenticated GNUnet CADET tunnel.
//!
//! This layer consumes/emits the actual plaintext ChannelMessage wire format.
//! Its external tunnel port must authenticate/decrypt before receive and retain
//! each original immutable encryption/CORE attempt until explicit settlement.
//! It performs no KX, ratchet, discovery, CORE IO or invented fragmentation.
use core::{cell::Cell, fmt, ptr};
use gnunet_types::{Error, MonoInstant};
use gnunet_wire::official::cadet_peer::ChannelMessage;

/// Actual bit used by v0.29.1 get_next_free_ctn, distinct from IPC channel IDs.
pub const NUMBER_SIDE_BIT: u32 = 0x0800_0000;
/// Official buffered-channel outstanding-send policy in the pinned service.
pub const DEFAULT_WINDOW: u8 = 4;
/// Distinct borrowed identity for one original channel-owner lifetime.
#[derive(Default)]
pub struct Instance {
    next: Cell<u64>,
    statistics: crate::statistics::Store,
}
impl Instance {
    /// Cumulative channel observations for this entire original domain.
    #[must_use]
    pub fn statistics(&self) -> crate::statistics::Snapshot {
        self.statistics.snapshot()
    }
    /// Reserve identity without allocation or a global counter.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next: Cell::new(0),
            statistics: crate::statistics::Store::new(),
        }
    }
}
#[derive(Clone, Copy)]
struct Brand<'a>(&'a Instance);
impl PartialEq for Brand<'_> {
    fn eq(&self, other: &Self) -> bool {
        ptr::eq(self.0, other.0)
    }
}
impl Eq for Brand<'_> {}
impl fmt::Debug for Brand<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChannelInstance")
    }
}
/// Original logical tunnel/channel source. It grants no cryptographic proof;
/// only the attached authenticated tunnel owner may feed its actual plaintext.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scope<'a> {
    brand: Brand<'a>,
    allocation: u64,
    channel: u32,
}
impl Scope<'_> {
    /// Raw channel number, never sufficient generation authority.
    #[must_use]
    pub const fn wire_id(self) -> u32 {
        self.channel
    }
}
/// One application endpoint's exclusive claim on this actual peer channel.
/// It is Rust-private ownership, never a wire channel number or crypto proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Application<'a> {
    scope: Scope<'a>,
}
impl<'a> Application<'a> {
    /// Original peer-channel source owned by this one application binding.
    #[must_use]
    pub const fn scope(self) -> Scope<'a> {
        self.scope
    }
}
/// Original locally admitted application payload and its non-reused generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Send<'a> {
    scope: Scope<'a>,
    slot: usize,
    serial: u64,
    mid: u32,
}
impl<'a> Send<'a> {
    /// Actual wrapping official message number.
    #[must_use]
    pub const fn mid(self) -> u32 {
        self.mid
    }
    /// Original owner source.
    #[must_use]
    pub const fn scope(self) -> Scope<'a> {
        self.scope
    }
    /// Non-reused original allocation generation, diagnostic outside this scope.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.serial
    }
}
/// Original retained received packet, before or after local application handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Received<'a> {
    scope: Scope<'a>,
    slot: usize,
    serial: u64,
    mid: u32,
}
impl Received<'_> {
    /// Actual wrapping peer message number.
    #[must_use]
    pub const fn mid(self) -> u32 {
        self.mid
    }
}
/// Exactly one original local application handoff, released by receive_done.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Delivery<'a> {
    received: Received<'a>,
    serial: u64,
}
impl<'a> Delivery<'a> {
    /// Original received message, including its slot generation.
    #[must_use]
    pub const fn received(self) -> Received<'a> {
        self.received
    }
}
/// Kind of original channel plaintext submitted to the external tunnel port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptKind {
    /// Outbound opening challenge.
    Open,
    /// Listening port proof.
    OpenAck,
    /// One reliable application packet, possibly a protocol retry.
    Data,
    /// Current selective/cumulative channel receive ACK.
    Ack,
    /// Ordered channel teardown.
    Destroy,
}
/// Exactly one original plaintext/encryption/CORE attempt, never a wire nonce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Attempt<'a> {
    scope: Scope<'a>,
    serial: u64,
    kind: AttemptKind,
    send: Option<Send<'a>>,
}
impl<'a> Attempt<'a> {
    /// Original owner source.
    #[must_use]
    pub const fn scope(self) -> Scope<'a> {
        self.scope
    }
    /// Diagnostic allocation counter, never sent to the remote peer.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.serial
    }
    /// Type of actual original encoded frame.
    #[must_use]
    pub const fn kind(self) -> AttemptKind {
        self.kind
    }
    /// Original application payload when this is a DATA attempt.
    #[must_use]
    pub const fn send(self) -> Option<Send<'a>> {
        self.send
    }
}
/// Actual encoded plaintext borrowed from caller storage. Encrypt and freeze
/// these exact bytes before reusing output; queueing is not physical emission.
pub struct Prepared<'id, 'bytes> {
    attempt: Attempt<'id>,
    bytes: &'bytes [u8],
}
impl<'id, 'bytes> Prepared<'id, 'bytes> {
    /// Original tunnel-port settlement token.
    #[must_use]
    pub const fn attempt(&self) -> Attempt<'id> {
        self.attempt
    }
    /// Complete actual channel plaintext, with no private generation fields.
    #[must_use]
    pub const fn bytes(&self) -> &'bytes [u8] {
        self.bytes
    }
}
/// Explicit encryption/connection boundary for original channel plaintext.
/// Implementations own the real authenticated logical tunnel, immutable queued
/// ciphertext and CORE cursors. No default implementation can claim encryption
/// or emission. The channel owner is driven only by its original progress tokens.
///
/// After a refused reserve/submit and before any physical exposure, the caller
/// may discard_attempt to roll back only that attempt, retaining reliable data.
pub trait TunnelPort<'id> {
    /// Original bounded crypto/native refusal retained by this explicit port.
    type Error;
    /// Reserve final immutable ciphertext/queue capacity without physical IO,
    /// fake KX success, ratchet advancement or application-delivery authority.
    fn reserve(&mut self, source: Scope<'id>, plaintext_bytes: usize) -> Result<(), Self::Error>;
    /// Freeze/encrypt these exact actual channel bytes under this original
    /// attempt. Admission must not report positive output or a peer ACK. Any
    /// irreversible crypto transition follows successful capacity/allocation.
    fn submit(&mut self, attempt: Attempt<'id>, plaintext: &[u8]) -> Result<(), Self::Error>;
}
/// One original prepared attempt's explicit disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Emission {
    /// The original frame actually emitted on this connection.
    Sent {
        /// Actual physical path connection identifier.
        connection: [u8; 32],
    },
    /// Original attempt was retired after actual send failure.
    Failed,
    /// Explicit diagnostic packet loss before any encryption/physical exposure.
    /// This is neither an emission nor a peer acknowledgement.
    Dropped,
}
/// Original attempt disposition, distinct from physical exposure or a peer ACK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Settled<'a> {
    /// Exact original attempt.
    pub attempt: Attempt<'a>,
    /// Actual port result or explicit unexposed diagnostic drop.
    pub emission: Emission,
    /// Whether any original output was actually exposed.
    pub exposed: bool,
}
/// Terminal original-payload result, without remote application-processing claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// Actual authenticated peer channel ACK accepted these bytes.
    /// It may only have buffered them; it does not acknowledge application work.
    PeerAccepted,
    /// Original local work retired before any physical exposure.
    RetiredUnsent,
    /// Original local work retired after exposure, without a peer ACK.
    DeliveryUnknown,
}
/// Actual first-attempt round-trip observation, only for an unambiguous ACK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Latency {
    /// Actual original sent connection.
    pub sent_on: [u8; 32],
    /// Actual authenticated ACK's incoming connection.
    pub ack_on: [u8; 32],
    /// Elapsed canonical monotonic microseconds.
    pub micros: u64,
}
/// Original terminal payload remains in caller storage until release_send.
pub struct Completion<'id, 'bytes> {
    /// Original send generation.
    pub send: Send<'id>,
    /// Actual channel/retirement result.
    pub outcome: Outcome,
    /// Original immutable admitted payload bytes.
    pub payload: &'bytes [u8],
    /// RTT observation only for one successful original emission.
    pub latency: Option<Latency>,
}
/// Preview of an actual buffered next-in-order packet. A native owner performs
/// any fallible copy first, then calls deliver(preview.received) to commit.
pub struct Incoming<'id, 'bytes> {
    /// Original buffer generation, not just its MID.
    pub received: Received<'id>,
    /// Actual complete peer payload, without a copy.
    pub payload: &'bytes [u8],
}
/// Original channel's opening/data/teardown state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Awaiting a correct OPEN_ACK port proof.
    Opening,
    /// Open peer channel; local application handoffs are allowed.
    Ready,
    /// Local teardown requested, awaiting its original emission.
    Closing,
    /// Remote/physical/local retirement; terminal payloads still drain.
    Closed,
}
/// Fixed channel configuration and local timer policy; no private wire flags.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// At most the pinned service's four outstanding sends.
    pub window: u8,
    /// Maximum complete APP_DATA payload, at most 64348 bytes.
    pub payload_bytes: usize,
    /// Initial retry delay in monotonic microseconds.
    pub retry_micros: u64,
    /// Maximum exponential retry delay, at least retry_micros.
    pub maximum_retry_micros: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            window: DEFAULT_WINDOW,
            payload_bytes: 64348,
            retry_micros: 250_000,
            maximum_retry_micros: 900_000_000,
        }
    }
}
/// Explicit local/remote identities and raw application port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Address {
    /// Actual tunnel channel number.
    pub channel: u32,
    /// Local peer identity.
    pub local_peer: [u8; 32],
    /// Remote authenticated tunnel identity.
    pub remote_peer: [u8; 32],
    /// Actual application listening port hash.
    pub port: [u8; 64],
}
/// Compute official SHA512(port || listener identity), without an invented domain.
#[must_use]
pub fn hash_port(port: &[u8; 64], listener: &[u8; 32]) -> [u8; 64] {
    gnunet_crypto::hash512_parts(&[port, listener])
}
/// Non-reusing allocator matching the pinned implementation's 0x08000000 split.
/// Keep it with its original logical tunnel; do not reset it after path loss.
pub struct Numbers {
    next: Option<u32>,
    side: u32,
}
impl Numbers {
    /// Select this actual peer pair's official channel number side.
    pub fn new(local: &[u8; 32], remote: &[u8; 32]) -> Result<Self, Error> {
        if local == remote {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            next: Some(0),
            side: if local > remote { NUMBER_SIDE_BIT } else { 0 },
        })
    }
    /// Reserve another original wire number. Exhaustion refuses instead of reuse.
    pub fn allocate(&mut self) -> Result<u32, Error> {
        let next = self.next.ok_or(Error::Capacity)?;
        self.next = if next == NUMBER_SIDE_BIT - 1 {
            None
        } else {
            Some(next + 1)
        };
        Ok(next | self.side)
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum SendState {
    Outstanding,
    Accepted,
    Retired,
}
#[derive(Clone, Copy)]
struct SendRecord {
    serial: u64,
    mid: u32,
    length: usize,
    state: SendState,
    exposed: bool,
    emissions: u32,
    failed: bool,
    first: Option<(MonoInstant, [u8; 32])>,
    ack: Option<(MonoInstant, [u8; 32])>,
    retry_at: MonoInstant,
    delay: u64,
}
/// One caller-provided fixed send buffer; data is copied before admission.
pub struct SendSlot<'bytes> {
    bytes: &'bytes mut [u8],
    record: Option<SendRecord>,
}
impl<'bytes> SendSlot<'bytes> {
    /// Wrap empty caller storage without allocation.
    #[must_use]
    pub fn new(bytes: &'bytes mut [u8]) -> Self {
        Self {
            bytes,
            record: None,
        }
    }
}
#[derive(Clone, Copy)]
struct ReceiveRecord {
    serial: u64,
    mid: u32,
    length: usize,
    delivered: bool,
}
/// One caller-provided fixed out-of-order/application delivery buffer.
pub struct ReceiveSlot<'bytes> {
    bytes: &'bytes mut [u8],
    record: Option<ReceiveRecord>,
}
impl<'bytes> ReceiveSlot<'bytes> {
    /// Wrap empty caller storage without allocation.
    #[must_use]
    pub fn new(bytes: &'bytes mut [u8]) -> Self {
        Self {
            bytes,
            record: None,
        }
    }
}
#[derive(Clone, Copy)]
struct Pending<'id> {
    attempt: Attempt<'id>,
    exposed: bool,
    ack_revision: u64,
}
/// Actual disposition of one authenticated incoming channel message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event<'a> {
    /// Correct peer port proof opened the original initiator.
    Opened,
    /// Duplicate OPEN scheduled another original port proof if needed.
    DuplicateOpen,
    /// Actual received payload is retained in caller storage.
    Buffered(Received<'a>),
    /// Already received or outside current bounded window.
    Dropped,
    /// Actual ACK newly accepted this many original retained sends.
    Acknowledged {
        /// Number of original outstanding sends accepted by this ACK.
        sends: usize,
    },
    /// Actual remote teardown; pending physical attempts must settle.
    Destroyed {
        /// Original pending port attempt, if any; never a new authority.
        pending: Option<Attempt<'a>>,
    },
    /// Data/ACK after retirement needs a real DESTROY reply.
    NeedDestroy,
    /// Unrelated/duplicate/invalid-direction control changed nothing.
    Ignored,
}

/// One actual reliable channel inside its original authenticated logical tunnel.
/// Payload buffers, original physical attempt completion and application delivery
/// are separate bounded lifetimes; no background scheduler or hidden allocation.
/// Original exclusive caller storage package, returned only after the channel
/// and every original payload/physical attempt have actually retired.
pub struct Buffers<'slots, 'bytes> {
    /// Fixed send metadata and its exclusively borrowed shared-slab buffers.
    pub sends: &'slots mut [SendSlot<'bytes>],
    /// Fixed receive metadata and its exclusively borrowed shared-slab buffers.
    pub receives: &'slots mut [ReceiveSlot<'bytes>],
}

impl Buffers<'_, '_> {
    /// Validate an empty Node slab package before any owner or backend admission.
    pub fn validate(&self, limits: Limits) -> Result<(), Error> {
        if self.sends.len() < usize::from(limits.window)
            || self.receives.is_empty()
            || self.sends.iter().any(|s| s.record.is_some())
            || self.receives.iter().any(|s| s.record.is_some())
        {
            return Err(Error::Capacity);
        }
        if self
            .sends
            .iter()
            .take(usize::from(limits.window))
            .any(|s| s.bytes.len() < limits.payload_bytes)
            || self
                .receives
                .iter()
                .map(|s| s.bytes.len())
                .max()
                .unwrap_or(0)
                < limits.payload_bytes
        {
            return Err(Error::TooLarge);
        }
        Ok(())
    }
}
/// One original bounded reliable channel endpoint; its scope uses a checked
/// allocation in a stable caller domain, never a dynamic owner address.
pub struct ChannelOwner<'id, 'slots, 'bytes> {
    scope: Scope<'id>,
    address: Address,
    listener: bool,
    application_claimed: bool,
    application_used: bool,
    challenge: [u8; 64],
    phase: Phase,
    limits: Limits,
    sends: &'slots mut [SendSlot<'bytes>],
    receives: &'slots mut [ReceiveSlot<'bytes>],
    next_send: u32,
    next_receive: u32,
    serial: u64,
    attempt_serial: u64,
    delivery_serial: u64,
    delivery: Option<Delivery<'id>>,
    pending: Option<Pending<'id>>,
    ack_revision: u64,
    ack_finished: u64,
    open_ack_due: bool,
    open_retry: MonoInstant,
    open_delay: u64,
    destroy_due: bool,
    last_now: MonoInstant,
}
impl<'id, 'slots, 'bytes> ChannelOwner<'id, 'slots, 'bytes> {
    /// Create an outbound reliable channel. It emits real OPEN until a correct
    /// raw-port proof arrives. Caller supplies a channel from its tunnel Numbers.
    pub fn outbound(
        instance: &'id Instance,
        address: Address,
        sends: &'slots mut [SendSlot<'bytes>],
        receives: &'slots mut [ReceiveSlot<'bytes>],
        now: MonoInstant,
        limits: Limits,
    ) -> Result<Self, Error> {
        Self::new(instance, address, sends, receives, now, limits, false, None)
    }
    /// Bind an actual incoming OPEN to a real known local port. The challenge is
    /// verified before the endpoint can emit OPEN_ACK or expose application data.
    pub fn incoming(
        instance: &'id Instance,
        address: Address,
        challenge: [u8; 64],
        sends: &'slots mut [SendSlot<'bytes>],
        receives: &'slots mut [ReceiveSlot<'bytes>],
        now: MonoInstant,
        limits: Limits,
    ) -> Result<Self, Error> {
        Self::new(
            instance,
            address,
            sends,
            receives,
            now,
            limits,
            true,
            Some(challenge),
        )
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Explicit slice convenience delegates actual bounded package admission without hidden owners"
    )]
    fn new(
        instance: &'id Instance,
        address: Address,
        sends: &'slots mut [SendSlot<'bytes>],
        receives: &'slots mut [ReceiveSlot<'bytes>],
        now: MonoInstant,
        limits: Limits,
        _listener: bool,
        expected: Option<[u8; 64]>,
    ) -> Result<Self, Error> {
        Self::allocate(
            instance,
            address,
            Buffers { sends, receives },
            expected,
            now,
            limits,
        )
        .map_err(|r| r.reason)
    }
    /// Admit an actual outgoing endpoint (None) or authenticated incoming OPEN
    /// challenge (Some), returning the original whole slab package on refusal.
    pub fn allocate(
        instance: &'id Instance,
        address: Address,
        buffers: Buffers<'slots, 'bytes>,
        incoming: Option<[u8; 64]>,
        now: MonoInstant,
        limits: Limits,
    ) -> Result<Self, gnunet_types::Rejected<Buffers<'slots, 'bytes>>> {
        let checked = (|| {
            if !(1..=DEFAULT_WINDOW).contains(&limits.window)
                || limits.payload_bytes > 64348
                || limits.retry_micros == 0
                || limits.maximum_retry_micros < limits.retry_micros
                || buffers.sends.len() < usize::from(limits.window)
                || buffers.receives.is_empty()
                || address.local_peer == address.remote_peer
            {
                return Err(Error::InvalidInput);
            }
            if buffers.sends.iter().any(|s| s.record.is_some())
                || buffers.receives.iter().any(|s| s.record.is_some())
            {
                return Err(Error::Conflict);
            }
            let listener = incoming.is_some();
            let challenge = hash_port(
                &address.port,
                if listener {
                    &address.local_peer
                } else {
                    &address.remote_peer
                },
            );
            if incoming.is_some_and(|expected| expected != challenge) {
                return Err(Error::Authentication);
            }
            let allocation = instance.next.get().checked_add(1).ok_or(Error::Overflow)?;
            Ok((listener, challenge, allocation))
        })();
        let (listener, challenge, allocation) = match checked {
            Ok(v) => v,
            Err(reason) => {
                return Err(gnunet_types::Rejected {
                    value: buffers,
                    reason,
                });
            }
        };
        instance.next.set(allocation);
        Ok(Self {
            scope: Scope {
                brand: Brand(instance),
                allocation,
                channel: address.channel,
            },
            address,
            listener,
            application_claimed: false,
            application_used: false,
            challenge,
            phase: if listener {
                Phase::Ready
            } else {
                Phase::Opening
            },
            limits,
            sends: buffers.sends,
            receives: buffers.receives,
            next_send: 0,
            next_receive: 1,
            serial: 0,
            attempt_serial: 0,
            delivery_serial: 0,
            delivery: None,
            pending: None,
            ack_revision: 0,
            ack_finished: 0,
            open_ack_due: listener,
            open_retry: now,
            open_delay: limits.retry_micros,
            destroy_due: false,
            last_now: now,
        })
    }
    /// Exact original channel identity; numeric wire equality is insufficient.
    #[must_use]
    pub const fn scope(&self) -> Scope<'id> {
        self.scope
    }
    /// Actual local/remote/port identity bound at construction.
    #[must_use]
    pub const fn address(&self) -> Address {
        self.address
    }
    /// Current opening/data/retirement phase.
    #[must_use]
    pub const fn phase(&self) -> Phase {
        self.phase
    }
    /// Whether this is the actual incoming/listening endpoint of the channel.
    #[must_use]
    pub const fn is_listener(&self) -> bool {
        self.listener
    }
    /// Bind one real local application to a ready channel at most once. Early
    /// peer packets may already be buffered, but no prior application send or
    /// local payload handoff may be reassigned to another application.
    pub fn claim_application(&mut self) -> Result<Application<'id>, Error> {
        if self.phase != Phase::Ready {
            return Err(Error::NotReady);
        }
        if self.application_claimed || self.application_used {
            return Err(Error::Conflict);
        }
        self.application_claimed = true;
        Ok(Application { scope: self.scope })
    }
    /// Check an original application's exact claim, including after retirement.
    #[must_use]
    pub fn application_matches(&self, application: Application<'id>) -> bool {
        self.application_claimed && application.scope == self.scope
    }
    /// Largest complete payload this actual fixed send storage can ever admit.
    #[must_use]
    pub fn send_capacity(&self) -> usize {
        self.sends
            .iter()
            .map(|slot| slot.bytes.len())
            .max()
            .unwrap_or(0)
            .min(self.limits.payload_bytes)
    }
    /// Borrow the exact original admitted bytes; stale/foreign send tokens refuse.
    pub fn send_payload(&self, send: Send<'id>) -> Result<&[u8], Error> {
        let record = self.send_record(send)?;
        Ok(&self.sends[send.slot].bytes[..record.length])
    }
    /// Original attempt that must finish or retire on its actual external owner.
    #[must_use]
    pub const fn pending(&self) -> Option<Attempt<'id>> {
        match self.pending {
            Some(pending) => Some(pending.attempt),
            None => None,
        }
    }
    fn time(&mut self, now: MonoInstant) -> Result<(), Error> {
        if now < self.last_now {
            return Err(Error::TimeUncertain);
        }
        self.last_now = now;
        Ok(())
    }
    fn send_record(&self, send: Send<'id>) -> Result<&SendRecord, Error> {
        if send.scope != self.scope {
            return Err(Error::StaleGeneration);
        }
        self.sends
            .get(send.slot)
            .and_then(|slot| slot.record.as_ref())
            .filter(|record| record.serial == send.serial && record.mid == send.mid)
            .ok_or(Error::StaleGeneration)
    }
    fn receive_record(&self, received: Received<'id>) -> Result<&ReceiveRecord, Error> {
        if received.scope != self.scope {
            return Err(Error::StaleGeneration);
        }
        self.receives
            .get(received.slot)
            .and_then(|slot| slot.record.as_ref())
            .filter(|record| record.serial == received.serial && record.mid == received.mid)
            .ok_or(Error::StaleGeneration)
    }
    fn send_id(&self, slot: usize, record: SendRecord) -> Send<'id> {
        Send {
            scope: self.scope,
            slot,
            serial: record.serial,
            mid: record.mid,
        }
    }
    fn receive_id(&self, slot: usize, record: ReceiveRecord) -> Received<'id> {
        Received {
            scope: self.scope,
            slot,
            serial: record.serial,
            mid: record.mid,
        }
    }
    /// Free local original send slots, capped by the actual reliable window.
    #[must_use]
    pub fn available_send(&self) -> usize {
        if self.phase != Phase::Ready {
            return 0;
        }
        let pending = self
            .sends
            .iter()
            .filter(|slot| {
                slot.record
                    .is_some_and(|record| record.state == SendState::Outstanding)
            })
            .count();
        let free = self
            .sends
            .iter()
            .filter(|slot| slot.record.is_none())
            .count();
        free.min(usize::from(self.limits.window).saturating_sub(pending))
    }
    /// Copy one complete APP_DATA payload before committing a send generation.
    /// No physical emission or peer acceptance is inferred by this admission.
    pub fn queue_send(&mut self, payload: &[u8], now: MonoInstant) -> Result<Send<'id>, Error> {
        self.time(now)?;
        if self.phase != Phase::Ready {
            return Err(Error::NotReady);
        }
        if self.available_send() == 0 {
            return Err(Error::WouldBlock);
        }
        if payload.len() > self.limits.payload_bytes {
            return Err(Error::Capacity);
        }
        let slot = self
            .sends
            .iter()
            .position(|slot| slot.record.is_none() && slot.bytes.len() >= payload.len())
            .ok_or(Error::Capacity)?;
        let serial = self.serial.checked_add(1).ok_or(Error::Overflow)?;
        let mid = self.next_send.wrapping_add(1);
        let record = SendRecord {
            serial,
            mid,
            length: payload.len(),
            state: SendState::Outstanding,
            exposed: false,
            emissions: 0,
            failed: false,
            first: None,
            ack: None,
            retry_at: now,
            delay: self.limits.retry_micros,
        };
        self.sends[slot].bytes[..payload.len()].copy_from_slice(payload);
        self.sends[slot].record = Some(record);
        self.application_used = true;
        self.serial = serial;
        self.next_send = mid;
        Ok(self.send_id(slot, record))
    }
    /// Effective local receive-payload policy, capped by the largest fixed
    /// receive buffer. A larger expected-base packet returns TooLarge, a
    /// permanent local limit rather than retryable temporary buffer pressure.
    #[must_use]
    pub fn receive_capacity(&self) -> usize {
        self.receives
            .iter()
            .map(|slot| slot.bytes.len())
            .max()
            .unwrap_or(0)
            .min(self.limits.payload_bytes)
    }
    fn futures(&self) -> u64 {
        self.receives
            .iter()
            .filter_map(|slot| slot.record)
            .filter(|record| !record.delivered)
            .fold(0, |bits, record| {
                let delta = record.mid.wrapping_sub(self.next_receive).wrapping_sub(1);
                if delta < 64 {
                    bits | (1_u64 << delta)
                } else {
                    bits
                }
            })
    }
    /// Current truthful cumulative/selective ACK snapshot. Base itself is missing;
    /// futures bit0 means base+1. Only retained original receive buffers set bits.
    #[must_use]
    pub fn ack(&self) -> (u32, u64) {
        (self.next_receive, self.futures())
    }
    /// Preview the next real in-order payload, before any fallible native copy.
    #[must_use]
    pub fn peek_delivery(&self) -> Option<Incoming<'id, '_>> {
        if self.phase != Phase::Ready || self.delivery.is_some() {
            return None;
        }
        self.receives.iter().enumerate().find_map(|(slot, buffer)| {
            buffer
                .record
                .filter(|record| !record.delivered && record.mid == self.next_receive)
                .map(|record| Incoming {
                    received: self.receive_id(slot, record),
                    payload: &buffer.bytes[..record.length],
                })
        })
    }
    /// Commit actual local application handoff only after any required copy.
    /// This advances channel ACK base; it does not imply application processing.
    pub fn deliver(&mut self, received: Received<'id>) -> Result<Delivery<'id>, Error> {
        let record = *self.receive_record(received)?;
        if record.delivered || record.mid != self.next_receive {
            return Err(Error::StaleGeneration);
        }
        if self.phase != Phase::Ready || self.delivery.is_some() {
            return Err(Error::WouldBlock);
        }
        let serial = self.delivery_serial.checked_add(1).ok_or(Error::Overflow)?;
        let revision = self.ack_revision.checked_add(1).ok_or(Error::Overflow)?;
        self.receives[received.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .delivered = true;
        self.application_used = true;
        self.next_receive = self.next_receive.wrapping_add(1);
        self.ack_revision = revision;
        self.delivery_serial = serial;
        let delivery = Delivery { received, serial };
        self.delivery = Some(delivery);
        Ok(delivery)
    }
    /// Release exactly the original application handoff, making the next retained
    /// in-order payload eligible. No ACK for an unhanded payload is invented.
    pub fn receive_done(&mut self, delivery: Delivery<'id>) -> Result<(), Error> {
        if self.delivery != Some(delivery) || self.phase != Phase::Ready {
            return Err(Error::StaleGeneration);
        }
        let record = *self.receive_record(delivery.received)?;
        self.receives[delivery.received.slot].bytes[..record.length].fill(0);
        self.receives[delivery.received.slot].record = None;
        self.delivery = None;
        Ok(())
    }
    /// Observe only an original DATA which the native owner has now actually
    /// discarded after this channel refused receive capacity. Refusal/retry alone
    /// must not call this diagnostic hook; no ACK or delivery is implied.
    pub fn discarded_receive_capacity(&self, source: Scope<'id>, message: ChannelMessage<'_>) {
        if source != self.scope {
            return;
        }
        if let ChannelMessage::Data { channel, .. } = message
            && channel == self.scope.channel
        {
            self.scope
                .brand
                .0
                .statistics
                .add(crate::statistics::Metric::SlowClient, 1);
        }
    }
    /// Feed only plaintext authenticated by the actual original logical tunnel.
    /// Capacity refusal retains no new payload and acknowledges no unowned bytes.
    pub fn receive(
        &mut self,
        source: Scope<'id>,
        message: ChannelMessage<'_>,
        connection: [u8; 32],
        now: MonoInstant,
    ) -> Result<Event<'id>, Error> {
        if source != self.scope {
            return Err(Error::StaleGeneration);
        }
        self.time(now)?;
        let channel = match message {
            ChannelMessage::Open { channel, .. }
            | ChannelMessage::OpenAck { channel, .. }
            | ChannelMessage::Destroy { channel, .. }
            | ChannelMessage::Data { channel, .. }
            | ChannelMessage::DataAck { channel, .. } => channel,
            ChannelMessage::KeepAlive => return Ok(Event::Ignored),
        };
        if channel != self.scope.channel {
            return Err(Error::StaleGeneration);
        }
        match message {
            ChannelMessage::Open { .. } => {
                if self.listener && self.phase == Phase::Ready {
                    if self
                        .pending
                        .is_none_or(|pending| pending.attempt.kind != AttemptKind::OpenAck)
                    {
                        self.open_ack_due = true;
                    }
                    Ok(Event::DuplicateOpen)
                } else {
                    Ok(Event::Ignored)
                }
            }
            ChannelMessage::OpenAck { port, .. } => {
                if !self.listener && self.phase == Phase::Ready && port == self.address.port {
                    self.scope
                        .brand
                        .0
                        .statistics
                        .add(crate::statistics::Metric::DuplicateCreateAck, 1);
                }
                if self.listener || self.phase != Phase::Opening || port != self.address.port {
                    return Ok(Event::Ignored);
                }
                self.phase = Phase::Ready;
                Ok(Event::Opened)
            }
            ChannelMessage::Destroy { .. } => {
                self.retire_records();
                Ok(Event::Destroyed {
                    pending: self.pending(),
                })
            }
            ChannelMessage::Data { mid, payload, .. } => {
                if matches!(self.phase, Phase::Closing | Phase::Closed) {
                    self.destroy_due = true;
                    return Ok(Event::NeedDestroy);
                }
                let revision = self.ack_revision.checked_add(1).ok_or(Error::Overflow)?;
                if mid.wrapping_sub(self.next_receive) > u32::from(self.limits.window) {
                    self.scope
                        .brand
                        .0
                        .statistics
                        .add(crate::statistics::Metric::DuplicateDataWindow, 1);
                    self.ack_revision = revision;
                    return Ok(Event::Dropped);
                }
                if self
                    .receives
                    .iter()
                    .any(|slot| slot.record.is_some_and(|record| record.mid == mid))
                {
                    self.scope
                        .brand
                        .0
                        .statistics
                        .add(crate::statistics::Metric::DuplicateData, 1);
                    self.ack_revision = revision;
                    return Ok(Event::Dropped);
                }
                if payload.len() > self.receive_capacity() {
                    if mid != self.next_receive {
                        self.ack_revision = revision;
                        return Ok(Event::Dropped);
                    }
                    return Err(Error::TooLarge);
                }
                // One fixed largest receive slot is reserved for in-order
                // base packets. A future packet must never occupy it, even
                // when the current base is held in a smaller slot: after that
                // handoff the next missing base may need the largest capacity.
                // A prior in-order handoff can temporarily occupy the reserve;
                // receive_done eventually releases it, so future storage cannot
                // permanently block an admissible missing-base packet.
                let reserved = if mid != self.next_receive {
                    self.receives
                        .iter()
                        .enumerate()
                        .max_by_key(|(_, slot)| slot.bytes.len())
                        .map(|(index, _)| index)
                } else {
                    None
                };
                let available = self.receives.iter().enumerate().position(|(index, slot)| {
                    Some(index) != reserved
                        && slot.record.is_none()
                        && slot.bytes.len() >= payload.len()
                });
                let Some(slot) = available else {
                    if mid != self.next_receive {
                        self.scope
                            .brand
                            .0
                            .statistics
                            .add(crate::statistics::Metric::SlowClient, 1);
                        // Consume/drop this future packet so a containing stream
                        // can continue to the missing base behind it. No new
                        // receive bit is set for bytes we did not retain.
                        self.ack_revision = revision;
                        return Ok(Event::Dropped);
                    }
                    return Err(Error::Capacity);
                };
                let serial = self.serial.checked_add(1).ok_or(Error::Overflow)?;
                let record = ReceiveRecord {
                    serial,
                    mid,
                    length: payload.len(),
                    delivered: false,
                };
                self.receives[slot].bytes[..payload.len()].copy_from_slice(payload);
                self.receives[slot].record = Some(record);
                self.serial = serial;
                self.ack_revision = revision;
                Ok(Event::Buffered(self.receive_id(slot, record)))
            }
            ChannelMessage::DataAck { mid, futures, .. } => {
                let mut accepted = 0;
                for slot in self.sends.iter_mut() {
                    if let Some(record) = slot.record.as_mut() {
                        if record.state != SendState::Outstanding || !record.exposed {
                            continue;
                        }
                        let delta = record.mid.wrapping_sub(mid);
                        let bit = delta.wrapping_sub(1);
                        // A cumulative ACK covers every serially older MID,
                        // including one held across many lost ACK snapshots.
                        // Exactly half the u32 space is ambiguous and excluded.
                        let past = mid.wrapping_sub(record.mid);
                        if (past != 0 && past < (1_u32 << 31))
                            || (bit < 64 && futures & (1_u64 << bit) != 0)
                        {
                            record.state = SendState::Accepted;
                            record.ack = Some((now, connection));
                            accepted += 1;
                        }
                    }
                }
                if accepted == 0 {
                    self.scope
                        .brand
                        .0
                        .statistics
                        .add(crate::statistics::Metric::DuplicateDataAck, 1);
                }
                Ok(Event::Acknowledged { sends: accepted })
            }
            ChannelMessage::KeepAlive => Ok(Event::Ignored),
        }
    }
    /// Encode one actual due control/reliable-data packet. The external tunnel
    /// port must retain its exact bytes/token before actual original emission.
    pub fn prepare_next<'output>(
        &mut self,
        now: MonoInstant,
        output: &'output mut [u8],
    ) -> Result<Option<Prepared<'id, 'output>>, Error> {
        self.time(now)?;
        if self.pending.is_some() {
            return Err(Error::WouldBlock);
        }
        let mut send = None;
        let (kind, message) = if self.destroy_due {
            (
                AttemptKind::Destroy,
                ChannelMessage::Destroy {
                    reserved: 0,
                    channel: self.scope.channel,
                },
            )
        } else if self.open_ack_due && self.phase == Phase::Ready {
            (
                AttemptKind::OpenAck,
                ChannelMessage::OpenAck {
                    reserved: 0,
                    channel: self.scope.channel,
                    port: self.address.port,
                },
            )
        } else if self.ack_revision != self.ack_finished
            && matches!(self.phase, Phase::Ready | Phase::Opening)
        {
            let (mid, futures) = self.ack();
            (
                AttemptKind::Ack,
                ChannelMessage::DataAck {
                    channel: self.scope.channel,
                    futures,
                    mid,
                },
            )
        } else if self.phase == Phase::Opening && now >= self.open_retry {
            (
                AttemptKind::Open,
                ChannelMessage::Open {
                    options_bytes: [2, 0, 0, 0],
                    h_port: self.challenge,
                    channel: self.scope.channel,
                },
            )
        } else if self.phase == Phase::Ready {
            let Some((slot, record)) = self
                .sends
                .iter()
                .enumerate()
                .filter_map(|(slot, buffer)| {
                    buffer
                        .record
                        .filter(|record| {
                            record.state == SendState::Outstanding && record.retry_at <= now
                        })
                        .map(|record| (slot, record))
                })
                .min_by_key(|(_, record)| (record.retry_at, record.serial))
            else {
                return Ok(None);
            };
            send = Some(self.send_id(slot, record));
            (
                AttemptKind::Data,
                ChannelMessage::Data {
                    mid: record.mid,
                    channel: self.scope.channel,
                    payload: &self.sends[slot].bytes[..record.length],
                },
            )
        } else {
            return Ok(None);
        };
        let serial = self.attempt_serial.checked_add(1).ok_or(Error::Overflow)?;
        let length = message.encode(output)?;
        let attempt = Attempt {
            scope: self.scope,
            serial,
            kind,
            send,
        };
        self.pending = Some(Pending {
            attempt,
            exposed: false,
            ack_revision: self.ack_revision,
        });
        self.attempt_serial = serial;
        Ok(Some(Prepared {
            attempt,
            bytes: &output[..length],
        }))
    }
    /// Record only actual first physical exposure of the original external
    /// encrypted attempt. Merely preparing/encrypting/queueing must not call it.
    pub fn exposed(&mut self, attempt: Attempt<'id>) -> Result<(), Error> {
        let pending = self
            .pending
            .as_mut()
            .filter(|pending| pending.attempt == attempt)
            .ok_or(Error::StaleGeneration)?;
        pending.exposed = true;
        if let Some(send) = attempt.send {
            self.send_record(send)?;
            self.sends[send.slot]
                .record
                .as_mut()
                .ok_or(Error::StaleGeneration)?
                .exposed = true;
        }
        Ok(())
    }
    /// Settle the original attempt after actual emission/retirement or explicit
    /// unexposed diagnostic loss. Reliable retries keep the same MID/plaintext.
    pub fn settle(
        &mut self,
        attempt: Attempt<'id>,
        emission: Emission,
        now: MonoInstant,
    ) -> Result<Settled<'id>, Error> {
        let pending = self
            .pending
            .filter(|pending| pending.attempt == attempt)
            .ok_or(Error::StaleGeneration)?;
        if matches!(emission, Emission::Sent { .. }) && !pending.exposed {
            return Err(Error::NotReady);
        }
        if emission == Emission::Dropped && pending.exposed {
            return Err(Error::OutcomeUnknown);
        }
        self.time(now)?;
        match attempt.kind {
            AttemptKind::Data => {
                let send = attempt.send.ok_or(Error::StaleGeneration)?;
                self.send_record(send)?;
                let record = self.sends[send.slot]
                    .record
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?;
                match emission {
                    Emission::Sent { connection } => {
                        record.emissions = record.emissions.saturating_add(1);
                        if record.first.is_none() {
                            record.first = Some((now, connection));
                        }
                    }
                    Emission::Failed | Emission::Dropped => record.failed = true,
                }
                record.retry_at = MonoInstant(now.0.saturating_add(record.delay.max(75_000)));
                record.delay = record
                    .delay
                    .saturating_mul(2)
                    .min(self.limits.maximum_retry_micros);
            }
            AttemptKind::Open => {
                self.open_retry = MonoInstant(now.0.saturating_add(self.open_delay));
                self.open_delay = self
                    .open_delay
                    .saturating_mul(2)
                    .min(self.limits.maximum_retry_micros);
            }
            AttemptKind::OpenAck => {
                if matches!(emission, Emission::Sent { .. } | Emission::Dropped) {
                    self.open_ack_due = false;
                }
            }
            AttemptKind::Ack => {
                if matches!(emission, Emission::Sent { .. } | Emission::Dropped) {
                    self.ack_finished = pending.ack_revision;
                }
            }
            AttemptKind::Destroy => {
                if matches!(emission, Emission::Sent { .. } | Emission::Dropped) {
                    self.destroy_due = false;
                    self.phase = Phase::Closed;
                }
            }
        }
        self.pending = None;
        Ok(Settled {
            attempt,
            emission,
            exposed: pending.exposed,
        })
    }
    /// Remove only an actual known-unexposed original attempt after the external
    /// port has removed its immutable bytes. Payload admission is retained.
    pub fn discard_attempt(&mut self, attempt: Attempt<'id>) -> Result<(), Error> {
        let pending = self
            .pending
            .filter(|pending| pending.attempt == attempt)
            .ok_or(Error::StaleGeneration)?;
        if pending.exposed {
            return Err(Error::OutcomeUnknown);
        }
        self.pending = None;
        Ok(())
    }
    /// Borrow the actual current terminal result for one exact original send.
    /// This reads owner state; callers cannot substitute a public Completion.
    pub fn completion_for(&self, send: Send<'id>) -> Result<Completion<'id, '_>, Error> {
        let record = *self.send_record(send)?;
        if record.state == SendState::Outstanding
            || self
                .pending
                .is_some_and(|pending| pending.attempt.send == Some(send))
        {
            return Err(Error::WouldBlock);
        }
        let outcome = if record.state == SendState::Accepted {
            Outcome::PeerAccepted
        } else if record.exposed {
            Outcome::DeliveryUnknown
        } else {
            Outcome::RetiredUnsent
        };
        let latency = match (record.first, record.ack) {
            (Some((start, sent_on)), Some((end, ack_on)))
                if record.emissions == 1 && !record.failed =>
            {
                Some(Latency {
                    sent_on,
                    ack_on,
                    micros: end.0.saturating_sub(start.0),
                })
            }
            _ => None,
        };
        Ok(Completion {
            send,
            outcome,
            payload: &self.sends[send.slot].bytes[..record.length],
            latency,
        })
    }
    /// Borrow one terminal original result only after any matching physical
    /// attempt settled. Caller releases its exact send token after observation.
    #[must_use]
    pub fn completion(&self) -> Option<Completion<'id, '_>> {
        self.sends.iter().enumerate().find_map(|(slot, buffer)| {
            buffer
                .record
                .and_then(|record| self.completion_for(self.send_id(slot, record)).ok())
        })
    }
    /// Wipe/free only the exact original observed terminal send buffer.
    pub fn release_send(&mut self, send: Send<'id>) -> Result<(), Error> {
        let record = *self.send_record(send)?;
        if record.state == SendState::Outstanding
            || self
                .pending
                .is_some_and(|pending| pending.attempt.send == Some(send))
        {
            return Err(Error::WouldBlock);
        }
        self.sends[send.slot].bytes[..record.length].fill(0);
        self.sends[send.slot].record = None;
        Ok(())
    }
    fn retire_records(&mut self) {
        self.phase = Phase::Closed;
        self.destroy_due = false;
        self.open_ack_due = false;
        self.ack_finished = self.ack_revision;
        self.delivery = None;
        for slot in self.receives.iter_mut() {
            if let Some(record) = slot.record.take() {
                slot.bytes[..record.length].fill(0);
            }
        }
        for slot in self.sends.iter_mut() {
            if let Some(record) = slot.record.as_mut()
                && record.state == SendState::Outstanding
            {
                record.state = SendState::Retired;
            }
        }
    }
    /// Request local teardown after settling/removing the original pending
    /// physical attempt. Original unacknowledged payload outcomes stay observable.
    pub fn close(&mut self) -> Result<(), Error> {
        if self.pending.is_some() {
            return Err(Error::WouldBlock);
        }
        self.retire_records();
        self.phase = Phase::Closing;
        self.destroy_due = true;
        Ok(())
    }
    /// Retire an actual authenticated tunnel only after its original port has
    /// stopped every immutable attempt. Nothing is replayed onto a new owner.
    pub fn retire(&mut self) -> Result<(), Error> {
        if self.pending.is_some() {
            return Err(Error::WouldBlock);
        }
        self.retire_records();
        self.destroy_due = false;
        Ok(())
    }
    /// Return the exact slab package only after actual close, no pending
    /// original attempt and all terminal payloads/deliveries were released.
    #[expect(
        clippy::result_large_err,
        reason = "Return the original bounded peer owner on refused pool return without allocation or lost retirement authority"
    )]
    pub fn into_buffers(mut self) -> Result<Buffers<'slots, 'bytes>, gnunet_types::Rejected<Self>> {
        if self.phase != Phase::Closed
            || self.pending.is_some()
            || self.delivery.is_some()
            || self.sends.iter().any(|s| s.record.is_some())
            || self.receives.iter().any(|s| s.record.is_some())
        {
            return Err(gnunet_types::Rejected {
                value: self,
                reason: Error::WouldBlock,
            });
        }
        Ok(Buffers {
            sends: core::mem::take(&mut self.sends),
            receives: core::mem::take(&mut self.receives),
        })
    }
    /// Next due retry/control time, using only caller's canonical monotonic time.
    #[must_use]
    pub fn next_wakeup(&self) -> Option<MonoInstant> {
        if self.pending.is_some() {
            return None;
        }
        if self.destroy_due
            || (self.open_ack_due && self.phase == Phase::Ready)
            || (self.ack_revision != self.ack_finished
                && matches!(self.phase, Phase::Opening | Phase::Ready))
        {
            return Some(self.last_now);
        }
        match self.phase {
            Phase::Opening => Some(self.open_retry),
            Phase::Ready => self
                .sends
                .iter()
                .filter_map(|slot| {
                    slot.record
                        .filter(|record| record.state == SendState::Outstanding)
                        .map(|record| record.retry_at)
                })
                .min(),
            Phase::Closing | Phase::Closed => None,
        }
    }
}

#[cfg(test)]
#[path = "peer_tests.rs"]
mod tests;

impl Drop for ChannelOwner<'_, '_, '_> {
    fn drop(&mut self) {
        for slot in self.sends.iter_mut() {
            if let Some(record) = slot.record.take() {
                slot.bytes[..record.length].fill(0);
            }
        }
        for slot in self.receives.iter_mut() {
            if let Some(record) = slot.record.take() {
                slot.bytes[..record.length].fill(0);
            }
        }
    }
}
