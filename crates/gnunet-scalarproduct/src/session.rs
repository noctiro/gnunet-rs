use crate::crypto::{aggregate, identity_pair, unblind};
use crate::{AliceKey, Dlog, DlogLimits, DlogProgress, PointPair, Vector};
use alloc::vec::Vec;
use core::{cell::Cell, fmt, mem::size_of};
use gnunet_crypto::Entropy;
use gnunet_types::Error;
use gnunet_wire::official::scalarproduct::{ClientResponse, PeerMessage, ResponseStatus};
use zeroize::Zeroize;

const MAX_PAIRS: usize = (gnunet_wire::official::cadet::MAX_APPLICATION_MESSAGE_SIZE - 8) / 64;

/// Non-cloneable outer lifetime/serial authority for independent computations.
pub struct Instance {
    next: Cell<Option<u64>>,
}
impl Instance {
    /// Construct an unused ID authority outside all borrowed computations.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next: Cell::new(Some(1)),
        }
    }
    fn allocate(&self) -> Result<u64, Error> {
        let id = self.next.get().ok_or(Error::Overflow)?;
        self.next.set(id.checked_add(1));
        Ok(id)
    }
}
impl Default for Instance {
    fn default() -> Self {
        Self::new()
    }
}

macro_rules! token {
    ($name:ident, $doc:literal) => {
        #[doc=$doc]
        #[derive(Clone, Copy)]
        pub struct $name<'i> {
            brand: &'i Instance,
            computation: u64,
            serial: u64,
        }
        impl PartialEq for $name<'_> {
            fn eq(&self, other: &Self) -> bool {
                core::ptr::eq(self.brand, other.brand)
                    && self.computation == other.computation
                    && self.serial == other.serial
            }
        }
        impl Eq for $name<'_> {}
        impl fmt::Debug for $name<'_> {
            fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
                out.debug_tuple(stringify!($name))
                    .field(&self.computation)
                    .field(&self.serial)
                    .finish()
            }
        }
    };
}
token!(
    EffectId,
    "Original instance/computation-branded native effect; never a wire ID."
);
token!(
    InputId,
    "Original instance/computation-branded input delivery retirement."
);
token!(
    IntersectionId,
    "One actual SETI operation/listener owner; never replaced on loss."
);

/// Actual native source identity supplied by the trusted host after admission.
/// Peer bytes alone do not authenticate a source or demonstrate remote liveness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerSource {
    /// Original CADET connection epoch, nonzero and never reused by the host.
    pub epoch: u64,
    /// Original physical channel serial within that epoch, nonzero.
    pub channel: u64,
    /// Actual authenticated remote peer from that channel.
    pub peer: [u8; 32],
}

/// Original public computation role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// Requester with the exact intended actual remote identity.
    Alice {
        /// Actual intended remote peer.
        peer: [u8; 32],
    },
    /// Responder, bound once to the actual accepted channel.
    Bob,
}

/// Explicit outgoing work and total retained-resource profile.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Outgoing Alice pairs per normal chunk, from 1 to the actual CADET limit.
    pub pairs_per_chunk: usize,
    /// Core/vector/effect/job actual retained bytes, including spare Vec capacity.
    pub max_retained_bytes: usize,
    /// Real finite discrete-log search profile.
    pub dlog: DlogLimits,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            pairs_per_chunk: 128,
            max_retained_bytes: 64 * 1024 * 1024,
            dlog: DlogLimits::default(),
        }
    }
}
impl Limits {
    /// Validate finite message/resource bounds without performing cryptography.
    pub fn validate(self) -> Result<(), Error> {
        self.dlog.validate()?;
        if self.pairs_per_chunk == 0
            || self.pairs_per_chunk > MAX_PAIRS
            || self.max_retained_bytes < size_of::<Computation<'_>>()
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}

/// Original failure boundary; no private native diagnostic is formatted away.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    /// Actual transport/SETI setup or source loss.
    Source,
    /// Actual SETI result/cancellation or matched-vector state.
    Intersection,
    /// Entropy, point validation or scalar/aggregate arithmetic.
    Crypto,
    /// No verified discrete logarithm inside the explicit configured range.
    Dlog,
    /// Original local client result write.
    Client,
    /// Explicit caller cancellation.
    Cancel,
}
/// First classified computation failure, separate from any established result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    /// Original classified error; native host retains any underlying I/O cause.
    pub cause: Error,
    /// Boundary at which it was observed.
    pub stage: Stage,
}

/// Verified bounded Alice value and its actual GCRYMPI_FMT_STD magnitude.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResultValue {
    value: i32,
    range: i32,
    bytes: [u8; 5],
    len: u8,
}
impl ResultValue {
    fn new(value: i32) -> Self {
        let mut bytes = [0; 5];
        let magnitude = value.unsigned_abs().to_be_bytes();
        let start = magnitude.iter().position(|b| *b != 0).unwrap_or(4);
        let mut len = 0usize;
        if start < 4 {
            if magnitude[start] & 128 != 0 {
                len = 1;
            }
            bytes[len..len + 4 - start].copy_from_slice(&magnitude[start..]);
            len += 4 - start;
        }
        Self {
            value,
            range: value.signum(),
            bytes,
            len: len as u8,
        }
    }
    /// Verified mathematical result inside the configured range.
    #[must_use]
    pub const fn value(self) -> i32 {
        self.value
    }
    /// Independent official range field (-1, 0, +1).
    #[must_use]
    pub const fn range(self) -> i32 {
        self.range
    }
    /// Positive signed-STD magnitude (empty for zero); range supplies the sign.
    #[must_use]
    pub fn mpi(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

/// Actual computation and independent retirement observations.
#[derive(Clone, Copy, Debug, Default)]
pub struct Outcome {
    /// Verified Alice result; Bob never invents the remote product.
    pub result: Option<ResultValue>,
    /// First original computation failure, independent of the known result.
    pub failure: Option<Failure>,
    /// First independent failure while retiring an already terminal computation.
    pub cleanup_failure: Option<Error>,
    /// Actual whole local client-result write, not remote processing/durability.
    pub client_written: bool,
}
impl Outcome {
    /// Known mathematical value, including an actual empty intersection's zero.
    /// A real sealed empty intersection is a successful zero for Alice; Bob
    /// still receives no mathematical product through the responder API.
    #[must_use]
    pub fn known_value(self) -> Option<i32> {
        self.result.map(ResultValue::value)
    }
}

/// Immutable owned exact peer payload, never rebuilt after partial/lost I/O.
pub enum PeerOutput {
    /// Normal ECC650 initiation.
    Session {
        /// Original session hash.
        session: [u8; 64],
    },
    /// Normal ECC651 interleaved point pairs.
    Alice {
        /// Original complete owned encrypted chunk.
        pairs: Vec<PointPair>,
    },
    /// Normal ECC652 aggregate pair; this alone is not Alice result success.
    Bob {
        /// Original weighted point aggregates.
        products: PointPair,
    },
}
impl PeerOutput {
    /// Borrow its exact standard wire representation without allocation.
    #[must_use]
    pub fn wire(&self) -> PeerMessage<'_> {
        match self {
            Self::Session { session } => PeerMessage::EccSession {
                reserved: 0,
                session,
            },
            Self::Alice { pairs } => PeerMessage::EccAlice {
                points: pairs.as_slice().as_flattened(),
            },
            Self::Bob { products } => PeerMessage::EccBob {
                product_g: &products[0],
                product_h: &products[1],
            },
        }
    }
}

/// Native obligations. Composite SETI setup completes only when its original
/// create/add/listen/evaluate/commit writes have actually completed locally.
pub enum Action<'i> {
    /// Original Bob CADET port announcement.
    OpenPort {
        /// Actual public port hash.
        port: [u8; 64],
    },
    /// Alice's actual SETI listener and original local set population.
    ListenIntersection {
        /// Original operation owner.
        id: IntersectionId<'i>,
        /// Hash of the session bytes.
        app: [u8; 64],
        /// Only this actual remote peer may be accepted.
        peer: [u8; 32],
    },
    /// Original outgoing CADET channel request; no remote-live assertion.
    Connect {
        /// Actual destination peer.
        peer: [u8; 32],
        /// Actual advertised port.
        port: [u8; 64],
    },
    /// Bob's actual SETI prepare/commit and original local set population.
    StartIntersection {
        /// Original operation owner.
        id: IntersectionId<'i>,
        /// Hash of the session bytes.
        app: [u8; 64],
        /// Actual source peer.
        peer: [u8; 32],
    },
    /// Write the original exact payload on its original actual channel.
    PeerSend {
        /// Original channel owner.
        source: PeerSource,
        /// Exact retained payload.
        payload: PeerOutput,
    },
    /// Release only this fully processed original CADET delivery.
    ReceiveDone {
        /// Original channel owner.
        source: PeerSource,
        /// Original input owner.
        input: InputId<'i>,
        /// Original host delivery serial, not a wire RID.
        delivery: u64,
    },
    /// Official local client result; successful Bob response has no product.
    ClientResult {
        /// Original status (2 success or 3 failure).
        status: ResponseStatus,
        /// Verified Alice value, absent for Bob/failure.
        value: Option<ResultValue>,
    },
    /// Physically retire the original SETI/listener/set obligations.
    CloseIntersection {
        /// Original operation owner.
        id: IntersectionId<'i>,
    },
    /// Physically retire this original channel and all retained native input.
    ClosePeer {
        /// Original channel owner.
        source: PeerSource,
    },
    /// Physically retire the original Bob port, without auto-reannouncement.
    ClosePort {
        /// Actual original port hash.
        port: [u8; 64],
    },
}
impl Action<'_> {
    /// Borrow exact official result fields; no allocation/MPI reinterpretation.
    #[must_use]
    pub fn client_response(&self) -> Option<ClientResponse<'_>> {
        match self {
            Self::ClientResult { status, value } => Some(ClientResponse {
                status: *status,
                range: value.as_ref().map_or(0, |v| v.range),
                product: value.as_ref().map_or(&[], ResultValue::mpi),
            }),
            _ => None,
        }
    }
    fn cleanup(&self) -> bool {
        matches!(
            self,
            Self::CloseIntersection { .. } | Self::ClosePeer { .. } | Self::ClosePort { .. }
        )
    }
}

/// Retained original effect, borrowed by the native host until real settlement.
pub struct Effect<'i> {
    /// Original once-only token.
    pub id: EffectId<'i>,
    /// Immutable original action and owned bytes.
    pub action: Action<'i>,
    admitted: bool,
}
impl Effect<'_> {
    /// Whether this original effect was admitted to its native owner.
    #[must_use]
    pub const fn is_admitted(&self) -> bool {
        self.admitted
    }
}
/// Original native action disposition, not a peer processing ACK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Completion {
    /// All of this action's original bytes were actually written locally.
    Written,
    /// This inner message was actually processed. Legal only for ReceiveDone
    /// when its original outer CADET Delivery still contains later messages.
    /// The host retains that outer input/offset and sends the actual ACK only
    /// after every inner message is processed. This is no wire-write receipt.
    Processed,
    /// It was not exposed; retain the original cause and do not replay.
    Unsent(Error),
    /// Some exposure/outcome may be unknown; retain the original cause.
    Lost(Error),
    /// Original cleanup was physically performed; never valid for a send.
    Retired,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Listen,
    Connect,
    Session,
    Port,
    WaitSession,
    StartIntersection,
    WaitIntersection,
    AliceWork,
    AliceAwait,
    BobReady,
    BobWork,
    AliceLog,
    Release,
    Reply,
    Closing,
    Stopped,
}
#[derive(Clone, Copy)]
enum AfterRelease {
    Intersection,
    Bob,
    Alice,
}
#[derive(Clone, Copy)]
struct Input<'i> {
    id: InputId<'i>,
    delivery: u64,
    source: PeerSource,
}
// Dlog is deliberately inline: terminal/loss paths do not allocate a Box.
#[expect(
    clippy::large_enum_variant,
    reason = "one explicitly budgeted inline job avoids allocation on failure/retirement"
)]
enum Work<'i> {
    Encrypt {
        pairs: Vec<PointPair>,
        goal: usize,
    },
    Aggregate {
        pairs: Vec<PointPair>,
        cursor: usize,
        staged: PointPair,
        input: Input<'i>,
    },
    Log {
        job: Dlog,
        // None only after the original native source/input was physically
        // retired under the final-payload local-work API. No ACK is invented.
        input: Option<Input<'i>>,
    },
}

/// One bounded ECC session. Owns coefficients, secrets, immutable effects and
/// original generations; contains no socket, callback task or background work.
pub struct Computation<'i> {
    brand: &'i Instance,
    serial: u64,
    next: Option<u64>,
    role: Role,
    session: [u8; 64],
    app: [u8; 64],
    intersection: IntersectionId<'i>,
    vector: Vector,
    limits: Limits,
    phase: Phase,
    pending: Option<Effect<'i>>,
    key: Option<AliceKey>,
    source: Option<PeerSource>,
    port_open: bool,
    intersection_open: bool,
    intersection_done: bool,
    cursor: usize,
    last_delivery: u64,
    work: Option<Work<'i>>,
    products: PointPair,
    release: Option<(Input<'i>, AfterRelease)>,
    want_reply: bool,
    cancelled: bool,
    outcome: Outcome,
}

impl<'i> Computation<'i> {
    fn base(
        brand: &'i Instance,
        session: [u8; 64],
        role: Role,
        vector: Vector,
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        if size_of::<Self>()
            .checked_add(vector.retained_bytes()?)
            .ok_or(Error::Overflow)?
            > limits.max_retained_bytes
        {
            return Err(Error::Capacity);
        }
        let serial = brand.allocate()?;
        let intersection = IntersectionId {
            brand,
            computation: serial,
            serial: 0,
        };
        Ok(Self {
            brand,
            serial,
            next: Some(1),
            role,
            session,
            app: gnunet_crypto::hash512(&session),
            intersection,
            vector,
            limits,
            phase: match role {
                Role::Alice { .. } => Phase::Listen,
                Role::Bob => Phase::Port,
            },
            pending: None,
            key: None,
            source: None,
            port_open: false,
            intersection_open: false,
            intersection_done: false,
            cursor: 0,
            last_delivery: 0,
            work: None,
            products: identity_pair(),
            release: None,
            want_reply: false,
            cancelled: false,
            outcome: Outcome::default(),
        })
    }
    /// Adopt a complete original vector and sample one fresh private Alice key.
    pub fn alice(
        brand: &'i Instance,
        session: [u8; 64],
        peer: [u8; 32],
        vector: Vector,
        limits: Limits,
        entropy: &mut impl Entropy,
    ) -> Result<Self, Error> {
        let mut this = Self::base(brand, session, Role::Alice { peer }, vector, limits)?;
        this.key = Some(AliceKey::generate(entropy)?);
        this.pump()?;
        Ok(this)
    }
    /// Adopt a complete original Bob vector and request its actual CADET port.
    pub fn bob(
        brand: &'i Instance,
        session: [u8; 64],
        vector: Vector,
        limits: Limits,
    ) -> Result<Self, Error> {
        let mut this = Self::base(brand, session, Role::Bob, vector, limits)?;
        this.pump()?;
        Ok(this)
    }
    fn next_serial(&mut self) -> Result<u64, Error> {
        let serial = self.next.ok_or(Error::Overflow)?;
        self.next = serial.checked_add(1);
        Ok(serial)
    }
    fn publish(&mut self, action: Action<'i>) -> Result<(), Error> {
        if self.pending.is_some() {
            return Err(Error::WouldBlock);
        }
        let serial = self.next_serial()?;
        self.pending = Some(Effect {
            id: EffectId {
                brand: self.brand,
                computation: self.serial,
                serial,
            },
            action,
            admitted: false,
        });
        Ok(())
    }
    fn pump(&mut self) -> Result<(), Error> {
        if self.pending.is_some() {
            return Ok(());
        }
        let action = match self.phase {
            Phase::Listen => {
                if let Role::Alice { peer } = self.role {
                    Some(Action::ListenIntersection {
                        id: self.intersection,
                        app: self.app,
                        peer,
                    })
                } else {
                    return Err(Error::Conflict);
                }
            }
            Phase::Connect => {
                if let Role::Alice { peer } = self.role {
                    Some(Action::Connect {
                        peer,
                        port: self.session,
                    })
                } else {
                    return Err(Error::Conflict);
                }
            }
            Phase::Port => Some(Action::OpenPort { port: self.session }),
            Phase::Session => Some(Action::PeerSend {
                source: self.source.ok_or(Error::NotReady)?,
                payload: PeerOutput::Session {
                    session: self.session,
                },
            }),
            Phase::StartIntersection => Some(Action::StartIntersection {
                id: self.intersection,
                app: self.app,
                peer: self.source.ok_or(Error::NotReady)?.peer,
            }),
            Phase::Release => {
                let (input, _) = self.release.ok_or(Error::Conflict)?;
                Some(Action::ReceiveDone {
                    source: input.source,
                    input: input.id,
                    delivery: input.delivery,
                })
            }
            Phase::Reply => Some(Action::ClientResult {
                status: ResponseStatus(if self.outcome.failure.is_some() { 3 } else { 2 }),
                value: if self.outcome.failure.is_some() {
                    None
                } else {
                    self.outcome.result
                },
            }),
            Phase::Closing => {
                if self.want_reply && !self.cancelled {
                    self.phase = Phase::Reply;
                    return self.pump();
                }
                if self.intersection_open {
                    Some(Action::CloseIntersection {
                        id: self.intersection,
                    })
                } else if let Some(source) = self.source {
                    Some(Action::ClosePeer { source })
                } else if self.port_open {
                    Some(Action::ClosePort { port: self.session })
                } else {
                    self.phase = Phase::Stopped;
                    None
                }
            }
            _ => None,
        };
        if let Some(action) = action {
            self.publish(action)?;
        }
        Ok(())
    }
    /// Borrow exactly one immutable original effect. None does not mean stopped.
    #[must_use]
    pub fn effect(&self) -> Option<&Effect<'i>> {
        self.pending.as_ref()
    }
    /// Admit this same retained action to the original physical owner once.
    pub fn admit_effect(&mut self, id: EffectId<'i>) -> Result<(), Error> {
        let effect = self.pending.as_mut().ok_or(Error::NotFound)?;
        if effect.id != id {
            return Err(Error::StaleGeneration);
        }
        if effect.admitted {
            return Err(Error::Conflict);
        }
        effect.admitted = true;
        Ok(())
    }
    /// Actual outcome facts, never inferred from EOF or effect queue admission.
    #[must_use]
    pub const fn outcome(&self) -> Outcome {
        self.outcome
    }
    /// Actual original native source, if still owned; close it on cancellation
    /// before settling any admitted partial send with its real disposition.
    #[must_use]
    pub const fn peer_source(&self) -> Option<PeerSource> {
        self.source
    }
    /// Whether actual cleanup debt and original retained effects are all retired.
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        self.phase == Phase::Stopped
            && self.pending.is_none()
            && self.source.is_none()
            && !self.port_open
            && !self.intersection_open
    }
    /// Actual retained allocation count; it does not claim measured peak RSS.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        let mut bytes = size_of::<Self>()
            .checked_add(self.vector.retained_bytes()?)
            .ok_or(Error::Overflow)?;
        if let Some(work) = &self.work {
            let extra = match work {
                Work::Encrypt { pairs, .. } | Work::Aggregate { pairs, .. } => pairs
                    .capacity()
                    .checked_mul(size_of::<PointPair>())
                    .ok_or(Error::Overflow)?,
                Work::Log { job, .. } => job.retained_bytes()?,
            };
            bytes = bytes.checked_add(extra).ok_or(Error::Overflow)?;
        }
        if let Some(Effect {
            action:
                Action::PeerSend {
                    payload: PeerOutput::Alice { pairs },
                    ..
                },
            ..
        }) = &self.pending
        {
            bytes = bytes
                .checked_add(
                    pairs
                        .capacity()
                        .checked_mul(size_of::<PointPair>())
                        .ok_or(Error::Overflow)?,
                )
                .ok_or(Error::Overflow)?;
        }
        Ok(bytes)
    }
    fn pairs(&self, count: usize) -> Result<Vec<PointPair>, Error> {
        let remaining = self
            .limits
            .max_retained_bytes
            .checked_sub(self.retained_bytes()?)
            .ok_or(Error::Capacity)?;
        if count
            .checked_mul(size_of::<PointPair>())
            .ok_or(Error::Overflow)?
            > remaining
        {
            return Err(Error::Capacity);
        }
        let mut pairs = Vec::new();
        pairs
            .try_reserve_exact(count)
            .map_err(|_| Error::Capacity)?;
        if pairs
            .capacity()
            .checked_mul(size_of::<PointPair>())
            .ok_or(Error::Overflow)?
            > remaining
        {
            return Err(Error::Capacity);
        }
        Ok(pairs)
    }
    fn fail(&mut self, stage: Stage, cause: Error) {
        if self.outcome.failure.is_none() {
            self.outcome.failure = Some(Failure { cause, stage });
        }
        self.key = None;
        self.work = None;
        self.vector.wipe();
        self.products.zeroize();
        self.release = None;
        if self
            .pending
            .as_ref()
            .is_some_and(|effect| !effect.admitted && !effect.action.cleanup())
        {
            self.pending = None;
        }
        self.want_reply = !self.cancelled;
        self.phase = Phase::Closing;
    }
    /// Bind exactly one actual native source, with no source replacement/replay.
    pub fn attach_peer(&mut self, source: PeerSource) -> Result<(), Error> {
        if source.epoch == 0 || source.channel == 0 {
            return Err(Error::InvalidInput);
        }
        if self.source.is_some() {
            return Err(Error::Conflict);
        }
        match self.role {
            Role::Alice { peer } => {
                if peer != source.peer {
                    return Err(Error::Authentication);
                }
                if self.phase != Phase::Connect {
                    return Err(Error::NotReady);
                }
                if !self.pending.as_ref().is_some_and(|effect| {
                    effect.admitted && matches!(effect.action, Action::Connect { .. })
                }) {
                    return Err(Error::NotReady);
                }
            }
            Role::Bob => {
                if self.phase != Phase::WaitSession {
                    return Err(Error::NotReady);
                }
            }
        }
        self.source = Some(source);
        self.pump()
    }
    /// Borrow stable original nonzero SETI keys without copying coefficients.
    pub fn intersection_keys(
        &self,
        id: IntersectionId<'i>,
    ) -> Result<impl Iterator<Item = &[u8; 64]>, Error> {
        if id != self.intersection {
            return Err(Error::StaleGeneration);
        }
        if self.intersection_done || self.cancelled || self.outcome.failure.is_some() {
            return Err(Error::Closed);
        }
        Ok(self.vector.keys())
    }
    /// O(1) original ordered key access for actual SETI population. Physical
    /// indices remain stable until actual DONE seals/compacts the vector. The
    /// host finishes population before admitting the actual intersection, so
    /// this does not reinterpret a partially removed set as the final result.
    pub fn intersection_key(
        &self,
        id: IntersectionId<'i>,
        index: usize,
    ) -> Result<Option<&[u8; 64]>, Error> {
        if id != self.intersection {
            return Err(Error::StaleGeneration);
        }
        if self.intersection_done || self.cancelled || self.outcome.failure.is_some() {
            return Err(Error::Closed);
        }
        Ok(self.vector.indexed_key(index))
    }
    fn intersection_guard(&self, id: IntersectionId<'i>, peer: [u8; 32]) -> Result<(), Error> {
        if id != self.intersection {
            return Err(Error::StaleGeneration);
        }
        if !self.intersection_open
            || self.intersection_done
            || self.cancelled
            || self.outcome.failure.is_some()
            || self.phase != Phase::WaitIntersection
        {
            return Err(Error::NotReady);
        }
        let expected = match self.role {
            Role::Alice { peer } => peer,
            Role::Bob => self.source.ok_or(Error::NotReady)?.peer,
        };
        if peer != expected {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    /// Apply one actual original SETI DEL_LOCAL; duplicate/foreign removals fail.
    pub fn intersection_removed(
        &mut self,
        id: IntersectionId<'i>,
        peer: [u8; 32],
        key: &[u8; 64],
    ) -> Result<(), Error> {
        self.intersection_guard(id, peer)?;
        self.vector.remove(key)
    }
    /// Seal the actual matched vector only on the original SETI DONE.
    pub fn intersection_done(
        &mut self,
        id: IntersectionId<'i>,
        peer: [u8; 32],
    ) -> Result<(), Error> {
        self.intersection_guard(id, peer)?;
        self.vector.seal();
        self.intersection_done = true;
        if self.vector.is_empty() {
            // Actual original SETI DONE has established the complete matched
            // vector. Its empty sum is exactly zero: no peer point, encryption,
            // DLOG or synthetic write receipt is required to establish it.
            self.outcome.result = match self.role {
                Role::Alice { .. } => Some(ResultValue::new(0)),
                Role::Bob => None,
            };
            self.want_reply = true;
            self.phase = Phase::Reply;
        } else {
            self.phase = match self.role {
                Role::Alice { .. } => Phase::AliceWork,
                Role::Bob => Phase::BobReady,
            };
        }
        self.pump()
    }
    /// Preserve failure of the original actual SETI operation, without reconnect.
    pub fn intersection_failed(
        &mut self,
        id: IntersectionId<'i>,
        cause: Error,
    ) -> Result<(), Error> {
        if id != self.intersection {
            return Err(Error::StaleGeneration);
        }
        if !self.intersection_open || self.intersection_done || self.cancelled {
            return Err(Error::StaleGeneration);
        }
        self.fail(Stage::Intersection, cause);
        self.pump()
    }
    fn input(&mut self, source: PeerSource, delivery: u64) -> Result<Input<'i>, Error> {
        if self.source != Some(source) {
            return Err(Error::StaleGeneration);
        }
        if delivery == 0 || delivery <= self.last_delivery {
            return Err(Error::Replay);
        }
        let serial = self.next_serial()?;
        self.last_delivery = delivery;
        Ok(Input {
            id: InputId {
                brand: self.brand,
                computation: self.serial,
                serial,
            },
            delivery,
            source,
        })
    }
    /// Admit one complete actual native payload. WouldBlock leaves that original
    /// Delivery with the host (e.g. Bob is awaiting SETI Done). No receive_done
    /// may be invented from input admission or from an invalid payload.
    pub fn receive(
        &mut self,
        source: PeerSource,
        delivery: u64,
        message: PeerMessage<'_>,
    ) -> Result<InputId<'i>, Error> {
        if self.source != Some(source) {
            return Err(Error::StaleGeneration);
        }
        if self.cancelled || self.outcome.failure.is_some() {
            return Err(Error::Closed);
        }
        if self.release.is_some() || self.work.is_some() {
            return Err(Error::WouldBlock);
        }
        match (self.role, self.phase, message) {
            (Role::Bob, Phase::WaitSession, PeerMessage::EccSession { session, .. }) => {
                if *session != self.session {
                    return Err(Error::Authentication);
                }
                let input = self.input(source, delivery)?;
                self.release = Some((input, AfterRelease::Intersection));
                self.phase = Phase::Release;
                self.pump()?;
                Ok(input.id)
            }
            (
                Role::Bob,
                Phase::StartIntersection | Phase::WaitIntersection,
                PeerMessage::EccAlice { .. },
            ) => Err(Error::WouldBlock),
            (Role::Bob, Phase::BobReady, PeerMessage::EccAlice { points }) => {
                if points.is_empty() || points.len() % 2 != 0 || points.len() / 2 > MAX_PAIRS {
                    return Err(Error::Malformed);
                }
                let count = points.len() / 2;
                if count
                    > self
                        .vector
                        .len()
                        .checked_sub(self.cursor)
                        .ok_or(Error::Conflict)?
                {
                    return Err(Error::Malformed);
                }
                let mut pairs = self.pairs(count)?;
                for pair in points.as_chunks::<2>().0 {
                    pairs.push(*pair);
                }
                let input = self.input(source, delivery)?;
                self.work = Some(Work::Aggregate {
                    pairs,
                    cursor: 0,
                    staged: self.products,
                    input,
                });
                self.phase = Phase::BobWork;
                Ok(input.id)
            }
            (
                Role::Alice { .. },
                Phase::AliceAwait,
                PeerMessage::EccBob {
                    product_g,
                    product_h,
                },
            ) => {
                let key = self.key.as_ref().ok_or(Error::Closed)?;
                let target = unblind(key, [*product_g, *product_h])?;
                let remaining = self
                    .limits
                    .max_retained_bytes
                    .checked_sub(self.retained_bytes()?)
                    .ok_or(Error::Capacity)?;
                let limits = DlogLimits {
                    max_retained_bytes: self.limits.dlog.max_retained_bytes.min(remaining),
                    ..self.limits.dlog
                };
                let job = Dlog::new(target, limits)?;
                let input = self.input(source, delivery)?;
                self.key = None;
                self.work = Some(Work::Log {
                    job,
                    input: Some(input),
                });
                self.phase = Phase::AliceLog;
                Ok(input.id)
            }
            _ => Err(Error::Malformed),
        }
    }
    /// Finite per-call crypto/DLOG work, with no new source, replay or task.
    pub fn step(&mut self, entropy: &mut impl Entropy, work_units: usize) -> Result<(), Error> {
        if work_units == 0 {
            return Err(Error::InvalidInput);
        }
        if self.pending.is_some() || self.cancelled || self.outcome.failure.is_some() {
            return self.pump();
        }
        if self.phase == Phase::AliceWork && self.work.is_none() {
            let remaining = self
                .vector
                .len()
                .checked_sub(self.cursor)
                .ok_or(Error::Conflict)?;
            if remaining == 0 {
                self.phase = Phase::AliceAwait;
                return Ok(());
            }
            let goal = remaining.min(self.limits.pairs_per_chunk);
            let pairs = self.pairs(goal)?;
            self.work = Some(Work::Encrypt { pairs, goal });
        }
        for _ in 0..work_units {
            let Some(mut work) = self.work.take() else {
                break;
            };
            let progressed: Result<bool, Error> = (|| match &mut work {
                Work::Encrypt { pairs, goal } => {
                    let value = self.vector.coefficient(self.cursor + pairs.len())?;
                    match self
                        .key
                        .as_ref()
                        .ok_or(Error::Closed)?
                        .encrypt(value, entropy)
                    {
                        Ok(pair) => {
                            pairs.push(pair);
                            Ok(pairs.len() == *goal)
                        }
                        Err(error) => Err(error),
                    }
                }
                Work::Aggregate {
                    pairs,
                    cursor,
                    staged,
                    ..
                } => {
                    let value = self.vector.coefficient(self.cursor + *cursor)?;
                    match aggregate(*staged, pairs[*cursor], value) {
                        Ok(next) => {
                            *staged = next;
                            *cursor += 1;
                            Ok(*cursor == pairs.len())
                        }
                        Err(error) => Err(error),
                    }
                }
                Work::Log { job, .. } => match job.step(1) {
                    Ok(DlogProgress::Pending) => Ok(false),
                    Ok(DlogProgress::Done(value)) => {
                        self.outcome.result = Some(ResultValue::new(value));
                        Ok(true)
                    }
                    Ok(DlogProgress::OutOfRange) => Err(Error::TooLarge),
                    Err(error) => Err(error),
                },
            })();
            match progressed {
                Err(cause) => {
                    let stage = if matches!(work, Work::Log { .. }) {
                        Stage::Dlog
                    } else {
                        Stage::Crypto
                    };
                    drop(work);
                    self.fail(stage, cause);
                    self.pump()?;
                    return Err(cause);
                }
                Ok(false) => self.work = Some(work),
                Ok(true) => {
                    match work {
                        Work::Encrypt { pairs, .. } => {
                            let source = self.source.ok_or(Error::NotReady)?;
                            self.publish(Action::PeerSend {
                                source,
                                payload: PeerOutput::Alice { pairs },
                            })?;
                        }
                        Work::Aggregate { input, .. } => {
                            self.release = Some((input, AfterRelease::Bob));
                            self.work = Some(work);
                            self.phase = Phase::Release;
                            self.pump()?;
                        }
                        Work::Log { input, .. } => {
                            if let Some(input) = input {
                                self.release = Some((input, AfterRelease::Alice));
                                self.phase = Phase::Release;
                            } else {
                                // The original outer input was physically
                                // retired after its complete tail validation.
                                // Local DLOG completion creates no old ACK IO.
                                self.want_reply = true;
                                self.phase = Phase::Reply;
                            }
                            self.pump()?;
                        }
                    }
                    break;
                }
            }
        }
        self.pump()
    }
    /// Settle the original action once, only after actual whole write or actual
    /// physical retirement. Wrong/stale IDs or fake cleanup-write classes do not
    /// consume the retained original action.
    pub fn complete_effect(
        &mut self,
        id: EffectId<'i>,
        completion: Completion,
    ) -> Result<(), Error> {
        let effect = self.pending.as_ref().ok_or(Error::NotFound)?;
        if effect.id != id {
            return Err(Error::StaleGeneration);
        }
        if !effect.admitted && !matches!(completion, Completion::Unsent(_)) {
            return Err(Error::Conflict);
        }
        if completion == Completion::Retired && !effect.action.cleanup() {
            return Err(Error::InvalidInput);
        }
        if completion == Completion::Processed
            && !matches!(effect.action, Action::ReceiveDone { .. })
        {
            return Err(Error::InvalidInput);
        }
        if completion == Completion::Written
            && matches!(effect.action, Action::Connect { .. })
            && self.source.is_none()
        {
            // The native channel exists before its create is written. Bind its
            // original epoch/channel first, so cancellation cannot lose it in
            // a create-written/attach gap. This is not remote-live evidence.
            return Err(Error::NotReady);
        }
        let effect = self.pending.take().ok_or(Error::Conflict)?;
        let failed = match completion {
            Completion::Unsent(error) | Completion::Lost(error) => Some(error),
            _ => None,
        };
        if effect.action.cleanup() {
            if let Some(error) = failed {
                self.outcome.cleanup_failure.get_or_insert(error);
            }
            // Host may use Lost/Unsent only after actual physical retirement;
            // a close queue admission is not sufficient to clear this debt.
            match effect.action {
                Action::CloseIntersection { .. } => self.intersection_open = false,
                Action::ClosePeer { .. } => {
                    self.source = None;
                    self.release = None;
                }
                Action::ClosePort { .. } => self.port_open = false,
                _ => return Err(Error::Conflict),
            }
            return self.pump();
        }
        if let Some(cause) = failed {
            let stage = if matches!(effect.action, Action::ClientResult { .. }) {
                Stage::Client
            } else {
                Stage::Source
            };
            if self.outcome.failure.is_some() || self.cancelled {
                self.outcome.cleanup_failure.get_or_insert(cause);
            } else {
                self.fail(stage, cause);
            }
            if matches!(effect.action, Action::ClientResult { .. }) {
                self.want_reply = false;
                self.phase = Phase::Closing;
            }
            return self.pump();
        }
        // Even if cancelled after admission, retain the actual setup/resource
        // fact first so cleanup cannot lose a physically-created obligation.
        match effect.action {
            Action::OpenPort { .. } => {
                self.port_open = true;
                if !self.cancelled && self.outcome.failure.is_none() {
                    self.phase = Phase::WaitSession;
                }
            }
            Action::ListenIntersection { .. } => {
                self.intersection_open = true;
                if !self.cancelled && self.outcome.failure.is_none() {
                    self.phase = Phase::Connect;
                }
            }
            Action::StartIntersection { .. } => {
                self.intersection_open = true;
                if !self.cancelled && self.outcome.failure.is_none() {
                    self.phase = Phase::WaitIntersection;
                }
            }
            Action::Connect { .. } => {
                if !self.cancelled && self.outcome.failure.is_none() {
                    self.phase = Phase::Session;
                }
            }
            Action::PeerSend { payload, .. } => {
                if !self.cancelled && self.outcome.failure.is_none() {
                    match payload {
                        PeerOutput::Session { .. } => self.phase = Phase::WaitIntersection,
                        PeerOutput::Alice { pairs } => {
                            self.cursor = self
                                .cursor
                                .checked_add(pairs.len())
                                .ok_or(Error::Overflow)?;
                            self.phase = if self.cursor == self.vector.len() {
                                Phase::AliceAwait
                            } else {
                                Phase::AliceWork
                            };
                        }
                        PeerOutput::Bob { .. } => {
                            self.want_reply = true;
                            self.phase = Phase::Reply;
                        }
                    }
                }
            }
            Action::ReceiveDone { input, .. } => {
                if !self.cancelled && self.outcome.failure.is_none() {
                    let (original, after) = self.release.take().ok_or(Error::Conflict)?;
                    if original.id != input {
                        return Err(Error::StaleGeneration);
                    }
                    match after {
                        AfterRelease::Intersection => self.phase = Phase::StartIntersection,
                        AfterRelease::Bob => {
                            let work = self.work.take().ok_or(Error::Conflict)?;
                            if let Work::Aggregate { pairs, staged, .. } = work {
                                self.products = staged;
                                self.cursor = self
                                    .cursor
                                    .checked_add(pairs.len())
                                    .ok_or(Error::Overflow)?;
                                if self.cursor == self.vector.len() {
                                    // Identity aggregate columns are valid subgroup sums.
                                    // Preserve them for ordinary unblinding and bounded
                                    // DLOG; input-point and SETI validation stay separate.
                                    self.phase = Phase::BobReady;
                                    self.publish(Action::PeerSend {
                                        source: self.source.ok_or(Error::NotReady)?,
                                        payload: PeerOutput::Bob {
                                            products: self.products,
                                        },
                                    })?;
                                } else {
                                    self.phase = Phase::BobReady;
                                }
                            } else {
                                return Err(Error::Conflict);
                            }
                        }
                        AfterRelease::Alice => {
                            self.want_reply = true;
                            self.phase = Phase::Reply;
                        }
                    }
                }
            }
            Action::ClientResult { .. } => {
                self.outcome.client_written = true;
                self.want_reply = false;
                self.key = None;
                self.work = None;
                self.vector.wipe();
                self.products.zeroize();
                self.phase = Phase::Closing;
            }
            _ => return Err(Error::Conflict),
        }
        if self.cancelled || self.outcome.failure.is_some() {
            self.phase = Phase::Closing;
        }
        self.pump()
    }
    /// Whether all peer data needed by the remaining local computation/result
    /// is already owned. This is not evidence that an outer packet has no later
    /// malformed inner: the native owner must validate its complete original
    /// tail before using retire_peer_for_local_work. No source is closed here.
    #[must_use]
    pub fn can_finish_locally(&self) -> bool {
        if self.cancelled || self.outcome.failure.is_some() || !self.intersection_done {
            return false;
        }
        match self.role {
            Role::Alice { .. } => match self.phase {
                Phase::AliceLog => matches!(self.work, Some(Work::Log { .. })),
                Phase::Release => {
                    self.outcome.result.is_some()
                        && matches!(self.release, Some((_, AfterRelease::Alice)))
                }
                Phase::Reply => self.outcome.result.is_some(),
                _ => false,
            },
            // Nonempty Bob replies follow the actual last PeerSend Written;
            // an empty sealed vector instead follows real original SETI DONE.
            // Neither case gives Bob Alice's mathematical result value.
            Role::Bob => self.phase == Phase::Reply && self.want_reply,
        }
    }
    /// Retire an already physically closed original peer while preserving only
    /// fully owned final-input/local-result work. The host must first validate
    /// every inner in that original outer Delivery, stop all old IO and retain
    /// the actual original native write/input dispositions. Original operation
    /// hard/cancel bounds stay with that host and are never renewed here.
    ///
    /// receipt is required only for an outstanding original final ReceiveDone:
    /// it must identify that exact action and its actual Written/Lost/Unsent
    /// disposition. Processed is not a final outer ACK and Retired is not a
    /// receive-ACK write. No unrelated admitted action can be consumed. All
    /// validation/serial preflight precedes mutation. Raw native causes remain
    /// independently owned by the host; the first classified cause is preserved.
    pub fn retire_peer_for_local_work(
        &mut self,
        source: PeerSource,
        cause: Error,
        receipt: Option<(EffectId<'i>, Completion)>,
    ) -> Result<(), Error> {
        if self.source != Some(source) {
            return Err(Error::StaleGeneration);
        }
        if !self.can_finish_locally() {
            return Err(Error::NotReady);
        }
        let final_release = self.phase == Phase::Release;
        match &self.pending {
            Some(effect) if matches!(effect.action, Action::ReceiveDone { .. }) => {
                if !final_release {
                    return Err(Error::Conflict);
                }
                let (id, completion) = receipt.ok_or(Error::NotReady)?;
                if effect.id != id {
                    return Err(Error::StaleGeneration);
                }
                let (input, _) = self.release.ok_or(Error::Conflict)?;
                if !matches!(effect.action, Action::ReceiveDone { source: s, input: i, delivery }
                    if s == source && i == input.id && delivery == input.delivery)
                {
                    return Err(Error::Conflict);
                }
                match completion {
                    Completion::Written | Completion::Lost(_) if effect.admitted => {}
                    Completion::Unsent(_) => {}
                    _ => return Err(Error::InvalidInput),
                }
            }
            Some(effect) if matches!(effect.action, Action::ClientResult { .. }) => {
                if receipt.is_some() || self.phase != Phase::Reply {
                    return Err(Error::Conflict);
                }
            }
            Some(_) => return Err(Error::NotReady),
            None if receipt.is_some() => return Err(Error::Conflict),
            None => {}
        }
        if let Some(Work::Log {
            input: Some(input), ..
        }) = &self.work
            && input.source != source
        {
            return Err(Error::StaleGeneration);
        }
        // After final ReceiveDone is retired, a result effect must be published.
        // Exhaustion is rejected before consuming that original action/debt.
        let result_serial = if final_release {
            Some(self.next.ok_or(Error::Overflow)?)
        } else {
            None
        };
        if let Some((_, Completion::Lost(error) | Completion::Unsent(error))) = receipt {
            self.outcome.cleanup_failure.get_or_insert(error);
        }
        self.outcome.cleanup_failure.get_or_insert(cause);
        self.source = None;
        if let Some(Work::Log { input, .. }) = &mut self.work {
            *input = None;
        }
        if let Some(serial) = result_serial {
            self.pending = None; // exact original ReceiveDone settled above
            self.release = None;
            self.want_reply = true;
            self.phase = Phase::Reply;
            self.next = serial.checked_add(1);
            self.pending = Some(Effect {
                id: EffectId {
                    brand: self.brand,
                    computation: self.serial,
                    serial,
                },
                action: Action::ClientResult {
                    status: ResponseStatus(2),
                    value: self.outcome.result,
                },
                admitted: false,
            });
        }
        Ok(())
    }
    /// Original source was physically retired. First settle any admitted peer
    /// write/input-release with its actual disposition; do not overwrite it.
    pub fn peer_lost(&mut self, source: PeerSource, cause: Error) -> Result<(), Error> {
        if self.source != Some(source) {
            return Err(Error::StaleGeneration);
        }
        if self.pending.as_ref().is_some_and(|e| {
            e.admitted
                && matches!(
                    e.action,
                    Action::PeerSend { .. } | Action::ReceiveDone { .. } | Action::Connect { .. }
                )
        }) {
            return Err(Error::Conflict);
        }
        self.source = None;
        if self.pending.as_ref().is_some_and(|e| {
            !e.admitted
                && matches!(
                    e.action,
                    Action::PeerSend { .. } | Action::ReceiveDone { .. } | Action::ClosePeer { .. }
                )
        }) {
            self.pending = None;
        }
        if self.cancelled
            || self.outcome.failure.is_some()
            || self.outcome.client_written
            || self.phase == Phase::Closing
        {
            self.outcome.cleanup_failure.get_or_insert(cause);
        } else {
            self.fail(Stage::Source, cause);
        }
        self.pump()
    }
    /// Cancel the original intent once. No deadline is extended and no new
    /// source is opened. An admitted partial action must still be settled after
    /// actual physical close; no synthetic successful completion is generated.
    pub fn cancel(&mut self) -> Result<(), Error> {
        if self.cancelled {
            return Err(Error::Conflict);
        }
        if self.is_quiescent() {
            return Err(Error::Closed);
        }
        self.cancelled = true;
        self.want_reply = false;
        if self.outcome.client_written {
            self.key = None;
            self.work = None;
            self.vector.wipe();
            self.products.zeroize();
            self.release = None;
            self.phase = Phase::Closing;
        } else {
            self.fail(Stage::Cancel, Error::Cancelled);
        }
        if self.pending.as_ref().is_some_and(|e| !e.admitted) {
            self.pending = None;
        }
        self.pump()
    }
}
impl Drop for Computation<'_> {
    fn drop(&mut self) {
        self.products.zeroize();
        if let Some(value) = self.outcome.result.as_mut() {
            value.value.zeroize();
            value.range.zeroize();
            value.bytes.zeroize();
            value.len.zeroize();
        }
    }
}

#[cfg(test)]
mod local_retirement_tests;
