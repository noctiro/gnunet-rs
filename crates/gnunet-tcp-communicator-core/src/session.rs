//! A bounded actual TCP session. Native and service effects require real ACKs.
//! No socket/peerstore/TRANSPORT plan is reported as an executed operation.
use crate::{
    initial,
    record::{Direction, Receiver, Record},
    wire,
};
use core::{
    fmt,
    hash::{Hash, Hasher},
};
use gnunet_crypto::{EddsaPrivateKey, EddsaPublicKey, Entropy};
use gnunet_session_crypto::{
    Prk, elligator,
    exchange::{self, EcdhePublic, EcdheSecret},
};
use gnunet_types::{Error, Rejected};
use zeroize::Zeroize;
/// Source ciphertext buffer size: 2*64KiB plus TCPBox36.
pub const CIPHERTEXT_CAPACITY: usize = 2 * 64 * 1024 + wire::BOX_PREFIX;
/// Source active connection idle period, five minutes in microseconds.
pub const IDLE_US: u64 = 300_000_000;
/// Source absolute FINISH flush budget, five seconds in microseconds.
pub const FINISH_US: u64 = 5_000_000;
/// Source prototype connection KX deadline, one minute.
pub const PROTO_US: u64 = 60_000_000;
/// Source default rekey interval, one day.
pub const REKEY_US: u64 = 86_400_000_000;
/// Source incoming-address expected lifetime, four hours.
pub const ADDRESS_VALIDITY_US: u64 = 14_400_000_000;
/// Caller-owned nonzero-sized scope. A retained token prevents safe scope reuse.
pub struct Scope {
    _byte: u8,
}
impl Scope {
    /// Create a fresh owner scope. No global atomic/allocator is used.
    #[must_use]
    pub const fn new() -> Self {
        Self { _byte: 0 }
    }
}
impl Default for Scope {
    fn default() -> Self {
        Self::new()
    }
}
/// Role of this physical TCP session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// Initiator already knows the expected remote identity.
    Outbound,
    /// Acceptor authenticates an anonymous initial confirmation.
    Inbound,
}
/// A replay value uses a distinct official PEERSTORE key.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReplayKind {
    /// Initial purpose31 timestamp.
    Handshake,
    /// Challenge-ACK purpose39 timestamp.
    Acknowledgement,
    /// Purpose32 rekey timestamp.
    Rekey,
}
impl ReplayKind {
    fn index(self) -> usize {
        match self {
            Self::Handshake => 0,
            Self::Acknowledgement => 1,
            Self::Rekey => 2,
        }
    }
    /// Exact source PEERSTORE key string, without an added protocol namespace.
    #[must_use]
    pub const fn key(self) -> &'static [u8] {
        match self {
            Self::Handshake => b"transport-tcp-communicator-handshake",
            Self::Acknowledgement => b"transport-tcp-communicator-handshake-ack",
            Self::Rekey => b"transport-tcp-communicator-rekey",
        }
    }
}
/// Bounded host/session policy, separate from any wire/config extensions.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    /// Caller-selected simultaneous original replay-operation credit, from3 to
    /// REPLAY_CAPACITY. This is a local resource profile, never a wire limit.
    pub max_replay_operations: usize,
    /// Source max unread transport completion count (default8).
    pub max_backpressure: usize,
    /// Source byte-rekey upper bound; positive, default400MiB.
    pub rekey_max_bytes: u64,
    /// Source time-rekey interval; u64MAX retains FOREVER semantics.
    pub rekey_interval_us: u64,
    /// Finite entropy rejection attempt limit; no fabricated random success.
    pub entropy_attempts: core::num::NonZeroUsize,
}
impl Policy {
    /// Construct the fixed C byte/profile defaults with an explicit entropy budget.
    #[must_use]
    pub const fn reference(attempts: core::num::NonZeroUsize) -> Self {
        Self {
            max_replay_operations: REPLAY_CAPACITY,
            max_backpressure: 8,
            rekey_max_bytes: 400 * 1024 * 1024,
            rekey_interval_us: REKEY_US,
            entropy_attempts: attempts,
        }
    }
}
/// Source time ports: logical GNUNET absolute scheduler time and the separately
/// generated signed persistent monotime. Logical `now` may move backwards.
#[derive(Clone, Copy, Debug)]
pub struct Time {
    /// Current logical GNUNET_TIME_absolute_get microseconds; may regress.
    /// Relative-to-absolute deadlines saturate to the FOREVER sentinel.
    pub now: u64,
    /// Actual GNUnet persistent-monotime equivalent, used in signatures.
    pub signed: u64,
}
/// One validated owned PILS identity/key pair. No Clone/Debug or secret export.
/// ```compile_fail,E0599
/// use gnunet_tcp_communicator_core::session::KeyRing;
/// let keys=KeyRing::from_seed([3;32]);let duplicate=keys.clone();
/// ```
/// ```compile_fail,E0277
/// use gnunet_tcp_communicator_core::session::KeyRing;
/// let keys=KeyRing::from_seed([3;32]);let exposed=format!("{keys:?}");
/// ```
pub struct KeyRing {
    signing: EddsaPrivateKey,
    exchange: EcdheSecret,
}
impl KeyRing {
    /// Derive both source key forms from one owned EdDSA seed and erase the input.
    #[must_use]
    pub fn from_seed(mut seed: [u8; 32]) -> Self {
        let exchange = EcdheSecret::from_eddsa_seed(seed);
        let signing = EddsaPrivateKey::from_seed(seed);
        seed.zeroize();
        Self { signing, exchange }
    }
    /// Current source public identity; no signing or native authority is exported.
    #[must_use]
    pub fn public(&self) -> EddsaPublicKey {
        self.signing.public_key()
    }
}
/// Immutable identity borrowed for the original session generation. Replacing
/// the current PILS identity requires a different owner; it cannot relabel an
/// existing handshake, ciphertext or rekey operation.
///
/// ```compile_fail,E0506
/// use gnunet_tcp_communicator_core::session::{Identity, KeyRing};
/// let mut keys = KeyRing::from_seed([1; 32]);
/// let original = Identity::from_keys(&keys);
/// keys = KeyRing::from_seed([2; 32]);
/// let _peer = original.public();
/// ```
#[derive(Clone, Copy)]
pub struct Identity<'a> {
    signing: &'a EddsaPrivateKey,
    exchange: &'a EcdheSecret,
}
impl<'a> Identity<'a> {
    /// Validate fixed references for a caller that deliberately fixes its PILS epoch.
    pub fn new(signing: &'a EddsaPrivateKey, exchange: &'a EcdheSecret) -> Result<Self, Error> {
        if EcdhePublic::from_edwards(signing.public_key().as_bytes())? != exchange.public_key() {
            return Err(Error::Authentication);
        }
        Ok(Self { signing, exchange })
    }
    /// Borrow one complete validated original key pair without copying its
    /// secrets or admitting a mutable provider during session operations.
    #[must_use]
    pub const fn from_keys(keys: &'a KeyRing) -> Self {
        Self {
            signing: &keys.signing,
            exchange: &keys.exchange,
        }
    }
    fn with<T>(
        self,
        f: impl FnOnce(&EddsaPrivateKey, &EcdheSecret) -> Result<T, Error>,
    ) -> Result<T, Error> {
        f(self.signing, self.exchange)
    }
    /// Read the original public identity without granting key ownership.
    #[must_use]
    pub fn public(self) -> EddsaPublicKey {
        self.signing.public_key()
    }
}
/// Exclusive buffers; physical IO and IPC drivers retain ownership of their own
/// sockets/queues. These backing buffers are never borrowed from the owner itself.
pub struct Buffers<'a> {
    /// Complete incoming record storage, at least MAX_RECORD65571.
    pub receive: &'a mut [u8],
    /// Persistent ciphertext TX, at least source CIPHERTEXT_CAPACITY131108.
    pub transmit: &'a mut [u8],
    /// One ordered prepared plaintext BOX, at least MAX_RECORD65571.
    pub plaintext: &'a mut [u8],
    /// Caller metadata for bounded transport completion capabilities.
    pub completions: &'a mut [CompletionSlot],
}
/// Completion metadata is caller storage, not a callback or raw native pointer.
#[derive(Default)]
pub struct CompletionSlot {
    serial: u64,
    live: bool,
}
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Kind {
    ReplayStart(ReplayKind),
    ReplayStore(ReplayKind),
    ReplayNext(ReplayKind),
    ReplayCancel(ReplayKind, bool),
    QueueAdd,
    QueueDelete,
    Receive,
    SendContinue,
    Close,
    Write,
}
/// Opaque original effect/completion identity, valid only for its originating scope.
#[derive(Clone, Copy)]
pub struct Ticket<'a> {
    owner: crate::registry::Instance<'a>,
    serial: u64,
    kind: Kind,
    replay_slot: usize,
}
impl PartialEq for Ticket<'_> {
    fn eq(&self, o: &Self) -> bool {
        self.owner == o.owner
            && self.serial == o.serial
            && self.kind == o.kind
            && self.replay_slot == o.replay_slot
    }
}
impl Eq for Ticket<'_> {}
impl Hash for Ticket<'_> {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self.owner.hash(h);
        self.serial.hash(h);
        self.kind.hash(h);
        self.replay_slot.hash(h)
    }
}
impl fmt::Debug for Ticket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ticket")
            .field("serial", &self.serial)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}
/// A physical/service effect; the host must perform exactly this original effect.
#[derive(Clone, Copy, Debug)]
pub enum Effect<'view, 'scope> {
    /// Start a timestamp iterator for this immutable verified peer/kind/value.
    ReplayStart {
        /// Official key kind.
        kind: ReplayKind,
        /// Verified peer.
        peer: EddsaPublicKey,
        /// Received signed monotime, not local wall time.
        received: u64,
    },
    /// Store the exact8-byte BE timestamp, forever/REPLACE, after source comparison.
    ReplayStore {
        /// Original timestamp key.
        kind: ReplayKind,
        /// Verified peer.
        peer: EddsaPublicKey,
        /// Exact received value.
        value: [u8; 8],
    },
    /// Ask the same live iterator for one more record.
    ReplayNext(ReplayKind, Ticket<'scope>),
    /// Cancel the original kind's query(false) or store(true) handle.
    ReplayCancel(ReplayKind, bool, Ticket<'scope>),
    /// Register actual official reliable TCP queue, MTU65535/unlimited/priority0.
    QueueAdd(EddsaPublicKey, Role),
    /// Delete the actual previously registered queue.
    QueueDelete,
    /// Submit the borrowed exact one-message payload with four-hour validity and
    /// this reserved completion capability. Do not retain the borrowed bytes.
    Receive {
        /// Source peer.
        peer: EddsaPublicKey,
        /// Exact already MAC-verified single transport message.
        message: &'view [u8],
        /// Original reserved callback token.
        completion: Ticket<'scope>,
    },
    /// Notify the source MQ only after its plaintext has drained into ciphertext.
    SendContinue,
    /// Close the actual original physical socket; no new/foreign fd may be substituted.
    Close,
}
/// The actual host result of an effect. Started/stored/queued are never inferred.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultKind {
    /// Actual service operation accepted/finished successfully.
    Success,
    /// Actual backend failure or host profile refusal, not fake admission.
    Failed,
    /// Receive was actually queued and owns its promised callback.
    Queued,
    /// Source receive returns SYSERR while TRANSPORT is not available.
    Unavailable,
    /// Source receive returns NO rather than creating callback credit.
    Dropped,
}
/// Bounded diagnostic counters; failure is observable without inventing success.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Diagnostics {
    /// Actual PEERSTORE store admission/callback failures.
    pub replay_store_failures: u64,
    /// Actual TRANSPORT completion failures.
    pub receive_failures: u64,
    /// Explicit service/profile admission failures.
    pub admission_failures: u64,
    /// Original native close returned an error while consuming its authority.
    pub close_failures: u64,
}
/// Distinct source native-write result classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteResult {
    /// Positive actual syscall bytes.
    Bytes(usize),
    /// EAGAIN or EINTR, with no successful progress.
    Retry,
    /// Actual zero send, preserved/rearmed as C does.
    Zero,
    /// Fatal native failure.
    Fatal,
}
/// Source-visible session phase, never a fictional ready connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Connected native stream waits for its initial key exchange.
    Initial,
    /// Verified initial message waits for actual replay-operation admission.
    InitialReplay,
    /// A source challenge response is outstanding.
    AwaitingAck,
    /// ACK verified, actual transport queue registration still pending.
    Registering,
    /// Actual queue-add host result succeeded.
    Established,
    /// Existing records then one FINISH must flush or reach the fixed hard deadline.
    Finishing,
    /// Actual service/native cleanup effects are outstanding.
    Closing,
    /// Native resource closed; only original completion callbacks may remain.
    Detached,
    /// Every original completion has drained.
    Closed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplayState {
    Idle,
    StartReady,
    Waiting,
    StoreReady,
    Storing,
    NextReady,
    Cancel,
}
#[derive(Clone, Copy)]
struct Replay {
    kind: ReplayKind,
    serial: u64,
    store_serial: u64,
    state: ReplayState,
    received: u64,
    query: bool,
    store: bool,
}
impl Replay {
    const EMPTY: Self = Self {
        kind: ReplayKind::Handshake,
        serial: 0,
        store_serial: 0,
        state: ReplayState::Idle,
        received: 0,
        query: false,
        store: false,
    };
}
#[derive(Clone, Copy)]
enum Pending {
    None,
    InitialResponse,
    InitialAck,
    Record,
    Rekey,
}
struct PreparedInitial {
    bytes: [u8; wire::INITIAL_KX],
    direction: Direction,
    challenge: [u8; 32],
    budget: u64,
}
/// Explicit no-allocation resource profile: two initial replay operations plus
/// up to thirty overlapping original rekey operations. Exhaustion is an error,
/// never permission to reuse a live query or delay switching an admitted cipher.
pub const REPLAY_CAPACITY: usize = 32;

/// Exclusively owned bounded session with immutable leased service/native effects.
/// Closing lanes and original completion callbacks remain usable after ordinary
/// serial exhaustion; no physical native handle is cloned or invented here.
pub struct Session<'a> {
    instance: crate::registry::Instance<'a>,
    identity: Identity<'a>,
    role: Role,
    policy: Policy,
    phase: Phase,
    target: Option<EddsaPublicKey>,
    initial: [u8; wire::INITIAL_KX],
    initial_filled: usize,
    receive_storage: Option<&'a mut [u8]>,
    incoming: Option<Receiver<'a>>,
    outgoing: Option<Direction>,
    tx: &'a mut [u8],
    tx_len: usize,
    plain: &'a mut [u8],
    plain_len: usize,
    completions: &'a mut [CompletionSlot],
    backpressure: usize,
    challenge: [u8; 32],
    remote_challenge: [u8; 32],
    timeout: u64,
    finish_deadline: u64,
    finish_pending: bool,
    rekey_deadline: u64,
    rekey_left: u64,
    serial: u64,
    leased: Option<Ticket<'a>>,
    write_lease: Option<Ticket<'a>>,
    write_limit: usize,
    write_scheduled: bool,
    replay: [Replay; REPLAY_CAPACITY],
    latest_monotime: [u64; 3],
    replay_cursor: usize,
    replay_first: bool,
    pending: Pending,
    pending_rekey: Option<Prk>,
    advertised: bool,
    queue_add: bool,
    queue_delete: bool,
    continue_send: bool,
    mq_waiting: bool,
    close: bool,
    receive_ready: bool,
    initial_verified: bool,
    unverified_size: usize,
    diagnostics: Diagnostics,
    metrics: crate::metrics::Metrics,
}
fn after(now: u64, delay: u64) -> u64 {
    now.saturating_add(delay)
}
fn expired(deadline: u64, now: u64) -> bool {
    deadline != u64::MAX && now >= deadline
}
impl<'a> Session<'a> {
    /// Attach a caller-owned physical connection attempt/accepted stream. The
    /// host retains its unique native authority and gates IO on actual connection
    /// progress; this constructor never reports that a native connect succeeded.
    pub fn new(
        scope: &'a mut Scope,
        identity: Identity<'a>,
        target: Option<EddsaPublicKey>,
        buffers: Buffers<'a>,
        policy: Policy,
        time: Time,
        entropy: &mut impl Entropy,
    ) -> Result<Self, Error> {
        Self::construct(
            crate::registry::Instance {
                scope,
                slot: 0,
                generation: 1,
            },
            identity,
            target,
            buffers,
            policy,
            time,
            entropy,
        )
        .map_err(|rejected| rejected.reason)
    }
    /// Consume the unique registry constructor right. Rejection returns both the
    /// original right and every original buffer unchanged, including entropy failure.
    #[cfg_attr(
        target_pointer_width = "64",
        expect(
            clippy::result_large_err,
            reason = "No-allocation rejection preserves the unique admission and every original caller buffer"
        )
    )]
    pub fn managed(
        admission: crate::registry::Admission<'a>,
        identity: Identity<'a>,
        buffers: Buffers<'a>,
        policy: Policy,
        time: Time,
        entropy: &mut impl Entropy,
    ) -> Result<Self, Rejected<(crate::registry::Admission<'a>, Buffers<'a>)>> {
        Self::construct(
            admission.instance,
            identity,
            admission.target,
            buffers,
            policy,
            time,
            entropy,
        )
        .map_err(|rejected| Rejected {
            reason: rejected.reason,
            value: (admission, rejected.value),
        })
    }
    fn construct(
        instance: crate::registry::Instance<'a>,
        identity: Identity<'a>,
        target: Option<EddsaPublicKey>,
        buffers: Buffers<'a>,
        policy: Policy,
        time: Time,
        entropy: &mut impl Entropy,
    ) -> Result<Self, Rejected<Buffers<'a>>> {
        if buffers.receive.len() < wire::MAX_RECORD
            || buffers.transmit.len() < CIPHERTEXT_CAPACITY
            || buffers.plaintext.len() < wire::MAX_RECORD
            || buffers.completions.len() < policy.max_backpressure
            || policy.rekey_max_bytes == 0
            || !(3..=REPLAY_CAPACITY).contains(&policy.max_replay_operations)
        {
            return Err(Rejected {
                reason: Error::Capacity,
                value: buffers,
            });
        }
        let role = if target.is_some() {
            Role::Outbound
        } else {
            Role::Inbound
        };
        let prepared = if let Some(target) = target {
            match Self::prepare_initial(identity, target, policy, time, entropy) {
                Ok(p) => Some(p),
                Err(reason) => {
                    return Err(Rejected {
                        reason,
                        value: buffers,
                    });
                }
            }
        } else {
            None
        };
        for slot in buffers.completions.iter_mut() {
            *slot = CompletionSlot::default();
        }
        let mut s = Self {
            instance,
            identity,
            role,
            policy,
            phase: Phase::Initial,
            target,
            initial: [0; wire::INITIAL_KX],
            initial_filled: 0,
            receive_storage: Some(buffers.receive),
            incoming: None,
            outgoing: None,
            tx: buffers.transmit,
            tx_len: 0,
            plain: buffers.plaintext,
            plain_len: 0,
            completions: buffers.completions,
            backpressure: 0,
            challenge: [0; 32],
            remote_challenge: [0; 32],
            timeout: after(
                time.now,
                if role == Role::Inbound {
                    PROTO_US
                } else {
                    IDLE_US
                },
            ),
            finish_deadline: u64::MAX,
            finish_pending: false,
            rekey_deadline: u64::MAX,
            rekey_left: 0,
            serial: 0,
            leased: None,
            write_lease: None,
            write_limit: 0,
            write_scheduled: false,
            replay: [Replay::EMPTY; REPLAY_CAPACITY],
            latest_monotime: [0; 3],
            replay_cursor: 0,
            replay_first: true,
            pending: Pending::None,
            pending_rekey: None,
            advertised: false,
            queue_add: false,
            queue_delete: false,
            continue_send: false,
            mq_waiting: false,
            close: false,
            receive_ready: false,
            initial_verified: false,
            unverified_size: 0,
            diagnostics: Diagnostics::default(),
            metrics: crate::metrics::Metrics::default(),
        };
        if let Some(prepared) = prepared {
            s.tx[..wire::INITIAL_KX].copy_from_slice(&prepared.bytes);
            s.tx_len = wire::INITIAL_KX;
            s.write_scheduled = true;
            s.outgoing = Some(prepared.direction);
            s.challenge = prepared.challenge;
            s.rekey_left = prepared.budget;
            s.rekey_deadline = after(time.now, policy.rekey_interval_us);
        }
        Ok(s)
    }
    /// Original physical-session generation, without socket or queue authority.
    #[must_use]
    pub const fn instance(&self) -> crate::registry::Instance<'a> {
        self.instance
    }
    /// Return original caller backing only after every actual original resource
    /// and completion was closed. Rejection preserves this unique live session.
    #[expect(
        clippy::result_large_err,
        reason = "No-alloc rejection must return the unique original session and cipher authority"
    )]
    pub fn into_buffers(mut self) -> Result<Buffers<'a>, Rejected<Self>> {
        if self.phase != Phase::Closed {
            return Err(Rejected {
                reason: Error::WouldBlock,
                value: self,
            });
        }
        let Some(receive) = self.receive_storage.take() else {
            return Err(Rejected {
                reason: Error::Conflict,
                value: self,
            });
        };
        Ok(Buffers {
            receive,
            transmit: core::mem::take(&mut self.tx),
            plaintext: core::mem::take(&mut self.plain),
            completions: core::mem::take(&mut self.completions),
        })
    }
    /// Current physical/cryptographic/queue phase, with no inferred host success.
    #[must_use]
    pub const fn phase(&self) -> Phase {
        self.phase
    }
    /// Original physical initiation role, preserved across local IPC reconnection.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }
    /// The authenticated remote identity, or outbound target before KX verification.
    #[must_use]
    pub const fn target(&self) -> Option<EddsaPublicKey> {
        self.target
    }
    /// Initial signature-verified peer, separate from an expected outbound target.
    /// Replay processing, challenge completion and actual queue admission are separate.
    #[must_use]
    pub fn authenticated_target(&self) -> Option<EddsaPublicKey> {
        if self.incoming.is_some() {
            self.target
        } else {
            None
        }
    }
    /// Original host/service failure observations; counters saturate.
    #[must_use]
    pub const fn diagnostics(&self) -> Diagnostics {
        self.diagnostics
    }
    /// Actual outstanding source receive completion count.
    #[must_use]
    pub const fn backpressure(&self) -> usize {
        self.backpressure
    }
    /// Current persistent ciphertext bytes, excluding no partially consumed prefix.
    #[must_use]
    pub const fn pending_transmit(&self) -> usize {
        self.tx_len
    }
    /// Preserve an earlier actual native-admission preamble deadline. This only
    /// narrows a still-initial session; it does not restart a proto timer or
    /// change any successful KX/ordinary IDLE behavior.
    pub fn limit_initial_deadline(&mut self, until: u64) -> Result<(), Error> {
        if self.phase != Phase::Initial || until == u64::MAX {
            return Err(Error::InvalidInput);
        }
        self.timeout = self.timeout.min(until);
        Ok(())
    }
    /// Source timer deadline. Native read interest may be flow-controlled separately.
    #[must_use]
    pub fn deadline(&self) -> Option<u64> {
        match self.phase {
            Phase::Finishing => Some(self.finish_deadline),
            Phase::Initial
            | Phase::InitialReplay
            | Phase::AwaitingAck
            | Phase::Registering
            | Phase::Established => {
                if self.read_interest() {
                    Some(self.timeout)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
    /// True only when the source would have an enabled ordinary read task.
    #[must_use]
    pub fn read_interest(&self) -> bool {
        match self.phase {
            Phase::Initial => true,
            Phase::AwaitingAck => !self.receive_ready && matches!(self.pending, Pending::None),
            Phase::Established | Phase::Finishing => {
                !self.receive_ready
                    && self.backpressure < self.policy.max_backpressure
                    && matches!(self.pending, Pending::None)
            }
            _ => false,
        }
    }
    /// Whether an actual writable turn is requested (readiness alone is not progress).
    #[must_use]
    pub fn write_interest(&self) -> bool {
        !matches!(self.phase, Phase::Closing | Phase::Detached | Phase::Closed)
            && (self.write_scheduled || self.write_lease.is_some())
    }
    fn mint(&mut self, kind: Kind) -> Result<Ticket<'a>, Error> {
        let Some(next) = self.serial.checked_add(1) else {
            self.destroy();
            return Err(Error::Capacity);
        };
        self.serial = next;
        Ok(Ticket {
            owner: self.instance,
            serial: next,
            kind,
            replay_slot: usize::MAX,
        })
    }
    fn original(&self, t: Ticket<'_>) -> bool {
        self.instance == t.owner
    }
    fn control(&self, kind: Kind, serial: u64) -> Ticket<'a> {
        Ticket {
            owner: self.instance,
            serial,
            kind,
            replay_slot: usize::MAX,
        }
    }
    fn replay_control(&self, kind: Kind, serial: u64, slot: usize) -> Ticket<'a> {
        let mut t = self.control(kind, serial);
        t.replay_slot = slot;
        t
    }
    fn replay_mint(&mut self, kind: Kind, slot: usize) -> Result<Ticket<'a>, Error> {
        let mut t = self.mint(kind)?;
        t.replay_slot = slot;
        Ok(t)
    }
    fn fill(entropy: &mut impl Entropy, out: &mut [u8]) -> Result<(), Error> {
        if entropy.fill(out).is_err() {
            out.zeroize();
            Err(Error::Entropy)
        } else {
            Ok(())
        }
    }
    fn random_below(policy: Policy, entropy: &mut impl Entropy) -> Result<u64, Error> {
        let max = policy.rekey_max_bytes;
        let limit = u64::MAX - (u64::MAX % max);
        for _ in 0..policy.entropy_attempts.get() {
            let mut b = [0; 8];
            Self::fill(entropy, &mut b)?;
            let value = u64::from_ne_bytes(b);
            if value < limit {
                return Ok(value % max);
            }
        }
        Err(Error::Entropy)
    }
    fn prepare_initial(
        identity: Identity<'a>,
        target: EddsaPublicKey,
        policy: Policy,
        time: Time,
        entropy: &mut impl Entropy,
    ) -> Result<PreparedInitial, Error> {
        let mut tweak = [0];
        Self::fill(entropy, &mut tweak)?;
        let special = elligator::Secret::generate(entropy, policy.entropy_attempts)?;
        let budget = Self::random_below(policy, entropy)?;
        let mut challenge = [0; 32];
        Self::fill(entropy, &mut challenge)?;
        let (bytes, direction) = identity.with(|signing, _| {
            initial::prepare(signing, target, &special, tweak[0], time.signed, &challenge)
        })?;
        Ok(PreparedInitial {
            bytes,
            direction,
            challenge,
            budget,
        })
    }
    fn make_initial(&mut self, time: Time, entropy: &mut impl Entropy) -> Result<(), Error> {
        if self.tx.len() - self.tx_len < wire::INITIAL_KX {
            return Err(Error::Capacity);
        }
        let prepared = Self::prepare_initial(
            self.identity,
            self.target.ok_or(Error::NotReady)?,
            self.policy,
            time,
            entropy,
        )?;
        self.tx[self.tx_len..self.tx_len + wire::INITIAL_KX].copy_from_slice(&prepared.bytes);
        self.tx_len += wire::INITIAL_KX;
        self.write_scheduled = true;
        self.outgoing = Some(prepared.direction);
        self.challenge = prepared.challenge;
        self.rekey_left = prepared.budget;
        self.rekey_deadline = after(time.now, self.policy.rekey_interval_us);
        Ok(())
    }
    fn send_ack(&mut self, time: Time) -> Result<(), Error> {
        let target = self.target.ok_or(Error::NotReady)?;
        if self.tx.len() - self.tx_len < wire::ACK {
            return Err(Error::Capacity);
        }
        let mut ack = self.identity.with(|signing, _| {
            wire::acknowledgement(signing, target, time.signed, &self.remote_challenge)
        })?;
        self.outgoing
            .as_mut()
            .ok_or(Error::NotReady)?
            .handshake_fragment(&mut ack)?;
        self.tx[self.tx_len..self.tx_len + ack.len()].copy_from_slice(&ack);
        self.tx_len += ack.len();
        self.write_scheduled = true;
        Ok(())
    }
    fn replay_start(&mut self, kind: ReplayKind, received: u64) -> Result<(), Error> {
        if received < self.latest_monotime[kind.index()] {
            self.destroy();
            return Err(Error::Replay);
        }
        let slot = if kind == ReplayKind::Rekey {
            let slot = (2..self.policy.max_replay_operations).find(|i| {
                self.replay[*i].state == ReplayState::Idle
                    && !self.replay[*i].query
                    && !self.replay[*i].store
            });
            let Some(slot) = slot else {
                self.diagnostics.admission_failures =
                    self.diagnostics.admission_failures.saturating_add(1);
                self.destroy();
                return Err(Error::Capacity);
            };
            slot
        } else {
            let i = kind.index();
            if self.replay[i].state != ReplayState::Idle {
                return Err(Error::WouldBlock);
            }
            i
        };
        let ticket = self.replay_mint(Kind::ReplayStart(kind), slot)?;
        self.latest_monotime[kind.index()] = received;
        self.replay[slot] = Replay {
            kind,
            serial: ticket.serial,
            store_serial: 0,
            state: ReplayState::StartReady,
            received,
            query: false,
            store: false,
        };
        Ok(())
    }
    /// Actual lifetime counters plus current locally registered queue state.
    /// This borrows no key, samples no clock and submits no native operation.
    #[must_use]
    pub fn metrics(&self) -> crate::metrics::Metrics {
        let mut metrics = self.metrics;
        metrics.queue(self.advertised);
        metrics
    }
    /// Feed owned-host ciphertext already read from the original socket. A return
    /// smaller than input retains the rest in the host's persistent RX buffer.
    /// Native progress is accounted once using native_read_progress, not on retries.
    pub fn ingest(
        &mut self,
        input: &[u8],
        time: Time,
        entropy: &mut impl Entropy,
    ) -> Result<usize, Error> {
        if matches!(self.phase, Phase::Closing | Phase::Detached | Phase::Closed) {
            return Err(Error::Closed);
        }
        if self.phase == Phase::Finishing && expired(self.finish_deadline, time.now) {
            self.destroy();
            return Err(Error::Deadline);
        }
        if self.phase == Phase::Initial {
            if expired(self.timeout, time.now) {
                self.destroy();
                return Err(Error::Deadline);
            }
            let n = core::cmp::min(wire::INITIAL_KX - self.initial_filled, input.len());
            self.initial[self.initial_filled..self.initial_filled + n].copy_from_slice(&input[..n]);
            self.initial_filled += n;
            if self.initial_filled == wire::INITIAL_KX {
                let opened = match self.identity.with(|signing, exchange| {
                    initial::open(
                        signing.public_key(),
                        exchange,
                        if self.role == Role::Outbound {
                            self.target
                        } else {
                            None
                        },
                        &self.initial,
                    )
                }) {
                    Ok(x) => x,
                    Err(e) => {
                        self.destroy();
                        return Err(e);
                    }
                };
                let sender = opened.sender();
                let monotonic = opened.monotonic();
                self.remote_challenge = *opened.challenge();
                self.target = Some(sender);
                let storage = self.receive_storage.take().ok_or(Error::NotReady)?;
                self.incoming = Some(
                    Receiver::with_direction(opened.into_direction(), storage)
                        .map_err(|r| r.reason)?,
                );
                self.initial.zeroize();
                self.initial_filled = 0;
                self.replay_start(ReplayKind::Handshake, monotonic)?;
                self.phase = Phase::InitialReplay;
                self.pending = if self.role == Role::Inbound {
                    Pending::InitialResponse
                } else {
                    Pending::InitialAck
                };
            }
            return Ok(n);
        }
        if !self.read_interest() {
            return Ok(0);
        }
        let receiver = self.incoming.as_mut().ok_or(Error::NotReady)?;
        let n = match receiver.push(input) {
            Ok(n) => n,
            Err(Error::WouldBlock) => 0,
            Err(e) => {
                self.finish(time)?;
                return Err(e);
            }
        };
        let first_verification = !receiver.is_verified();
        match receiver.record() {
            Ok(record) => {
                if first_verification && let Record::Box(payload) = record {
                    self.metrics.box_decrypted(payload.len());
                }
                self.pending = Pending::Record;
            }
            Err(Error::WouldBlock) => return Ok(n),
            Err(e) => {
                self.finish(time)?;
                return Err(e);
            }
        }
        self.process_record(time, entropy)?;
        Ok(n)
    }
    /// Record a real positive recv once. Ordinary reads refresh before parsing;
    /// KX keeps its original source deadline until its successful completion.
    pub fn native_read_progress(&mut self, now: u64) {
        if self.phase != Phase::Initial
            && !matches!(self.phase, Phase::Closing | Phase::Detached | Phase::Closed)
        {
            self.timeout = after(now, IDLE_US)
        }
    }
    /// Record actual physical EOF/fatal loss and retire this original stream.
    /// No new record or send continuation is produced. Any already-issued write
    /// and original service/completion leases must still receive their real
    /// results before close can return the caller's backing storage.
    /// A caller aborting a send must close its actual native owner and use this
    /// terminal path; it cannot remove an admitted BOX then reuse its MAC stream.
    pub fn native_lost(&mut self) {
        self.destroy();
    }
    /// Process deferred crypto work after a real backend/resource becomes available.
    pub fn progress(&mut self, time: Time, entropy: &mut impl Entropy) -> Result<(), Error> {
        if matches!(
            self.phase,
            Phase::Finishing | Phase::Closing | Phase::Detached | Phase::Closed
        ) {
            return Ok(());
        }
        match self.pending {
            Pending::InitialResponse if self.replay[0].query => {
                self.make_initial(time, entropy)?;
                self.pending = Pending::None;
                self.phase = Phase::AwaitingAck;
                self.timeout = after(time.now, IDLE_US);
            }
            Pending::InitialAck if self.replay[0].query => {
                self.send_ack(time)?;
                self.pending = Pending::None;
                self.phase = Phase::AwaitingAck;
                self.timeout = after(time.now, IDLE_US);
            }
            Pending::Record => self.process_record(time, entropy)?,
            _ => {}
        }
        Ok(())
    }
    fn process_record(&mut self, time: Time, _entropy: &mut impl Entropy) -> Result<(), Error> {
        if !matches!(self.pending, Pending::Record) {
            return Ok(());
        }
        if !self.initial_verified && self.unverified_size > 256 {
            self.finish(time)?;
            return Err(Error::PermissionDenied);
        }
        let receiver = self.incoming.as_ref().ok_or(Error::NotReady)?;
        let record = receiver.verified_record()?;
        match record {
            Record::Ack(bytes) => {
                if self.phase != Phase::AwaitingAck {
                    self.finish(time)?;
                    return Err(Error::Malformed);
                }
                if self.replay[1].state != ReplayState::Idle {
                    return Ok(());
                }
                if let Err(e) = wire::verify_ack(bytes, self.identity.public(), &self.challenge) {
                    self.finish(time)?;
                    return Err(e);
                }
                let stamp =
                    u64::from_be_bytes(bytes[100..108].try_into().map_err(|_| Error::Malformed)?);
                self.replay_start(ReplayKind::Acknowledgement, stamp)?;
                self.incoming.as_mut().ok_or(Error::NotReady)?.release()?;
                self.pending = Pending::None;
                self.phase = Phase::Registering;
                self.unverified_size = self.unverified_size.saturating_add(wire::ACK);
                // Source begins the ACK replay query before role-specific challenge echo
                // and actual queue advertisement. These follow its real start result.
            }
            Record::Box(bytes) => {
                if bytes.len() < 4
                    || u16::from_be_bytes([bytes[0], bytes[1]]) as usize != bytes.len()
                {
                    let n = bytes.len() + wire::BOX_PREFIX;
                    self.incoming.as_mut().ok_or(Error::NotReady)?.release()?;
                    self.unverified_size = self.unverified_size.saturating_add(n);
                    self.pending = Pending::None;
                    return Ok(());
                }
                if self.completions.iter().all(|s| s.live) {
                    return Ok(());
                }
                self.receive_ready = true;
                self.pending = Pending::None;
            }
            Record::Rekey(bytes) => {
                let target = self.target.ok_or(Error::NotReady)?;
                let (enc, stamp) = match wire::verify_rekey(bytes, target, self.identity.public()) {
                    Ok(x) => x,
                    Err(e) => {
                        self.finish(time)?;
                        return Err(e);
                    }
                };
                let prk = match self.identity.with(|_, exchange| {
                    exchange::kem_decapsulate(exchange, EcdhePublic::from_bytes(enc))
                }) {
                    Ok(p) => p,
                    Err(e) => {
                        self.finish(time)?;
                        return Err(e);
                    }
                };
                self.replay_start(ReplayKind::Rekey, stamp)?;
                self.pending_rekey = Some(prk);
                self.pending = Pending::Rekey;
            }
            Record::Finish => {
                self.destroy();
            }
        }
        Ok(())
    }
    /// Source MQ admission stages the entire unencrypted BOX and advances its MAC.
    /// A staged BOX is committed to this ordered MAC stream; it must drain
    /// before another admission. There is no single-message cancellation.
    /// Finishing refuses new sends without touching the old MQ wait or ratchet.
    pub fn send(&mut self, message: &[u8]) -> Result<(), Error> {
        if self.phase != Phase::Established {
            return Err(Error::NotReady);
        }
        if self.plain_len != 0 || self.mq_waiting {
            return Err(Error::WouldBlock);
        }
        let n = self
            .outgoing
            .as_mut()
            .ok_or(Error::NotReady)?
            .stage_box(message, self.plain)?;
        self.plain_len = n;
        self.write_scheduled = true;
        self.mq_waiting = true;
        Ok(())
    }
    fn pump_write(&mut self, time: Time, entropy: &mut impl Entropy) -> Result<(), Error> {
        let result = self.pump_write_inner(time, entropy);
        self.write_scheduled =
            !matches!(self.phase, Phase::Closing | Phase::Detached | Phase::Closed)
                && (self.tx_len > 0
                    || self.plain_len > 0
                    || (self.mq_waiting && !self.continue_send));
        result
    }
    fn pump_write_inner(&mut self, time: Time, entropy: &mut impl Entropy) -> Result<(), Error> {
        if self.phase == Phase::Finishing && expired(self.finish_deadline, time.now) {
            self.destroy();
            return Ok(());
        }
        // A staged BOX already consumed the next MAC key. Preserve its original
        // plaintext and all earlier ciphertext; generate the single FINISH only
        // after those complete records have actually drained from native TX.
        if self.phase == Phase::Finishing
            && self.finish_pending
            && self.plain_len == 0
            && self.tx_len == 0
        {
            let n = self
                .outgoing
                .as_mut()
                .ok_or(Error::NotReady)?
                .stage_finish(self.plain)?;
            self.plain_len = n;
            self.finish_pending = false;
        }
        if self.plain_len > 0 && self.tx.len() - self.tx_len >= self.plain_len {
            let n = self.plain_len;
            self.outgoing
                .as_mut()
                .ok_or(Error::NotReady)?
                .encrypt_prepared(&self.plain[..n], &mut self.tx[self.tx_len..])?;
            self.tx_len += n;
            self.rekey_left = self.rekey_left.saturating_sub(n as u64);
            self.plain[..n].zeroize();
            self.plain_len = 0;
        }
        if self.phase != Phase::Finishing
            && (self.rekey_left == 0 || expired(self.rekey_deadline, time.now))
            && self.plain_len == 0
            && self.tx.len() - self.tx_len >= wire::REKEY
            && self.outgoing.is_some()
        {
            let budget = Self::random_below(self.policy, entropy)?;
            let ephemeral = EcdheSecret::generate(entropy)?;
            let (enc, prk) = exchange::kem_encapsulate(
                EcdhePublic::from_edwards(self.target.ok_or(Error::NotReady)?.as_bytes())?,
                &ephemeral,
            )?;
            let plain = self.identity.with(|signing, _| {
                wire::rekey(
                    signing,
                    self.target.ok_or(Error::NotReady)?,
                    enc.as_bytes(),
                    time.signed,
                )
            })?;
            let n = self.outgoing.as_mut().ok_or(Error::NotReady)?.seal_rekey(
                &plain,
                &prk,
                &mut self.tx[self.tx_len..],
            )?;
            self.tx_len += n;
            self.rekey_left = budget;
            self.rekey_deadline = after(time.now, self.policy.rekey_interval_us);
        }
        if self.plain_len == 0 && self.phase != Phase::Finishing && self.mq_waiting {
            self.continue_send = true;
        }
        if self.phase == Phase::Finishing
            && !self.finish_pending
            && self.tx_len == 0
            && self.plain_len == 0
        {
            self.destroy();
        }
        Ok(())
    }
    /// Enter one actual writable scheduler turn. An empty TX turn can encrypt
    /// pending whole plaintext without pretending a zero-byte syscall occurred.
    pub fn write_ready(
        &mut self,
        time: Time,
        entropy: &mut impl Entropy,
    ) -> Result<Option<Ticket<'a>>, Error> {
        if let Some(ticket) = self.write_lease {
            return Ok(Some(ticket));
        }
        // An already-issued write above keeps its original authority. Before
        // any new lease/crypto, enforce the fixed close bound even when ready
        // input/output would otherwise keep a native timer from being polled.
        if self.phase == Phase::Finishing && expired(self.finish_deadline, time.now) {
            self.destroy();
            return Ok(None);
        }
        if !self.write_interest() {
            return Ok(None);
        }
        self.write_scheduled = false;
        if self.tx_len == 0 {
            self.pump_write(time, entropy)?;
            if self.tx_len == 0 {
                return Ok(None);
            }
        }
        // A newly prepared FINISH has no SendContinue effect to wake the host.
        // Lease its actual ciphertext in this same writable turn; preparing it
        // is not a syscall result and does not consume any transmitted bytes.
        let ticket = self.mint(Kind::Write)?;
        self.write_lease = Some(ticket);
        self.write_limit = self.tx_len;
        Ok(Some(ticket))
    }
    /// Borrow original persistent ciphertext for one immutable original write lease.
    pub fn write_bytes(&self, ticket: Ticket<'_>) -> Result<&[u8], Error> {
        if !self.original(ticket) || self.write_lease != Some(ticket) {
            return Err(Error::Stale);
        }
        Ok(&self.tx[..self.write_limit])
    }
    /// Commit only an actual syscall result. Retry/zero retain exact bytes and
    /// positive partial writes refresh idle and preserve all remaining ciphertext.
    pub fn written(
        &mut self,
        ticket: Ticket<'_>,
        result: WriteResult,
        time: Time,
        entropy: &mut impl Entropy,
    ) -> Result<(), Error> {
        if !self.original(ticket) || self.write_lease != Some(ticket) {
            return Err(Error::Stale);
        }
        match result {
            WriteResult::Bytes(n) => {
                if n == 0 || n > self.write_limit {
                    return Err(Error::InvalidInput);
                }
                self.tx.copy_within(n..self.tx_len, 0);
                self.tx[self.tx_len - n..self.tx_len].zeroize();
                self.tx_len -= n;
                self.timeout = after(time.now, IDLE_US)
            }
            WriteResult::Retry | WriteResult::Zero => {}
            WriteResult::Fatal => {
                self.write_lease = None;
                self.destroy();
                return Ok(());
            }
        }
        self.write_lease = None;
        if !matches!(self.phase, Phase::Closing | Phase::Detached | Phase::Closed) {
            self.pump_write(time, entropy)?;
        }
        Ok(())
    }
    /// Begin one bounded authenticated graceful close. Already prepared BOX and
    /// ciphertext keep their original MAC/cipher order; one FINISH follows their
    /// actual drain. Repeated calls preserve that record and the original bound.
    /// No new send is admitted, and no old MQ wait gains a success continuation.
    pub fn finish(&mut self, time: Time) -> Result<(), Error> {
        if matches!(
            self.phase,
            Phase::Finishing | Phase::Closing | Phase::Detached | Phase::Closed
        ) {
            return Ok(());
        }
        if self.outgoing.is_none() {
            self.destroy();
            return Ok(());
        }
        self.phase = Phase::Finishing;
        self.finish_pending = true;
        self.write_scheduled = true;
        self.finish_deadline = after(time.now, FINISH_US);
        self.continue_send = false;
        self.receive_ready = false;
        Ok(())
    }
    /// Apply a real expired scheduled timer. Read-based idle enforcement is only
    /// enabled when its ordinary read task is enabled; FINISH has its own hard cap.
    pub fn tick(&mut self, now: u64) {
        if (self.phase == Phase::Finishing && expired(self.finish_deadline, now))
            || (self.read_interest() && expired(self.timeout, now))
        {
            self.destroy();
        }
    }
    fn destroy(&mut self) {
        if matches!(self.phase, Phase::Closing | Phase::Detached | Phase::Closed) {
            return;
        }
        self.phase = Phase::Closing;
        self.finish_pending = false;
        self.write_scheduled = false;
        self.close = true;
        self.queue_add = false;
        self.queue_delete = self.advertised;
        self.continue_send = false;
        self.mq_waiting = false;
        self.receive_ready = false;
        self.pending = Pending::None;
        self.pending_rekey = None;
        for op in &mut self.replay {
            if op.query || op.store {
                op.state = ReplayState::Cancel
            } else if op.state == ReplayState::StartReady {
                op.state = ReplayState::Idle
            }
        }
        if self.write_lease.is_some() { /* host must still acknowledge original in-flight syscall */
        }
    }
    /// Return an unsubmitted replay start/store lease to the fair effect scheduler.
    /// This submits no service operation and acknowledges no result; an original
    /// older iterator can progress while another start waits for its store barrier.
    pub fn defer_effect(&mut self, ticket: Ticket<'_>) -> Result<(), Error> {
        if !self.original(ticket) || self.leased != Some(ticket) {
            return Err(Error::Stale);
        }
        if !matches!(ticket.kind, Kind::ReplayStart(_) | Kind::ReplayStore(_)) {
            return Err(Error::InvalidInput);
        }
        self.leased = None;
        Ok(())
    }
    /// Lease the next actual service/control operation. An existing lease is
    /// returned unchanged across drive cancellation until its real result arrives.
    pub fn next_effect(&mut self) -> Result<Option<Ticket<'a>>, Error> {
        if let Some(t) = self.leased {
            return Ok(Some(t));
        }
        let closing = self.phase == Phase::Closing;
        if closing {
            for i in 0..REPLAY_CAPACITY {
                let op = self.replay[i];
                let kind = op.kind;
                if op.store {
                    let t = self.replay_control(Kind::ReplayCancel(kind, true), op.store_serial, i);
                    self.leased = Some(t);
                    return Ok(Some(t));
                }
                if op.query {
                    let t = self.replay_control(Kind::ReplayCancel(kind, false), op.serial, i);
                    self.leased = Some(t);
                    return Ok(Some(t));
                }
            }
            if self.queue_delete {
                let t = self.control(Kind::QueueDelete, 0);
                self.leased = Some(t);
                return Ok(Some(t));
            }
            if self.close && self.write_lease.is_none() {
                let t = self.control(Kind::Close, 0);
                self.leased = Some(t);
                return Ok(Some(t));
            }
            return Ok(None);
        }
        if matches!(self.phase, Phase::Detached | Phase::Closed) {
            return Ok(None);
        }
        if !self.replay_first
            && let Some(t) = self.next_ordinary_effect()?
        {
            return Ok(Some(t));
        }
        for offset in 0..self.policy.max_replay_operations {
            let i = (self.replay_cursor + offset) % self.policy.max_replay_operations;
            let op = self.replay[i];
            let kind = op.kind;
            let ticket = match op.state {
                ReplayState::StartReady => {
                    Some(self.replay_control(Kind::ReplayStart(kind), op.serial, i))
                }
                ReplayState::StoreReady => {
                    let t = self.replay_mint(Kind::ReplayStore(kind), i)?;
                    self.replay[i].store_serial = t.serial;
                    Some(t)
                }
                ReplayState::NextReady => Some(self.replay_mint(Kind::ReplayNext(kind), i)?),
                ReplayState::Cancel if op.store => {
                    Some(self.replay_control(Kind::ReplayCancel(kind, true), op.store_serial, i))
                }
                ReplayState::Cancel if op.query => {
                    Some(self.replay_control(Kind::ReplayCancel(kind, false), op.serial, i))
                }
                _ => None,
            };
            if let Some(t) = ticket {
                self.leased = Some(t);
                self.replay_cursor = (i + 1) % self.policy.max_replay_operations;
                self.replay_first = false;
                return Ok(Some(t));
            }
        }
        self.next_ordinary_effect()
    }
    fn next_ordinary_effect(&mut self) -> Result<Option<Ticket<'a>>, Error> {
        if self.queue_add {
            let t = self.mint(Kind::QueueAdd)?;
            self.leased = Some(t);
            self.replay_first = true;
            return Ok(Some(t));
        }
        if self.continue_send {
            let t = self.mint(Kind::SendContinue)?;
            self.leased = Some(t);
            self.replay_first = true;
            return Ok(Some(t));
        }
        if self.receive_ready
            && let Some(slot) = self.completions.iter().position(|s| !s.live)
        {
            let t = self.mint(Kind::Receive)?;
            self.completions[slot].serial = t.serial;
            self.leased = Some(t);
            self.replay_first = true;
            return Ok(Some(t));
        }
        Ok(None)
    }
    /// Borrow the immutable operation of the exact current lease. Payload and
    /// completion lifetimes are separate: the host may retain only the token.
    /// ```compile_fail,E0502
    /// use gnunet_tcp_communicator_core::session::{Session,Ticket,ResultKind,Time};
    /// use gnunet_crypto::Entropy;
    /// fn retained<'a>(session:&mut Session<'a>,ticket:Ticket<'a>,rng:&mut impl Entropy){
    ///   let borrowed=session.effect(ticket).unwrap();
    ///   session.acknowledge(ticket,ResultKind::Queued,Time{now:1,signed:1},rng).unwrap();
    ///   let still_used=borrowed;
    /// }
    /// ```
    pub fn effect(&self, ticket: Ticket<'_>) -> Result<Effect<'_, 'a>, Error> {
        if !self.original(ticket) || self.leased != Some(ticket) {
            return Err(Error::Stale);
        }
        let peer = self.target;
        Ok(match ticket.kind {
            Kind::ReplayStart(kind) => Effect::ReplayStart {
                kind,
                peer: peer.ok_or(Error::NotReady)?,
                received: self.replay[ticket.replay_slot].received,
            },
            Kind::ReplayStore(kind) => Effect::ReplayStore {
                kind,
                peer: peer.ok_or(Error::NotReady)?,
                value: self.latest_monotime[kind.index()].to_be_bytes(),
            },
            Kind::ReplayNext(kind) => Effect::ReplayNext(
                kind,
                self.replay_control(
                    Kind::ReplayStart(kind),
                    self.replay[ticket.replay_slot].serial,
                    ticket.replay_slot,
                ),
            ),
            Kind::ReplayCancel(kind, store) => Effect::ReplayCancel(
                kind,
                store,
                self.replay_control(
                    if store {
                        Kind::ReplayStore(kind)
                    } else {
                        Kind::ReplayStart(kind)
                    },
                    if store {
                        self.replay[ticket.replay_slot].store_serial
                    } else {
                        self.replay[ticket.replay_slot].serial
                    },
                    ticket.replay_slot,
                ),
            ),
            Kind::QueueAdd => Effect::QueueAdd(peer.ok_or(Error::NotReady)?, self.role),
            Kind::QueueDelete => Effect::QueueDelete,
            Kind::SendContinue => Effect::SendContinue,
            Kind::Close => Effect::Close,
            Kind::Receive => {
                let Record::Box(message) = self
                    .incoming
                    .as_ref()
                    .ok_or(Error::NotReady)?
                    .verified_record()?
                else {
                    return Err(Error::Conflict);
                };
                Effect::Receive {
                    peer: peer.ok_or(Error::NotReady)?,
                    message,
                    completion: self.control(Kind::Receive, ticket.serial),
                }
            }
            Kind::Write => return Err(Error::InvalidInput),
        })
    }
    /// Acknowledge an effect only after the original host operation actually ran.
    /// Callback-producing operations remain independently live until their callback.
    pub fn acknowledge(
        &mut self,
        ticket: Ticket<'_>,
        result: ResultKind,
        time: Time,
        entropy: &mut impl Entropy,
    ) -> Result<(), Error> {
        if !self.original(ticket) || self.leased != Some(ticket) {
            return Err(Error::Stale);
        }
        if !match ticket.kind {
            Kind::Receive => matches!(
                result,
                ResultKind::Queued
                    | ResultKind::Unavailable
                    | ResultKind::Dropped
                    | ResultKind::Failed
            ),
            _ => matches!(result, ResultKind::Success | ResultKind::Failed),
        } {
            return Err(Error::InvalidInput);
        }
        self.leased = None;
        if result == ResultKind::Failed {
            self.diagnostics.admission_failures =
                self.diagnostics.admission_failures.saturating_add(1);
        }
        // Original pre-close callback leases still retire, but their result
        // cannot reopen a graceful close or start a fresh ACK/rekey direction.
        let closing = matches!(self.phase, Phase::Finishing | Phase::Closing);
        match ticket.kind {
            Kind::ReplayStart(kind) => {
                let op = &mut self.replay[ticket.replay_slot];
                if op.serial != ticket.serial {
                    return Err(Error::Stale);
                }
                if result == ResultKind::Success {
                    op.query = true;
                    op.state = if closing {
                        ReplayState::Cancel
                    } else {
                        ReplayState::Waiting
                    };
                    if !closing {
                        match kind {
                            ReplayKind::Handshake => self.progress(time, entropy)?,
                            ReplayKind::Acknowledgement => {
                                if self.role == Role::Inbound {
                                    self.send_ack(time)?;
                                }
                                self.initial_verified = true;
                                self.queue_add = true;
                                self.phase = Phase::Registering;
                            }
                            ReplayKind::Rekey => {
                                let prk = self.pending_rekey.take().ok_or(Error::NotReady)?;
                                self.incoming.as_mut().ok_or(Error::NotReady)?.rekey(&prk)?;
                                self.metrics.rekey_applied();
                                self.unverified_size =
                                    self.unverified_size.saturating_add(wire::REKEY);
                                self.pending = Pending::None;
                            }
                        }
                    }
                } else {
                    op.state = ReplayState::Idle;
                    if !closing {
                        self.finish(time)?;
                    }
                }
            }
            Kind::ReplayStore(_kind) => {
                if result == ResultKind::Failed {
                    self.diagnostics.replay_store_failures =
                        self.diagnostics.replay_store_failures.saturating_add(1);
                }
                let op = &mut self.replay[ticket.replay_slot];
                if op.store_serial != ticket.serial {
                    return Err(Error::Stale);
                }
                if result == ResultKind::Success {
                    op.store = true;
                    op.state = if closing {
                        ReplayState::Cancel
                    } else {
                        ReplayState::Storing
                    };
                } else {
                    op.store = false;
                    op.state = if closing {
                        if op.query {
                            ReplayState::Cancel
                        } else {
                            ReplayState::Idle
                        }
                    } else {
                        ReplayState::Idle
                    };
                }
            }
            Kind::ReplayNext(_kind) => {
                let op = &mut self.replay[ticket.replay_slot];
                if !op.query {
                    return Err(Error::Stale);
                }
                op.state = if closing {
                    ReplayState::Cancel
                } else {
                    ReplayState::Waiting
                };
                if result != ResultKind::Success && !closing {
                    self.finish(time)?;
                }
            }
            Kind::ReplayCancel(_kind, store) => {
                let op = &mut self.replay[ticket.replay_slot];
                if store {
                    op.store = false;
                } else {
                    op.query = false;
                }
                op.state = if op.query || op.store {
                    ReplayState::Cancel
                } else {
                    ReplayState::Idle
                };
            }
            Kind::QueueAdd => {
                self.queue_add = false;
                if result == ResultKind::Success {
                    self.advertised = true;
                    if closing {
                        self.queue_delete = true
                    } else {
                        self.phase = Phase::Established
                    }
                } else if !closing {
                    self.finish(time)?;
                }
            }
            Kind::QueueDelete => {
                self.queue_delete = false;
                self.advertised = false;
            }
            Kind::Receive => {
                let slot = self
                    .completions
                    .iter_mut()
                    .find(|s| s.serial == ticket.serial)
                    .ok_or(Error::Stale)?;
                if result == ResultKind::Queued {
                    slot.live = true;
                    self.backpressure = self.backpressure.checked_add(1).ok_or(Error::Overflow)?;
                } else {
                    slot.live = false;
                }
                if let Some(receiver) = self.incoming.as_mut() {
                    let n = match receiver.verified_record()? {
                        Record::Box(b) => {
                            if result == ResultKind::Unavailable {
                                self.metrics.core_unavailable(b.len());
                            }
                            b.len() + wire::BOX_PREFIX
                        }
                        _ => return Err(Error::Conflict),
                    };
                    receiver.release()?;
                    self.unverified_size = self.unverified_size.saturating_add(n);
                }
                self.receive_ready = false;
            }
            Kind::SendContinue => {
                self.continue_send = false;
                self.mq_waiting = false;
            }
            Kind::Close => {
                if result == ResultKind::Failed {
                    self.diagnostics.close_failures =
                        self.diagnostics.close_failures.saturating_add(1);
                }
                // Success and Failed both consume the host's original close authority;
                // a failed close remains an explicit host result, never retried on a reused fd.
                self.close = false;
                if let Some(receiver) = self.incoming.take() {
                    self.receive_storage = Some(receiver.into_storage());
                }
                self.outgoing = None;
                self.pending_rekey = None;
                self.initial.zeroize();
                self.plain[..self.plain_len].zeroize();
                self.tx[..self.tx_len].zeroize();
                self.plain_len = 0;
                self.tx_len = 0;
                self.phase = if self.backpressure == 0 {
                    Phase::Closed
                } else {
                    Phase::Detached
                };
            }
            Kind::Write => return Err(Error::InvalidInput),
        }
        Ok(())
    }
    fn replay_compare(
        &mut self,
        operation: Ticket<'_>,
        stored: u64,
        time: Time,
    ) -> Result<bool, Error> {
        let Kind::ReplayStart(kind) = operation.kind else {
            return Err(Error::InvalidInput);
        };
        if stored > self.latest_monotime[kind.index()] {
            self.finish(time)?;
            self.replay[operation.replay_slot].state = ReplayState::Cancel;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    /// Compare a real same-source local durable floor after the original PS
    /// Start was actually admitted. This creates no iterator NEXT/STOP/END,
    /// record callback, credit or successful STORE. Only a real END can make
    /// StoreReady. The comparison/closing rule is shared with replay_record.
    pub fn replay_floor(
        &mut self,
        operation: Ticket<'_>,
        stored: u64,
        time: Time,
    ) -> Result<(), Error> {
        if !self.original(operation) {
            return Err(Error::Stale);
        }
        if !matches!(operation.kind, Kind::ReplayStart(_)) {
            return Err(Error::InvalidInput);
        }
        let op = &self.replay[operation.replay_slot];
        if op.serial != operation.serial || !op.query {
            return Err(Error::Stale);
        }
        if self.phase == Phase::Closing {
            return Ok(());
        }
        if op.state != ReplayState::Waiting {
            return Err(Error::WouldBlock);
        }
        self.replay_compare(operation, stored, time)?;
        Ok(())
    }
    /// Deliver one actual record/end callback to its originating live iterator.
    /// A terminal callback invalidates that iterator; no NEXT/STOP is sent on it.
    pub fn replay_record(
        &mut self,
        operation: Ticket<'_>,
        value: Option<&[u8]>,
        time: Time,
    ) -> Result<(), Error> {
        if !self.original(operation) {
            return Err(Error::Stale);
        }
        let Kind::ReplayStart(kind) = operation.kind else {
            return Err(Error::InvalidInput);
        };
        let op = &mut self.replay[operation.replay_slot];
        if op.serial != operation.serial || !op.query {
            return Err(Error::Stale);
        }
        if self.phase == Phase::Closing {
            if value.is_none() {
                if self.leased.is_some_and(
                    |t| t.replay_slot==operation.replay_slot && matches!(t.kind,Kind::ReplayNext(k)|Kind::ReplayCancel(k,false)if k==kind),
                ) {
                    self.leased = None;
                }
                op.query = false;
                if !op.store {
                    op.state = ReplayState::Idle
                }
            }
            return Ok(());
        }
        if value.is_none() {
            op.query = false;
            // Only a real terminal callback ends the scan. Writing while a live
            // SQLite iterator is advancing can feed its own newly inserted row.
            op.state = if matches!(
                self.phase,
                Phase::Finishing | Phase::Detached | Phase::Closed
            ) || op.state == ReplayState::Cancel
            {
                ReplayState::Idle
            } else {
                ReplayState::StoreReady
            };
            if self.leased.is_some_and(|t| {
                t.replay_slot == operation.replay_slot
                    && matches!(t.kind, Kind::ReplayNext(k)|Kind::ReplayCancel(k,false) if k==kind)
            }) {
                self.leased = None;
            }
            return Ok(());
        }
        if op.state != ReplayState::Waiting {
            return Err(Error::WouldBlock);
        }
        match value {
            None => return Err(Error::Conflict),
            Some(bytes) => {
                if bytes.len() != 8 {
                    op.state = ReplayState::NextReady;
                    return Ok(());
                }
                let stored = u64::from_be_bytes(bytes.try_into().map_err(|_| Error::Malformed)?);
                if !self.replay_compare(operation, stored, time)? {
                    self.replay[operation.replay_slot].state = ReplayState::NextReady;
                }
            }
        }
        Ok(())
    }
    /// Retire a failed original scan without manufacturing a successful END.
    /// A backend failure closes the peer; no unverified replacement is submitted.
    pub fn replay_failed(&mut self, operation: Ticket<'_>, time: Time) -> Result<(), Error> {
        if !self.original(operation) {
            return Err(Error::Stale);
        }
        let Kind::ReplayStart(kind) = operation.kind else {
            return Err(Error::InvalidInput);
        };
        let op = &mut self.replay[operation.replay_slot];
        if op.serial != operation.serial || !op.query {
            return Err(Error::Stale);
        }
        op.query = false;
        op.state = ReplayState::Idle;
        if self.leased.is_some_and(|t| {
            t.replay_slot == operation.replay_slot
                && matches!(t.kind,Kind::ReplayNext(k)|Kind::ReplayCancel(k,false) if k==kind)
        }) {
            self.leased = None;
        }
        self.finish(time)?;
        Ok(())
    }
    /// Actual PEERSTORE store continuation. Failure is not persistence success;
    /// a failed commit closes the peer without pretending replay history persisted.
    pub fn replay_stored(&mut self, operation: Ticket<'_>, success: bool) -> Result<(), Error> {
        if !self.original(operation) {
            return Err(Error::Stale);
        }
        let Kind::ReplayStore(kind) = operation.kind else {
            return Err(Error::InvalidInput);
        };
        let op = &mut self.replay[operation.replay_slot];
        if op.store_serial != operation.serial || !op.store {
            return Err(Error::Stale);
        }
        op.store = false;
        if self.leased.is_some_and(|t| {
            t.replay_slot == operation.replay_slot
                && matches!(t.kind,Kind::ReplayCancel(k,true)if k==kind)
        }) {
            self.leased = None;
        }
        if !success {
            self.diagnostics.replay_store_failures =
                self.diagnostics.replay_store_failures.saturating_add(1);
        }
        op.state = ReplayState::Idle;
        if !success {
            self.destroy();
        }
        Ok(())
    }
    /// Deliver exactly one actual transport message completion, including failure.
    /// Original credits can drain after physical close and cannot target a new scope.
    pub fn completed(
        &mut self,
        completion: Ticket<'_>,
        success: bool,
        now: u64,
    ) -> Result<(), Error> {
        if !self.original(completion) || completion.kind != Kind::Receive {
            return Err(Error::Stale);
        }
        let slot = self
            .completions
            .iter_mut()
            .find(|s| s.serial == completion.serial && s.live)
            .ok_or(Error::Stale)?;
        if self.backpressure == 0 {
            return Err(Error::Conflict);
        }
        slot.live = false;
        if !success {
            self.metrics.receive_failed();
            self.diagnostics.receive_failures = self.diagnostics.receive_failures.saturating_add(1);
        }
        self.backpressure -= 1;
        if self.phase == Phase::Detached && self.backpressure == 0 {
            self.phase = Phase::Closed;
        } else if !matches!(self.phase, Phase::Closing | Phase::Detached | Phase::Closed) {
            self.timeout = after(now, IDLE_US);
        }
        Ok(())
    }
}
impl Drop for Session<'_> {
    fn drop(&mut self) {
        self.initial.zeroize();
        self.plain[..self.plain_len].zeroize();
        self.tx[..self.tx_len].zeroize(); /* Host still owns original native/service resources and must physically drop them. */
    }
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
