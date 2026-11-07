//! Caller-driven original KX/rekey controller. No I/O, allocator or background clock.
//! One confirmed session, one candidate and one retained control output are bounded.
use super::{
    Context, Exchange, Identity, Limits as CryptoLimits, LocalKeys, Opened, Role, Scope, Sealed,
    Session, Snapshot as CryptoSnapshot, Storage, identity_dh,
};
use crate::statistics::Metric;
use crate::{
    connection::{self, Book, Endpoint, ResetAuthority, ResetProof, Route},
    peer,
};
use gnunet_crypto::{Entropy, hash512};
use gnunet_types::{Error, MonoInstant};
use gnunet_wire::official::cadet_peer::{ChannelMessage, KX_AUTH_LEN, KX_FORCE_REPLY, PeerMessage};
use subtle::ConstantTimeEq;

/// Original cryptographic epoch within one uniquely allocated owned tunnel Context.
#[derive(Clone, Copy, Debug)]
pub struct Generation<'id> {
    scope: Scope<'id>,
    serial: u64,
}
impl Generation<'_> {
    /// Diagnostic epoch, never a wire RID or nonce.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.serial
    }
    /// Compare the original stable domain/unique allocation, independently of
    /// its crypto generation. Reusing a registry row cannot recreate this tag.
    /// This is local metadata, never a wire identifier or DH result.
    #[must_use]
    pub fn same_context(self, other: Self) -> bool {
        self.scope == other.scope
    }
    /// Whether this original context lease remains live. Native retirement
    /// still matches stored original jobs after this becomes false.
    #[must_use]
    pub fn is_live(self) -> bool {
        self.scope.is_live()
    }
    pub(super) fn admission(self) -> Result<(), Error> {
        self.scope.authorize_admission(self.serial)
    }
}
impl PartialEq for Generation<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.scope == other.scope && self.serial == other.serial
    }
}
impl Eq for Generation<'_> {}

/// Public control kind, independent of the connection owner's physical attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Original/retried initial Alice KX.
    KeyExchange,
    /// Original/current KX_AUTH response.
    Authentication,
    /// Genuine encrypted header-only tunnel keepalive.
    KeepAlive,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Plan {
    Kx,
    Auth { force: bool, initial: bool },
    KeepAlive,
}
impl Plan {
    fn kind(self) -> Kind {
        match self {
            Self::Kx => Kind::KeyExchange,
            Self::Auth { .. } => Kind::Authentication,
            Self::KeepAlive => Kind::KeepAlive,
        }
    }
}
#[derive(Clone, Copy)]
struct Intent<'route> {
    generation: u64,
    plan: Plan,
    preferred: Option<Route<'route>>,
}

/// One retained immutable control output, bound to its exact original route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Attempt<'id, 'route> {
    generation: Generation<'id>,
    serial: u64,
    route: Route<'route>,
    kind: Kind,
}
impl<'id, 'route> Attempt<'id, 'route> {
    /// Original crypto epoch; late completion never selects a replacement epoch.
    #[must_use]
    pub const fn generation(self) -> Generation<'id> {
        self.generation
    }
    /// Original connection allocation, not just CID bytes.
    #[must_use]
    pub const fn route(self) -> Route<'route> {
        self.route
    }
    /// Original logical control kind.
    #[must_use]
    pub const fn kind(self) -> Kind {
        self.kind
    }
    /// Diagnostic original output serial.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.serial
    }
}

/// Linear original control preview. Submit it once or explicitly return it on
/// refused admission; no Clone/Copy constructor can duplicate that ownership.
pub struct Prepared<'id, 'route, 'out> {
    attempt: Attempt<'id, 'route>,
    bytes: &'out [u8],
}
impl<'id, 'route, 'out> Prepared<'id, 'route, 'out> {
    /// Original logical output identity.
    #[must_use]
    pub const fn attempt(&self) -> Attempt<'id, 'route> {
        self.attempt
    }
    /// Exact immutable original official frame; queue admission is not emission.
    #[must_use]
    pub const fn bytes(&self) -> &'out [u8] {
        self.bytes
    }
}
/// Original immutable control already retained in this actual Book. The
/// linear preview was consumed; no borrowed staging bytes or fake write remain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueuedControl<'id, 'route> {
    attempt: Attempt<'id, 'route>,
    frame: connection::Frame<'route>,
}
impl<'id, 'route> QueuedControl<'id, 'route> {
    /// Original controller attempt.
    #[must_use]
    pub const fn attempt(self) -> Attempt<'id, 'route> {
        self.attempt
    }
    /// Original immutable Book frame, before/after actual CORE admission.
    #[must_use]
    pub const fn frame(self) -> connection::Frame<'route> {
        self.frame
    }
}
/// One genuine encrypted unknown-channel DESTROY, with original route/epoch.
/// Native caller reserves a Book frame first and retains these exact bytes.
pub struct Rejection<'id, 'route, 'out> {
    generation: Generation<'id>,
    route: Route<'route>,
    sealed: Sealed<'id, 'out>,
}
impl<'id, 'route, 'out> Rejection<'id, 'route, 'out> {
    /// Original key epoch, never a wire identifier.
    #[must_use]
    pub const fn generation(&self) -> Generation<'id> {
        self.generation
    }
    /// Actually selected eligible endpoint route.
    #[must_use]
    pub const fn route(&self) -> Route<'route> {
        self.route
    }
    /// Original whole immutable ciphertext.
    #[must_use]
    pub const fn bytes(&self) -> &'out [u8] {
        self.sealed.bytes()
    }
}
/// Refused binding returns the original linear preview, never drops an output
/// whose actual connection owner may still need explicit retirement.
pub struct RejectedControl<'id, 'route, 'out> {
    /// Actual original refusal.
    pub reason: Error,
    /// Exact original preview returned to its caller.
    pub prepared: Prepared<'id, 'route, 'out>,
}

#[derive(Clone, Copy)]
enum PendingState<'route> {
    Retained,
    Previewed,
    Queued(connection::Frame<'route>),
    Bound(connection::Attempt<'route>),
}
struct Pending<'id, 'route> {
    attempt: Attempt<'id, 'route>,
    plan: Plan,
    state: PendingState<'route>,
    bytes: [u8; KX_AUTH_LEN],
    length: usize,
}
#[derive(Clone, Copy)]
struct Retry {
    expires: MonoInstant,
    due: Option<MonoInstant>,
    delay: u64,
    sent: u32,
    invalid: u32,
}
impl Retry {
    fn new(delay: u64, expires: MonoInstant) -> Self {
        Self {
            expires,
            due: None,
            delay,
            sent: 0,
            invalid: 0,
        }
    }
}
struct Live<'id, 'slots> {
    generation: u64,
    session: Session<'id, 'slots>,
}
enum Candidate<'id, 'slots> {
    Alice {
        generation: u64,
        local: LocalKeys,
        exchange: Exchange,
        storage: Storage<'slots>,
        retry: Retry,
    },
    Betty {
        live: Live<'id, 'slots>,
        retry: Retry,
    },
    AwaitIdentityDh {
        generation: u64,
        local: LocalKeys,
        remote: Exchange,
        authentication: Option<([u8; 64], bool)>,
        storage: Storage<'slots>,
        retry: Retry,
    },
    AliceReady {
        live: Live<'id, 'slots>,
        retry: Retry,
    },
}
impl Candidate<'_, '_> {
    fn generation(&self) -> u64 {
        match self {
            Self::Alice { generation, .. } | Self::AwaitIdentityDh { generation, .. } => {
                *generation
            }
            Self::Betty { live, .. } | Self::AliceReady { live, .. } => live.generation,
        }
    }
    fn retry(&self) -> Retry {
        match self {
            Self::Alice { retry, .. }
            | Self::Betty { retry, .. }
            | Self::AwaitIdentityDh { retry, .. }
            | Self::AliceReady { retry, .. } => *retry,
        }
    }
    fn retry_mut(&mut self) -> &mut Retry {
        match self {
            Self::Alice { retry, .. }
            | Self::Betty { retry, .. }
            | Self::AwaitIdentityDh { retry, .. }
            | Self::AliceReady { retry, .. } => retry,
        }
    }
}

/// Exactly two caller-owned crypto stores: at most confirmed plus one candidate.
pub struct Stores<'slots> {
    /// First committed/staged skipped-key pair.
    pub first: Storage<'slots>,
    /// Independent second committed/staged skipped-key pair.
    pub second: Storage<'slots>,
}
impl Stores<'_> {
    /// Preflight both empty original crypto stores before peer allocation.
    pub fn validate(&self, limits: CryptoLimits) -> Result<(), Error> {
        Session::validate_storage(&self.first, limits)?;
        Session::validate_storage(&self.second, limits)
    }
}
/// Explicit control/resource policy in canonical monotonic microseconds.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Crypto framing/gap policy, independent of connection selection.
    pub crypto: CryptoLimits,
    /// Initial actual-written KX retry delay; source profile uses250ms.
    pub retry_micros: u64,
    /// Capped retry delay.
    pub maximum_retry_micros: u64,
    /// Absolute candidate lifetime in canonical monotonic microseconds. This
    /// local bound starts at original admission and is never extended by
    /// admission refusal, route loss, output failure, duplicates or retries.
    pub negotiation_micros: u64,
    /// Actual written controls before this negotiation expires.
    pub maximum_transmissions: u32,
    /// Bounded refused candidate authentication work before discard.
    pub maximum_unverified_attempts: u32,
    /// Last handled signed-reset monotime restored by this tunnel's owner.
    pub reset_high_water: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            crypto: CryptoLimits::default(),
            retry_micros: 250_000,
            maximum_retry_micros: 900_000_000,
            negotiation_micros: 120_000_000,
            maximum_transmissions: 16,
            maximum_unverified_attempts: 16,
            reset_high_water: 0,
        }
    }
}

/// Actual local control transition, never remote channel acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event<'id> {
    /// Original fresh local KX negotiation admitted; no bytes are exposed yet.
    Started(Generation<'id>),
    /// One original candidate is awaiting its single actual identity-DH job.
    AwaitIdentityDh(Generation<'id>),
    /// Its one original backend job was actually admitted; no success is implied.
    IdentityDhSubmitted(Generation<'id>),
    /// The original canceled job still retains actual backend ownership.
    IdentityDhRetiring,
    /// The original canceled job has actually retired without a cipher promotion.
    IdentityDhRetired,
    /// One unverified responder candidate admitted; confirmed session survived.
    Candidate(Generation<'id>),
    /// Real KX_AUTH or whole authenticated encrypted packet promoted an epoch.
    Confirmed(Generation<'id>),
    /// Actual duplicate/stale control caused no cipher-state reset.
    Duplicate,
    /// Bounded other candidate remains pending; input was not authenticated.
    CandidateBusy,
    /// Betty cannot initiate KX; caller must request an actual signed monotime
    /// CREATE through its connection/PILS ports. Nothing is sent here.
    NeedSignedReset,
    /// Only a verified fresh ResetProof armed the peer-reset policy.
    ResetArmed,
    /// Original confirmed session remains, but negotiation budget expired.
    Expired,
    /// Wrong role/unrequested control was consumed without authority.
    Ignored,
    /// An actual retry deadline now queued another original control intent.
    RetryDue,
    /// No control deadline/state transition occurred.
    Idle,
}
/// Public bounded observations; no private key/proof/plaintext formatting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot<'id, 'route> {
    /// Current confirmed epoch, if any.
    pub confirmed: Option<Generation<'id>>,
    /// One pending original negotiation epoch, if any.
    pub candidate: Option<Generation<'id>>,
    /// Exact retained output awaiting rejection/binding/actual completion.
    pub pending: Option<Attempt<'id, 'route>>,
    /// Absolute original candidate deadline, including when no control could
    /// be admitted or physically written. None means no candidate is pending.
    pub negotiation_deadline: Option<MonoInstant>,
    /// Actual-written retry deadline; None does not mean successful delivery.
    pub retry_at: Option<MonoInstant>,
    /// Fresh-reset pause on new application seals; old verified receive remains.
    pub traffic_paused: bool,
    /// Last once-handled verified origin monotime.
    pub reset_high_water: u64,
    /// Owner permanently closed this controller.
    pub closed: bool,
}
/// One actual authenticated payload, optionally promoting the candidate first.
pub struct Received<'id, 'out> {
    /// Exact key epoch which authenticated this input.
    pub generation: Generation<'id>,
    /// Whether this real packet promoted the unverified candidate.
    pub promoted: bool,
    /// Authenticated original plaintext and original peer Context.
    pub opened: Opened<'id, 'out>,
}
/// Original channel operation bound once to original immutable sealed bytes.
pub struct SealedChannel<'id, 'route, 'channel, 'out> {
    generation: Generation<'id>,
    route: Route<'route>,
    original: peer::Attempt<'channel>,
    sealed: Sealed<'id, 'out>,
}
impl<'id, 'route, 'channel, 'out> SealedChannel<'id, 'route, 'channel, 'out> {
    /// Actual original channel attempt; full local write is not DATA_ACK.
    #[must_use]
    pub const fn original(&self) -> peer::Attempt<'channel> {
        self.original
    }
    /// Original cryptographic epoch even after later authenticated rekey.
    #[must_use]
    pub const fn generation(&self) -> Generation<'id> {
        self.generation
    }
    /// Original chosen route allocation, not a newly looked-up equal CID.
    #[must_use]
    pub const fn route(&self) -> Route<'route> {
        self.route
    }
    /// Exact immutable original ciphertext, never a request to re-seal it.
    #[must_use]
    pub const fn bytes(&self) -> &'out [u8] {
        self.sealed.bytes()
    }
    /// Verify the actual containing CORE owner retained this exact original
    /// route and immutable ciphertext before any physical exposure. The caller
    /// then retains both original attempt tokens through actual settlement.
    pub fn check_core<const P: usize>(
        &self,
        book: &Book<'route, '_, '_, P>,
        original: connection::Attempt<'route>,
    ) -> Result<(), Error> {
        if original.route() != Some(self.route)
            || book.frame_bytes(original.frame())? != self.bytes()
        {
            return Err(Error::StaleGeneration);
        }
        Ok(())
    }
}
/// Preflight/crypto refusal returns unconsumed original channel plaintext.
pub struct RejectedChannel<'channel, 'plain> {
    /// Actual original error, with no fabricated exposure/success.
    pub reason: Error,
    /// Same linear original Prepared; its parent channel still owns settlement.
    pub prepared: peer::Prepared<'channel, 'plain>,
}

#[derive(Clone, Copy)]
enum IdentityMode<'id> {
    Local(&'id Identity),
    External(identity_dh::Source<'id>),
}
impl IdentityMode<'_> {
    fn peer(self) -> [u8; 32] {
        match self {
            Self::Local(identity) => identity.peer(),
            Self::External(source) => source.local(),
        }
    }
}
#[derive(Clone, Copy)]
enum IdentityJobState {
    Queued,
    Submitted,
    Retiring,
}
#[derive(Clone, Copy)]
struct IdentityJob<'id> {
    request: identity_dh::Request<'id>,
    state: IdentityJobState,
}

/// Pure original-context KX/rekey owner; no private wire/FFI/default success port.
pub struct Controller<'id, 'slots, 'route> {
    context: Context<'id>,
    identity: IdentityMode<'id>,
    identity_job: Option<IdentityJob<'id>>,
    authority: ResetAuthority<'route>,
    free: [Option<Storage<'slots>>; 2],
    active: Option<Live<'id, 'slots>>,
    candidate: Option<Candidate<'id, 'slots>>,
    intent: Option<Intent<'route>>,
    pending: Option<Pending<'id, 'route>>,
    next_generation: u64,
    next_attempt: u64,
    reset_high_water: u64,
    traffic_paused: bool,
    closed: bool,
    last_now: MonoInstant,
    limits: Limits,
}

impl<'id, 'slots, 'route> Controller<'id, 'slots, 'route> {
    /// Own the original peer/identity Context lease and original routing
    /// book reset authority; no socket or ephemeral is generated by construction.
    pub fn new(
        context: Context<'id>,
        identity: &'id Identity,
        authority: ResetAuthority<'route>,
        stores: Stores<'slots>,
        limits: Limits,
        now: MonoInstant,
    ) -> Result<Self, Error> {
        Self::build(
            context,
            IdentityMode::Local(identity),
            authority,
            stores,
            limits,
            now,
        )
    }
    /// Bind a trusted asynchronous original identity-DH source. Public peer
    /// metadata grants no DH completion; actual results are consumed only through
    /// advance_identity_dh's explicit trusted port callback. No private seed is needed.
    pub fn new_external_identity(
        context: Context<'id>,
        source: identity_dh::Source<'id>,
        authority: ResetAuthority<'route>,
        stores: Stores<'slots>,
        limits: Limits,
        now: MonoInstant,
    ) -> Result<Self, Error> {
        Self::build(
            context,
            IdentityMode::External(source),
            authority,
            stores,
            limits,
            now,
        )
    }
    fn build(
        context: Context<'id>,
        identity: IdentityMode<'id>,
        authority: ResetAuthority<'route>,
        stores: Stores<'slots>,
        limits: Limits,
        now: MonoInstant,
    ) -> Result<Self, Error> {
        context.binding.authorize()?;
        if let IdentityMode::External(source) = identity
            && !source.is_live()
        {
            return Err(Error::StaleGeneration);
        }
        if context.binding.local != identity.peer() || authority.local() != context.binding.local {
            return Err(Error::Authentication);
        }
        if limits.retry_micros == 0
            || limits.maximum_retry_micros < limits.retry_micros
            || limits.negotiation_micros == 0
            || limits.maximum_transmissions == 0
            || limits.maximum_unverified_attempts == 0
        {
            return Err(Error::InvalidInput);
        }
        Session::validate_storage(&stores.first, limits.crypto)?;
        Session::validate_storage(&stores.second, limits.crypto)?;
        Ok(Self {
            context,
            identity,
            identity_job: None,
            authority,
            free: [Some(stores.first), Some(stores.second)],
            active: None,
            candidate: None,
            intent: None,
            pending: None,
            next_generation: 0,
            next_attempt: 0,
            reset_high_water: limits.reset_high_water,
            traffic_paused: false,
            closed: false,
            last_now: now,
            limits,
        })
    }
    /// Original end-to-end tunnel identity; connection authority remains separate.
    #[must_use]
    pub const fn scope(&self) -> Scope<'id> {
        self.context.binding
    }
    fn authorize(&self, scope: Scope<'id>) -> Result<(), Error> {
        if scope != self.context.binding {
            return Err(Error::StaleGeneration);
        }
        if self.closed {
            return Err(Error::Closed);
        }
        self.context.binding.authorize()
    }
    fn time(&mut self, now: MonoInstant) -> Result<(), Error> {
        if now < self.last_now {
            return Err(Error::TimeUncertain);
        }
        self.last_now = now;
        Ok(())
    }
    fn generation(&self, serial: u64) -> Generation<'id> {
        Generation {
            scope: self.scope(),
            serial,
        }
    }
    /// Current public facts, without inferred physical output or remote receipt.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<'id, 'route> {
        Snapshot {
            confirmed: self.active.as_ref().map(|a| self.generation(a.generation)),
            candidate: self
                .candidate
                .as_ref()
                .map(|c| self.generation(c.generation())),
            pending: self.pending.as_ref().map(|p| p.attempt),
            negotiation_deadline: self.candidate.as_ref().map(|c| c.retry().expires),
            retry_at: self.candidate.as_ref().and_then(|c| c.retry().due),
            traffic_paused: self.traffic_paused,
            reset_high_water: self.reset_high_water,
            closed: self.closed,
        }
    }
    /// Official diagnostic CadetTunnelEState value from this actual owner.
    /// Queuing KX/AUTH does not count as a write: the sent substates use only
    /// original full-written retry observations. KEY_OK means working keys,
    /// never remote application processing or available path admission.
    #[must_use]
    pub fn management_state(&self) -> u16 {
        if self.closed {
            return 0;
        }
        if self.active.is_some() {
            return 5;
        }
        match self.candidate.as_ref() {
            Some(Candidate::Alice { retry, .. }) => {
                if retry.sent == 0 {
                    0
                } else {
                    1
                }
            }
            Some(
                Candidate::AwaitIdentityDh {
                    authentication: Some(_),
                    ..
                }
                | Candidate::AliceReady { .. },
            ) => 3,
            Some(Candidate::AwaitIdentityDh {
                authentication: None,
                ..
            }) => 2,
            Some(Candidate::Betty { retry, .. }) => {
                if retry.sent == 0 {
                    2
                } else {
                    4
                }
            }
            None => 0,
        }
    }
    /// Earliest real canonical timer observation required from the containing
    /// reactor, including the finite lifetime when nothing was written. A pure
    /// controller never reads or fabricates a clock itself.
    #[must_use]
    pub fn next_deadline(&self) -> Option<MonoInstant> {
        self.candidate.as_ref().map(|candidate| {
            let retry = candidate.retry();
            if self.pending.is_some() || self.intent.is_some() {
                retry.expires
            } else {
                retry
                    .due
                    .map_or(retry.expires, |due| due.min(retry.expires))
            }
        })
    }
    fn expires(&self) -> Result<MonoInstant, Error> {
        Ok(MonoInstant(
            self.last_now
                .0
                .checked_add(self.limits.negotiation_micros)
                .ok_or(Error::Overflow)?,
        ))
    }
    // A deadline never releases externally retained original output ownership.
    // Late completion merely drains that old output and cannot revive its keys.
    fn expire_candidate(&mut self) -> bool {
        if self
            .candidate
            .as_ref()
            .is_some_and(|candidate| self.last_now >= candidate.retry().expires)
        {
            self.discard_candidate();
            return true;
        }
        false
    }
    /// Actual confirmed cipher counters only; no candidate/private key export.
    #[must_use]
    pub fn crypto_snapshot(&self) -> Option<CryptoSnapshot> {
        self.active.as_ref().map(|a| a.session.snapshot())
    }
    fn schedule(&mut self, intent: Intent<'route>) {
        if self.intent.is_some_and(|old| {
            old.generation == intent.generation
                && !matches!(old.plan, Plan::KeepAlive)
                && matches!(intent.plan, Plan::KeepAlive)
        }) {
            return;
        }
        if self
            .intent
            .is_none_or(|old| old.generation <= intent.generation)
        {
            self.intent = Some(intent);
        }
    }
    fn free_index(&self) -> Result<usize, Error> {
        self.free
            .iter()
            .position(Option::is_some)
            .ok_or(Error::Capacity)
    }
    fn put_storage(&mut self, storage: Storage<'slots>) {
        // A promotion/discard removes one of at most two live owners first.
        // Its original pool always has a vacant entry; no secret allocation fails.
        for slot in &mut self.free {
            if slot.is_none() {
                *slot = Some(storage);
                return;
            }
        }
    }
    fn discard_candidate(&mut self) {
        if let Some(candidate) = self.candidate.take() {
            let generation = candidate.generation();
            self.context.binding.admission(0);
            let storage = match candidate {
                Candidate::Alice { storage, .. } | Candidate::AwaitIdentityDh { storage, .. } => {
                    storage
                }
                Candidate::Betty { live, .. } | Candidate::AliceReady { live, .. } => {
                    live.session.recycle_storage()
                }
            };
            self.put_storage(storage);
            if let Some(job) = self.identity_job.as_mut()
                && job.request.generation.value() == generation
            {
                match job.state {
                    IdentityJobState::Queued => self.identity_job = None,
                    IdentityJobState::Submitted | IdentityJobState::Retiring => {
                        job.state = IdentityJobState::Retiring
                    }
                }
            }
            if self.intent.is_some_and(|i| i.generation == generation) {
                self.intent = None;
            }
        }
    }
    fn promote(&mut self, live: Live<'id, 'slots>) -> Generation<'id> {
        self.context.binding.admission(0);
        if let Some(old) = self.active.take() {
            self.put_storage(old.session.recycle_storage());
        }
        self.active = Some(live);
        self.traffic_paused = false;
        if self
            .intent
            .is_some_and(|i| !matches!(i.plan, Plan::KeepAlive))
        {
            self.intent = None;
        }
        self.generation(self.active.as_ref().map_or(0, |a| a.generation))
    }
    /// Local channel demand may start a fresh Alice KX, or request the real
    /// connection/PILS signed-monotime path for Betty. Existing working keys live.
    pub fn request(
        &mut self,
        scope: Scope<'id>,
        now: MonoInstant,
        entropy: &mut impl Entropy,
    ) -> Result<Event<'id>, Error> {
        self.authorize(scope)?;
        self.time(now)?;
        self.expire_candidate();
        if self.candidate.is_some() || self.identity_job.is_some() {
            return Ok(Event::CandidateBusy);
        }
        if self.context.binding.role == Role::Betty {
            return Ok(Event::NeedSignedReset);
        }
        self.start_alice(entropy)
    }
    fn start_alice(&mut self, entropy: &mut impl Entropy) -> Result<Event<'id>, Error> {
        if self.identity_job.is_some() {
            return Ok(Event::CandidateBusy);
        }
        let free = self.free_index()?;
        let generation = self.next_generation.checked_add(1).ok_or(Error::Overflow)?;
        let expires = self.expires()?;
        let local = LocalKeys::generate(entropy)?;
        let exchange = local.exchange();
        let storage = self.free[free].take().ok_or(Error::Capacity)?;
        self.next_generation = generation;
        self.context.binding.admission(generation);
        self.candidate = Some(Candidate::Alice {
            generation,
            local,
            exchange,
            storage,
            retry: Retry::new(self.limits.retry_micros, expires),
        });
        self.schedule(Intent {
            generation,
            plan: Plan::Kx,
            preferred: None,
        });
        Ok(Event::Started(self.generation(generation)))
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Original candidate scalars, exchanges, storage and immutable retry lifetime move together without cloning keys"
    )]
    fn await_identity_dh(
        &mut self,
        source: identity_dh::Source<'id>,
        generation: u64,
        local: LocalKeys,
        remote: Exchange,
        authentication: Option<([u8; 64], bool)>,
        storage: Storage<'slots>,
        retry: Retry,
    ) {
        self.context.binding.admission(generation);
        let request = identity_dh::Request {
            source,
            generation: self.generation(generation),
            local: local.exchange(),
            remote,
            role: self.context.binding.role,
            expires: retry.expires,
        };
        self.candidate = Some(Candidate::AwaitIdentityDh {
            generation,
            local,
            remote,
            authentication,
            storage,
            retry,
        });
        self.identity_job = Some(IdentityJob {
            request,
            state: IdentityJobState::Queued,
        });
        if self
            .intent
            .is_some_and(|intent| intent.generation == generation)
        {
            self.intent = None;
        }
    }
    /// Explicitly select a new actual identity-DH source only after every old
    /// candidate/job retired. Confirmed cipher generation, counters and skipped
    /// keys remain unchanged. This does not authenticate the source by metadata;
    /// actual operations still come exclusively through its trusted Port.
    pub fn rebind_identity_source(
        &mut self,
        scope: Scope<'id>,
        source: identity_dh::Source<'id>,
    ) -> Result<(), Error> {
        self.authorize(scope)?;
        if !matches!(self.identity, IdentityMode::External(_)) {
            return Err(Error::Unsupported);
        }
        if source.local() != self.context.binding.local {
            return Err(Error::Authentication);
        }
        if !source.is_live() {
            return Err(Error::StaleGeneration);
        }
        if self.candidate.is_some() || self.identity_job.is_some() {
            return Err(Error::WouldBlock);
        }
        self.identity = IdentityMode::External(source);
        Ok(())
    }
    /// Original single pending identity-DH operation, including an expired/closed
    /// candidate's actual backend retirement obligation. Metadata is not a result.
    #[must_use]
    pub fn pending_identity_dh(&self) -> Option<identity_dh::Request<'id>> {
        self.identity_job.map(|job| job.request)
    }
    /// Whether no further DH result may apply and actual original retirement is due.
    #[must_use]
    pub fn identity_dh_retiring(&self) -> bool {
        self.identity_job
            .is_some_and(|job| matches!(job.state, IdentityJobState::Retiring))
    }
    fn identity_port(
        &self,
        scope: Scope<'id>,
        port: &impl identity_dh::Port<'id>,
    ) -> Result<(), Error> {
        if scope != self.context.binding {
            return Err(Error::StaleGeneration);
        }
        let IdentityMode::External(source) = self.identity else {
            return Err(Error::Unsupported);
        };
        if port.source() != source {
            return Err(Error::StaleGeneration);
        }
        Ok(())
    }
    /// Explicitly cancel/retire the original pending identity-DH job. This also
    /// works after close or clock refusal. Confirmed keys remain unaffected;
    /// true retirement comes only from this exact trusted source, never a label.
    pub fn retire_identity_dh(
        &mut self,
        scope: Scope<'id>,
        port: &mut impl identity_dh::Port<'id>,
    ) -> Result<Event<'id>, Error> {
        self.identity_port(scope, port)?;
        if self.identity_job.is_none() {
            return Ok(Event::Idle);
        }
        self.discard_candidate();
        let Some(job) = self.identity_job else {
            return Ok(Event::IdentityDhRetired);
        };
        if matches!(job.state, IdentityJobState::Queued) {
            self.identity_job = None;
            return Ok(Event::IdentityDhRetired);
        }
        if port.retire(job.request)? {
            self.identity_job = None;
            Ok(Event::IdentityDhRetired)
        } else {
            Ok(Event::IdentityDhRetiring)
        }
    }
    /// Advance exactly one original external identity-DH admission/completion.
    /// Actual native IO belongs to the supplied trusted provider and is polled
    /// independently. Old confirmed traffic remains usable while this waits.
    /// A wrong/late provider/result never creates a generation or resets keys.
    pub fn advance_identity_dh(
        &mut self,
        scope: Scope<'id>,
        port: &mut impl identity_dh::Port<'id>,
        now: MonoInstant,
    ) -> Result<Event<'id>, Error> {
        self.identity_port(scope, port)?;
        if self.closed || self.identity_dh_retiring() {
            return self.retire_identity_dh(scope, port);
        }
        self.time(now)?;
        let expired = self.expire_candidate();
        if self.identity_dh_retiring() {
            return self.retire_identity_dh(scope, port);
        }
        let Some(job) = self.identity_job else {
            return Ok(if expired { Event::Expired } else { Event::Idle });
        };
        let Some(Candidate::AwaitIdentityDh {
            generation,
            local,
            remote,
            retry,
            ..
        }) = self.candidate.as_ref()
        else {
            return Err(Error::StaleGeneration);
        };
        if job.request.generation != self.generation(*generation)
            || job.request.local != local.exchange()
            || job.request.remote != *remote
            || job.request.role != self.context.binding.role
            || job.request.expires != retry.expires
        {
            return Err(Error::StaleGeneration);
        }
        if matches!(job.state, IdentityJobState::Queued) {
            match port.submit(job.request) {
                Ok(()) => {
                    self.identity_job = Some(IdentityJob {
                        request: job.request,
                        state: IdentityJobState::Submitted,
                    });
                    return Ok(Event::IdentityDhSubmitted(job.request.generation));
                }
                Err(error @ (Error::Capacity | Error::WouldBlock)) => return Err(error),
                Err(error) => {
                    self.discard_candidate();
                    return Err(error);
                }
            }
        }
        let is_kx = matches!(
            self.candidate,
            Some(Candidate::AwaitIdentityDh {
                authentication: None,
                ..
            })
        );
        let result = port.finish(job.request, |identity_hash| {
            Session::candidate_keys_with_identity_hash(
                self.context.binding,
                local,
                *remote,
                identity_hash,
            )
        });
        let derived = match result {
            Err(error) => {
                self.discard_candidate();
                return Err(error);
            }
            Ok(identity_dh::Completion::Pending) => return Ok(Event::Idle),
            Ok(identity_dh::Completion::Finished(result)) => {
                // Finished is the trusted port's original result/request actual
                // retirement boundary. Even a bad callback result is consumed once.
                self.identity_job = None;
                match result {
                    Ok(derived) => derived,
                    Err(error) => {
                        if is_kx {
                            self.scope().statistics().add(Metric::UselessKx, 1);
                        }
                        self.discard_candidate();
                        return Err(error);
                    }
                }
            }
        };
        self.observe_root(&derived);
        let Some(Candidate::AwaitIdentityDh {
            generation,
            local,
            authentication,
            storage,
            retry,
            ..
        }) = self.candidate.take()
        else {
            return Err(Error::StaleGeneration);
        };
        let mut session = Session::from_candidate(
            self.context.binding,
            local,
            derived,
            storage,
            self.limits.crypto,
        );
        if let Some((proof, force)) = authentication {
            let remote = session.remote_exchange;
            if let Err(error) = session.verify_initial_auth(session.scope(), remote, &proof) {
                // The one DH job already settled. Retain derived candidate keys
                // for a correct duplicate proof without issuing a second job.
                self.candidate = Some(Candidate::AliceReady {
                    live: Live {
                        generation,
                        session,
                    },
                    retry,
                });
                self.scope().statistics().add(Metric::AuthFailure, 1);
                self.bad_candidate();
                return Err(error);
            }
            let generation = self.promote(Live {
                generation,
                session,
            });
            if force || self.context.binding.role == Role::Alice {
                self.schedule(Intent {
                    generation: generation.serial,
                    plan: Plan::Auth {
                        force: false,
                        initial: true,
                    },
                    preferred: None,
                });
            }
            Ok(Event::Confirmed(generation))
        } else {
            self.candidate = Some(Candidate::Betty {
                live: Live {
                    generation,
                    session,
                },
                retry,
            });
            self.schedule(Intent {
                generation,
                plan: Plan::Auth {
                    force: true,
                    initial: true,
                },
                preferred: None,
            });
            Ok(Event::Candidate(self.generation(generation)))
        }
    }
    fn endpoint(&self, scope: Scope<'id>, input: &Endpoint<'route, '_>) -> Result<(), Error> {
        self.authorize(scope)?;
        if input.authority() != self.authority || input.expected_peer() != self.context.binding.peer
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    /// Consume only the routing book's private actual-source Endpoint receipt.
    /// Unauthenticated KX never replaces or clears the confirmed cipher session.
    pub fn control(
        &mut self,
        scope: Scope<'id>,
        input: Endpoint<'route, '_>,
        now: MonoInstant,
        entropy: &mut impl Entropy,
    ) -> Result<Event<'id>, Error> {
        self.endpoint(scope, &input)?;
        self.time(now)?;
        self.expire_candidate();
        match input.message() {
            PeerMessage::KeyExchange {
                ephemeral_key,
                ratchet_key,
                ..
            } => {
                scope.statistics().add(Metric::KxReceived, 1);
                self.kx(
                    Exchange {
                        ephemeral_key,
                        ratchet_key,
                    },
                    entropy,
                )
            }
            PeerMessage::KeyExchangeAuth {
                ephemeral_key,
                ratchet_key,
                auth,
                flags,
                ..
            } => {
                scope.statistics().add(Metric::AuthReceived, 1);
                self.authentication(
                    Exchange {
                        ephemeral_key,
                        ratchet_key,
                    },
                    &auth,
                    flags & KX_FORCE_REPLY != 0,
                    entropy,
                )
            }
            _ => Err(Error::Unsupported),
        }
    }
    fn current_auth(session: &Session<'_, '_>, remote: Exchange, proof: &[u8; 64]) -> bool {
        remote.ephemeral_key == session.remote_exchange.ephemeral_key
            && remote.ratchet_key == *session.remote_ratchet.as_bytes()
            && bool::from(proof.ct_eq(&hash512(session.keys.root.as_ref())))
    }
    fn original_auth(session: &Session<'_, '_>, remote: Exchange, proof: &[u8; 64]) -> bool {
        remote == session.remote_exchange && bool::from(proof.ct_eq(&session.initial_proof))
    }
    fn kx(&mut self, remote: Exchange, entropy: &mut impl Entropy) -> Result<Event<'id>, Error> {
        let statistics = self.scope().statistics();
        if self.context.binding.role != Role::Betty {
            return Ok(Event::Ignored);
        }
        if let Some(Candidate::Betty { live, .. }) = self.candidate.as_ref()
            && live.session.remote_exchange == remote
        {
            self.schedule(Intent {
                generation: live.generation,
                plan: Plan::Auth {
                    force: true,
                    initial: true,
                },
                preferred: None,
            });
            statistics.add(Metric::DuplicateUnverifiedKx, 1);
            return Ok(Event::Duplicate);
        }
        if let Some(active) = self.active.as_ref()
            && remote.ephemeral_key == active.session.remote_exchange.ephemeral_key
            && (remote.ratchet_key == *active.session.remote_ratchet.as_bytes()
                || remote == active.session.remote_exchange)
        {
            self.schedule(Intent {
                generation: active.generation,
                plan: Plan::Auth {
                    force: false,
                    initial: remote == active.session.remote_exchange,
                },
                preferred: None,
            });
            statistics.add(Metric::DuplicateKx, 1);
            return Ok(Event::Duplicate);
        }
        if let Some(Candidate::AwaitIdentityDh {
            remote: original, ..
        }) = self.candidate.as_ref()
            && *original == remote
        {
            statistics.add(Metric::DuplicateUnverifiedKx, 1);
            return Ok(Event::Duplicate);
        }
        // Observe equality only; no replacement or proof is manufactured.
        if self
            .active
            .as_ref()
            .is_some_and(|a| remote.ratchet_key == *a.session.remote_ratchet.as_bytes())
        {
            statistics.add(Metric::RatchetKnown, 1);
        }
        if self.candidate.is_some() || self.identity_job.is_some() {
            return Ok(Event::CandidateBusy);
        }
        let index = self.free_index()?;
        let generation = self.next_generation.checked_add(1).ok_or(Error::Overflow)?;
        let expires = self.expires()?;
        let local = LocalKeys::generate(entropy)?;
        if let IdentityMode::External(source) = self.identity {
            let storage = self.free[index].take().ok_or(Error::Capacity)?;
            self.next_generation = generation;
            statistics.add(Metric::FreshKx, 1);
            self.await_identity_dh(
                source,
                generation,
                local,
                remote,
                None,
                storage,
                Retry::new(self.limits.retry_micros, expires),
            );
            return Ok(Event::AwaitIdentityDh(self.generation(generation)));
        }
        let IdentityMode::Local(identity) = self.identity else {
            return Err(Error::NotReady);
        };
        let prepared = match Session::candidate_keys(self.context.binding, identity, &local, remote)
        {
            Ok(prepared) => prepared,
            Err(error) => {
                statistics.add(Metric::UselessKx, 1);
                return Err(error);
            }
        };
        self.observe_root(&prepared);
        let storage = self.free[index].take().ok_or(Error::Capacity)?;
        let session = Session::from_candidate(
            self.context.binding,
            local,
            prepared,
            storage,
            self.limits.crypto,
        );
        self.next_generation = generation;
        self.context.binding.admission(generation);
        statistics.add(Metric::FreshKx, 1);
        self.candidate = Some(Candidate::Betty {
            live: Live {
                generation,
                session,
            },
            retry: Retry::new(self.limits.retry_micros, expires),
        });
        self.schedule(Intent {
            generation,
            plan: Plan::Auth {
                force: true,
                initial: true,
            },
            preferred: None,
        });
        Ok(Event::Candidate(self.generation(generation)))
    }
    fn observe_root(&self, derived: &super::CandidateKeys) {
        if self.active.as_ref().is_some_and(|active| {
            bool::from(active.session.keys.root[..].ct_eq(&derived.keys.root[..]))
        }) {
            self.scope().statistics().add(Metric::RootKnown, 1);
        }
    }
    fn bad_candidate(&mut self) {
        if let Some(candidate) = self.candidate.as_mut() {
            candidate.retry_mut().invalid = candidate.retry().invalid.saturating_add(1);
            if candidate.retry().invalid >= self.limits.maximum_unverified_attempts {
                self.discard_candidate();
            }
        }
    }
    fn authentication(
        &mut self,
        remote: Exchange,
        proof: &[u8; 64],
        force: bool,
        entropy: &mut impl Entropy,
    ) -> Result<Event<'id>, Error> {
        if let Some(active) = self.active.as_ref() {
            let initial = Self::original_auth(&active.session, remote, proof);
            if initial || Self::current_auth(&active.session, remote, proof) {
                // A retransmitted responder proof can need Alice's lost final
                // original response even after Alice's send ratchet advanced.
                // Keep that original public proof; never reset cipher state.
                if force || initial && self.context.binding.role == Role::Alice {
                    self.schedule(Intent {
                        generation: active.generation,
                        plan: Plan::Auth {
                            force: false,
                            initial,
                        },
                        preferred: None,
                    });
                }
                self.scope().statistics().add(Metric::RedundantAuth, 1);
                return Ok(Event::Duplicate);
            }
        }
        let Some(candidate) = self.candidate.as_ref() else {
            // An unauthenticated hint may start one bounded fresh Alice probe,
            // never reset/pause the working session. Betty needs signed CREATE.
            return if self.context.binding.role == Role::Alice {
                self.start_alice(entropy)
            } else {
                Ok(Event::NeedSignedReset)
            };
        };
        if let Candidate::AwaitIdentityDh {
            remote: original,
            authentication,
            ..
        } = candidate
        {
            return Ok(
                if *original == remote
                    && authentication.is_some_and(|(original, original_force)| {
                        original == *proof && original_force == force
                    })
                {
                    Event::Duplicate
                } else {
                    Event::CandidateBusy
                },
            );
        }
        if let IdentityMode::External(source) = self.identity
            && matches!(candidate, Candidate::Alice { .. })
        {
            if self.identity_job.is_some() {
                return Ok(Event::CandidateBusy);
            }
            let Some(Candidate::Alice {
                generation,
                local,
                storage,
                retry,
                ..
            }) = self.candidate.take()
            else {
                return Err(Error::StaleGeneration);
            };
            self.await_identity_dh(
                source,
                generation,
                local,
                remote,
                Some((*proof, force)),
                storage,
                retry,
            );
            return Ok(Event::AwaitIdentityDh(self.generation(generation)));
        }
        let prepared = match candidate {
            Candidate::Alice { local, .. } => {
                let IdentityMode::Local(identity) = self.identity else {
                    return Err(Error::NotReady);
                };
                let derived =
                    match Session::candidate_keys(self.context.binding, identity, local, remote) {
                        Ok(derived) => derived,
                        Err(error) => {
                            self.bad_candidate();
                            return Err(error);
                        }
                    };
                self.observe_root(&derived);
                if !bool::from(proof.ct_eq(&hash512(derived.keys.root.as_ref()))) {
                    self.scope().statistics().add(Metric::AuthFailure, 1);
                    self.bad_candidate();
                    return Err(Error::Authentication);
                }
                Some(derived)
            }
            Candidate::Betty { live, .. } | Candidate::AliceReady { live, .. } => {
                if !Self::original_auth(&live.session, remote, proof) {
                    self.scope().statistics().add(Metric::AuthFailure, 1);
                    self.bad_candidate();
                    return Err(Error::Authentication);
                }
                None
            }
            Candidate::AwaitIdentityDh { .. } => return Ok(Event::CandidateBusy),
        };
        let candidate = self.candidate.take().ok_or(Error::StaleGeneration)?;
        let live = match (candidate, prepared) {
            (
                Candidate::Alice {
                    generation,
                    local,
                    storage,
                    ..
                },
                Some(prepared),
            ) => {
                let mut session = Session::from_candidate(
                    self.context.binding,
                    local,
                    prepared,
                    storage,
                    self.limits.crypto,
                );
                session.verify_initial_auth(session.scope(), remote, proof)?;
                Live {
                    generation,
                    session,
                }
            }
            (Candidate::Betty { mut live, .. } | Candidate::AliceReady { mut live, .. }, None) => {
                live.session
                    .verify_initial_auth(live.session.scope(), remote, proof)?;
                live
            }
            _ => return Err(Error::StaleGeneration),
        };
        let generation = self.promote(live);
        if force || self.context.binding.role == Role::Alice {
            self.schedule(Intent {
                generation: generation.serial,
                plan: Plan::Auth {
                    force: false,
                    initial: true,
                },
                preferred: None,
            });
        }
        Ok(Event::Confirmed(generation))
    }

    /// Apply only a private connection-book proof already verified under the
    /// original peer's purpose38 signature and strict origin monotime ledger.
    /// Keep confirmed receive keys; pause only new application seals. Entropy/
    /// fresh KX follows through request(), never by resetting old counters.
    pub fn peer_reset(
        &mut self,
        scope: Scope<'id>,
        proof: ResetProof<'route>,
        now: MonoInstant,
    ) -> Result<Event<'id>, Error> {
        self.authorize(scope)?;
        self.time(now)?;
        if proof.authority() != self.authority
            || proof.origin() != self.context.binding.peer
            || proof.authority().local() != self.context.binding.local
        {
            return Err(Error::Authentication);
        }
        if proof.monotime() <= self.reset_high_water {
            return Err(Error::Replay);
        }
        self.reset_high_water = proof.monotime();
        self.discard_candidate();
        self.intent = None;
        self.traffic_paused = true;
        Ok(Event::ResetArmed)
    }
    /// Observe only actual local retry deadlines. No queued/admitted/unwritten
    /// output starts a timer. An outstanding linear preview/physical output must
    /// first be rejected or settled on its original owner.
    pub fn tick(&mut self, scope: Scope<'id>, now: MonoInstant) -> Result<Event<'id>, Error> {
        self.authorize(scope)?;
        self.time(now)?;
        if self.expire_candidate() {
            return Ok(Event::Expired);
        }
        if self.pending.is_some() || self.intent.is_some() {
            return Ok(Event::Idle);
        }
        let Some(candidate) = self.candidate.as_ref() else {
            return Ok(Event::Idle);
        };
        if matches!(candidate, Candidate::AwaitIdentityDh { .. }) {
            return Ok(Event::Idle);
        }
        let retry = candidate.retry();
        if retry.due.is_none_or(|at| now < at) {
            return Ok(Event::Idle);
        }
        if retry.sent >= self.limits.maximum_transmissions {
            self.discard_candidate();
            return Ok(Event::Expired);
        }
        let generation = candidate.generation();
        let plan = if matches!(
            candidate,
            Candidate::Alice { .. } | Candidate::AliceReady { .. }
        ) {
            Plan::Kx
        } else {
            Plan::Auth {
                force: true,
                initial: true,
            }
        };
        self.schedule(Intent {
            generation,
            plan,
            preferred: None,
        });
        Ok(Event::RetryDue)
    }
    fn book<const P: usize>(&self, book: &Book<'route, '_, '_, P>) -> Result<(), Error> {
        if book.reset_authority() == self.authority {
            Ok(())
        } else {
            Err(Error::StaleGeneration)
        }
    }
    fn live_generation(&self, generation: u64) -> bool {
        self.active
            .as_ref()
            .is_some_and(|a| a.generation == generation)
            || self
                .candidate
                .as_ref()
                .is_some_and(|c| c.generation() == generation)
    }
    fn current_auth_message(
        session: &Session<'_, '_>,
        connection: [u8; 32],
        force: bool,
    ) -> PeerMessage<'static> {
        PeerMessage::KeyExchangeAuth {
            flags: if force { KX_FORCE_REPLY } else { 0 },
            connection,
            ephemeral_key: session.local_exchange.ephemeral_key,
            ratchet_key: session.local_ratchet_public,
            auth: hash512(session.keys.root.as_ref()),
        }
    }
    fn encode_control(
        &mut self,
        intent: Intent<'route>,
        route: Route<'route>,
        output: &mut [u8],
        entropy: &mut impl Entropy,
    ) -> Result<usize, Error> {
        match intent.plan {
            Plan::Kx => {
                let (generation, exchange) = match self.candidate.as_ref() {
                    Some(Candidate::Alice {
                        generation,
                        exchange,
                        ..
                    }) => (*generation, *exchange),
                    Some(Candidate::AliceReady { live, .. }) => {
                        (live.generation, live.session.local_exchange)
                    }
                    Some(Candidate::AwaitIdentityDh {
                        generation, local, ..
                    }) if self.context.binding.role == Role::Alice => {
                        (*generation, local.exchange())
                    }
                    _ => return Err(Error::StaleGeneration),
                };
                if generation != intent.generation {
                    return Err(Error::StaleGeneration);
                }
                PeerMessage::KeyExchange {
                    flags: KX_FORCE_REPLY,
                    connection: route.connection(),
                    ephemeral_key: exchange.ephemeral_key,
                    ratchet_key: exchange.ratchet_key,
                }
                .encode(output)
            }
            Plan::Auth { force, initial } => {
                if let Some(Candidate::Betty { live, .. }) = self.candidate.as_ref()
                    && live.generation == intent.generation
                {
                    return live
                        .session
                        .initial_auth(live.session.scope(), route.connection(), force)?
                        .encode(output);
                }
                let live = self
                    .active
                    .as_ref()
                    .filter(|a| a.generation == intent.generation)
                    .ok_or(Error::StaleGeneration)?;
                if initial {
                    live.session
                        .initial_auth(live.session.scope(), route.connection(), force)?
                        .encode(output)
                } else {
                    Self::current_auth_message(&live.session, route.connection(), force)
                        .encode(output)
                }
            }
            Plan::KeepAlive => {
                if self.traffic_paused {
                    return Err(Error::NotReady);
                }
                let live = self
                    .active
                    .as_mut()
                    .filter(|a| a.generation == intent.generation)
                    .ok_or(Error::StaleGeneration)?;
                let plaintext = [0, 4, 3, 244];
                Ok(live
                    .session
                    .seal(
                        live.session.scope(),
                        route.connection(),
                        &plaintext,
                        output,
                        entropy,
                    )?
                    .bytes()
                    .len())
            }
        }
    }
    /// Schedule a real due per-connection encrypted KEEPALIVE. This is a bounded
    /// lower-priority control intent, never a plaintext wire heartbeat or ACK.
    pub fn keepalive<const P: usize>(
        &mut self,
        scope: Scope<'id>,
        route: Route<'route>,
        book: &Book<'route, '_, '_, P>,
        now: MonoInstant,
    ) -> Result<(), Error> {
        self.authorize(scope)?;
        self.time(now)?;
        self.book(book)?;
        let info = book.route_info(route)?;
        if info.expected_peer != Some(self.context.binding.peer)
            || book.keepalive_due(now) != Some(route)
        {
            return Err(Error::NotReady);
        }
        let generation = self.active.as_ref().ok_or(Error::NotReady)?.generation;
        self.schedule(Intent {
            generation,
            plan: Plan::KeepAlive,
            preferred: Some(route),
        });
        Ok(())
    }
    /// Prepare one original immutable control only on an actually eligible live
    /// route. Returning bytes is not exposure; admitted bytes remain identical
    /// until explicit original rejection/submission/completion.
    pub fn prepare<'out, const P: usize>(
        &mut self,
        scope: Scope<'id>,
        book: &Book<'route, '_, '_, P>,
        now: MonoInstant,
        output: &'out mut [u8],
        entropy: &mut impl Entropy,
    ) -> Result<Option<Prepared<'id, 'route, 'out>>, Error> {
        self.authorize(scope)?;
        self.time(now)?;
        self.book(book)?;
        self.expire_candidate();
        // Only an explicitly returned, never-admitted keepalive may be retired
        // here. Its MK/Ns remains consumed; externally previewed/bound original
        // frames must still be explicitly returned or physically settled.
        if self.pending.as_ref().is_some_and(|pending| {
            matches!(pending.state, PendingState::Retained)
                && pending.plan == Plan::KeepAlive
                && (self.traffic_paused
                    || self
                        .intent
                        .is_some_and(|intent| intent.plan != Plan::KeepAlive))
        }) {
            self.pending = None;
        }
        if let Some(pending) = self.pending.as_ref() {
            if !matches!(pending.state, PendingState::Retained) {
                return Ok(None);
            }
            let eligible = self.live_generation(pending.attempt.generation.serial)
                && book.select(self.context.binding.peer) == Some(pending.attempt.route);
            if eligible {
                let pending = self.pending.as_mut().ok_or(Error::StaleGeneration)?;
                let bytes = output.get_mut(..pending.length).ok_or(Error::Capacity)?;
                bytes.copy_from_slice(&pending.bytes[..pending.length]);
                pending.state = PendingState::Previewed;
                return Ok(Some(Prepared {
                    attempt: pending.attempt,
                    bytes,
                }));
            }
            // The caller explicitly returned this never-submitted preview.
            // A replacement route gets a new original output identity/CID;
            // the original local KX private keys remain unchanged.
            let old = self.pending.take().ok_or(Error::StaleGeneration)?;
            if self.live_generation(old.attempt.generation.serial) && old.plan != Plan::KeepAlive {
                self.schedule(Intent {
                    generation: old.attempt.generation.serial,
                    plan: old.plan,
                    preferred: None,
                });
            }
        }
        let Some(intent) = self.intent else {
            return Ok(None);
        };
        if !self.live_generation(intent.generation) {
            self.intent = None;
            return Ok(None);
        }
        let route = if let Some(preferred) = intent.preferred {
            if book.keepalive_due(now) != Some(preferred) {
                return Ok(None);
            }
            preferred
        } else {
            let Some(route) = book.select(self.context.binding.peer) else {
                return Ok(None);
            };
            route
        };
        let expected = match intent.plan {
            Plan::Kx => 104,
            Plan::Auth { .. } => 168,
            Plan::KeepAlive => 116,
        };
        if output.len() < expected {
            return Err(Error::Capacity);
        }
        let serial = self.next_attempt.checked_add(1).ok_or(Error::Overflow)?;
        let mut bytes = [0; KX_AUTH_LEN];
        let length = self.encode_control(intent, route, &mut bytes, entropy)?;
        let attempt = Attempt {
            generation: self.generation(intent.generation),
            serial,
            route,
            kind: intent.plan.kind(),
        };
        output[..length].copy_from_slice(&bytes[..length]);
        self.next_attempt = serial;
        self.intent = None;
        self.pending = Some(Pending {
            attempt,
            plan: intent.plan,
            state: PendingState::Previewed,
            bytes,
            length,
        });
        Ok(Some(Prepared {
            attempt,
            bytes: &output[..length],
        }))
    }
    /// Return only an original preview refused before connection admission.
    /// This consumes the linear view and preserves the exact retained bytes.
    pub fn reject_prepared(&mut self, prepared: Prepared<'id, 'route, '_>) -> Result<(), Error> {
        let retired = !self.live_generation(prepared.attempt.generation.serial);
        let pending = self.pending.as_mut().ok_or(Error::StaleGeneration)?;
        if pending.attempt != prepared.attempt
            || !matches!(pending.state, PendingState::Previewed)
            || prepared.bytes != &pending.bytes[..pending.length]
        {
            return Err(Error::StaleGeneration);
        }
        if self.closed || retired {
            self.pending = None;
        } else {
            pending.state = PendingState::Retained;
        }
        Ok(())
    }
    /// Bind exactly this immutable preview to the actual connection-book start.
    /// Caller reserves/queues Book's real frame first, then starts it and binds
    /// here before exposing any actual CORE output. Refusal returns the preview.
    #[expect(
        clippy::result_large_err,
        reason = "Return the original linear preview and stable context facts without an allocator or losing its cleanup authority"
    )]
    pub fn submit<'out, const P: usize>(
        &mut self,
        prepared: Prepared<'id, 'route, 'out>,
        book: &Book<'route, '_, '_, P>,
        original: connection::Attempt<'route>,
    ) -> Result<(), RejectedControl<'id, 'route, 'out>> {
        let result = (|| {
            self.authorize(prepared.attempt.generation.scope)?;
            if !self.live_generation(prepared.attempt.generation.serial) {
                return Err(Error::StaleGeneration);
            }
            self.book(book)?;
            let pending = self.pending.as_ref().ok_or(Error::StaleGeneration)?;
            if pending.attempt != prepared.attempt
                || !matches!(pending.state, PendingState::Previewed)
                || original.route() != Some(prepared.attempt.route)
                || prepared.bytes != &pending.bytes[..pending.length]
                || book.frame_bytes(original.frame())? != prepared.bytes
            {
                return Err(Error::StaleGeneration);
            }
            Ok::<(), Error>(())
        })();
        if let Err(reason) = result {
            return Err(RejectedControl { reason, prepared });
        }
        let Some(pending) = self.pending.as_mut() else {
            return Err(RejectedControl {
                reason: Error::StaleGeneration,
                prepared,
            });
        };
        pending.state = PendingState::Bound(original);
        Ok(())
    }
    /// Transfer the original linear preview into a real immutable queued Book
    /// frame. This is queue admission only; a later native start binds it.
    #[expect(
        clippy::result_large_err,
        reason = "Return the original linear preview on refused noalloc queue binding"
    )]
    pub fn queue_control<'out, const P: usize>(
        &mut self,
        prepared: Prepared<'id, 'route, 'out>,
        book: &Book<'route, '_, '_, P>,
        frame: connection::Frame<'route>,
    ) -> Result<QueuedControl<'id, 'route>, RejectedControl<'id, 'route, 'out>> {
        let checked = (|| {
            self.authorize(prepared.attempt.generation.scope)?;
            self.book(book)?;
            let pending = self.pending.as_ref().ok_or(Error::StaleGeneration)?;
            if pending.attempt != prepared.attempt
                || !matches!(pending.state, PendingState::Previewed)
                || !self.live_generation(prepared.attempt.generation.serial)
                || book.frame_route(frame)? != Some(prepared.attempt.route)
                || book.frame_bytes(frame)? != prepared.bytes
                || prepared.bytes != &pending.bytes[..pending.length]
            {
                return Err(Error::StaleGeneration);
            }
            Ok(())
        })();
        if let Err(reason) = checked {
            return Err(RejectedControl { reason, prepared });
        }
        let Some(pending) = self.pending.as_mut() else {
            return Err(RejectedControl {
                reason: Error::StaleGeneration,
                prepared,
            });
        };
        pending.state = PendingState::Queued(frame);
        Ok(QueuedControl {
            attempt: prepared.attempt,
            frame,
        })
    }
    /// Whether this admitted original control is still needed before native
    /// start. A caller cancels only its original queued frame if this is false.
    #[must_use]
    pub fn queued_needed(&self, queued: QueuedControl<'id, 'route>) -> bool {
        !self.closed
            && self.live_generation(queued.attempt.generation.serial)
            && self.pending.as_ref().is_some_and(|p| {
                p.attempt == queued.attempt
                    && matches!(p.state, PendingState::Queued(frame) if frame == queued.frame)
            })
    }
    /// Bind the actual original native start for the already admitted immutable
    /// frame. Old admitted controls still retain exact retirement after close.
    pub fn bind_queued<const P: usize>(
        &mut self,
        queued: QueuedControl<'id, 'route>,
        book: &Book<'route, '_, '_, P>,
        original: connection::Attempt<'route>,
    ) -> Result<(), Error> {
        self.book(book)?;
        let pending = self.pending.as_mut().ok_or(Error::StaleGeneration)?;
        if pending.attempt != queued.attempt
            || original.frame() != queued.frame
            || original.route() != Some(queued.attempt.route)
            || !matches!(pending.state, PendingState::Queued(frame) if frame == queued.frame)
            || book.frame_bytes(queued.frame)? != &pending.bytes[..pending.length]
        {
            return Err(Error::StaleGeneration);
        }
        pending.state = PendingState::Bound(original);
        Ok(())
    }
    /// Consume only this actual Book's original terminal queued/bound frame.
    /// Canceling never-started frames retires control without a written timer.
    pub fn complete_queued<const P: usize>(
        &mut self,
        queued: QueuedControl<'id, 'route>,
        book: &Book<'route, '_, '_, P>,
        completion: connection::Completion<'route>,
        now: MonoInstant,
    ) -> Result<Event<'id>, Error> {
        self.book(book)?;
        if completion.frame != queued.frame || book.frame_completion(queued.frame)? != completion {
            return Err(Error::StaleGeneration);
        }
        if let Some(original) = completion.attempt
            && self.pending.as_ref().is_some_and(
                |p| matches!(p.state, PendingState::Queued(frame) if frame == queued.frame),
            )
        {
            self.bind_queued(queued, book, original)?;
        }
        self.complete(queued.attempt, completion, now)
    }
    /// Consume the actual original connection completion. Only an actually
    /// exposed whole write starts this negotiation's retry clock. Old epochs
    /// merely release their original output; no new cipher counter is touched.
    pub fn complete(
        &mut self,
        attempt: Attempt<'id, 'route>,
        completion: connection::Completion<'route>,
        now: MonoInstant,
    ) -> Result<Event<'id>, Error> {
        self.time(now)?;
        let pending = self.pending.as_ref().ok_or(Error::StaleGeneration)?;
        let (original, frame) = match pending.state {
            PendingState::Bound(original) => (Some(original), original.frame()),
            PendingState::Queued(frame) if completion.attempt.is_none() => (None, frame),
            _ => return Err(Error::StaleGeneration),
        };
        if pending.attempt != attempt
            || completion.attempt != original
            || completion.frame != frame
            || completion.route != Some(attempt.route)
        {
            return Err(Error::StaleGeneration);
        }
        let written = completion.outcome == connection::Outcome::Written;
        if written && !completion.exposed
            || completion.outcome == connection::Outcome::Unsent && completion.exposed
            || completion.outcome == connection::Outcome::Unknown && !completion.exposed
        {
            return Err(Error::InvalidInput);
        }
        self.expire_candidate();
        let applies = self
            .candidate
            .as_ref()
            .is_some_and(|c| c.generation() == attempt.generation.serial);
        let mut next_retry = None;
        if written && applies && attempt.kind != Kind::KeepAlive {
            let mut retry = self
                .candidate
                .as_ref()
                .ok_or(Error::StaleGeneration)?
                .retry();
            let at = MonoInstant(now.0.checked_add(retry.delay).ok_or(Error::Overflow)?);
            retry.sent = retry.sent.checked_add(1).ok_or(Error::Overflow)?;
            retry.due = Some(at);
            retry.delay = retry
                .delay
                .saturating_mul(2)
                .min(self.limits.maximum_retry_micros);
            next_retry = Some(retry);
        }
        let pending = self.pending.take().ok_or(Error::StaleGeneration)?;
        if written {
            self.scope().statistics().add(
                match attempt.kind {
                    Kind::KeyExchange => Metric::KxSent,
                    Kind::Authentication => Metric::AuthSent,
                    Kind::KeepAlive => Metric::KeepaliveSent,
                },
                1,
            );
        }
        if let Some(retry) = next_retry {
            *self
                .candidate
                .as_mut()
                .ok_or(Error::StaleGeneration)?
                .retry_mut() = retry;
        } else if !written && !self.closed {
            let needed = match pending.plan {
                Plan::Auth { .. } => self.live_generation(attempt.generation.serial),
                Plan::Kx => {
                    matches!(self.candidate.as_ref(), Some(Candidate::Alice { generation, .. })
                    if *generation == attempt.generation.serial)
                }
                Plan::KeepAlive => false,
            };
            if needed {
                // The original physical attempt is already terminal. A new
                // logical auth attempt may be needed even after confirmation;
                // no actual-written timer, counter rollback or same-attempt
                // re-encryption is fabricated. Candidate expiry stays fixed.
                self.schedule(Intent {
                    generation: attempt.generation.serial,
                    plan: pending.plan,
                    preferred: None,
                });
            }
        }
        Ok(Event::Idle)
    }
    /// Actual route retirement never rewinds/end-destroys working crypto. The
    /// old original output still needs its actual Book/native completion.
    pub fn connection_lost(
        &self,
        scope: Scope<'id>,
        route: Route<'route>,
    ) -> Result<Option<Attempt<'id, 'route>>, Error> {
        self.authorize(scope)?;
        Ok(self
            .pending
            .as_ref()
            .filter(|p| p.attempt.route == route)
            .map(|p| p.attempt))
    }

    /// Authenticate real endpoint ciphertext against confirmed keys first,
    /// then the sole candidate. Only a complete successful candidate open may
    /// promote it; wrong tags never destroy or replace the working session.
    pub fn open<'out>(
        &mut self,
        scope: Scope<'id>,
        input: Endpoint<'route, '_>,
        wire: &[u8],
        output: &'out mut [u8],
    ) -> Result<Received<'id, 'out>, Error> {
        self.endpoint(scope, &input)?;
        // The reactor services next_deadline() via tick() before incoming IO;
        // this method has no new clock argument and cannot read wall time.
        self.expire_candidate();
        if !matches!(input.message(), PeerMessage::Encrypted { .. })
            || PeerMessage::decode(wire)? != input.message()
        {
            return Err(Error::Authentication);
        }
        if self.active.is_none()
            && !matches!(
                self.candidate,
                Some(Candidate::Betty { .. } | Candidate::AliceReady { .. })
            )
        {
            let metric = if matches!(
                self.candidate,
                Some(
                    Candidate::Alice { .. }
                        | Candidate::AwaitIdentityDh {
                            authentication: Some(_),
                            ..
                        }
                )
            ) {
                Metric::EncryptedWithoutKx
            } else {
                Metric::EncryptedWithoutAnyKx
            };
            scope.statistics().add(metric, 1);
        }
        let mut active_failure = None;
        if let Some(active) = self.active.as_mut() {
            match active
                .session
                .authenticate(active.session.scope(), wire, output)
            {
                Ok((size, header)) => {
                    let generation = Generation {
                        scope,
                        serial: active.generation,
                    };
                    // Working old-epoch traffic also ages out an unsolicited
                    // responder candidate, as in the source unverified budget.
                    // A locally requested Alice probe has a distinct owner.
                    if self.context.binding.role == Role::Betty
                        && matches!(
                            self.candidate,
                            Some(Candidate::Betty { .. } | Candidate::AwaitIdentityDh { .. })
                        )
                    {
                        self.bad_candidate();
                    }
                    return Ok(Received {
                        generation,
                        promoted: false,
                        opened: Opened {
                            scope,
                            bytes: &output[..size],
                            header,
                        },
                    });
                }
                Err(error @ (Error::Authentication | Error::Replay)) => {
                    active_failure = Some(error);
                }
                Err(error) => return Err(error),
            }
        }
        let Some(Candidate::Betty { live, .. } | Candidate::AliceReady { live, .. }) =
            self.candidate.as_mut()
        else {
            if active_failure.is_some() {
                scope.statistics().add(Metric::UnableDecrypt, 1);
            }
            return Err(active_failure.unwrap_or(Error::NotReady));
        };
        let result = live
            .session
            .authenticate(live.session.scope(), wire, output);
        let (size, header) = match result {
            Ok(result) => result,
            Err(error) => {
                if matches!(error, Error::Authentication | Error::Replay) {
                    scope.statistics().add(Metric::UnableDecrypt, 1);
                    self.bad_candidate();
                }
                return Err(error);
            }
        };
        let Some(Candidate::Betty { live, .. } | Candidate::AliceReady { live, .. }) =
            self.candidate.take()
        else {
            return Err(Error::StaleGeneration);
        };
        let generation = self.promote(live);
        Ok(Received {
            generation,
            promoted: true,
            opened: Opened {
                scope,
                bytes: &output[..size],
                header,
            },
        })
    }

    /// Seal one actual linear channel Prepared exactly once. Successful output
    /// consumes Prepared; neither it nor its private fields can be recreated by
    /// copying Attempt. A refused call returns that same original Prepared.
    /// Native reservation precedes this method; bytes/Attempt live with caller.
    pub fn seal_channel<'channel, 'plain, 'out, const P: usize>(
        &mut self,
        scope: Scope<'id>,
        owner: &peer::ChannelOwner<'channel, '_, '_>,
        prepared: peer::Prepared<'channel, 'plain>,
        book: &Book<'route, '_, '_, P>,
        output: &'out mut [u8],
        entropy: &mut impl Entropy,
    ) -> Result<SealedChannel<'id, 'route, 'channel, 'out>, RejectedChannel<'channel, 'plain>> {
        let preflight = (|| {
            self.authorize(scope)?;
            self.book(book)?;
            if self.traffic_paused {
                return Err(Error::NotReady);
            }
            let address = owner.address();
            if owner.pending() != Some(prepared.attempt())
                || owner.scope() != prepared.attempt().scope()
                || address.local_peer != self.context.binding.local
                || address.remote_peer != self.context.binding.peer
            {
                return Err(Error::StaleGeneration);
            }
            ChannelMessage::decode(prepared.bytes())?;
            let route = book
                .select(self.context.binding.peer)
                .ok_or(Error::WouldBlock)?;
            if self.active.is_none() {
                return Err(Error::NotReady);
            }
            Ok::<_, Error>(route)
        })();
        let route = match preflight {
            Ok(route) => route,
            Err(reason) => return Err(RejectedChannel { reason, prepared }),
        };
        let Some(live) = self.active.as_mut() else {
            return Err(RejectedChannel {
                reason: Error::NotReady,
                prepared,
            });
        };
        let original = prepared.attempt();
        match live.session.seal(
            live.session.scope(),
            route.connection(),
            prepared.bytes(),
            output,
            entropy,
        ) {
            Ok(sealed) => Ok(SealedChannel {
                generation: Generation {
                    scope,
                    serial: live.generation,
                },
                route,
                original,
                sealed,
            }),
            Err(reason) => Err(RejectedChannel { reason, prepared }),
        }
    }
    /// Seal an actual unknown-channel DESTROY only after the containing owner
    /// reserved final frame capacity. Never expose a generic DATA sealing bypass.
    pub fn reject_channel<'out, const P: usize>(
        &mut self,
        scope: Scope<'id>,
        channel: u32,
        book: &Book<'route, '_, '_, P>,
        output: &'out mut [u8],
        entropy: &mut impl Entropy,
    ) -> Result<Rejection<'id, 'route, 'out>, Error> {
        self.authorize(scope)?;
        self.book(book)?;
        if self.traffic_paused {
            return Err(Error::NotReady);
        }
        let route = book
            .select(self.context.binding.peer)
            .ok_or(Error::WouldBlock)?;
        if !book.payload_capacity(route, 124)? {
            return Err(Error::Capacity);
        }
        let mut plaintext = [0; 12];
        ChannelMessage::Destroy {
            reserved: 0,
            channel,
        }
        .encode(&mut plaintext)?;
        let live = self.active.as_mut().ok_or(Error::NotReady)?;
        let generation = Generation {
            scope,
            serial: live.generation,
        };
        let sealed = live.session.seal(
            live.session.scope(),
            route.connection(),
            &plaintext,
            output,
            entropy,
        )?;
        Ok(Rejection {
            generation,
            route,
            sealed,
        })
    }
    /// External canonical count/time policy may request the next permitted DH
    /// ratchet, never a counter reset or an unauthenticated key replacement.
    pub fn request_ratchet(&mut self, scope: Scope<'id>) -> Result<(), Error> {
        self.authorize(scope)?;
        let live = self.active.as_mut().ok_or(Error::NotReady)?;
        live.session.request_ratchet(live.session.scope())
    }
    /// Recover both original storage packages only after permanent close and
    /// actual retirement of control output and the original DH operation.
    #[expect(
        clippy::result_large_err,
        reason = "Keep the original bounded owner on refused noalloc pool return"
    )]
    pub fn into_stores(mut self) -> Result<Stores<'slots>, gnunet_types::Rejected<Self>> {
        if !self.closed || self.pending.is_some() || self.identity_job.is_some() {
            return Err(gnunet_types::Rejected {
                value: self,
                reason: Error::WouldBlock,
            });
        }
        let first = match self.free[0].take() {
            Some(s) => s,
            None => {
                return Err(gnunet_types::Rejected {
                    value: self,
                    reason: Error::NotReady,
                });
            }
        };
        let second = match self.free[1].take() {
            Some(s) => s,
            None => {
                self.free[0] = Some(first);
                return Err(gnunet_types::Rejected {
                    value: self,
                    reason: Error::NotReady,
                });
            }
        };
        Ok(Stores { first, second })
    }
    /// Explicit permanent retirement wipes all private sessions/candidates but
    /// keeps original bound control output until its actual completion arrives.
    /// Returned snapshot conveys no synthetic physical/channel success.
    pub fn close(&mut self, scope: Scope<'id>) -> Result<Snapshot<'id, 'route>, Error> {
        self.authorize(scope)?;
        self.closed = true;
        self.discard_candidate();
        if let Some(active) = self.active.take() {
            self.put_storage(active.session.recycle_storage());
        }
        self.intent = None;
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| matches!(pending.state, PendingState::Retained))
        {
            self.pending = None;
        }
        self.traffic_paused = true;
        self.context.close();
        Ok(self.snapshot())
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod async_identity_tests;
