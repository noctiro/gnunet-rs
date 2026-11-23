//! Original-instance NSE effects. The host retains actual native writes until
//! completion or physical retirement; these tokens never stand for delivery.
use crate::{
    crypto::{self, ReferenceEndian, WorkBits},
    history::{self, HISTORY_SIZE, Summary},
};
use gnunet_crypto::{EddsaPublicKey, EddsaSignature, pow};
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime,
    nse::{
        self,
        flood::{self, Fields, Message},
    },
};

/// Exclusively borrowed, non-zero-sized original owner storage.
#[derive(Debug, Default)]
pub struct Instance {
    marker: u8,
}
impl Instance {
    /// Create a distinct service brand; moving it while borrowed is forbidden by Rust.
    #[must_use]
    pub const fn new() -> Self {
        Self { marker: 0 }
    }
}
#[derive(Clone, Copy, Debug)]
struct Stamp<'i> {
    brand: &'i Instance,
    serial: u64,
}
impl PartialEq for Stamp<'_> {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.brand, other.brand) && self.serial == other.serial
    }
}
impl Eq for Stamp<'_> {}
macro_rules! id {
    ($name:ident,$doc:literal) => {
        #[doc=$doc]
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct $name<'i>(Stamp<'i>);
    };
}
id!(
    PeerId,
    "One original CORE peer connection, never a wire field."
);
id!(
    SubscriberId,
    "One original NSE subscriber connection, never a wire field."
);
id!(
    EffectId,
    "One original native effect; numeric coincidence grants no authority."
);

/// Host-supplied uniform bounded randomness. A refusal preserves pending scheduling.
pub trait Random {
    /// Return a value strictly below nonzero `upper`, or preserve the original cause.
    fn below(&mut self, upper: u32) -> Result<u32, Error>;
}

/// Official algorithm settings. Endianness is internal reference behavior, not new wire negotiation.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// All peers use the same round interval; normal GNUnet uses one hour.
    pub interval_micros: u64,
    /// Raw-file profile's logical delay between bounded proof-search calls,
    /// normally 5000 microseconds. Durable hosts pace work with elapsed time.
    pub work_delay_micros: u64,
    /// Default15; zero explicitly disables crypto authentication.
    pub work_bits: WorkBits,
    /// Native timestamp memory behavior of the reference, testable on either target.
    pub reference_endian: ReferenceEndian,
    /// Internal jitter policy. False matches the normal C preprocessor-active profile.
    pub randomize_delays: bool,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            interval_micros: history::INTERVAL_MICROS,
            work_delay_micros: 5000,
            work_bits: WorkBits::default(),
            reference_endian: ReferenceEndian::native(),
            randomize_delays: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AlarmKind<'i> {
    Round,
    Work,
    Peer(PeerId<'i>),
}
/// Original absolute logical deadline. Early native completion cannot advance it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Alarm<'i> {
    id: EffectId<'i>,
    kind: AlarmKind<'i>,
    at: u64,
}
impl Alarm<'_> {
    /// Original logical deadline, not a native delay or a delivery timeout.
    #[must_use]
    pub const fn deadline(self) -> u64 {
        self.at
    }
}
/// A host must retire old physical outputs/signatures/work/timers before committing this barrier.
#[must_use]
#[derive(Debug)]
pub struct Retirement<'i> {
    id: EffectId<'i>,
}
/// Immutable original local PILS signing request. Its actual signer must match.
#[derive(Clone, Copy, Debug)]
pub struct SignRequest<'i> {
    id: EffectId<'i>,
    peer: PeerId<'i>,
    epoch: EffectId<'i>,
    frame: Fields,
}
impl<'i> SignRequest<'i> {
    /// Original destination connection whose signing effect is being retained.
    #[must_use]
    pub const fn peer(self) -> PeerId<'i> {
        self.peer
    }
    /// Exact original purpose-prefixed snapshot; never reconstructed from a later history slot.
    pub fn payload(&self) -> Result<[u8; flood::SIGNED_LEN], Error> {
        let mut bytes = [0; flood::SIGNED_LEN];
        self.frame.encode_signed(&mut bytes)?;
        Ok(bytes)
    }
    /// Expected actual signer for this particular request.
    #[must_use]
    pub const fn signer(&self) -> [u8; 32] {
        self.frame.origin
    }
}
/// Original CORE output snapshot; written completion returns capacity, not delivery credit.
#[derive(Clone, Copy, Debug)]
pub struct Transmission<'i> {
    id: EffectId<'i>,
    peer: PeerId<'i>,
    epoch: EffectId<'i>,
    frame: Fields,
}
impl<'i> Transmission<'i> {
    /// Original destination connection. A reconnect has a different token.
    #[must_use]
    pub const fn peer(self) -> PeerId<'i> {
        self.peer
    }
    /// Encode the retained original frame, preserving a forwarded signature.
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, Error> {
        self.frame.encode(output)
    }
    /// Original public snapshot; this is not an application delivery receipt.
    #[must_use]
    pub const fn fields(&self) -> Fields {
        self.frame
    }
}
/// Immutable original public notification, retained across partial native writes.
#[derive(Clone, Copy, Debug)]
pub struct Notification<'i> {
    id: EffectId<'i>,
    subscriber: SubscriberId<'i>,
    revision: u64,
    estimate: nse::Estimate,
}
impl<'i> Notification<'i> {
    /// Original subscriber connection.
    #[must_use]
    pub const fn subscriber(self) -> SubscriberId<'i> {
        self.subscriber
    }
    /// Original encoded estimate; later revisions coalesce behind it.
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, Error> {
        self.estimate.encode(output)
    }
    /// Public observation with its original logical time sample.
    #[must_use]
    pub const fn estimate(self) -> nse::Estimate {
        self.estimate
    }
}
/// Bounded proof-search authority for one identity epoch and original counter.
#[derive(Clone, Copy, Debug)]
pub struct WorkRequest<'i> {
    id: EffectId<'i>,
    epoch: EffectId<'i>,
    counter: u64,
}
/// Result of at most the requested number of real hashes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkProgress {
    /// Valid raw proof found for this exact identity/work requirement. A
    /// durable owner still needs its exact commit before using the proof.
    Found([u8; 8]),
    /// Bounded work exhausted; a new owned delay is pending.
    More,
    /// Remaining counter range exhausted; no wrap or implicit retry of earlier values occurs.
    Exhausted,
}

/// Recovery from a board store bound to the exact identity and proof policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofRecovery {
    /// No committed proof state exists. Start at candidate zero.
    Missing,
    /// The first untested big-endian search counter.
    Checkpoint(u64),
    /// Original confirmed proof bytes, which startup still authenticates.
    Confirmed([u8; 8]),
    /// The final candidate failed and no counter remains.
    Exhausted,
}

/// Exact durable update intended for the original board proof record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofUpdate {
    /// Every earlier counter was tested; this is the first untested one.
    Checkpoint(u64),
    /// The actual validated candidate. Acknowledgement makes it usable.
    Candidate([u8; 8]),
    /// The entire search space for this identity has been exhausted.
    Exhausted,
}

/// Original typed board proof write. Issuing this value does not commit it.
#[derive(Clone, Copy, Debug)]
pub struct DurablePersistRequest<'i> {
    id: EffectId<'i>,
    epoch: EffectId<'i>,
    revision: u64,
    update: ProofUpdate,
}
impl DurablePersistRequest<'_> {
    /// Exact state, including the distinction between a counter and proof.
    #[must_use]
    pub const fn update(&self) -> ProofUpdate {
        self.update
    }
}

/// Original desktop raw8 proof-file write request. Emission is not durability.
#[derive(Clone, Copy, Debug)]
pub struct PersistRequest<'i> {
    ticket: DurablePersistRequest<'i>,
    bytes: [u8; 8],
}
impl PersistRequest<'_> {
    /// Exact raw8 file bytes, without a private wrapper or endian conversion.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; 8] {
        &self.bytes
    }
}
/// Round policy result; control cancellation does not authenticate an equal/lower claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Received {
    /// No active validated PILS context exists yet.
    NoIdentity,
    /// Timestamp is outside previous/current/next.
    OutsideRounds,
    /// Equal known claim cancelled the opposing current transmission.
    Equal,
    /// Lower claim scheduled an owned pushback without replacing history.
    Pushback,
    /// The configured crypto gate admitted better current or previous-round history.
    Better,
    /// The configured gate admitted better next-round data, retained until its actual round.
    Carryover,
    /// A trusted self connection prompted a public estimate update.
    SelfUpdate,
    /// A next-round claim did not improve the retained best.
    NoImprovement,
}
/// One native timer completion's logical outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlarmProgress {
    /// Original logical deadline is still in the future; lease remains live.
    Early,
    /// One round advanced. Large clock jumps require bounded repeated calls.
    Round,
    /// One raw-file profile work request is now eligible.
    Work,
    /// A peer effect was prepared, deferred behind an original output, or lacked history/proof.
    Peer,
}
#[derive(Clone, Copy)]
struct Entry {
    frame: Fields,
    local_unsigned: bool,
}
impl Entry {
    // A local unsigned frame is a scheduling placeholder until this exact
    // identity actually has its proof. Remote entries reached crypto::admit.
    // A score of zero remains a real candidate, not an absence sentinel.
    fn qualified(self, identity: Identity<'_>) -> bool {
        !self.local_unsigned
            || (self.frame.origin == identity.key
                && identity.proof.confirmed() == Some(self.frame.proof))
    }
}
#[derive(Clone, Copy)]
enum Pending<'i> {
    Sign {
        request: SignRequest<'i>,
        issued: bool,
        cancelled: bool,
    },
    Send {
        request: Transmission<'i>,
        issued: bool,
        admitted: bool,
    },
}
#[derive(Clone, Copy)]
struct Peer<'i> {
    id: PeerId<'i>,
    key: [u8; 32],
    previous: bool,
    needs_schedule: bool,
    alarm: Option<Alarm<'i>>,
    deferred: bool,
    pending: Option<Pending<'i>>,
}
#[derive(Clone, Copy)]
struct Subscriber<'i> {
    id: SubscriberId<'i>,
    seen: u64,
    refresh: bool,
    pending: Option<Notification<'i>>,
}
#[derive(Clone, Copy)]
struct Identity<'i> {
    key: [u8; 32],
    epoch: EffectId<'i>,
    proof: LocalProof<'i>,
    activation: Activation,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Activation {
    Immediate,
    Durable,
}

enum Recovery {
    Raw(Option<[u8; 8]>),
    Durable(ProofRecovery),
}

#[derive(Clone, Copy)]
struct Search<'i> {
    counter: u64,
    id: EffectId<'i>,
    ready: bool,
}

#[derive(Clone, Copy)]
enum LocalProof<'i> {
    Searching(Search<'i>),
    AwaitingCommit { raw: [u8; 8], revision: u64 },
    Confirmed([u8; 8]),
    Exhausted,
}

impl LocalProof<'_> {
    const fn confirmed(self) -> Option<[u8; 8]> {
        match self {
            Self::Confirmed(raw) => Some(raw),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
struct Persistence<'i> {
    request: DurablePersistRequest<'i>,
    uncertain: bool,
}

/// Bounded pure NSE service. It owns no runtime, private key, allocator or Argon2 array.
/// Native hosts must honor retirement barriers and report actual original completions.
pub struct Service<'i, const P: usize, const S: usize> {
    brand: &'i Instance,
    sequence: u64,
    config: Config,
    closed: bool,
    identity: Option<Identity<'i>>,
    retirement: Option<EffectId<'i>>,
    peers: [Option<Peer<'i>>; P],
    subscribers: [Option<Subscriber<'i>>; S],
    history: [Option<Entry>; HISTORY_SIZE],
    index: usize,
    count: usize,
    current: u64,
    next: u64,
    carryover: Option<Fields>,
    round_alarm: Option<Alarm<'i>>,
    work_alarm: Option<Alarm<'i>>,
    revision: u64,
    peer_cursor: usize,
    sign_cursor: usize,
    send_cursor: usize,
    subscriber_cursor: usize,
    persist_revision: u64,
    persisted_revision: u64,
    persist_pending: Option<Persistence<'i>>,
    persist_latest: Option<ProofUpdate>,
    metrics: crate::metrics::Metrics,
}
impl<'i, const P: usize, const S: usize> Service<'i, P, S> {
    /// Start an empty service; subscriptions can observe its legitimate zero snapshot before PILS.
    pub fn new(instance: &'i mut Instance, config: Config) -> Result<Self, Error> {
        if config.interval_micros == 0 || config.work_delay_micros == u64::MAX {
            return Err(Error::InvalidInput);
        }
        let _ = instance.marker;
        Ok(Self {
            brand: instance,
            sequence: 1,
            config,
            closed: false,
            identity: None,
            retirement: None,
            peers: [None; P],
            subscribers: [None; S],
            history: [None; HISTORY_SIZE],
            index: HISTORY_SIZE - 1,
            count: 0,
            current: 0,
            next: 0,
            carryover: None,
            round_alarm: None,
            work_alarm: None,
            revision: 1,
            peer_cursor: 0,
            sign_cursor: 0,
            send_cursor: 0,
            subscriber_cursor: 0,
            persist_revision: 0,
            persisted_revision: 0,
            persist_pending: None,
            persist_latest: None,
            metrics: crate::metrics::Metrics::new(),
        })
    }
    fn live(&self) -> Result<(), Error> {
        if self.closed {
            Err(Error::Closed)
        } else {
            Ok(())
        }
    }
    fn fresh(&mut self) -> Result<EffectId<'i>, Error> {
        self.live()?;
        let serial = self.sequence;
        self.sequence = serial.checked_add(1).ok_or(Error::Overflow)?;
        Ok(EffectId(Stamp {
            brand: self.brand,
            serial,
        }))
    }
    fn peer_index(&self, id: PeerId<'i>) -> Result<usize, Error> {
        self.live()?;
        self.peers
            .iter()
            .position(|p| p.is_some_and(|p| p.id == id))
            .ok_or(Error::Stale)
    }
    fn subscriber_index(&self, id: SubscriberId<'i>) -> Result<usize, Error> {
        self.live()?;
        self.subscribers
            .iter()
            .position(|s| s.is_some_and(|s| s.id == id))
            .ok_or(Error::Stale)
    }
    fn changed(&mut self) -> Result<(), Error> {
        self.revision = self.revision.checked_add(1).ok_or(Error::Overflow)?;
        self.refresh_metrics();
        Ok(())
    }
    fn refresh_metrics(&mut self) {
        let peers = self.peer_count();
        let diameter = self
            .history
            .iter()
            .flatten()
            .map(|entry| entry.frame.hops)
            .max()
            .unwrap_or(0);
        let estimate = self.compute_summary().and_then(Summary::linear_count);
        self.metrics.gauges(estimate, diameter, peers);
    }
    /// Actual cumulative observations and current gauges for this Service only.
    /// Reading does not sample a clock, hash a key, allocate or publish anything.
    #[must_use]
    pub const fn metrics(&self) -> crate::metrics::Metrics {
        self.metrics
    }

    fn local(&self, timestamp: u64, identity: Identity<'i>) -> Entry {
        Entry {
            frame: Fields {
                hops: 0,
                timestamp: AbsoluteTime::from_micros(timestamp),
                matching_bits: crypto::matching_bits(
                    timestamp,
                    &identity.key,
                    self.config.reference_endian,
                ),
                origin: identity.key,
                proof: identity.proof.confirmed().unwrap_or([0; 8]),
                signature: [0; 64],
            },
            local_unsigned: true,
        }
    }
    // Proof completion can make the local candidate eligible after a weaker
    // remote candidate was accepted. Ranking never rewrites an issued lease.
    fn prefer_current_local(&mut self, local: Entry, identity: Identity<'_>) {
        if local.qualified(identity)
            && self.history[self.index]
                .filter(|entry| entry.qualified(identity))
                .is_none_or(|entry| local.frame.matching_bits > entry.frame.matching_bits)
        {
            self.history[self.index] = Some(local);
        }
    }
    fn previous_index(&self) -> usize {
        (self.index + HISTORY_SIZE - 1) % HISTORY_SIZE
    }
    fn current_or_previous(&self, time: u64) -> bool {
        time == self.current || self.current.checked_sub(self.config.interval_micros) == Some(time)
    }
    fn publish_proof_update(&mut self, update: ProofUpdate) -> Result<u64, Error> {
        self.persist_revision = self
            .persist_revision
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        self.persist_latest = Some(update);
        Ok(self.persist_revision)
    }
    /// Original active identity epoch; no private key is held by this service.
    #[must_use]
    pub fn identity(&self) -> Option<[u8; 32]> {
        self.identity.map(|i| i.key)
    }
    /// Actual usable local proof; a durable candidate becomes visible here
    /// only after its exact committed write is acknowledged.
    #[must_use]
    pub fn local_proof(&self) -> Option<[u8; 8]> {
        self.identity
            .and_then(|identity| identity.proof.confirmed())
    }
    /// Number of currently retained peer connections.
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.peers.iter().flatten().count()
    }
    /// Current logical round and next boundary, if an identity is active.
    #[must_use]
    pub fn rounds(&self) -> Option<(u64, u64)> {
        self.identity.map(|_| (self.current, self.next))
    }
    /// Copy the public best current packet fields; unsigned local snapshots grant no send authority.
    #[must_use]
    pub fn best(&self) -> Option<Fields> {
        self.history[self.index].map(|e| e.frame)
    }
    /// Compute the official weighted summary; a snapshot is not a precise authenticated peer count.
    pub fn summary(&self) -> Result<Summary, Error> {
        self.live()?;
        self.compute_summary()
    }
    fn compute_summary(&self) -> Result<Summary, Error> {
        let mut values = [0; HISTORY_SIZE];
        let durable = self
            .identity
            .filter(|identity| identity.activation == Activation::Durable);
        let mut count = 0;
        for i in 0..self.count {
            let entry = self.history[(self.index + HISTORY_SIZE - i) % HISTORY_SIZE];
            if durable.is_some_and(|identity| entry.is_none_or(|entry| !entry.qualified(identity)))
            {
                continue;
            }
            values[count] = entry.map_or(0, |entry| entry.frame.matching_bits);
            count += 1;
        }
        history::summarize(&values[..count], self.peer_count())
    }
    /// Invalidate original effects before native retirement. The host must stop old physical owners
    /// before finish_identity_change; this token is not a proof-file lock or a durability guarantee.
    pub fn begin_identity_change(&mut self) -> Result<Retirement<'i>, Error> {
        let _next_revision = self.revision.checked_add(1).ok_or(Error::Overflow)?;
        let id = self.fresh()?;
        self.identity = None;
        self.retirement = Some(id);
        self.round_alarm = None;
        self.work_alarm = None;
        self.carryover = None;
        self.history = [None; HISTORY_SIZE];
        self.metrics.reset_diameter();
        self.count = 0;
        self.persist_pending = None;
        self.persist_latest = None;
        self.persist_revision = 0;
        self.persisted_revision = 0;
        for peer in self.peers.iter_mut().flatten() {
            peer.alarm = None;
            peer.pending = None;
            peer.needs_schedule = false;
            peer.deferred = false;
        }
        for subscriber in self.subscribers.iter_mut().flatten() {
            subscriber.pending = None;
        }
        self.changed()?;
        Ok(Retirement { id })
    }
    /// Commit a host-validated actual PILS announcement after retiring original outputs. Saved raw8
    /// is revalidated for this exact new identity. Refusal keeps the barrier available for retry.
    pub fn finish_identity_change(
        &mut self,
        barrier: &Retirement<'i>,
        key: [u8; 32],
        saved: [u8; 8],
        now: u64,
        memory: &mut [pow::Block],
    ) -> Result<(), Error> {
        self.finish_identity_change_from_saved(barrier, key, Some(saved), now, memory)
    }

    /// Commit an identity with its explicitly present raw proof or search cursor.
    /// An absent record starts at cursor zero without using the work arena.
    /// A present all-zero record is checked just like any other raw proof.
    pub fn finish_identity_change_from_saved(
        &mut self,
        barrier: &Retirement<'i>,
        key: [u8; 32],
        saved: Option<[u8; 8]>,
        now: u64,
        memory: &mut [pow::Block],
    ) -> Result<(), Error> {
        self.finish_identity_change_inner(barrier, key, Recovery::Raw(saved), now, memory)
    }

    /// Commit one identity with exact typed recovery from its board store.
    /// Only confirmed raw bytes are authenticated during startup; a search
    /// checkpoint remains the first untested value even if it would pass work.
    pub fn finish_identity_change_durable(
        &mut self,
        barrier: &Retirement<'i>,
        key: [u8; 32],
        recovery: ProofRecovery,
        now: u64,
        memory: &mut [pow::Block],
    ) -> Result<(), Error> {
        self.finish_identity_change_inner(barrier, key, Recovery::Durable(recovery), now, memory)
    }

    fn finish_identity_change_inner(
        &mut self,
        barrier: &Retirement<'i>,
        key: [u8; 32],
        recovery: Recovery,
        now: u64,
        memory: &mut [pow::Block],
    ) -> Result<(), Error> {
        self.live()?;
        if self.retirement != Some(barrier.id) {
            return Err(Error::Stale);
        }
        let _next_revision = self.revision.checked_add(1).ok_or(Error::Overflow)?;
        let current = (now / self.config.interval_micros) * self.config.interval_micros;
        let next = current
            .checked_add(self.config.interval_micros)
            .ok_or(Error::Overflow)?;
        let (activation, recovered) = match recovery {
            Recovery::Raw(Some(raw)) => {
                let recovered = if crypto::valid_proof(self.config.work_bits, &key, &raw, memory)? {
                    ProofRecovery::Confirmed(raw)
                } else {
                    ProofRecovery::Checkpoint(u64::from_be_bytes(raw))
                };
                (Activation::Immediate, recovered)
            }
            Recovery::Raw(None) => (Activation::Immediate, ProofRecovery::Missing),
            Recovery::Durable(recovered) => {
                if let ProofRecovery::Confirmed(raw) = recovered
                    && !crypto::valid_proof(self.config.work_bits, &key, &raw, memory)?
                {
                    return Err(Error::Authentication);
                }
                (Activation::Durable, recovered)
            }
        };
        let epoch = self.fresh()?;
        let round_id = self.fresh()?;
        let (proof, work_alarm) = match recovered {
            ProofRecovery::Missing | ProofRecovery::Checkpoint(_) => {
                let counter = match recovered {
                    ProofRecovery::Checkpoint(counter) => counter,
                    _ => 0,
                };
                let first_due = (activation == Activation::Immediate).then_some(now);
                let (search, alarm) = self.issue_search(counter, first_due)?;
                (LocalProof::Searching(search), alarm)
            }
            ProofRecovery::Confirmed(raw) => (LocalProof::Confirmed(raw), None),
            ProofRecovery::Exhausted => (LocalProof::Exhausted, None),
        };
        let identity = Identity {
            key,
            epoch,
            proof,
            activation,
        };
        self.current = current;
        self.next = next;
        self.index = HISTORY_SIZE - 1;
        self.count = usize::from(proof.confirmed().is_some());
        self.identity = Some(identity);
        self.retirement = None;
        self.history[self.index] = Some(self.local(current, identity));
        if proof.confirmed().is_some()
            && let Some(previous) = current.checked_sub(self.config.interval_micros)
        {
            self.history[self.previous_index()] = Some(self.local(previous, identity));
        }
        self.round_alarm = Some(Alarm {
            id: round_id,
            kind: AlarmKind::Round,
            at: next,
        });
        self.work_alarm = work_alarm;
        for peer in self.peers.iter_mut().flatten() {
            peer.previous = true;
            peer.needs_schedule = true;
        }
        self.changed()
    }
    /// Adopt one actual original CORE connection. Duplicate identities are rejected, not merged.
    pub fn connect_peer(&mut self, key: [u8; 32]) -> Result<PeerId<'i>, Error> {
        self.live()?;
        if self.peers.iter().flatten().any(|p| p.key == key) {
            return Err(Error::Conflict);
        }
        let slot = self
            .peers
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let id = PeerId(self.fresh()?.0);
        self.peers[slot] = Some(Peer {
            id,
            key,
            previous: true,
            needs_schedule: true,
            alarm: None,
            deferred: false,
            pending: None,
        });
        self.refresh_metrics();
        Ok(id)
    }
    /// Retire exactly one original peer's timers/signatures/output before forgetting its token.
    pub fn disconnect_peer(&mut self, peer: PeerId<'i>) -> Result<(), Error> {
        let index = self.peer_index(peer)?;
        self.peers[index] = None;
        self.refresh_metrics();
        Ok(())
    }
    /// Physical CORE MQ loss retires all original peer authorities; subscribers remain independent.
    pub fn core_lost(&mut self) {
        self.peers = [None; P];
        self.refresh_metrics();
    }
    /// Apply exact START321 and reserve one bounded native subscriber with immediate snapshot.
    pub fn subscribe(&mut self, start: &[u8]) -> Result<SubscriberId<'i>, Error> {
        self.live()?;
        nse::decode_start(start)?;
        let index = self
            .subscribers
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let id = SubscriberId(self.fresh()?.0);
        self.subscribers[index] = Some(Subscriber {
            id,
            seen: 0,
            refresh: true,
            pending: None,
        });
        Ok(id)
    }

    /// Apply another exact START321 on the same original subscribed stream.
    /// An accepted request requires a fresh snapshot even at the same estimate
    /// revision. The original subscription and any other clients are unchanged.
    ///
    /// # Errors
    /// Refuses invalid framing or a stale subscriber. Returns WouldBlock while
    /// a previous snapshot is requested or its original writer still owns it.
    pub fn refresh_subscription(
        &mut self,
        id: SubscriberId<'i>,
        start: &[u8],
    ) -> Result<(), Error> {
        let index = self.subscriber_index(id)?;
        nse::decode_start(start)?;
        let subscriber = self.subscribers[index].as_mut().ok_or(Error::Stale)?;
        if subscriber.refresh || subscriber.pending.is_some() {
            return Err(Error::WouldBlock);
        }
        subscriber.refresh = true;
        Ok(())
    }

    /// Retire the original subscriber connection, without acknowledging any other stream.
    pub fn unsubscribe(&mut self, id: SubscriberId<'i>) -> Result<(), Error> {
        let index = self.subscriber_index(id)?;
        self.subscribers[index] = None;
        Ok(())
    }

    /// Lease the latest unseen or requested estimate for this subscriber only.
    /// Its writer retains the returned token through any partial writes.
    /// Later revisions wait until the same lease completes through [Self::notified].
    ///
    /// # Errors
    /// Refuses a retired or foreign subscriber and reports exhausted effect IDs.
    pub fn notification_for(
        &mut self,
        subscriber: SubscriberId<'i>,
        now: u64,
    ) -> Result<Option<Notification<'i>>, Error> {
        let index = self.subscriber_index(subscriber)?;
        self.lease_notification(index, now)
    }

    /// Fairly lease one immutable notification; later revisions coalesce behind an in-flight copy.
    pub fn next_notification(&mut self, now: u64) -> Result<Option<Notification<'i>>, Error> {
        self.live()?;
        if S == 0 {
            return Ok(None);
        }
        for offset in 0..S {
            let i = (self.subscriber_cursor + offset) % S;
            if let Some(value) = self.lease_notification(i, now)? {
                self.subscriber_cursor = (i + 1) % S;
                return Ok(Some(value));
            }
        }
        Ok(None)
    }

    fn lease_notification(
        &mut self,
        index: usize,
        now: u64,
    ) -> Result<Option<Notification<'i>>, Error> {
        let Some(subscriber) = self.subscribers[index] else {
            return Ok(None);
        };
        if subscriber.pending.is_some() || (!subscriber.refresh && subscriber.seen >= self.revision)
        {
            return Ok(None);
        }
        let estimate = self.summary()?.estimate(now);
        let value = Notification {
            id: self.fresh()?,
            subscriber: subscriber.id,
            revision: self.revision,
            estimate,
        };
        let slot = self.subscribers[index].as_mut().ok_or(Error::Stale)?;
        slot.refresh = false;
        slot.pending = Some(value);
        Ok(Some(value))
    }

    /// Actual full native completion returns only the original notification's capacity.
    pub fn notified(&mut self, value: &Notification<'i>) -> Result<(), Error> {
        let i = self.subscriber_index(value.subscriber)?;
        let sub = self.subscribers[i].as_mut().ok_or(Error::Stale)?;
        let original = sub
            .pending
            .filter(|p| p.id == value.id)
            .ok_or(Error::Stale)?;
        sub.seen = original.revision;
        sub.pending = None;
        Ok(())
    }
    fn delay(&self, peer: Peer<'i>, now: u64, random: &mut impl Random) -> Result<u64, Error> {
        if peer.previous {
            if !self.config.randomize_delays {
                return Ok(now);
            }
            let jitter = random.below(50)?;
            if jitter >= 50 {
                return Err(Error::Entropy);
            }
            return now.checked_add(u64::from(jitter)).ok_or(Error::Overflow);
        }
        let entry = self.history[self.index].ok_or(Error::NotReady)?;
        let mean = self.summary()?.mean;
        let distance =
            history::matching_delay(self.config.interval_micros, entry.frame.matching_bits, mean)?;
        let jitter = if self.config.randomize_delays {
            let max_hops = self
                .history
                .iter()
                .flatten()
                .map(|e| e.frame.hops)
                .max()
                .unwrap_or(0);
            let span = distance / (u64::from(max_hops) + 1) as f64;
            if span >= u32::MAX as f64 {
                return Err(Error::Overflow);
            }
            let bound = (span as u32).checked_add(1).ok_or(Error::Overflow)?;
            let jitter = random.below(bound)?;
            if jitter >= bound {
                return Err(Error::Entropy);
            }
            jitter
        } else {
            0
        };
        let delay = distance + f64::from(jitter);
        if delay >= u64::MAX as f64 {
            return Err(Error::Overflow);
        }
        self.current
            .checked_add(delay as u64)
            .ok_or(Error::Overflow)
    }
    /// Register/select the earliest owned absolute target. Entropy is sampled only for a newly
    /// scheduled peer; repeated polls retain each original target and token.
    pub fn next_alarm(
        &mut self,
        now: u64,
        random: &mut impl Random,
    ) -> Result<Option<Alarm<'i>>, Error> {
        self.live()?;
        if self.identity.is_none() {
            return Ok(None);
        }
        for i in 0..P {
            if let Some(peer) = self.peers[i]
                && peer.needs_schedule
            {
                let at = self.delay(peer, now, random)?;
                let id = self.fresh()?;
                if let Some(p) = &mut self.peers[i] {
                    p.alarm = Some(Alarm {
                        id,
                        kind: AlarmKind::Peer(p.id),
                        at,
                    });
                    p.needs_schedule = false;
                }
            }
        }
        let mut selected = self
            .round_alarm
            .into_iter()
            .chain(self.work_alarm)
            .min_by_key(|a| a.at);
        if P > 0 {
            for offset in 0..P {
                let i = (self.peer_cursor + offset) % P;
                if let Some(alarm) = self.peers[i].and_then(|p| p.alarm)
                    && selected.is_none_or(|s| alarm.at < s.at)
                {
                    selected = Some(alarm);
                }
            }
        }
        Ok(selected)
    }
    /// Apply exactly one original timer. Early completion keeps it pending, including after rollback.
    pub fn alarm_fired(&mut self, alarm: &Alarm<'i>, now: u64) -> Result<AlarmProgress, Error> {
        self.live()?;
        match alarm.kind {
            AlarmKind::Round => {
                if self.round_alarm != Some(*alarm) {
                    return Err(Error::Stale);
                }
                if now < alarm.at {
                    return Ok(AlarmProgress::Early);
                }
                let identity = self.identity.ok_or(Error::NotReady)?;
                let next = self
                    .next
                    .checked_add(self.config.interval_micros)
                    .ok_or(Error::Overflow)?;
                let id = self.fresh()?;
                self.current = self.next;
                self.next = next;
                self.index = (self.index + 1) % HISTORY_SIZE;
                self.count = (self.count + 1).min(HISTORY_SIZE);
                let local = self.local(self.current, identity);
                let entry = match self.carryover.take() {
                    Some(mut frame)
                        if frame.timestamp.as_micros() == self.current
                            && (!local.qualified(identity)
                                || frame.matching_bits > local.frame.matching_bits) =>
                    {
                        frame.hops = frame.hops.wrapping_add(1);
                        Entry {
                            frame,
                            local_unsigned: false,
                        }
                    }
                    _ => local,
                };
                self.history[self.index] = Some(entry);
                self.round_alarm = Some(Alarm {
                    id,
                    kind: AlarmKind::Round,
                    at: next,
                });
                for peer in self.peers.iter_mut().flatten() {
                    if peer.alarm.is_some() || peer.needs_schedule {
                        peer.previous = true;
                    }
                    peer.alarm = None;
                    peer.needs_schedule = true;
                }
                self.metrics.reset_diameter();
                self.refresh_metrics();
                Ok(AlarmProgress::Round)
            }
            AlarmKind::Work => {
                if self.work_alarm != Some(*alarm) {
                    return Err(Error::Stale);
                }
                if now < alarm.at {
                    return Ok(AlarmProgress::Early);
                }
                let identity = self.identity.as_mut().ok_or(Error::NotReady)?;
                let LocalProof::Searching(search) = &mut identity.proof else {
                    return Err(Error::Stale);
                };
                search.ready = true;
                self.work_alarm = None;
                Ok(AlarmProgress::Work)
            }
            AlarmKind::Peer(peer) => {
                let i = self.peer_index(peer)?;
                let p = self.peers[i].ok_or(Error::Stale)?;
                if p.alarm != Some(*alarm) {
                    return Err(Error::Stale);
                }
                if now < alarm.at {
                    return Ok(AlarmProgress::Early);
                }
                let identity = self.identity.ok_or(Error::NotReady)?;
                let index = if p.previous {
                    self.previous_index()
                } else {
                    self.index
                };
                let planned = if p.pending.is_none() {
                    match self.history[index] {
                        None => {
                            // As in the producer, an unfinished local proof
                            // precedes lack-of-history classification.
                            self.metrics
                                .increment(if identity.proof.confirmed().is_none() {
                                    1
                                } else {
                                    2
                                });
                            None
                        }
                        Some(entry)
                            if entry.local_unsigned
                                && (identity.proof.confirmed() != Some(entry.frame.proof)
                                    || entry.frame.origin != identity.key) =>
                        {
                            self.metrics.increment(1);
                            None
                        }
                        Some(entry) => Some(entry),
                    }
                } else {
                    None
                };
                let planned = match planned {
                    Some(entry) => Some((entry, self.fresh()?)),
                    None => None,
                };
                if let Some(p) = &mut self.peers[i] {
                    p.alarm = None;
                }
                if p.pending.is_some() {
                    if let Some(p) = &mut self.peers[i] {
                        p.deferred = true;
                    }
                    return Ok(AlarmProgress::Peer);
                }
                if p.previous
                    && let Some(p) = &mut self.peers[i]
                {
                    p.previous = false;
                    p.needs_schedule = true;
                }
                let Some((entry, id)) = planned else {
                    return Ok(AlarmProgress::Peer);
                };
                let pending = if entry.local_unsigned {
                    Pending::Sign {
                        request: SignRequest {
                            id,
                            peer,
                            epoch: identity.epoch,
                            frame: entry.frame,
                        },
                        issued: false,
                        cancelled: false,
                    }
                } else {
                    Pending::Send {
                        request: Transmission {
                            id,
                            peer,
                            epoch: identity.epoch,
                            frame: entry.frame,
                        },
                        issued: false,
                        admitted: false,
                    }
                };
                if let Some(p) = &mut self.peers[i] {
                    p.pending = Some(pending);
                }
                if P > 0 {
                    self.peer_cursor = (i + 1) % P;
                }
                Ok(AlarmProgress::Peer)
            }
        }
    }
    /// Fairly take an original local signing snapshot. No remote signature is replaced.
    pub fn next_sign(&mut self) -> Result<Option<SignRequest<'i>>, Error> {
        self.live()?;
        if P == 0 {
            return Ok(None);
        }
        for offset in 0..P {
            let i = (self.sign_cursor + offset) % P;
            if let Some(peer) = self.peers[i]
                && let Some(Pending::Sign {
                    request,
                    issued: false,
                    cancelled: false,
                }) = peer.pending
            {
                if let Some(p) = &mut self.peers[i] {
                    p.pending = Some(Pending::Sign {
                        request,
                        issued: true,
                        cancelled: false,
                    });
                }
                self.sign_cursor = (i + 1) % P;
                return Ok(Some(request));
            }
        }
        Ok(None)
    }
    /// Validate actual PILS signer, original epoch/payload and signature before making output ready.
    /// Authentication refusal preserves the request. Cancelled is a terminal completion
    /// of that original tombstone; it grants no output and cannot complete a newer operation.
    pub fn signed(
        &mut self,
        request: &SignRequest<'i>,
        signer: [u8; 32],
        signature: [u8; 64],
    ) -> Result<(), Error> {
        let i = self.peer_index(request.peer)?;
        let identity = self.identity.ok_or(Error::Stale)?;
        if identity.epoch != request.epoch {
            return Err(Error::Stale);
        }
        let peer = self.peers[i].ok_or(Error::Stale)?;
        let cancelled = match peer.pending {
            Some(Pending::Sign {
                request: original,
                issued: true,
                cancelled,
            }) if original.id == request.id => cancelled,
            _ => return Err(Error::Stale),
        };
        if cancelled || !self.current_or_previous(request.frame.timestamp.as_micros()) {
            if let Some(p) = &mut self.peers[i] {
                p.pending = None;
                if p.deferred {
                    p.needs_schedule = true;
                    p.deferred = false;
                }
            }
            return Err(Error::Cancelled);
        }
        if signer != identity.key || signer != request.frame.origin {
            return Err(Error::Authentication);
        }
        EddsaPublicKey::from_bytes(signer).verify(
            flood::SIGNATURE_PURPOSE,
            &request.payload()?,
            &EddsaSignature::from_bytes(signature),
        )?;
        let mut frame = request.frame;
        frame.signature = signature;
        if let Some(p) = &mut self.peers[i] {
            p.pending = Some(Pending::Send {
                request: Transmission {
                    id: request.id,
                    peer: request.peer,
                    epoch: request.epoch,
                    frame,
                },
                issued: false,
                admitted: false,
            });
        }
        Ok(())
    }
    /// Cancel exactly the original uncommitted local signature; late callbacks become stale.
    pub fn cancel_sign(&mut self, request: &SignRequest<'i>) -> Result<(), Error> {
        let i = self.peer_index(request.peer)?;
        let p = self.peers[i].as_mut().ok_or(Error::Stale)?;
        if !matches!(p.pending,Some(Pending::Sign {request:r,..})if r.id==request.id) {
            return Err(Error::Stale);
        }
        p.pending = None;
        if p.deferred {
            p.needs_schedule = true;
            p.deferred = false;
        }
        Ok(())
    }
    /// Fairly lease one original immutable CORE frame; never lease it to another native stream.
    pub fn next_transmission(&mut self) -> Result<Option<Transmission<'i>>, Error> {
        self.live()?;
        if P == 0 {
            return Ok(None);
        }
        for offset in 0..P {
            let i = (self.send_cursor + offset) % P;
            if let Some(peer) = self.peers[i]
                && let Some(Pending::Send {
                    request,
                    issued: false,
                    admitted,
                }) = peer.pending
            {
                if let Some(p) = &mut self.peers[i] {
                    p.pending = Some(Pending::Send {
                        request,
                        issued: true,
                        admitted,
                    });
                }
                self.send_cursor = (i + 1) % P;
                return Ok(Some(request));
            }
        }
        Ok(None)
    }
    /// Record one original flood actually admitted by the native CORE owner.
    /// The host calls this only after retaining the original CORE SendId/source.
    /// A duplicate, foreign, stale or unleased request grants no counter change.
    /// True means first local admission, never whole-write or remote delivery.
    pub fn transmission_admitted(&mut self, request: &Transmission<'i>) -> bool {
        let Ok(index) = self.peer_index(request.peer) else {
            return false;
        };
        if self
            .identity
            .is_none_or(|identity| identity.epoch != request.epoch)
        {
            return false;
        }
        let Some(peer) = self.peers[index].as_mut() else {
            return false;
        };
        let Some(Pending::Send {
            request: original,
            issued: true,
            admitted,
        }) = peer.pending.as_mut()
        else {
            return false;
        };
        if original.id != request.id || *admitted {
            return false;
        }
        *admitted = true;
        self.metrics.increment(4);
        if request.frame.hops == 0 {
            self.metrics.increment(3);
        }
        true
    }
    /// Report actual full original CORE submission; this is not remote delivery or processing.
    pub fn transmitted(&mut self, request: &Transmission<'i>) -> Result<(), Error> {
        self.finish_transmission(request)
    }
    /// Retire an original issued CORE frame once its native owner has refused
    /// or retired it. This releases the lease without claiming admission or
    /// a whole write. A later schedule uses the actual current history.
    pub fn transmission_abandoned(&mut self, request: &Transmission<'i>) -> Result<(), Error> {
        self.finish_transmission(request)
    }
    fn finish_transmission(&mut self, request: &Transmission<'i>) -> Result<(), Error> {
        let i = self.peer_index(request.peer)?;
        if self.identity.is_none_or(|id| id.epoch != request.epoch) {
            return Err(Error::Stale);
        }
        let p = self.peers[i].as_mut().ok_or(Error::Stale)?;
        if !matches!(p.pending,Some(Pending::Send {request:r,issued:true,..})if r.id==request.id) {
            return Err(Error::Stale);
        }
        p.pending = None;
        if p.deferred {
            p.deferred = false;
            p.needs_schedule = true;
        }
        Ok(())
    }
    fn cancel_unsubmitted(peer: &mut Peer<'i>) {
        match peer.pending {
            Some(Pending::Sign {
                request,
                issued: true,
                ..
            }) => {
                peer.pending = Some(Pending::Sign {
                    request,
                    issued: true,
                    cancelled: true,
                });
            }
            Some(Pending::Sign { issued: false, .. } | Pending::Send { issued: false, .. }) => {
                peer.pending = None
            }
            _ => {}
        }
    }
    /// Handle one actual CORE message. Equal/lower data affects scheduling but is never accepted
    /// as authenticated history. Better/current/previous/next replacement performs the real gate.
    pub fn receive(
        &mut self,
        peer: PeerId<'i>,
        bytes: &[u8],
        memory: &mut [pow::Block],
    ) -> Result<Received, Error> {
        let i = self.peer_index(peer)?;
        let Some(identity) = self.identity else {
            return Ok(Received::NoIdentity);
        };
        let message = Message::decode(bytes)?;
        let frame = message.fields()?;
        self.metrics.increment(5);
        let time = frame.timestamp.as_micros();
        if time == self.next {
            if self
                .carryover
                .is_some_and(|m| m.matching_bits >= frame.matching_bits)
            {
                return Ok(Received::NoImprovement);
            }
            self.carryover = Some(crypto::admit(bytes, self.config.work_bits, memory)?.fields());
            return Ok(Received::Carryover);
        }
        let current = time == self.current;
        let previous = self.current.checked_sub(self.config.interval_micros) == Some(time);
        if !current && !previous {
            self.metrics.increment(6);
            return Ok(Received::OutsideRounds);
        }
        if self.peers[i].is_some_and(|p| p.key == identity.key) {
            if frame.origin == identity.key {
                self.changed()?;
                return Ok(Received::SelfUpdate);
            }
            return Ok(Received::NoImprovement);
        }
        let slot = if current {
            self.index
        } else {
            self.previous_index()
        };
        let best = self.history[slot]
            .filter(|entry| entry.qualified(identity))
            .map(|entry| entry.frame.matching_bits);
        if best == Some(frame.matching_bits) {
            if let Some(p) = &mut self.peers[i] {
                p.previous = false;
                if current {
                    p.alarm = None;
                    p.needs_schedule = false;
                    Self::cancel_unsubmitted(p);
                }
            }
            return Ok(Received::Equal);
        }
        if best.is_some_and(|best| frame.matching_bits < best) {
            self.metrics.increment(7);
            let effect_id = self.fresh()?;
            if let Some(p) = &mut self.peers[i] {
                if previous {
                    p.previous = true;
                }
                p.alarm = None;
                p.needs_schedule = false;
            }
            let alarm = Alarm {
                id: effect_id,
                kind: AlarmKind::Peer(peer),
                at: 0,
            };
            if let Some(p) = &mut self.peers[i] {
                p.alarm = Some(alarm);
            }
            return Ok(Received::Pushback);
        }
        let _next_revision = self.revision.checked_add(1).ok_or(Error::Overflow)?;
        let mut accepted = crypto::admit(bytes, self.config.work_bits, memory)?.fields();
        accepted.hops = accepted.hops.wrapping_add(1);
        self.history[slot] = Some(Entry {
            frame: accepted,
            local_unsigned: false,
        });
        if identity.activation == Activation::Durable {
            self.count = self.count.max(if current { 1 } else { 2 });
        }
        if let Some(p) = &mut self.peers[i] {
            p.previous = false;
            if current {
                p.alarm = None;
                p.needs_schedule = false;
                Self::cancel_unsubmitted(p);
            }
        }
        self.changed()?;
        for (j, p) in self.peers.iter_mut().enumerate() {
            if j != i
                && let Some(p) = p
                && !p.previous
            {
                p.alarm = None;
                p.needs_schedule = true;
            }
        }
        Ok(Received::Better)
    }
    /// Original bounded work request. A durable host controls elapsed cadence;
    /// the raw-file profile waits for its actual logical work timer.
    #[must_use]
    pub fn work_request(&self) -> Option<WorkRequest<'i>> {
        let identity = self.identity?;
        if identity.activation == Activation::Durable
            && self
                .persist_pending
                .is_some_and(|persist| persist.uncertain)
        {
            return None;
        }
        let LocalProof::Searching(search) = identity.proof else {
            return None;
        };
        search.ready.then_some(WorkRequest {
            id: search.id,
            epoch: identity.epoch,
            counter: search.counter,
        })
    }

    /// Perform 1..1024 actual caller-budgeted candidates. Big-endian enumeration
    /// is an internal traversal; an accepted proof preserves its exact raw bytes.
    /// The raw-file profile uses `now` to schedule a new logical work timer.
    /// Durable hosts must pace each renewed request using their elapsed clock.
    pub fn work(
        &mut self,
        request: &WorkRequest<'i>,
        budget: u16,
        now: u64,
        memory: &mut [pow::Block],
    ) -> Result<WorkProgress, Error> {
        self.live()?;
        if budget == 0 || budget > 1024 {
            return Err(Error::InvalidInput);
        }
        if self.work_request().is_none_or(|owned| {
            owned.id != request.id
                || owned.epoch != request.epoch
                || owned.counter != request.counter
        }) {
            return Err(Error::Stale);
        }
        let mut identity = self.identity.ok_or(Error::Stale)?;
        let LocalProof::Searching(mut search) = identity.proof else {
            return Err(Error::Stale);
        };
        for _ in 0..budget {
            let proof = search.counter.to_be_bytes();
            if crypto::valid_proof(self.config.work_bits, &identity.key, &proof, memory)? {
                if identity.activation == Activation::Immediate {
                    let _revision = self.revision.checked_add(1).ok_or(Error::Overflow)?;
                }
                let revision = self.publish_proof_update(ProofUpdate::Candidate(proof))?;
                match identity.activation {
                    Activation::Immediate => self.activate_proof(identity, proof)?,
                    Activation::Durable => {
                        identity.proof = LocalProof::AwaitingCommit {
                            raw: proof,
                            revision,
                        };
                        self.identity = Some(identity);
                    }
                }
                return Ok(WorkProgress::Found(proof));
            }
            let Some(next) = search.counter.checked_add(1) else {
                if identity.activation == Activation::Durable {
                    let _revision = self.publish_proof_update(ProofUpdate::Exhausted)?;
                }
                identity.proof = LocalProof::Exhausted;
                self.identity = Some(identity);
                return Ok(WorkProgress::Exhausted);
            };
            search.counter = next;
        }
        let due = if identity.activation == Activation::Immediate {
            Some(
                now.checked_add(self.config.work_delay_micros)
                    .ok_or(Error::Overflow)?,
            )
        } else {
            None
        };
        let (next, alarm) = self.issue_search(search.counter, due)?;
        let _revision = self.publish_proof_update(ProofUpdate::Checkpoint(next.counter))?;
        identity.proof = LocalProof::Searching(next);
        self.identity = Some(identity);
        self.work_alarm = alarm;
        Ok(WorkProgress::More)
    }

    fn issue_search(
        &mut self,
        counter: u64,
        wall_deadline: Option<u64>,
    ) -> Result<(Search<'i>, Option<Alarm<'i>>), Error> {
        let search = Search {
            counter,
            id: self.fresh()?,
            ready: wall_deadline.is_none(),
        };
        let alarm = wall_deadline
            .map(|at| {
                self.fresh().map(|id| Alarm {
                    id,
                    kind: AlarmKind::Work,
                    at,
                })
            })
            .transpose()?;
        Ok((search, alarm))
    }

    fn activate_proof(&mut self, mut identity: Identity<'i>, proof: [u8; 8]) -> Result<(), Error> {
        let _revision = self.revision.checked_add(1).ok_or(Error::Overflow)?;
        identity.proof = LocalProof::Confirmed(proof);
        self.identity = Some(identity);
        // Rebind only original unsigned local history, keeping genuine remote
        // records and every already issued transmission intact.
        for entry in self.history.iter_mut().flatten() {
            if entry.local_unsigned && entry.frame.origin == identity.key {
                entry.frame.proof = proof;
                entry.frame.signature = [0; 64];
            }
        }
        let local = self.local(self.current, identity);
        self.prefer_current_local(local, identity);
        if self.count == 0 {
            self.count = 1;
        }
        for peer in self.peers.iter_mut().flatten() {
            if peer.alarm.is_none() {
                peer.previous = false;
                peer.needs_schedule = true;
            }
        }
        self.changed()
    }

    /// Observe the latest board update without leasing a physical write.
    /// New search checkpoints may coalesce while an older write is in flight.
    #[must_use]
    pub fn pending_proof_update(&self) -> Option<ProofUpdate> {
        if self
            .identity
            .is_some_and(|identity| identity.activation == Activation::Durable)
            && self.persisted_revision != self.persist_revision
        {
            self.persist_latest
        } else {
            None
        }
    }

    /// Lease the latest typed board state to the original durable writer.
    pub fn next_durable_persist(&mut self) -> Result<Option<DurablePersistRequest<'i>>, Error> {
        self.next_persistence(Activation::Durable)
    }

    /// Lease a desktop raw8 write. The raw-file profile keeps its original
    /// interpretation and never emits a typed exhaustion marker.
    pub fn next_persist(&mut self) -> Result<Option<PersistRequest<'i>>, Error> {
        let Some(ticket) = self.next_persistence(Activation::Immediate)? else {
            return Ok(None);
        };
        let bytes = match ticket.update {
            ProofUpdate::Checkpoint(counter) => counter.to_be_bytes(),
            ProofUpdate::Candidate(raw) => raw,
            ProofUpdate::Exhausted => return Err(Error::Conflict),
        };
        Ok(Some(PersistRequest { ticket, bytes }))
    }

    fn next_persistence(
        &mut self,
        activation: Activation,
    ) -> Result<Option<DurablePersistRequest<'i>>, Error> {
        self.live()?;
        let Some(identity) = self.identity else {
            return Ok(None);
        };
        if identity.activation != activation {
            return Err(Error::Unsupported);
        }
        if self.persist_pending.is_some() || self.persisted_revision == self.persist_revision {
            return Ok(None);
        }
        let update = self.persist_latest.ok_or(Error::Conflict)?;
        let request = DurablePersistRequest {
            id: self.fresh()?,
            epoch: identity.epoch,
            revision: self.persist_revision,
            update,
        };
        self.persist_pending = Some(Persistence {
            request,
            uncertain: false,
        });
        Ok(Some(request))
    }

    /// Confirm the exact typed board commit. A failed write retains its
    /// original token. OutcomeUnknown prevents cancellation until the medium
    /// is recovered and can confirm this same update.
    pub fn durable_persisted(
        &mut self,
        request: &DurablePersistRequest<'i>,
        outcome: Result<(), Error>,
    ) -> Result<(), Error> {
        self.finish_persistence(request, outcome, Activation::Durable)
    }

    /// Confirm actual durability only for the original desktop write.
    pub fn persisted(
        &mut self,
        request: &PersistRequest<'i>,
        outcome: Result<(), Error>,
    ) -> Result<(), Error> {
        self.finish_persistence(&request.ticket, outcome, Activation::Immediate)
    }

    /// Retire a typed write which is known to have committed nothing. The
    /// newest pending state may then receive a new original token.
    pub fn cancel_durable_persist(
        &mut self,
        request: &DurablePersistRequest<'i>,
    ) -> Result<(), Error> {
        let (_, current) = self.persist_original(request, Activation::Durable)?;
        if current.uncertain {
            return Err(Error::OutcomeUnknown);
        }
        self.persist_pending = None;
        Ok(())
    }

    fn persist_original(
        &self,
        request: &DurablePersistRequest<'i>,
        activation: Activation,
    ) -> Result<(Identity<'i>, Persistence<'i>), Error> {
        self.live()?;
        let identity = self
            .identity
            .filter(|identity| identity.epoch == request.epoch && identity.activation == activation)
            .ok_or(Error::Stale)?;
        let original = self
            .persist_pending
            .filter(|current| current.request.id == request.id)
            .ok_or(Error::Stale)?;
        Ok((identity, original))
    }

    fn finish_persistence(
        &mut self,
        request: &DurablePersistRequest<'i>,
        outcome: Result<(), Error>,
        activation: Activation,
    ) -> Result<(), Error> {
        let (identity, mut original) = self.persist_original(request, activation)?;
        if outcome == Err(Error::OutcomeUnknown) {
            original.uncertain = true;
            self.persist_pending = Some(original);
        }
        outcome?;
        if activation == Activation::Durable
            && let ProofUpdate::Candidate(proof) = original.request.update
        {
            if !matches!(identity.proof, LocalProof::AwaitingCommit { raw, revision }
                if raw == proof && revision == original.request.revision)
            {
                return Err(Error::Conflict);
            }
            self.activate_proof(identity, proof)?;
        }
        self.persisted_revision = original.request.revision;
        self.persist_pending = None;
        Ok(())
    }
    /// Permanently close logical authority. The native host retires physical ports first.
    pub fn close(&mut self) {
        self.identity = None;
        self.retirement = None;
        self.peers = [None; P];
        self.subscribers = [None; S];
        self.round_alarm = None;
        self.work_alarm = None;
        self.carryover = None;
        self.persist_pending = None;
        self.persist_latest = None;
        self.refresh_metrics();
        self.closed = true;
    }
}

#[cfg(test)]
mod resource_boundaries {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Terminal counters and original leases require explicit assertions."
    )]
    use super::*;
    struct NoRandom;
    impl Random for NoRandom {
        fn below(&mut self, _: u32) -> Result<u32, Error> {
            Err(Error::Entropy)
        }
    }
    fn zero() -> Result<Config, Error> {
        Ok(Config {
            work_bits: WorkBits::new(0)?,
            interval_micros: 1000,
            ..Config::default()
        })
    }
    #[test]
    fn absent_proof_starts_at_zero_without_work_scratch() -> Result<(), Error> {
        let mut instance = Instance::new();
        let mut service = Service::<0, 0>::new(&mut instance, Config::default())?;
        let original = service.begin_identity_change()?;
        assert_eq!(
            service.finish_identity_change_from_saved(&original, [1; 32], Some([0; 8]), 1, &mut []),
            Err(Error::Capacity)
        );
        service.finish_identity_change_from_saved(&original, [1; 32], None, 1, &mut [])?;
        assert!(service.work_request().is_none());
        assert_eq!(service.count, 0);
        let alarm = service
            .next_alarm(1, &mut NoRandom)?
            .ok_or(Error::NotReady)?;
        assert_eq!(alarm.deadline(), 1);
        assert_eq!(service.alarm_fired(&alarm, 1)?, AlarmProgress::Work);
        assert_eq!(service.work_request().ok_or(Error::NotReady)?.counter, 0);
        assert!(service.next_persist()?.is_none());
        Ok(())
    }
    #[test]
    fn durable_candidate_only_qualifies_after_exact_confirmed_write() -> Result<(), Error> {
        let mut instance = Instance::new();
        let mut service = Service::<0, 0>::new(&mut instance, zero()?)?;
        let barrier = service.begin_identity_change()?;
        service.finish_identity_change_durable(
            &barrier,
            [1; 32],
            ProofRecovery::Checkpoint(0),
            1,
            &mut [],
        )?;
        assert_eq!(service.local_proof(), None);
        let alarm = service
            .next_alarm(1, &mut NoRandom)?
            .ok_or(Error::NotReady)?;
        assert_eq!(alarm.deadline(), 1000);
        let search = service.work_request().ok_or(Error::NotReady)?;
        assert_eq!(search.counter, 0);
        assert_eq!(
            service.work(&search, 1, 1, &mut [])?,
            WorkProgress::Found([0; 8])
        );
        assert!(service.work_request().is_none());
        let identity = service.identity.ok_or(Error::NotReady)?;
        assert!(
            !service.history[service.index]
                .ok_or(Error::NotReady)?
                .qualified(identity)
        );
        assert_eq!(
            service.pending_proof_update(),
            Some(ProofUpdate::Candidate([0; 8]))
        );
        let first = service.next_durable_persist()?.ok_or(Error::NotReady)?;
        assert_eq!(
            service.durable_persisted(&first, Err(Error::Io)),
            Err(Error::Io)
        );
        assert!(service.next_durable_persist()?.is_none());
        assert_eq!(service.local_proof(), None);
        service.cancel_durable_persist(&first)?;
        let second = service.next_durable_persist()?.ok_or(Error::NotReady)?;
        assert_eq!(second.update(), ProofUpdate::Candidate([0; 8]));
        assert_eq!(service.durable_persisted(&first, Ok(())), Err(Error::Stale));
        assert_eq!(
            service.durable_persisted(&second, Err(Error::OutcomeUnknown)),
            Err(Error::OutcomeUnknown)
        );
        assert_eq!(
            service.cancel_durable_persist(&second),
            Err(Error::OutcomeUnknown)
        );
        assert_eq!(service.local_proof(), None);
        service.durable_persisted(&second, Ok(()))?;
        assert_eq!(service.local_proof(), Some([0; 8]));
        assert!(
            service.history[service.index]
                .ok_or(Error::NotReady)?
                .qualified(service.identity.ok_or(Error::NotReady)?)
        );
        assert_eq!(service.pending_proof_update(), None);
        assert_eq!(
            service.durable_persisted(&second, Ok(())),
            Err(Error::Stale)
        );
        Ok(())
    }
    #[test]
    fn id_exhaustion_keeps_original_completions_and_does_not_reuse_slot() -> Result<(), Error> {
        let mut instance = Instance::new();
        let mut service = Service::<0, 2>::new(&mut instance, zero()?)?;
        let id = service.subscribe(&[0, 4, 1, 65])?;
        let notification = service.next_notification(1)?.ok_or(Error::NotReady)?;
        service.sequence = u64::MAX;
        assert_eq!(service.subscribe(&[0, 4, 1, 65]), Err(Error::Overflow));
        assert_eq!(service.sequence, u64::MAX);
        service.notified(&notification)?;
        service.unsubscribe(id)?;
        assert_eq!(service.subscribe(&[0, 4, 1, 65]), Err(Error::Overflow));
        Ok(())
    }
    #[test]
    fn targeted_notifications_coalesce_independently_and_retire_with_their_client()
    -> Result<(), Error> {
        let mut instance = Instance::new();
        let mut service = Service::<0, 2>::new(&mut instance, zero()?)?;
        let start = [0, 4, 1, 65];
        let first = service.subscribe(&start)?;
        let second = service.subscribe(&start)?;

        let targeted = service
            .notification_for(second, 10)?
            .ok_or(Error::NotReady)?;
        let global = service.next_notification(11)?.ok_or(Error::NotReady)?;
        assert_eq!(targeted.subscriber(), second);
        assert_eq!(global.subscriber(), first);
        service.changed()?;
        assert!(service.notification_for(first, 12)?.is_none());
        assert!(service.notification_for(second, 12)?.is_none());
        assert!(service.next_notification(12)?.is_none());
        service.notified(&targeted)?;
        let updated = service
            .notification_for(second, 13)?
            .ok_or(Error::NotReady)?;
        assert_eq!(updated.estimate().timestamp.as_micros(), 13);
        assert!(updated.revision > targeted.revision);
        assert_eq!(global.estimate().timestamp.as_micros(), 11);

        service.unsubscribe(first)?;
        assert!(matches!(
            service.notification_for(first, 14),
            Err(Error::Stale)
        ));
        assert_eq!(service.notified(&global), Err(Error::Stale));
        let replacement = service.subscribe(&start)?;
        assert_ne!(replacement, first);
        let new = service
            .notification_for(replacement, 15)?
            .ok_or(Error::NotReady)?;
        service.notified(&updated)?;
        assert!(service.notification_for(second, 16)?.is_none());
        assert!(service.notification_for(replacement, 16)?.is_none());
        service.notified(&new)?;
        Ok(())
    }

    #[test]
    fn repeated_start_keeps_subscriber_and_demands_a_fresh_snapshot() -> Result<(), Error> {
        let mut instance = Instance::new();
        let mut service = Service::<0, 1>::new(&mut instance, zero()?)?;
        let start = [0, 4, 1, 65];
        let subscriber = service.subscribe(&start)?;
        assert_eq!(
            service.refresh_subscription(subscriber, &start),
            Err(Error::WouldBlock)
        );
        let first = service
            .notification_for(subscriber, 20)?
            .ok_or(Error::NotReady)?;
        assert_eq!(
            service.refresh_subscription(subscriber, &start),
            Err(Error::WouldBlock)
        );
        service.notified(&first)?;
        assert!(service.notification_for(subscriber, 21)?.is_none());

        assert!(
            service
                .refresh_subscription(subscriber, &[0, 4, 1, 66])
                .is_err()
        );
        assert!(service.notification_for(subscriber, 21)?.is_none());
        service.refresh_subscription(subscriber, &start)?;
        assert_eq!(
            service.refresh_subscription(subscriber, &start),
            Err(Error::WouldBlock)
        );
        let repeated = service
            .notification_for(subscriber, 22)?
            .ok_or(Error::NotReady)?;
        assert_eq!(repeated.subscriber(), subscriber);
        assert_eq!(repeated.revision, first.revision);
        assert_ne!(repeated.id, first.id);
        assert_eq!(repeated.estimate().timestamp.as_micros(), 22);
        assert_eq!(service.notified(&first), Err(Error::Stale));
        assert_eq!(service.subscribe(&start), Err(Error::Capacity));
        service.notified(&repeated)?;
        assert!(service.notification_for(subscriber, 23)?.is_none());
        Ok(())
    }

    #[test]
    fn effect_exhaustion_does_not_consume_an_original_timer() -> Result<(), Error> {
        let mut instance = Instance::new();
        let mut service = Service::<1, 0>::new(&mut instance, zero()?)?;
        let barrier = service.begin_identity_change()?;
        service.finish_identity_change(&barrier, [1; 32], [0; 8], 2000, &mut [])?;
        let peer = service.connect_peer([2; 32])?;
        let alarm = service
            .next_alarm(2000, &mut NoRandom)?
            .ok_or(Error::NotReady)?;
        service.sequence = u64::MAX;
        assert_eq!(service.alarm_fired(&alarm, 2000), Err(Error::Overflow));
        assert_eq!(service.next_alarm(2000, &mut NoRandom)?, Some(alarm));
        service.disconnect_peer(peer)?;
        Ok(())
    }
    #[test]
    fn proof_search_tail_exhaustion_is_explicit_without_wrapping() -> Result<(), Error> {
        let mut instance = Instance::new();
        let mut service = Service::<0, 0>::new(
            &mut instance,
            Config {
                work_bits: WorkBits::new(511)?,
                interval_micros: 1000,
                ..Config::default()
            },
        )?;
        let mut memory = std::vec![pow::Block::new();pow::MEMORY_BLOCKS];
        let barrier = service.begin_identity_change()?;
        service.finish_identity_change(
            &barrier,
            [3; 32],
            u64::MAX.to_be_bytes(),
            2000,
            &mut memory,
        )?;
        let alarm = service
            .next_alarm(2000, &mut NoRandom)?
            .ok_or(Error::NotReady)?;
        service.alarm_fired(&alarm, 2000)?;
        let request = service.work_request().ok_or(Error::NotReady)?;
        assert_eq!(
            service.work(&request, 1, 2000, &mut memory)?,
            WorkProgress::Exhausted
        );
        assert!(service.work_request().is_none());
        assert_eq!(
            service.work(&request, 1, 2000, &mut memory),
            Err(Error::Stale)
        );
        assert!(service.next_persist()?.is_none());

        let barrier = service.begin_identity_change()?;
        service.finish_identity_change_durable(
            &barrier,
            [3; 32],
            ProofRecovery::Checkpoint(u64::MAX - 1),
            2001,
            &mut [],
        )?;
        let alarm = service
            .next_alarm(2001, &mut NoRandom)?
            .ok_or(Error::NotReady)?;
        assert_eq!(alarm.deadline(), 3000);
        let original = service.work_request().ok_or(Error::NotReady)?;
        assert_eq!(original.counter, u64::MAX - 1);
        assert_eq!(
            service.work(&original, 1, 2001, &mut memory)?,
            WorkProgress::More
        );
        assert_eq!(
            service.pending_proof_update(),
            Some(ProofUpdate::Checkpoint(u64::MAX))
        );
        assert_eq!(
            service.work(&original, 1, 2000, &mut memory),
            Err(Error::Stale)
        );
        let request = service.work_request().ok_or(Error::NotReady)?;
        assert_eq!(request.counter, u64::MAX);
        let checkpoint = service.next_durable_persist()?.ok_or(Error::NotReady)?;
        assert_eq!(
            service.durable_persisted(&checkpoint, Err(Error::OutcomeUnknown)),
            Err(Error::OutcomeUnknown)
        );
        assert!(service.work_request().is_none());
        assert_eq!(
            service.work(&request, 1, 2000, &mut memory),
            Err(Error::Stale)
        );
        service.durable_persisted(&checkpoint, Ok(()))?;
        assert_eq!(
            service.work(&request, 1, 2000, &mut memory)?,
            WorkProgress::Exhausted
        );
        assert!(service.work_request().is_none());
        let saved = service.next_durable_persist()?.ok_or(Error::NotReady)?;
        assert_eq!(saved.update(), ProofUpdate::Exhausted);
        service.durable_persisted(&saved, Ok(()))?;
        let barrier = service.begin_identity_change()?;
        service.finish_identity_change_durable(
            &barrier,
            [3; 32],
            ProofRecovery::Exhausted,
            2000,
            &mut [],
        )?;
        assert_eq!(
            service
                .next_alarm(2000, &mut NoRandom)?
                .ok_or(Error::NotReady)?
                .deadline(),
            3000
        );
        assert!(service.work_request().is_none());
        assert!(service.next_durable_persist()?.is_none());
        Ok(())
    }
}

#[cfg(test)]
mod candidate_tests;
