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
    /// Logical delay between bounded proof-search calls, normally5000 microseconds.
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
    /// Valid raw proof found for this exact identity/work requirement.
    Found([u8; 8]),
    /// Bounded work exhausted; a new owned delay is pending.
    More,
    /// Remaining counter range exhausted; no wrap or implicit retry of earlier values occurs.
    Exhausted,
}
/// Original proof-file write request. Emission is not durability.
#[derive(Clone, Copy, Debug)]
pub struct PersistRequest<'i> {
    id: EffectId<'i>,
    epoch: EffectId<'i>,
    revision: u64,
    proof: [u8; 8],
}
impl PersistRequest<'_> {
    /// Exact raw8 file bytes, without a private wrapper or endian conversion.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; 8] {
        &self.proof
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
    /// One bounded work request is now eligible.
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
            || (self.frame.origin == identity.key && identity.proof == Some(self.frame.proof))
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
    pending: Option<Notification<'i>>,
}
#[derive(Clone, Copy)]
struct Identity<'i> {
    key: [u8; 32],
    epoch: EffectId<'i>,
    proof: Option<[u8; 8]>,
    counter: u64,
    work_id: EffectId<'i>,
    work_ready: bool,
    exhausted: bool,
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
    persist_pending: Option<PersistRequest<'i>>,
    persist_latest: Option<[u8; 8]>,
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
                proof: identity.proof.unwrap_or([0; 8]),
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
    fn notify_proof(&mut self, proof: [u8; 8]) -> Result<(), Error> {
        self.persist_revision = self
            .persist_revision
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        self.persist_latest = Some(proof);
        Ok(())
    }
    /// Original active identity epoch; no private key is held by this service.
    #[must_use]
    pub fn identity(&self) -> Option<[u8; 32]> {
        self.identity.map(|i| i.key)
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
        for (i, value) in values[..self.count].iter_mut().enumerate() {
            *value = self.history[(self.index + HISTORY_SIZE - i) % HISTORY_SIZE]
                .map_or(0, |e| e.frame.matching_bits);
        }
        history::summarize(&values[..self.count], self.peer_count())
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
        self.live()?;
        if self.retirement != Some(barrier.id) {
            return Err(Error::Stale);
        }
        let _next_revision = self.revision.checked_add(1).ok_or(Error::Overflow)?;
        let current = (now / self.config.interval_micros) * self.config.interval_micros;
        let next = current
            .checked_add(self.config.interval_micros)
            .ok_or(Error::Overflow)?;
        let proof =
            crypto::valid_proof(self.config.work_bits, &key, &saved, memory)?.then_some(saved);
        let epoch = self.fresh()?;
        let work_id = self.fresh()?;
        let round_id = self.fresh()?;
        let work_alarm = if proof.is_none() {
            Some(Alarm {
                id: self.fresh()?,
                kind: AlarmKind::Work,
                at: now,
            })
        } else {
            None
        };
        let identity = Identity {
            key,
            epoch,
            proof,
            counter: u64::from_be_bytes(saved),
            work_id,
            work_ready: false,
            exhausted: false,
        };
        self.current = current;
        self.next = next;
        self.index = HISTORY_SIZE - 1;
        self.count = usize::from(proof.is_some());
        self.identity = Some(identity);
        self.retirement = None;
        self.history[self.index] = Some(self.local(current, identity));
        if proof.is_some()
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
            pending: None,
        });
        Ok(id)
    }
    /// Retire the original subscriber connection, without acknowledging any other stream.
    pub fn unsubscribe(&mut self, id: SubscriberId<'i>) -> Result<(), Error> {
        let index = self.subscriber_index(id)?;
        self.subscribers[index] = None;
        Ok(())
    }
    /// Fairly lease one immutable notification; later revisions coalesce behind an in-flight copy.
    pub fn next_notification(&mut self, now: u64) -> Result<Option<Notification<'i>>, Error> {
        self.live()?;
        if S == 0 {
            return Ok(None);
        }
        for offset in 0..S {
            let i = (self.subscriber_cursor + offset) % S;
            if let Some(sub) = self.subscribers[i]
                && sub.pending.is_none()
                && sub.seen < self.revision
            {
                let summary = self.summary()?;
                let value = Notification {
                    id: self.fresh()?,
                    subscriber: sub.id,
                    revision: self.revision,
                    estimate: summary.estimate(now),
                };
                if let Some(s) = &mut self.subscribers[i] {
                    s.pending = Some(value);
                }
                self.subscriber_cursor = (i + 1) % S;
                return Ok(Some(value));
            }
        }
        Ok(None)
    }
    /// Actual full native completion returns only the original notification's capacity.
    pub fn notified(&mut self, value: &Notification<'i>) -> Result<(), Error> {
        let i = self.subscriber_index(value.subscriber)?;
        let sub = self.subscribers[i].as_mut().ok_or(Error::Stale)?;
        if sub.pending.is_none_or(|p| p.id != value.id) {
            return Err(Error::Stale);
        }
        sub.seen = value.revision;
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
                self.work_alarm = None;
                let identity = self.identity.as_mut().ok_or(Error::NotReady)?;
                identity.work_ready = true;
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
                                .increment(if identity.proof.is_none() { 1 } else { 2 });
                            None
                        }
                        Some(entry)
                            if entry.local_unsigned
                                && (identity.proof != Some(entry.frame.proof)
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
    /// Original bounded work request, available only after its actual logical timer.
    #[must_use]
    pub fn work_request(&self) -> Option<WorkRequest<'i>> {
        self.identity
            .filter(|i| i.proof.is_none() && i.work_ready && !i.exhausted)
            .map(|i| WorkRequest {
                id: i.work_id,
                epoch: i.epoch,
                counter: i.counter,
            })
    }
    /// Perform1..1024 actual caller-budgeted candidates; no hidden unbounded search or large buffer.
    /// Big-endian enumeration is an internal solution traversal; the emitted proof stays raw8.
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
        let mut identity = self.identity.ok_or(Error::Stale)?;
        if self.work_request().is_none_or(|r| {
            r.id != request.id || r.epoch != request.epoch || r.counter != request.counter
        }) {
            return Err(Error::Stale);
        }
        for _ in 0..budget {
            let proof = identity.counter.to_be_bytes();
            if crypto::valid_proof(self.config.work_bits, &identity.key, &proof, memory)? {
                let _next_persist = self
                    .persist_revision
                    .checked_add(1)
                    .ok_or(Error::Overflow)?;
                let _next_revision = self.revision.checked_add(1).ok_or(Error::Overflow)?;
                identity.proof = Some(proof);
                identity.work_ready = false;
                self.identity = Some(identity);
                // Proof authorizes this identity across rounds. Rebind every unsigned
                // local history entry, never a verified remote signature or a leased frame.
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
                self.notify_proof(proof)?;
                for p in self.peers.iter_mut().flatten() {
                    if p.alarm.is_none() {
                        p.previous = false;
                        p.needs_schedule = true;
                    }
                }
                self.changed()?;
                return Ok(WorkProgress::Found(proof));
            }
            match identity.counter.checked_add(1) {
                Some(next) => identity.counter = next,
                None => {
                    identity.exhausted = true;
                    identity.work_ready = false;
                    self.identity = Some(identity);
                    return Ok(WorkProgress::Exhausted);
                }
            }
        }
        let at = now
            .checked_add(self.config.work_delay_micros)
            .ok_or(Error::Overflow)?;
        let id = self.fresh()?;
        identity.work_ready = false;
        identity.work_id = self.fresh()?;
        self.notify_proof(identity.counter.to_be_bytes())?;
        self.identity = Some(identity);
        self.work_alarm = Some(Alarm {
            id,
            kind: AlarmKind::Work,
            at,
        });
        Ok(WorkProgress::More)
    }
    /// Lease latest raw proof/progress for a native durable writer. An in-flight earlier write is
    /// retained while new progress coalesces; no database or filesystem lock is implied.
    pub fn next_persist(&mut self) -> Result<Option<PersistRequest<'i>>, Error> {
        self.live()?;
        if self.persist_pending.is_some() || self.persisted_revision == self.persist_revision {
            return Ok(None);
        }
        let identity = self.identity.ok_or(Error::NotReady)?;
        let proof = self.persist_latest.ok_or(Error::NotReady)?;
        let value = PersistRequest {
            id: self.fresh()?,
            epoch: identity.epoch,
            revision: self.persist_revision,
            proof,
        };
        self.persist_pending = Some(value);
        Ok(Some(value))
    }
    /// Confirm actual durability only for the original write. Unknown outcomes stay explicit errors;
    /// the host must settle its backend before retrying or creating another writer.
    pub fn persisted(
        &mut self,
        request: &PersistRequest<'i>,
        outcome: Result<(), Error>,
    ) -> Result<(), Error> {
        self.live()?;
        if self.identity.is_none_or(|i| i.epoch != request.epoch)
            || self.persist_pending.is_none_or(|p| p.id != request.id)
        {
            return Err(Error::Stale);
        }
        outcome?;
        self.persisted_revision = request.revision;
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
        Ok(())
    }
}

#[cfg(test)]
mod candidate_tests;
