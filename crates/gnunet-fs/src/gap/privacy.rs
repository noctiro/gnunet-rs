//! Actual local FS cover-budget and randomized-release ownership.
//!
//! Only exact completed relayed CORE application writes earn equivalent credits.
//! Permissions are local admission evidence, never peer processing, end-to-end
//! statistical anonymity, generated dummy traffic or an extra wire field.
use super::{Entropy, Neighbor, Path, Route, SendKind, SendRetired, Transmit};
use core::{cell::Cell, fmt, ptr};
use gnunet_types::Error;
use gnunet_wire::official::{MessageType, fs::BlockType, message_type as mt};

/// Active C cover accounting interval, five seconds in the original clock.
pub const AGE_US: u64 = 5_000_000;
/// Actual default C DELAY bound: uniform0..1000 multiplied by milliseconds.
pub const DEFAULT_DELAY_MS: u32 = 1000;
/// Explicit conservative local cover period, matching twice the mean of the
/// active C default uniform0..1000 millisecond delay distribution.
pub const DEFAULT_COVER_WINDOW_US: u64 = 1_000_000;
/// One stable external local permission domain, without a global identifier.
#[derive(Default)]
pub struct Instance {
    next: Cell<u64>,
    active: Cell<u64>,
    epoch: Cell<u64>,
    now: Cell<Option<u64>>,
}
impl Instance {
    /// Empty caller-owned permission identity and checked serial source.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next: Cell::new(0),
            active: Cell::new(0),
            epoch: Cell::new(0),
            now: Cell::new(None),
        }
    }
}
/// Publicly equivalent original application shape, excluding local ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Class {
    message_type: MessageType,
    block_type: BlockType,
    bytes: u16,
}
impl Class {
    pub(super) fn new(
        message_type: MessageType,
        block_type: BlockType,
        bytes: usize,
    ) -> Result<Self, Error> {
        if !matches!(message_type, mt::FS_GET | mt::FS_PUT) {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            message_type,
            block_type,
            bytes: u16::try_from(bytes).map_err(|_| Error::TooLarge)?,
        })
    }
    /// Actual official137 or138 registry value.
    #[must_use]
    pub const fn message_type(self) -> u16 {
        self.message_type.value()
    }
    /// Actual request or result type, including ANY only for a GET.
    #[must_use]
    pub const fn block_type(self) -> BlockType {
        self.block_type
    }
    /// Exact complete application message bytes; source capacity is separate.
    #[must_use]
    pub const fn bytes(self) -> usize {
        self.bytes as usize
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Key<'id> {
    Query {
        route: Route<'id>,
        neighbor: Neighbor<'id>,
    },
    Reply {
        route: Route<'id>,
        path: Path<'id>,
        result: u64,
        neighbor: Neighbor<'id>,
    },
}
/// Immutable original policy facts minted by the GAP route/result owner.
/// Callers cannot label a self-originated message as relayed cover.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Requirement<'id> {
    key: Key<'id>,
    class: Class,
    level: Option<u32>,
    relay: bool,
    known: bool,
    delayed: bool,
}
impl<'id> Requirement<'id> {
    pub(super) fn query(
        route: Route<'id>,
        neighbor: Neighbor<'id>,
        class: Class,
        level: u32,
        relay: bool,
    ) -> Self {
        Self {
            key: Key::Query { route, neighbor },
            class,
            level: Some(level),
            relay,
            known: true,
            delayed: true,
        }
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Original route/path/result, source policy and exact egress class are independent immutable facts"
    )]
    pub(super) fn reply(
        route: Route<'id>,
        path: Path<'id>,
        result: u64,
        neighbor: Neighbor<'id>,
        class: Class,
        level: Option<u32>,
        relay: bool,
        known: bool,
        delayed: bool,
    ) -> Self {
        Self {
            key: Key::Reply {
                route,
                path,
                result,
                neighbor,
            },
            class,
            level,
            relay,
            known,
            delayed,
        }
    }
    /// Original actual egress neighbor allocation, never raw-peer rebinding.
    #[must_use]
    pub const fn neighbor(self) -> Neighbor<'id> {
        match self.key {
            Key::Query { neighbor, .. } | Key::Reply { neighbor, .. } => neighbor,
        }
    }
    /// Original logical request allocation.
    #[must_use]
    pub const fn route(self) -> Route<'id> {
        match self.key {
            Key::Query { route, .. } | Key::Reply { route, .. } => route,
        }
    }
    /// Original reverse-path allocation, when this is a content reply.
    #[must_use]
    pub const fn path(self) -> Option<Path<'id>> {
        match self.key {
            Key::Query { .. } => None,
            Key::Reply { path, .. } => Some(path),
        }
    }
    /// Exact observed public application shape.
    #[must_use]
    pub const fn class(self) -> Class {
        self.class
    }
    /// Original requested/locally stored numeric level; peer unknown is separate.
    #[must_use]
    pub const fn level(self) -> Option<u32> {
        self.level
    }
    /// Real equivalent writes required in this local accounting policy.
    #[must_use]
    pub const fn needed(self) -> u32 {
        match self.level {
            Some(level) => level.saturating_sub(1),
            None => 0,
        }
    }
    /// Whether actual source policy was supplied. A peer source may explicitly
    /// have unknown anonymity (level None); omitted source policy is different.
    #[must_use]
    pub const fn source_policy_supplied(self) -> bool {
        self.known
    }
    /// Whether successful handoff may earn genuinely relayed cover.
    #[must_use]
    pub const fn relayed(self) -> bool {
        self.relay
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CreditKey<'id> {
    neighbor: Neighbor<'id>,
    class: Class,
}
impl<'id> From<Requirement<'id>> for CreditKey<'id> {
    fn from(r: Requirement<'id>) -> Self {
        Self {
            neighbor: r.neighbor(),
            class: r.class,
        }
    }
}
#[derive(Clone, Copy)]
struct Credit<'id> {
    key: CreditKey<'id>,
    count: u32,
    expires_at: u64,
}
/// One explicit fixed budget row, independent of original native packet buffers.
#[derive(Clone, Copy, Default)]
pub struct CreditSlot<'id> {
    record: Option<Credit<'id>>,
}
impl CreditSlot<'_> {
    /// Empty original-epoch/class accounting storage.
    #[must_use]
    pub const fn new() -> Self {
        Self { record: None }
    }
}
#[derive(Clone, Copy)]
struct Intent<'id> {
    requirement: Requirement<'id>,
    ready_at: u64,
}
/// One explicit bounded randomized-release intent. It owns no native operation.
#[derive(Clone, Copy, Default)]
pub struct IntentSlot<'id> {
    record: Option<Intent<'id>>,
}
impl IntentSlot<'_> {
    /// Empty policy intent storage; no IO or permission is admitted.
    #[must_use]
    pub const fn new() -> Self {
        Self { record: None }
    }
}
/// Explicit release policy. Numeric cover levels have no artificial maximum.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Official fs DELAY selection, applied symmetrically to anonymous GAP flow.
    pub randomized_delays: bool,
    /// Uniform delay in whole milliseconds0..=bound, using caller CSPRNG.
    pub maximum_delay_ms: u32,
    /// Exact local cover period. A class batch expires at its first completed
    /// write plus this interval; later traffic/refunds cannot extend it. When
    /// randomized release is enabled this cannot exceed twice its mean delay.
    pub cover_window_us: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            randomized_delays: false,
            maximum_delay_ms: DEFAULT_DELAY_MS,
            cover_window_us: DEFAULT_COVER_WINDOW_US,
        }
    }
}
/// Why an original candidate currently has no admission permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitReason {
    /// It lacks actual equivalent relayed complete-write credits.
    Cover,
    /// Its original randomized release target has not elapsed.
    Delay,
    /// Eligible fixed intent rows are owned by other candidates; one row is
    /// reserved for genuine relay progress and cannot be taken by own traffic.
    Capacity,
    /// The one original native permission still owns its eventual retirement.
    OriginalSend,
    /// Actual source anonymity/provenance has not been supplied.
    SourcePolicy,
}
/// One actual bounded policy observation, not a wire failure or negative result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Wait<'id> {
    /// Original exact application/destination/query authority.
    pub requirement: Requirement<'id>,
    /// Actual admission restriction.
    pub reason: WaitReason,
    /// Currently usable equivalent credits for this original destination/class.
    pub available: u32,
    /// Real required credits, preserving the original numeric level.
    pub needed: u32,
    /// Original absolute source-clock release target, if already drawn.
    pub ready_at: Option<u64>,
}
/// Local public accounting observations. Counts never imply peer processing.
#[derive(Clone, Copy, Debug, Default)]
pub struct Report<'id> {
    /// Full actual routed query application writes observed.
    pub relayed_queries_written: u64,
    /// Full actual routed content application writes observed.
    pub relayed_contents_written: u64,
    /// Full actual non-cover-eligible application writes observed.
    pub other_written: u64,
    /// Actual first local exposure of non-cover-eligible applications.
    pub other_exposed: u64,
    /// Actual equivalent credits irrevocably spent by exposed operations.
    pub spent: u64,
    /// Unexposed reservations returned after the same actual aging.
    pub refunded: u64,
    /// Credits removed by aging, generation loss, shutdown or time uncertainty.
    pub discarded: u64,
    /// Actual complete writes not recorded because fixed budget rows are full.
    pub unrecorded_capacity: u64,
    /// Actual complete writes beyond the bounded u32 counter, conservatively lost.
    pub unrecorded_overflow: u64,
    /// Full local writes not credited because their original completion was
    /// uncertain, target retired, or the owner was stopping.
    pub uncredited_complete: u64,
    /// Number of admission checks that waited, not a count of unique queries.
    pub waited: u64,
    /// Actual distinct randomized targets drawn for admitted intent rows.
    pub delays_drawn: u64,
    /// Actual source-clock backward observations that invalidate old evidence.
    pub time_epochs: u64,
    /// Latest original wait; callers can inspect all retained intent rows too.
    pub last_wait: Option<Wait<'id>>,
}
/// Opaque local permission tied to one immutable original route/result/egress.
/// It borrows stable external identity only, never the movable Policy owner.
#[derive(Clone, Copy)]
pub struct Permit<'id> {
    owner: &'id Instance,
    serial: u64,
    epoch: u64,
    expires_at: Option<u64>,
    requirement: Requirement<'id>,
}
impl<'id> Permit<'id> {
    /// Whether this exact permission still authorizes new pure preparation.
    /// Original IO retirement remains possible after this becomes false.
    #[must_use]
    pub fn is_live(self) -> bool {
        self.owner.active.get() == self.serial && self.cover_current()
    }
    /// Whether its original cover-evidence time epoch is still current. This
    /// alone does not authorize new admission or settle an original operation.
    #[must_use]
    pub fn time_epoch_current(self) -> bool {
        self.owner.epoch.get() == self.epoch
    }
    /// Whether the original cover evidence remains within its source-clock
    /// epoch and exact period. The native owner retires unexposed/partial work
    /// at this boundary before driving additional original payload IO.
    #[must_use]
    pub fn cover_current(self) -> bool {
        self.time_epoch_current()
            && self
                .expires_at
                .is_none_or(|end| self.owner.now.get().is_some_and(|now| now < end))
    }
    /// Original immutable admission facts.
    #[must_use]
    pub const fn requirement(self) -> Requirement<'id> {
        self.requirement
    }
    pub(super) fn authorizes(self, requirement: Requirement<'_>) -> Result<(), Error> {
        if !self.is_live() || self.requirement != requirement {
            Err(Error::StaleGeneration)
        } else {
            Ok(())
        }
    }
}
impl fmt::Debug for Permit<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FsCoverPermit")
            .field("serial", &self.serial)
            .field("epoch", &self.epoch)
            .field("expires_at", &self.expires_at)
            .field("requirement", &self.requirement)
            .finish()
    }
}
/// Actual permission check, without a manufactured IO success.
pub enum Admission<'id> {
    /// Original matching cover/queue conditions granted this linear operation.
    Ready(Permit<'id>),
    /// No native operation was admitted and genuine foreign traffic may proceed.
    Wait(Wait<'id>),
}
#[derive(Clone, Copy)]
struct Claim<'id> {
    permit: Permit<'id>,
    charge: u32,
    age: u64,
    expires_at: Option<u64>,
    transmit: Option<Transmit<'id>>,
    exposed: bool,
}
/// Bounded pure accounting/release owner over caller storage. It creates no
/// packet, thread, hidden clock/resolver, artificial traffic or peer success.
pub struct Policy<'id, 'slots> {
    owner: &'id Instance,
    credits: &'slots mut [CreditSlot<'id>],
    intents: &'slots mut [IntentSlot<'id>],
    limits: Limits,
    claim: Option<Claim<'id>>,
    last_now: Option<u64>,
    next_age: Option<u64>,
    age: u64,
    epoch: u64,
    stopping: bool,
    report: Report<'id>,
}
fn aged(mut count: u32, periods: u64) -> u32 {
    // A u32 balance becomes zero in fewer than512 such steps. No huge clock
    // jump creates unbounded work or wraps C's intermediate multiplication.
    for _ in 0..periods.min(512) {
        count = ((u64::from(count) * 15) / 16) as u32;
        if count == 0 {
            break;
        }
    }
    count
}
impl<'id, 'slots> Policy<'id, 'slots> {
    /// Borrow fixed empty rows and one stable identity before driving any IO.
    pub fn new(
        instance: &'id mut Instance,
        credits: &'slots mut [CreditSlot<'id>],
        intents: &'slots mut [IntentSlot<'id>],
        limits: Limits,
    ) -> Result<Self, Error> {
        if credits.is_empty()
            || intents.len() < 2
            || limits.maximum_delay_ms == u32::MAX
            || limits.cover_window_us == 0
            || limits.randomized_delays
                && (limits.maximum_delay_ms == 0
                    || limits.cover_window_us > u64::from(limits.maximum_delay_ms) * 1000)
        {
            return Err(Error::InvalidInput);
        }
        if instance.active.get() != 0
            || credits.iter().any(|s| s.record.is_some())
            || intents.iter().any(|s| s.record.is_some())
        {
            return Err(Error::Conflict);
        }
        let epoch = instance.epoch.get().checked_add(1).ok_or(Error::Overflow)?;
        instance.epoch.set(epoch);
        Ok(Self {
            owner: instance,
            credits,
            intents,
            limits,
            claim: None,
            last_now: None,
            next_age: None,
            age: 0,
            epoch,
            stopping: false,
            report: Report::default(),
        })
    }
    /// Preserve source-clock samples, never clamp or substitute another clock.
    /// A backward observation revokes old evidence/permissions, but retains the
    /// original randomized targets and original IO retirement obligation.
    pub fn advance(&mut self, now: u64) -> Result<(), Error> {
        if self.last_now.is_none() {
            self.next_age = Some(now.checked_add(AGE_US).ok_or(Error::Overflow)?);
        } else if self.last_now.is_some_and(|old| now < old) {
            let epoch = self.epoch.checked_add(1).ok_or(Error::Overflow)?;
            let target = now.checked_add(AGE_US).ok_or(Error::Overflow)?;
            self.clear_credits();
            self.epoch = epoch;
            self.owner.epoch.set(epoch);
            self.next_age = Some(target);
            self.report.time_epochs = self.report.time_epochs.saturating_add(1);
        }
        self.last_now = Some(now);
        self.owner.now.set(Some(now));
        for slot in &mut *self.credits {
            if slot.record.is_some_and(|credit| now >= credit.expires_at)
                && let Some(credit) = slot.record.take()
            {
                self.report.discarded = self
                    .report
                    .discarded
                    .saturating_add(u64::from(credit.count));
            }
        }
        if let Some(target) = self.next_age
            && now >= target
        {
            let periods = (now - target) / AGE_US + 1;
            let next = target
                .checked_add(periods.checked_mul(AGE_US).ok_or(Error::Overflow)?)
                .ok_or(Error::Overflow)?;
            let age = self.age.checked_add(periods).ok_or(Error::Overflow)?;
            for slot in &mut *self.credits {
                if let Some(mut credit) = slot.record {
                    let old = credit.count;
                    credit.count = aged(credit.count, periods);
                    self.report.discarded = self
                        .report
                        .discarded
                        .saturating_add(u64::from(old - credit.count));
                    slot.record = (credit.count != 0).then_some(credit);
                }
            }
            self.next_age = Some(next);
            self.age = age;
        }
        Ok(())
    }
    fn clear_credits(&mut self) {
        for slot in &mut *self.credits {
            if let Some(c) = slot.record.take() {
                self.report.discarded = self.report.discarded.saturating_add(u64::from(c.count));
            }
        }
    }
    fn balance(&self, key: CreditKey<'id>) -> u32 {
        self.credits
            .iter()
            .find_map(|s| s.record.filter(|c| c.key == key).map(|c| c.count))
            .unwrap_or(0)
    }
    fn wait(
        &mut self,
        r: Requirement<'id>,
        reason: WaitReason,
        available: u32,
        ready_at: Option<u64>,
    ) -> Admission<'id> {
        let observation = Wait {
            requirement: r,
            reason,
            available,
            needed: r.needed(),
            ready_at,
        };
        self.report.waited = self.report.waited.saturating_add(1);
        self.report.last_wait = Some(observation);
        Admission::Wait(observation)
    }
    /// Draw at most one bounded release target, and reserve L-1 actual matching
    /// credits only when ready. Missing cover does not occupy an intent row or
    /// the single native send, so genuine relays can create the needed cover.
    pub fn admit(
        &mut self,
        r: Requirement<'id>,
        now: u64,
        entropy: &mut impl Entropy,
    ) -> Result<Admission<'id>, Error> {
        self.advance(now)?;
        if self.stopping {
            return Err(Error::Closed);
        }
        let have = self.balance(r.into());
        if self.claim.is_some() {
            return Ok(self.wait(r, WaitReason::OriginalSend, have, None));
        }
        if !r.known {
            return Ok(self.wait(r, WaitReason::SourcePolicy, have, None));
        }
        let old = self
            .intents
            .iter()
            .position(|s| s.record.is_some_and(|i| i.requirement == r));
        let old_target = old.and_then(|i| self.intents[i].record.map(|i| i.ready_at));
        if have < r.needed() {
            return Ok(self.wait(r, WaitReason::Cover, have, old_target));
        }
        if self.limits.randomized_delays && r.delayed {
            let target = if let Some(target) = old_target {
                target
            } else {
                // Keep the last row available to genuine relays even when
                // originated intents lose their cover while waiting. Relays
                // prefer that row and may also use spare general rows.
                let free = if r.relay {
                    self.intents.iter().rposition(|s| s.record.is_none())
                } else {
                    self.intents[..self.intents.len() - 1]
                        .iter()
                        .position(|s| s.record.is_none())
                };
                let Some(slot) = free else {
                    return Ok(self.wait(r, WaitReason::Capacity, have, None));
                };
                let upper = self.limits.maximum_delay_ms + 1;
                let draw = entropy.uniform(upper)?;
                if draw >= upper {
                    return Err(Error::InvalidInput);
                }
                let target = now
                    .checked_add(u64::from(draw) * 1000)
                    .ok_or(Error::Overflow)?;
                self.intents[slot].record = Some(Intent {
                    requirement: r,
                    ready_at: target,
                });
                self.report.delays_drawn = self.report.delays_drawn.saturating_add(1);
                target
            };
            if now < target {
                return Ok(self.wait(r, WaitReason::Delay, have, Some(target)));
            }
        }
        let serial = self
            .owner
            .next
            .get()
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        let cost = r.needed();
        let mut expires_at = None;
        if cost != 0 {
            let slot = self
                .credits
                .iter_mut()
                .find(|s| s.record.is_some_and(|c| c.key == r.into()))
                .ok_or(Error::Conflict)?;
            let credit = slot.record.as_mut().ok_or(Error::Conflict)?;
            expires_at = Some(credit.expires_at);
            credit.count = credit.count.checked_sub(cost).ok_or(Error::Conflict)?;
            if credit.count == 0 {
                slot.record = None;
            }
        }
        for slot in &mut *self.intents {
            if slot.record.is_some_and(|i| i.requirement == r) {
                slot.record = None;
            }
        }
        let permit = Permit {
            owner: self.owner,
            serial,
            epoch: self.epoch,
            expires_at,
            requirement: r,
        };
        self.owner.next.set(serial);
        self.owner.active.set(serial);
        self.claim = Some(Claim {
            permit,
            charge: cost,
            age: self.age,
            expires_at,
            transmit: None,
            exposed: false,
        });
        Ok(Admission::Ready(permit))
    }
    fn claim_mut(&mut self, p: Permit<'id>) -> Result<&mut Claim<'id>, Error> {
        if !ptr::eq(self.owner, p.owner) {
            return Err(Error::StaleGeneration);
        }
        self.claim
            .as_mut()
            .filter(|c| {
                c.permit.serial == p.serial
                    && c.permit.epoch == p.epoch
                    && c.permit.requirement == p.requirement
            })
            .ok_or(Error::StaleGeneration)
    }
    /// Bind only the exact pure transmit prepared under this permission.
    pub fn bind(&mut self, p: Permit<'id>, tx: Transmit<'id>) -> Result<(), Error> {
        p.authorizes(p.requirement)?;
        let claim = self.claim_mut(p)?;
        if claim.transmit.is_some() {
            return Err(Error::Conflict);
        }
        claim.transmit = Some(tx);
        Ok(())
    }
    /// Observe the original actual positive CORE payload write, not send credit.
    pub fn exposed(&mut self, p: Permit<'id>) -> Result<(), Error> {
        let claim = self.claim_mut(p)?;
        if claim.transmit.is_none() {
            return Err(Error::NotReady);
        }
        let changed = !claim.exposed;
        claim.exposed = true;
        if changed && !p.requirement.relay {
            self.report.other_exposed = self.report.other_exposed.saturating_add(1);
        }
        Ok(())
    }
    fn restore(&mut self, c: Claim<'id>, target_live: bool) {
        if c.charge == 0 {
            return;
        }
        if c.exposed
            || c.permit.epoch != self.epoch
            || !target_live
            || self.stopping
            || c.expires_at
                .is_none_or(|end| self.last_now.is_none_or(|now| now >= end))
        {
            if c.exposed {
                self.report.spent = self.report.spent.saturating_add(u64::from(c.charge));
            } else {
                self.report.discarded = self.report.discarded.saturating_add(u64::from(c.charge));
            }
            return;
        }
        let amount = aged(c.charge, self.age.saturating_sub(c.age));
        self.report.discarded = self
            .report
            .discarded
            .saturating_add(u64::from(c.charge - amount));
        if amount == 0 {
            return;
        }
        let key = c.permit.requirement.into();
        if let Some(slot) = self
            .credits
            .iter_mut()
            .find(|s| s.record.is_some_and(|v| v.key == key))
        {
            if let Some(credit) = &mut slot.record {
                let accepted = amount.min(u32::MAX - credit.count);
                credit.count += accepted;
                // Joining a newer live batch cannot extend the original
                // reservation's period or make old cover look freshly earned.
                credit.expires_at = credit
                    .expires_at
                    .min(c.expires_at.unwrap_or(credit.expires_at));
                self.report.refunded = self.report.refunded.saturating_add(u64::from(accepted));
                self.report.discarded = self
                    .report
                    .discarded
                    .saturating_add(u64::from(amount - accepted));
            }
        } else if let Some(slot) = self.credits.iter_mut().find(|s| s.record.is_none()) {
            let Some(expires_at) = c.expires_at else {
                self.report.discarded = self.report.discarded.saturating_add(u64::from(amount));
                return;
            };
            slot.record = Some(Credit {
                key,
                count: amount,
                expires_at,
            });
            self.report.refunded = self.report.refunded.saturating_add(u64::from(amount));
        } else {
            self.report.discarded = self.report.discarded.saturating_add(u64::from(amount));
        }
    }
    /// Retire only an original permission that never acquired a pure transmit.
    /// Refusal cannot erase a bound operation or manufacture its quiescence.
    pub fn cancel_unprepared(
        &mut self,
        p: Permit<'id>,
        now: u64,
        target_live: bool,
    ) -> Result<(), Error> {
        self.advance(now)?;
        let c = *self.claim_mut(p)?;
        if c.transmit.is_some() {
            return Err(Error::Conflict);
        }
        self.claim = None;
        if self.owner.active.get() == p.serial {
            self.owner.active.set(0);
        }
        self.restore(c, target_live);
        Ok(())
    }
    /// Settle exact original IO even after its permission/clock epoch revoked.
    /// Only a full admitted/exposed genuinely relayed write with the original
    /// CORE completion explicitly Written earns credit; Unknown never does.
    /// This is local CORE handoff confirmation, not a peer processing ACK.
    pub fn settle(
        &mut self,
        p: Permit<'id>,
        fact: SendRetired<'id>,
        now: u64,
        confirmed_written: bool,
        target_live: bool,
    ) -> Result<(), Error> {
        self.advance(now)?;
        let mut c = *self.claim_mut(p)?;
        // An unrepresentable future cover window loses optional new evidence;
        // it must never prevent the exact original IO receipt from retiring.
        let credit_end = now.checked_add(self.limits.cover_window_us);
        let r = p.requirement;
        if c.transmit != Some(fact.transmit)
            || fact.route != r.route()
            || fact.neighbor != r.neighbor()
            || fact.path != r.path()
            || fact.bytes != r.class.bytes()
            || (fact.kind == SendKind::Query) != (r.class.message_type == mt::FS_GET)
        {
            return Err(Error::Authentication);
        }
        if confirmed_written && !fact.written {
            return Err(Error::InvalidInput);
        }
        if fact.written && (!fact.admitted || !fact.exposed) || fact.exposed && !fact.admitted {
            return Err(Error::InvalidInput);
        }
        if fact.exposed && !c.exposed {
            c.exposed = true;
            if !r.relay {
                self.report.other_exposed = self.report.other_exposed.saturating_add(1);
            }
        }
        self.claim = None;
        if self.owner.active.get() == p.serial {
            self.owner.active.set(0);
        }
        self.restore(c, target_live);
        if fact.written {
            if r.relay {
                if r.class.message_type == mt::FS_GET {
                    self.report.relayed_queries_written =
                        self.report.relayed_queries_written.saturating_add(1);
                } else {
                    self.report.relayed_contents_written =
                        self.report.relayed_contents_written.saturating_add(1);
                }
                if confirmed_written && target_live && !self.stopping {
                    let Some(credit_end) = credit_end else {
                        self.report.unrecorded_overflow =
                            self.report.unrecorded_overflow.saturating_add(1);
                        return Ok(());
                    };
                    let key = r.into();
                    if let Some(slot) = self
                        .credits
                        .iter_mut()
                        .find(|s| s.record.is_some_and(|c| c.key == key))
                    {
                        if let Some(credit) = &mut slot.record {
                            if credit.count == u32::MAX {
                                self.report.unrecorded_overflow =
                                    self.report.unrecorded_overflow.saturating_add(1);
                            } else {
                                credit.count += 1;
                            }
                        }
                    } else if let Some(slot) = self.credits.iter_mut().find(|s| s.record.is_none())
                    {
                        slot.record = Some(Credit {
                            key,
                            count: 1,
                            expires_at: credit_end,
                        });
                    } else {
                        self.report.unrecorded_capacity =
                            self.report.unrecorded_capacity.saturating_add(1);
                    }
                } else {
                    self.report.uncredited_complete =
                        self.report.uncredited_complete.saturating_add(1);
                }
            } else {
                self.report.other_written = self.report.other_written.saturating_add(1);
            }
        }
        Ok(())
    }
    /// Withdraw only one actual neighbor allocation. Copied old requirements
    /// cannot transfer its credits/permission to an equal raw peer identity.
    pub fn retire_neighbor(&mut self, n: Neighbor<'id>) {
        for slot in &mut *self.credits {
            if slot.record.is_some_and(|c| c.key.neighbor == n)
                && let Some(c) = slot.record.take()
            {
                self.report.discarded = self.report.discarded.saturating_add(u64::from(c.count));
            }
        }
        for slot in &mut *self.intents {
            if slot.record.is_some_and(|i| i.requirement.neighbor() == n) {
                slot.record = None;
            }
        }
        if self
            .claim
            .is_some_and(|c| c.permit.requirement.neighbor() == n)
        {
            self.owner.active.set(0);
        }
    }
    /// Remove only obsolete unadmitted intents; retain the original send claim.
    pub fn retain_intents(&mut self, mut current: impl FnMut(Requirement<'id>) -> bool) {
        for slot in &mut *self.intents {
            if slot.record.is_some_and(|i| !current(i.requirement)) {
                slot.record = None;
            }
        }
    }
    /// Current actual balance for this exact original egress/application class.
    #[must_use]
    pub fn available(&self, r: Requirement<'id>) -> u32 {
        self.balance(r.into())
    }
    /// Whether unadmitted output is owned by source/cover/release policy.
    /// Normal no-delay level1 delivery retains the existing consumer semantics.
    #[must_use]
    pub fn holds_output(&self, r: Requirement<'id>) -> bool {
        !r.known || r.needed() != 0 || self.limits.randomized_delays && r.delayed
    }
    /// Observe a current restriction without admitting work or drawing entropy.
    #[must_use]
    pub fn restriction(&self, r: Requirement<'id>, now: u64) -> WaitReason {
        if !r.known {
            WaitReason::SourcePolicy
        } else if self.balance(r.into()) < r.needed() {
            WaitReason::Cover
        } else if self.intents.iter().any(|s| {
            s.record
                .is_some_and(|i| i.requirement == r && i.ready_at > now)
        }) {
            WaitReason::Delay
        } else {
            WaitReason::OriginalSend
        }
    }
    /// Earliest *future* original target needing an external clock wake. A due
    /// intent waiting on IO/cover cannot create a permanently ready timer loop.
    #[must_use]
    pub fn next_deadline(&self, now: u64) -> Option<u64> {
        if self.stopping {
            return None;
        }
        self.intents
            .iter()
            .filter_map(|s| s.record.map(|i| i.ready_at).filter(|t| *t > now))
            .chain(self.claim.and_then(|c| c.expires_at).filter(|t| *t > now))
            .chain(
                self.credits
                    .iter()
                    .filter_map(|slot| slot.record.map(|c| c.expires_at)),
            )
            .chain(self.next_age.filter(|_| {
                self.credits
                    .iter()
                    .any(|s| s.record.is_some_and(|c| c.count != 0))
            }))
            .min()
    }
    /// Exact caller-selected local period and randomized release limits.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }
    /// Actual outstanding permission, including revoked original retirement.
    #[must_use]
    pub fn pending(&self) -> Option<Permit<'id>> {
        self.claim.map(|c| c.permit)
    }
    /// Read real original unspent rows, not inferred peer traffic or success.
    pub fn credits(&self) -> impl Iterator<Item = (Neighbor<'id>, Class, u32)> + '_ {
        self.credits
            .iter()
            .filter_map(|s| s.record.map(|c| (c.key.neighbor, c.key.class, c.count)))
    }
    /// Read actual original randomized targets without drawing new entropy.
    pub fn intents(&self) -> impl Iterator<Item = (Requirement<'id>, u64)> + '_ {
        self.intents
            .iter()
            .filter_map(|s| s.record.map(|i| (i.requirement, i.ready_at)))
    }
    /// Bounded actual accounting/wait observations.
    #[must_use]
    pub const fn report(&self) -> &Report<'id> {
        &self.report
    }
    /// Stop new admission and withdraw metadata-only intents. Original IO must
    /// still settle explicitly; this operation creates no ACK/END/quiescence.
    pub fn request_shutdown(&mut self) {
        self.stopping = true;
        self.owner.active.set(0);
        self.clear_credits();
        for s in &mut *self.intents {
            s.record = None;
        }
    }
    /// Only this local policy's original claim and intents have retired.
    #[must_use]
    pub fn quiesced(&self) -> bool {
        self.stopping && self.claim.is_none() && self.intents.iter().all(|s| s.record.is_none())
    }
}
impl Drop for Policy<'_, '_> {
    fn drop(&mut self) {
        self.owner.active.set(0);
        for s in &mut *self.credits {
            s.record = None;
        }
        for s in &mut *self.intents {
            s.record = None;
        }
    }
}
