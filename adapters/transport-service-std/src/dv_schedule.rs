//! Bounded actual DV probe/LEARN fanout scheduling. No Flow, frame, signature,
//! durable scalar, neighbour or source receipt is invented by this module.
//! Owner remains the sole poller/drainer of its actual shared reservation worker.
use crate::{
    Failure, Failures,
    epoch::{RangeOrigin, ReservationOutcome},
    generation::{self, CommittedRange, Purpose, Request, Reservations},
    owner::{Event as OwnerEvent, Owner},
    sender::DvScope,
    time::Bounds,
};
use gnunet_crypto::Entropy;
use gnunet_pils::client::Identity;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_transport::{PeerId, dv};
use gnunet_transport_dv_runtime_host as actor;
use gnunet_types::Error as Fault;
use gnunet_wire::official::AbsoluteTime;
use std::{
    cell::Cell,
    future::Future,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};

/// Explicit finite scheduling resources. All intervals use native monotonic
/// time; canonical UTC is only an expiry check or scalar lower-bound input.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Registered actual queue leases tracked at once.
    pub neighbours: usize,
    /// Concurrent original outstanding probes, <=caller Actor ProbeSlot count.
    pub probes: usize,
    /// Concurrent LEARN fanout planning rows.
    pub learns: usize,
    /// Concurrent original forward outputs, separate from actual Actor bounds.
    pub forwards: usize,
    /// Locally interested targets. Expiry means inconclusive, never no route.
    pub interests: usize,
    /// At most this many next recipients per original LEARN, including return.
    pub fanout: usize,
    /// Period between original attempts on each original eligible queue.
    pub interval: Duration,
    /// Rate floor even when a new discovery asks for an early probe round.
    pub minimum_interval: Duration,
    /// Original probe budget, including durable-range wait and actual sending.
    pub probe_lifetime: Duration,
    /// Original actual shared worker admission budget, never renewed on busy.
    pub range_operation: Duration,
    /// Original native usable range lifetime; canonical rollback cannot extend.
    pub range_lifetime: Duration,
    /// Begin bounded next-range prefetch before current original expiration.
    pub prefetch: Duration,
    /// Retry backpressure without spinning or creating another original task.
    pub retry: Duration,
    /// Maximum state transitions per poll; every path/hop scan is also bounded.
    pub quantum: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            neighbours: 64,
            probes: 8,
            learns: 8,
            forwards: 16,
            interests: 32,
            fanout: 3,
            interval: Duration::from_secs(60),
            minimum_interval: Duration::from_secs(10),
            probe_lifetime: Duration::from_secs(30),
            range_operation: Duration::from_secs(30),
            range_lifetime: Duration::from_secs(300),
            prefetch: Duration::from_secs(10),
            retry: Duration::from_millis(50),
            quantum: 4,
        }
    }
}
/// Original local discovery interest. Private brand and checked serial prevent
/// a same-number interest under another Scheduler/source from being canceled.
#[derive(Clone)]
pub struct Interest {
    domain: Arc<()>,
    serial: u64,
}
impl PartialEq for Interest {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.domain, &other.domain) && self.serial == other.serial
    }
}
impl Eq for Interest {}
impl std::fmt::Debug for Interest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("DvInterest").field(&self.serial).finish()
    }
}
/// Actual progress. Created/Forwarding are only actual Actor job admission;
/// Written requires Actor's retained original actual physical completion.
pub enum Event<'id> {
    /// Genuine same-scope worker request was actually admitted, not committed.
    RangeRequested(Request),
    /// Private genuine same-request committed range is retained exclusively.
    RangeAccepted {
        /// Actual backend commit generation.
        generation: u64,
        /// Actually committed inclusive first scalar.
        first: u64,
        /// Actually committed inclusive last scalar.
        last: u64,
    },
    /// Genuine actual commit was too late/wrong-scope to authorize new work.
    RangeBurned {
        /// Actual backend commit generation.
        generation: u64,
        /// Actually committed inclusive first scalar.
        first: u64,
        /// Actually committed inclusive last scalar.
        last: u64,
    },
    /// Original range intent expired before any actual worker queue admission.
    RangeNotAdmitted,
    /// Original source/Engine was physically or logically retired; no new use.
    ScopeRetired,
    /// Actual purpose37 request admitted under a real durable scalar.
    ProbeCreated {
        /// Original private Actor work identity.
        token: actor::Token<'id>,
        /// Original actual registered direct queue lease.
        neighbour: actor::Neighbour<'id>,
    },
    /// Actual original complete physical DV probe write observed once.
    ProbeWritten(actor::Token<'id>),
    /// Original probe route lease retired and actual physical output ended.
    ProbeFinished {
        /// Original private Actor work identity.
        token: actor::Token<'id>,
        /// True only after retained actual whole-write observation.
        sent: bool,
        /// Original observed physical outcome; no remote delivery claim.
        outcome: actor::WriteOutcome,
    },
    /// Verified LEARN and its fixed selected eligible next-hop list retained.
    LearnPlanned {
        /// Original retained signature-verified input identity.
        input: actor::Token<'id>,
        /// Bounded fixed count of selected actual queue leases.
        recipients: usize,
    },
    /// Actual purpose36 request admitted; no wire write/remote delivery implied.
    ForwardCreated {
        /// Original retained signature-verified input identity.
        input: actor::Token<'id>,
        /// Original immutable Actor output identity.
        output: actor::Token<'id>,
        /// Actual selected original direct queue lease.
        next: actor::Neighbour<'id>,
    },
    /// Actual forward ended, or its receipt was already consumed elsewhere.
    /// None preserves lack of a physical fact instead of fabricating success.
    ForwardFinished {
        /// Original immutable Actor output identity.
        output: actor::Token<'id>,
        /// Original observed physical outcome; no remote delivery claim.
        outcome: Option<actor::WriteOutcome>,
    },
    /// Actual currently confirmed route under this same Actor/source exists.
    Discovered {
        /// Original local interest allocation.
        interest: Interest,
        /// Original requested remote public identity.
        target: PeerId,
        /// Actual route validity under this same original source.
        route: actor::RouteLife<'id>,
    },
    /// Original target expired; this does not assert that the target has no path.
    Inconclusive {
        /// Original local interest allocation; it is no longer pending here.
        interest: Interest,
        /// Original requested public peer; no negative reachability is inferred.
        target: PeerId,
    },
    /// Exact actual operation/admission failure, preserving its original cause.
    Failed {
        /// Original probe identity when the failure was probe-specific.
        probe: Option<actor::Token<'id>>,
        /// Exact original actual failure, without replacement success.
        error: Failure,
    },
    /// Bounded local state transition, never an external receipt.
    Activity,
}
struct ProbeIntent {
    budget: actor::Budget,
    retry: Instant,
}
struct NeighbourRow<'id> {
    neighbour: actor::Neighbour<'id>,
    due: Instant,
    last: Option<Instant>,
    intent: Option<ProbeIntent>,
    probe: Option<actor::Token<'id>>,
}
struct ProbeRow<'id> {
    token: actor::Token<'id>,
    budget: actor::Budget,
    reported: bool,
    retiring: bool,
}
struct Plan<'id> {
    input: actor::Token<'id>,
    budget: actor::Budget,
    selected: Vec<actor::Neighbour<'id>>,
    next: usize,
    retry: Instant,
}
// A cursor points to the next original row, rather than permanently favoring
// vector index zero. Removing a row preserves its old successor even when the
// tail is moved into the vacant position.
#[derive(Default)]
struct PlanCursor {
    next: usize,
}
impl PlanCursor {
    fn take(&mut self, len: usize) -> Option<usize> {
        if len == 0 {
            self.next = 0;
            return None;
        }
        let index = self.next % len;
        self.next = if index + 1 == len { 0 } else { index + 1 };
        Some(index)
    }
    fn removed(&mut self, index: usize, old_len: usize) {
        if old_len <= 1 {
            self.next = 0;
            return;
        }
        let next = self.next % old_len;
        let next = if next == index {
            (index + 1) % old_len
        } else {
            next
        };
        self.next = if next == old_len - 1 { index } else { next };
    }
}
const SCHEDULE_CLASSES: usize = 4;
#[derive(Default)]
struct IdlePass {
    seen: usize,
}
impl IdlePass {
    fn idle(&mut self) -> bool {
        // A parent's continued polling is not new child work. Completed scans
        // stay complete until an actual local change or original timer fires.
        // Report only the transition so later spot-check polls still use their
        // original quantum without rebuilding continuation debt.
        let completed = self.complete();
        self.seen = self.seen.saturating_add(1).min(SCHEDULE_CLASSES);
        !completed && self.complete()
    }
    fn complete(&self) -> bool {
        self.seen == SCHEDULE_CLASSES
    }
    fn progress(&mut self) {
        self.seen = 0;
    }
}
struct Forward<'id> {
    token: actor::Token<'id>,
    next: actor::Neighbour<'id>,
    budget: actor::Budget,
    retiring: bool,
}
struct Target {
    interest: Interest,
    peer: PeerId,
    budget: actor::Budget,
}
struct RangeIntent {
    budget: actor::Budget,
    usable_hard: Instant,
    request: Option<Request>,
    retiring: bool,
}
struct Range {
    actual: Arc<CommittedRange>,
    next: u64,
    hard: Instant,
}
impl Range {
    fn usable(&self, now: u64) -> bool {
        Instant::now() < self.hard
            && self.next <= self.actual.span().last()
            && now <= self.actual.span().last()
    }
    fn take(&mut self, now: u64) -> Option<u64> {
        if !self.usable(now) {
            return None;
        }
        let n = self.next.max(now);
        self.next = n.checked_add(1)?;
        Some(n)
    }
}
/// One exclusive scalar allocated from an ACTUAL private committed DV range.
/// Not Clone/Copy; consumption validates original source and caller budget.
/// This is durability provenance, not a signature or native-write receipt.
pub struct Stamp<'pils, 'owner> {
    actual: Arc<CommittedRange>,
    value: u64,
    scope: DvScope<'owner>,
    actor: Identity<'pils>,
    clock: Arc<dyn RuntimeClock>,
    budget: actor::Budget,
    range_hard: Instant,
    alive: Rc<Cell<bool>>,
}
impl Stamp<'_, '_> {
    /// Actual original backend commit generation; not a publication ACK.
    pub fn generation(&self) -> u64 {
        self.actual.generation()
    }
    /// Exact original genuine range request, not another consumer's job.
    pub fn request(&self) -> &Request {
        self.actual.request()
    }
}
impl<'pils, 'owner> Stamp<'pils, 'owner> {
    /// Burn/consume once for the SAME original operation. No file, entropy,
    /// signature or worker is opened here; actual Actor crypto still follows.
    pub fn consume<'id, 'source, 'slots, 'out, J, E: Entropy, const N: usize>(
        self,
        runtime: &mut actor::Runtime<'id, 'source, 'pils, 'slots, 'out, J, N>,
        owner: &Owner<'owner, E>,
        original: actor::Budget,
    ) -> Result<u64, Failure> {
        if Instant::now() >= self.budget.hard || Instant::now() >= self.range_hard {
            return Err(Fault::Deadline.into());
        }
        if !self.alive.get() {
            return Err(Fault::Closed.into());
        }
        if original.until != self.budget.until || original.hard != self.budget.hard {
            return Err(Fault::Stale.into());
        }
        if runtime.is_closed()
            || runtime.identity() != self.actor
            || owner.dv_scope().as_ref() != Some(&self.scope)
            || !Arc::ptr_eq(&self.clock, &runtime.clock())
            || !Arc::ptr_eq(&self.clock, &owner.dv_clock())
            || self.actual.purpose() != Purpose::Dv
            || !self.actual.span().contains(self.value)
        {
            return Err(Fault::Authentication.into());
        }
        let now = match self.clock.sample() {
            Ok(sample) => sample.now.as_micros(),
            Err(error) => {
                runtime.close();
                return Err(error.into());
            }
        };
        if !live(self.budget, now) || Instant::now() >= self.range_hard {
            return Err(Fault::Deadline.into());
        }
        Ok(self.value)
    }
}
/// Actual shared Owner+Actor source bindings with fixed small pools. No worker
/// is polled here; request_dv_range is called on the real Owner and only its
/// genuine private CommittedRange callback can populate the exclusive allocator.
#[must_use = "close scheduler-owned work before replacing either source/Engine scope"]
pub struct Scheduler<'id, 'pils, 'owner> {
    domain: Arc<()>,
    serial: u64,
    alive: Rc<Cell<bool>>,
    actor: Identity<'pils>,
    scope: DvScope<'owner>,
    clock: Arc<dyn RuntimeClock>,
    limits: Limits,
    neighbours: Vec<NeighbourRow<'id>>,
    probes: Vec<ProbeRow<'id>>,
    plans: Vec<Plan<'id>>,
    plan_cursor: PlanCursor,
    forwards: Vec<Forward<'id>>,
    targets: Vec<Target>,
    range: Option<Range>,
    spare: Option<Range>,
    range_intent: Option<RangeIntent>,
    greatest_upper: u64,
    cursor: usize,
    class: usize,
    idle_pass: IdlePass,
    select: usize,
    closed: bool,
    alarm: Option<Pin<Box<Sleep>>>,
    cleanup: Option<Failure>,
}
fn reserve<T>(limit: usize) -> Result<Vec<T>, Fault> {
    let mut rows = Vec::new();
    rows.try_reserve_exact(limit).map_err(|_| Fault::Capacity)?;
    Ok(rows)
}
fn after(now: u64, duration: Duration) -> Result<actor::Budget, Fault> {
    let micros = u64::try_from(duration.as_micros()).map_err(|_| Fault::Overflow)?;
    if micros == 0 {
        return Err(Fault::InvalidInput);
    }
    let until = now
        .checked_add(micros)
        .filter(|n| *n != u64::MAX)
        .ok_or(Fault::Overflow)?;
    let hard = Instant::now()
        .checked_add(duration)
        .ok_or(Fault::Overflow)?;
    Ok(actor::Budget {
        until: AbsoluteTime::from_micros(until),
        hard,
    })
}
fn live(budget: actor::Budget, now: u64) -> bool {
    Instant::now() < budget.hard && now < budget.until.as_micros()
}
fn busy(error: &Failure) -> bool {
    error
        .downcast_ref::<Fault>()
        .is_some_and(|e| *e == Fault::WouldBlock)
        || matches!(
            error.downcast_ref::<generation::Error>(),
            Some(generation::Error::Protocol(Fault::WouldBlock))
        )
}
fn actor_busy(error: &actor::Error) -> bool {
    matches!(
        error,
        actor::Error::Protocol(Fault::Capacity | Fault::WouldBlock | Fault::NotReady)
            | actor::Error::Pils(gnunet_client_host::ConnectError::Protocol(
                Fault::Capacity | Fault::WouldBlock | Fault::NotReady
            ))
    )
}
impl<'id, 'pils, 'owner> Scheduler<'id, 'pils, 'owner> {
    /// Bind the actual current opaque Owner Engine scope and the independently
    /// observed Actor PILS epoch. They must have the same actual public local
    /// identity; their separate MQ epoch tokens are deliberately NOT equated.
    pub fn new<'source, 'slots, 'out, J, E: Entropy, const N: usize>(
        runtime: &actor::Runtime<'id, 'source, 'pils, 'slots, 'out, J, N>,
        owner: &Owner<'owner, E>,
        limits: Limits,
    ) -> Result<Self, Failure> {
        if limits.neighbours == 0
            || limits.probes == 0
            || limits.learns == 0
            || limits.forwards == 0
            || limits.interests == 0
            || limits.quantum == 0
            || limits.fanout == 0
            || limits.fanout > 8
            || limits.minimum_interval.is_zero()
            || limits.interval < limits.minimum_interval
            || limits.probe_lifetime.is_zero()
            || limits.range_operation.is_zero()
            || limits.range_lifetime.is_zero()
            || limits.prefetch >= limits.range_lifetime
            || limits.retry.is_zero()
        {
            return Err(Fault::InvalidInput.into());
        }
        let scope = owner.dv_scope().ok_or(Fault::NotReady)?;
        let identity = runtime.identity();
        if runtime.is_closed()
            || identity.peer() != scope.identity().peer()
            || !Arc::ptr_eq(&runtime.clock(), &owner.dv_clock())
        {
            return Err(Fault::Authentication.into());
        }
        Ok(Self {
            domain: Arc::new(()),
            serial: 0,
            alive: Rc::new(Cell::new(true)),
            actor: identity,
            scope,
            clock: runtime.clock(),
            limits,
            neighbours: reserve(limits.neighbours)?,
            probes: reserve(limits.probes)?,
            plans: reserve(limits.learns)?,
            plan_cursor: PlanCursor::default(),
            forwards: reserve(limits.forwards)?,
            targets: reserve(limits.interests)?,
            range: None,
            spare: None,
            range_intent: None,
            greatest_upper: 0,
            cursor: 0,
            class: 0,
            idle_pass: IdlePass::default(),
            select: 0,
            closed: false,
            alarm: None,
            cleanup: None,
        })
    }
    /// Real original engine allocation, not reconstructed from a peer or integer.
    pub fn scope(&self) -> &DvScope<'owner> {
        &self.scope
    }
    /// Finite unsurveyed class debt, distinct from physical or protocol work.
    /// The parent must retain a pass while this child scan is incomplete.
    #[cfg(feature = "program")]
    pub(crate) fn scan_pending(&self) -> bool {
        !self.closed && !self.idle_pass.complete()
    }
    /// Invalidate old idle observations after actual local work or a one-time
    /// Actor transition. A repeated terminal/blocked query must not call this.
    pub(crate) fn scan_changed(&mut self) {
        self.idle_pass.progress();
    }
    /// Pending exact actual shared worker job, retained through logical cancel.
    pub fn pending_range(&self) -> Option<&Request> {
        self.range_intent.as_ref().and_then(|i| i.request.as_ref())
    }
    /// Queue one finite original local route interest. No online query or fake
    /// negative response is created; expiry will be reported as inconclusive.
    pub fn discover(&mut self, peer: PeerId, budget: actor::Budget) -> Result<Interest, Fault> {
        if self.closed {
            return Err(Fault::Closed);
        }
        if Instant::now() >= budget.hard
            || budget.until.as_micros() == 0
            || budget.until.as_micros() == u64::MAX
        {
            return Err(Fault::Deadline);
        }
        if self.targets.len() == self.limits.interests {
            return Err(Fault::Capacity);
        }
        let serial = self.serial.checked_add(1).ok_or(Fault::Overflow)?;
        self.serial = serial;
        let interest = Interest {
            domain: self.domain.clone(),
            serial,
        };
        self.targets.push(Target {
            interest: interest.clone(),
            peer,
            budget,
        });
        self.scan_changed();
        let now = Instant::now();
        for n in &mut self.neighbours {
            if n.intent.is_none() && n.probe.is_none() {
                let floor = n
                    .last
                    .and_then(|last| last.checked_add(self.limits.minimum_interval))
                    .unwrap_or(now);
                n.due = n.due.min(floor.max(now));
            }
        }
        Ok(interest)
    }
    /// Cancel only this original local interest, not signed probes, other
    /// consumers, an actual worker operation or a remote wire transaction.
    pub fn cancel_interest(&mut self, id: &Interest) -> Result<(), Fault> {
        let i = self
            .targets
            .iter()
            .position(|t| &t.interest == id)
            .ok_or(Fault::Stale)?;
        self.targets.swap_remove(i);
        self.scan_changed();
        Ok(())
    }
    /// Observe only this scheduler's genuine original purpose-DV result.
    /// Call after Owner.poll's callback returns, with the actual current Owner.
    /// Unhandled non-Clone Owner events remain untouched in the SAME slot; only
    /// a matching consumed receipt returns Some scheduler event. No unrelated
    /// event is boxed, copied or rebound to another source/request.
    pub fn observe_owner<'source, 'slots, 'out, J, E: Entropy, const N: usize>(
        &mut self,
        runtime: &mut actor::Runtime<'id, 'source, 'pils, 'slots, 'out, J, N>,
        owner: &Owner<'owner, E>,
        input: &mut Option<OwnerEvent<'owner>>,
    ) -> Option<Event<'id>> {
        if let Some(OwnerEvent::DvRange { original, actual }) = input.as_ref() {
            let ours = self
                .range_intent
                .as_ref()
                .and_then(|i| i.request.as_ref())
                .is_some_and(|r| r == original.request() && r == actual.request());
            if !ours || original.scope() != &self.scope {
                return None;
            }
            // The original private event has been matched without moving it.
            // No callback/await/mutation of input occurs between check and take.
            let Some(OwnerEvent::DvRange {
                original: _,
                actual,
            }) = input.take()
            else {
                return None;
            };
            self.scan_changed();
            let intent = self.range_intent.take();
            let span = actual.span();
            let generation = actual.generation();
            let mut clock_failure = None;
            let checked = (|| {
                let intent = intent.as_ref().ok_or(Fault::Stale)?;
                if Instant::now() >= intent.budget.hard || intent.retiring {
                    return Err(Fault::Deadline);
                }
                if self.closed
                    || runtime.is_closed()
                    || runtime.identity() != self.actor
                    || owner.dv_scope().as_ref() != Some(&self.scope)
                {
                    return Err(Fault::Stale);
                }
                if actual.purpose() != Purpose::Dv
                    || !matches!(actual.request().kind(),generation::Kind::Range{purpose:Purpose::Dv,span:s} if s==span)
                {
                    return Err(Fault::Authentication);
                }
                let now = match self.clock.sample() {
                    Ok(sample) => sample.now.as_micros(),
                    Err(error) => {
                        clock_failure = Some(error);
                        return Err(error);
                    }
                };
                if !live(intent.budget, now)
                    || Instant::now() >= intent.usable_hard
                    || now > span.last()
                {
                    return Err(Fault::Deadline);
                }
                if span.first() <= self.greatest_upper {
                    return Err(Fault::Replay);
                }
                Ok(())
            })();
            self.greatest_upper = self.greatest_upper.max(span.last());
            if let Some(error) = clock_failure {
                runtime.close();
                self.close(runtime);
                return Some(Event::Failed {
                    probe: None,
                    error: Box::new(error),
                });
            }
            if checked.is_err() {
                // Genuine committed values remain consumed even when no
                // probe can use them; never replay/relabel this receipt.
                return Some(Event::RangeBurned {
                    generation,
                    first: span.first(),
                    last: span.last(),
                });
            }
            let Some(intent) = intent else {
                return Some(Event::RangeBurned {
                    generation,
                    first: span.first(),
                    last: span.last(),
                });
            };
            let range = Range {
                actual: Arc::new(actual),
                next: span.first(),
                hard: intent.usable_hard,
            };
            if self.range.is_none() {
                self.range = Some(range)
            } else if self.spare.is_none() {
                self.spare = Some(range)
            } else {
                return Some(Event::RangeBurned {
                    generation,
                    first: span.first(),
                    last: span.last(),
                });
            }
            Some(Event::RangeAccepted {
                generation,
                first: span.first(),
                last: span.last(),
            })
        } else if let Some(OwnerEvent::ReservationRetired(actual)) = input.as_ref() {
            if !self.retired(actual) {
                return None;
            }
            let Some(OwnerEvent::ReservationRetired(ReservationOutcome::RangeBurned {
                actual,
                ..
            })) = input.take()
            else {
                return None;
            };
            let span = actual.span();
            Some(Event::RangeBurned {
                generation: actual.generation(),
                first: span.first(),
                last: span.last(),
            })
        } else {
            None
        }
    }
    fn retired(&mut self, actual: &ReservationOutcome<'owner>) -> bool {
        let Some(request) = self.pending_range() else {
            return false;
        };
        if let ReservationOutcome::RangeBurned { original, .. } = actual
            && original.request() == request
            && matches!(original.origin(),RangeOrigin::Dv(scope) if scope==&self.scope)
        {
            self.range_intent = None;
            self.scan_changed();
            return true;
        }
        false
    }
    fn remember(&mut self, error: Failure) {
        if self.cleanup.is_none() {
            self.cleanup = Some(error)
        }
    }
    /// Scheduler cancellation stops only its own original probe/forward work.
    /// Actor/Bridge/Owner still own external native frames and disk drain/join.
    /// Queued original range metadata is retained until its actual Owner result.
    pub fn close<'source, 'slots, 'out, J, const N: usize>(
        &mut self,
        runtime: &mut actor::Runtime<'id, 'source, 'pils, 'slots, 'out, J, N>,
    ) {
        self.closed = true;
        self.alive.set(false);
        self.alarm = None;
        self.range = None;
        self.spare = None;
        self.targets.clear();
        if let Some(intent) = &mut self.range_intent {
            intent.retiring = true;
            if intent.request.is_none() {
                self.range_intent = None;
            }
        }
        for p in 0..self.probes.len() {
            self.probes[p].retiring = true;
            if let Err(e) = runtime.retire_probe(self.probes[p].token) {
                self.remember(Box::new(e));
            }
        }
        for f in 0..self.forwards.len() {
            self.forwards[f].retiring = true;
            if let Err(e) = runtime.cancel(self.forwards[f].token) {
                self.remember(Box::new(e));
            }
        }
        for p in 0..self.plans.len() {
            if let Err(e) = runtime.cancel(self.plans[p].input) {
                self.remember(Box::new(e));
            }
        }
        self.plans.clear();
        self.plan_cursor = PlanCursor::default();
        self.idle_pass.progress();
        for n in &mut self.neighbours {
            n.intent = None;
        }
    }
    /// First independent original cleanup cause; it never replaces an earlier
    /// source/clock/worker cause returned by poll.
    pub fn take_cleanup_error(&mut self) -> Option<Failure> {
        self.cleanup.take()
    }
    fn remove_plan(&mut self, index: usize) -> Plan<'id> {
        let old_len = self.plans.len();
        let plan = self.plans.swap_remove(index);
        self.plan_cursor.removed(index, old_len);
        plan
    }
    fn ready_event(&mut self, event: Event<'id>) -> Poll<Result<Event<'id>, Failure>> {
        // Earlier classes may become ready after an actual event, so a partial
        // idle pass can no longer establish that they are still idle.
        self.idle_pass.progress();
        Poll::Ready(Ok(event))
    }
    fn sync<'source, 'slots, 'out, J, const N: usize>(
        &mut self,
        runtime: &mut actor::Runtime<'id, 'source, 'pils, 'slots, 'out, J, N>,
    ) -> Result<bool, Failure> {
        let mut changed = false;
        let mut i = 0;
        while i < self.neighbours.len() {
            if runtime
                .neighbours()
                .any(|n| n == &self.neighbours[i].neighbour)
            {
                i += 1;
                continue;
            }
            if let Some(token) = self.neighbours[i].probe {
                runtime.retire_probe(token)?;
            }
            self.neighbours.swap_remove(i);
            changed = true;
        }
        for n in runtime.neighbours() {
            if self.neighbours.iter().any(|r| &r.neighbour == n) {
                continue;
            }
            if self.neighbours.len() == self.limits.neighbours {
                return Err(Fault::Capacity.into());
            }
            self.neighbours.push(NeighbourRow {
                neighbour: n.clone(),
                due: Instant::now(),
                last: None,
                intent: None,
                probe: None,
            });
            changed = true;
        }
        for f in 0..self.forwards.len() {
            if !self.forwards[f].retiring
                && !runtime.neighbours().any(|n| n == &self.forwards[f].next)
            {
                runtime.cancel(self.forwards[f].token)?;
                self.forwards[f].retiring = true;
                self.scan_changed();
            }
        }
        Ok(changed)
    }
    fn arm(&mut self, cx: &mut Context<'_>, earlier_only: bool) -> Result<(), Fault> {
        // Observe the original registered timer before moving expired retry
        // hints to the existing finite fallback. Rearming first would erase
        // this real wake, while comparing stale retry values on every poll
        // would recreate child scan debt indefinitely.
        let original_ready = self
            .alarm
            .as_mut()
            .is_some_and(|alarm| alarm.as_mut().poll(cx).is_ready());
        if original_ready {
            self.scan_changed();
        }
        let now = Instant::now();
        let fallback = now.checked_add(self.limits.retry).ok_or(Fault::Overflow)?;
        let mut next: Option<Instant> = None;
        let mut consider = |at: Instant| {
            let at = if at > now { at } else { fallback };
            next = Some(next.map_or(at, |old| old.min(at)));
        };
        for n in &self.neighbours {
            if let Some(i) = &n.intent {
                consider(i.budget.hard);
                consider(i.retry)
            } else if n.probe.is_none() && !self.closed {
                consider(n.due)
            }
        }
        for p in &self.probes {
            if !p.retiring {
                consider(p.budget.hard)
            }
        }
        for p in &self.plans {
            consider(p.budget.hard);
            consider(p.retry)
        }
        for f in &self.forwards {
            if !f.retiring {
                consider(f.budget.hard)
            }
        }
        for t in &self.targets {
            consider(t.budget.hard)
        }
        if let Some(i) = &self.range_intent
            && !i.retiring
        {
            consider(i.budget.hard);
            if i.request.is_none() {
                consider(fallback)
            }
        }
        let Some(next) = next else {
            self.alarm = None;
            return Ok(());
        };
        // A new intent/range can introduce an earlier hard target after the
        // initial guard. The final Pending check may bring that target forward,
        // but cannot postpone an existing live retry merely because it polled.
        // An observed expired alarm still receives the existing fallback rearm.
        if earlier_only
            && !original_ready
            && self
                .alarm
                .as_ref()
                .is_some_and(|alarm| alarm.deadline() <= next)
        {
            return Ok(());
        }
        let timer = self
            .alarm
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(next)));
        timer.as_mut().reset(next);
        let registered_ready = timer.as_mut().poll(cx).is_ready();
        // The target may have elapsed between the first poll and registration.
        // Preserve that real wake, once per arm, without claiming native IO.
        if registered_ready && !original_ready {
            self.scan_changed();
        }
        Ok(())
    }
    fn reap<'source, 'slots, 'out, J, const N: usize>(
        &mut self,
        runtime: &mut actor::Runtime<'id, 'source, 'pils, 'slots, 'out, J, N>,
    ) -> Result<Option<Event<'id>>, Failure> {
        let native = Instant::now();
        for i in 0..self.probes.len() {
            let token = self.probes[i].token;
            let budget = self.probes[i].budget;
            let reported = self.probes[i].reported;
            let status = runtime.probe_status(token)?;
            if status.sent && !reported {
                self.probes[i].reported = true;
                return Ok(Some(Event::ProbeWritten(token)));
            }
            if status.retired {
                self.probes[i].retiring = true;
            }
            if !status.retired && native >= budget.hard {
                runtime.retire_probe(token)?;
                self.probes[i].retiring = true;
                return Ok(Some(Event::Activity));
            }
            if status.retired && status.outcome.is_some() {
                let sent = status.sent;
                let outcome = status.outcome.ok_or(Fault::Stale)?;
                runtime.release_probe(token)?;
                self.probes.swap_remove(i);
                for n in &mut self.neighbours {
                    if n.probe == Some(token) {
                        n.probe = None;
                    }
                }
                return Ok(Some(Event::ProbeFinished {
                    token,
                    sent,
                    outcome,
                }));
            }
        }
        for i in 0..self.forwards.len() {
            let token = self.forwards[i].token;
            match runtime.output_outcome(token) {
                Ok(Some(outcome)) => {
                    self.forwards.swap_remove(i);
                    return Ok(Some(Event::ForwardFinished {
                        output: token,
                        outcome: Some(outcome),
                    }));
                }
                Err(actor::Error::Protocol(Fault::Stale)) => {
                    self.forwards.swap_remove(i);
                    return Ok(Some(Event::ForwardFinished {
                        output: token,
                        outcome: None,
                    }));
                }
                Err(e) => return Err(Box::new(e)),
                Ok(None)
                    if !self.forwards[i].retiring && native >= self.forwards[i].budget.hard =>
                {
                    runtime.cancel(token)?;
                    self.forwards[i].retiring = true;
                }
                _ => {}
            }
        }
        Ok(None)
    }
    fn native_guard<'source, 'slots, 'out, J, const N: usize>(
        &mut self,
        runtime: &mut actor::Runtime<'id, 'source, 'pils, 'slots, 'out, J, N>,
        cx: &mut Context<'_>,
    ) -> Result<Option<Event<'id>>, Failure> {
        self.arm(cx, false)?;
        if let Some(event) = self.reap(runtime)? {
            return Ok(Some(event));
        }
        let now = Instant::now();
        if let Some(i) = self.targets.iter().position(|t| now >= t.budget.hard) {
            let t = self.targets.swap_remove(i);
            return Ok(Some(Event::Inconclusive {
                interest: t.interest,
                target: t.peer,
            }));
        }
        for i in 0..self.neighbours.len() {
            if self.neighbours[i]
                .intent
                .as_ref()
                .is_some_and(|p| now >= p.budget.hard)
            {
                self.neighbours[i].intent = None;
                return Ok(Some(Event::Activity));
            }
        }
        if let Some(i) = self.plans.iter().position(|p| now >= p.budget.hard) {
            let p = self.remove_plan(i);
            if let Err(error) = runtime.cancel(p.input)
                && !matches!(error, actor::Error::Protocol(Fault::Stale))
            {
                return Err(Box::new(error));
            }
            return Ok(Some(Event::Activity));
        }
        if let Some(intent) = &mut self.range_intent
            && !intent.retiring
            && now >= intent.budget.hard
        {
            intent.retiring = true;
            if intent.request.is_none() {
                self.range_intent = None;
                return Ok(Some(Event::RangeNotAdmitted));
            }
        }
        if self.range.as_ref().is_some_and(|r| now >= r.hard) {
            self.range = None;
            self.scan_changed();
        }
        if self.spare.as_ref().is_some_and(|r| now >= r.hard) {
            self.spare = None;
            self.scan_changed();
        }
        Ok(None)
    }
    fn current<'source, 'slots, 'out, J, E: Entropy, const N: usize>(
        &self,
        runtime: &actor::Runtime<'id, 'source, 'pils, 'slots, 'out, J, N>,
        owner: &Owner<'owner, E>,
    ) -> bool {
        !self.closed
            && !runtime.is_closed()
            && runtime.identity() == self.actor
            && owner.dv_scope().as_ref() == Some(&self.scope)
    }
    fn prepare_range(&mut self, now: u64, original: Option<actor::Budget>) -> Result<(), Fault> {
        if self.range_intent.is_some() || self.spare.is_some() {
            return Ok(());
        }
        let mut budget = after(now, self.limits.range_operation)?;
        if let Some(original) = original {
            budget.hard = budget.hard.min(original.hard);
            budget.until = budget.until.min(original.until)
        }
        if !live(budget, now) {
            return Err(Fault::Deadline);
        }
        let usable_hard = Instant::now()
            .checked_add(self.limits.range_lifetime)
            .ok_or(Fault::Overflow)?;
        self.range_intent = Some(RangeIntent {
            budget,
            usable_hard,
            request: None,
            retiring: false,
        });
        self.scan_changed();
        Ok(())
    }
    fn refresh_ranges(&mut self, now: u64) {
        let mut changed = false;
        if self.range.as_ref().is_some_and(|r| !r.usable(now)) {
            self.range = None;
            changed = true;
        }
        if self.spare.as_ref().is_some_and(|r| !r.usable(now)) {
            self.spare = None;
            changed = true;
        }
        if self.range.is_none() && self.spare.is_some() {
            self.range = self.spare.take();
            changed = true;
        }
        if changed {
            self.scan_changed();
        }
    }
    /// Shared production DV stamp allocator for probes AND actual BOX material
    /// attempts. It uses only owned private committed ranges, never arbitrary
    /// scalar inputs or a second watermark/worker. None retains a real demand.
    pub fn claim_stamp<'source, 'slots, 'out, J, E: Entropy, const N: usize>(
        &mut self,
        runtime: &mut actor::Runtime<'id, 'source, 'pils, 'slots, 'out, J, N>,
        owner: &Owner<'owner, E>,
        original: actor::Budget,
    ) -> Result<Option<Stamp<'pils, 'owner>>, Failure> {
        if Instant::now() >= original.hard {
            return Err(Fault::Deadline.into());
        }
        if !self.current(runtime, owner) {
            self.close(runtime);
            return Err(Fault::Stale.into());
        }
        let now = match self.clock.sample() {
            Ok(sample) => sample.now.as_micros(),
            Err(error) => {
                runtime.close();
                self.close(runtime);
                return Err(error.into());
            }
        };
        if !live(original, now) {
            return Err(Fault::Deadline.into());
        }
        self.refresh_ranges(now);
        if let Some(range) = &mut self.range
            && let Some(value) = range.take(now)
        {
            let stamp = Stamp {
                actual: range.actual.clone(),
                value,
                scope: self.scope.clone(),
                actor: self.actor,
                clock: self.clock.clone(),
                budget: original,
                range_hard: range.hard,
                alive: self.alive.clone(),
            };
            self.scan_changed();
            return Ok(Some(stamp));
        }
        self.prepare_range(now, Some(original))?;
        Ok(None)
    }
    fn ranges<'source, 'slots, 'out, J, E: Entropy, const N: usize>(
        &mut self,
        runtime: &mut actor::Runtime<'id, 'source, 'pils, 'slots, 'out, J, N>,
        owner: &mut Owner<'owner, E>,
        reservations: &mut Reservations,
        now: u64,
        observe: &mut impl FnMut(OwnerEvent<'owner>),
    ) -> Result<Option<Event<'id>>, Failure> {
        self.refresh_ranges(now);
        let prefetch = self.range.as_ref().is_some_and(|r| {
            r.hard.saturating_duration_since(Instant::now()) <= self.limits.prefetch
                || r.actual.span().last().saturating_sub(now)
                    <= u64::try_from(self.limits.prefetch.as_micros()).unwrap_or(u64::MAX)
        });
        let waiting = self
            .neighbours
            .iter()
            .filter_map(|n| n.intent.as_ref().map(|p| p.budget))
            .min_by_key(|b| b.hard);
        if self.range_intent.is_none()
            && self.spare.is_none()
            && ((self.range.is_none() && waiting.is_some()) || prefetch)
        {
            self.prepare_range(now, waiting)?;
        }
        let Some(intent) = &mut self.range_intent else {
            return Ok(None);
        };
        if intent.retiring || intent.request.is_some() {
            return Ok(None);
        }
        if !live(intent.budget, now) {
            intent.retiring = true;
            return Ok(Some(Event::Activity));
        }
        // The actual Owner performs a fresh clock/source/Engine check, registers
        // its real typed DV intent, then actually submits the original worker job.
        let bounds = Bounds {
            expires: intent.budget.until.as_micros(),
            hard: intent.budget.hard,
        };
        match owner.request_dv_range(reservations, &self.scope, bounds, observe) {
            Ok(request) => {
                intent.request = Some(request.clone());
                Ok(Some(Event::RangeRequested(request)))
            }
            Err(error) if busy(&error) => Ok(None),
            Err(error) => {
                // Original source/cleanup facts emitted by Owner.stop remain in
                // the caller's observer; this exact original error is preserved.
                self.close(runtime);
                Err(error)
            }
        }
    }
    fn plan<'source, 'slots, 'out, J, const N: usize>(
        &mut self,
        runtime: &mut actor::Runtime<'id, 'source, 'pils, 'slots, 'out, J, N>,
    ) -> Result<Option<Event<'id>>, Failure> {
        if self.plans.len() == self.limits.learns {
            return Ok(None);
        }
        let candidate = runtime
            .learn_ready_tokens()
            .find(|id| !self.plans.iter().any(|p| p.input == *id));
        let Some(input) = candidate else {
            return Ok(None);
        };
        let budget = runtime.input_budget(input)?;
        if Instant::now() >= budget.hard {
            runtime.cancel(input)?;
            return Ok(Some(Event::Activity));
        }
        let mut hops = [PeerId([0; 32]); dv::MAX_HOPS];
        let metadata = (|| -> Result<_, actor::Error> {
            let verified = runtime.learn(input)?;
            let packet = verified.packet();
            for (i, hop) in hops.iter_mut().enumerate().take(packet.hop_count()) {
                *hop = packet.hop(i)?.peer;
            }
            Ok((
                packet.initiator()?,
                verified.predecessor(),
                packet.hop_count(),
            ))
        })();
        let (initiator, previous, count) = match metadata {
            Ok(metadata) => metadata,
            Err(error @ actor::Error::TaskBudgetExpired) => {
                if let Err(cleanup) = runtime.cancel(input) {
                    self.remember(Box::new(cleanup));
                }
                return Ok(Some(Event::Failed {
                    probe: None,
                    error: Box::new(error),
                }));
            }
            Err(error) => return Err(Box::new(error)),
        };
        let mut selected = reserve(self.limits.fanout)?;
        let may_forward = initiator.0 != *self.actor.peer().as_bytes() && count < dv::MAX_HOPS;
        // Actual C returns only nontrivial probes to a directly reachable
        // initiator. Other fork selection is bounded round-robin local policy.
        if count > 0
            && may_forward
            && let Some(n) = runtime.neighbours().find(|n| n.peer() == initiator)
        {
            selected.push(n.clone());
        }
        let total = runtime.neighbours().count();
        if total > 0 && may_forward {
            let start = self.select % total;
            self.select = self.select.wrapping_add(1);
            for n in runtime
                .neighbours()
                .skip(start)
                .chain(runtime.neighbours().take(start))
            {
                if selected.len() == self.limits.fanout {
                    break;
                }
                if n.peer() == previous
                    || n.peer() == initiator
                    || hops[..count].contains(&n.peer())
                    || selected.iter().any(|s| s == n)
                {
                    continue;
                }
                selected.push(n.clone());
            }
        }
        let recipients = selected.len();
        self.plans.push(Plan {
            input,
            budget,
            selected,
            next: 0,
            retry: Instant::now(),
        });
        Ok(Some(Event::LearnPlanned { input, recipients }))
    }
    fn forward<'source, 'slots, 'out, J, const N: usize>(
        &mut self,
        runtime: &mut actor::Runtime<'id, 'source, 'pils, 'slots, 'out, J, N>,
        now: u64,
    ) -> Result<Option<Event<'id>>, Failure> {
        // No insertion occurs in this pass, and every removal returns. Thus
        // each original retained plan is considered at most once per call.
        for _ in 0..self.plans.len() {
            let i = self
                .plan_cursor
                .take(self.plans.len())
                .ok_or(Fault::NotReady)?;
            if !runtime
                .learn_ready_tokens()
                .any(|id| id == self.plans[i].input)
            {
                self.remove_plan(i);
                return Ok(Some(Event::Activity));
            }
            if !live(self.plans[i].budget, now) {
                let p = self.remove_plan(i);
                if let Err(error) = runtime.cancel(p.input)
                    && !matches!(error, actor::Error::Protocol(Fault::Stale))
                {
                    return Err(Box::new(error));
                }
                return Ok(Some(Event::Activity));
            }
            if self.plans[i].next == self.plans[i].selected.len() {
                let p = self.remove_plan(i);
                runtime.finish_learning(p.input)?;
                return Ok(Some(Event::Activity));
            }
            if self.forwards.len() == self.limits.forwards || Instant::now() < self.plans[i].retry {
                continue;
            }
            let next = self.plans[i].selected[self.plans[i].next].clone();
            let input = self.plans[i].input;
            if !runtime.neighbours().any(|n| n == &next) {
                self.plans[i].next += 1;
                return Ok(Some(Event::Activity));
            }
            // The reverse bit is the actual incoming direct queue's registered
            // fact. Runtime independently retains original input/next/hard.
            let reverse = runtime.input_neighbour(input)?.reverse_link();
            match runtime.forward_learn(input, &next, reverse) {
                Ok(output) => {
                    self.plans[i].next += 1;
                    self.forwards.push(Forward {
                        token: output,
                        next: next.clone(),
                        budget: self.plans[i].budget,
                        retiring: false,
                    });
                    return Ok(Some(Event::ForwardCreated {
                        input,
                        output,
                        next,
                    }));
                }
                Err(error) if actor_busy(&error) => {
                    self.plans[i].retry = Instant::now()
                        .checked_add(self.limits.retry)
                        .ok_or(Fault::Overflow)?;
                }
                Err(error) => {
                    let p = self.remove_plan(i);
                    if let Err(cleanup) = runtime.cancel(p.input) {
                        self.remember(Box::new(cleanup));
                    }
                    return Ok(Some(Event::Failed {
                        probe: None,
                        error: Box::new(error),
                    }));
                }
            }
        }
        Ok(None)
    }
    fn targets<'source, 'slots, 'out, J, const N: usize>(
        &mut self,
        runtime: &mut actor::Runtime<'id, 'source, 'pils, 'slots, 'out, J, N>,
        now: u64,
    ) -> Result<Option<Event<'id>>, Failure> {
        for i in 0..self.targets.len() {
            if !live(self.targets[i].budget, now) {
                let t = self.targets.swap_remove(i);
                return Ok(Some(Event::Inconclusive {
                    interest: t.interest,
                    target: t.peer,
                }));
            }
            if let Some(path) = runtime
                .send_path_with_policy(self.targets[i].peer, actor::SendPolicy::Bidirectional)?
            {
                let t = self.targets.swap_remove(i);
                return Ok(Some(Event::Discovered {
                    interest: t.interest,
                    target: t.peer,
                    // Preserve genuine Passive/Confirmed and original native
                    // hard. No closed probe cycle or measured RTT is invented.
                    route: path.life,
                }));
            }
        }
        Ok(None)
    }
    fn intents(&mut self, now: u64) -> Result<bool, Fault> {
        let native = Instant::now();
        let mut changed = false;
        for n in &mut self.neighbours {
            if n.probe.is_some() {
                continue;
            }
            if let Some(intent) = &n.intent {
                if !live(intent.budget, now) {
                    n.intent = None;
                    changed = true;
                }
                continue;
            }
            if native < n.due {
                continue;
            }
            let budget = after(now, self.limits.probe_lifetime)?;
            // The attempt's period is anchored NOW, before any capacity/worker
            // wait. Failed retries do not rebase either period or task budget.
            n.last = Some(native);
            n.due = native
                .checked_add(self.limits.interval)
                .ok_or(Fault::Overflow)?;
            n.intent = Some(ProbeIntent {
                budget,
                retry: native,
            });
            changed = true;
        }
        Ok(changed)
    }
    fn probe<'source, 'slots, 'out, J, E: Entropy, P: Entropy, const N: usize>(
        &mut self,
        runtime: &mut actor::Runtime<'id, 'source, 'pils, 'slots, 'out, J, N>,
        owner: &Owner<'owner, E>,
        entropy: &mut P,
        now: u64,
    ) -> Result<Option<Event<'id>>, Failure> {
        if self.probes.len() == self.limits.probes || self.neighbours.is_empty() {
            return Ok(None);
        }
        for _ in 0..self.neighbours.len() {
            let i = self.cursor % self.neighbours.len();
            self.cursor = self.cursor.wrapping_add(1);
            let Some(intent) = &self.neighbours[i].intent else {
                continue;
            };
            if Instant::now() < intent.retry {
                continue;
            }
            if !live(intent.budget, now) {
                self.neighbours[i].intent = None;
                return Ok(Some(Event::Activity));
            }
            let budget = intent.budget;
            let neighbour = self.neighbours[i].neighbour.clone();
            let Some(stamp) = self.claim_stamp(runtime, owner, budget)? else {
                return Ok(None);
            };
            // Private, genuine same-source/same-budget proof is consumed ONCE.
            // A scalar reaches Actor only after this actual range validation.
            let stamp = stamp.consume(runtime, owner, budget)?;
            match runtime.probe_with_budget(&neighbour, stamp, entropy, budget) {
                Ok(token) => {
                    let actual = runtime.probe_status(token)?.budget;
                    self.probes.push(ProbeRow {
                        token,
                        budget: actual,
                        reported: false,
                        retiring: false,
                    });
                    self.neighbours[i].probe = Some(token);
                    self.neighbours[i].intent = None;
                    return Ok(Some(Event::ProbeCreated { token, neighbour }));
                }
                Err(error) if actor_busy(&error) => {
                    // This unused scalar stays burnt. Backpressure can request
                    // another already-committed value, never a fake commit or
                    // deadline extension. All retry work is rate bounded.
                    if let Some(intent) = &mut self.neighbours[i].intent {
                        intent.retry = Instant::now()
                            .checked_add(self.limits.retry)
                            .ok_or(Fault::Overflow)?;
                    }
                }
                Err(error) => {
                    self.neighbours[i].intent = None;
                    return Ok(Some(Event::Failed {
                        probe: None,
                        error: Box::new(error),
                    }));
                }
            }
        }
        Ok(None)
    }
    /// Actual bounded poll actor: first native deadlines/receipts, then current
    /// source identity, actual UTC sample, LEARN fanout and real range/probe work.
    /// Owner remains sole shared-worker poller. Feed its owned DV events through
    /// observe_owner AFTER its callback returns; no callback may reenter Owner.
    pub fn poll<'source, 'slots, 'out, J, E: Entropy, P: Entropy, const N: usize>(
        &mut self,
        cx: &mut Context<'_>,
        runtime: &mut actor::Runtime<'id, 'source, 'pils, 'slots, 'out, J, N>,
        owner: &mut Owner<'owner, E>,
        reservations: &mut Reservations,
        entropy: &mut P,
        observe: &mut impl FnMut(OwnerEvent<'owner>),
    ) -> Poll<Result<Event<'id>, Failure>> {
        if !self.closed && !self.current(runtime, owner) {
            self.close(runtime);
            return self.ready_event(Event::ScopeRetired);
        }
        match self.native_guard(runtime, cx) {
            Ok(Some(event)) => return self.ready_event(event),
            Ok(None) => {}
            Err(error) => return Poll::Ready(Err(error)),
        }
        if self.closed {
            return Poll::Pending;
        }
        let now = match self.clock.sample() {
            Ok(sample) => sample.now.as_micros(),
            Err(original) => {
                // Shared clock failure is not allowed to leave either actual
                // native source waiting. Preserve the original and independently
                // close/cancel all resources before returning the failure.
                runtime.close();
                self.close(runtime);
                let mut cleanup = owner.stop(observe);
                if let Some(error) = self.cleanup.take() {
                    cleanup.push(error)
                }
                return Poll::Ready(Err(Box::new(Failures {
                    original: Some(Box::new(original)),
                    cleanup,
                })));
            }
        };
        if now >= self.actor.expiration().as_micros()
            || now >= self.scope.identity().expiration().as_micros()
        {
            self.close(runtime);
            return self.ready_event(Event::ScopeRetired);
        }
        if let Some(intent) = &mut self.range_intent
            && !live(intent.budget, now)
        {
            intent.retiring = true;
            if intent.request.is_none() {
                self.range_intent = None;
                return self.ready_event(Event::RangeNotAdmitted);
            }
        }
        // Canonical correction can retire an original task; native retry/hard
        // targets were already checked above and can never be postponed by it.
        for i in 0..self.probes.len() {
            if !self.probes[i].retiring && !live(self.probes[i].budget, now) {
                let token = self.probes[i].token;
                if let Err(error) = runtime.retire_probe(token) {
                    return Poll::Ready(Err(Box::new(error)));
                }
                self.probes[i].retiring = true;
                return self.ready_event(Event::Activity);
            }
        }
        match self.sync(runtime) {
            Ok(true) => return self.ready_event(Event::Activity),
            Ok(false) => {}
            Err(error) => return Poll::Ready(Err(error)),
        }
        match self.targets(runtime, now) {
            Ok(Some(event)) => return self.ready_event(event),
            Ok(None) => {}
            Err(error) => return Poll::Ready(Err(error)),
        }
        match self.intents(now) {
            Ok(true) => self.scan_changed(),
            Ok(false) => {}
            Err(error) => return Poll::Ready(Err(error.into())),
        }
        // Rotate classes rather than letting a continuously busy LEARN stream
        // starve real pending probes, or letting probes starve forwarding.
        for _ in 0..self.limits.quantum {
            let class = self.class % SCHEDULE_CLASSES;
            self.class = self.class.wrapping_add(1);
            let step = match class {
                0 => self.plan(runtime),
                1 => self.forward(runtime, now),
                2 => self.ranges(runtime, owner, reservations, now, observe),
                _ => self.probe(runtime, owner, entropy, now),
            };
            match step {
                Ok(Some(event)) => {
                    return self.ready_event(event);
                }
                Ok(None) => {
                    if self.idle_pass.idle() {
                        break;
                    }
                }
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
        // Source admission may have created a shorter probe/range target than
        // the guard's old fallback without emitting an Event. Register only an
        // actually earlier target before returning Pending.
        if let Err(error) = self.arm(cx, true) {
            return Poll::Ready(Err(error.into()));
        }
        if !self.idle_pass.complete() {
            // A small quantum has not yet polled every class/wake source.
            // Continue that finite pass; a complete idle pass never self-wakes.
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
}

impl Drop for Scheduler<'_, '_, '_> {
    fn drop(&mut self) {
        // Revokes only not-yet-admitted private scalar claims. Actual native
        // outputs/worker debt still require explicit close and their real owners.
        self.alive.set(false);
    }
}

#[cfg(test)]
mod tests;
