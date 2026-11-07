//! Logical GNUNET_TIME offset and source SPEEDUP state; never adjusts OS time.
//! Scheduler tickets use absolute logical time. A host must also wake/re-evaluate
//! its existing deadlines when offset changes; Tokio Instant alone cannot do it.
use gnunet_types::{AbsoluteTime, Error};
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);
/// One exact pending speedup task, scoped to its originating owner/generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ticket {
    owner: u64,
    generation: u64,
    at: AbsoluteTime,
}
impl Ticket {
    /// Original logical absolute deadline; initial ready task is zero.
    #[must_use]
    pub fn at(self) -> AbsoluteTime {
        self.at
    }
    /// SPEEDUP tasks and their descendants always inherit non-lifeness.
    #[must_use]
    pub fn lifeness(self) -> bool {
        false
    }
}
/// Source initial task scheduling result, including deliberately disabled state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Start {
    /// Zero interval or zero delta disables scheduling.
    Disabled,
    /// Queue this task as ready, without granting program lifeness.
    Ready(Ticket),
}
/// Actual tick effects; re-evaluate every scheduler deadline after installing offset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Advanced {
    /// New process logical offset, replacing any initial testing skew.
    pub offset: i64,
    /// Subsequent absolute task, retaining non-lifeness.
    pub next: Ticket,
}
/// Source speedup globals retained across start/stop, with explicit live ownership.
pub struct Clock {
    owner: u64,
    generation: u64,
    offset: i64,
    current_speedup: i64,
    interval: u64,
    delta: u64,
    pending: Option<Ticket>,
}
impl Clock {
    /// New independent process-clock context. No wall-clock, entropy or scheduler IO.
    pub fn new() -> Result<Self, Error> {
        let owner = NEXT_OWNER
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
            .map_err(|_| Error::Overflow)?;
        Ok(Self {
            owner,
            generation: 0,
            offset: 0,
            current_speedup: 0,
            interval: 0,
            delta: 0,
            pending: None,
        })
    }
    /// Source get_offset, including the preserved post-stop value.
    #[must_use]
    pub fn offset(&self) -> i64 {
        self.offset
    }
    /// Source set_offset, including signed testing/time-travel offsets.
    pub fn set_offset(&mut self, value: i64) {
        self.offset = value;
    }
    /// Unsigned GNUNET_TIME absolute arithmetic, distinct from display timeval adjustment.
    #[must_use]
    pub fn absolute(&self, wall_us: u64) -> AbsoluteTime {
        AbsoluteTime::from_micros(wall_us.wrapping_add_signed(self.offset))
    }
    /// Apply testing.skew_offset - testing.skew_variance only when both parse.
    /// Failure leaves the existing process offset unchanged.
    pub fn testing_skew(&mut self, cfg: &gnunet_config::Configuration) {
        self.testing_skew_observed(cfg, None);
    }
    /// Source short-circuit testing lookups through a local diagnostic route.
    pub fn testing_skew_observed(
        &mut self,
        cfg: &gnunet_config::Configuration,
        observer: Option<gnunet_config::diagnostic::BorrowedObserver<'_>>,
    ) {
        if let Ok(offset) = cfg.get_number_observed(b"testing", b"skew_offset", observer)
            && let Ok(variance) = cfg.get_number_observed(b"testing", b"skew_variance", observer)
        {
            self.offset = offset.wrapping_sub(variance) as i64;
        }
    }
    /// Read source interval then delta. On a missing delta, the already-read interval
    /// remains changed, exactly as the source globals; no task is fabricated.
    pub fn start(&mut self, cfg: &gnunet_config::Configuration) -> Result<Start, Error> {
        self.start_observed(cfg, None)
    }
    /// Prepare source SPEEDUP using caller-observed CONFIG reads. Notice delivery
    /// belongs to the caller after any enclosing state lock is released.
    pub fn start_observed(
        &mut self,
        cfg: &gnunet_config::Configuration,
        observer: Option<gnunet_config::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<Start, Error> {
        let attempt = self.start_generation()?;
        let interval = cfg
            .get_time_observed(b"testing", b"SPEEDUP_INTERVAL", observer)
            .map_err(|_| Error::InvalidInput);
        let delta = if interval.is_ok() {
            Some(
                cfg.get_time_observed(b"testing", b"SPEEDUP_DELTA", observer)
                    .map_err(|_| Error::InvalidInput),
            )
        } else {
            None
        };
        self.commit_start(attempt, interval, delta)
    }
    pub(crate) fn start_generation(&mut self) -> Result<u64, Error> {
        if self.pending.is_some() {
            return Err(Error::Conflict);
        }
        self.generation = self.generation.checked_add(1).ok_or(Error::Overflow)?;
        Ok(self.generation)
    }
    pub(crate) fn commit_start(
        &mut self,
        attempt: u64,
        interval: Result<u64, Error>,
        delta: Option<Result<u64, Error>>,
    ) -> Result<Start, Error> {
        if self.generation != attempt || self.pending.is_some() {
            return Err(Error::StaleGeneration);
        }
        self.interval = interval?;
        self.delta = delta.ok_or(Error::Conflict)??;
        if self.interval == 0 || self.delta == 0 {
            return Ok(Start::Disabled);
        }
        let ticket = self.ticket(AbsoluteTime::UNIX_EPOCH)?;
        self.pending = Some(ticket);
        Ok(Start::Ready(ticket))
    }
    fn ticket(&mut self, at: AbsoluteTime) -> Result<Ticket, Error> {
        let generation = self.generation.checked_add(1).ok_or(Error::Overflow)?;
        self.generation = generation;
        Ok(Ticket {
            owner: self.owner,
            generation,
            at,
        })
    }
    /// Fire an actually admitted due task. Old/foreign tickets cannot mutate a new
    /// owner or cancel its replacement. Arithmetic follows the native C unsigned
    /// addition followed by two's-complement signed assignment.
    pub fn tick(&mut self, ticket: Ticket, wall_us: u64) -> Result<Advanced, Error> {
        let plan = self.plan_tick(ticket, wall_us)?;
        Ok(self.commit_tick(plan))
    }
    pub(crate) fn plan_tick(&self, ticket: Ticket, wall_us: u64) -> Result<TickPlan, Error> {
        if self.pending != Some(ticket) {
            return Err(Error::StaleGeneration);
        }
        let now = self.absolute(wall_us);
        if ticket.at.is_never() || (ticket.at != AbsoluteTime::UNIX_EPOCH && now < ticket.at) {
            return Err(Error::WouldBlock);
        }
        let generation = self.generation.checked_add(1).ok_or(Error::Overflow)?;
        let offset = self.current_speedup.wrapping_add(self.delta as i64);
        let after = wall_us.wrapping_add_signed(offset);
        let at = if self.interval == u64::MAX {
            AbsoluteTime::NEVER
        } else {
            AbsoluteTime::from_micros(after.saturating_add(self.interval))
        };
        Ok(TickPlan {
            offset,
            next: Ticket {
                owner: self.owner,
                generation,
                at,
            },
        })
    }
    pub(crate) fn commit_tick(&mut self, plan: TickPlan) -> Advanced {
        self.generation = plan.next.generation;
        self.current_speedup = plan.offset;
        self.offset = plan.offset;
        self.pending = Some(plan.next);
        Advanced {
            offset: plan.offset,
            next: plan.next,
        }
    }
    /// Cancel the current original task, returning its exact ticket. Offset and the
    /// source static accumulation remain unchanged. No callback is synthesized.
    pub fn stop(&mut self) -> Option<Ticket> {
        self.pending.take()
    }
    /// Source stop logs its DEBUG notice whenever both last-read values are nonzero,
    /// even if no task is live after a failed/repeated startup.
    #[must_use]
    pub fn stop_notice(&self) -> bool {
        self.interval != 0 && self.delta != 0
    }
    /// Current task ownership, never an actual OS wait or completion assertion.
    #[must_use]
    pub fn pending(&self) -> Option<Ticket> {
        self.pending
    }
    /// Source configuration globals, retained after stop and partial failed start.
    #[must_use]
    pub fn settings(&self) -> (u64, u64) {
        (self.interval, self.delta)
    }
}

pub(crate) struct TickPlan {
    pub(crate) offset: i64,
    next: Ticket,
}
