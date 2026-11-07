//! Bounded observational availability accounting for one immutable search target.
//!
//! Rank is the official client's `2 * successes - trials`, and certainty is its
//! completed trial count. A deadline after a real SEARCH is an inconclusive
//! trial, never an absence proof. This owner has no automatic scheduler: leaf
//! choice, retry policy and concurrency across result owners belong to Session.
//! Native elapsed intervals are accepted source-clock samples, not the C
//! client's private active/inactive queue-time accounting.

use crate::network::{self, DownloadOptions, probe};
use gnunet_fs::{Content, content::Layout};
use gnunet_types::{AbsoluteTime, Duration, Error};
use std::{
    ops::Range,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);

/// Explicit lifetime bounds for one retained result's observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// All admitted runs, including cancellations and setup refusals.
    pub attempts: u32,
    /// Authenticated successes plus genuinely started deadline observations.
    /// At most i32::MAX, so the official rank expression cannot overflow.
    pub trials: u32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            attempts: 32,
            trials: 8,
        }
    }
}

/// Independent error counters. They never silently become negative trials.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Errors {
    /// Native configuration or invalid operation setup refusals.
    pub setup: u32,
    /// Explicit native work, memory or arithmetic bounds.
    pub resource: u32,
    /// Actual OS/socket losses, including a retained loss before deadline.
    pub transport: u32,
    /// Content/query/tag authentication refusals.
    pub authentication: u32,
    /// Other malformed or refused official protocol semantics.
    pub protocol: u32,
    /// Refused monotonic clock samples or validity uncertainty.
    pub clock: u32,
    /// Other original local adapter failures.
    pub local: u32,
    /// Other native backend causes retained by the owning run report.
    pub other: u32,
}

/// Current bounded observations. These do not promise future reachability.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Summary {
    pub(crate) attempts: u32,
    pub(crate) successes: u32,
    pub(crate) trials: u32,
    pub(crate) cancelled: u32,
    /// Deadlines before a complete SEARCH was written; excluded from trials.
    pub(crate) setup_deadlines: u32,
    pub(crate) errors: Errors,
    /// Sum of accepted logical source-clock intervals. On interruption
    /// this is a measured prefix; it is not a claimed exact retirement time.
    pub(crate) source_elapsed: Duration,
    pub(crate) queries_written: u64,
    pub(crate) active: bool,
}
impl Summary {
    /// All runs admitted by this result owner.
    #[must_use]
    pub const fn attempts(self) -> u32 {
        self.attempts
    }
    /// Actual root-authenticated native range observations.
    #[must_use]
    pub const fn successes(self) -> u32 {
        self.successes
    }
    /// Authenticated successes plus started inconclusive deadlines.
    #[must_use]
    pub const fn trials(self) -> u32 {
        self.trials
    }
    /// Caller cancellations and explicitly abandoned admissions.
    #[must_use]
    pub const fn cancelled(self) -> u32 {
        self.cancelled
    }
    /// Deadlines before any complete native SEARCH was written.
    #[must_use]
    pub const fn setup_deadlines(self) -> u32 {
        self.setup_deadlines
    }
    /// Independent original error classifications.
    #[must_use]
    pub const fn errors(self) -> Errors {
        self.errors
    }
    /// Sum of accepted logical source-clock intervals, not native elapsed time.
    #[must_use]
    pub const fn source_elapsed(self) -> Duration {
        self.source_elapsed
    }
    /// Completely written native SEARCH frames across settled runs.
    #[must_use]
    pub const fn queries_written(self) -> u64 {
        self.queries_written
    }
    /// Whether this result owner has one outstanding admission.
    #[must_use]
    pub const fn active(self) -> bool {
        self.active
    }
    /// Official availability rank, over the completed observational trials.
    #[must_use]
    pub fn rank(self) -> i32 {
        self.successes as i32 - (self.trials - self.successes) as i32
    }
    /// Official certainty: the number of completed observational trials.
    #[must_use]
    pub const fn certainty(self) -> u32 {
        self.trials
    }
}

/// Scope of this one result/revision's observation stream. Session additionally
/// binds its private result owner, source query revision and canonical URI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Target {
    content: Content,
    peer: [u8; 32],
    anonymity: u32,
    local_only: bool,
}
impl Target {
    pub(crate) const fn new(content: Content, policy: DownloadOptions) -> Self {
        Self {
            content,
            peer: policy.target,
            anonymity: policy.anonymity,
            local_only: policy.local_only,
        }
    }
    fn matches(self, content: Content, policy: DownloadOptions) -> bool {
        self == Self::new(content, policy)
    }
}

/// Single-use owner-scoped attempt; diagnostic indexes are not commit rights.
/// Root's Session wrapper moves this through begin/run/settle without holding a
/// mutable Session borrow throughout native I/O. It is deliberately not Clone.
#[derive(Debug)]
pub(crate) struct Attempt {
    owner: u64,
    serial: u32,
    target: Target,
    leaf: u64,
    range: Range<u64>,
    admitted: AbsoluteTime,
    deadline: AbsoluteTime,
}
impl Attempt {
    pub(crate) const fn content(&self) -> Content {
        self.target.content
    }
    pub(crate) const fn leaf(&self) -> u64 {
        self.leaf
    }
}

/// Fixed-size, allocation-free accounting owner embedded in one result record.
/// The private owner stamp prevents settling a same-index foreign Book ticket.
/// Mutators remain crate-private: only Session's private native run receipt may
/// causally bind an actual observation to an attempt, rather than time alone.
#[derive(Debug)]
pub(crate) struct Book {
    owner: u64,
    target: Target,
    limits: Limits,
    summary: Summary,
    active: Option<u32>,
    last_checked: Option<AbsoluteTime>,
}
impl Book {
    pub(crate) fn new(target: Target, limits: Limits) -> Result<Self, Error> {
        if limits.attempts == 0 || limits.trials == 0 || limits.trials > i32::MAX as u32 {
            return Err(Error::InvalidInput);
        }
        let owner = NEXT_OWNER
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| Error::Overflow)?;
        Ok(Self {
            owner,
            target,
            limits,
            summary: Summary::default(),
            active: None,
            last_checked: None,
        })
    }
    pub(crate) const fn summary(&self) -> Summary {
        self.summary
    }
    pub(crate) fn begin(
        &mut self,
        leaf: u64,
        policy: DownloadOptions,
        now: AbsoluteTime,
    ) -> Result<Attempt, Error> {
        if self.active.is_some() {
            return Err(Error::WouldBlock);
        }
        if self.summary.attempts >= self.limits.attempts
            || self.summary.trials >= self.limits.trials
        {
            return Err(Error::Capacity);
        }
        if !self.target.matches(self.target.content, policy) || policy.deadline <= now {
            return Err(Error::InvalidInput);
        }
        if self.last_checked.is_some_and(|previous| now < previous) {
            return Err(Error::TimeUncertain);
        }
        // Layout includes the partial tail and the authenticated empty leaf.
        // Automatic C-client empty/one-block retry heuristics are not wire rules.
        let range = Layout::new(self.target.content.size).leaf(leaf)?.range();
        let serial = self
            .summary
            .attempts
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        self.summary.attempts = serial;
        self.summary.active = true;
        self.active = Some(serial);
        Ok(Attempt {
            owner: self.owner,
            serial,
            target: self.target,
            leaf,
            range,
            admitted: now,
            deadline: policy.deadline,
        })
    }
    fn check(&self, attempt: &Attempt) -> Result<(), Error> {
        if attempt.owner != self.owner
            || attempt.target != self.target
            || self.active != Some(attempt.serial)
        {
            return Err(Error::StaleGeneration);
        }
        Ok(())
    }
    fn policy(
        &self,
        attempt: &Attempt,
        content: Content,
        leaf: u64,
        policy: DownloadOptions,
    ) -> Result<(), Error> {
        self.check(attempt)?;
        if !attempt.target.matches(content, policy)
            || leaf != attempt.leaf
            || policy.deadline != attempt.deadline
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    fn interval(
        &self,
        attempt: &Attempt,
        start: Option<AbsoluteTime>,
        end: Option<AbsoluteTime>,
    ) -> Result<Option<Duration>, Error> {
        match (start, end) {
            (Some(start), Some(end)) => {
                if start < attempt.admitted
                    || self.last_checked.is_some_and(|previous| start < previous)
                {
                    return Err(Error::TimeUncertain);
                }
                Ok(Some(end.duration_since(start)?))
            }
            (None, None) => Ok(None),
            _ => Err(Error::TimeUncertain),
        }
    }
    /// Account for a genuine native proof borrowed from Session's consumed
    /// private ProbeCompletion. The private wrapper binds this exact Attempt
    /// to its actual run and prevents caller replay after successful settlement.
    pub(crate) fn settle_success(
        &mut self,
        attempt: &Attempt,
        observed: &probe::Observed,
    ) -> Result<Summary, Error> {
        self.policy(
            attempt,
            observed.verified().content(),
            observed.leaf(),
            observed.policy(),
        )?;
        if observed.range() != attempt.range
            || observed.queries_written() == 0
            || !observed.retired()
            || observed.finished() >= attempt.deadline
        {
            return Err(Error::Conflict);
        }
        let elapsed =
            self.interval(attempt, Some(observed.started()), Some(observed.finished()))?;
        self.commit(
            attempt,
            Terminal::Success,
            elapsed,
            Some(observed.finished()),
            observed.queries_written(),
        )
    }
    /// Account for the original native failure after matching the selected
    /// target. Session consumes the private completion once, then may return
    /// the unchanged full native failure, including its cause and raw reply.
    pub(crate) fn settle_failure(
        &mut self,
        attempt: &Attempt,
        failure: &probe::Failure,
    ) -> Result<Summary, Error> {
        self.policy(attempt, failure.content(), failure.leaf(), failure.policy())?;
        if failure
            .range()
            .as_ref()
            .is_some_and(|range| *range != attempt.range)
            || (failure.started().is_some() && !failure.retired())
            || (failure.queries_written() > 0
                && (failure.started().is_none() || failure.range().is_none()))
        {
            return Err(Error::Conflict);
        }
        let elapsed = self.interval(attempt, failure.started(), failure.last_checked())?;
        let terminal = Terminal::from_failure(failure.cause(), failure.queries_written());
        self.commit(
            attempt,
            terminal,
            elapsed,
            failure.last_checked(),
            failure.queries_written(),
        )
    }
    /// Explicitly abandon an unrun/dropped run ticket. This cancels only its
    /// accounting slot; Session must first stop/retire any actual native owner.
    /// No caller-supplied timestamp is reported as native observation duration.
    pub(crate) fn cancel(&mut self, attempt: &Attempt) -> Result<Summary, Error> {
        self.commit(attempt, Terminal::Cancelled, None, None, 0)
    }
    /// Forget this owner's current local accounting slot after its public
    /// ticket/future was dropped or detached. This neither closes a socket nor
    /// proves physical cancellation. A still-running old native completion is
    /// stale after this call and cannot update a later admitted attempt.
    pub(crate) fn abandon(&mut self) -> Result<Summary, Error> {
        if self.active.is_none() {
            return Err(Error::NotReady);
        }
        let mut next = self.summary;
        next.cancelled = next.cancelled.checked_add(1).ok_or(Error::Overflow)?;
        next.active = false;
        self.summary = next;
        self.active = None;
        Ok(next)
    }
    fn commit(
        &mut self,
        attempt: &Attempt,
        terminal: Terminal,
        elapsed: Option<Duration>,
        last_checked: Option<AbsoluteTime>,
        queries_written: u64,
    ) -> Result<Summary, Error> {
        self.check(attempt)?;
        let mut next = self.summary;
        let add = |value: &mut u32| -> Result<(), Error> {
            *value = value.checked_add(1).ok_or(Error::Overflow)?;
            Ok(())
        };
        match terminal {
            Terminal::Success => {
                add(&mut next.successes)?;
                add(&mut next.trials)?;
            }
            Terminal::Inconclusive { transport_loss } => {
                add(&mut next.trials)?;
                if transport_loss {
                    add(&mut next.errors.transport)?;
                }
            }
            Terminal::Cancelled => add(&mut next.cancelled)?,
            Terminal::SetupDeadline { transport_loss } => {
                add(&mut next.setup_deadlines)?;
                if transport_loss {
                    add(&mut next.errors.transport)?;
                }
            }
            Terminal::Error(kind) => add(match kind {
                Kind::Setup => &mut next.errors.setup,
                Kind::Resource => &mut next.errors.resource,
                Kind::Transport => &mut next.errors.transport,
                Kind::Authentication => &mut next.errors.authentication,
                Kind::Protocol => &mut next.errors.protocol,
                Kind::Clock => &mut next.errors.clock,
                Kind::Local => &mut next.errors.local,
                #[cfg(feature = "network")]
                Kind::Other => &mut next.errors.other,
            })?,
        }
        if next.trials > self.limits.trials || next.successes > next.trials {
            return Err(Error::Capacity);
        }
        if let Some(elapsed) = elapsed {
            next.source_elapsed = next.source_elapsed.checked_add(elapsed)?;
        }
        next.queries_written = next
            .queries_written
            .checked_add(queries_written)
            .ok_or(Error::Overflow)?;
        next.active = false;
        self.summary = next;
        self.active = None;
        if let Some(now) = last_checked {
            self.last_checked = Some(now);
        }
        Ok(next)
    }
}

#[derive(Clone, Copy, Debug)]
enum Kind {
    Setup,
    Resource,
    Transport,
    Authentication,
    Protocol,
    Clock,
    Local,
    #[cfg(feature = "network")]
    Other,
}
#[derive(Clone, Copy, Debug)]
enum Terminal {
    Success,
    Inconclusive { transport_loss: bool },
    SetupDeadline { transport_loss: bool },
    Cancelled,
    Error(Kind),
}
impl Terminal {
    fn from_failure(error: &network::Error, written: u64) -> Self {
        match error {
            network::Error::Deadline { first_io } if written > 0 => Self::Inconclusive {
                transport_loss: first_io.is_some(),
            },
            network::Error::Deadline { first_io } => Self::SetupDeadline {
                transport_loss: first_io.is_some(),
            },
            network::Error::Cancelled(_) | network::Error::Local(crate::Error::Cancelled) => {
                Self::Cancelled
            }
            network::Error::Protocol(error)
            | network::Error::Local(crate::Error::Protocol(error))
            | network::Error::Client(gnunet_client_host::ConnectError::Protocol(error)) => {
                Self::Error(match error {
                    Error::Authentication => Kind::Authentication,
                    Error::TimeUncertain => Kind::Clock,
                    Error::Capacity | Error::Overflow | Error::TooLarge => Kind::Resource,
                    Error::InvalidInput | Error::Unsupported | Error::NotReady => Kind::Setup,
                    _ => Kind::Protocol,
                })
            }
            network::Error::Client(gnunet_client_host::ConnectError::Configuration(_)) => {
                Self::Error(Kind::Setup)
            }
            network::Error::Client(gnunet_client_host::ConnectError::Io(_))
            | network::Error::Local(crate::Error::Io(_)) => Self::Error(Kind::Transport),
            network::Error::Local(crate::Error::Limit) => Self::Error(Kind::Resource),
            network::Error::Local(crate::Error::Corrupt) => Self::Error(Kind::Authentication),
            network::Error::Local(_) => Self::Error(Kind::Local),
            #[cfg(feature = "network")]
            network::Error::Store(_) => Self::Error(Kind::Other),
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "State-model tests assert checked accounting while propagating fallible setup"
)]
mod tests {
    use super::*;

    fn fixture() -> Result<(Book, DownloadOptions), Error> {
        let content = Content {
            key: [1; 64],
            query: [2; 64],
            size: 32769,
        };
        let policy = DownloadOptions::new(AbsoluteTime::from_micros(100));
        Ok((
            Book::new(
                Target::new(content, policy),
                Limits {
                    attempts: 6,
                    trials: 2,
                },
            )?,
            policy,
        ))
    }

    /// State-model check only: fixture terminal values do not stand in for a
    /// native/C observation. The public path still requires private Observed.
    #[test]
    fn owner_and_tail_ticket_cannot_settle_a_foreign_or_stale_book() -> Result<(), Error> {
        let (mut a, policy) = fixture()?;
        let (mut b, _) = fixture()?;
        let attempt = a.begin(1, policy, AbsoluteTime::from_micros(1))?;
        assert_eq!(attempt.range, 32768..32769);
        let before = b.summary();
        assert_eq!(b.cancel(&attempt), Err(Error::StaleGeneration));
        assert_eq!(b.summary(), before);
        assert_eq!(a.cancel(&attempt)?.cancelled, 1);
        assert_eq!(a.cancel(&attempt), Err(Error::StaleGeneration));
        assert_eq!(a.summary().trials, 0);
        assert_eq!(a.abandon(), Err(Error::NotReady));
        let detached = a.begin(0, policy, AbsoluteTime::from_micros(2))?;
        assert_eq!(a.abandon()?.cancelled, 2);
        assert_eq!(a.cancel(&detached), Err(Error::StaleGeneration));
        Ok(())
    }

    #[test]
    fn measured_trials_errors_and_cancel_have_distinct_bounded_effects() -> Result<(), Error> {
        let (mut book, policy) = fixture()?;
        let attempt = book.begin(0, policy, AbsoluteTime::from_micros(1))?;
        let out = book.commit(
            &attempt,
            Terminal::Success,
            Some(Duration(3)),
            Some(AbsoluteTime::from_micros(4)),
            2,
        )?;
        assert_eq!(
            (out.rank(), out.certainty(), out.source_elapsed),
            (1, 1, Duration(3))
        );
        let attempt = book.begin(0, policy, AbsoluteTime::from_micros(4))?;
        let out = book.commit(
            &attempt,
            Terminal::from_failure(&network::Error::Protocol(Error::Authentication), 1),
            Some(Duration(1)),
            Some(AbsoluteTime::from_micros(5)),
            1,
        )?;
        assert_eq!(
            (out.rank(), out.trials, out.errors.authentication),
            (1, 1, 1)
        );
        let attempt = book.begin(1, policy, AbsoluteTime::from_micros(5))?;
        let out = book.commit(
            &attempt,
            Terminal::from_failure(
                &network::Error::Deadline {
                    first_io: Some(std::io::Error::other("model transport loss")),
                },
                1,
            ),
            Some(Duration(7)),
            Some(AbsoluteTime::from_micros(12)),
            1,
        )?;
        assert_eq!(
            (
                out.rank(),
                out.certainty(),
                out.source_elapsed,
                out.errors.transport
            ),
            (0, 2, Duration(11), 1)
        );
        assert!(matches!(
            book.begin(0, policy, AbsoluteTime::from_micros(12)),
            Err(Error::Capacity)
        ));
        assert!(!out.active);
        Ok(())
    }
}
