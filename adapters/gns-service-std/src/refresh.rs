//! Independent, bounded refresh owners. No foreground query/effect capability is
//! retained and no background failure is delivered as a caller lookup result.
use crate::{Bounds, Close, Operation, Provider, Value};
use gnunet_gns::{CacheRefresh, EffectKind};
use gnunet_types::{AbsoluteTime, Duration, Error};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::time::{Instant, Sleep};

/// Explicit background resource policy, independent of foreground admission.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Original active/queued/retiring refresh jobs; zero really disables refresh.
    pub jobs: usize,
    /// Aggregate actual Vec capacity of selected encrypted candidates. Label
    /// metadata additionally has at most jobs original bounded names plus one hint.
    pub bytes: usize,
    /// One new original GET-through-cache bound, never renewed across phases.
    pub timeout: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            jobs: 8,
            bytes: 512 * 1024,
            timeout: Duration(30_000_000),
        }
    }
}
/// Diagnostic coordinate local to one manager; no receipt/cancellation API
/// accepts it and it contains no authority from a completed foreground query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Id(u64);
/// Actual operation family of the independently owned refresh.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    /// Original readonly DHT GET.
    Remote,
    /// One original NAMECACHE insertion.
    Cache,
}
/// Exactly one owned observation, consumed by the process diagnostics.
#[derive(Debug)]
pub enum Event<E, R> {
    /// Optional intent became a distinct bounded owner, without native admission.
    Queued {
        /// Independent refresh coordinate, carrying no foreground authority.
        id: Id,
    },
    /// New original native operation was admitted; no write/ACK is inferred.
    Started {
        /// Independent original refresh coordinate.
        id: Id,
        /// Actual original native operation family.
        stage: Stage,
        /// The original budget elapsed during admission; retirement follows.
        expired: bool,
    },
    /// A candidate was not a verified improvement; its same GET remains bounded.
    Ignored {
        /// Independent original refresh coordinate.
        id: Id,
        /// Validation/refusal cause, or None for no fresher valid improvement.
        reason: Option<Error>,
    },
    /// One independently verified improvement was selected, not stored.
    Selected {
        /// Independent original refresh coordinate.
        id: Id,
        /// Authenticated absolute expiration of the selected original block.
        expiration: u64,
    },
    /// An actual callback arrived beyond the original refresh bound. Its facts
    /// remain owned without authorizing a cache insertion or caller answer.
    LateObservation {
        /// Independent original refresh coordinate.
        id: Id,
        /// Actual original native operation family.
        stage: Stage,
        /// Actual original callback, separate from any foreground result.
        value: Result<Value, E>,
    },
    /// Actual NAMECACHE status. Only1 means its local cache operation succeeded.
    Stored {
        /// Independent original refresh coordinate.
        id: Id,
        /// Unchanged original service status, never remote DHT acceptance.
        status: i32,
    },
    /// Actual original operation failed; this never fails a caller query.
    Failed {
        /// Independent original refresh coordinate.
        id: Id,
        /// Actual original native operation family.
        stage: Stage,
        /// Original provider error without replacing its native cause.
        error: E,
        /// The original budget elapsed while observing this failure.
        expired: bool,
    },
    /// Actual native-only guard failure, preserving the original error.
    GuardFailed {
        /// Independent original refresh coordinate.
        id: Id,
        /// Actual original native operation family.
        stage: Stage,
        /// Original guard cause; retirement remains separately owned.
        error: E,
    },
    /// Local validation, policy or resource refusal, independent of query results.
    Refused {
        /// Existing refresh coordinate, absent if admission itself was refused.
        id: Option<Id>,
        /// Original checked policy, validation or capacity cause.
        reason: Error,
    },
    /// Original whole-refresh bound elapsed; retirement is still owned.
    Expired {
        /// Independent original refresh coordinate.
        id: Id,
    },
    /// Real original close made progress.
    Retiring {
        /// Independent original refresh coordinate.
        id: Id,
        /// Actual original native operation family.
        stage: Stage,
    },
    /// Real original retirement failure, without a fabricated Closed report.
    RetireFailed {
        /// Independent original refresh coordinate.
        id: Id,
        /// Actual original native operation family.
        stage: Stage,
        /// Independent close cause; the original operation is still retained.
        error: E,
    },
    /// Original operation really retired, preserving its native report.
    Retired {
        /// Independent original refresh coordinate.
        id: Id,
        /// Actual original native operation family.
        stage: Stage,
        /// Actual original physical/protocol retirement facts.
        report: R,
    },
    /// No operation/selected candidate remains owned by this refresh.
    Finished {
        /// Independent original refresh coordinate.
        id: Id,
    },
}
/// Bounded aggregate observations, never a remote-replication/performance claim.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    /// Independently admitted original refresh intents.
    pub admitted: u64,
    /// Hints coalesced into an existing original key owner.
    pub duplicates: u64,
    /// Intent admission capacity/counter refusals; optional pure hint drops
    /// and later candidate/resource observations are separate from this count.
    pub refused: u64,
    /// Actual candidate validations/age comparisons.
    pub candidates: u64,
    /// Actual strictly-fresher authenticated selections.
    pub selected: u64,
    /// Actual status1 value callbacks, not remote publications. Outcomes seen
    /// only during retirement remain in their original typed native reports.
    pub stored: u64,
}
struct Task<O: Operation> {
    operation: O,
    stage: Stage,
    closing: bool,
    error: Option<O::Error>,
}
struct Row<O: Operation> {
    id: Id,
    intent: CacheRefresh,
    hard: Instant,
    bounds: Option<Bounds>,
    task: Option<Task<O>>,
    pending: Option<(Vec<u8>, u64)>,
    cache: bool,
    done: bool,
}
impl<O: Operation> Row<O> {
    fn stop(&mut self) {
        self.done = true;
        self.pending = None;
        self.retire();
    }
    fn retire(&mut self) {
        if let Some(task) = &mut self.task
            && !task.closing
        {
            task.closing = true;
            task.error = task.operation.begin_close();
            if task.error.is_some() {
                self.done = true;
                self.pending = None;
            }
        }
    }
}
pub(crate) struct Pool<O: Operation> {
    rows: Vec<Row<O>>,
    limits: Limits,
    core: gnunet_gns::Limits,
    serial: u64,
    cursor: usize,
    closing: bool,
    stats: Stats,
    alarm: Option<Pin<Box<Sleep>>>,
    alarm_at: Option<Instant>,
}
impl<O: Operation> Pool<O> {
    pub(crate) fn new(limits: Limits, core: gnunet_gns::Limits) -> Result<Self, Error> {
        if limits.jobs > 64
            || limits.jobs > 0
                && (limits.timeout.0 == 0
                    || limits.timeout.0 == u64::MAX
                    || limits.bytes == 0
                    || Instant::now()
                        .checked_add(std::time::Duration::from_micros(limits.timeout.0))
                        .is_none())
        {
            return Err(Error::InvalidInput);
        }
        let mut rows = Vec::new();
        rows.try_reserve_exact(limits.jobs)
            .map_err(|_| Error::Capacity)?;
        Ok(Self {
            rows,
            limits,
            core,
            serial: 0,
            cursor: 0,
            closing: false,
            stats: Stats::default(),
            alarm: None,
            alarm_at: None,
        })
    }
    pub(crate) const fn enabled(&self) -> bool {
        self.limits.jobs > 0 && !self.closing
    }
    pub(crate) const fn stats(&self) -> Stats {
        self.stats
    }
    pub(crate) fn operations(&self) -> usize {
        self.rows.iter().filter(|r| r.task.is_some()).count()
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
    pub(crate) fn next_until(&self) -> Option<AbsoluteTime> {
        self.rows
            .iter()
            .filter(|r| !r.done)
            .filter_map(|r| r.bounds.map(Bounds::until))
            .min()
    }
    pub(crate) fn next_hard(&self) -> Option<Instant> {
        self.rows.iter().filter(|r| !r.done).map(|r| r.hard).min()
    }
    fn bytes(&self) -> Result<usize, Error> {
        self.rows
            .iter()
            .filter_map(|r| r.pending.as_ref())
            .try_fold(0usize, |total, (block, _)| {
                total.checked_add(block.capacity()).ok_or(Error::Overflow)
            })
    }
    /// Native time is captured here in the manager's native-only first phase,
    /// before its next canonical sample and before any actual provider admission.
    pub(crate) fn admit(&mut self, intent: CacheRefresh) -> Option<Event<O::Error, O::Report>> {
        if !self.enabled() {
            return None;
        }
        if self.rows.iter().any(|r| r.intent.key() == intent.key()) {
            self.stats.duplicates = self.stats.duplicates.saturating_add(1);
            return None;
        }
        let result = (|| {
            if self.rows.len() == self.limits.jobs {
                return Err(Error::Capacity);
            }
            let serial = self.serial.checked_add(1).ok_or(Error::Overflow)?;
            let hard = Instant::now()
                .checked_add(std::time::Duration::from_micros(self.limits.timeout.0))
                .ok_or(Error::Overflow)?;
            Ok((serial, hard))
        })();
        let (serial, hard) = match result {
            Ok(value) => value,
            Err(reason) => {
                self.stats.refused = self.stats.refused.saturating_add(1);
                return Some(Event::Refused { id: None, reason });
            }
        };
        self.serial = serial;
        let id = Id(serial);
        self.rows.push(Row {
            id,
            intent,
            hard,
            bounds: None,
            task: None,
            pending: None,
            cache: false,
            done: false,
        });
        self.stats.admitted = self.stats.admitted.saturating_add(1);
        Some(Event::Queued { id })
    }
    pub(crate) fn begin_close(&mut self) {
        self.closing = true;
        for row in &mut self.rows {
            row.stop();
        }
    }
    pub(crate) fn guard(&mut self, cx: &mut Context<'_>) -> Option<Event<O::Error, O::Report>> {
        let target = self.next_hard();
        if self.alarm_at != target {
            self.alarm_at = target;
            self.alarm = target.map(|at| Box::pin(tokio::time::sleep_until(at)));
        }
        if let Some(alarm) = &mut self.alarm {
            let _ready = alarm.as_mut().poll(cx);
        }
        for row in &mut self.rows {
            if !row.done && Instant::now() >= row.hard {
                row.stop();
                return Some(Event::Expired { id: row.id });
            }
            if let Some(task) = &mut row.task
                && let Some(error) = task.operation.poll_native_guard(cx)
            {
                let id = row.id;
                let stage = task.stage;
                row.stop();
                return Some(Event::GuardFailed { id, stage, error });
            }
        }
        None
    }
    fn retirement_at(
        &mut self,
        i: usize,
        cx: &mut Context<'_>,
    ) -> Option<Event<O::Error, O::Report>> {
        let row = &mut self.rows[i];
        let id = row.id;
        if let Some(task) = &mut row.task
            && task.closing
        {
            let stage = task.stage;
            if let Some(error) = task.error.take() {
                return Some(Event::RetireFailed { id, stage, error });
            }
            match task.operation.poll_close(cx) {
                Poll::Pending => {}
                Poll::Ready(Close::Activity) => return Some(Event::Retiring { id, stage }),
                Poll::Ready(Close::Failed(error)) => {
                    row.done = true;
                    row.pending = None;
                    return Some(Event::RetireFailed { id, stage, error });
                }
                Poll::Ready(Close::Closed(report)) => {
                    row.task = None;
                    return Some(Event::Retired { id, stage, report });
                }
            }
        }
        if row.done && row.task.is_none() {
            self.rows.swap_remove(i);
            return Some(Event::Finished { id });
        }
        None
    }
    pub(crate) fn poll_close(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Option<Event<O::Error, O::Report>> {
        for _ in 0..self.rows.len() {
            let i = self.cursor % self.rows.len();
            self.cursor = (i + 1) % self.rows.len();
            if let Some(event) = self.retirement_at(i, cx) {
                return Some(event);
            }
        }
        None
    }
    pub(crate) fn poll<P: Provider<Operation = O>>(
        &mut self,
        cx: &mut Context<'_>,
        now: AbsoluteTime,
        provider: &mut P,
    ) -> Option<Event<O::Error, O::Report>> {
        for _ in 0..self.rows.len() {
            let i = self.cursor % self.rows.len();
            self.cursor = (i + 1) % self.rows.len();
            if let Some(event) = self.retirement_at(i, cx) {
                return Some(event);
            }
            let row = &mut self.rows[i];
            let id = row.id;
            if row.done {
                continue;
            }
            if Instant::now() >= row.hard || row.bounds.is_some_and(|b| b.expired(now)) {
                row.stop();
                return Some(Event::Expired { id });
            }
            if row.task.is_none() {
                if self.closing {
                    row.stop();
                    continue;
                }
                if row.bounds.is_none() {
                    let until = match row.intent.created_at().checked_add(self.limits.timeout.0) {
                        Some(v) if v != u64::MAX => AbsoluteTime::from_micros(v),
                        _ => {
                            row.stop();
                            return Some(Event::Refused {
                                id: Some(id),
                                reason: Error::Overflow,
                            });
                        }
                    };
                    match Bounds::new(until, row.hard) {
                        Ok(bounds) => row.bounds = Some(bounds),
                        Err(reason) => {
                            row.stop();
                            return Some(Event::Refused {
                                id: Some(id),
                                reason,
                            });
                        }
                    }
                }
                let bounds = match row.bounds {
                    Some(bounds) => bounds,
                    None => {
                        row.stop();
                        return Some(Event::Refused {
                            id: Some(id),
                            reason: Error::NotReady,
                        });
                    }
                };
                if bounds.expired(now) {
                    row.stop();
                    return Some(Event::Expired { id });
                }
                let stage = if row.cache {
                    Stage::Cache
                } else {
                    Stage::Remote
                };
                let effect = if row.cache {
                    let Some((block, expiration)) = row.pending.take() else {
                        row.stop();
                        return Some(Event::Refused {
                            id: Some(id),
                            reason: Error::NotReady,
                        });
                    };
                    if expiration <= now.as_micros() {
                        row.stop();
                        return Some(Event::Refused {
                            id: Some(id),
                            reason: Error::Timeout,
                        });
                    }
                    EffectKind::CachePut {
                        key: *row.intent.key(),
                        block,
                    }
                } else {
                    match row.intent.effect() {
                        Ok(effect) => effect,
                        Err(reason) => {
                            row.stop();
                            return Some(Event::Refused {
                                id: Some(id),
                                reason,
                            });
                        }
                    }
                };
                if bounds.expired(now) {
                    row.stop();
                    return Some(Event::Expired { id });
                }
                match provider.start(&effect, bounds) {
                    Ok(operation) => {
                        row.task = Some(Task {
                            operation,
                            stage,
                            closing: false,
                            error: None,
                        });
                        let expired = bounds.expired(now);
                        if expired {
                            row.stop();
                        }
                        return Some(Event::Started { id, stage, expired });
                    }
                    Err(error) => {
                        let expired = bounds.expired(now);
                        row.stop();
                        return Some(Event::Failed {
                            id,
                            stage,
                            error,
                            expired,
                        });
                    }
                }
            }
            let (stage, value) = {
                let row = &mut self.rows[i];
                let Some(task) = &mut row.task else {
                    continue;
                };
                if task.closing {
                    continue;
                }
                let value = match task.operation.poll(cx, now) {
                    Poll::Pending => continue,
                    Poll::Ready(value) => value,
                };
                (task.stage, value)
            };
            let row = &mut self.rows[i];
            if row.bounds.is_some_and(|b| b.expired(now)) {
                if stage == Stage::Cache && matches!(&value, Ok(Value::Stored(1))) {
                    self.stats.stored = self.stats.stored.saturating_add(1);
                }
                row.stop();
                return Some(Event::LateObservation { id, stage, value });
            }
            let value = match value {
                Ok(value) => value,
                Err(error) => {
                    row.stop();
                    return Some(Event::Failed {
                        id,
                        stage,
                        error,
                        expired: false,
                    });
                }
            };
            match (stage, value) {
                (Stage::Remote, Value::Block(block)) => {
                    self.stats.candidates = self.stats.candidates.saturating_add(1);
                    let result = self.rows[i]
                        .intent
                        .candidate(&block, now.as_micros(), self.core);
                    let row = &mut self.rows[i];
                    if row.bounds.is_some_and(|b| b.expired(now)) {
                        row.stop();
                        return Some(Event::Expired { id });
                    }
                    match result {
                        Ok(Some(expiration)) => {
                            let space = self
                                .bytes()
                                .and_then(|bytes| {
                                    bytes.checked_add(block.capacity()).ok_or(Error::Overflow)
                                })
                                .is_ok_and(|bytes| bytes <= self.limits.bytes);
                            let row = &mut self.rows[i];
                            if !space {
                                row.stop();
                                return Some(Event::Refused {
                                    id: Some(id),
                                    reason: Error::Capacity,
                                });
                            }
                            row.pending = Some((block, expiration));
                            row.cache = true;
                            row.retire();
                            self.stats.selected = self.stats.selected.saturating_add(1);
                            return Some(Event::Selected { id, expiration });
                        }
                        Ok(None) => {
                            if row.intent.remaining() == 0 {
                                row.stop();
                            }
                            return Some(Event::Ignored { id, reason: None });
                        }
                        Err(reason) => {
                            if row.intent.remaining() == 0 {
                                row.stop();
                            }
                            return Some(Event::Ignored {
                                id,
                                reason: Some(reason),
                            });
                        }
                    }
                }
                (Stage::Cache, Value::Stored(status)) => {
                    if status == 1 {
                        self.stats.stored = self.stats.stored.saturating_add(1);
                    }
                    self.rows[i].stop();
                    return Some(Event::Stored { id, status });
                }
                (Stage::Remote, Value::End) => {
                    self.rows[i].stop();
                    return Some(Event::Refused {
                        id: Some(id),
                        reason: Error::NotFound,
                    });
                }
                _ => {
                    self.rows[i].stop();
                    return Some(Event::Refused {
                        id: Some(id),
                        reason: Error::Malformed,
                    });
                }
            }
        }
        None
    }
}
