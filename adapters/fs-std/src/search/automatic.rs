//! Caller-driven automatic native probes for original authenticated search hits.
//!
//! Search and probe futures retain their original native owners. This driver
//! schedules only visible resolved CHK/LOC results, and it returns original
//! search steps and genuine probe reports rather than availability booleans.
//! A deadline is inconclusive. No historical receipt is replayed as a new run.

pub mod persistence;
use super::{Error as SearchError, ResultId, Session, Step, availability, probe};
use crate::{Buffers, ipc, network};
use gnunet_crypto::Entropy;
use gnunet_fs::Content;
use gnunet_service_runtime::clock::{Deadline, RuntimeClock};
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
pub use persistence::Persistence;
use std::{
    cmp::{Ordering as CmpOrdering, Reverse},
    collections::BinaryHeap,
    fmt,
    future::{Future, poll_fn},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
};

/// Explicit local automatic-observation policy; none of these values adds an FS
/// wire field or imposes a private C-client scheduling heuristic on the protocol.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    /// Simultaneous native probes. One result can have at most one live attempt.
    pub max_running: usize,
    /// Fresh finite budget per probe, clipped to the original search deadline.
    pub slice_us: u64,
    /// Delay after a genuine success/inconclusive written deadline. None means
    /// one automatic probe per result; errors/cancellations never auto-repeat.
    pub repeat_delay_us: Option<u64>,
    /// Explicit lifetime observation bounds for every result's original Book.
    pub observations: availability::Limits,
    /// Whether to authenticate a real empty root automatically. False only
    /// skips that local heuristic; an explicit manual empty probe remains valid.
    pub include_empty: bool,
    /// Original native path-work/resource bounds. Its deadline is replaced by
    /// each fresh clipped slice; anonymity and placement always come from Session.
    pub native: probe::Options,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            max_running: 2,
            slice_us: 5_000_000,
            repeat_delay_us: None,
            observations: availability::Limits::default(),
            include_empty: false,
            native: probe::Options::new(AbsoluteTime::from_micros(0)),
        }
    }
}
impl Policy {
    fn validate(self, result_limit: usize) -> Result<(), ProtocolError> {
        if self.max_running == 0
            || self.max_running > result_limit
            || self.slice_us == 0
            || self.slice_us == u64::MAX
            || matches!(self.repeat_delay_us, Some(0 | u64::MAX))
            || self.observations.attempts == 0
            || self.observations.trials == 0
            || self.observations.trials > i32::MAX as u32
            || self.native.max_path_blocks == 0
            || self.native.max_encoded_bytes == 0
            || self.native.queries_per_connection == 0
            || self.native.io_slice_bytes == 0
        {
            return Err(ProtocolError::InvalidInput);
        }
        Ok(())
    }
}

/// One actual search or probe event. Neither this event nor a copied URI can be
/// submitted to Session as a replacement for its private native completion.
pub enum Event {
    /// Original search event, preserving metadata/query/native refusal semantics.
    Search(Box<Step>),
    /// Original genuine native run settled into this result's original Book.
    Probe(Box<Report>),
    /// Probe admission failed before a ticket could run. The search result and
    /// original error remain visible; no observation/trial is invented.
    AdmissionFailed {
        /// Original result, including its private Session owner stamp.
        result: ResultId,
        /// Original URI, entropy, source, budget or admission refusal.
        cause: SearchError,
    },
    /// Original native completion could not be accounted for. It remains intact
    /// for the original Session; this driver stops rather than discard evidence.
    AccountingRefused {
        /// Original rejected native completion and its original accounting cause.
        native: probe::Refused<probe::Completion>,
        /// Independent original persistent-recording outcome, when enabled.
        persistence: Option<Box<persistence::Outcome>>,
    },
    /// Original persistent preparation/recording refused before a native ticket
    /// ran. The original admission is cancelled only through its own Session.
    PersistenceFailed {
        /// Original result, scoped to this Session and source revision.
        result: ResultId,
        /// Original persistent record/limit/binding error.
        cause: persistence::Error,
        /// Independent inability to retire the original unrun Book admission.
        accounting: Option<probe::Refused<probe::Probe>>,
    },
}

/// Genuine Session result and independent original persistence result. Historical
/// revalidation never substitutes for the native result in `native`.
pub struct Report {
    /// Original actual run settled into the original result's Book.
    pub native: probe::Report,
    /// Original durable recording outcome, including a real recoverable receipt
    /// on local WAL failure. None is ordinary in-memory observation mode.
    pub persistence: Option<Box<persistence::Outcome>>,
}

/// Independent coordinator and original search-retirement failure. Per-query
/// failures and original probe reports are already returned as stream events.
#[derive(Debug)]
pub struct Failure {
    /// Original source/search/scheduler cause; absent for retirement-only failure.
    pub cause: Option<SearchError>,
    /// Independent actual original search cancellation refusal.
    pub cleanup: Option<SearchError>,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("automatic FS probing stopped")?;
        if let Some(error) = &self.cause {
            write!(f, ": {error}")?;
        }
        if let Some(error) = &self.cleanup {
            write!(f, "; search retirement: {error}")?;
        }
        Ok(())
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause
            .as_ref()
            .or(self.cleanup.as_ref())
            .map(|cause| cause as _)
    }
}

struct StopInner {
    requested: AtomicBool,
    waiter: Mutex<Option<Waker>>,
}
/// Stop only this automatic driver. Its original search MQs are cancelled and
/// every admitted native probe is driven to a real typed cancellation/result.
#[derive(Clone)]
pub struct Stop(Arc<StopInner>);
impl Stop {
    fn new() -> Self {
        Self(Arc::new(StopInner {
            requested: AtomicBool::new(false),
            waiter: Mutex::new(None),
        }))
    }
    /// Request no further admissions and wake the driver's original waiter.
    /// This is intent only; keep driving `next` to observe actual retirement.
    pub fn request(&self) {
        self.0.requested.store(true, Ordering::Release);
        let waiter = self.0.waiter.lock().ok().and_then(|mut guard| guard.take());
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }
    /// Caller/coordinator stop intent, not a socket retirement acknowledgement.
    #[must_use]
    pub fn is_requested(&self) -> bool {
        self.0.requested.load(Ordering::Acquire)
    }
    fn retire_waiter(&self) {
        let waiter = self.0.waiter.lock().ok().and_then(|mut guard| guard.take());
        drop(waiter);
    }
    fn poll(&self, cx: &mut Context<'_>) -> Poll<Result<(), ProtocolError>> {
        if self.is_requested() {
            return Poll::Ready(Ok(()));
        }
        let waker = cx.waker().clone();
        let mut guard = self
            .0
            .waiter
            .lock()
            .map_err(|_| ProtocolError::Unavailable)?;
        let old = guard.replace(waker);
        drop(guard);
        drop(old);
        if self.is_requested() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Tracked {
    Unseen,
    Queued,
    Running,
    Finished,
}
#[derive(Clone, Copy, Debug)]
struct Due {
    at: AbsoluteTime,
    order: u64,
    result: ResultId,
}
impl PartialEq for Due {
    fn eq(&self, other: &Self) -> bool {
        (self.at, self.order) == (other.at, other.order)
    }
}
impl Eq for Due {}
impl Ord for Due {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        (self.at, self.order).cmp(&(other.at, other.order))
    }
}
impl PartialOrd for Due {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}
type Active = Pin<Box<dyn Future<Output = persistence::Finished>>>;
struct Actives {
    values: Vec<Active>,
    stop: Stop,
}
impl std::ops::Deref for Actives {
    type Target = Vec<Active>;
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}
impl std::ops::DerefMut for Actives {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.values
    }
}
impl Drop for Actives {
    fn drop(&mut self) {
        // Native owners retire before the Session owner is dropped/extracted.
        self.values.clear();
        self.stop.retire_waiter();
    }
}

/// Bounded runtime observations; they do not establish complete search coverage
/// or present/future availability of any unqueried file range.
#[derive(Clone, Copy, Debug, Default)]
pub struct Progress {
    /// Genuine Session tickets admitted, independently of physical SEARCH writes.
    pub admitted: u64,
    /// Original native results successfully settled into their original Books.
    pub settled: u64,
    /// Original admission refusals before native ticket execution.
    pub admission_failures: u64,
    /// Maximum simultaneous native probe futures retained.
    pub max_active: usize,
}

/// One original owned Session with incremental, fair automatic native probing.
/// Existing visible results are inspected once at construction; subsequent
/// admission inspects only Result/Update events. Each result has at most one due
/// heap node or active future, with bounds inherited from Session's result limit.
/// Buffers are created lazily and reused at a maximum of `policy.max_running`.
/// No background task, private wire flag, cache, file output or Resolver is made.
pub struct Automatic<'id, F, const KNOWN: usize>
where
    F: FnMut() -> Result<ipc::EndpointSource, ipc::Error>,
{
    policy: Policy,
    clock: Arc<dyn RuntimeClock>,
    last_now: AbsoluteTime,
    tracked: Vec<Tracked>,
    due: BinaryHeap<Reverse<Due>>,
    order: u64,
    active: Actives,
    free: Vec<Buffers>,
    cursor: usize,
    probe_first: bool,
    pending: Option<Event>,
    stop: Stop,
    stopping: bool,
    failure: Option<SearchError>,
    cleanup: Option<SearchError>,
    progress: Progress,
    persistence: Option<Persistence>,
    session: Session<'id, F, KNOWN>,
}
impl<'id, F, const KNOWN: usize> Automatic<'id, F, KNOWN>
where
    F: FnMut() -> Result<ipc::EndpointSource, ipc::Error>,
{
    /// Own the original Session and local policy without opening a socket. The
    /// source factory and absolute search lifetime remain the caller's originals.
    /// Existing outstanding manual probes refuse attachment, since this driver
    /// cannot acquire or cancel their independently owned native futures.
    pub fn new(session: Session<'id, F, KNOWN>, policy: Policy) -> Result<Self, SearchError> {
        policy.validate(session.options.limits.results)?;
        if session.closed {
            return Err(ProtocolError::Closed.into());
        }
        let clock = session
            .clock
            .as_ref()
            .ok_or(ProtocolError::NotReady)?
            .clone();
        let now = clock.sample()?.now;
        if session.last_now.is_some_and(|previous| now < previous) {
            return Err(ProtocolError::TimeUncertain.into());
        }
        if now >= session.options.deadline {
            return Err(ProtocolError::Deadline.into());
        }
        let mut tracked = Vec::new();
        tracked
            .try_reserve_exact(session.results.len())
            .map_err(|_| SearchError::Limit)?;
        tracked.resize(session.results.len(), Tracked::Unseen);
        let mut due = BinaryHeap::new();
        due.try_reserve(session.results.len())
            .map_err(|_| SearchError::Limit)?;
        let mut order = 0u64;
        for (index, record) in session.results.iter().enumerate() {
            let id = session.result_id(index);
            if session
                .availability_summary(id)
                .is_some_and(|summary| summary.active())
            {
                return Err(ProtocolError::WouldBlock.into());
            }
            if record.visible() && content(record, policy)?.is_some() {
                order = order.checked_add(1).ok_or(ProtocolError::Overflow)?;
                due.push(Reverse(Due {
                    at: now,
                    order,
                    result: id,
                }));
                tracked[index] = Tracked::Queued;
            }
        }
        let mut active = Vec::new();
        active
            .try_reserve_exact(policy.max_running)
            .map_err(|_| SearchError::Limit)?;
        let mut free = Vec::new();
        free.try_reserve_exact(policy.max_running)
            .map_err(|_| SearchError::Limit)?;
        let stop = Stop::new();
        Ok(Self {
            session,
            policy,
            clock,
            last_now: now,
            tracked,
            due,
            order,
            active: Actives {
                values: active,
                stop: stop.clone(),
            },
            free,
            cursor: 0,
            probe_first: false,
            pending: None,
            stop,
            stopping: false,
            failure: None,
            cleanup: None,
            progress: Progress::default(),
            persistence: None,
        })
    }
    /// Borrow the original Session for genuine result/query/availability details.
    #[must_use]
    pub const fn session(&self) -> &Session<'id, F, KNOWN> {
        &self.session
    }
    /// Retain an original source-bound durable observation store. Preparation
    /// opens/creates one original per-result Task before its native admission;
    /// history remains separate from each genuinely fresh Book observation.
    pub fn with_persistence(mut self, persistence: Persistence) -> Self {
        self.persistence = Some(persistence);
        self
    }
    /// Cooperative stop handle belonging only to this driver.
    #[must_use]
    pub fn stop_handle(&self) -> Stop {
        self.stop.clone()
    }
    /// Runtime counters; native queries/bytes remain in each original report.
    #[must_use]
    pub const fn progress(&self) -> Progress {
        self.progress
    }
    /// Return the original Session only when no independently owned native probe
    /// is active. Queued probes are local intent only and can be abandoned. On
    /// refusal the whole driver is returned; no native owner is dropped.
    pub fn into_session(self) -> Result<Session<'id, F, KNOWN>, Box<Self>> {
        if !self.active.is_empty() {
            return Err(Box::new(self));
        }
        Ok(self.session)
    }
    fn now(&mut self) -> Result<AbsoluteTime, SearchError> {
        let now = self.clock.sample()?.now;
        if now < self.last_now || self.session.last_now.is_some_and(|previous| now < previous) {
            return Err(ProtocolError::TimeUncertain.into());
        }
        self.last_now = now;
        Ok(now)
    }
    fn halt(&mut self, cause: SearchError) {
        if self.failure.is_none() {
            self.failure = Some(cause);
        }
        self.stop.request();
    }
    fn begin_stop(&mut self) {
        if self.stopping {
            return;
        }
        self.stopping = true;
        self.due.clear();
        if !self.session.closed
            && let Err(error) = self.session.cancel()
        {
            self.cleanup = Some(error);
        }
    }
    fn queue(&mut self, id: ResultId, at: AbsoluteTime) -> Result<(), SearchError> {
        let record = self.session().result(id).ok_or(ProtocolError::Stale)?;
        if !record.visible() || content(record, self.policy)?.is_none() {
            return Ok(());
        }
        if id.index() >= self.tracked.len() {
            let len = self.session().results.len();
            self.tracked
                .try_reserve_exact(len - self.tracked.len())
                .map_err(|_| SearchError::Limit)?;
            self.tracked.resize(len, Tracked::Unseen);
        }
        if self.tracked[id.index()] != Tracked::Unseen {
            return Ok(());
        }
        self.enqueue(id, at)
    }
    fn enqueue(&mut self, id: ResultId, at: AbsoluteTime) -> Result<(), SearchError> {
        let order = self.order.checked_add(1).ok_or(ProtocolError::Overflow)?;
        self.due.try_reserve(1).map_err(|_| SearchError::Limit)?;
        self.due.push(Reverse(Due {
            at,
            order,
            result: id,
        }));
        self.order = order;
        self.tracked[id.index()] = Tracked::Queued;
        Ok(())
    }
    fn admission_failed(&mut self, id: ResultId, cause: SearchError) -> Event {
        self.tracked[id.index()] = Tracked::Finished;
        self.progress.admission_failures += 1;
        Event::AdmissionFailed { result: id, cause }
    }
    fn dispatch(
        &mut self,
        entropy: &mut impl Entropy,
        now: AbsoluteTime,
    ) -> Result<Option<Event>, SearchError> {
        while self.active.len() < self.policy.max_running {
            let Some(Reverse(due)) = self.due.peek().copied() else {
                break;
            };
            if due.at > now {
                break;
            }
            self.due.pop();
            let id = due.result;
            if self
                .session
                .availability_summary(id)
                .is_some_and(|summary| {
                    summary.attempts() >= self.policy.observations.attempts
                        || summary.trials() >= self.policy.observations.trials
                })
            {
                self.tracked[id.index()] = Tracked::Finished;
                continue;
            }
            // Persistence prepares its own original per-result Task but starts
            // no native work and writes no successful observation here.
            let prepared = match persistence::prepare(
                self.persistence.as_mut(),
                &self.session,
                id,
                &self.policy,
            ) {
                Ok(prepared) => prepared,
                Err(cause) => {
                    self.tracked[id.index()] = Tracked::Finished;
                    self.progress.admission_failures += 1;
                    return Ok(Some(Event::PersistenceFailed {
                        result: id,
                        cause,
                        accounting: None,
                    }));
                }
            };
            let admitted = self
                .progress
                .admitted
                .checked_add(1)
                .ok_or(ProtocolError::Overflow)?;
            let attempt = (|| -> Result<probe::Probe, SearchError> {
                let record = self.session.result(id).ok_or(ProtocolError::Stale)?;
                let target = content(record, self.policy)?.ok_or(ProtocolError::Unsupported)?;
                let leaf = network::probe::sample_leaf(target, entropy)?;
                // WAL opening/revalidation can take time. Sample a fresh slice
                // only after persistent preparation, in the original domain.
                let now = self.now()?;
                let end = now
                    .as_micros()
                    .checked_add(self.policy.slice_us)
                    .ok_or(ProtocolError::Overflow)?;
                let deadline = AbsoluteTime::from_micros(end).min(self.session.options.deadline);
                if deadline <= now || deadline.as_micros() == u64::MAX {
                    return Err(ProtocolError::Deadline.into());
                }
                let mut options = self.policy.native;
                options.deadline = deadline;
                options.observations = self.policy.observations;
                self.session.begin_probe(id, leaf, options)
            })();
            let ticket = match attempt {
                Ok(ticket) => ticket,
                Err(error) => return Ok(Some(self.admission_failed(id, error))),
            };
            let buffers = self.free.pop().unwrap_or_default();
            self.active.push(Box::pin(persistence::run(
                prepared,
                ticket,
                buffers,
                self.stop.clone(),
            )));
            self.tracked[id.index()] = Tracked::Running;
            self.progress.admitted = admitted;
            self.progress.max_active = self.progress.max_active.max(self.active.len());
        }
        Ok(None)
    }
    fn settle(&mut self, run: persistence::Run) -> Event {
        let (completed, persistent) = match run {
            persistence::Run::Executed {
                completion,
                persistence,
            } => (*completion, persistence),
            persistence::Run::NotStarted { ticket, cause } => {
                let ticket = *ticket;
                let id = ticket.result();
                self.tracked[id.index()] = Tracked::Finished;
                self.progress.admission_failures += 1;
                let accounting = self.session.cancel_probe(ticket).err();
                if let Some(refused) = &accounting {
                    self.halt(refused.cause.into());
                }
                return Event::PersistenceFailed {
                    result: id,
                    cause,
                    accounting,
                };
            }
        };
        let id = completed.result();
        self.tracked[id.index()] = Tracked::Finished;
        match self.session.finish_probe(completed) {
            Ok(report) => {
                self.progress.settled += 1;
                let checked = match &report.observation {
                    Ok(observed) => Some(observed.finished()),
                    Err(failure) => failure.last_checked(),
                };
                if let Some(checked) = checked {
                    self.last_now = self.last_now.max(checked);
                }
                let native_repeatable = match &report.observation {
                    Ok(_) => true,
                    Err(failure) => {
                        matches!(failure.cause(), network::Error::Deadline { .. })
                            && failure.queries_written() > 0
                    }
                };
                if !self.stop.is_requested()
                    && native_repeatable
                    && persistent
                        .as_deref()
                        .is_none_or(persistence::Outcome::repeatable)
                    && report.summary.attempts() < self.policy.observations.attempts
                    && report.summary.trials() < self.policy.observations.trials
                    && let Some(delay) = self.policy.repeat_delay_us
                {
                    let schedule = self
                        .now()
                        .and_then(|now| {
                            now.as_micros()
                                .checked_add(delay)
                                .map(AbsoluteTime::from_micros)
                                .ok_or(ProtocolError::Overflow.into())
                        })
                        .and_then(|due| self.enqueue(id, due));
                    if let Err(error) = schedule {
                        self.halt(error);
                    }
                }
                Event::Probe(Box::new(Report {
                    native: report,
                    persistence: persistent,
                }))
            }
            Err(native) => {
                self.halt(native.cause.into());
                Event::AccountingRefused {
                    native,
                    persistence: persistent,
                }
            }
        }
    }
    /// Fairly drive original search and due native probe owners. Every accepted
    /// search step and every original probe result is returned individually.
    /// Stop/coordinator failure requests actual cancellation and drains all
    /// admitted probes before returning terminal failure/None. Call repeatedly;
    /// observation silence is never converted into absence or complete search.
    pub async fn next(&mut self, entropy: &mut impl Entropy) -> Result<Option<Event>, Failure> {
        loop {
            if let Some(event) = self.pending.take() {
                return Ok(Some(event));
            }
            if self.stop.is_requested() {
                self.begin_stop();
            }
            if !self.stopping {
                match self.now() {
                    Ok(now) if now >= self.session().options.deadline => {
                        self.halt(ProtocolError::Deadline.into())
                    }
                    Ok(now) => match self.dispatch(entropy, now) {
                        Ok(Some(event)) => return Ok(Some(event)),
                        Ok(None) => {}
                        Err(error) => self.halt(error),
                    },
                    Err(error) => self.halt(error),
                }
            }
            if self.stop.is_requested() {
                self.begin_stop();
            }
            if self.stopping && self.active.is_empty() {
                self.stop.retire_waiter();
                return match (self.failure.take(), self.cleanup.take()) {
                    (None, None) => Ok(None),
                    (cause, cleanup) => Err(Failure { cause, cleanup }),
                };
            }
            let target = self
                .due
                .peek()
                .filter(|_| self.active.len() < self.policy.max_running)
                .map_or(self.session().options.deadline, |Reverse(due)| {
                    due.at.min(self.session().options.deadline)
                });
            let mut timer = if self.stopping {
                None
            } else {
                match Deadline::at(self.clock.clone(), target) {
                    Ok(timer) => Some(timer),
                    Err(error) => {
                        self.halt(error.into());
                        None
                    }
                }
            };
            if self.stop.is_requested() && !self.stopping {
                continue;
            }
            enum Wake {
                Search(Result<Box<Step>, SearchError>),
                Probe(usize, Box<persistence::Finished>),
                Tick,
                Failed(ProtocolError),
            }
            let stop = self.stop.clone();
            let stopping = self.stopping;
            let probe_first = self.probe_first;
            let wake = {
                let mut search = std::pin::pin!(self.session.drive(None));
                poll_fn(|cx| {
                    let poll_probes =
                        |active: &mut Vec<Active>, cursor: usize, cx: &mut Context<'_>| {
                            let len = active.len();
                            for offset in 0..len {
                                let index = (cursor + offset) % len;
                                if let Poll::Ready(completed) = active[index].as_mut().poll(cx) {
                                    return Poll::Ready(Wake::Probe(index, Box::new(completed)));
                                }
                            }
                            Poll::Pending
                        };
                    if probe_first
                        && let Poll::Ready(wake) = poll_probes(&mut self.active, self.cursor, cx)
                    {
                        return Poll::Ready(wake);
                    }
                    if !stopping && let Poll::Ready(step) = search.as_mut().poll(cx) {
                        return Poll::Ready(Wake::Search(step.map(Box::new)));
                    }
                    if !probe_first
                        && let Poll::Ready(wake) = poll_probes(&mut self.active, self.cursor, cx)
                    {
                        return Poll::Ready(wake);
                    }
                    if !stopping {
                        match stop.poll(cx) {
                            Poll::Ready(Ok(())) => return Poll::Ready(Wake::Tick),
                            Poll::Ready(Err(error)) => return Poll::Ready(Wake::Failed(error)),
                            Poll::Pending => {}
                        }
                        if let Some(timer) = timer.as_mut() {
                            match Pin::new(timer).poll(cx) {
                                Poll::Ready(Ok(())) => return Poll::Ready(Wake::Tick),
                                Poll::Ready(Err(error)) => return Poll::Ready(Wake::Failed(error)),
                                Poll::Pending => {}
                            }
                        }
                    }
                    Poll::Pending
                })
                .await
            };
            match wake {
                Wake::Search(Ok(step)) => {
                    self.probe_first = true;
                    let id = match step.as_ref() {
                        Step::Result { result } | Step::Update { result } => Some(*result),
                        _ => None,
                    };
                    if let Some(id) = id
                        && let Err(error) = self.now().and_then(|now| self.queue(id, now))
                    {
                        self.pending = Some(Event::AdmissionFailed {
                            result: id,
                            cause: error,
                        });
                    }
                    return Ok(Some(Event::Search(step)));
                }
                Wake::Search(Err(error)) => self.halt(error),
                Wake::Probe(index, completed) => {
                    drop(self.active.swap_remove(index));
                    self.cursor = if self.active.is_empty() {
                        0
                    } else {
                        index % self.active.len()
                    };
                    let persistence::Finished { buffers, run } = *completed;
                    self.free.push(buffers);
                    self.probe_first = false;
                    return Ok(Some(self.settle(run)));
                }
                Wake::Tick => {}
                Wake::Failed(error) => self.halt(error.into()),
            }
        }
    }
}

fn content(record: &super::ResultRecord, policy: Policy) -> Result<Option<Content>, SearchError> {
    let value = match &record.identity {
        super::Identity::Content(value) => *value,
        super::Identity::Location(value) => value.content(),
        _ => return Ok(None),
    };
    if value.size == 0 && !policy.include_empty {
        Ok(None)
    } else {
        Ok(Some(value))
    }
}
