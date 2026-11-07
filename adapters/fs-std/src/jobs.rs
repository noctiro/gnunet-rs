//! Durable discovery and caller-driven concurrent execution of original FS tasks.
//! Scheduling owns local intent only. Original task owners retain every native
//! acknowledgement, unknown mutation, output reconciliation and lifecycle fact.
pub mod catalog;
mod execute;
mod queue;
use crate::{
    durable, ipc::EndpointSource, namespace::graph, probe_task, publication, search, unindex_task,
};
use catalog::{Catalog, EntryId};
pub use execute::bind;
use gnunet_service_runtime::clock::{Deadline, RuntimeClock};
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
use queue::{Permit, Queue};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
};

/// Original coordinator or task-opening failure. Actual running task failures
/// remain inside `Execution` rather than being replaced by a scheduler error.
#[derive(Debug)]
pub enum Error {
    /// Original catalog WAL, directory binding or configuration refusal.
    Catalog(catalog::Error),
    /// Clock, generation, arithmetic or explicit scheduler bound refusal.
    Protocol(ProtocolError),
    /// Original native filesystem error.
    Io(io::Error),
    /// Original CLIENT source/Resolver failure, without a replacement source.
    Transport(gnunet_client_host::ConnectError),
    /// Original local repository/output refusal.
    Local(crate::Error),
    /// Original managed namespace graph failure.
    Graph(graph::Error),
    /// Original download task opening/attachment failure.
    Download(Box<durable::Failure>),
    /// Independent original download status/model failure.
    DownloadState(Box<durable::Cause>),
    /// Original persistent search opening failure.
    Search(Box<search::task::Failure>),
    /// Original prepared publication opening failure.
    Publication(Box<publication::Failure>),
    /// Original durable probe opening failure, retaining any actual observation.
    Probe(Box<probe_task::Failure>),
    /// Original probe target, history or local admission refusal.
    ProbeState(Box<probe_task::Cause>),
    /// Original durable unindex opening failure and retained mutation facts.
    Unindex(unindex_task::Cause),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Catalog(e) => e.fmt(f),
            Self::Protocol(e) => e.fmt(f),
            Self::Io(e) => e.fmt(f),
            Self::Transport(e) => e.fmt(f),
            Self::Local(e) => e.fmt(f),
            Self::Graph(e) => e.fmt(f),
            Self::Download(e) => e.fmt(f),
            Self::DownloadState(e) => e.fmt(f),
            Self::Search(e) => e.fmt(f),
            Self::Publication(e) => e.fmt(f),
            Self::Probe(e) => e.fmt(f),
            Self::ProbeState(e) => e.fmt(f),
            Self::Unindex(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Catalog(e) => Some(e),
            Self::Protocol(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Transport(e) => Some(e),
            Self::Local(e) => Some(e),
            Self::Graph(e) => Some(e),
            Self::Download(e) => Some(e),
            Self::DownloadState(e) => Some(e),
            Self::Search(e) => Some(e),
            Self::Publication(e) => Some(e),
            Self::Probe(e) => Some(e),
            Self::ProbeState(e) => Some(e),
            Self::Unindex(e) => Some(e),
        }
    }
}
macro_rules! from_error {
    ($source:ty, $variant:ident) => {
        impl From<$source> for Error {
            fn from(error: $source) -> Self {
                Self::$variant(error)
            }
        }
    };
}
from_error!(catalog::Error, Catalog);
from_error!(ProtocolError, Protocol);
from_error!(io::Error, Io);
from_error!(gnunet_client_host::ConnectError, Transport);
from_error!(crate::Error, Local);
from_error!(graph::Error, Graph);

/// Actual historical status from the currently locked original typed task.
#[derive(Clone, Debug)]
pub enum State {
    /// Actual download ledger status, without current output revalidation.
    Download(durable::Status),
    /// Actual search observation ledger, without fresh availability claims.
    Search(search::task::Status),
    /// Actual publication ledger; native reply and index certainty stay separate.
    Publication(Box<publication::Status>),
    /// Original historical probe observations; never current reachability.
    Probe(Box<probe_task::Status>),
    /// Actual exact-file unindex ledger, including any unresolved mutation.
    Unindex(unindex_task::Status),
}
/// A historical state that does not authorize automatic new work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Blocked {
    /// Historical completion: no fresh native work is scheduled.
    Complete,
    /// Original cancellation or cancellation intent must not resume.
    Cancelled,
    /// Original uncertain local append prevents further task writes.
    Fenced,
    /// Original PUT/index intent, Unknown or explicit refusal requires its owner.
    PendingMutation,
    /// An actual in-memory owner is already running this task.
    Active,
    /// Original observation budget exhausted; this is not content completion.
    Exhausted,
    /// An old read-only observation intent needs explicit abandonment/settlement.
    Interrupted,
}
/// Full actual typed execution result, retaining original replies and independent
/// cleanup/state failures. A local scheduler coordinate is never a receipt.
#[derive(Debug)]
pub enum Execution {
    /// Original durable download outcome/failure.
    Download(Result<Box<durable::Outcome>, Box<durable::Failure>>),
    /// Original persistent search outcome/failure.
    Search(Result<search::task::Outcome, Box<search::task::Failure>>),
    /// Original prepared publication outcome/failure and native receipts.
    Publication(Result<Box<publication::Outcome>, Box<publication::Failure>>),
    /// Original native probe plus independent durable-record outcome/failure.
    Probe(Result<Box<probe_task::Outcome>, Box<probe_task::Failure>>),
    /// Isolate the large original report so other queued job outcomes do not
    /// retain its full storage; original journal/cleanup facts stay intact.
    Unindex(Result<Box<unindex_task::Report>, Box<unindex_task::Failure>>),
    /// Task could not be opened/bound/prepared; no task run was admitted.
    NotStarted(Error),
}
impl Execution {
    fn repeatable(&self) -> bool {
        match self {
            Self::Download(Ok(outcome)) => outcome.disposition == durable::Disposition::Paused,
            Self::Search(Ok(outcome)) => {
                outcome.reason != search::task::StopReason::Cancelled
                    && outcome.query_failures.is_empty()
            }
            Self::Publication(Ok(outcome)) => {
                matches!(
                    outcome.reason,
                    publication::StopReason::CallerPause | publication::StopReason::Deadline
                ) && outcome.cleanup.is_none()
            }
            Self::Probe(Ok(outcome)) => {
                matches!(
                    outcome.receipt.kind(),
                    probe_task::Kind::Success | probe_task::Kind::Inconclusive
                ) && outcome.status.phase == probe_task::Phase::Paused
            }
            Self::Unindex(result) => match result {
                Ok(report) => report.resumable(),
                Err(failure) => failure.resumable(),
            },
            _ => false,
        }
    }
}
/// One finished run emitted by the original native execution wrapper. Its public
/// fields are observations; there is no completion-submission API that could
/// turn a projected event into permission to repeat a mutation.
#[derive(Debug)]
pub struct Completed {
    /// Original persistent catalog coordinate.
    pub entry: EntryId,
    /// Original random typed task identity.
    pub task_id: [u8; 32],
    /// Full original typed result, including its independent native facts.
    pub execution: Execution,
    /// Actual original task status after execution, when inspectable.
    pub after: Option<State>,
    /// Independent inability to inspect download status after its actual result.
    pub state_error: Option<durable::Cause>,
    /// Independent queue/clock refusal after native settlement. Actual results
    /// remain available even when scheduling cannot continue.
    pub scheduling_error: Option<ProtocolError>,
}
/// Caller-owned stream event. Search stops do not imply search completion.
#[derive(Debug)]
pub enum Event {
    /// Actual task finished, retaining its full original native result.
    Settled(Box<Completed>),
    /// Actual locked historical task status refused automatic new work.
    Skipped {
        /// Original persistent catalog entry.
        entry: EntryId,
        /// Why no new run was admitted.
        reason: Blocked,
        /// Actual historical status; not freshly authenticated content.
        state: State,
    },
}

struct StopInner {
    requested: AtomicBool,
    waiter: Mutex<Option<Waker>>,
}
/// Cooperative stop handle for one worker. Requesting stop wakes its original
/// waiter; active tasks receive Pause and drain through their original owners.
#[derive(Clone)]
pub struct Stop(Arc<StopInner>);
impl Stop {
    fn new() -> Self {
        Self(Arc::new(StopInner {
            requested: AtomicBool::new(false),
            waiter: Mutex::new(None),
        }))
    }
    /// Request no new dispatch and cooperative retirement of original task runs.
    /// This sends no synthetic wire cancellation and does not roll back effects.
    pub fn request(&self) {
        self.0.requested.store(true, Ordering::Release);
        let waiter = self.0.waiter.lock().ok().and_then(|mut guard| guard.take());
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }
    /// Current caller/coordinator stop intent, not evidence of native retirement.
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
        let previous = guard.replace(waker);
        drop(guard);
        drop(previous);
        if self.is_requested() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}
/// Original independent FS and DATASTORE selectors sharing one exact clock.
/// Duplicating selectors preserves their original Resolver and creates no MQ.
pub struct Sources {
    fs: EndpointSource,
    datastore: EndpointSource,
    clock: Arc<dyn RuntimeClock>,
}
impl Sources {
    /// Refuse mixed clock owners before native work. Direct Unix callers can use
    /// EndpointSource::unix_with_clock for both ports.
    pub fn new(fs: EndpointSource, datastore: EndpointSource) -> Result<Self, Error> {
        let clock = fs.clock();
        if !Arc::ptr_eq(&clock, &datastore.clock()) {
            return Err(ProtocolError::InvalidInput.into());
        }
        Ok(Self {
            fs,
            datastore,
            clock,
        })
    }
}
/// Explicit scheduler/run bounds, separate from original task resource policies.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Maximum enabled entries admitted from the catalog.
    pub max_jobs: usize,
    /// Maximum simultaneously polled task runs and their bounded buffers/WALs.
    pub max_running: usize,
    /// Stop new dispatch at this finite source deadline, then drain original
    /// runs through cooperative Pause; this is not a forced future abort.
    pub until: AbsoluteTime,
    /// Bounds used to open each original task WAL and managed graph.
    pub storage: durable::store::Limits,
}
/// Worker-local observations; no count establishes remote replication.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    /// Scheduling futures admitted, including historical skips/setup refusals.
    pub dispatched: usize,
    /// Actual typed task run calls, excluding historical skips/setup refusal.
    pub started: usize,
    /// Actual typed runs whose original futures returned a result.
    pub settled: usize,
    /// Original setup/open/binding refusals before a task run.
    pub not_started: usize,
    /// Historical statuses that prevented an automatic run.
    pub skipped: usize,
    /// Maximum simultaneously retained dispatch futures.
    pub max_active: usize,
}
type Resource = (u64, u64);
struct Finished {
    permit: Permit,
    entry: EntryId,
    resource: Option<Resource>,
    run: execute::Run,
}
type Active = Pin<Box<dyn Future<Output = Finished>>>;
/// One exclusive catalog owner with bounded concurrent caller-driven task runs.
/// `next` yields actual results individually, so periodic operation accumulates
/// no unbounded result history. Call stop_handle().request() and keep driving to
/// drain. Dropping the worker drops active owners and leaves interrupted task
/// history; it cannot claim settled pause or recover an unobserved native reply.
pub struct Worker {
    catalog: Catalog,
    sources: Sources,
    options: Options,
    queue: Queue,
    ids: HashMap<[u8; 32], EntryId>,
    active: Vec<Active>,
    cursor: usize,
    stop: Stop,
    failure: Option<Error>,
    last_now: AbsoluteTime,
    stats: Stats,
    resources: HashSet<Resource>,
    waiting: HashMap<Resource, VecDeque<[u8; 32]>>,
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.retire_waiter();
    }
}
impl Worker {
    /// Discover enabled registered tasks; no task, native socket or output is
    /// opened until it is dispatched. Catalog lock excludes another worker.
    pub fn new(catalog: Catalog, sources: Sources, options: Options) -> Result<Self, Error> {
        if let Some(error) = catalog.storage_failure() {
            return Err(catalog::Error::Storage(error.clone()).into());
        }
        let now = sources.clock.sample()?.now;
        if options.until <= now || options.until.as_micros() == u64::MAX {
            return Err(ProtocolError::InvalidInput.into());
        }
        let mut queue = Queue::new(options.max_jobs, options.max_running)?;
        let mut ids = HashMap::new();
        ids.try_reserve(catalog.entries().len())
            .map_err(|_| ProtocolError::Capacity)?;
        for record in catalog.entries().filter(|record| record.enabled) {
            queue.insert(record.registration.task_id, now)?;
            ids.insert(record.registration.task_id, record.id);
        }
        let mut active = Vec::new();
        active
            .try_reserve_exact(options.max_running)
            .map_err(|_| ProtocolError::Capacity)?;
        let mut resources = HashSet::new();
        resources
            .try_reserve(options.max_running)
            .map_err(|_| ProtocolError::Capacity)?;
        let mut waiting = HashMap::new();
        waiting
            .try_reserve(options.max_jobs)
            .map_err(|_| ProtocolError::Capacity)?;
        Ok(Self {
            catalog,
            sources,
            options,
            queue,
            ids,
            active,
            cursor: 0,
            stop: Stop::new(),
            failure: None,
            last_now: now,
            stats: Stats::default(),
            resources,
            waiting,
        })
    }
    /// Shared cooperative stop handle for this original worker only.
    #[must_use]
    pub fn stop_handle(&self) -> Stop {
        self.stop.clone()
    }
    /// Current worker-local counts, independent of historical task facts.
    #[must_use]
    pub const fn stats(&self) -> Stats {
        self.stats
    }
    /// Borrow registered scheduling intent. Historical task state is opened only
    /// on dispatch, and retained status does not assert current availability.
    #[must_use]
    pub const fn catalog(&self) -> &Catalog {
        &self.catalog
    }
    /// Persistently disable a queued, waiting or already settled entry. A live
    /// run returns WouldBlock without changing policy; stop and drain it first.
    /// A catalog write failure requests worker stop and returns the original
    /// error; caller must keep driving `next` to drain other active owners.
    pub fn suspend(&mut self, entry: EntryId) -> Result<(), Error> {
        let record = self.catalog.entry(entry).ok_or(ProtocolError::Stale)?;
        if !record.enabled {
            return Ok(());
        }
        let key = record.registration.task_id;
        let resource = record.registration.graph.as_ref().map(|dir| {
            let id = dir.identity();
            (id.device, id.inode)
        });
        match self.queue.remove(key) {
            Ok(()) | Err(ProtocolError::NotFound) => {}
            Err(error) => return Err(error.into()),
        }
        if let Some(resource) = resource
            && let Some(wait) = self.waiting.get_mut(&resource)
        {
            wait.retain(|waiting| *waiting != key);
            if wait.is_empty() {
                self.waiting.remove(&resource);
            }
        }
        if let Err(error) = self.catalog.set_enabled(entry, false) {
            self.stop.request();
            return Err(error.into());
        }
        self.ids.remove(&key);
        Ok(())
    }
    fn halt(&mut self, error: Error) {
        if self.failure.is_none() {
            self.failure = Some(error);
        }
        self.stop.request();
    }
    fn now(&mut self) -> Result<AbsoluteTime, ProtocolError> {
        let now = self.sources.clock.sample()?.now;
        if now < self.last_now {
            return Err(ProtocolError::TimeUncertain);
        }
        self.last_now = now;
        Ok(now)
    }
    fn dispatch(&mut self, now: AbsoluteTime) -> Result<(), Error> {
        while self.active.len() < self.options.max_running {
            let Some(permit) = self.queue.next(now)? else {
                break;
            };
            let key = permit.key();
            let id = *self.ids.get(&key).ok_or(ProtocolError::Stale)?;
            let record = self.catalog.entry(id).ok_or(ProtocolError::Stale)?;
            let resource = record.registration.graph.as_ref().map(|dir| {
                let id = dir.identity();
                (id.device, id.inode)
            });
            if let Some(resource) = resource
                && self.resources.contains(&resource)
            {
                let wait = self.waiting.entry(resource).or_default();
                wait.try_reserve(1).map_err(|_| ProtocolError::Capacity)?;
                self.queue.finish(&permit, None)?;
                wait.push_back(key);
                continue;
            }
            let registration = record.registration.clone();
            let pair = self
                .sources
                .fs
                .duplicate()
                .and_then(|fs| self.sources.datastore.duplicate().map(|ds| (fs, ds)));
            let stop = self.stop.clone();
            let storage = self.options.storage;
            let dispatched = self
                .stats
                .dispatched
                .checked_add(1)
                .ok_or(ProtocolError::Overflow)?;
            if let Some(resource) = resource {
                self.resources.insert(resource);
            }
            self.active.push(Box::pin(async move {
                let run = match pair {
                    Ok((fs, ds)) => execute::run(registration, storage, fs, ds, stop).await,
                    Err(error) => execute::Run::Finished {
                        execution: Box::new(Execution::NotStarted(error.into())),
                        after: None,
                        state_error: None,
                    },
                };
                Finished {
                    permit,
                    entry: id,
                    resource,
                    run,
                }
            }));
            self.stats.dispatched = dispatched;
            self.stats.max_active = self.stats.max_active.max(self.active.len());
        }
        Ok(())
    }
    fn release_resource(
        &mut self,
        resource: Option<Resource>,
        now: AbsoluteTime,
    ) -> Result<(), ProtocolError> {
        if let Some(resource) = resource {
            self.resources.remove(&resource);
            if !self.stop.is_requested()
                && let Some(wait) = self.waiting.get_mut(&resource)
            {
                if let Some(key) = wait.pop_front() {
                    self.queue.insert(key, now)?;
                }
                if wait.is_empty() {
                    self.waiting.remove(&resource);
                }
            }
        }
        Ok(())
    }
    fn finish(&mut self, finished: Finished) -> Event {
        let key = finished.permit.key();
        let checked = if self.stop.is_requested() {
            Ok(self.last_now)
        } else {
            self.now()
        };
        let (now, mut scheduling_error) = match checked {
            Ok(now) => (now, None),
            Err(error) => {
                self.halt(error.into());
                (self.last_now, Some(error))
            }
        };
        let repeat = match &finished.run {
            execute::Run::Finished {
                execution,
                after,
                state_error,
            } => {
                !self.stop.is_requested()
                    && execution.repeatable()
                    && state_error.is_none()
                    && after
                        .as_ref()
                        .is_some_and(|state| execute::blocked(state).is_none())
            }
            _ => false,
        };
        let delay = if repeat {
            self.catalog
                .entry(finished.entry)
                .and_then(|r| r.registration.policy.repeat_delay_us)
        } else {
            None
        };
        let due = delay.and_then(|delay| match now.as_micros().checked_add(delay) {
            Some(value) if value != u64::MAX => Some(AbsoluteTime::from_micros(value)),
            _ => {
                scheduling_error = Some(ProtocolError::Overflow);
                None
            }
        });
        if let Err(error) = self.queue.finish(&finished.permit, due) {
            scheduling_error = Some(error);
        }
        if let Err(error) = self.release_resource(finished.resource, now) {
            scheduling_error = Some(error);
        }
        if let Some(error) = scheduling_error {
            self.halt(error.into());
        }
        match finished.run {
            execute::Run::Skipped { reason, state } => {
                self.stats.skipped += 1;
                Event::Skipped {
                    entry: finished.entry,
                    reason,
                    state,
                }
            }
            execute::Run::Finished {
                execution,
                after,
                state_error,
            } => {
                let execution = *execution;
                if matches!(execution, Execution::NotStarted(_)) {
                    self.stats.not_started += 1;
                } else {
                    self.stats.started += 1;
                    self.stats.settled += 1;
                }
                Event::Settled(Box::new(Completed {
                    entry: finished.entry,
                    task_id: key,
                    execution,
                    after,
                    state_error,
                    scheduling_error,
                }))
            }
        }
    }
    /// Drive until the next actual result/status or settled worker stop. Stop and
    /// coordinator errors forbid new dispatch, request Pause, and keep polling
    /// original active futures. The first coordinator failure is returned only
    /// after their typed results have all been yielded. No background task is
    /// spawned. Keep polling after an event until None or terminal Err.
    pub async fn next(&mut self) -> Result<Option<Event>, Error> {
        loop {
            if !self.stop.is_requested() {
                match self.now() {
                    Ok(now) if now >= self.options.until => self.stop.request(),
                    Ok(now) => {
                        if let Err(error) = self.dispatch(now) {
                            self.halt(error);
                        }
                    }
                    Err(error) => self.halt(error.into()),
                }
            }
            if self.active.is_empty()
                && (self.stop.is_requested() || self.queue.next_due().is_none())
            {
                self.stop.retire_waiter();
                return match self.failure.take() {
                    Some(error) => Err(error),
                    None => Ok(None),
                };
            }
            let mut timer = if self.stop.is_requested() {
                None
            } else {
                let due = if self.active.len() < self.options.max_running {
                    self.queue.next_due()
                } else {
                    None
                };
                let target = due.map_or(self.options.until, |due| due.min(self.options.until));
                match Deadline::at(self.sources.clock.clone(), target) {
                    Ok(timer) => Some(timer),
                    Err(error) => {
                        self.halt(error.into());
                        None
                    }
                }
            };
            if self.active.is_empty() && self.stop.is_requested() {
                continue;
            }
            enum Wake {
                Finished(usize, Box<Finished>),
                Tick,
                Error(ProtocolError),
            }
            let stop = self.stop.clone();
            let stopping = stop.is_requested();
            let wake = poll_fn(|cx| {
                let len = self.active.len();
                for offset in 0..len {
                    let index = (self.cursor + offset) % len;
                    if let Poll::Ready(done) = self.active[index].as_mut().poll(cx) {
                        return Poll::Ready(Wake::Finished(index, Box::new(done)));
                    }
                }
                if !stopping {
                    match stop.poll(cx) {
                        Poll::Ready(Ok(())) => return Poll::Ready(Wake::Tick),
                        Poll::Ready(Err(error)) => return Poll::Ready(Wake::Error(error)),
                        Poll::Pending => {}
                    }
                    if let Some(timer) = timer.as_mut() {
                        match Pin::new(timer).poll(cx) {
                            Poll::Ready(Ok(())) => return Poll::Ready(Wake::Tick),
                            Poll::Ready(Err(error)) => return Poll::Ready(Wake::Error(error)),
                            Poll::Pending => {}
                        }
                    }
                }
                Poll::Pending
            })
            .await;
            match wake {
                Wake::Finished(index, finished) => {
                    drop(self.active.swap_remove(index));
                    self.cursor = if self.active.is_empty() {
                        0
                    } else {
                        index % self.active.len()
                    };
                    return Ok(Some(self.finish(*finished)));
                }
                Wake::Tick => {}
                Wake::Error(error) => self.halt(error.into()),
            }
        }
    }
}
