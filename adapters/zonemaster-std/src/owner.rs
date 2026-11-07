//! Actual authoritative stream/worker/cache/publication composition.
use crate::{
    Failure,
    metrics::{Counter, Metrics},
    nonce, publish,
    worker::{Completion, Pool, Ticket},
};
use gnunet_client_host::EndpointSource;
use gnunet_namecache_client_host as namecache;
use gnunet_namestore_client_host as namestore;
use gnunet_service_runtime::clock::{ClockSubscription, Deadline, RuntimeClock};
use gnunet_types::Error as Fault;
use gnunet_zonemaster::{
    material,
    schedule::{self, Core, Job, Kind, Source, Work},
};
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
mod streams;
mod work;
/// Actual original source lifetimes, worker/job and credit policy.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Existing original-MQ/record/credit budgets.
    pub namestore: namestore::Limits,
    /// Existing cache client resources.
    pub cache: namecache::Limits,
    /// Actual worker count (official default4).
    pub workers: usize,
    /// Bounded actual CPU queue.
    pub worker_queue: usize,
    /// Finite original monitor/iterator stream lifetime.
    pub source_lifetime: Duration,
    /// Finite original INIT/SYNC/partial/control bound.
    pub control_timeout: Duration,
    /// Independent retry wake, never original target reset.
    pub retry: Duration,
    /// Actual NEXT batch size, at most official1000.
    pub batch: u64,
    /// Monitor live credit, official5.
    pub monitor_credit: u64,
    /// Real concurrent original public PUT operations.
    pub publications: usize,
    /// Actual record normalization/plaintext resources.
    pub material: material::Limits,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            namestore: namestore::Limits {
                credit: 1000,
                ..Default::default()
            },
            cache: namecache::Limits {
                operations: 1000,
                block_bytes: 65519,
                ..Default::default()
            },
            workers: 4,
            worker_queue: 5000,
            source_lifetime: Duration::from_secs(86400),
            control_timeout: Duration::from_secs(10),
            retry: Duration::from_millis(100),
            batch: 1000,
            monitor_credit: 5,
            publications: 1000,
            material: Default::default(),
        }
    }
}
/// Explicit actual endpoint selectors and independent real public PUT provider.
pub struct Sources<'a> {
    /// Exact NAMESTORE monitor source selector.
    pub monitor: EndpointSource,
    /// Independent full-inventory source selector.
    pub inventory: EndpointSource,
    /// Actual NAMECACHE, absent only if disabled.
    pub cache: Option<EndpointSource>,
    /// Caller-owned actual production DHT port.
    pub publish: &'a mut dyn publish::Port,
}
/// Caller-owned original native instance brands; no key is read from a file.
pub struct Identities<'id> {
    /// Monitor/iterator domains share this explicit allocator.
    pub namestore: &'id namestore::Instance,
    /// Original cache CLIENT domain.
    pub cache: &'id namecache::Instance,
}
#[derive(Clone, Copy)]
struct Bound {
    expires: u64,
    hard: Instant,
}
impl Bound {
    fn after(now: u64, d: Duration) -> Result<Self, Fault> {
        if d.is_zero() {
            return Err(Fault::Deadline);
        }
        let delta = u64::try_from(d.as_micros()).map_err(|_| Fault::Overflow)?;
        Ok(Self {
            expires: now
                .checked_add(delta)
                .filter(|n| *n != u64::MAX)
                .ok_or(Fault::Overflow)?,
            hard: Instant::now().checked_add(d).ok_or(Fault::Overflow)?,
        })
    }
    fn live(self, now: u64) -> bool {
        self.expires > now && Instant::now() < self.hard
    }
}
struct Intent {
    limit: u64,
    bounds: Bound,
}
struct Pending {
    reply: namestore::Reply,
    received: u64,
    bounds: Bound,
}
struct Stream<'id> {
    source: Source,
    kind: Kind,
    operation: namestore::Operation<'id>,
    epoch: Option<namestore::Epoch<'id>>,
    bounds: Bound,
    initial: Option<Instant>,
    partial: Option<Instant>,
    control: Option<(namestore::Control<'id>, Bound, u64)>,
    intent: Option<Intent>,
    pending: Option<Pending>,
    terminal: Option<namestore::Progress<'id>>,
    started: bool,
    synchronized: bool,
    seen: u64,
    started_at: u64,
}
#[derive(Debug)]
struct WorkerBindingFailure {
    reason: Fault,
    reservation: Option<nonce::Receipt>,
}
impl std::fmt::Display for WorkerBindingFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "zonemaster worker binding {:?}; actual local reservation {:?}",
            self.reason, self.reservation
        )
    }
}
impl std::error::Error for WorkerBindingFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.reason)
    }
}
struct Returned {
    expires: u64,
    result: Result<material::Sealed, Fault>,
}
struct JobRow<'id> {
    job: Job,
    source: Source,
    bounds: Bound,
    ticket: Option<Ticket>,
    worker_returned: bool,
    worker_result: Option<Returned>,
    cache: Option<namecache::Operation<'id>>,
    public: bool,
    cancelled: bool,
    cancel_started: bool,
    native_retired: bool,
}
/// Real progress; no event fabricates publication, database fsync or a source ACK.
pub enum Event {
    /// Actual native source/byte/control activity.
    Activity,
    /// Real original source row admitted to processing.
    Record,
    /// Actual worker/native operation admission only.
    Admitted,
    /// Actual signed record pair returned from the original worker.
    Sealed,
    /// Actual durable local reservation, independently of subsequent sealing,
    /// cancellation or publication. It asserts no peer processing or storage.
    NonceReserved {
        /// Original sealing job whose counter was reserved.
        job: Job,
        /// Actual committed reservation, independent of later publication.
        receipt: nonce::Receipt,
    },
    /// Actual original API result/continuation only.
    Submitted,
    /// Original finite resource refused; actual retry alarm is registered.
    Backpressure,
    /// Independent original provider/cleanup error.
    Failure(Failure),
    /// All external native owners stopped; CPU join facts stay explicit.
    Stopped,
}
/// Original actual failure plus independently retained cleanup facts.
#[derive(Debug)]
pub struct Failures {
    /// Original cause.
    pub original: Option<Failure>,
    /// Independent real cleanup errors.
    pub cleanup: Vec<Failure>,
}
impl std::fmt::Display for Failures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(e) = &self.original {
            write!(f, "zonemaster: {e}")?
        }
        for e in &self.cleanup {
            write!(f, "; cleanup: {e}")?
        }
        Ok(())
    }
}
impl std::error::Error for Failures {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.cleanup.first().map(|error| error.as_ref()))
    }
}
/// Owned actual shutdown facts. Terminal producer notices are transferred once,
/// independently of logical cancellation and CPU/native cleanup failures.
#[derive(Debug)]
pub struct StopReport {
    /// Original independent cleanup errors, without replacing actual notices.
    pub failures: Vec<Failure>,
    /// Actual previously unconsumed original public terminal notices at stop.
    /// A Submitted entry remains a local full-write fact, not job success.
    pub publications: Vec<publish::Event>,
    /// Latest actual local reservation, including closed-channel completions.
    /// This is one observed transaction, not a count or remote-storage receipt.
    pub latest_nonce_reservation: Option<nonce::Receipt>,
}
/// Actual bounded owner; all source/worker/provider state lives here, no task.
pub struct Owner<'id, 'port> {
    core: Core,
    clock: Arc<dyn RuntimeClock>,
    subscription: Box<dyn ClockSubscription>,
    revision: u64,
    pure: schedule::Limits,
    ids: Identities<'id>,
    limits: Limits,
    monitor_source: EndpointSource,
    inventory_source: EndpointSource,
    monitor: Option<namestore::Monitor<'id>>,
    inventory: Option<namestore::ZoneIterator<'id>>,
    monitor_state: Option<Stream<'id>>,
    inventory_state: Option<Stream<'id>>,
    cache: Option<namecache::Client<'id>>,
    publish: &'port mut dyn publish::Port,
    pool: Pool,
    jobs: Vec<JobRow<'id>>,
    failures: Vec<Failure>,
    public_terminal: Vec<publish::Event>,
    monitor_retry: Option<Instant>,
    inventory_retry: Option<Instant>,
    publication_at: Option<u64>,
    credit_at: Option<u64>,
    native_alarm: Option<Pin<Box<Sleep>>>,
    logical_alarm: Option<Pin<Box<Deadline>>>,
    logical_at: Option<u64>,
    retry: Option<Pin<Box<Sleep>>>,
    cursor: usize,
    metrics: Metrics,
    cache_blocked: bool,
    cache_input: Option<Instant>,
    first_inventory: bool,
    stopped: bool,
    joined: bool,
}

fn reserve<T>(n: usize) -> Result<Vec<T>, Fault> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Fault::Capacity)?;
    Ok(v)
}
fn retryable(e: &gnunet_client_host::ConnectError) -> bool {
    matches!(
        e,
        gnunet_client_host::ConnectError::Protocol(
            Fault::WouldBlock | Fault::Capacity | Fault::NotReady
        )
    )
}
impl<'id, 'port> Owner<'id, 'port> {
    /// Construct actual bounded CPU workers and native client owners only after
    /// checking explicit source/clock/resource policy. Opens no socket or store.
    /// A real caller-owned publish port is mandatory; no fallback sink exists.
    pub fn new(
        ids: Identities<'id>,
        sources: Sources<'port>,
        clock: Arc<dyn RuntimeClock>,
        pure: schedule::Limits,
        limits: Limits,
        nonce: nonce::Config,
    ) -> Result<Self, Failure> {
        for source in [&sources.monitor, &sources.inventory]
            .into_iter()
            .chain(sources.cache.as_ref())
        {
            if !Arc::ptr_eq(&source.clock(), &clock) {
                return Err("zonemaster source clock differs".into());
            }
        }
        if !Arc::ptr_eq(&sources.publish.clock(), &clock) {
            return Err("zonemaster publish clock differs".into());
        }
        if limits.batch == 0
            || limits.batch > 1000
            || limits.monitor_credit == 0
            || limits.monitor_credit > limits.namestore.credit
            || limits.publications == 0
            || limits.publications > pure.jobs
            || limits.worker_queue > pure.jobs
            || limits.workers == 0
            || limits.workers > 64
            || limits.worker_queue == 0
            || limits.batch > limits.namestore.credit
            || limits.material.records > limits.namestore.records
        {
            return Err(Fault::Capacity.into());
        }
        let now = clock.sample()?.now.as_micros();
        for d in [limits.source_lifetime, limits.control_timeout, limits.retry] {
            Bound::after(now, d)?;
        }
        let core = Core::new(pure, sources.cache.is_some(), now)?;
        let subscription = clock.subscribe()?;
        let cache = sources
            .cache
            .map(|s| namecache::Client::new(ids.cache, s, limits.cache))
            .transpose()?;
        let jobs = reserve(pure.jobs)?;
        let failures = reserve(
            pure.jobs
                .checked_mul(2)
                .and_then(|n| n.checked_add(32))
                .ok_or(Fault::Overflow)?,
        )?;
        let public_terminal = reserve(limits.publications)?;
        let pool = Pool::new(limits.workers, limits.worker_queue, nonce)?;
        let mut metrics = Metrics::default();
        metrics.set(
            Counter::Workers,
            u64::try_from(limits.workers).map_err(|_| Fault::Overflow)?,
        );
        Ok(Self {
            metrics,
            core,
            clock,
            subscription,
            revision: 0,
            pure,
            ids,
            limits,
            monitor_source: sources.monitor,
            inventory_source: sources.inventory,
            monitor: None,
            inventory: None,
            monitor_state: None,
            inventory_state: None,
            cache,
            publish: sources.publish,
            pool,
            jobs,
            failures,
            public_terminal,
            monitor_retry: None,
            inventory_retry: None,
            publication_at: None,
            credit_at: None,
            native_alarm: None,
            logical_alarm: None,
            logical_at: None,
            retry: None,
            cursor: 0,
            cache_blocked: false,
            cache_input: None,
            first_inventory: true,
            stopped: false,
            joined: false,
        })
    }
    /// Actual local metrics for the existing STATISTICS publisher.
    pub const fn metrics(&self) -> Metrics {
        self.metrics
    }
    fn refresh_metrics(&mut self, now: u64) {
        self.metrics.set(
            Counter::Jobs,
            u64::try_from(self.core.pending()).unwrap_or(u64::MAX),
        );
        self.metrics.set(
            Counter::Minimum,
            self.core.minimum_relative().unwrap_or(u64::MAX),
        );
        self.metrics
            .set(Counter::Window, self.core.publication_window());
        let target = self.core.publication_delay();
        self.metrics.set(Counter::Target, target);
        self.metrics
            .set(Counter::Public, self.core.last_inventory_count());
        if let Some(s) = &self.inventory_state {
            self.metrics.set(Counter::Processed, s.seen);
            if let Some(velocity) = now.saturating_sub(s.started_at).checked_div(s.seen) {
                self.metrics.set(Counter::Velocity, velocity);
                let speed = if target == 0 {
                    u64::MAX
                } else {
                    u64::try_from(
                        u128::from(velocity.saturating_sub(target)) * 100 / u128::from(target),
                    )
                    .unwrap_or(u64::MAX)
                };
                self.metrics.set(Counter::Speed, speed);
            }
        }
    }
    fn state(&self, kind: Kind) -> Option<&Stream<'id>> {
        match kind {
            Kind::Monitor => self.monitor_state.as_ref(),
            Kind::Inventory => self.inventory_state.as_ref(),
        }
    }
    fn state_mut(&mut self, kind: Kind) -> Option<&mut Stream<'id>> {
        match kind {
            Kind::Monitor => self.monitor_state.as_mut(),
            Kind::Inventory => self.inventory_state.as_mut(),
        }
    }
    fn failure(&mut self, error: Failure) {
        self.failures.push(error)
    }
    fn delay(&mut self) -> Result<(), Failure> {
        if self.retry.is_none() {
            self.retry = Some(Box::pin(tokio::time::sleep_until(
                Instant::now()
                    .checked_add(self.limits.retry)
                    .ok_or(Fault::Overflow)?,
            )));
        }
        Ok(())
    }
    fn clock(&mut self, cx: &mut Context<'_>) -> Poll<Result<u64, Failure>> {
        match self.subscription.poll_changed(cx, self.revision) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(s)) => self.revision = s.revision,
            Poll::Pending => {}
        }
        let sample = self.clock.sample()?;
        self.revision = sample.revision;
        match self.subscription.poll_changed(cx, sample.revision) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Pending => Poll::Ready(Ok(sample.now.as_micros())),
        }
    }
    fn stop_stream(&mut self, kind: Kind) -> Result<(), Failure> {
        let state = match kind {
            Kind::Monitor => {
                if let Some(mut source) = self.monitor.take() {
                    let _actual = source.close();
                }
                self.monitor_state.take()
            }
            Kind::Inventory => {
                if let Some(mut source) = self.inventory.take() {
                    let _actual = source.close();
                }
                self.inventory_state.take()
            }
        };
        if let Some(state) = state {
            self.core.source_lost(state.source)?;
            for row in &mut self.jobs {
                if row.source == state.source {
                    row.cancelled = true;
                    if let Some(ticket) = &row.ticket {
                        ticket.cancel();
                    }
                }
            }
        }
        let at = Instant::now()
            .checked_add(self.limits.retry)
            .ok_or(Fault::Overflow)?;
        match kind {
            Kind::Monitor => self.monitor_retry = Some(at),
            Kind::Inventory => self.inventory_retry = Some(at),
        }
        Ok(())
    }
    fn cache_progress(&mut self, p: namecache::Progress<'id>) -> Result<Event, Failure> {
        self.cache_blocked = false;
        match p {
            namecache::Progress::Completed(c) => {
                self.cache_input = None;
                if let Some(i) = self.jobs.iter().position(|r| r.cache == Some(c.operation)) {
                    let job = self.jobs[i].job;
                    self.jobs[i].cache = None;
                    let success = matches!(c.outcome,namecache::Outcome::Cache(code)if code==1);
                    if !success {
                        self.failure(
                            format!(
                                "zonemaster original NAMECACHE job {job:?} result: {:?}",
                                c.outcome
                            )
                            .into(),
                        );
                    }
                    match self.core.native_done(job, false, success) {
                        Ok(()) | Err(Fault::Stale) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                Ok(Event::Submitted)
            }
            namecache::Progress::Lost { report, cause } => {
                self.cache_input = None;
                self.failure(
                    format!("zonemaster original NAMECACHE source loss: {cause:?}; {report:?}")
                        .into(),
                );
                for row in &mut self.jobs {
                    if row.cache.take().is_some() {
                        match self.core.native_done(row.job, false, false) {
                            Ok(()) | Err(Fault::Stale) => {}
                            Err(e) => return Err(e.into()),
                        }
                    }
                }
                Ok(Event::Activity)
            }
            namecache::Progress::Unavailable(e) => {
                self.cache_blocked = true;
                self.failure(e.into());
                self.delay()?;
                Ok(Event::Backpressure)
            }
            namecache::Progress::Activity { read_bytes, .. } if read_bytes > 0 => {
                if self.cache_input.is_none() {
                    self.cache_input = Some(
                        Instant::now()
                            .checked_add(self.limits.control_timeout)
                            .ok_or(Fault::Overflow)?,
                    );
                }
                Ok(Event::Activity)
            }
            namecache::Progress::Ignored { .. } => {
                self.cache_input = None;
                Ok(Event::Activity)
            }
            namecache::Progress::Closed if !self.stopped => Err(Fault::Closed.into()),
            _ => Ok(Event::Activity),
        }
    }
    fn publish_progress(&mut self, p: publish::Event) -> Result<Event, Failure> {
        match p {
            publish::Event::Submitted { job } => {
                if let Some(row) = self.jobs.iter_mut().find(|r| r.job == job && r.public) {
                    row.public = false;
                    self.core.native_done(job, true, true)?;
                }
                Ok(Event::Submitted)
            }
            publish::Event::Lost { job, error } => {
                if let Some(row) = self.jobs.iter_mut().find(|r| r.job == job && r.public) {
                    row.public = false;
                    self.core.native_done(job, true, false)?;
                }
                if let Some(e) = error {
                    self.failure(e);
                }
                Ok(Event::Activity)
            }
        }
    }
    fn worker_progress(&mut self, c: Completion) -> Result<Event, Failure> {
        let crate::worker::Returned {
            job,
            expires,
            result,
            cause,
            reservation,
        } = c.into_parts();
        // Actual IO causes cannot disappear behind stale/canceled/native-late
        // result disposal or a canonical clock that never stabilizes.
        let has_cause = cause.is_some();
        if let Some(error) = cause
            && self.pool.observe_nonce_failure(&error)
        {
            self.failure(Box::new(error));
        }
        if !has_cause
            && let Err(error) = &result
            && !matches!(error, Fault::Cancelled | Fault::Deadline)
        {
            self.failure(Box::new(*error));
        }
        let Some(i) = self.jobs.iter().position(|r| r.job == job) else {
            drop(result);
            return Ok(
                reservation.map_or(Event::Activity, |receipt| Event::NonceReserved {
                    job,
                    receipt,
                }),
            );
        };
        if self.jobs[i].bounds.expires != expires {
            return Err(Box::new(WorkerBindingFailure {
                reason: Fault::Stale,
                reservation,
            }));
        }
        if self.jobs[i].worker_returned {
            return Err(Box::new(WorkerBindingFailure {
                reason: Fault::Replay,
                reservation,
            }));
        }
        self.jobs[i].worker_returned = true;
        self.jobs[i].ticket = None;
        if self.jobs[i].cancelled || Instant::now() >= self.jobs[i].bounds.hard {
            drop(result);
            self.core.cancel(job)?;
            self.core.worker_discarded(job)?;
            return Ok(
                reservation.map_or(Event::Activity, |receipt| Event::NonceReserved {
                    job,
                    receipt,
                }),
            );
        }
        // The actual ciphertext/classification stays under the same job until
        // a stable coherent clock checks the original targets/source/revision.
        self.jobs[i].worker_result = Some(Returned { expires, result });
        Ok(
            reservation.map_or(Event::Sealed, |receipt| Event::NonceReserved {
                job,
                receipt,
            }),
        )
    }
    fn native_guard(&mut self, cx: &mut Context<'_>) -> Result<Option<Event>, Failure> {
        let native = Instant::now();
        if self.cache_input.is_some_and(|at| at <= native) {
            self.cache_input = None;
            if let Some(cache) = &mut self.cache {
                // Partial input has its own first-byte hard bound. Physically
                // retire that original MQ before releasing affected jobs.
                let actual = cache.reconnect()?;
                return self.cache_progress(actual).map(Some);
            }
        }
        for kind in [Kind::Monitor, Kind::Inventory] {
            if self.state(kind).is_some_and(|s| {
                s.terminal.is_none()
                    && (native >= s.bounds.hard
                        || s.initial.is_some_and(|n| native >= n)
                        || s.partial.is_some_and(|n| native >= n)
                        || s.control.as_ref().is_some_and(|(_, b, _)| native >= b.hard)
                        || s.intent.as_ref().is_some_and(|i| native >= i.bounds.hard)
                        || s.pending.as_ref().is_some_and(|p| native >= p.bounds.hard))
            }) {
                self.stop_stream(kind)?;
                return Ok(Some(Event::Activity));
            }
        }
        for row in &mut self.jobs {
            if native >= row.bounds.hard && !row.cancelled {
                row.cancelled = true;
                self.core.cancel(row.job)?;
                if let Some(ticket) = &row.ticket {
                    ticket.cancel();
                }
            }
        }
        for retry in [&mut self.monitor_retry, &mut self.inventory_retry] {
            if retry.is_some_and(|at| at <= native) {
                *retry = None;
            }
        }
        let mut due = self
            .jobs
            .iter()
            .filter(|r| !r.cancelled)
            .map(|r| r.bounds.hard)
            .min();
        for state in [&self.monitor_state, &self.inventory_state]
            .into_iter()
            .flatten()
            .filter(|s| s.terminal.is_none())
        {
            due = due
                .into_iter()
                .chain(Some(state.bounds.hard))
                .chain(state.initial)
                .chain(state.partial)
                .chain(state.control.as_ref().map(|(_, b, _)| b.hard))
                .chain(state.intent.as_ref().map(|i| i.bounds.hard))
                .chain(state.pending.as_ref().map(|p| p.bounds.hard))
                .min();
        }
        due = due
            .into_iter()
            .chain(self.monitor_retry)
            .chain(self.inventory_retry)
            .chain(self.cache_input)
            .min();
        if let Some(at) = due {
            let alarm = self
                .native_alarm
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(at)));
            alarm.as_mut().reset(at);
            if alarm.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        } else {
            self.native_alarm = None;
        }
        let mut child_event = None;
        // Child guards settle only their original native deadlines/queued facts;
        // they neither read/write/decode/crypto nor sample a logical clock.
        for kind in [Kind::Monitor, Kind::Inventory] {
            if self.state(kind).is_some_and(|s| s.terminal.is_none()) {
                let guarded = match kind {
                    Kind::Monitor => self
                        .monitor
                        .as_mut()
                        .map(|s| s.poll_native_guard(cx))
                        .transpose()?,
                    Kind::Inventory => self
                        .inventory
                        .as_mut()
                        .map(|s| s.poll_native_guard(cx))
                        .transpose()?,
                }
                .flatten();
                if let Some(p) = guarded {
                    if let Some(s) = self.state_mut(kind) {
                        s.initial = None;
                        s.partial = None;
                        s.control = None;
                        s.intent = None;
                        s.terminal = Some(p);
                    }
                    child_event = Some(Event::Activity);
                }
            }
        }
        if let Some(cache) = &mut self.cache
            && let Some(p) = cache.poll_native_guard(cx)
        {
            child_event = Some(self.cache_progress(p)?);
        }
        if let Some(p) = self.publish.poll_native_guard(cx) {
            child_event = Some(self.publish_progress(p?)?);
        }
        if child_event.is_some() {
            return Ok(child_event);
        }
        // CPU returns can always be drained. Cancelled results are destroyed
        // without a fake time; live results are applied only after clock ready.
        match self.pool.poll(cx) {
            Poll::Ready(Some(c)) => return self.worker_progress(c).map(Some),
            Poll::Ready(None) if !self.stopped => {
                return Err("zonemaster worker result owner ended".into());
            }
            _ => {}
        }
        Ok(None)
    }
    fn apply_workers(&mut self, now: u64) -> Result<Option<Event>, Failure> {
        if let Some(i) = self.jobs.iter().position(|r| r.worker_result.is_some()) {
            let completion = self.jobs[i].worker_result.take().ok_or(Fault::Conflict)?;
            let Returned { expires, result } = completion;
            let job = self.jobs[i].job;
            if expires != self.jobs[i].bounds.expires {
                return Err(Fault::Stale.into());
            }
            if !self.jobs[i].bounds.live(now) {
                self.jobs[i].cancelled = true;
                self.core.cancel(job)?;
                drop(result);
                self.core.worker_discarded(job)?;
                return Ok(Some(Event::Activity));
            }
            let accepted = self.core.sealed(job, result, now)?;
            if accepted && self.cache.is_none() {
                self.metrics.bump(Counter::CacheSkipped);
            }
            return Ok(Some(Event::Sealed));
        }
        Ok(None)
    }
    fn logical_guard(&mut self, cx: &mut Context<'_>, now: u64) -> Result<(), Failure> {
        let target = self
            .core
            .next_deadline()
            .into_iter()
            .chain((!self.core.inventory_live()).then_some(self.core.inventory_at()))
            .chain(self.publication_at)
            .chain(self.credit_at)
            .filter(|n| *n > now)
            .min();
        if target != self.logical_at {
            self.logical_at = target;
            self.logical_alarm = target
                .map(|n| {
                    Deadline::at(
                        self.clock.clone(),
                        gnunet_types::AbsoluteTime::from_micros(n),
                    )
                    .map(Box::pin)
                })
                .transpose()?;
        }
        if let Some(alarm) = &mut self.logical_alarm {
            match alarm.as_mut().poll(cx) {
                Poll::Ready(Err(e)) => return Err(e.into()),
                Poll::Ready(Ok(())) => {
                    self.logical_alarm = None;
                    self.logical_at = None;
                    cx.waker().wake_by_ref()
                }
                Poll::Pending => {}
            }
        }
        Ok(())
    }
    fn poll_inner(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event, Failure>> {
        if self.stopped {
            return Poll::Ready(Ok(Event::Stopped));
        }
        let native_event = self.native_guard(cx)?;
        // Deliver one retained independent failure even if a busy source always
        // has another fact ready. Native guards were still checked first.
        if let Some(error) = self.failures.pop() {
            return Poll::Ready(Ok(Event::Failure(error)));
        }
        if let Some(event) = native_event {
            return Poll::Ready(Ok(event));
        }
        // These retirements/cancelled jobs require no logical clock and must not
        // be blocked by a continuously racing source-clock revision.
        if let Some(event) = self.cancelled_work()? {
            return Poll::Ready(Ok(event));
        }
        if let Some(error) = self.failures.pop() {
            return Poll::Ready(Ok(Event::Failure(error)));
        }
        let now = match self.clock(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(r) => r?,
        };
        self.core.expire(now);
        self.refresh_metrics(now);
        if let Some(event) = self.apply_workers(now)? {
            return Poll::Ready(Ok(event));
        }
        if let Some(event) = self.terminals(now)? {
            return Poll::Ready(Ok(event));
        }
        let ready = if let Some(retry) = &mut self.retry {
            if retry.as_mut().poll(cx).is_ready() {
                self.retry = None;
                true
            } else {
                false
            }
        } else {
            true
        };
        if ready {
            if let Some(event) = self.sources(now)? {
                return Poll::Ready(Ok(event));
            }
            if let Some(event) = self.records(now)? {
                return Poll::Ready(Ok(event));
            }
            if let Some(event) = self.submit_work(now)? {
                return Poll::Ready(Ok(event));
            }
        }
        self.logical_guard(cx, now)?;
        for offset in 0..4 {
            let port = (self.cursor + offset) % 4;
            if port == 2 && self.cache_blocked && !ready {
                continue;
            }
            if port == 3 && !self.jobs.iter().any(|r| r.public) {
                continue;
            }
            let next = match port {
                0 => {
                    if self
                        .monitor_state
                        .as_ref()
                        .is_some_and(|s| s.pending.is_none() && s.terminal.is_none())
                    {
                        if let Some(monitor) = &mut self.monitor {
                            match monitor.poll(cx, None) {
                                Poll::Ready(r) => Some(self.stream_progress(
                                    Kind::Monitor,
                                    r?,
                                    self.clock.sample()?.now.as_micros(),
                                )?),
                                Poll::Pending => None,
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
                1 => {
                    if self
                        .inventory_state
                        .as_ref()
                        .is_some_and(|s| s.pending.is_none() && s.terminal.is_none())
                    {
                        if let Some(iter) = &mut self.inventory {
                            match iter.poll(cx, None) {
                                Poll::Ready(r) => Some(self.stream_progress(
                                    Kind::Inventory,
                                    r?,
                                    self.clock.sample()?.now.as_micros(),
                                )?),
                                Poll::Pending => None,
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
                2 => {
                    if let Some(cache) = &mut self.cache {
                        match cache.poll(cx, None) {
                            Poll::Ready(r) => Some(self.cache_progress(r?)?),
                            Poll::Pending => None,
                        }
                    } else {
                        None
                    }
                }
                _ => match self.publish.poll(cx) {
                    Poll::Ready(r) => Some(self.publish_progress(r?)?),
                    Poll::Pending => None,
                },
            };
            if let Some(event) = next {
                self.cursor = (port + 1) % 4;
                return Poll::Ready(Ok(event));
            }
        }
        Poll::Pending
    }
    /// Actual bounded driver. Any terminal failure first closes all original
    /// external native owners; cleanup cannot invent receipt or need new time.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event, Failure>> {
        let result = self.poll_inner(cx);
        if let Poll::Ready(Err(original)) = result {
            self.begin_stop();
            let cleanup = std::mem::take(&mut self.failures);
            Poll::Ready(Err(Box::new(Failures {
                original: Some(original),
                cleanup,
            })))
        } else {
            result
        }
    }
    /// Canceling an observation preserves all original native/worker ownership.
    pub async fn drive(&mut self) -> Result<Event, Failure> {
        poll_fn(|cx| self.poll(cx)).await
    }
    /// Physically stop original external native owners and cancel CPU interests,
    /// without waiting for CPU joins or sampling time. An enclosing foreground
    /// can close its other actual listeners/clients before calling stop to join.
    pub fn begin_stop(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        if let Some(mut s) = self.monitor.take() {
            let _actual = s.close();
        }
        if let Some(mut s) = self.inventory.take() {
            let _actual = s.close();
        }
        if let Some(cache) = &mut self.cache {
            let _actual = cache.close();
        }
        for row in &mut self.jobs {
            if let Some(ticket) = &row.ticket {
                ticket.cancel();
            }
            if row.public {
                if let Err(error) = self.publish.stop(row.job) {
                    self.failures.push(error)
                }
                row.public = false;
            }
        }
        // Close the whole original DHT source even when its last PUT already
        // completed and no job retains public debt. Idle MQ/attempt ownership
        // must also end before the original CPU workers are joined.
        if let Err(error) = self.publish.close() {
            self.failures.push(error);
        }
        // These actual terminal notices cannot be applied as business success
        // after logical stop. Transfer them to the owned shutdown report instead
        // of dropping the port queue or turning each fact into an error/log.
        for _ in 0..self.limits.publications {
            let Some(notice) = self.publish.take_settled() else {
                break;
            };
            self.public_terminal.push(notice);
        }
        self.pool.begin_stop();
    }
    /// Stop original native sources, then actually join bounded CPU work and
    /// erase retained state. No new key/clock/crypto work starts. Original joins
    /// and independent cleanup errors are preserved; dropping also joins.
    pub fn stop(&mut self) -> StopReport {
        self.begin_stop();
        if self.joined {
            return StopReport {
                failures: Vec::new(),
                publications: Vec::new(),
                latest_nonce_reservation: None,
            };
        }
        self.joined = true;

        if let Err(error) = self.pool.join_all() {
            self.failures.push(error)
        }
        while let Some(error) = self.pool.take_retired_failure() {
            self.failures.push(error);
        }
        let latest_nonce_reservation = self.pool.take_last_reservation();
        self.metrics.set(Counter::Workers, 0);
        self.jobs.clear();
        self.core.retire_all_after_native_stop();
        self.metrics.set(Counter::Jobs, 0);
        self.monitor_state = None;
        self.inventory_state = None;
        self.native_alarm = None;
        self.logical_alarm = None;
        self.retry = None;
        StopReport {
            failures: std::mem::take(&mut self.failures),
            publications: std::mem::take(&mut self.public_terminal),
            latest_nonce_reservation,
        }
    }
}
impl Drop for Owner<'_, '_> {
    fn drop(&mut self) {
        let _independent = self.stop();
    }
}
