//! Multi-query ownership and failure isolation around the existing resolver.
use crate::ports::{Bounds, Close, NativeFailure, Operation, Provider, Shared, Value};
use crate::refresh;
use gnunet_gns::{EffectId, EffectKind, Failure, Lookup, QueryId, Record, Resolver};
use gnunet_types::{AbsoluteTime, Error};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::time::{Instant, Sleep};

type Op<P> = <P as Provider>::Operation;
type NativeError<P> = <Op<P> as Operation>::Error;
type NativeReport<P> = <Op<P> as Operation>::Report;
/// An observation with this provider's concrete error and retirement report.
pub type ProviderEvent<'a, P> = Event<'a, NativeError<P>, NativeReport<P>>;

/// A distinct native or local receipt failure. Native payloads stay owned.
#[derive(Debug)]
pub enum Cause<E> {
    /// Actual native/source error.
    Native(E),
    /// Wrong receipt kind, bounded-resource rejection or pure processing error.
    Protocol(Error),
    /// Actual NAMECACHE status, which is not an acknowledgement of success.
    CacheStore(i32),
}
/// An event releases its actual cause/report to the caller exactly once. The
/// caller must preserve those facts alongside the final result, including a
/// successful lookup whose optional cache insertion or retirement failed.
#[derive(Debug)]
pub enum Event<'a, E, R> {
    /// One original native operation was admitted, not completed.
    Started {
        /// Original logical query.
        query: QueryId<'a>,
        /// Exact original dependency effect.
        effect: EffectId<'a>,
    },
    /// One correctly typed actual observation was consumed by the resolver.
    Observed {
        /// Original logical query.
        query: QueryId<'a>,
        /// Exact original dependency effect.
        effect: EffectId<'a>,
    },
    /// A callback really arrived after the original bound. Preserve its facts
    /// without granting it authority to finish the logical lookup.
    LateObservation {
        /// Original logical query.
        query: QueryId<'a>,
        /// Exact original dependency effect.
        effect: EffectId<'a>,
        /// Actual late observation with its owned native result.
        value: Result<Value, E>,
    },
    /// A constructor refused after the original bound; retain both timeout
    /// semantics and the actual refusal. No replacement attempt is admitted.
    LateRefusal {
        /// Original logical query.
        query: QueryId<'a>,
        /// Exact original dependency effect.
        effect: EffectId<'a>,
        /// Original typed native error.
        error: E,
    },
    /// A bad candidate did not exhaust or restart its original DHT GET.
    Ignored {
        /// Original logical query.
        query: QueryId<'a>,
        /// Exact original dependency effect.
        effect: EffectId<'a>,
        /// Original protocol or validation reason.
        reason: Error,
    },
    /// Only this exact effect failed. The optional second error is a distinct
    /// pure receipt failure; neither cause is replaced by a diagnostic string.
    Failed {
        /// Original logical query.
        query: QueryId<'a>,
        /// Exact original dependency effect.
        effect: EffectId<'a>,
        /// Actual failure category and owned original error.
        cause: Cause<E>,
        /// Independent failure while delivering this effect receipt.
        receipt_error: Option<Error>,
    },
    /// Native-only guard failed before any canonical time read. Its reason is
    /// retained for the exact effect's later clock-dependent failure receipt.
    GuardFailed {
        /// Original logical query.
        query: QueryId<'a>,
        /// Exact original dependency effect.
        effect: EffectId<'a>,
        /// Original typed native error.
        error: E,
    },
    /// This original request's fixed native/logical bound elapsed. Actual
    /// operation retirement remains owned; this is not its Closed report.
    Expired {
        /// Original logical query.
        query: QueryId<'a>,
    },
    /// Actual progress of this original operation's retained close work.
    Retiring {
        /// Original logical query.
        query: QueryId<'a>,
        /// Exact original dependency effect.
        effect: EffectId<'a>,
    },
    /// A distinct error from original cancellation/retirement, still not Closed.
    RetireFailed {
        /// Original logical query.
        query: QueryId<'a>,
        /// Exact original dependency effect.
        effect: EffectId<'a>,
        /// Original typed native error.
        error: E,
    },
    /// Original native operation actually relinquished its work.
    Retired {
        /// Original logical query.
        query: QueryId<'a>,
        /// Exact original dependency effect.
        effect: EffectId<'a>,
        /// Actual retirement report from the original native operation.
        report: R,
    },
    /// An owned query result is now available, and its operation has retired.
    /// A service must still encode/write it on the original client connection.
    Ready {
        /// Original logical query.
        query: QueryId<'a>,
    },
    /// Actual independent cache-refresh observation. It carries no foreground
    /// query/effect identity and cannot complete or cancel a caller lookup.
    Refresh(refresh::Event<E, R>),
    /// Actual process/shared-source observation, independent of other queries.
    Shared(Shared<E>),
    /// All native operations and provider shared resources actually retired.
    /// Untaken logical results may remain for the caller to consume.
    Stopped,
}
#[derive(Clone, Copy)]
enum Kind {
    Revocation,
    Cache,
    Remote,
    CachePut,
    Nameserver,
    Dns,
    System,
    Service,
}
impl Kind {
    fn of(effect: &EffectKind) -> Self {
        match effect {
            EffectKind::Revocation { .. } => Self::Revocation,
            EffectKind::Cache { .. } => Self::Cache,
            EffectKind::Remote { .. } => Self::Remote,
            EffectKind::CachePut { .. } => Self::CachePut,
            EffectKind::Nameserver { .. } => Self::Nameserver,
            EffectKind::Dns { .. } => Self::Dns,
            EffectKind::System { .. } => Self::System,
            EffectKind::Service { .. } => Self::Service,
        }
    }
    fn accepts(self, value: &Value) -> bool {
        matches!(
            (self, value),
            (Self::Revocation, Value::Revocation(_))
                | (Self::Cache, Value::Cache(_))
                | (Self::Remote, Value::Block(_) | Value::End)
                | (Self::CachePut, Value::Stored(_))
                | (Self::Service, Value::Service(_))
                | (Self::Nameserver, Value::Addresses { .. })
                | (Self::Dns | Self::System, Value::Records { .. })
        )
    }
}
struct Task<'a, O: Operation> {
    effect: EffectId<'a>,
    kind: Kind,
    operation: O,
    closing: bool,
    close_error: Option<O::Error>,
}
struct Entry<'a, O: Operation> {
    query: QueryId<'a>,
    bounds: Bounds,
    alarm: Option<Pin<Box<Sleep>>>,
    task: Option<Task<'a, O>>,
    // A guard can fail while canonical time is unavailable. Do not sample time
    // here or silently turn a CachePut failure into a fabricated Stored reply.
    failed: Option<(EffectId<'a>, Error, u32)>,
    result: Option<Result<Vec<Record>, Failure>>,
    announced: bool,
}
/// Bounded business manager. It creates no listener, dependency source, broker,
/// key, thread or detached task. The future SERVICE owns the same SharedClock
/// and calls poll_native_guard before reading it, then poll with that sample.
///
/// Native failures are per operation. A shared-source failure is an event and
/// never clears unrelated requests. A later source recovery does not recreate
/// an old query, renew its Bounds, or replay an exposed CachePut.
pub struct Manager<'a, P: Provider> {
    resolver: Resolver<'a>,
    provider: P,
    entries: Vec<Entry<'a, Op<P>>>,
    limits: gnunet_gns::Limits,
    cursor: usize,
    phase: usize,
    closing: bool,
    stopped: bool,
    shared_close_error: Option<NativeError<P>>,
    refresh: refresh::Pool<Op<P>>,
}
impl<'a, P: Provider> Manager<'a, P> {
    /// Reserve one bounded query/operation table; starts no native work.
    pub fn new(
        instance: &'a mut gnunet_gns::Instance,
        provider: P,
        limits: gnunet_gns::Limits,
    ) -> Result<Self, Error> {
        Self::new_with_refresh(instance, provider, limits, refresh::Limits::default())
    }
    /// Construct explicit independently bounded near-expiry cache refresh work.
    /// Zero jobs disables even the pure optional hint allocation.
    pub fn new_with_refresh(
        instance: &'a mut gnunet_gns::Instance,
        provider: P,
        limits: gnunet_gns::Limits,
        mut refresh_limits: refresh::Limits,
    ) -> Result<Self, Error> {
        if !limits.cache {
            refresh_limits.jobs = 0;
        }
        let _capacity = limits
            .queries
            .checked_add(refresh_limits.jobs)
            .ok_or(Error::Overflow)?;
        let mut resolver = Resolver::new(instance, limits)?;
        let refresh = refresh::Pool::new(refresh_limits, limits)?;
        resolver.enable_cache_refresh(refresh.enabled());
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(limits.queries)
            .map_err(|_| Error::Capacity)?;
        Ok(Self {
            resolver,
            provider,
            entries,
            limits,
            cursor: 0,
            phase: 0,
            closing: false,
            stopped: false,
            shared_close_error: None,
            refresh,
        })
    }
    /// Admit one original explicit-zone request. No native provider work starts
    /// until poll; the same Bounds is passed to all later dependency attempts.
    pub fn lookup(
        &mut self,
        request: Lookup<'_>,
        bounds: Bounds,
        now: AbsoluteTime,
    ) -> Result<QueryId<'a>, Error> {
        if self.closing {
            return Err(Error::Closed);
        }
        if bounds.expired(now) {
            return Err(Error::Timeout);
        }
        if self.entries.len() == self.limits.queries {
            return Err(Error::WouldBlock);
        }
        let query = self.resolver.lookup(request)?;
        if bounds.expired(now) {
            self.resolver.cancel(query)?;
            let _cancelled = self.resolver.take_result(query)?;
            return Err(Error::Timeout);
        }
        self.entries.push(Entry {
            query,
            bounds,
            alarm: None,
            task: None,
            failed: None,
            result: None,
            announced: false,
        });
        Ok(query)
    }
    /// Original requests, including untaken results and retiring operations.
    pub fn queries(&self) -> usize {
        self.entries.len()
    }
    /// Actual operation owners, including all cancellation/close debt.
    pub fn operations(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.task.is_some())
            .count()
            + self.refresh.operations()
    }
    /// Actual bounded background observations, independent of caller results.
    pub fn refresh_stats(&self) -> refresh::Stats {
        self.refresh.stats()
    }
    /// Earliest original canonical bound. Native alarms remain independent.
    pub fn next_wakeup(&self) -> Option<AbsoluteTime> {
        self.entries
            .iter()
            .filter(|entry| entry.result.is_none())
            .map(|entry| entry.bounds.until())
            .chain(self.refresh.next_until())
            .min()
    }
    /// Earliest original native query bound; provider native guards additionally
    /// cover their source/partial-frame/cancellation deadlines.
    pub fn next_native_deadline(&self) -> Option<Instant> {
        self.entries
            .iter()
            .filter(|entry| entry.result.is_none())
            .map(|entry| entry.bounds.hard())
            .chain(self.refresh.next_hard())
            .min()
    }
    /// Read-only provider state, including its actual source recovery state.
    pub fn provider(&self) -> &P {
        &self.provider
    }
    /// Explicit provider recovery/control. The caller must obey the same
    /// original-owner/source contracts; this does not renew any query budget.
    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }
    /// True only after stop and actual retirement, never merely timeout/Drop.
    pub fn is_quiescent(&self) -> bool {
        self.closing
            && self.operations() == 0
            && self.refresh.is_empty()
            && self.provider.is_closed()
    }
    /// Cancel only the exact original query, clock-free. Its original operation
    /// remains until poll_close reports actual Closed. Foreign/stale IDs fail.
    pub fn cancel(&mut self, query: QueryId<'_>) -> Result<(), Error> {
        let i = self.index(query)?;
        self.finish(i, Failure::Cancelled)
    }
    /// Stop new admissions once. Every original operation is fenced/retired;
    /// all native causes remain in per-operation or shared events. No new grace
    /// period, source time, epoch or replacement provider is constructed here.
    pub fn begin_close(&mut self) -> Result<(), Error> {
        if self.closing {
            return Ok(());
        }
        self.closing = true;
        self.resolver.enable_cache_refresh(false);
        self.refresh.begin_close();
        let mut first = None;
        for i in 0..self.entries.len() {
            if let Err(error) = self.finish(i, Failure::Cancelled) {
                first.get_or_insert(error);
            }
        }
        self.shared_close_error = self.provider.begin_close();
        first.map_or(Ok(()), Err)
    }
    /// Consume the actual result only after its original native task retired.
    /// Query capacity is released here, not on admission/write or a timer.
    pub fn take_result(
        &mut self,
        query: QueryId<'_>,
    ) -> Result<Option<Result<Vec<Record>, Failure>>, Error> {
        let i = self.index(query)?;
        if self.entries[i].task.is_some()
            || self.entries[i].failed.is_some()
            || self.entries[i].result.is_none()
        {
            return Ok(None);
        }
        Ok(self.entries.swap_remove(i).result)
    }
    fn index(&self, query: QueryId<'_>) -> Result<usize, Error> {
        self.entries
            .iter()
            .position(|entry| entry.query == query)
            .ok_or(Error::Stale)
    }
    fn retire(&mut self, i: usize) {
        if let Some(task) = &mut self.entries[i].task
            && !task.closing
        {
            task.closing = true;
            task.close_error = task.operation.begin_close();
        }
    }
    fn collect(&mut self, i: usize) -> Result<(), Error> {
        if self.entries[i].result.is_none() {
            let query = self.entries[i].query;
            if let Some(result) = self.resolver.take_result(query)? {
                self.entries[i].result = Some(result);
                self.entries[i].alarm = None;
                self.entries[i].failed = None;
                self.retire(i);
            }
        }
        Ok(())
    }
    fn finish(&mut self, i: usize, failure: Failure) -> Result<(), Error> {
        self.collect(i)?;
        if self.entries[i].result.is_none() {
            let query = self.entries[i].query;
            self.resolver.cancel(query)?;
            let _cancelled = self.resolver.take_result(query)?.ok_or(Error::NotReady)?;
            self.entries[i].result = Some(Err(failure));
        }
        self.entries[i].failed = None;
        self.entries[i].alarm = None;
        self.retire(i);
        Ok(())
    }
    fn fail_effect(
        &mut self,
        i: usize,
        effect: EffectId<'a>,
        reason: Error,
        spent: u32,
        now: AbsoluteTime,
    ) -> Option<Error> {
        let result = self
            .resolver
            .failed_counted(effect, reason, spent, now.as_micros());
        let mut secondary = result.err();
        if let Err(error) = self.collect(i) {
            secondary.get_or_insert(error);
        }
        // An unsuccessful receipt may leave the pure effect pending. Fence that
        // request explicitly instead of dropping the native task and silently
        // admitting the same action again on a replacement source.
        if secondary.is_some()
            && self.entries[i].result.is_none()
            && let Err(error) = self.finish(i, Failure::Fault(reason))
        {
            secondary.get_or_insert(error);
        }
        self.retire(i);
        secondary
    }
    /// Native-only first phase, also usable when the canonical clock is lost.
    /// Checks original request alarms and all retained native source guards;
    /// never admits a new effect or processes records with a guessed timestamp.
    pub fn poll_native_guard(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Result<Option<ProviderEvent<'a, P>>, Error> {
        if let Some(error) = self.shared_close_error.take() {
            return Ok(Some(Event::Shared(Shared::Failed(error))));
        }
        for i in 0..self.entries.len() {
            if self.entries[i].result.is_none() {
                let bounds = self.entries[i].bounds;
                let alarm = self.entries[i]
                    .alarm
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(bounds.hard())));
                let expired = Instant::now() >= bounds.hard() || alarm.as_mut().poll(cx).is_ready();
                if expired {
                    let query = self.entries[i].query;
                    self.finish(i, Failure::Fault(Error::Timeout))?;
                    return Ok(Some(Event::Expired { query }));
                }
            }
            let entry = &mut self.entries[i];
            if let Some(task) = &mut entry.task
                && let Some(error) = task.operation.poll_native_guard(cx)
            {
                let query = entry.query;
                let effect = task.effect;
                if !task.closing && entry.result.is_none() && entry.failed.is_none() {
                    entry.failed = Some((effect, error.reason(), error.spent()));
                }
                self.retire(i);
                return Ok(Some(Event::GuardFailed {
                    query,
                    effect,
                    error,
                }));
            }
        }
        if !self.closing
            && let Some(intent) = self.resolver.take_cache_refresh()
            && let Some(event) = self.refresh.admit(intent)
        {
            return Ok(Some(Event::Refresh(event)));
        }
        if let Some(event) = self.refresh.guard(cx) {
            return Ok(Some(Event::Refresh(event)));
        }
        if let Some(error) = self.provider.poll_native_guard(cx) {
            return Ok(Some(Event::Shared(Shared::Failed(error))));
        }
        Ok(None)
    }
    fn retirement(&mut self, cx: &mut Context<'_>) -> Option<ProviderEvent<'a, P>> {
        for _ in 0..self.entries.len() {
            let i = self.cursor % self.entries.len();
            self.cursor = (i + 1) % self.entries.len();
            let entry = &mut self.entries[i];
            let Some(task) = &mut entry.task else {
                continue;
            };
            if !task.closing {
                continue;
            }
            let query = entry.query;
            let effect = task.effect;
            if let Some(error) = task.close_error.take() {
                return Some(Event::RetireFailed {
                    query,
                    effect,
                    error,
                });
            }
            match task.operation.poll_close(cx) {
                Poll::Pending => {}
                Poll::Ready(Close::Activity) => return Some(Event::Retiring { query, effect }),
                Poll::Ready(Close::Failed(error)) => {
                    return Some(Event::RetireFailed {
                        query,
                        effect,
                        error,
                    });
                }
                Poll::Ready(Close::Closed(report)) => {
                    entry.task = None;
                    return Some(Event::Retired {
                        query,
                        effect,
                        report,
                    });
                }
            }
        }
        None
    }
    /// Continue original cleanup during clock failure/Stop. This method starts
    /// no ordinary provider effect and requires no canonical-clock sample.
    pub fn poll_close(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<ProviderEvent<'a, P>, Error>> {
        if let Some(event) = self.poll_native_guard(cx)? {
            return Poll::Ready(Ok(event));
        }
        if let Some(event) = self.retirement(cx) {
            return Poll::Ready(Ok(event));
        }
        if let Some(event) = self.refresh.poll_close(cx) {
            return Poll::Ready(Ok(Event::Refresh(event)));
        }
        if let Poll::Ready(event) = self.provider.poll_shared(cx) {
            return Poll::Ready(Ok(Event::Shared(event)));
        }
        if self.is_quiescent() && !self.stopped {
            self.stopped = true;
            return Poll::Ready(Ok(Event::Stopped));
        }
        Poll::Pending
    }
    fn receive(
        &mut self,
        cx: &mut Context<'_>,
        now: AbsoluteTime,
    ) -> Result<Option<ProviderEvent<'a, P>>, Error> {
        for _ in 0..self.entries.len() {
            let i = self.cursor % self.entries.len();
            self.cursor = (i + 1) % self.entries.len();
            let entry = &mut self.entries[i];
            let Some(task) = &mut entry.task else {
                continue;
            };
            if task.closing || entry.failed.is_some() || entry.result.is_some() {
                continue;
            }
            let query = entry.query;
            let effect = task.effect;
            let kind = task.kind;
            let value = match task.operation.poll(cx, now) {
                Poll::Pending => continue,
                Poll::Ready(value) => value,
            };
            // A callback arriving after either original boundary cannot acquire
            // receipt authority merely because polling it made native progress.
            if self.entries[i].bounds.expired(now) {
                self.finish(i, Failure::Fault(Error::Timeout))?;
                return Ok(Some(Event::LateObservation {
                    query,
                    effect,
                    value,
                }));
            }
            let value = match value {
                Ok(value) => value,
                Err(error) => {
                    let receipt_error =
                        self.fail_effect(i, effect, error.reason(), error.spent(), now);
                    return Ok(Some(Event::Failed {
                        query,
                        effect,
                        cause: Cause::Native(error),
                        receipt_error,
                    }));
                }
            };
            let spent = match &value {
                Value::Addresses { spent, .. } | Value::Records { spent, .. } => *spent,
                _ => 0,
            };
            if !kind.accepts(&value) {
                let receipt_error = self.fail_effect(i, effect, Error::Malformed, spent, now);
                return Ok(Some(Event::Failed {
                    query,
                    effect,
                    cause: Cause::Protocol(Error::Malformed),
                    receipt_error,
                }));
            }
            if let Value::Stored(status) = &value
                && *status != 1
            {
                let status = *status;
                let receipt_error = self.fail_effect(i, effect, Error::Storage, spent, now);
                return Ok(Some(Event::Failed {
                    query,
                    effect,
                    cause: Cause::CacheStore(status),
                    receipt_error,
                }));
            }
            let remote_candidate = matches!(&value, Value::Block(_));
            let result = match value {
                Value::Revocation(revoked) => self.resolver.revoked(effect, revoked),
                Value::Cache(block) => {
                    self.resolver
                        .cached(effect, block.as_deref(), now.as_micros())
                }
                Value::Stored(_) => self.resolver.cache_stored(effect, now.as_micros()),
                Value::Service(selector) => self.resolver.service(effect, selector),
                Value::Addresses { addresses, spent } => {
                    self.resolver.addresses(effect, &addresses, spent)
                }
                Value::Records { records, spent } => {
                    let mut total = 0usize;
                    let mut valid = records.len() <= self.limits.records;
                    for record in &records {
                        match total.checked_add(record.data.len()) {
                            Some(next) if next <= self.limits.record_bytes => total = next,
                            _ => {
                                valid = false;
                                break;
                            }
                        }
                    }
                    if valid {
                        let mut views = Vec::new();
                        match views.try_reserve_exact(records.len()) {
                            Ok(()) => {
                                views.extend(records.iter().map(Record::as_data));
                                self.resolver
                                    .resolved(effect, &views, spent, now.as_micros())
                            }
                            Err(_) => Err(Error::Capacity),
                        }
                    } else {
                        Err(Error::Capacity)
                    }
                }
                Value::Block(block) => self.resolver.remote_block(effect, &block, now.as_micros()),
                Value::End => self
                    .resolver
                    .failed(effect, Error::NotFound, now.as_micros()),
            };
            self.collect(i)?;
            let same = self.entries[i].result.is_none()
                && self
                    .resolver
                    .effect(query)?
                    .is_some_and(|current| current.id == effect);
            if remote_candidate
                && same
                && let Err(reason) = result
            {
                return Ok(Some(Event::Ignored {
                    query,
                    effect,
                    reason,
                }));
            }
            if !same {
                self.retire(i);
            }
            if let Err(reason) = result {
                let receipt_error = if same {
                    self.fail_effect(i, effect, reason, spent, now)
                } else {
                    None
                };
                return Ok(Some(Event::Failed {
                    query,
                    effect,
                    cause: Cause::Protocol(reason),
                    receipt_error,
                }));
            }
            return Ok(Some(Event::Observed { query, effect }));
        }
        Ok(None)
    }
    fn prepare(&mut self, now: AbsoluteTime) -> Result<Option<ProviderEvent<'a, P>>, Error> {
        for _ in 0..self.entries.len() {
            let i = self.cursor % self.entries.len();
            self.cursor = (i + 1) % self.entries.len();
            let query = self.entries[i].query;
            if let Some((effect, reason, spent)) = self.entries[i].failed.take() {
                let receipt_error = self.fail_effect(i, effect, reason, spent, now);
                return Ok(Some(Event::Failed {
                    query,
                    effect,
                    cause: Cause::Protocol(reason),
                    receipt_error,
                }));
            }
            if self.entries[i].result.is_none() && self.entries[i].bounds.expired(now) {
                self.finish(i, Failure::Fault(Error::Timeout))?;
                return Ok(Some(Event::Expired { query }));
            }
            if self.entries[i].task.is_some() {
                continue;
            }
            self.collect(i)?;
            if self.entries[i].result.is_some() {
                if !self.entries[i].announced {
                    self.entries[i].announced = true;
                    return Ok(Some(Event::Ready { query }));
                }
                continue;
            }
            if self.closing {
                continue;
            }
            let Some(effect) = self.resolver.effect(query)? else {
                return Err(Error::NotReady);
            };
            let id = effect.id;
            let kind = Kind::of(&effect.kind);
            let bounds = self.entries[i].bounds;
            // Pure effect derivation may consume time. Recheck the original
            // native boundary immediately before admitting a native operation.
            if bounds.expired(now) {
                self.finish(i, Failure::Fault(Error::Timeout))?;
                return Ok(Some(Event::Expired { query }));
            }
            match self.provider.start(&effect.kind, bounds) {
                Ok(operation) => {
                    self.entries[i].task = Some(Task {
                        effect: id,
                        kind,
                        operation,
                        closing: false,
                        close_error: None,
                    });
                    // A slow constructor is still charged to original hard.
                    if bounds.expired(now) {
                        self.finish(i, Failure::Fault(Error::Timeout))?;
                        return Ok(Some(Event::Expired { query }));
                    }
                    return Ok(Some(Event::Started { query, effect: id }));
                }
                Err(error) => {
                    if bounds.expired(now) {
                        self.finish(i, Failure::Fault(Error::Timeout))?;
                        return Ok(Some(Event::LateRefusal {
                            query,
                            effect: id,
                            error,
                        }));
                    }
                    let receipt_error = self.fail_effect(i, id, error.reason(), error.spent(), now);
                    return Ok(Some(Event::Failed {
                        query,
                        effect: id,
                        cause: Cause::Native(error),
                        receipt_error,
                    }));
                }
            }
        }
        Ok(None)
    }
    /// Drive one observation with a genuine same-clock sample. First call
    /// poll_native_guard before acquiring that sample; this method repeats the
    /// native checks so stale supplied samples cannot bypass the native hard.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        now: AbsoluteTime,
    ) -> Poll<Result<ProviderEvent<'a, P>, Error>> {
        if let Some(event) = self.poll_native_guard(cx)? {
            return Poll::Ready(Ok(event));
        }
        for _ in 0..5 {
            let phase = self.phase;
            self.phase = (phase + 1) % 5;
            let event = match phase {
                0 => self.retirement(cx),
                1 if !self.closing => self.receive(cx, now)?,
                2 => self.prepare(now)?,
                3 => match self.provider.poll_shared(cx) {
                    Poll::Pending => None,
                    Poll::Ready(event) => Some(Event::Shared(event)),
                },
                4 => {
                    if self.closing {
                        self.refresh.poll_close(cx).map(Event::Refresh)
                    } else {
                        self.refresh
                            .poll(cx, now, &mut self.provider)
                            .map(Event::Refresh)
                    }
                }
                _ => None,
            };
            if let Some(event) = event {
                return Poll::Ready(Ok(event));
            }
        }
        if self.is_quiescent() && !self.stopped {
            self.stopped = true;
            return Poll::Ready(Ok(Event::Stopped));
        }
        Poll::Pending
    }
}
