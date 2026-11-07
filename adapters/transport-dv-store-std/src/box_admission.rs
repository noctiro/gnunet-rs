//! Actual authenticated BOX -> original durable sender fact -> live replay
//! admission. No nonce disk protocol, arbitrary verified constructor, payload
//! clone, automatic store replay or Engine/native delivery receipt is introduced.
use crate::{
    Admission, Canceled, Error, Event, Loaded, NAMESPACE, Operation, Owner, Persisted, Provider,
    Request,
};
use gnunet_service_runtime::clock::{ClockSubscription, RuntimeClock};
use gnunet_snapshot_host::worker::Job;
use gnunet_transport::PeerId;
use gnunet_transport_dv_crypto::{
    Opened, Token,
    replay::{Admitted, Reason as ReplayReason, Replay},
};
use gnunet_types::Error as Protocol;
use std::{
    cell::Cell,
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
/// Exact bounded local reason; no successful disk/worker outcome is fabricated.
#[derive(Clone, Debug)]
pub enum Reason {
    /// Original logical/source task check refused.
    Source(Protocol),
    /// Actual process clock/subscription refused or raced.
    Clock(Protocol),
    /// Immutable original native deadline elapsed.
    Deadline,
    /// Actual original provider classification/cause.
    Store(Error),
    /// An original operation/receipt/context did not match.
    Binding(Protocol),
    /// Actual current durable sender watermark is greater.
    Older {
        /// Actual original authenticated packet stamp.
        packet: u64,
        /// Actual current durable high-water fact.
        durable: u64,
    },
    /// Caller canceled this original BOX callback.
    Canceled,
    /// Actual bounded live-replay owner refused without another admission.
    Replay(ReplayReason),
}
#[derive(Clone, Copy)]
enum Boundary {
    Deadline,
    Clock(Protocol),
    Source(Protocol),
}
impl Boundary {
    fn reason(self) -> Reason {
        match self {
            Self::Deadline => Reason::Deadline,
            Self::Clock(e) => Reason::Clock(e),
            Self::Source(e) => Reason::Source(e),
        }
    }
}
/// Fixed original actual runtime clock and native hard bound. Constructor reads
/// no files/keys, creates no task and never computes a fresh relative deadline.
/// Caller supplies the SAME process clock and hard target captured at original
/// packet/task admission. Retrying does not replace/renew these private fields.
pub struct Bounds {
    clock: Arc<dyn RuntimeClock>,
    subscription: Box<dyn ClockSubscription>,
    revision: u64,
    hard: Instant,
    timer: Option<Pin<Box<Sleep>>>,
    failed: Cell<Option<Boundary>>,
}
impl Bounds {
    /// Reserve one bounded actual source listener. Expired native targets refuse
    /// before subscribing or sampling. The pure Opened retains its own original
    /// logical deadline; it is checked at every actual stage and final grant.
    pub fn new(clock: Arc<dyn RuntimeClock>, hard: Instant) -> Result<Self, Reason> {
        if Instant::now() >= hard {
            return Err(Reason::Deadline);
        }
        let subscription = clock.subscribe().map_err(Reason::Clock)?;
        if Instant::now() >= hard {
            return Err(Reason::Deadline);
        }
        Ok(Self {
            clock,
            subscription,
            revision: 0,
            hard,
            timer: None,
            failed: Cell::new(None),
        })
    }
    /// Immutable caller's original native target, not a wait-budget renewal.
    pub const fn hard(&self) -> Instant {
        self.hard
    }
    fn fail(&self, reason: Boundary) -> Reason {
        let first = self.failed.get().unwrap_or(reason);
        self.failed.set(Some(first));
        first.reason()
    }
    fn now(&self) -> Result<u64, Reason> {
        if let Some(reason) = self.failed.get() {
            return Err(reason.reason());
        }
        if Instant::now() >= self.hard {
            return Err(self.fail(Boundary::Deadline));
        }
        let sample = self
            .clock
            .sample()
            .map_err(|e| self.fail(Boundary::Clock(e)))?;
        if Instant::now() >= self.hard {
            return Err(self.fail(Boundary::Deadline));
        }
        Ok(sample.now.as_micros())
    }
    fn check(&self, opened: &Opened<'_, '_, '_>) -> Result<u64, Reason> {
        let now = self.now()?;
        opened
            .message(now)
            .map_err(|e| self.fail(Boundary::Source(e)))?;
        Ok(now)
    }
    fn poll_expiry(
        &mut self,
        cx: &mut Context<'_>,
        validate: impl FnOnce(u64) -> Result<(), Protocol>,
    ) -> Poll<Reason> {
        if let Some(reason) = self.failed.get() {
            return Poll::Ready(reason.reason());
        }
        // Native hard guard/alarm always precedes canonical sampling/races.
        if Instant::now() >= self.hard {
            return Poll::Ready(self.fail(Boundary::Deadline));
        }
        let at = self.hard.min(Instant::now() + Duration::from_millis(100));
        let alarm = self
            .timer
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(at)));
        alarm.as_mut().reset(at);
        let _wake = alarm.as_mut().poll(cx);
        match self.subscription.poll_changed(cx, self.revision) {
            Poll::Ready(Err(e)) => return Poll::Ready(self.fail(Boundary::Clock(e))),
            Poll::Ready(Ok(s)) => self.revision = s.revision,
            Poll::Pending => {}
        }
        let sample = match self.clock.sample() {
            Ok(s) => s,
            Err(e) => return Poll::Ready(self.fail(Boundary::Clock(e))),
        };
        match self.subscription.poll_changed(cx, sample.revision) {
            Poll::Ready(Err(e)) => return Poll::Ready(self.fail(Boundary::Clock(e))),
            Poll::Ready(Ok(_)) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Pending => self.revision = sample.revision,
        }
        if Instant::now() >= self.hard {
            return Poll::Ready(self.fail(Boundary::Deadline));
        }
        match validate(sample.now.as_micros()) {
            Ok(()) => Poll::Pending,
            Err(e) => Poll::Ready(self.fail(Boundary::Source(e))),
        }
    }
}
/// Exact original authenticated box identity. Constructor is private; metadata
/// cannot mint an Opened, durable receipt, replay grant or actual callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Binding<'id> {
    token: Token<'id>,
    sender: PeerId,
    target: PeerId,
    stamp: u64,
    encapsulation: [u8; 32],
    nonce: [u8; 24],
}
impl<'id> Binding<'id> {
    fn new(opened: &Opened<'_, 'id, '_>) -> Self {
        Self {
            token: opened.token(),
            sender: opened.sender(),
            target: opened.target(),
            stamp: opened.stamp(),
            encapsulation: *opened.encapsulation(),
            nonce: *opened.nonce(),
        }
    }
    /// Original actual authenticated task identity.
    pub const fn token(self) -> Token<'id> {
        self.token
    }
    /// Actual signature-verified sender of this original packet.
    pub const fn sender(self) -> PeerId {
        self.sender
    }
    /// Original authenticated target, never rebound to current identity.
    pub const fn target(self) -> PeerId {
        self.target
    }
    /// Actual original public encapsulation bound to the authenticated packet.
    pub const fn encapsulation(self) -> [u8; 32] {
        self.encapsulation
    }
    /// Exact original authenticated AEAD nonce; never a durable nonce receipt.
    pub const fn nonce(self) -> [u8; 24] {
        self.nonce
    }
    /// Actual signed sender-monotonic value.
    pub const fn stamp(self) -> u64 {
        self.stamp
    }
    fn check(&self, opened: &Opened<'_, 'id, '_>) -> Result<(), Reason> {
        if *self != Self::new(opened) {
            Err(Reason::Binding(Protocol::Stale))
        } else {
            Ok(())
        }
    }
    fn request(&self, request: Request<'id>, store: bool) -> Result<(), Reason> {
        if request.owner() != Owner::Box(self.token)
            || request.peer() != self.sender
            || request.stamp() != if store { Some(self.stamp) } else { None }
        {
            return Err(Reason::Binding(Protocol::Stale));
        }
        Ok(())
    }
}
fn same_provider(provider: &Provider<'_>, operation: &Operation<'_>) -> Result<(), Reason> {
    if Arc::ptr_eq(&provider.domain, &operation.domain) {
        Ok(())
    } else {
        Err(Reason::Binding(Protocol::Stale))
    }
}
fn load_proof(
    provider: &Provider<'_>,
    loaded: &Loaded<'_>,
    binding: Binding<'_>,
) -> Result<(), Reason> {
    same_provider(provider, loaded.operation())?;
    binding.request(loaded.operation().request(), false)?;
    if loaded.evidence().namespace() != NAMESPACE {
        return Err(Reason::Binding(Protocol::Stale));
    }
    Ok(())
}
struct Expected<'id> {
    operation: Operation<'id>,
    job: Option<Job>,
    generation: u64,
    loaded: Loaded<'id>,
}
impl<'id> Expected<'id> {
    fn persisted(&self, binding: Binding<'id>, actual: &Persisted<'id>) -> Result<(), Reason> {
        if actual.operation() != &self.operation
            || actual.job() != self.job.as_ref()
            || actual.stamp() != binding.stamp
            || actual.evidence().namespace() != NAMESPACE
            || actual.evidence().generation() != self.generation
        {
            return Err(Reason::Binding(Protocol::StaleGeneration));
        }
        binding.request(actual.operation().request(), true)?;
        if actual.canceled() {
            return Err(Reason::Canceled);
        }
        if let Some(job) = &self.job
            && (job.namespace() != NAMESPACE || actual.evidence().snapshot_job() != Some(job))
        {
            return Err(Reason::Binding(Protocol::Stale));
        }
        Ok(())
    }
}
/// Original admitted disk debt retained after cancel/expiry. It is not an IO
/// revocation/success receipt. The original Provider must still poll/drain/join.
#[derive(Debug)]
pub struct Debt<'id> {
    operation: Operation<'id>,
    job: Job,
    cancellation: Option<Result<Canceled<'id>, Error>>,
}
impl<'id> Debt<'id> {
    /// Exact original store operation.
    pub fn operation(&self) -> &Operation<'id> {
        &self.operation
    }
    /// Original actual worker Job, never a replacement.
    pub fn job(&self) -> &Job {
        &self.job
    }
    /// Actual local callback-cancel attempt, independent of the original reason.
    /// None means no currently matching pending job was observed for a cancel;
    /// it does not fabricate a successful native close or revoke.
    pub fn cancellation(&self) -> Option<&Result<Canceled<'id>, Error>> {
        self.cancellation.as_ref()
    }
}
/// Normal bounded refusal owns the unchanged original plaintext + original time
/// bounds. Drop erases plaintext; arbitrary reason data cannot create a grant.
pub struct Refused<'source, 'id, 'out> {
    opened: Opened<'source, 'id, 'out>,
    bounds: Bounds,
    binding: Binding<'id>,
    reason: Reason,
    debt: Option<Debt<'id>>,
}
impl fmt::Debug for Refused<'_, '_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DvBoxRefused")
            .field("binding", &self.binding)
            .field("reason", &self.reason)
            .field("debt", &self.debt)
            .field("plaintext", &"[REDACTED]")
            .finish()
    }
}
impl<'source, 'id, 'out> Refused<'source, 'id, 'out> {
    /// Consume this terminal owner, wipe/release its whole original buffer loan,
    /// and preserve the exact original failure/cancel/disk-debt metadata.
    pub fn recycle(self) -> Recycled<'id, 'out> {
        Recycled {
            buffer: self.opened.recycle(),
            binding: self.binding,
            reason: Some(self.reason),
            debt: self.debt,
        }
    }
    /// Original actual context, without another cryptographic constructor.
    pub const fn binding(&self) -> Binding<'id> {
        self.binding
    }
    /// Exact first refusal reason, never overwritten by cancellation failure.
    pub fn reason(&self) -> &Reason {
        &self.reason
    }
    /// Original actual disk job/cancel disposition, when a store was admitted.
    pub fn debt(&self) -> Option<&Debt<'id>> {
        self.debt.as_ref()
    }
    /// Retry only a preadmission WouldBlock with no original store debt, keeping
    /// the exact original task and native/logical bounds. All terminal canceled,
    /// expired, Unknown and replay-refused states remain sealed refusals.
    pub fn retry(self, provider: &mut Provider<'id>) -> Start<'source, 'id, 'out> {
        if self.debt.is_none()
            && matches!(&self.reason,Reason::Store(e) if matches!(&e.cause,crate::Cause::Protocol(Protocol::WouldBlock)))
        {
            start(provider, self.opened, self.bounds)
        } else {
            Start::Refused(self)
        }
    }
}
/// Consumed authentication/grant authority and the original fully erased caller
/// loan. Original optional disk debt remains explicit and must still drain.
#[must_use = "retain/repool original zeroized buffer and account for original worker debt"]
pub struct Recycled<'id, 'out> {
    buffer: &'out mut [u8],
    binding: Binding<'id>,
    reason: Option<Reason>,
    debt: Option<Debt<'id>>,
}
impl fmt::Debug for Recycled<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecycledDvBoxLoan")
            .field("binding", &self.binding)
            .field("bytes", &self.buffer.len())
            .field("reason", &self.reason)
            .field("debt", &self.debt)
            .field("contents", &"[ERASED]")
            .finish()
    }
}
impl<'id, 'out> Recycled<'id, 'out> {
    /// Return only the zeroized reusable loan and historical original metadata.
    /// This is not an Opened, durable/replay/Engine/FC success constructor.
    pub fn into_parts(
        self,
    ) -> (
        &'out mut [u8],
        Binding<'id>,
        Option<Reason>,
        Option<Debt<'id>>,
    ) {
        (self.buffer, self.binding, self.reason, self.debt)
    }
}
/// Actual beginning outcome; no original provider result is invented.
#[must_use = "retain original Waiting/Ready/Refused owner and its worker debt"]
pub enum Start<'source, 'id, 'out> {
    /// Exact equal prior durable knowledge, not a new store ACK.
    Ready(Ready<'source, 'id, 'out>),
    /// One actual higher/new watermark worker job.
    Waiting(Waiting<'source, 'id, 'out>),
    /// Bounded original refusal/backpressure, no grant.
    Refused(Refused<'source, 'id, 'out>),
}
/// Exact original durable proof plus the still-authenticated original payload.
/// A fresh same-provider load is required again immediately before every grant.
#[must_use = "consume only through grant or explicit cancellation/drop"]
pub struct Ready<'source, 'id, 'out> {
    opened: Opened<'source, 'id, 'out>,
    bounds: Bounds,
    binding: Binding<'id>,
    expected: Expected<'id>,
    persisted: Persisted<'id>,
}
/// Original higher/new watermark disk wait. Payload is borrowed exactly once,
/// not cloned. Drop erases it but never pretends to cancel actual worker debt.
#[must_use = "observe/cancel/expire original operation and drain Provider independently"]
pub struct Waiting<'source, 'id, 'out> {
    opened: Option<Opened<'source, 'id, 'out>>,
    bounds: Option<Bounds>,
    binding: Binding<'id>,
    expected: Expected<'id>,
}
fn refused<'source, 'id, 'out>(
    opened: Opened<'source, 'id, 'out>,
    bounds: Bounds,
    binding: Binding<'id>,
    reason: Reason,
) -> Refused<'source, 'id, 'out> {
    Refused {
        opened,
        bounds,
        binding,
        reason,
        debt: None,
    }
}
/// Start only from an actual AEAD+signature Opened and caller's immutable source
/// bounds. All facts come from actual private Provider load/store receipts.
pub fn start<'source, 'id, 'out>(
    provider: &mut Provider<'id>,
    opened: Opened<'source, 'id, 'out>,
    bounds: Bounds,
) -> Start<'source, 'id, 'out> {
    let binding = Binding::new(&opened);
    if let Err(reason) = bounds.check(&opened) {
        return Start::Refused(refused(opened, bounds, binding, reason));
    }
    let loaded = match provider.load(Request::box_load(binding.token, binding.sender)) {
        Ok(loaded) => loaded,
        Err(e) => return Start::Refused(refused(opened, bounds, binding, Reason::Store(e))),
    };
    if let Err(reason) = load_proof(provider, &loaded, binding) {
        return Start::Refused(refused(opened, bounds, binding, reason));
    }
    if let Some(durable) = loaded.value()
        && durable > binding.stamp
    {
        return Start::Refused(refused(
            opened,
            bounds,
            binding,
            Reason::Older {
                packet: binding.stamp,
                durable,
            },
        ));
    }
    if let Err(reason) = bounds.check(&opened) {
        return Start::Refused(refused(opened, bounds, binding, reason));
    }
    match provider.store(Request::box_store(
        binding.token,
        binding.sender,
        binding.stamp,
    )) {
        Err(e) => Start::Refused(refused(opened, bounds, binding, Reason::Store(e))),
        Ok(Admission::Known(persisted)) => {
            let expected = Expected {
                operation: persisted.operation().clone(),
                job: None,
                generation: loaded.evidence().generation(),
                loaded,
            };
            if let Err(reason) = expected.persisted(binding, &persisted) {
                return Start::Refused(refused(opened, bounds, binding, reason));
            }
            if let Err(reason) = same_provider(provider, &expected.operation) {
                return Start::Refused(refused(opened, bounds, binding, reason));
            }
            Start::Ready(Ready {
                opened,
                bounds,
                binding,
                expected,
                persisted,
            })
        }
        Ok(Admission::Queued { operation, job }) => {
            let Some(generation) = loaded.evidence().generation().checked_add(1) else {
                let cancellation = Some(provider.cancel(&operation));
                return Start::Refused(Refused {
                    opened,
                    bounds,
                    binding,
                    reason: Reason::Binding(Protocol::Overflow),
                    debt: Some(Debt {
                        operation,
                        job,
                        cancellation,
                    }),
                });
            };
            let expected = Expected {
                operation,
                job: Some(job),
                generation,
                loaded,
            };
            let mut waiting = Waiting {
                opened: Some(opened),
                bounds: Some(bounds),
                binding,
                expected,
            };
            let checked = same_provider(provider, &waiting.expected.operation)
                .and_then(|()| binding.request(waiting.expected.operation.request(), true))
                .and_then(|()| {
                    if waiting
                        .expected
                        .job
                        .as_ref()
                        .is_none_or(|j| j.namespace() != NAMESPACE)
                        || provider.pending().is_none_or(|(op, job)| {
                            op != &waiting.expected.operation
                                || Some(job) != waiting.expected.job.as_ref()
                        })
                    {
                        Err(Reason::Binding(Protocol::StaleGeneration))
                    } else {
                        Ok(())
                    }
                });
            if let Err(reason) = checked {
                match waiting.abort(provider, reason) {
                    Some(refused) => Start::Refused(refused),
                    None => Start::Waiting(waiting),
                }
            } else {
                Start::Waiting(waiting)
            }
        }
    }
}
/// A complete event observation preserves unrelated events and original waits.
#[must_use = "retain the returned original wait/ready/refusal"]
pub enum Observation<'source, 'id, 'out> {
    /// Event belonged to a different original operation.
    Unrelated(Waiting<'source, 'id, 'out>),
    /// Actual original successful durable receipt.
    Ready(Ready<'source, 'id, 'out>),
    /// Canceled/expired/unknown/refused; no grant.
    Refused(Refused<'source, 'id, 'out>),
    /// Original wait was already explicitly finished.
    Closed,
}
impl<'source, 'id, 'out> Waiting<'source, 'id, 'out> {
    /// Actually request original callback cancellation before recycling the
    /// erased loan. Store job remains in Provider; return its original tombstone
    /// metadata for real drain. None means a previous cancel/expiry already
    /// transferred this loan to its returned Refused, never a fabricated loan.
    pub fn recycle(mut self, provider: &mut Provider<'id>) -> Option<Recycled<'id, 'out>> {
        self.cancel(provider).map(Refused::recycle)
    }
    /// Original actual queued store operation.
    pub fn operation(&self) -> &Operation<'id> {
        &self.expected.operation
    }
    /// Original actual worker Job; never a queued==persisted statement.
    pub fn job(&self) -> Option<&Job> {
        self.expected.job.as_ref()
    }
    /// Exact original packet task/source context.
    pub const fn binding(&self) -> Binding<'id> {
        self.binding
    }
    fn abort(
        &mut self,
        provider: &mut Provider<'id>,
        reason: Reason,
    ) -> Option<Refused<'source, 'id, 'out>> {
        let bounds = self.bounds.take()?;
        let opened = self.opened.take()?;
        let debt = self.expected.job.as_ref().map(|job| {
            let cancellation = provider
                .pending()
                .filter(|(op, j)| *op == &self.expected.operation && *j == job)
                .map(|_| ());
            let cancellation = cancellation.map(|()| provider.cancel(&self.expected.operation));
            Debt {
                operation: self.expected.operation.clone(),
                job: job.clone(),
                cancellation,
            }
        });
        Some(Refused {
            opened,
            bounds,
            binding: self.binding,
            reason,
            debt,
        })
    }
    /// Cancel callback only, retaining/reporting the exact original disk debt.
    /// A completed disk mutation is not falsely retracted or replayed.
    pub fn cancel(&mut self, provider: &mut Provider<'id>) -> Option<Refused<'source, 'id, 'out>> {
        self.abort(provider, Reason::Canceled)
    }
    /// Native hard alarm precedes canonical clock sampling/race. Caller polls
    /// this alongside actual Provider events; expiry suppresses success while
    /// Provider retains its real noninterruptible disk job/drain ownership.
    pub fn poll_expired(
        &mut self,
        cx: &mut Context<'_>,
        provider: &mut Provider<'id>,
    ) -> Poll<Option<Refused<'source, 'id, 'out>>> {
        let (Some(opened), Some(bounds)) = (self.opened.as_ref(), self.bounds.as_mut()) else {
            return Poll::Ready(None);
        };
        match bounds.poll_expiry(cx, |now| opened.message(now).map(|_| ())) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(reason) => Poll::Ready(self.abort(provider, reason)),
        }
    }
    /// Only exact original actual successful private Persisted can become Ready.
    /// A wrong/other event is returned as Unrelated, not consumed/rebound.
    pub fn observe(
        mut self,
        provider: &mut Provider<'id>,
        event: &Event<'id>,
    ) -> Observation<'source, 'id, 'out> {
        let (Some(opened), Some(bounds)) = (self.opened.as_ref(), self.bounds.as_ref()) else {
            return Observation::Closed;
        };
        if let Err(reason) = bounds.check(opened) {
            return match self.abort(provider, reason) {
                Some(r) => Observation::Refused(r),
                None => Observation::Closed,
            };
        }
        match event {
            Event::Committed(persisted) if persisted.operation() == &self.expected.operation => {
                if let Err(reason) = self.expected.persisted(self.binding, persisted) {
                    return match self.abort(provider, reason) {
                        Some(r) => Observation::Refused(r),
                        None => Observation::Closed,
                    };
                }
                let (Some(opened), Some(bounds)) = (self.opened.take(), self.bounds.take()) else {
                    return Observation::Closed;
                };
                Observation::Ready(Ready {
                    opened,
                    bounds,
                    binding: self.binding,
                    expected: self.expected,
                    persisted: persisted.clone(),
                })
            }
            Event::Failed {
                operation: Some(operation),
                job,
                error,
                ..
            } if operation == &self.expected.operation
                && job.as_ref() == self.expected.job.as_ref() =>
            {
                match self.abort(provider, Reason::Store(error.clone())) {
                    Some(r) => Observation::Refused(r),
                    None => Observation::Closed,
                }
            }
            Event::Ended if provider.ended => {
                match self.abort(provider, Reason::Binding(Protocol::OutcomeUnknown)) {
                    Some(r) => Observation::Refused(r),
                    None => Observation::Closed,
                }
            }
            _ => Observation::Unrelated(self),
        }
    }
}
/// Private-constructor actual durable fact + original live replay admission.
/// This cannot be built from a bare pure replay Admitted or an arbitrary stamp.
/// Original time bounds and zeroizing plaintext remain owned until Drop.
#[must_use = "consume actual original bounded message or drop its zeroizing lease"]
pub struct Granted<'source, 'id, 'out> {
    admitted: Admitted<'source, 'id, 'out>,
    bounds: Bounds,
    binding: Binding<'id>,
    persisted: Persisted<'id>,
    current: Loaded<'id>,
}
impl fmt::Debug for Granted<'_, '_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DurableLiveDvGranted")
            .field("binding", &self.binding)
            .field(
                "durable_generation",
                &self.persisted.evidence().generation(),
            )
            .field("plaintext", &"[REDACTED]")
            .finish()
    }
}
impl<'source, 'id, 'out> Granted<'source, 'id, 'out> {
    /// Consume the real grant/crypto authority, erase/release the whole original
    /// output loan, and leave nonce history intact. This never completes original
    /// Engine/native flow-control or filesystem debt by itself.
    pub fn recycle(self) -> Recycled<'id, 'out> {
        Recycled {
            buffer: self.admitted.recycle(),
            binding: self.binding,
            reason: None,
            debt: None,
        }
    }
    /// Register original expiration while Engine capacity waits. A reported
    /// failure is latched and cannot be revived by logical-clock rollback.
    pub fn poll_expired(&mut self, cx: &mut Context<'_>) -> Poll<Reason> {
        let admitted = &self.admitted;
        self.bounds
            .poll_expiry(cx, |now| admitted.message(now).map(|_| ()))
    }
    /// Exact original packet/provider binding, never another target/task.
    pub const fn binding(&self) -> Binding<'id> {
        self.binding
    }
    /// Original immutable native target. A bridge with an independent monotonic
    /// epoch must recompute remaining time at actual admission, never renew it.
    pub fn native_deadline(&self) -> Instant {
        self.bounds.hard()
    }
    /// Actual successful original store/equal-known fact receipt.
    pub fn persisted(&self) -> &Persisted<'id> {
        &self.persisted
    }
    /// Actual same-provider load observed immediately before live replay grant.
    pub fn current_load(&self) -> &Loaded<'id> {
        &self.current
    }
    /// Borrow actual plaintext only while original native/logical/source/replay
    /// bounds still hold; Engine/native admission/write remains independent.
    pub fn message(&self) -> Result<&[u8], Reason> {
        let now = self.bounds.now()?;
        self.admitted
            .message(now)
            .map_err(|e| self.bounds.fail(Boundary::Source(e)))
    }
}
/// Grant retains Ready only on a current-store WouldBlock; retrying it performs
/// only a fresh read, never another original store mutation. Other refusals are
/// terminal typed owners and cannot extract/reopen their original payload.
#[must_use = "consume actual Admitted or retain/drop original refused Ready"]
pub enum Grant<'source, 'id, 'out> {
    /// Actual durable fact + live replay admission, still no Engine/IO ACK.
    Admitted(Granted<'source, 'id, 'out>),
    /// Original payload/proof/bounds retained unchanged for explicit policy.
    Refused {
        /// Original still-owned state, no new store intent.
        ready: Ready<'source, 'id, 'out>,
        /// Actual bounded current refusal.
        reason: Reason,
    },
    /// Terminal refusal retains the original zeroizing owner without permitting
    /// canceled/expired/Unknown work to become a new grant through retry.
    Rejected(Refused<'source, 'id, 'out>),
    /// Deadline/source changed after replay insertion. Authentication authority
    /// was consumed and the whole original loan erased/recovered; nonce history
    /// stays recorded. No grant/Engine/native completion escapes.
    Closed(Recycled<'id, 'out>),
}
impl<'source, 'id, 'out> Ready<'source, 'id, 'out> {
    /// Revoke this ungranted local authority and return its whole erased loan.
    /// Actual durable fact is historical; no new or unrelated store is canceled.
    pub fn recycle(self) -> Recycled<'id, 'out> {
        self.cancel().recycle()
    }
    /// Register the original source/logical/native expiry while waiting to grant.
    /// Reported failures are latched; no later rollback/retry creates a grant.
    pub fn poll_expired(&mut self, cx: &mut Context<'_>) -> Poll<Reason> {
        let opened = &self.opened;
        self.bounds
            .poll_expiry(cx, |now| opened.message(now).map(|_| ()))
    }
    /// Exact original authenticated packet context.
    pub const fn binding(&self) -> Binding<'id> {
        self.binding
    }
    /// Actual original successful store/equal-value durable fact.
    pub fn persisted(&self) -> &Persisted<'id> {
        &self.persisted
    }
    /// Actual initial load receipt, never an arbitrary u64 floor constructor.
    pub fn loaded(&self) -> &Loaded<'id> {
        &self.expected.loaded
    }
    /// Explicit cancel/drop without pretending to undo actual durability.
    pub fn cancel(self) -> Refused<'source, 'id, 'out> {
        self.refuse(Reason::Canceled)
    }
    fn refuse(self, reason: Reason) -> Refused<'source, 'id, 'out> {
        refused(self.opened, self.bounds, self.binding, reason)
    }
    /// Recheck exact original context/provider/receipt and CURRENT actual durable
    /// floor before live replay. This blocks old Ready10 while newer11 is pending
    /// or committed. Equal facts may grant only from the same actual provider.
    pub fn grant(
        self,
        provider: &mut Provider<'id>,
        replay: &mut Replay<'_, 'source, 'id>,
    ) -> Grant<'source, 'id, 'out> {
        let checked = self
            .binding
            .check(&self.opened)
            .and_then(|()| self.bounds.check(&self.opened).map(|_| ()))
            .and_then(|()| same_provider(provider, &self.expected.operation))
            .and_then(|()| self.expected.persisted(self.binding, &self.persisted));
        if let Err(reason) = checked {
            return Grant::Rejected(self.refuse(reason));
        }
        let current = match provider
            .load(Request::box_load(self.binding.token, self.binding.sender))
        {
            Ok(load) => load,
            Err(error) => {
                let reason = Reason::Store(error);
                if matches!(&reason,Reason::Store(e) if matches!(&e.cause,crate::Cause::Protocol(Protocol::WouldBlock)))
                {
                    return Grant::Refused {
                        ready: self,
                        reason,
                    };
                }
                return Grant::Rejected(self.refuse(reason));
            }
        };
        if let Err(reason) = load_proof(provider, &current, self.binding) {
            return Grant::Rejected(self.refuse(reason));
        }
        if current.evidence().generation() < self.expected.generation || current.value().is_none() {
            return Grant::Rejected(self.refuse(Reason::Binding(Protocol::StaleGeneration)));
        }
        if let Some(durable) = current.value() {
            if durable > self.binding.stamp {
                let packet = self.binding.stamp;
                return Grant::Rejected(self.refuse(Reason::Older { packet, durable }));
            }
            if durable != self.binding.stamp {
                return Grant::Rejected(self.refuse(Reason::Binding(Protocol::StaleGeneration)));
            }
        }
        let now = match self.bounds.check(&self.opened) {
            Ok(now) => now,
            Err(reason) => return Grant::Rejected(self.refuse(reason)),
        };
        let Ready {
            opened,
            bounds,
            binding,
            expected,
            persisted,
        } = self;
        match replay.admit(opened, now) {
            Err(denied) => {
                drop(expected);
                drop(persisted);
                Grant::Rejected(refused(
                    denied.value,
                    bounds,
                    binding,
                    Reason::Replay(denied.reason),
                ))
            }
            Ok(admitted) => {
                let check = bounds
                    .now()
                    .and_then(|now| admitted.message(now).map(|_| ()).map_err(Reason::Source));
                match check {
                    Ok(()) => Grant::Admitted(Granted {
                        admitted,
                        bounds,
                        binding,
                        persisted,
                        current,
                    }),
                    Err(reason) => Grant::Closed(Recycled {
                        buffer: admitted.recycle(),
                        binding,
                        reason: Some(reason),
                        debt: None,
                    }),
                }
            }
        }
    }
}
