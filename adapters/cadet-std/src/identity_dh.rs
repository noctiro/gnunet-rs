//! Actual source-bound native PILS identity-DH provider for the pure CADET port.
//! No private key access, raw-result injection, replay or fallback backend.
use crate::{EndpointSource, Error, time::Timebase};
use gnunet_cadet::tunnel::identity_dh::{self as pure, Completion, Request, Source};
use gnunet_pils::{
    HelloLimits, Profile,
    client::{self as pc, Epoch, Identity, Instance, KeyTarget, OperationId, Secret},
};
use gnunet_pils_host::client::{Client, Limits as NativeLimits, Progress};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::{Error as ProtocolError, MonoInstant, Rejected};
use std::{
    future::{Future, poll_fn},
    sync::Arc,
    task::{Context, Poll},
};
use tokio::time::Instant;

/// Before source binding, one actual PILS client with no crypto operations.
/// Public identity must be observed here before a pure Source can be minted.
pub struct Connecting<'pils, const O: usize = 32> {
    native: Client<'pils, O>,
    local: [u8; 32],
    fault: bool,
    mismatch: Option<Identity<'pils>>,
}
impl<'pils, const O: usize> Connecting<'pils, O> {
    /// Reserve the real original client/clock listener without starting IO. The
    /// supplied expected local peer is public CORE/runtime identity, not a seed.
    pub fn new(
        instance: &'pils mut Instance,
        source: EndpointSource,
        local: [u8; 32],
        profile: Profile,
        limits: NativeLimits,
        hello: HelloLimits,
    ) -> Result<Self, Error> {
        let native = Client::new(instance, source, profile, limits, hello)?;
        Ok(Self {
            native,
            local,
            fault: false,
            mismatch: None,
        })
    }
    /// Actual canonical source clock; cloning reserves no new listener.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.native.clock()
    }
    /// Verified announcement which actually caused this startup owner's refusal.
    /// This is an observation, not authority to rebind another provider or retry.
    #[must_use]
    pub fn identity_mismatch(&self) -> Option<Identity<'pils>> {
        self.mismatch
    }
    /// Poll actual public startup progress. A mismatched announced local peer
    /// closes this owned client before returning Authentication; no Source exists.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Option<Instant>,
    ) -> Poll<Result<Progress<'pils, O>, Error>> {
        if self.fault {
            return Poll::Ready(Err(ProtocolError::Authentication.into()));
        }
        let result = {
            let mut work = std::pin::pin!(self.native.drive(deadline));
            work.as_mut().poll(cx)
        };
        if let Poll::Ready(Ok(Progress::Inbound(pc::Inbound::Identity { identity, .. }))) = &result
            && *identity.peer().as_bytes() != self.local
        {
            self.mismatch = Some(*identity);
            let _retired = self.native.close();
            self.fault = true;
            return Poll::Ready(Err(ProtocolError::Authentication.into()));
        }
        result
    }
    /// Startup waiting is cancellation-safe on the same owned native client.
    pub async fn drive(&mut self, deadline: Option<Instant>) -> Result<Progress<'pils, O>, Error> {
        poll_fn(|cx| self.poll(cx, deadline)).await
    }
    /// Explicitly retry only this real client's refused source-domain ports.
    pub fn recover_ports(&mut self) -> Result<(), Error> {
        self.native.recover_ports()
    }
    /// Bind only the actual current verified identity and original typed MQ.
    /// Refusal returns the same startup owner; no native source is discarded.
    #[expect(
        clippy::result_large_err,
        reason = "Return the original live PILS startup owner unchanged on bind refusal without a fallible allocation or implicit physical retirement"
    )]
    pub fn bind<'id, 'slots>(
        self,
        registry: &mut pure::Registry<'id>,
        jobs: &'slots mut [JobSlot<'id, 'pils>],
        contexts: &'slots mut [ContextSlot<'id>],
        timebase: Timebase,
    ) -> Result<Port<'id, 'pils, 'slots, O>, Rejected<Self>> {
        let checked = (|| {
            if !Arc::ptr_eq(&self.native.clock(), &timebase.source()) {
                return Err(ProtocolError::StaleGeneration);
            }
            if self.fault {
                return Err(ProtocolError::Authentication);
            }
            if jobs.is_empty()
                || contexts.is_empty()
                || jobs.iter().any(|j| j.record.is_some())
                || contexts.iter().any(|c| c.record.is_some())
            {
                return Err(ProtocolError::Capacity);
            }
            let identity = self.native.identity().ok_or(ProtocolError::NotReady)?;
            let epoch = self.native.epoch().ok_or(ProtocolError::NotReady)?;
            if identity.epoch() != epoch || *identity.peer().as_bytes() != self.local {
                return Err(ProtocolError::Authentication);
            }
            let now = timebase.sample()?.monotonic;
            Ok((identity, epoch, now))
        })();
        let (identity, epoch, now) = match checked {
            Ok(value) => value,
            Err(reason) => {
                return Err(Rejected {
                    value: self,
                    reason,
                });
            }
        };
        let binding = match registry.bind(self.local, epoch.value()) {
            Ok(binding) => binding,
            Err(reason) => {
                return Err(Rejected {
                    value: self,
                    reason,
                });
            }
        };
        let source = binding.source();
        Ok(Port {
            native: self.native,
            binding,
            timebase,
            identity,
            epoch,
            source,
            jobs,
            contexts,
            last_now: now,
            dead: None,
            last_native_error: None,
            report: Report::default(),
        })
    }
}
enum State {
    Running,
    Ready(Secret<64>),
    Failed(ProtocolError),
    Retiring(ProtocolError),
}
struct Job<'id, 'pils> {
    request: Request<'id>,
    identity: Identity<'pils>,
    operation: OperationId<'pils>,
    state: State,
}
/// Caller-owned fixed in-flight metadata/result slot. Secret results cannot be
/// cloned or formatted and erase on completion, cancellation, close and drop.
pub struct JobSlot<'id, 'pils> {
    record: Option<Job<'id, 'pils>>,
}
impl JobSlot<'_, '_> {
    /// Empty explicit provider storage; no operation is admitted.
    #[must_use]
    pub const fn new() -> Self {
        Self { record: None }
    }
}
impl Default for JobSlot<'_, '_> {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Clone, Copy)]
struct ContextRecord<'id> {
    high: gnunet_cadet::tunnel::controller::Generation<'id>,
    until: MonoInstant,
}
/// Caller-owned no-secret original-context generation high-water. One record
/// serves successive candidates of the same tunnel, independently of jobs.
#[derive(Clone, Copy)]
pub struct ContextSlot<'id> {
    record: Option<ContextRecord<'id>>,
}
impl ContextSlot<'_> {
    /// Empty explicit anti-resubmission metadata.
    #[must_use]
    pub const fn new() -> Self {
        Self { record: None }
    }
}
impl Default for ContextSlot<'_> {
    fn default() -> Self {
        Self::new()
    }
}
/// Public counters, without DH bytes or private-key/seed formatting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Report {
    /// Actual original ECDH admissions.
    pub submitted: u64,
    /// Validated actual original 64-byte results retained privately.
    pub received: u64,
    /// Original results consumed through finish callbacks.
    pub consumed: u64,
    /// Actual source/MQ stops; no replay is allowed afterwards.
    pub stopped: u64,
    /// Actual original job retirements, not fake server ACKs.
    pub retired: u64,
}
/// Actual native/public metadata progress; never exposes the private DH result.
pub enum Step<'id, 'pils, const O: usize = 32> {
    /// The original private result is ready for the trusted finish callback.
    Result {
        /// Exact original private request capability.
        request: Request<'id>,
        /// Actual original operation on this owned client.
        operation: OperationId<'pils>,
    },
    /// Actual cancellation/expiry request bytes are quiescent; finish/retire can
    /// consume the original failure once, then only metadata tombstone remains.
    Retired {
        /// Exact original request.
        request: Request<'id>,
        /// Original operation.
        operation: OperationId<'pils>,
    },
    /// Actual source loss was processed and the owned client permanently closed
    /// before another poll could reissue retained crypto on a new MQ.
    Lost {
        /// Original native loss event, including its actual cause/report.
        original: Progress<'pils, O>,
        /// IDs actually retired by native close.
        retired: [Option<OperationId<'pils>>; O],
    },
    /// Announced local identity changed; original source was physically stopped.
    IdentityChanged {
        /// Actual offending current announcement.
        identity: Identity<'pils>,
        /// Whether the announcement belongs to this same original native MQ.
        same_epoch: bool,
        /// IDs actually retired by native close.
        retired: [Option<OperationId<'pils>>; O],
    },
    /// The actual SDK rejected the original operation because its selected key
    /// changed. Its source is closed; an observer must verify any next identity.
    KeyChanged {
        /// Exact original operation owner.
        request: Request<'id>,
        /// Actual original native operation.
        operation: OperationId<'pils>,
        /// IDs actually retired by physical close.
        retired: [Option<OperationId<'pils>>; O],
    },
    /// Unexpected actual completion family/identity; no result callback happened.
    Rejected {
        /// Actual original operation, if its metadata was known.
        operation: OperationId<'pils>,
        /// Concrete source/protocol reason.
        reason: ProtocolError,
    },
    /// Other actual native progress with no secret completion inside.
    Native(Progress<'pils, O>),
    /// Permanently stopped original source; original jobs may still be consumed
    /// as failures or retired through the pure Port API without a new clock.
    Closed(ProtocolError),
}
/// Real native PILS provider for one immutable original Source/identity/MQ.
/// Caller storage bounds concurrent jobs and independent no-secret original
/// context high-waters. Successive tunnel generations reuse a context record;
/// the old copied request cannot reissue after its job slot is reused.
pub struct Port<'id, 'pils, 'slots, const O: usize = 32> {
    native: Client<'pils, O>,
    binding: pure::Binding<'id>,
    timebase: Timebase,
    identity: Identity<'pils>,
    epoch: Epoch<'pils>,
    source: Source<'id>,
    jobs: &'slots mut [JobSlot<'id, 'pils>],
    contexts: &'slots mut [ContextSlot<'id>],
    last_now: MonoInstant,
    dead: Option<ProtocolError>,
    last_native_error: Option<Error>,
    report: Report,
}
impl<'id, 'pils, 'slots, const O: usize> Port<'id, 'pils, 'slots, O> {
    /// Actual immutable backend identity. Numeric epoch alone is not authority.
    #[must_use]
    pub const fn source(&self) -> Source<'id> {
        self.source
    }
    /// Same actual source clock, without reserving another listener.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.timebase.source()
    }
    /// Same native elapsed epoch and canonical source, without another listener.
    #[must_use]
    pub fn timebase(&self) -> &Timebase {
        &self.timebase
    }
    /// Actual public observations; no secret/result bytes are included.
    #[must_use]
    pub const fn report(&self) -> Report {
        self.report
    }
    /// Actual source/port error whose richer native cause cannot fit pure Error.
    /// Taking it does not reset/rebind the stopped source or imply retirement.
    pub fn take_native_error(&mut self) -> Option<Error> {
        self.last_native_error.take()
    }
    /// Original earliest outstanding job deadline. The containing reactor must
    /// service this along with controller deadlines even while native IO waits.
    #[must_use]
    pub fn next_deadline(&self) -> Option<MonoInstant> {
        self.jobs
            .iter()
            .filter_map(|j| j.record.as_ref())
            .filter(|j| !matches!(j.state, State::Failed(_) | State::Retiring(_)))
            .map(|j| j.request.expires())
            .min()
    }
    fn authorize(&self, request: Request<'id>) -> Result<(), ProtocolError> {
        if request.source() != self.source {
            return Err(ProtocolError::StaleGeneration);
        }
        Ok(())
    }
    fn now(&mut self) -> Result<MonoInstant, ProtocolError> {
        let now = match self.timebase.sample() {
            Ok(sample) => sample.monotonic,
            Err(reason) => {
                let _retired = self.stop(reason);
                return Err(reason);
            }
        };
        if now < self.last_now {
            let _retired = self.stop(ProtocolError::TimeUncertain);
            return Err(ProtocolError::TimeUncertain);
        }
        self.last_now = now;
        Ok(now)
    }
    fn find(&self, request: Request<'id>) -> Option<usize> {
        self.jobs
            .iter()
            .position(|j| j.record.as_ref().is_some_and(|j| j.request == request))
    }
    fn operation(&self, operation: OperationId<'pils>) -> Option<usize> {
        self.jobs
            .iter()
            .position(|j| j.record.as_ref().is_some_and(|j| j.operation == operation))
    }
    fn purge_contexts(&mut self, now: MonoInstant) {
        for slot in self.contexts.iter_mut() {
            if slot.record.is_some_and(|context| {
                (now >= context.until || !context.high.is_live())
                    && !self.jobs.iter().any(|j| {
                        j.record
                            .as_ref()
                            .is_some_and(|job| job.request.generation().same_context(context.high))
                    })
            }) {
                slot.record = None;
            }
        }
    }
    fn context_slot(&self, request: Request<'id>) -> Result<usize, ProtocolError> {
        if let Some(index) = self.contexts.iter().position(|slot| {
            slot.record
                .is_some_and(|c| c.high.same_context(request.generation()))
        }) {
            if self.contexts[index]
                .record
                .is_some_and(|c| request.generation().value() <= c.high.value())
            {
                return Err(ProtocolError::Conflict);
            }
            return Ok(index);
        }
        self.contexts
            .iter()
            .position(|slot| slot.record.is_none())
            .ok_or(ProtocolError::Capacity)
    }
    fn stop(&mut self, reason: ProtocolError) -> [Option<OperationId<'pils>>; O] {
        let retired = self.native.close();
        self.binding.close();
        if self.dead.is_none() {
            self.report.stopped = self.report.stopped.saturating_add(1);
        }
        self.dead = Some(reason);
        for slot in self.jobs.iter_mut() {
            if let Some(job) = slot.record.as_mut() {
                job.state = State::Failed(reason);
            }
        }
        retired
    }
    fn native_error(&mut self, error: Error) -> ProtocolError {
        match error {
            Error::Protocol(reason) => reason,
            other => {
                self.last_native_error = Some(other);
                let _retired = self.stop(ProtocolError::Io);
                ProtocolError::Io
            }
        }
    }
    fn quiescent(&mut self, operation: OperationId<'pils>) -> Result<bool, ProtocolError> {
        self.native
            .operation_quiescent(operation)
            .map_err(|e| self.native_error(e))
    }
    fn begin_retire(&mut self, index: usize, reason: ProtocolError) -> Result<bool, ProtocolError> {
        let job = self.jobs[index]
            .record
            .as_ref()
            .ok_or(ProtocolError::StaleGeneration)?;
        let operation = job.operation;
        if self.quiescent(operation)? {
            self.jobs[index]
                .record
                .as_mut()
                .ok_or(ProtocolError::StaleGeneration)?
                .state = State::Failed(reason);
            return Ok(true);
        }
        if !self.jobs[index]
            .record
            .as_ref()
            .is_some_and(|j| matches!(j.state, State::Retiring(_)))
        {
            if let Err(error) = self.native.cancel(operation) {
                let reason = self.native_error(error);
                return Err(reason);
            }
            self.jobs[index]
                .record
                .as_mut()
                .ok_or(ProtocolError::StaleGeneration)?
                .state = State::Retiring(reason);
        }
        if self.quiescent(operation)? {
            self.jobs[index]
                .record
                .as_mut()
                .ok_or(ProtocolError::StaleGeneration)?
                .state = State::Failed(reason);
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn expired(&mut self, now: MonoInstant) -> Result<Option<Step<'id, 'pils, O>>, ProtocolError> {
        self.purge_contexts(now);
        for index in 0..self.jobs.len() {
            let Some(job) = self.jobs[index].record.as_ref() else {
                continue;
            };
            let request = job.request;
            let operation = job.operation;
            if matches!(job.state, State::Failed(_)) {
                continue;
            }
            let retirement = match job.state {
                State::Retiring(reason) => Some(reason),
                _ if now >= request.expires() => Some(ProtocolError::Deadline),
                _ if request.admission().is_err() => Some(ProtocolError::Cancelled),
                _ => None,
            };
            if let Some(reason) = retirement
                && self.begin_retire(index, reason)?
            {
                return Ok(Some(Step::Retired { request, operation }));
            }
        }
        Ok(None)
    }
    fn current(&self) -> bool {
        self.dead.is_none()
            && self.native.epoch() == Some(self.epoch)
            && self
                .native
                .identity()
                .is_some_and(|id| id.epoch() == self.epoch && id.peer() == self.identity.peer())
    }
    fn complete(&mut self, result: pc::Completion<'pils>, now: MonoInstant) -> Step<'id, 'pils, O> {
        let operation = result.operation();
        let Some(index) = self.operation(operation) else {
            return Step::Rejected {
                operation,
                reason: ProtocolError::StaleGeneration,
            };
        };
        let job = self.jobs[index].record.as_ref();
        let Some(job) = job else {
            return Step::Rejected {
                operation,
                reason: ProtocolError::StaleGeneration,
            };
        };
        let request = job.request;
        if now >= request.expires()
            || request.admission().is_err()
            || matches!(job.state, State::Retiring(_))
        {
            // The actual result is consumed only to erase it. It cannot become
            // a success after cancellation/expiry; physical quiescence is still
            // checked by finish/retire, never guessed from a queue callback.
            let reason = match job.state {
                State::Retiring(reason) => reason,
                _ if now >= request.expires() => ProtocolError::Deadline,
                _ => ProtocolError::Cancelled,
            };
            if let Some(job) = self.jobs[index].record.as_mut() {
                job.state = State::Failed(reason);
            }
            return Step::Rejected { operation, reason };
        }
        match result {
            pc::Completion::Ecdh { identity, key, .. }
                if self.current()
                    && identity.epoch() == self.epoch
                    && identity.peer() == self.identity.peer()
                    && identity.peer() == job.identity.peer() =>
            {
                if let Some(job) = self.jobs[index].record.as_mut() {
                    job.state = State::Ready(key);
                }
                self.report.received = self.report.received.saturating_add(1);
                Step::Result { request, operation }
            }
            pc::Completion::Failed {
                kind: pc::OperationKind::Ecdh,
                reason: pc::Failure::KeyChanged,
                ..
            } => {
                let retired = self.stop(ProtocolError::Authentication);
                Step::KeyChanged {
                    request,
                    operation,
                    retired,
                }
            }
            pc::Completion::Failed {
                kind: pc::OperationKind::Ecdh,
                reason,
                ..
            } => {
                let reason = match reason {
                    pc::Failure::CryptoRejected | pc::Failure::InvalidSignature => {
                        ProtocolError::Authentication
                    }
                    pc::Failure::KeyChanged => ProtocolError::Authentication,
                    pc::Failure::IdentityUnavailable => ProtocolError::NotReady,
                };
                if let Some(job) = self.jobs[index].record.as_mut() {
                    job.state = State::Failed(reason);
                }
                Step::Rejected { operation, reason }
            }
            _ => {
                let _retired = self.stop(ProtocolError::Authentication);
                Step::Rejected {
                    operation,
                    reason: ProtocolError::Authentication,
                }
            }
        }
    }
    /// Poll the one owned real PILS client and keep matching secrets private.
    /// A service/MQ loss closes it before any native reconnect/replay can occur.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Option<Instant>,
    ) -> Poll<Result<Step<'id, 'pils, O>, Error>> {
        if let Some(reason) = self.dead {
            return Poll::Ready(Ok(Step::Closed(reason)));
        }
        let now = self.now()?;
        if let Some(step) = self.expired(now)? {
            return Poll::Ready(Ok(step));
        }
        let original = self
            .next_deadline()
            .map(|target| self.timebase.native_bound(target))
            .transpose()?;
        let target = [deadline, original].into_iter().flatten().min();
        let result = {
            let mut work = std::pin::pin!(self.native.drive(target));
            work.as_mut().poll(cx)
        };
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                let _retired = self.stop(ProtocolError::Io);
                Poll::Ready(Err(error))
            }
            Poll::Ready(Ok(progress)) => Poll::Ready(Ok(match progress {
                Progress::Inbound(pc::Inbound::Identity { identity, .. })
                    if identity.epoch() != self.epoch
                        || identity.peer() != self.identity.peer() =>
                {
                    let retired = self.stop(ProtocolError::Authentication);
                    Step::IdentityChanged {
                        identity,
                        same_epoch: identity.epoch() == self.epoch,
                        retired,
                    }
                }
                Progress::Inbound(pc::Inbound::Complete(completion)) => {
                    self.complete(completion, now)
                }
                actual @ Progress::Lost { .. } => {
                    let retired = self.stop(ProtocolError::Closed);
                    Step::Lost {
                        original: actual,
                        retired,
                    }
                }
                Progress::Connected(epoch) if epoch != self.epoch => {
                    let retired = self.stop(ProtocolError::StaleGeneration);
                    Step::Lost {
                        original: Progress::Connected(epoch),
                        retired,
                    }
                }
                Progress::Closed => {
                    let _retired = self.stop(ProtocolError::Closed);
                    Step::Closed(ProtocolError::Closed)
                }
                other => Step::Native(other),
            })),
        }
    }
    /// Wait for one actual source event. Canceling the future keeps original
    /// operation IDs, cursors, jobs and private zeroizing results intact.
    pub async fn drive(&mut self, deadline: Option<Instant>) -> Result<Step<'id, 'pils, O>, Error> {
        poll_fn(|cx| self.poll(cx, deadline)).await
    }
    /// Physically stop this original client, revoke replays, erase retained
    /// results, then allow pure controllers to finish/retire their actual jobs.
    pub fn close(&mut self) -> [Option<OperationId<'pils>>; O] {
        self.stop(ProtocolError::Closed)
    }
    /// Explicitly recover only this original native clock/Resolver port. A dead
    /// Source never rebinds to a replacement client or different source here.
    pub fn recover_ports(&mut self) -> Result<(), Error> {
        if self.dead.is_some() {
            return Err(ProtocolError::Closed.into());
        }
        self.native.recover_ports()
    }
}
impl<'id, const O: usize> pure::Port<'id> for Port<'id, '_, '_, O> {
    fn source(&self) -> Source<'id> {
        self.source
    }
    fn submit(&mut self, request: Request<'id>) -> Result<(), ProtocolError> {
        self.authorize(request)?;
        if self.dead.is_some() {
            return Err(ProtocolError::Closed);
        }
        request.admission()?;
        let now = self.now()?;
        self.purge_contexts(now);
        if request.expires().0 == u64::MAX || now >= request.expires() {
            return Err(ProtocolError::Deadline);
        }
        self.timebase.native_bound(request.expires())?;
        if self.find(request).is_some() {
            return Err(ProtocolError::Conflict);
        }
        let context = self.context_slot(request)?;
        if self.jobs.iter().any(|slot| {
            slot.record
                .as_ref()
                .is_some_and(|job| job.request.generation().same_context(request.generation()))
        }) {
            return Err(ProtocolError::WouldBlock);
        }
        if !self.current() {
            return Err(ProtocolError::StaleGeneration);
        }
        let slot = self
            .jobs
            .iter()
            .position(|j| j.record.is_none())
            .ok_or(ProtocolError::Capacity)?;
        let identity = self.native.identity().ok_or(ProtocolError::NotReady)?;
        let operation = self
            .native
            .ecdh(
                request.remote_exchange().ephemeral_key,
                KeyTarget::Exact(identity),
            )
            .map_err(|error| self.native_error(error))?;
        let until = self.contexts[context]
            .record
            .map_or(request.expires(), |old| old.until.max(request.expires()));
        self.contexts[context].record = Some(ContextRecord {
            high: request.generation(),
            until,
        });
        self.jobs[slot].record = Some(Job {
            request,
            identity,
            operation,
            state: State::Running,
        });
        self.report.submitted = self.report.submitted.saturating_add(1);
        Ok(())
    }
    fn finish<T>(
        &mut self,
        request: Request<'id>,
        accept: impl FnOnce(&[u8; 64]) -> Result<T, ProtocolError>,
    ) -> Result<Completion<T>, ProtocolError> {
        self.authorize(request)?;
        let index = self.find(request).ok_or(ProtocolError::StaleGeneration)?;
        let job = self.jobs[index]
            .record
            .as_ref()
            .ok_or(ProtocolError::StaleGeneration)?;
        let operation = job.operation;
        if let State::Failed(reason) = job.state {
            if !self.quiescent(operation)? {
                return Ok(Completion::Pending);
            }
            self.jobs[index].record = None;
            return Ok(Completion::Finished(Err(reason)));
        }
        if request.admission().is_err() {
            if !self.begin_retire(index, ProtocolError::Cancelled)? {
                return Ok(Completion::Pending);
            }
            self.jobs[index].record = None;
            return Ok(Completion::Finished(Err(ProtocolError::Cancelled)));
        }
        let now = self.now()?;
        if now >= request.expires() {
            if !self.begin_retire(index, ProtocolError::Deadline)? {
                return Ok(Completion::Pending);
            }
            self.jobs[index].record = None;
            return Ok(Completion::Finished(Err(ProtocolError::Deadline)));
        }
        if !self.current() {
            return Err(ProtocolError::StaleGeneration);
        }
        if !self.quiescent(operation)? {
            return Ok(Completion::Pending);
        }
        if !self.jobs[index]
            .record
            .as_ref()
            .is_some_and(|job| matches!(job.state, State::Ready(_)))
        {
            return Ok(Completion::Pending);
        }
        let job = self.jobs[index]
            .record
            .take()
            .ok_or(ProtocolError::StaleGeneration)?;
        let State::Ready(secret) = job.state else {
            return Err(ProtocolError::StaleGeneration);
        };
        self.report.consumed = self.report.consumed.saturating_add(1);
        Ok(Completion::Finished(accept(secret.as_bytes())))
    }
    fn retire(&mut self, request: Request<'id>) -> Result<bool, ProtocolError> {
        self.authorize(request)?;
        let index = self.find(request).ok_or(ProtocolError::StaleGeneration)?;
        if self.begin_retire(index, ProtocolError::Cancelled)? {
            self.jobs[index].record = None;
            self.report.retired = self.report.retired.saturating_add(1);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
impl<const O: usize> Drop for Port<'_, '_, '_, O> {
    fn drop(&mut self) {
        let _retired = self.native.close();
        self.binding.close();
        for slot in self.jobs.iter_mut() {
            slot.record = None;
        }
        for slot in self.contexts.iter_mut() {
            slot.record = None;
        }
    }
}
