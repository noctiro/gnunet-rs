//! Actual bounded PILS purpose38 signing for one original connection-book domain.
//! Signatures remain private until the original Book accepts its exact request.
//! No private-key read, injected-success constructor or reconnect replay is used.
pub mod monotime;
use crate::{EndpointSource, Error, time::Timebase};
use gnunet_cadet::connection::{Book, Frame, ResetAuthority, SignRequest};
use gnunet_pils::{
    HelloLimits, Profile,
    client::{self as pc, Epoch, Identity, Instance, KeyTarget, OperationId},
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

/// One actual PILS startup owner; no signing is admitted before its own verified
/// public identity and typed original MQ epoch have been observed.
pub struct Connecting<'pils, const O: usize = 32> {
    native: Client<'pils, O>,
    local: [u8; 32],
    stopped: bool,
    mismatch: Option<Identity<'pils>>,
}
impl<'pils, const O: usize> Connecting<'pils, O> {
    /// Construct one node-wide explicit native client, without starting IO or
    /// creating a Resolver, task, per-peer client or private-key owner.
    pub fn new(
        instance: &'pils mut Instance,
        source: EndpointSource,
        local: [u8; 32],
        profile: Profile,
        limits: NativeLimits,
        hello: HelloLimits,
    ) -> Result<Self, Error> {
        Ok(Self {
            native: Client::new(instance, source, profile, limits, hello)?,
            local,
            stopped: false,
            mismatch: None,
        })
    }
    /// Same canonical source clock, without another listener reservation.
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
    /// Poll actual public startup progress. A mismatched announced key closes
    /// the original client before returning the concrete authentication refusal.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Option<Instant>,
    ) -> Poll<Result<Progress<'pils, O>, Error>> {
        if self.stopped {
            return Poll::Ready(Err(ProtocolError::Closed.into()));
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
            self.stopped = true;
            return Poll::Ready(Err(ProtocolError::Authentication.into()));
        }
        result
    }
    /// Cancellation-safe wait on this same startup owner.
    pub async fn drive(&mut self, deadline: Option<Instant>) -> Result<Progress<'pils, O>, Error> {
        poll_fn(|cx| self.poll(cx, deadline)).await
    }
    /// Explicitly retry this owner's actual refused runtime ports.
    pub fn recover_ports(&mut self) -> Result<(), Error> {
        if self.stopped {
            return Err(ProtocolError::Closed.into());
        }
        self.native.recover_ports()
    }
    /// Bind the verified actual identity/epoch to exactly one original Book.
    /// Refusal returns the original startup owner unchanged, without stopping IO.
    #[expect(
        clippy::result_large_err,
        reason = "Return the original live PILS startup owner without a fallible allocation or implicit retirement on bind refusal"
    )]
    pub fn bind<'book, 'slots, const P: usize>(
        self,
        book: &Book<'book, '_, '_, P>,
        slots: &'slots mut [JobSlot<'book, 'pils>],
        limits: Limits,
        timebase: Timebase,
    ) -> Result<Signer<'book, 'pils, 'slots, O>, Rejected<Self>> {
        let checked = (|| {
            if !Arc::ptr_eq(&self.native.clock(), &timebase.source()) {
                return Err(ProtocolError::StaleGeneration);
            }
            if self.stopped {
                return Err(ProtocolError::Closed);
            }
            if slots.is_empty()
                || slots
                    .iter()
                    .any(|slot| slot.record.is_some() || slot.used.is_some())
            {
                return Err(ProtocolError::Capacity);
            }
            if limits.retirement_grace_micros == 0 || limits.retirement_grace_micros == u64::MAX {
                return Err(ProtocolError::InvalidInput);
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
            Ok(checked) => checked,
            Err(reason) => {
                return Err(Rejected {
                    value: self,
                    reason,
                });
            }
        };
        Ok(Signer {
            native: self.native,
            timebase,
            identity,
            epoch,
            authority: book.reset_authority(),
            slots,
            limits,
            last_now: now,
            stopped: None,
            report: Report::default(),
        })
    }
}
/// Finite original physical retirement policy, independent of socket readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Hard stop is computed once as original expiry plus this grace. Cancellation
    /// never extends it; at the hard bound the original MQ is physically closed.
    pub retirement_grace_micros: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            retirement_grace_micros: 5_000_000,
        }
    }
}
/// Private-minted exact original native job. Metadata copies cannot mint another
/// operation or replace its Book, typed operation, deadline or source epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Job<'book, 'pils> {
    request: SignRequest<'book>,
    operation: OperationId<'pils>,
    expires: MonoInstant,
    hard_stop: MonoInstant,
}
impl<'book, 'pils> Job<'book, 'pils> {
    /// Original public request, never an actual completion proof.
    #[must_use]
    pub const fn request(self) -> SignRequest<'book> {
        self.request
    }
    /// Original operation on the signer's own actual PILS MQ.
    #[must_use]
    pub const fn operation(self) -> OperationId<'pils> {
        self.operation
    }
    /// Original native elapsed expiry; polling and cancellation never extend it.
    #[must_use]
    pub const fn expires(self) -> MonoInstant {
        self.expires
    }
    /// Fixed original physical retirement bound.
    #[must_use]
    pub const fn hard_stop(self) -> MonoInstant {
        self.hard_stop
    }
}
enum State {
    Running,
    Ready([u8; 64]),
    Retiring(ProtocolError),
    Failed(ProtocolError),
}
struct Record<'book, 'pils> {
    job: Job<'book, 'pils>,
    state: State,
}
/// Fixed caller storage for an original job and one no-reissue tombstone. A
/// tombstone retires only when the same Book proves its request no longer live.
pub struct JobSlot<'book, 'pils> {
    record: Option<Record<'book, 'pils>>,
    used: Option<SignRequest<'book>>,
}
impl JobSlot<'_, '_> {
    /// Empty bounded storage, with no admitted backend operation.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            record: None,
            used: None,
        }
    }
}
impl Default for JobSlot<'_, '_> {
    fn default() -> Self {
        Self::new()
    }
}
/// Actual source observations; no raw signature or private result is exposed.
pub enum Step<'book, 'pils, const O: usize = 32> {
    /// Verified original signature retained privately for Book acceptance.
    Ready {
        /// Exact original job.
        job: Job<'book, 'pils>,
    },
    /// Original canceled/expired native request is now physically quiescent.
    Retired {
        /// Exact original job.
        job: Job<'book, 'pils>,
    },
    /// Actual MQ was closed before a native reconnect/replay could take place.
    Lost {
        /// Original native loss or changed-epoch event.
        original: Progress<'pils, O>,
        /// IDs actually retired by physical close.
        retired: [Option<OperationId<'pils>>; O],
    },
    /// Actual announced key changed; original source is physically stopped.
    IdentityChanged {
        /// Offending actual public announcement.
        identity: Identity<'pils>,
        /// Whether the announcement belongs to this same original native MQ.
        same_epoch: bool,
        /// IDs actually retired by physical close.
        retired: [Option<OperationId<'pils>>; O],
    },
    /// The actual SDK rejected the original operation because its selected key
    /// changed. Its source is closed; an observer must verify any next identity.
    KeyChanged {
        /// Exact original operation owner.
        job: Job<'book, 'pils>,
        /// Actual original native operation.
        operation: OperationId<'pils>,
        /// IDs actually retired by physical close.
        retired: [Option<OperationId<'pils>>; O],
    },
    /// Fixed original hard retirement bound closed the actual MQ.
    Stopped {
        /// Original failure leading to the stop.
        reason: ProtocolError,
        /// IDs actually retired by physical close.
        retired: [Option<OperationId<'pils>>; O],
    },
    /// A concrete original request failed; no Book signature was applied.
    Rejected {
        /// Exact known original job, if any.
        job: Option<Job<'book, 'pils>>,
        /// Actual typed operation.
        operation: OperationId<'pils>,
        /// Original reason.
        reason: ProtocolError,
    },
    /// Actual unrelated public native progress, without a completion inside.
    Native(Progress<'pils, O>),
    /// Permanently stopped owner. Its original jobs remain finishable as actual
    /// failures or explicitly retireable, without requiring another clock read.
    Closed(ProtocolError),
}
/// Book acceptance outcome for one private original result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Completion<'book> {
    /// Actual native request or suffix retirement has not finished.
    Pending,
    /// Book cannot yet enqueue the original CREATE; private result is retained.
    Blocked(ProtocolError),
    /// Actual verified signature was accepted once by the exact original Book.
    Signed {
        /// Original Book's actual newly queued CREATE frame.
        frame: Frame<'book>,
    },
    /// Original actual failure was consumed once; no new CREATE was queued.
    Failed(ProtocolError),
}
/// Source counters, without private-key material or signatures.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Report {
    /// Actual original PILS sign admissions.
    pub submitted: u64,
    /// Verified source-bound original signatures received.
    pub received: u64,
    /// Original signatures actually accepted by Book.
    pub applied: u64,
    /// Actual original caller retirements after physical quiescence.
    pub retired: u64,
    /// Original MQ stops; no reconnect is permitted afterwards.
    pub stopped: u64,
}
/// One node-wide actual signer bound to the original Book, local key and typed
/// PILS epoch. Caller rows bound jobs and stale-copy protection separately from
/// remote peers; this owner creates no hidden task or per-peer connection.
pub struct Signer<'book, 'pils, 'slots, const O: usize = 32> {
    native: Client<'pils, O>,
    timebase: Timebase,
    identity: Identity<'pils>,
    epoch: Epoch<'pils>,
    authority: ResetAuthority<'book>,
    slots: &'slots mut [JobSlot<'book, 'pils>],
    limits: Limits,
    last_now: MonoInstant,
    stopped: Option<ProtocolError>,
    report: Report,
}
impl<'book, 'pils, 'slots, const O: usize> Signer<'book, 'pils, 'slots, O> {
    /// Same original canonical source clock.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.timebase.source()
    }
    /// Same native elapsed epoch and canonical source, without another listener.
    #[must_use]
    pub fn timebase(&self) -> &Timebase {
        &self.timebase
    }
    /// Original typed PILS epoch, not a numeric replacement-generation proof.
    #[must_use]
    pub const fn epoch(&self) -> Epoch<'pils> {
        self.epoch
    }
    /// Actual verified original local public identity.
    #[must_use]
    pub fn local(&self) -> [u8; 32] {
        *self.identity.peer().as_bytes()
    }
    /// Actual original source observations only.
    #[must_use]
    pub const fn report(&self) -> Report {
        self.report
    }
    /// Bound original Book domain, without granting a reset/authentication proof.
    #[must_use]
    pub const fn authority(&self) -> ResetAuthority<'book> {
        self.authority
    }
    /// Actual still-retained original job for this request. A tombstone alone
    /// never supplies a job or a completion/retirement claim.
    #[must_use]
    pub fn job_for(&self, request: SignRequest<'book>) -> Option<Job<'book, 'pils>> {
        self.slots
            .iter()
            .filter_map(|slot| slot.record.as_ref())
            .find(|record| record.job.request == request)
            .map(|record| record.job)
    }
    fn same_book<const P: usize>(&self, book: &Book<'book, '_, '_, P>) -> Result<(), Error> {
        if self.authority != book.reset_authority() {
            return Err(ProtocolError::StaleGeneration.into());
        }
        Ok(())
    }
    fn now(&mut self) -> Result<MonoInstant, Error> {
        let sample = match self.timebase.sample() {
            Ok(sample) => sample,
            Err(reason) => {
                let _retired = self.stop(reason);
                return Err(reason.into());
            }
        };
        if sample.monotonic < self.last_now {
            let _retired = self.stop(ProtocolError::TimeUncertain);
            return Err(ProtocolError::TimeUncertain.into());
        }
        self.last_now = sample.monotonic;
        Ok(sample.monotonic)
    }
    fn current(&self) -> bool {
        self.stopped.is_none()
            && self.native.epoch() == Some(self.epoch)
            && self
                .native
                .identity()
                .is_some_and(|id| id.epoch() == self.epoch && id.peer() == self.identity.peer())
    }
    fn index(&self, job: Job<'book, 'pils>) -> Result<usize, Error> {
        self.slots
            .iter()
            .position(|slot| slot.record.as_ref().is_some_and(|record| record.job == job))
            .ok_or_else(|| ProtocolError::StaleGeneration.into())
    }
    fn stop(&mut self, reason: ProtocolError) -> [Option<OperationId<'pils>>; O] {
        let retired = self.native.close();
        if self.stopped.is_none() {
            self.report.stopped = self.report.stopped.saturating_add(1);
        }
        self.stopped = Some(reason);
        for slot in self.slots.iter_mut() {
            if let Some(record) = slot.record.as_mut() {
                record.state = State::Failed(reason);
            }
        }
        retired
    }
    fn quiescent(&mut self, operation: OperationId<'pils>) -> Result<bool, Error> {
        match self.native.operation_quiescent(operation) {
            Ok(done) => Ok(done),
            Err(error) => {
                let _retired = self.stop(ProtocolError::Io);
                Err(error)
            }
        }
    }
    fn begin_retire(&mut self, index: usize, reason: ProtocolError) -> Result<bool, Error> {
        let record = self.slots[index]
            .record
            .as_ref()
            .ok_or(ProtocolError::StaleGeneration)?;
        let operation = record.job.operation;
        if self.quiescent(operation)? {
            self.slots[index]
                .record
                .as_mut()
                .ok_or(ProtocolError::StaleGeneration)?
                .state = State::Failed(reason);
            return Ok(true);
        }
        let retiring = self.slots[index]
            .record
            .as_ref()
            .is_some_and(|record| matches!(record.state, State::Retiring(_)));
        if !retiring {
            if let Err(error) = self.native.cancel(operation) {
                let _retired = self.stop(ProtocolError::Io);
                return Err(error);
            }
            self.slots[index]
                .record
                .as_mut()
                .ok_or(ProtocolError::StaleGeneration)?
                .state = State::Retiring(reason);
        }
        if self.quiescent(operation)? {
            self.slots[index]
                .record
                .as_mut()
                .ok_or(ProtocolError::StaleGeneration)?
                .state = State::Failed(reason);
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn clean_tombstones<const P: usize>(&mut self, book: &Book<'book, '_, '_, P>) {
        for slot in self.slots.iter_mut() {
            if slot.record.is_none()
                && slot
                    .used
                    .is_some_and(|request| book.signing_local(request).is_err())
            {
                slot.used = None;
            }
        }
    }
    /// Admit exactly one original request after checking the same live Book and
    /// current real key/MQ. No ID, row or operation is consumed on refusal.
    pub fn submit<const P: usize>(
        &mut self,
        book: &Book<'book, '_, '_, P>,
        request: SignRequest<'book>,
        expires: MonoInstant,
    ) -> Result<Job<'book, 'pils>, Error> {
        self.same_book(book)?;
        if self.stopped.is_some() {
            return Err(ProtocolError::Closed.into());
        }
        if !self.current() || book.signing_local(request)? != self.local() {
            return Err(ProtocolError::Authentication.into());
        }
        let now = self.now()?;
        if expires.0 == u64::MAX || expires <= now {
            return Err(ProtocolError::Deadline.into());
        }
        let hard_stop = MonoInstant(
            expires
                .0
                .checked_add(self.limits.retirement_grace_micros)
                .filter(|n| *n != u64::MAX)
                .ok_or(ProtocolError::Overflow)?,
        );
        self.timebase.native_bound(hard_stop)?;
        self.clean_tombstones(book);
        if self.slots.iter().any(|slot| slot.used == Some(request)) {
            return Err(ProtocolError::Conflict.into());
        }
        let index = self
            .slots
            .iter()
            .position(|slot| slot.record.is_none() && slot.used.is_none())
            .ok_or(ProtocolError::Capacity)?;
        let mut purpose = [0; 16];
        let size = request.purpose(&mut purpose)?;
        // Exact binds the complete current announcement, including its local
        // revision. A verified same-key HELLO on this original MQ can refresh
        // that observation without replacing our original epoch/key anchor or
        // any previously admitted job and its fixed retirement bounds.
        let identity = self.native.identity().ok_or(ProtocolError::NotReady)?;
        if identity.epoch() != self.epoch || identity.peer() != self.identity.peer() {
            return Err(ProtocolError::Authentication.into());
        }
        let operation = self
            .native
            .sign(&purpose[..size], KeyTarget::Exact(identity))?;
        let job = Job {
            request,
            operation,
            expires,
            hard_stop,
        };
        self.slots[index].used = Some(request);
        self.slots[index].record = Some(Record {
            job,
            state: State::Running,
        });
        self.report.submitted = self.report.submitted.saturating_add(1);
        Ok(job)
    }
    /// Earliest original expiry or hard-stop target, never a refreshed timeout.
    #[must_use]
    pub fn next_deadline(&self) -> Option<MonoInstant> {
        self.slots
            .iter()
            .filter_map(|slot| slot.record.as_ref())
            .filter_map(|record| match record.state {
                State::Failed(_) => None,
                State::Retiring(_) => Some(record.job.hard_stop),
                _ => Some(record.job.expires),
            })
            .min()
    }
    fn expire(&mut self, now: MonoInstant) -> Result<Option<Step<'book, 'pils, O>>, Error> {
        for index in 0..self.slots.len() {
            let Some(record) = self.slots[index].record.as_ref() else {
                continue;
            };
            let job = record.job;
            if matches!(record.state, State::Failed(_)) {
                continue;
            }
            if now >= job.hard_stop {
                let retired = self.stop(ProtocolError::Deadline);
                return Ok(Some(Step::Stopped {
                    reason: ProtocolError::Deadline,
                    retired,
                }));
            }
            let reason = match record.state {
                State::Retiring(reason) => Some(reason),
                _ if now >= job.expires => Some(ProtocolError::Deadline),
                _ => None,
            };
            if let Some(reason) = reason
                && self.begin_retire(index, reason)?
            {
                return Ok(Some(Step::Retired { job }));
            }
        }
        Ok(None)
    }
    fn complete(
        &mut self,
        completion: pc::Completion<'pils>,
        now: MonoInstant,
    ) -> Step<'book, 'pils, O> {
        let operation = completion.operation();
        let Some(index) = self.slots.iter().position(|slot| {
            slot.record
                .as_ref()
                .is_some_and(|record| record.job.operation == operation)
        }) else {
            return Step::Rejected {
                job: None,
                operation,
                reason: ProtocolError::StaleGeneration,
            };
        };
        let Some(record) = self.slots[index].record.as_ref() else {
            return Step::Rejected {
                job: None,
                operation,
                reason: ProtocolError::StaleGeneration,
            };
        };
        let job = record.job;
        let no_success = match record.state {
            State::Retiring(reason) | State::Failed(reason) => Some(reason),
            _ if now >= job.expires => Some(ProtocolError::Deadline),
            _ => None,
        };
        if let Some(reason) = no_success {
            if let Some(record) = self.slots[index].record.as_mut() {
                record.state = State::Failed(reason);
            }
            return Step::Rejected {
                job: Some(job),
                operation,
                reason,
            };
        }
        match completion {
            pc::Completion::Signature {
                peer,
                signature,
                announced: Some(identity),
                ..
            } if self.current()
                && peer == self.identity.peer()
                && identity.epoch() == self.epoch
                && identity.peer() == self.identity.peer() =>
            {
                if let Some(record) = self.slots[index].record.as_mut() {
                    record.state = State::Ready(*signature.as_bytes());
                }
                self.report.received = self.report.received.saturating_add(1);
                Step::Ready { job }
            }
            pc::Completion::Failed {
                kind: pc::OperationKind::Sign,
                reason: pc::Failure::KeyChanged,
                ..
            } => {
                let retired = self.stop(ProtocolError::Authentication);
                Step::KeyChanged {
                    job,
                    operation,
                    retired,
                }
            }
            pc::Completion::Failed {
                kind: pc::OperationKind::Sign,
                reason,
                ..
            } => {
                let reason = match reason {
                    pc::Failure::IdentityUnavailable => ProtocolError::NotReady,
                    pc::Failure::CryptoRejected
                    | pc::Failure::InvalidSignature
                    | pc::Failure::KeyChanged => ProtocolError::Authentication,
                };
                if let Some(record) = self.slots[index].record.as_mut() {
                    record.state = State::Failed(reason);
                }
                Step::Rejected {
                    job: Some(job),
                    operation,
                    reason,
                }
            }
            _ => {
                let _retired = self.stop(ProtocolError::Authentication);
                Step::Rejected {
                    job: Some(job),
                    operation,
                    reason: ProtocolError::Authentication,
                }
            }
        }
    }
    /// Poll only original IO/deadlines. Actual loss/identity change permanently
    /// closes this source before another drive could reissue original signing.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Option<Instant>,
    ) -> Poll<Result<Step<'book, 'pils, O>, Error>> {
        if let Some(reason) = self.stopped {
            return Poll::Ready(Ok(Step::Closed(reason)));
        }
        let now = self.now()?;
        if let Some(step) = self.expire(now)? {
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
                actual => Step::Native(actual),
            })),
        }
    }
    /// Poll original Book revocation before IO, preserving actual retirement of
    /// any admitted operation while rejecting new work for a retired route.
    pub fn poll_book<const P: usize>(
        &mut self,
        cx: &mut Context<'_>,
        book: &Book<'book, '_, '_, P>,
        deadline: Option<Instant>,
    ) -> Poll<Result<Step<'book, 'pils, O>, Error>> {
        self.same_book(book)?;
        self.clean_tombstones(book);
        for index in 0..self.slots.len() {
            let Some(record) = self.slots[index].record.as_ref() else {
                continue;
            };
            if !matches!(record.state, State::Failed(_) | State::Retiring(_))
                && book.signing_local(record.job.request).is_err()
            {
                let job = record.job;
                if self.begin_retire(index, ProtocolError::Cancelled)? {
                    return Poll::Ready(Ok(Step::Retired { job }));
                }
            }
        }
        self.poll(cx, deadline)
    }
    /// Cancellation-safe waiting on the same owner and original operation data.
    pub async fn drive(
        &mut self,
        deadline: Option<Instant>,
    ) -> Result<Step<'book, 'pils, O>, Error> {
        poll_fn(|cx| self.poll(cx, deadline)).await
    }
    /// Apply a private actual result to the exact original Book. Capacity keeps
    /// the original signature for retry; no additional PILS operation is started.
    pub fn finish<const P: usize>(
        &mut self,
        book: &mut Book<'book, '_, '_, P>,
        job: Job<'book, 'pils>,
    ) -> Result<Completion<'book>, Error> {
        self.same_book(book)?;
        let index = self.index(job)?;
        if let Some(reason) =
            self.slots[index]
                .record
                .as_ref()
                .and_then(|record| match record.state {
                    State::Failed(reason) | State::Retiring(reason) => Some(reason),
                    _ => None,
                })
        {
            if !self.quiescent(job.operation)? {
                return Ok(Completion::Pending);
            }
            self.slots[index].record = None;
            return Ok(Completion::Failed(reason));
        }
        let now = self.now()?;
        let reason = if book.signing_local(job.request).is_err() {
            Some(ProtocolError::Cancelled)
        } else if now >= job.expires {
            Some(ProtocolError::Deadline)
        } else {
            None
        };
        if let Some(reason) = reason {
            if !self.begin_retire(index, reason)? {
                return Ok(Completion::Pending);
            }
            self.slots[index].record = None;
            return Ok(Completion::Failed(reason));
        }
        if !self.current() {
            let _retired = self.stop(ProtocolError::StaleGeneration);
            self.slots[index].record = None;
            return Ok(Completion::Failed(ProtocolError::StaleGeneration));
        }
        if !self.quiescent(job.operation)? {
            return Ok(Completion::Pending);
        }
        let Some(record) = self.slots[index].record.as_ref() else {
            return Err(ProtocolError::StaleGeneration.into());
        };
        let State::Ready(signature) = record.state else {
            return Ok(Completion::Pending);
        };
        match book.signed(job.request, self.local(), signature, now) {
            Ok(frame) => {
                self.slots[index].record = None;
                self.report.applied = self.report.applied.saturating_add(1);
                Ok(Completion::Signed { frame })
            }
            Err(reason @ (ProtocolError::Capacity | ProtocolError::WouldBlock)) => {
                Ok(Completion::Blocked(reason))
            }
            Err(reason) => {
                self.slots[index].record = None;
                Ok(Completion::Failed(reason))
            }
        }
    }
    /// Cancel/drain only the original admitted job. True means its actual SDK
    /// operation is quiescent; it does not claim remote receipt or route teardown.
    pub fn retire(&mut self, job: Job<'book, 'pils>) -> Result<bool, Error> {
        let index = self.index(job)?;
        if self.begin_retire(index, ProtocolError::Cancelled)? {
            self.slots[index].record = None;
            self.report.retired = self.report.retired.saturating_add(1);
            Ok(true)
        } else {
            Ok(false)
        }
    }
    /// Physically stop this original source before marking original jobs failed.
    /// Caller can then finish/retire those exact jobs without a new source clock.
    pub fn close(&mut self) -> [Option<OperationId<'pils>>; O] {
        self.stop(ProtocolError::Closed)
    }
    /// Every original job has actually retired from this stopped source. Used
    /// alongside the coordinator's independent peer barrier before handoff.
    #[must_use]
    pub fn jobs_retired(&self) -> bool {
        self.stopped.is_some() && self.slots.iter().all(|slot| slot.record.is_none())
    }
    /// Explicit recovery of this original runtime port; no dead source is rebound.
    pub fn recover_ports(&mut self) -> Result<(), Error> {
        if self.stopped.is_some() {
            return Err(ProtocolError::Closed.into());
        }
        self.native.recover_ports()
    }
}
impl<const O: usize> Drop for Signer<'_, '_, '_, O> {
    fn drop(&mut self) {
        let _retired = self.native.close();
        for slot in self.slots.iter_mut() {
            slot.record = None;
            slot.used = None;
        }
    }
}
