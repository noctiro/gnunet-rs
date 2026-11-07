//! Actual independent PEERSTORE writer for the retained original Validated
//! effect. No aggregate journal/server or successful-enqueue stand-in exists.
use crate::{
    Failure,
    time::{self, Bounds},
};
use gnunet_client_host::EndpointSource;
use gnunet_peerstore_client_host as ps;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_transport::PeerId;
use gnunet_transport_host::AddressStore;
use gnunet_types::Error as Fault;
use gnunet_wire::official::AbsoluteTime;
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
/// Finite original storage operation/source/input budgets.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Actual existing CLIENT budgets.
    pub client: ps::Limits,
    /// Original operation response/admission budget.
    pub operation: Duration,
    /// First actual native source attachment budget.
    pub initial: Duration,
    /// First partial input bound.
    pub input: Duration,
    /// Source lease even while idle.
    pub source: Duration,
    /// Registered retry for known pre-admission capacity only.
    pub retry: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            client: ps::Limits {
                operations: 1,
                ..Default::default()
            },
            operation: Duration::from_secs(60),
            initial: Duration::from_secs(30),
            input: Duration::from_secs(10),
            source: Duration::from_secs(86400),
            retry: Duration::from_millis(100),
        }
    }
}
struct Pending<'id> {
    peer: PeerId,
    address: Vec<u8>,
    until: AbsoluteTime,
    bounds: Bounds,
    operation: Option<ps::Operation<'id>>,
    epoch: Option<ps::Epoch<'id>>,
    result: Option<Result<(), Fault>>,
    observed: Option<ps::Outcome>,
}
#[derive(Debug)]
struct Errors {
    original: Failure,
    cleanup: Option<Failure>,
}
impl std::fmt::Display for Errors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.original.fmt(f)?;
        if let Some(e) = &self.cleanup {
            write!(f, "; cleanup: {e}")?;
        }
        Ok(())
    }
}
impl std::error::Error for Errors {}
/// Exact original validated-address effect retired from a closed Engine.
/// The address allocation and actual raw operation/epoch are never rebound.
pub struct RetiredValidation<'id> {
    /// Original authenticated peer binding.
    pub peer: PeerId,
    /// Original immutable PEERSTORE URL value including its terminal NUL.
    pub address: Vec<u8>,
    /// Exact original absolute record expiry; no retirement/retry renewal.
    pub expiration: AbsoluteTime,
    /// Original canonical and independent native job targets.
    pub bounds: Bounds,
    /// Actual original native operation, or no-admission provenance.
    pub operation: Option<ps::Operation<'id>>,
    /// Actual original source epoch, when attached.
    pub epoch: Option<ps::Epoch<'id>>,
    /// Actual processing/local/unknown assurance of this old effect only.
    pub outcome: RetiredOutcome,
    /// Original native/worker-port failure, independent of any known raw code.
    pub failure: Option<crate::epoch::SharedFailure>,
}
/// Actual local/native assurance of the original retirement.
pub enum RetiredOutcome {
    /// No native STORE operation was ever admitted for this original effect.
    NotAdmitted,
    /// Original matching actual STORE_RESULT1 only, never fsync or new authority.
    StoredByService,
    /// Actual original signed STORE_RESULT failure, not an inferred rollback.
    Refused(i32),
    /// Actual SDK local termination with original byte-exposure facts.
    Ended {
        /// Actual local completion reason from the original SDK row.
        reason: ps::Reason,
        /// Actual Unsent/Unknown bytes, never an inferred rollback.
        submission: ps::Submission,
    },
    /// Physical retirement without an authoritative observed original result.
    Unknown,
}
/// Holds exactly one original public effect until its real STORE_RESULT. STOREs
/// are never replayed after loss, even if the public record may have committed.
pub struct ValidatedStore<'id> {
    client: ps::Client<'id>,
    clock: Arc<dyn RuntimeClock>,
    limits: Limits,
    pending: Option<Pending<'id>>,
    error: Option<Failure>,
    failed: bool,
    store_failures: u64,
    epoch: Option<ps::Epoch<'id>>,
    source: Option<Bounds>,
    initial: Option<Instant>,
    input: Option<Instant>,
    alarm: Option<Pin<Box<Sleep>>>,
    retry: Option<Pin<Box<Sleep>>>,
}
impl<'id> ValidatedStore<'id> {
    /// Reserve actual public CLIENT resources under the same process source.
    pub fn new(
        instance: &'id mut ps::Instance,
        source: EndpointSource,
        time: time::Clock,
        limits: Limits,
    ) -> Result<Self, Failure> {
        let clock = source.clock();
        if !Arc::ptr_eq(&clock, &time.source()) {
            return Err("TRANSPORT PEERSTORE clock differs".into());
        }
        for d in [
            limits.operation,
            limits.initial,
            limits.input,
            limits.source,
            limits.retry,
        ] {
            if d.is_zero() || Instant::now().checked_add(d).is_none() {
                return Err("invalid TRANSPORT PEERSTORE time budget".into());
            }
        }
        let now = clock.sample()?.now.as_micros();
        let bounds = Bounds::after(now, limits.source)?;
        let initial = Instant::now()
            .checked_add(limits.initial)
            .ok_or(Fault::Overflow)?
            .min(bounds.hard);
        let client = ps::Client::new(instance, source, limits.client)?;
        Ok(Self {
            client,
            clock,
            limits,
            pending: None,
            error: None,
            failed: false,
            store_failures: 0,
            epoch: None,
            source: Some(bounds),
            initial: Some(initial),
            input: None,
            alarm: None,
            retry: None,
        })
    }
    fn fail(&mut self, error: Failure) -> Fault {
        if !self.failed {
            self.failed = true;
            let cleanup = self.client.close().err().map(|e| Box::new(e) as Failure);
            self.error = Some(Box::new(Errors {
                original: error,
                cleanup,
            }));
            if let Some(row) = &mut self.pending
                && row.result.is_none()
            {
                row.result = Some(Err(Fault::Storage));
            }
        }
        Fault::Storage
    }
    /// Actual native attachment only, never storage readiness/success.
    pub fn connected(&self) -> bool {
        self.epoch.is_some() && !self.failed
    }
    /// Actual source-matched foreign-address STORE_RESULT failure codes.
    pub fn store_failures(&self) -> u64 {
        self.store_failures
    }
    /// Retain actual original native/STORE failure separately from Error enum.
    pub fn take_error(&mut self) -> Option<Failure> {
        self.error.take()
    }
    /// Only original native targets; no sample, decode or IO. Real close precedes
    /// local failure. An outer canonical wait cannot mask these targets.
    pub fn native_guard(&mut self, cx: &mut Context<'_>) -> Result<(), Fault> {
        if self.failed {
            return Err(Fault::Storage);
        }
        let now = Instant::now();
        if self.source.is_some_and(|b| now >= b.hard)
            || self.initial.is_some_and(|at| now >= at)
            || self.input.is_some_and(|at| now >= at)
            || self.pending.as_ref().is_some_and(|p| now >= p.bounds.hard)
        {
            return Err(self.fail(Box::new(Fault::Deadline)));
        }
        let target = self
            .source
            .map(|b| b.hard)
            .into_iter()
            .chain(self.initial)
            .chain(self.input)
            .chain(self.pending.as_ref().map(|p| p.bounds.hard))
            .min();
        if let Some(at) = target {
            let alarm = self
                .alarm
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(at)));
            alarm.as_mut().reset(at);
            if alarm.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        } else {
            self.alarm = None;
        }
        Ok(())
    }
    fn progress(&mut self, p: ps::Progress<'id>) -> Result<(), Fault> {
        match p {
            ps::Progress::Connected(epoch) => {
                self.epoch = Some(epoch);
                self.initial = None;
                if let Some(row) = &mut self.pending {
                    if row.epoch.is_some_and(|old| old != epoch) {
                        return Err(self.fail(Box::new(Fault::Stale)));
                    }
                    row.epoch = Some(epoch);
                }
            }
            ps::Progress::Activity {
                epoch, read_bytes, ..
            } => {
                if self.epoch != Some(epoch) {
                    return Err(self.fail(Box::new(Fault::Stale)));
                }
                if read_bytes > 0 && self.input.is_none() {
                    self.input = Some(
                        Instant::now()
                            .checked_add(self.limits.input)
                            .ok_or(Fault::Overflow)?,
                    );
                }
            }
            ps::Progress::Written {
                epoch, operation, ..
            } => {
                if let Some(row) = &self.pending
                    && row.operation == Some(operation)
                    && row.epoch != Some(epoch)
                {
                    return Err(self.fail(Box::new(Fault::Stale)));
                }
            }
            ps::Progress::Completed {
                epoch,
                operation,
                kind,
                outcome,
            } => {
                self.input = None;
                if let Some(row) = &mut self.pending
                    && row.operation == Some(operation)
                {
                    if kind != ps::Kind::Store
                        || (matches!(outcome, ps::Outcome::StoreResult(_)) && epoch != row.epoch)
                    {
                        return Err(self.fail(Box::new(Fault::Stale)));
                    }
                    row.observed = Some(outcome);
                    if matches!(outcome, ps::Outcome::StoreResult(1)) {
                        row.result = Some(Ok(()));
                    } else {
                        if matches!(outcome, ps::Outcome::StoreResult(_)) {
                            self.store_failures = self.store_failures.saturating_add(1);
                        }
                        return Err(self.fail(
                            format!(
                                "TRANSPORT original validated STORE {operation:?}: {outcome:?}"
                            )
                            .into(),
                        ));
                    }
                }
            }
            ps::Progress::Lost { epoch, cause, .. } => {
                self.input = None;
                self.epoch = None;
                // An exposed/unexposed original store is never copied to a new MQ.
                return Err(self.fail(
                    format!("TRANSPORT PEERSTORE original source {epoch:?}: {cause:?}").into(),
                ));
            }
            ps::Progress::Unavailable(error) => return Err(self.fail(Box::new(error))),
            ps::Progress::ConnectRetry { error, retry_after } => {
                let _ = retry_after;
                return Err(self.fail(Box::new(error)));
            }
            ps::Progress::Ignored(_) => self.input = None,
            ps::Progress::Capacity(_) => return Err(self.fail(Box::new(Fault::Capacity))),
            ps::Progress::Closed => return Err(self.fail(Box::new(Fault::Closed))),
            ps::Progress::Record(_) | ps::Progress::Sync { .. } => {
                return Err(self.fail(Box::new(Fault::Malformed)));
            }
            ps::Progress::WaitDeadline => {}
        }
        Ok(())
    }
    /// Drive the actual CLIENT independently from domain persistence polling,
    /// including when the Engine is waiting on this same original receipt.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Fault>> {
        self.native_guard(cx)?;
        let result = {
            let mut driving = std::pin::pin!(self.client.drive(None));
            driving.as_mut().poll(cx)
        };
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.fail(Box::new(error)))),
            Poll::Ready(Ok(p)) => {
                self.progress(p)?;
                self.native_guard(cx)?;
                Poll::Ready(Ok(()))
            }
        }
    }
    /// No old authenticated foreign-address effect remains owned.
    pub fn idle(&self) -> bool {
        self.pending.is_none()
    }
    /// A real source failure cannot be repaired merely by rebuilding Engine.
    pub fn reusable(&self) -> bool {
        !self.failed
    }
    /// Drain an already retired Engine's exact original STORE, without admitting
    /// an unstarted effect. The native operation itself remains on its source.
    pub fn poll_retired(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<RetiredValidation<'id>>, Fault>> {
        if self.pending.is_none() {
            return Poll::Ready(Ok(None));
        }
        let never_admitted = self.pending.as_ref().is_some_and(|p| p.operation.is_none());
        if !never_admitted && self.pending.as_ref().is_some_and(|p| p.result.is_none()) {
            match self.poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(_)) => {}
            }
            if self.pending.as_ref().is_some_and(|p| p.result.is_none()) {
                return Poll::Pending;
            }
        }
        if self.failed {
            let (mut retired, cleanup) = self.retire_now();
            if !cleanup.is_empty()
                && let Some(done) = &mut retired
            {
                done.failure = Some(crate::epoch::SharedFailure::new(Box::new(
                    crate::Failures {
                        original: done
                            .failure
                            .as_ref()
                            .map(crate::epoch::SharedFailure::boxed),
                        cleanup,
                    },
                )));
            }
            return Poll::Ready(Ok(retired));
        }
        let row = self.pending.take().ok_or(Fault::Stale)?;
        let failure = self.take_error().map(crate::epoch::SharedFailure::new);
        let outcome = retired_outcome(&row);
        self.retry = None;
        Poll::Ready(Ok(Some(RetiredValidation {
            peer: row.peer,
            address: row.address,
            expiration: row.until,
            bounds: row.bounds,
            operation: row.operation,
            epoch: row.epoch,
            outcome,
            failure,
        })))
    }
    /// Physically close first, then transfer every original effect/result without
    /// clock/IO admission. An absent result remains Unknown, never rolled back.
    pub fn retire_now(&mut self) -> (Option<RetiredValidation<'id>>, Vec<Failure>) {
        let mut errors = Vec::new();
        let close = self.client.close();
        if let Err(error) = close {
            errors.push(Box::new(error) as Failure);
        }
        while let Some(event) = self.client.next_event() {
            if let ps::Progress::Completed {
                operation,
                kind,
                epoch,
                outcome,
            } = event
                && let Some(row) = &mut self.pending
                && row.operation == Some(operation)
            {
                if kind != ps::Kind::Store
                    || (matches!(outcome, ps::Outcome::StoreResult(_)) && row.epoch != epoch)
                {
                    errors.push(Box::new(Fault::Stale));
                } else if row.observed.is_none() {
                    if matches!(outcome, ps::Outcome::StoreResult(code) if code != 1) {
                        self.store_failures = self.store_failures.saturating_add(1);
                    }
                    row.observed = Some(outcome);
                }
            }
        }
        let failure = self.take_error().map(crate::epoch::SharedFailure::new);
        let retired = self.pending.take().map(|row| {
            let outcome = retired_outcome(&row);
            RetiredValidation {
                peer: row.peer,
                address: row.address,
                expiration: row.until,
                bounds: row.bounds,
                operation: row.operation,
                epoch: row.epoch,
                outcome,
                failure: failure.clone(),
            }
        });
        if retired.is_none()
            && let Some(error) = failure
        {
            errors.push(error.boxed());
        }
        self.failed = true;
        self.retry = None;
        self.alarm = None;
        self.initial = None;
        self.input = None;
        (retired, errors)
    }
    /// Physically retire the original MQ and preserve its independent outcome.
    pub fn close(&mut self) -> Vec<Failure> {
        let mut errors = Vec::new();
        if let Err(e) = self.client.close() {
            errors.push(Box::new(e) as Failure);
        }
        if let Some(e) = self.error.take() {
            errors.push(e);
        }
        self.failed = true;
        errors
    }
}
impl AddressStore for ValidatedStore<'_> {
    fn validated(&mut self, _peer: PeerId, _address: &[u8], _until: u64) -> Result<(), Fault> {
        Err(Fault::NotReady)
    }
    fn poll_validated(
        &mut self,
        cx: &mut Context<'_>,
        peer: PeerId,
        address: &[u8],
        until: u64,
    ) -> Poll<Result<(), Fault>> {
        self.native_guard(cx)?;
        if self.pending.is_none() {
            if address.is_empty() || address.contains(&0) {
                return Poll::Ready(Err(Fault::Malformed));
            }
            let now = self
                .clock
                .sample()
                .map_err(|e| self.fail(Box::new(e)))?
                .now
                .as_micros();
            // Engine supplied an actual absolute expiration at successful
            // validation. Retain it exactly: queue waits, retries or a later
            // logical correction never turn it into now+remaining/now+lifetime.
            let bounds = Bounds::after(now, self.limits.operation)?;
            let mut value = Vec::new();
            value
                .try_reserve_exact(address.len().checked_add(1).ok_or(Fault::Overflow)?)
                .map_err(|_| Fault::Capacity)?;
            value.extend_from_slice(address);
            value.push(0);
            self.pending = Some(Pending {
                peer,
                address: value,
                until: AbsoluteTime::from_micros(until),
                bounds,
                operation: None,
                epoch: self.epoch,
                result: None,
                observed: None,
            });
        }
        let row = self.pending.as_ref().ok_or(Fault::NotReady)?;
        if row.peer != peer
            || row.until.as_micros() != until
            || row.address.strip_suffix(&[0]) != Some(address)
        {
            return Poll::Ready(Err(Fault::Stale));
        }
        if let Some(result) = self.pending.as_mut().and_then(|p| p.result.take()) {
            self.pending = None;
            return Poll::Ready(result);
        }
        if self.pending.as_ref().is_some_and(|p| p.operation.is_none()) {
            if let Some(retry) = &mut self.retry {
                if retry.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
                self.retry = None;
            }
            let row = self.pending.as_ref().ok_or(Fault::NotReady)?;
            let record = ps::Record {
                peer: row.peer.0,
                expiry: row.until.as_micros(),
                subsystem: Some(b"transport"),
                key: Some(b"transport-communicator-url"),
                value: &row.address,
            };
            match self.client.store(record, 0, row.bounds.expires) {
                Ok(operation) => {
                    self.pending.as_mut().ok_or(Fault::Stale)?.operation = Some(operation)
                }
                Err(ps::Error::Protocol(Fault::WouldBlock | Fault::Capacity | Fault::NotReady)) => {
                    self.retry = Some(Box::pin(tokio::time::sleep_until(
                        Instant::now()
                            .checked_add(self.limits.retry)
                            .ok_or(Fault::Overflow)?,
                    )));
                }
                Err(error) => return Poll::Ready(Err(self.fail(Box::new(error)))),
            }
        }
        if let Poll::Ready(result) = self.poll(cx) {
            result?;
        }
        if let Some(result) = self.pending.as_mut().and_then(|p| p.result.take()) {
            self.pending = None;
            return Poll::Ready(result);
        }
        Poll::Pending
    }
}
fn retired_outcome(row: &Pending<'_>) -> RetiredOutcome {
    if row.operation.is_none() {
        return RetiredOutcome::NotAdmitted;
    }
    match row.observed {
        Some(ps::Outcome::StoreResult(1)) => RetiredOutcome::StoredByService,
        Some(ps::Outcome::StoreResult(code)) => RetiredOutcome::Refused(code),
        Some(ps::Outcome::Local { reason, submission }) => {
            RetiredOutcome::Ended { reason, submission }
        }
        Some(ps::Outcome::IterationEnd(_)) | None => RetiredOutcome::Unknown,
    }
}
