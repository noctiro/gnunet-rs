//! One concrete process owns the original ClockPort and single replay Ledger.
//! Calls are sequential; no RefCell, second clock, worker or fake history port.
use crate::{
    clock::{self, ClockPort},
    epoch::{self, Epoch, Quiescent, ReplayPermit},
};
use gnunet_crypto::EddsaPublicKey;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_tcp_communicator_core::session::Time;
use gnunet_tcp_communicator_host::{
    Clock,
    history::{HistoryProgress, ReplayHistory, ReplayTask},
};
use gnunet_tcp_replay_host::{self as replay, Ledger, Submission};
use gnunet_types::Error;
use std::{
    fmt, io,
    sync::Arc,
    task::{Context, Poll},
};
/// Supported normal maximum session count times the existing actual per-session
/// replay operation bound. Registry preamble metadata2n does not double physical
/// Manager sessions or this original replay task budget.
pub const MAXIMUM_ENTRIES: usize = 4096 * gnunet_tcp_communicator_core::session::REPLAY_CAPACITY;
/// Original storage/authorization refusal; successful PS queue admission is
/// never undone or retried because later local reporting failed.
#[derive(Debug)]
pub enum Failure {
    /// Explicit quota/source/operation invariant failure.
    Protocol(Error),
    /// Original local ledger fault with actual publication/cleanup details.
    Ledger(Arc<replay::Failure>),
    /// Original frontier barrier cause; the local floor remains burned.
    Frontier(epoch::Failure),
    /// Original canonical clock/frontier acquisition failure.
    Clock(clock::Failure),
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TCP process replay: {self:?}")
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(e) => Some(e),
            Self::Ledger(e) => Some(&**e),
            Self::Frontier(e) => Some(e),
            Self::Clock(e) => Some(e),
        }
    }
}
/// Both independent actual first operation and clock failures. Taking this
/// report does not reset the permanent failure latch.
#[derive(Debug)]
pub struct Failures {
    /// Original process/history operation failure.
    pub operation: Option<Failure>,
    /// Independent original ClockPort failure.
    pub clock: Option<clock::Failure>,
}
impl fmt::Display for Failures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TCP process failures: {self:?}")
    }
}
impl std::error::Error for Failures {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.operation
            .as_ref()
            .map(|v| v as &dyn std::error::Error)
            .or_else(|| self.clock.as_ref().map(|v| v as &dyn std::error::Error))
    }
}
/// Constructor rejection retains both exact original owners for explicit cleanup.
pub struct Rejected {
    /// Actual refusal before ownership is accepted.
    pub error: Failure,
    /// Original clock and worker owners; no substitute is created.
    pub resources: Box<Resources>,
}
impl fmt::Debug for Rejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rejected")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
impl fmt::Display for Rejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}
impl std::error::Error for Rejected {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}
/// Actual original resources, initialized and Bound before ProcessPorts admission.
pub struct Resources {
    /// Same process clock/frontier owner.
    pub clock: ClockPort,
    /// Same initialized/recovered single-worker ledger owner.
    pub ledger: Ledger,
}
enum State {
    Pending(replay::Token),
    Floor(replay::Floor),
    Ready(ReplayPermit),
    Admitted,
    Retiring(replay::Token),
    Retired,
}
struct Entry {
    task: ReplayTask,
    value: u64,
    state: State,
}
/// Actual worker join plus independent original operation/clock failures.
#[derive(Debug)]
pub struct Shutdown {
    /// Original ledger drain/join report, not a guessed shutdown.
    pub ledger: replay::Shutdown,
    /// Original independent causes, if any.
    pub failures: Option<Failures>,
    /// First real local drain refusal, independently of its retained cause.
    pub drain: Option<Error>,
}
/// Same concrete object implements Clock and actual ReplayHistory. Fixed entries
/// retain original Task/token/permit until real admission or retirement.
pub struct ProcessPorts {
    clock: ClockPort,
    ledger: Ledger,
    entries: Vec<Option<Entry>>,
    source: Option<ReplayTask>,
    failed: bool,
    first: Option<Failure>,
    reported: bool,
    closing: bool,
    joined: bool,
    uncertain: bool,
}
impl ProcessPorts {
    /// Accept the exact owners only after all metadata reservation and same-source
    /// Bound-catalog/frontier checks. Rejection returns both original resources.
    pub fn adopt(mut resources: Resources, maximum: usize) -> Result<Self, Rejected> {
        let prepared = (|| -> Result<Vec<Option<Entry>>, Failure> {
            if maximum == 0
                || maximum > MAXIMUM_ENTRIES
                || maximum
                    .checked_mul(core::mem::size_of::<Option<Entry>>())
                    .is_none_or(|bytes| bytes > isize::MAX as usize)
            {
                return Err(Failure::Protocol(Error::Capacity));
            }
            let catalog = resources.ledger.catalog().map_err(Failure::Protocol)?;
            if !catalog.is_bound() {
                return Err(Failure::Protocol(Error::NotReady));
            }
            resources
                .clock
                .attach_catalog(&catalog)
                .map_err(Failure::Clock)?;
            let mut entries = Vec::new();
            entries
                .try_reserve_exact(maximum)
                .map_err(|_| Failure::Protocol(Error::Capacity))?;
            entries.resize_with(maximum, || None);
            Ok(entries)
        })();
        match prepared {
            Ok(entries) => Ok(Self {
                clock: resources.clock,
                ledger: resources.ledger,
                entries,
                source: None,
                failed: false,
                first: None,
                reported: false,
                closing: false,
                joined: false,
                uncertain: false,
            }),
            Err(error) => Err(Rejected {
                error,
                resources: Box::new(resources),
            }),
        }
    }
    /// Actual process source used by the original Resolver/client/address owner.
    #[must_use]
    pub fn source(&self) -> Arc<dyn RuntimeClock> {
        self.clock.source()
    }
    /// Admit only this actual identity/ledger-bound original process epoch.
    pub fn begin_epoch(&mut self, peer: EddsaPublicKey) -> Result<Epoch, clock::Failure> {
        self.clock.begin_epoch(peer)
    }
    /// Last real successful time, for exact clock-free peer retirement only.
    #[must_use]
    pub fn last_time(&self) -> Option<Time> {
        self.clock.last_time()
    }
    /// Retain all independent first causes without clearing permanent refusal.
    pub fn take_failure(&mut self) -> Option<Failures> {
        let operation = self.first.take();
        let clock = self.clock.take_failure();
        if operation.is_none() && clock.is_none() {
            None
        } else {
            Some(Failures { operation, clock })
        }
    }
    fn fail(&mut self, error: Failure, uncertain: bool) -> Error {
        self.failed = true;
        self.uncertain |= uncertain;
        if self.first.is_none() {
            self.first = Some(error);
        }
        if uncertain {
            Error::OutcomeUnknown
        } else {
            Error::Io
        }
    }
    fn bind_task(&mut self, task: &ReplayTask) -> Result<(), Error> {
        if self.failed || self.closing {
            return Err(Error::Closed);
        }
        if let Some(source) = &self.source {
            if !source.same_process(task) {
                return Err(Error::Stale);
            }
        } else {
            self.source = Some(task.clone());
        }
        Ok(())
    }
    fn index(&self, task: &ReplayTask) -> Option<usize> {
        self.entries
            .iter()
            .position(|row| row.as_ref().is_some_and(|e| e.task == *task))
    }
    fn ready(&mut self, index: usize, floor: replay::Floor) -> Result<(), Error> {
        let original = &self.entries[index].as_ref().ok_or(Error::Stale)?.task;
        if floor.peer() != original.peer()
            || floor.kind() != original.kind()
            || floor.stamp() != self.entries[index].as_ref().ok_or(Error::Stale)?.value
        {
            return Err(self.fail(Failure::Protocol(Error::Stale), true));
        }
        let permit = match self.clock.authorize_replay(floor) {
            Ok(permit) => permit,
            Err(rejected) => {
                let uncertain = rejected.error.outcome == epoch::Outcome::Unknown;
                return Err(self.fail(Failure::Frontier(rejected.error), uncertain));
            }
        };
        self.entries[index].as_mut().ok_or(Error::Stale)?.state = State::Ready(permit);
        Ok(())
    }
    /// Gate new replay work, keeping original worker and callback debts alive.
    /// Existing peers may still use their original clock for graceful cleanup.
    pub fn begin_stop(&mut self) {
        self.closing = true;
    }
    /// Refuse canonical work without discarding original worker/job ownership.
    /// shutdown must still actually drain/join before finish can clean an epoch.
    pub fn close(&mut self) {
        self.begin_stop();
        self.clock.close();
    }
    /// Real drain/join after original Pool/service work has retired. This samples
    /// no new clock. Every original ledger outcome is observed before actual join.
    pub async fn shutdown(&mut self, mut observe: impl FnMut(HistoryProgress)) -> Shutdown {
        self.closing = true;
        self.clock.close();
        for i in 0..self.entries.len() {
            let task = self.entries[i].as_ref().map(|entry| entry.task.clone());
            if let Some(task) = task
                && let Err(error) = self.retire_history(&task)
            {
                self.fail(Failure::Protocol(error), true);
            }
        }
        self.ledger.begin_close();
        let mut drain = None;
        while !self.ledger.is_drained() || self.entries.iter().any(Option::is_some) {
            match std::future::poll_fn(|cx| self.poll_history(cx)).await {
                Ok(event) => observe(event),
                Err(error) => {
                    if drain.is_none() {
                        drain = Some(error);
                    }
                    if !self.failed {
                        self.fail(Failure::Protocol(error), true);
                    }
                }
            }
        }
        let ledger = self.ledger.shutdown(|_| {}).await;
        self.joined = ledger.stopped.is_some() && ledger.join.is_none();
        if let Some(error) = &ledger.original {
            self.failed = true;
            self.uncertain |= error.uncertain;
        }
        if ledger.join.is_some() {
            self.uncertain = true;
        }
        Shutdown {
            ledger,
            failures: self.take_failure(),
            drain,
        }
    }
    /// Clean only the actual original quiescent Pool after ledger physical join.
    /// Unknown persistence cannot be converted to a clean process by this method.
    pub fn finish_epoch(&mut self, proof: Quiescent) -> Result<(), epoch::FinishRejected> {
        if !self.joined || self.uncertain || self.entries.iter().any(Option::is_some) {
            return Err(epoch::FinishRejected {
                proof,
                error: epoch::Failure {
                    stage: epoch::Stage::BackendQuarantine,
                    outcome: epoch::Outcome::Unknown,
                    cause: io::Error::other("original replay worker/debt not certainly joined"),
                },
            });
        }
        self.clock.finish_epoch(proof)
    }
}
impl Clock for ProcessPorts {
    fn read(&mut self) -> Result<Time, Error> {
        if self.failed {
            return Err(Error::OutcomeUnknown);
        }
        self.clock.read()
    }
    fn revision(&self) -> u64 {
        self.clock.revision()
    }
    fn poll_change(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.clock.poll_change(cx)
    }
}
impl ReplayHistory for ProcessPorts {
    fn local_floor(&mut self, task: &ReplayTask) -> Result<Option<u64>, Error> {
        self.bind_task(task)?;
        self.ledger.catalog()?.floor(task.peer(), task.kind())
    }
    fn poll_store(
        &mut self,
        cx: &mut Context<'_>,
        task: &ReplayTask,
        value: u64,
    ) -> Poll<Result<(), Error>> {
        self.bind_task(task)?;
        if value < task.stamp() {
            return Poll::Ready(Err(Error::Stale));
        }
        let index = match self.index(task) {
            Some(index) => {
                let entry = self.entries[index].as_ref().ok_or(Error::Stale)?;
                if value < entry.value {
                    return Poll::Ready(Err(Error::Stale));
                }
                match &entry.state {
                    State::Ready(permit) if entry.value == value => {
                        return Poll::Ready(self.clock.validate_replay(permit));
                    }
                    State::Floor(_) if entry.value == value => {
                        let entry = self.entries[index].take().ok_or(Error::Stale)?;
                        let State::Floor(floor) = entry.state else {
                            return Poll::Ready(Err(Error::Stale));
                        };
                        self.entries[index] = Some(Entry {
                            task: entry.task,
                            value,
                            state: State::Retired,
                        });
                        self.ready(index, floor)?;
                        return Poll::Ready(Ok(()));
                    }
                    State::Floor(_) | State::Ready(_) => {}
                    State::Pending(_) => return Poll::Pending,
                    State::Admitted | State::Retiring(_) | State::Retired => {
                        return Poll::Ready(Err(Error::Stale));
                    }
                }
                index
            }
            None => {
                let Some(index) = self.entries.iter().position(Option::is_none) else {
                    return Poll::Ready(Err(Error::Capacity));
                };
                index
            }
        };
        // A higher real verified value is a new local intent only after the old
        // original job settled. Never replace a pending worker body/token or
        // reseal/requeue a same-value operation because MQ capacity is blocked.
        match self.ledger.submit(task.peer(), task.kind(), value) {
            Ok(Submission::Known(floor)) => {
                self.entries[index] = Some(Entry {
                    task: task.clone(),
                    value,
                    state: State::Floor(floor),
                });
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Ok(Submission::Queued(token)) => {
                self.entries[index] = Some(Entry {
                    task: task.clone(),
                    value,
                    state: State::Pending(token),
                });
                Poll::Pending
            }
            Err(Error::WouldBlock) => Poll::Pending,
            Err(error) => Poll::Ready(Err(error)),
        }
    }
    fn store_admitted(&mut self, task: &ReplayTask, value: u64) {
        let Some(index) = self.index(task) else {
            self.fail(Failure::Protocol(Error::Stale), true);
            return;
        };
        let Some(entry) = self.entries[index].as_mut() else {
            self.fail(Failure::Protocol(Error::Stale), true);
            return;
        };
        if entry.value != value || !matches!(entry.state, State::Ready(_)) {
            self.fail(Failure::Protocol(Error::Stale), true);
            return;
        }
        entry.state = State::Admitted;
    }
    fn retire_history(&mut self, task: &ReplayTask) -> Result<(), Error> {
        if let Some(source) = &self.source
            && !source.same_process(task)
        {
            return Err(Error::Stale);
        }
        let Some(index) = self.index(task) else {
            let index = self
                .entries
                .iter()
                .position(Option::is_none)
                .ok_or(Error::WouldBlock)?;
            self.entries[index] = Some(Entry {
                task: task.clone(),
                value: task.stamp(),
                state: State::Retired,
            });
            return Ok(());
        };
        let entry = self.entries[index].as_mut().ok_or(Error::Stale)?;
        match &entry.state {
            State::Pending(token) => {
                self.ledger.cancel(token)?;
                entry.state = State::Retiring(token.clone());
            }
            State::Retiring(_) | State::Retired => {}
            State::Floor(_) | State::Ready(_) | State::Admitted => entry.state = State::Retired,
        }
        Ok(())
    }
    fn poll_history(&mut self, cx: &mut Context<'_>) -> Poll<Result<HistoryProgress, Error>> {
        if let Some(index) = self.entries.iter().position(|entry| {
            entry
                .as_ref()
                .is_some_and(|e| matches!(e.state, State::Retired))
        }) {
            let entry = self.entries[index].take().ok_or(Error::Stale)?;
            return Poll::Ready(Ok(HistoryProgress::Retired {
                task: entry.task,
                uncertain: self.uncertain,
            }));
        }
        if self.failed && !self.reported {
            self.reported = true;
            return Poll::Ready(Err(Error::OutcomeUnknown));
        }
        match self.ledger.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(replay::Progress::Persisted(floor)) => {
                let index=self.entries.iter().position(|e|e.as_ref().is_some_and(|e|matches!(&e.state,State::Pending(token)|State::Retiring(token)if *token==*floor.token()))).ok_or(Error::Stale)?;
                if matches!(
                    self.entries[index].as_ref().map(|e| &e.state),
                    Some(State::Retiring(_))
                ) || self.closing
                {
                    self.entries[index].as_mut().ok_or(Error::Stale)?.state = State::Retired;
                } else {
                    let entry = self.entries[index].as_mut().ok_or(Error::Stale)?;
                    if floor.peer() != entry.task.peer()
                        || floor.kind() != entry.task.kind()
                        || floor.stamp() != entry.value
                    {
                        return Poll::Ready(Err(self.fail(Failure::Protocol(Error::Stale), true)));
                    }
                    entry.state = State::Floor(floor);
                }
                Poll::Ready(Ok(HistoryProgress::Activity))
            }
            Poll::Ready(replay::Progress::Retired { token, .. }) => {
                let index=self.entries.iter().position(|e|e.as_ref().is_some_and(|e|matches!(&e.state,State::Pending(actual)|State::Retiring(actual)if *actual==token))).ok_or(Error::Stale)?;
                self.entries[index].as_mut().ok_or(Error::Stale)?.state = State::Retired;
                Poll::Ready(Ok(HistoryProgress::Activity))
            }
            Poll::Ready(replay::Progress::Failed { token, error }) => {
                if let Some(token)=token && let Some(index)=self.entries.iter().position(|e|e.as_ref().is_some_and(|e|matches!(&e.state,State::Pending(actual)|State::Retiring(actual)if *actual==token))){self.entries[index].as_mut().ok_or(Error::Stale)?.state=State::Retired;}
                let uncertain = error.uncertain;
                let reason = self.fail(Failure::Ledger(error), uncertain);
                self.reported = true;
                Poll::Ready(Err(reason))
            }
            Poll::Ready(replay::Progress::Drained) => {
                if self.closing {
                    for entry in self.entries.iter_mut().flatten() {
                        entry.state = State::Retired;
                    }
                    Poll::Ready(Ok(HistoryProgress::Activity))
                } else {
                    Poll::Ready(Err(self.fail(Failure::Protocol(Error::Closed), true)))
                }
            }
            Poll::Ready(replay::Progress::Initialized(_) | replay::Progress::Bound(_)) => {
                Poll::Ready(Err(self.fail(Failure::Protocol(Error::Stale), true)))
            }
        }
    }
}
