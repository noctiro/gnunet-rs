//! Task failure, phase-source retirement and final session cleanup obligations.
use super::{Round, Session, Stage, TaskState};
use crate::{Action, Error, Failure, FailureTaskState, TaskFailureContext, state, wire::Block};

impl<'id> Session<'id> {
    pub(super) fn task_failed(
        &mut self,
        index: usize,
        cause: Error,
        cancel: bool,
    ) -> Result<(), Error> {
        self.tasks[index].staged.ids.clear();
        self.tasks[index].inventory = None;
        if self.tasks[index].failure.is_none() {
            if self.first_task_context.is_none() {
                let task = &self.tasks[index];
                let state = match task.state {
                    TaskState::Planned => FailureTaskState::Planned,
                    TaskState::Starting => FailureTaskState::Starting,
                    TaskState::Active => FailureTaskState::Active,
                    TaskState::Done => FailureTaskState::Done,
                    TaskState::Failed => FailureTaskState::Failed,
                    TaskState::Cancel => FailureTaskState::Cancel,
                };
                self.first_task_context = Some(TaskFailureContext {
                    cause,
                    stage: self.failure_stage(),
                    task_serial: task.id.serial,
                    set_serial: task.set.serial,
                    round: task.key,
                    peer_index: task.peer,
                    state,
                    observed_canonical: self.now,
                });
            }
            self.tasks[index].failure = Some(cause);
            self.failed_tasks = self.failed_tasks.checked_add(1).ok_or(Error::Overflow)?;
        }
        if !cancel && !matches!(self.tasks[index].state, TaskState::Done | TaskState::Failed) {
            self.unfinished = self.unfinished.checked_sub(1).ok_or(Error::Conflict)?;
        }
        self.run_blocked = false;
        self.run_cursor = self.run_cursor.min(index);
        self.tasks[index].state = if cancel {
            TaskState::Cancel
        } else {
            TaskState::Failed
        };
        self.wake_gradecast();
        Ok(())
    }
    pub(super) fn retire_round_offers(&mut self, kind: Round, leader: i16) {
        let repetition = if kind.preface() { -1 } else { self.rep as i16 };
        for offer in &mut self.offers {
            if !offer.claimed
                && offer.key.kind == kind.wire()
                && offer.key.repetition == repetition
                && offer.key.leader == leader
            {
                offer.retire = true;
            }
        }
    }
    pub(super) fn discard_unissued_set(&mut self, at: usize) -> Result<(), Error> {
        let source = self.sets.get(at).ok_or(Error::NotFound)?;
        if source.preparation_issued || self.tasks.iter().any(|task| task.set == source.id) {
            return Err(Error::Conflict);
        }
        let id = source.id;
        self.inputs.retain(|input| *input != id);
        self.sets.remove(at);
        Ok(())
    }
    pub(super) fn finish_step(&mut self) -> Result<bool, Error> {
        // Installed secretsharing starts a second session with the same public
        // hash immediately from525. Retire the old real listener/offer source
        // before publishing the public terminal, never merely clear a counter.
        if self.listener {
            self.publish(Action::CloseListener)?;
            return Ok(true);
        }

        if let Some(id) = self.current.ids.get(self.output_cursor).copied() {
            self.output_cursor += 1;
            if self.local_values.contains(id) {
                return Ok(true);
            }
            let block = Block::decode(&self.pool.elements[id as usize].raw)?;
            if block.marker != 0 {
                return Ok(true);
            }
            let element_type = block.payload_type;
            let mut free = self.available()?;
            let mut data = state::bytes(block.data.len(), &mut free)?;
            data.copy_from_slice(block.data);
            self.publish(Action::ClientElement { element_type, data })?;
            return Ok(true);
        }
        self.publish(Action::ClientDone)?;
        Ok(true)
    }
    pub(super) fn closing_step(&mut self) -> Result<bool, Error> {
        if let Some(at) = self.sets.iter().position(|set| !set.preparation_issued) {
            self.discard_unissued_set(at)?;
            return Ok(true);
        }
        if self.close_cursor < self.tasks.len() {
            let i = self.close_cursor;
            self.close_cursor += 1;
            if matches!(self.tasks[i].state, TaskState::Active | TaskState::Cancel) {
                let task = self.tasks[i].id;
                self.tasks[i].state = TaskState::Cancel;
                self.publish(Action::CancelTask { task })?;
            }
            return Ok(true);
        }
        if self.unfinished != 0 {
            self.close_cursor = 0;
            return Ok(false);
        }
        // The original listener physically owns all remaining unaccepted offers;
        // its actual retirement closes them as one retained source generation.
        if self.listener {
            self.publish(Action::CloseListener)?;
            return Ok(true);
        }
        if let Some(offer) = self.offers.iter().find(|o| !o.reject_requested) {
            let id = offer.id;
            self.publish(Action::RejectOffer { offer: id })?;
            let at = self.offer_at(id)?;
            self.offers[at].reject_requested = true;
            return Ok(true);
        }
        if let Some(set) = self.sets.iter().find(|s| !s.closed && !s.close_requested) {
            let id = set.id;
            self.publish(Action::CloseSet { set: id })?;
            let at = self.set_at(id)?;
            self.sets[at].close_requested = true;
            return Ok(true);
        }
        if self.listener {
            self.publish(Action::CloseListener)?;
            return Ok(true);
        }
        if self.cancelling && !self.client_close_requested {
            let cause = self.outcome.failure.map_or(Error::Cancelled, |f| f.cause);
            self.publish(Action::CloseClient { cause })?;
            self.client_close_requested = true;
            return Ok(true);
        }
        if self
            .tasks
            .iter()
            .all(|t| matches!(t.state, TaskState::Done | TaskState::Failed))
            && self.sets.iter().all(|s| s.closed)
            && self.offers.is_empty()
        {
            self.stage = Stage::Stopped;
            return Ok(true);
        }
        Ok(false)
    }
    /// Closing-only progress requiring no clock read, synthetic timestamp or
    /// entropy. Admitted original IO still waits for its real terminal receipt.
    pub fn retire_step(&mut self) -> Result<bool, Error> {
        if self.stage == Stage::Stopped {
            return Ok(false);
        }
        if self.stage != Stage::Closing {
            return Err(Error::NotReady);
        }
        if self.pending.is_some() {
            return Ok(false);
        }
        self.closing_step()
    }
    /// Cancel without clock or entropy. An admitted original action remains
    /// until its real native disposition; future work is never silently replayed.
    pub fn cancel(&mut self, cause: Error) -> Result<(), Error> {
        if self.stage == Stage::Stopped {
            return Err(Error::Closed);
        }
        // The ordinary C client destroys its MQ immediately after525. Once
        // that exact original write is known, source teardown is cleanup only.
        if self.outcome.client_done_written {
            if !matches!(cause, Error::Closed | Error::Cancelled) {
                self.outcome.cleanup_failure.get_or_insert(cause);
            }
            if self.stage != Stage::Closing {
                self.close_cursor = 0;
            }
            self.stage = Stage::Closing;
            return Ok(());
        }
        if self.outcome.failure.is_none() {
            self.failure_context = Some(self.snapshot_failure(cause));
        }
        self.outcome.failure.get_or_insert(Failure {
            cause,
            cancelled: cause == Error::Cancelled,
        });
        self.cancelling = true;
        if self.stage != Stage::Closing {
            self.close_cursor = 0;
        }
        self.stage = Stage::Closing;
        if self
            .pending
            .as_ref()
            .is_some_and(|e| !e.admitted && !e.action.cleanup())
        {
            let effect = self.pending.take().ok_or(Error::Conflict)?;
            match effect.action {
                Action::PrepareSet { set } => {
                    let at = self.set_at(set)?;
                    self.sets[at].closed = true;
                }
                Action::Reconcile { task, incoming, .. } => {
                    let at = self.task_at(task)?;
                    self.task_failed(at, cause, false)?;
                    if let Some(o) = incoming {
                        let i = self.offer_at(o)?;
                        self.offers[i].claimed = false;
                    }
                }
                Action::Listen { .. } => {}
                _ => {}
            }
        }
        for i in 0..self.tasks.len() {
            if self.tasks[i].state == TaskState::Planned {
                self.task_failed(i, cause, false)?;
            }
        }
        Ok(())
    }
}
