//! Trusted native source retirement, distinct from a successful SET result.
use super::*;

impl<'id> Session<'id> {
    /// Copy current labels of the exact branded population, without sampling
    /// time, retaining its owner or granting authority to a diagnostic serial.
    pub fn set_context(&self, source: SetId<'id>) -> Result<SetContext, Error> {
        let row = &self.sets[self.set_at(source)?];
        Ok(SetContext {
            serial: row.id.serial,
            kind: row.kind,
            repetition: row.repetition,
            leader: row.leader,
            deadline: row.deadline,
            members: row.members.ids.len(),
            ready: row.ready,
            retired: row.retired,
        })
    }

    /// Report physical retirement (or proven never-admission) of one exact SET
    /// source, without
    /// replacing it or granting a DONE, membership vote or successful write.
    /// The trusted native host supplies the original pending effect's actual
    /// disposition if that effect belongs to this source. An unrelated pending
    /// effect must remain untouched. The outer listener/PILS/clock/session
    /// failure fences remain the host's separate whole-session responsibility.
    ///
    /// Every unfinished original task on this source fails, including planned
    /// tasks with no native OperationId. Later plans on the same source fail
    /// without new IO. Its immutable members cannot be read/populated/reused.
    /// CloseSet is still required to settle the original logical close debt;
    /// the host may then report Retired from this already proven physical loss.
    pub fn source_retired(
        &mut self,
        source: SetId<'id>,
        cause: Error,
        pending: Option<RetiredEffect<'id>>,
    ) -> Result<Option<Terminal<'id>>, Error> {
        let at = self.set_at(source)?;
        let matching = self.pending.as_ref().filter(|effect| match effect.action {
            Action::PrepareSet { set } | Action::Reconcile { set, .. } => set == source,
            Action::CancelTask { task } => self
                .task_at(task)
                .is_ok_and(|task| self.tasks[task].set == source),
            _ => false,
        });
        let pending = pending.map(|pending| match pending {
            RetiredEffect::Disposition { effect, completion } => (effect, completion, None),
            RetiredEffect::Uncommitted {
                effect,
                offer,
                cause,
            } => (effect, Completion::Unsent(cause), Some(offer)),
        });
        match (matching, pending) {
            (Some(effect), Some((id, completion, uncommitted))) if effect.id == id => {
                let allowed = if effect.action.cleanup() {
                    completion == Completion::Retired
                } else {
                    matches!(
                        completion,
                        Completion::Written | Completion::Unsent(_) | Completion::Lost(_)
                    )
                };
                if !allowed {
                    return Err(Error::InvalidInput);
                }
                if let Some(original) = uncommitted
                    && !matches!(effect.action, Action::Reconcile { incoming: Some(offer), .. } if offer == original)
                {
                    return Err(Error::StaleGeneration);
                }
            }
            (None, None) => {}
            (Some(_), None) => return Err(Error::NotReady),
            _ => return Err(Error::StaleGeneration),
        }
        let terminal = pending
            .map(|(id, completion, uncommitted)| {
                self.complete_effect_inner(id, completion, Some(source), uncommitted)
            })
            .transpose()?;
        self.sets[at].retired.get_or_insert(cause);
        self.sets[at].ready = false;
        let original = self.sets[at].retired.ok_or(Error::Conflict)?;
        let set = &self.sets[at];
        for offer in &mut self.offers {
            if !offer.claimed
                && offer.key.kind == set.kind
                && offer.key.repetition == set.repetition
                && offer.key.leader == set.leader
            {
                offer.retire = true;
            }
        }
        for task in 0..self.tasks.len() {
            if self.tasks[task].set == source
                && !matches!(self.tasks[task].state, TaskState::Done | TaskState::Failed)
            {
                self.task_failed(task, original, false)?;
            }
        }
        self.run_blocked = false;
        self.wake_gradecast();
        Ok(terminal)
    }
}

#[cfg(test)]
mod tests;
