//! Original effect admission and exact write or physical-retirement settlement.
use super::{Session, Stage, TaskState};
use crate::{Action, Completion, Effect, EffectId, Error, OfferId, SetId, Terminal};

impl<'id> Session<'id> {
    pub(super) fn publish(&mut self, action: Action<'id>) -> Result<(), Error> {
        if self.pending.is_some() {
            return Err(Error::WouldBlock);
        }
        let source = match &action {
            Action::PrepareSet { set } | Action::Reconcile { set, .. } => Some(*set),
            _ => None,
        };
        if let Some(source) = source {
            let source = &self.sets[self.set_at(source)?];
            if source.closed || source.retired.is_some() {
                return Err(Error::Closed);
            }
        }
        let deadline = match &action {
            Action::PrepareSet { set } => Some(self.sets[self.set_at(*set)?].deadline),
            Action::Reconcile { task, .. } => Some(self.tasks[self.task_at(*task)?].deadline),
            a if a.cleanup() => None,
            _ => Some(self.schedule.deadline()),
        };
        let serial = self.serial()?;
        let preparation = match action {
            Action::PrepareSet { set } => Some(self.set_at(set)?),
            _ => None,
        };
        self.pending = Some(Effect {
            id: EffectId {
                brand: self.brand,
                session: self.session,
                serial,
            },
            action,
            admitted: false,
            deadline,
        });
        if let Some(at) = preparation {
            self.sets[at].preparation_issued = true;
        }
        Ok(())
    }
    /// Borrow the single original immutable effect; None is not completion.
    #[must_use]
    pub fn effect(&self) -> Option<&Effect<'id>> {
        self.pending.as_ref()
    }
    /// Native admission of exactly this original effect, once.
    pub fn admit_effect(&mut self, id: EffectId<'id>) -> Result<(), Error> {
        let effect = self.pending.as_mut().ok_or(Error::NotFound)?;
        if effect.id != id {
            return Err(Error::StaleGeneration);
        }
        if effect.admitted {
            return Err(Error::Conflict);
        }
        effect.admitted = true;
        Ok(())
    }
    /// Metadata gate for the same original normal effect. This uses only the last
    /// observed canonical time; it does not replace a real native hard guard.
    #[must_use]
    pub fn effect_io_allowed(&self, id: EffectId<'id>) -> bool {
        !self.cancelling
            && self.pending.as_ref().is_some_and(|e| {
                e.id == id && !e.action.cleanup() && e.deadline.is_none_or(|end| self.now < end)
            })
    }
    /// Settle one original native effect. Cleanup receipts require actual
    /// physical retirement. Written is refused without changing the pending
    /// cleanup obligation. Unsent/Lost retain their physical-retirement precondition.
    ///
    /// # Errors
    /// Rejects a stale effect, missing admission or a disposition incompatible
    /// with the action before consuming its original pending obligation.
    pub fn complete_effect(
        &mut self,
        id: EffectId<'id>,
        completion: Completion,
    ) -> Result<Terminal<'id>, Error> {
        self.complete_effect_inner(id, completion, None, None)
    }
    pub(super) fn complete_effect_inner(
        &mut self,
        id: EffectId<'id>,
        completion: Completion,
        retired_source: Option<SetId<'id>>,
        uncommitted_offer: Option<OfferId<'id>>,
    ) -> Result<Terminal<'id>, Error> {
        let effect = self.pending.as_ref().ok_or(Error::NotFound)?;
        if effect.id != id {
            return Err(Error::StaleGeneration);
        }
        if !effect.admitted && !matches!(completion, Completion::Unsent(_)) {
            return Err(Error::Conflict);
        }
        if (completion == Completion::Retired && !effect.action.cleanup())
            || (completion == Completion::Written && effect.action.cleanup())
        {
            return Err(Error::InvalidInput);
        }
        let effect = self.pending.take().ok_or(Error::Conflict)?;
        let cause = match completion {
            Completion::Unsent(e) | Completion::Lost(e) => Some(e),
            _ => None,
        };
        if effect.action.cleanup() {
            if let Some(e) = cause {
                self.outcome.cleanup_failure.get_or_insert(e);
            }
            match effect.action {
                Action::RejectOffer { offer } => {
                    let o = self.offer_at(offer)?;
                    self.offers.swap_remove(o);
                }
                Action::CancelTask { task } => {
                    let t = self.task_at(task)?;
                    self.task_failed(t, self.tasks[t].failure.unwrap_or(Error::Cancelled), false)?;
                }
                Action::CloseSet { set } => {
                    let s = self.set_at(set)?;
                    self.sets[s].closed = true;
                }
                Action::CloseListener => {
                    self.listener = false;
                    self.offers.clear();
                }
                Action::CloseClient { .. } => {}
                _ => return Err(Error::Conflict),
            }
        } else if let Some(e) = cause {
            if self.outcome.failure.is_some() {
                self.outcome.cleanup_failure.get_or_insert(e);
            }
            match effect.action {
                Action::PrepareSet { set } => {
                    let s = self.set_at(set)?;
                    if retired_source != Some(set) {
                        self.sets[s].closed = true;
                    }
                }
                Action::Reconcile { task, incoming, .. } => {
                    let t = self.task_at(task)?;
                    self.task_failed(t, e, false)?;
                    if let Some(o) = incoming {
                        let at = self.offer_at(o)?;
                        if uncommitted_offer == Some(o) {
                            self.offers[at].claimed = false;
                            self.offers[at].retire = true;
                        } else {
                            self.offers.swap_remove(at);
                        }
                    }
                }
                Action::Listen { .. } => {}
                _ => {}
            }
            if retired_source.is_none() {
                self.cancel(e)?;
            }
        } else {
            match &effect.action {
                Action::Listen { .. } => self.listener = true,
                Action::PrepareSet { set } => {
                    let s = self.set_at(*set)?;
                    self.sets[s].ready = true;
                }
                Action::Reconcile { task, incoming, .. } => {
                    let t = self.task_at(*task)?;
                    if self.cancelling {
                        self.tasks[t].state = TaskState::Cancel;
                    } else {
                        self.tasks[t].state = TaskState::Active;
                    }
                    if let Some(o) = incoming {
                        let at = self.offer_at(*o)?;
                        self.offers.swap_remove(at);
                    }
                }
                Action::ClientElement { .. } => {}
                Action::ClientDone => {
                    self.outcome.client_done_written = true;
                    self.stage = Stage::Closing;
                    self.close_cursor = 0;
                }
                _ => return Err(Error::Conflict),
            }
        }
        self.run_blocked = false;
        self.wake_gradecast();
        Ok(Terminal { effect, completion })
    }
}
