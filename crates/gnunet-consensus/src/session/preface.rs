//! Initial union and size inventory, with original source and task retirement.
use super::*;

impl Session<'_> {
    fn total_tasks(&self) -> Result<usize, Error> {
        if self.kind.preface() {
            Ok(self.peers.len())
        } else {
            Err(Error::Conflict)
        }
    }
    pub(super) fn setup_step(&mut self) -> Result<bool, Error> {
        if self.now >= self.phase_deadline() {
            if let Some(source) = self.inputs.first().copied() {
                let at = self.set_at(source)?;
                if !self.sets[at].preparation_issued {
                    self.discard_unissued_set(at)?;
                    return self.finish_preface();
                }
            } else {
                return self.finish_preface();
            }
        }

        if self.total_tasks()? > self.limits.tasks {
            return Err(Error::Capacity);
        }
        if self.inputs.is_empty() {
            self.start_phase_set(self.kind, 0, true)?;
            return Ok(true);
        }
        for id in &self.inputs {
            let at = self.set_at(*id)?;
            if !self.sets[at].ready && self.sets[at].retired.is_none() {
                let set = *id;
                self.publish(Action::PrepareSet { set })?;
                return Ok(true);
            }
        }
        if self.setup_cursor < self.total_tasks()? {
            let set = *self.inputs.first().ok_or(Error::NotReady)?;
            self.plan_task(self.kind, None, self.setup_cursor, set)?;
            self.setup_cursor += 1;
            return Ok(true);
        }
        self.stage = Stage::Run;
        Ok(true)
    }
    pub(super) fn run_step(&mut self) -> Result<bool, Error> {
        if self.run_blocked {
            if self.now < self.phase_deadline() {
                return Ok(false);
            }
            self.run_blocked = false;
            self.run_cursor = 0;
        }

        if self.run_cursor < self.tasks.len() {
            let i = self.run_cursor;
            self.run_cursor += 1;
            let task = &self.tasks[i];
            if task.state == TaskState::Cancel {
                let task = task.id;
                self.publish(Action::CancelTask { task })?;
                return Ok(true);
            }
            if task.state == TaskState::Active && self.now >= self.phase_deadline() {
                self.task_failed(i, Error::Deadline, true)?;
                return Ok(true);
            }
            if task.state != TaskState::Planned {
                return Ok(true);
            }
            if self.blacklisted[task.peer] != 0 {
                self.task_failed(i, Error::Authentication, false)?;
                return Ok(true);
            }
            if self.now >= self.phase_deadline() {
                self.task_failed(i, Error::Deadline, false)?;
                return Ok(true);
            }
            let incoming = if task.key.peer2 as usize == self.local {
                self.offers
                    .iter()
                    .find(|o| {
                        o.available(self.now)
                            && o.peer == task.peer
                            && Self::key_eq(o.key, task.key)
                    })
                    .map(|o| o.id)
            } else {
                None
            };
            if task.key.peer2 as usize == self.local && incoming.is_none() {
                return Ok(true);
            }
            let action = Action::Reconcile {
                task: task.id,
                set: task.set,
                peer: self.peers[task.peer],
                context: task.key,
                incoming,
            };
            self.publish(action)?;
            self.tasks[i].state = TaskState::Starting;
            if let Some(offer) = incoming {
                let at = self.offer_at(offer)?;
                self.offers[at].claimed = true;
                self.tasks[i].remote_context_contested = self.offers[at].key.contested != 0;
            }
            return Ok(true);
        }
        if self.unfinished != 0 {
            self.run_blocked = true;
            return Ok(false);
        }
        if let Some(task) = self
            .tasks
            .iter()
            .position(|task| task.state == TaskState::Done && !task.staged.ids.is_empty())
        {
            return self.apply_staged(task);
        }
        // Every original task is semantically or physically terminal before its
        // original input source is retired. Close debts are actual, not counted away.
        if let Some(s) = self.sets.iter().find(|s| !s.closed && !s.close_requested) {
            let set = s.id;
            self.publish(Action::CloseSet { set })?;
            let at = self.set_at(set)?;
            self.sets[at].close_requested = true;
            return Ok(true);
        }
        if self.sets.iter().any(|s| !s.closed) {
            return Ok(false);
        }
        self.sets.clear();
        self.inputs.clear();
        // Every original preface source was physically retired above. Its
        // terminal native tasks no longer consume the next repetition's pool.
        self.tasks.clear();
        self.staged_bytes = 0;
        self.finish_preface()
    }
    fn finish_preface(&mut self) -> Result<bool, Error> {
        self.retire_round_offers(self.kind, -1);
        match self.kind {
            Round::Union => {
                self.first_size = self.current.ids.len() as u64;
                self.begin(Round::Inventory)?;
            }
            Round::Inventory => {
                self.kind = Round::Lead;
                self.rep = 0;
                self.work_leader = 0;
                self.stage = Stage::InitRep;
                self.work_cursor = 0;
            }
            _ => return Err(Error::Conflict),
        }
        Ok(true)
    }
}
