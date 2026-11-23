//! Task-bound SET result intake; only a completed operation publishes staged membership.
use super::*;

impl<'id> Session<'id> {
    fn stage_member(&mut self, task: usize, element: u32) -> Result<(), Error> {
        let before = self.tasks[task].staged.charged()?;
        let mut free = self.available()?;
        self.tasks[task]
            .staged
            .add(element, self.limits, &mut free)?;
        let after = self.tasks[task].staged.charged()?;
        self.staged_bytes = self
            .staged_bytes
            .checked_add(after.checked_sub(before).ok_or(Error::Conflict)?)
            .ok_or(Error::Overflow)?;
        Ok(())
    }
    /// Apply one already-completed task's retained membership result per turn.
    /// Source retirement cannot revoke a previously observed matching DONE.
    pub(super) fn apply_staged(&mut self, task: usize) -> Result<bool, Error> {
        if self.tasks[task].state != TaskState::Done {
            return Ok(false);
        }
        let Some(&element) = self.tasks[task].staged.ids.last() else {
            return Ok(false);
        };
        let source = self.set_at(self.tasks[task].set)?;
        let mut free = self.available()?;
        match self.sets[source].kind {
            Round::Union | Round::Inventory => self.current.add(element, self.limits, &mut free)?,
            Round::Lead => {
                let leader = self.tasks[task].key.leader as usize;
                if self.sets[source].members.contains(element) {
                    self.leaders[leader].proposal.remove(element);
                } else {
                    self.leaders[leader]
                        .proposal
                        .add(element, self.limits, &mut free)?;
                }
            }
            _ => return Err(Error::Conflict),
        }
        let _applied = self.tasks[task].staged.ids.pop();
        Ok(true)
    }
    pub(super) fn remove_source_tasks(&mut self, source: SetId<'id>) -> Result<(), Error> {
        let released = self
            .tasks
            .iter()
            .filter(|task| task.set == source)
            .try_fold(0usize, |bytes, task| {
                if !task.staged.ids.is_empty() {
                    return Err(Error::Conflict);
                }
                bytes
                    .checked_add(task.staged.charged()?)
                    .ok_or(Error::Overflow)
            })?;
        self.staged_bytes = self
            .staged_bytes
            .checked_sub(released)
            .ok_or(Error::Conflict)?;
        self.tasks.retain(|task| task.set != source);
        Ok(())
    }
    fn record_result(&mut self, t: usize, change: Change, id: u32) -> Result<(), Error> {
        let task = &self.tasks[t];
        let leader = task.key.leader;
        let peer = task.peer;
        let base = self.set_at(task.set)?;
        let kind = self.sets[base].kind;
        if self.sets[base].members.contains(id) != (change == Change::Remove) {
            return Err(Error::Authentication);
        }
        match kind {
            Round::Union | Round::Inventory => {
                if change == Change::Add {
                    self.stage_member(t, id)?;
                }
            }
            Round::Lead => {
                let l = usize::try_from(leader).map_err(|_| Error::Malformed)?;
                if l != self.local {
                    self.stage_member(t, id)?;
                }
            }
            Round::Echo => {
                let l = leader as usize;
                let mut free = self.available()?;
                self.leaders[l]
                    .echo_ballot
                    .record(id, change, peer, self.limits, &mut free)?;
            }
            Round::Confirm => {
                let l = leader as usize;
                let mut free = self.available()?;
                self.leaders[l]
                    .confirm_ballot
                    .record(id, change, peer, self.limits, &mut free)?;
            }
        }
        Ok(())
    }
    /// Apply only one actual matching original SET operation result. A selected
    /// application policy may accept opaque data without calling it authenticated.
    pub fn set_result(
        &mut self,
        id: TaskId<'id>,
        peer: [u8; 32],
        event: SetEvent<'_>,
        now: u64,
        validator: &mut impl Validator,
    ) -> Result<(), Error> {
        self.now = self.now.max(now);
        let t = self.task_at(id)?;
        if self.now >= self.schedule.deadline() && !self.cancelling {
            self.cancel(Error::Deadline)?;
        }

        if self.peers[self.tasks[t].peer] != peer {
            return Err(Error::Authentication);
        }
        if !self.cancelling
            && self.tasks[t].state == TaskState::Active
            && self.now >= self.tasks[t].deadline
        {
            self.task_failed(t, Error::Deadline, true)?;
        }
        if self.cancelling || self.tasks[t].state == TaskState::Cancel {
            if matches!(event, SetEvent::Done { .. } | SetEvent::Failure(_))
                && matches!(self.tasks[t].state, TaskState::Active | TaskState::Cancel)
            {
                let cause = self.tasks[t]
                    .failure
                    .unwrap_or_else(|| self.outcome.failure.map_or(Error::Cancelled, |f| f.cause));
                self.task_failed(t, cause, false)?;
                return Ok(());
            }
            return Err(Error::Closed);
        }
        let result = self.apply_result(id, peer, event, now, validator);
        if let Err(cause) = result
            && self.tasks[t].state == TaskState::Active
            && !matches!(cause, Error::WouldBlock | Error::NotReady)
        {
            self.task_failed(t, cause, true)?;
        }
        result
    }
    fn apply_result(
        &mut self,
        id: TaskId<'id>,
        peer: [u8; 32],
        event: SetEvent<'_>,
        now: u64,
        validator: &mut impl Validator,
    ) -> Result<(), Error> {
        self.allowed()?;
        self.now = self.now.max(now);
        let t = self.task_at(id)?;
        if self.tasks[t].state != TaskState::Active || self.peers[self.tasks[t].peer] != peer {
            return Err(Error::StaleGeneration);
        }
        let kind = self.sets[self.set_at(self.tasks[t].set)?].kind;
        match event {
            SetEvent::Failure(cause) => self.task_failed(t, cause, false),
            SetEvent::Done { current_size } => {
                let key = self.tasks[t].key;
                let p = self.tasks[t].peer;
                if kind == Round::Union {
                    self.first_size = self.first_size.max(current_size);
                }
                if kind == Round::Echo {
                    self.leaders[key.leader as usize].echo_ballot.commit(p)?;
                }
                if kind == Round::Confirm {
                    let remote = self.tasks[t].remote_marker
                        || self.tasks[t].remote_context_contested
                        || (self.tasks[t].own_contested && !self.tasks[t].own_marker_missing);
                    if remote {
                        self.leaders[key.leader as usize]
                            .confirm_ballot
                            .contest(p)?;
                    }
                    self.leaders[key.leader as usize].confirm_ballot.commit(p)?;
                }
                self.run_blocked = false;
                self.tasks[t].state = TaskState::Done;
                self.unfinished = self.unfinished.checked_sub(1).ok_or(Error::Conflict)?;
                self.wake_gradecast();
                Ok(())
            }
            SetEvent::AddLocal { element_type, data }
            | SetEvent::AddRemote { element_type, data } => {
                if self.blacklisted[self.tasks[t].peer] != 0 {
                    return Ok(());
                }
                if element_type != 25 {
                    return Err(Error::Malformed);
                }
                let block = Block::decode(data)?;
                if block.marker != 0 {
                    if block.marker == 1 && kind == Round::Confirm {
                        if matches!(event, SetEvent::AddLocal { .. }) {
                            block.contested_marker()?;
                            self.tasks[t].remote_marker = true;
                        } else if self.tasks[t].own_contested && data == [0, 0, 1] {
                            self.tasks[t].own_marker_missing = true;
                        } else {
                            return Err(Error::Authentication);
                        }
                    }
                    if block.marker == 2
                        && kind == Round::Inventory
                        && matches!(event, SetEvent::AddLocal { .. })
                    {
                        let (size, sender) = block.size_marker()?;
                        let p = self.tasks[t].peer;
                        if usize::from(sender) == p {
                            if self.tasks[t]
                                .inventory
                                .is_some_and(|original| original != size)
                            {
                                return Err(Error::Authentication);
                            }
                            self.tasks[t].inventory = Some(size);
                        }
                    }
                    return Ok(());
                }
                if block.data.len() > self.limits.element_bytes {
                    return Err(Error::TooLarge);
                }
                if block.payload_type > wire::USER_TYPE_MAX {
                    return Err(Error::InvalidInput);
                }
                let _policy = validator.check(block.payload_type, block.data, self.now)?;
                let removing = matches!(event, SetEvent::AddRemote { .. });
                // A removal can only name bytes in the original local
                // snapshot. A local leader's proposal is already fixed by
                // that snapshot and never includes peer-only LEAD payloads.
                let original_only = removing
                    || (kind == Round::Lead && self.tasks[t].key.leader as usize == self.local);
                let element = if original_only {
                    match self.pool.find(data, self.abi)? {
                        Some(element) => element,
                        None if removing => return Err(Error::Authentication),
                        None => return Ok(()),
                    }
                } else {
                    let mut free = self.available()?;
                    self.pool.intern(data, self.abi, self.limits, &mut free)?
                };
                let change = if removing {
                    Change::Remove
                } else {
                    Change::Add
                };
                self.record_result(t, change, element)
            }
        }
    }
}
