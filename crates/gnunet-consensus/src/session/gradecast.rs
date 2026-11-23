//! Independent leader chains, real terminal votes and repetition decisions.
use super::*;

impl Session<'_> {
    pub(super) fn leader_setup(&mut self, l: usize, kind: Round) -> Result<bool, Error> {
        let expired = self.now >= self.window_deadline(kind, self.rep);
        let Some(source) = self.leaders[l].source else {
            if expired {
                return self.leader_advance(l, kind);
            }
            let source = self.start_phase_set(kind, l, false)?;
            self.leaders[l].source = Some(source);
            return Ok(true);
        };
        let at = self.set_at(source)?;
        if expired && !self.sets[at].preparation_issued {
            self.discard_unissued_set(at)?;
            return self.leader_advance(l, kind);
        }
        if !self.sets[at].ready && self.sets[at].retired.is_none() {
            self.publish(Action::PrepareSet { set: source })?;
            return Ok(true);
        }
        let total = if kind == Round::Lead && l != self.local {
            1
        } else {
            self.peers.len()
        };
        let cursor = self.leaders[l].cursor;
        if cursor < total {
            let other = if kind == Round::Lead && l != self.local {
                l
            } else {
                cursor
            };
            self.plan_task(kind, Some(l), other, source)?;
            self.leaders[l].cursor += 1;
            return Ok(true);
        }
        self.leaders[l].stage = LeaderStage::Run(kind);
        self.leaders[l].cursor = 0;
        Ok(true)
    }
    pub(super) fn leader_run(&mut self, l: usize, kind: Round) -> Result<bool, Error> {
        let source = self.leaders[l].source.ok_or(Error::Conflict)?;
        if self.tasks.iter().any(|task| {
            task.set == source && !matches!(task.state, TaskState::Done | TaskState::Failed)
        }) {
            return Ok(false);
        }
        if let Some(task) = self.tasks.iter().position(|task| {
            task.set == source && task.state == TaskState::Done && !task.staged.ids.is_empty()
        }) {
            return self.apply_staged(task);
        }
        let at = self.set_at(source)?;
        if !self.sets[at].close_requested {
            self.publish(Action::CloseSet { set: source })?;
            self.sets[at].close_requested = true;
            return Ok(true);
        }
        if !self.sets[at].closed {
            return Ok(false);
        }
        // CloseSet has physically retired this exact source and its original
        // native task rows. Stable retain preserves serial order for task_at;
        // fresh IDs never relabel callbacks or keep a whole past phase alive.
        self.remove_source_tasks(source)?;
        self.sets.retain(|set| set.id != source);
        self.leader_advance(l, kind)
    }
    fn leader_advance(&mut self, l: usize, kind: Round) -> Result<bool, Error> {
        self.retire_round_offers(kind, l as i16);
        self.leaders[l].source = None;
        self.leaders[l].cursor = 0;
        self.leaders[l].stage = match kind {
            Round::Lead => LeaderStage::Setup(Round::Echo),
            Round::Echo => LeaderStage::EchoGrade,
            Round::Confirm => LeaderStage::ConfirmGrade,
            _ => return Err(Error::Conflict),
        };
        Ok(true)
    }
    pub(super) fn gradecast_task(&mut self, i: usize) -> Result<bool, Error> {
        let task = &self.tasks[i];
        if task.state == TaskState::Cancel {
            let task = task.id;
            self.publish(Action::CancelTask { task })?;
            return Ok(true);
        }
        let expired = self.now >= task.deadline;
        if task.state == TaskState::Active && expired {
            self.task_failed(i, Error::Deadline, true)?;
            return Ok(true);
        }
        if task.state != TaskState::Planned {
            return Ok(false);
        }
        if self.blacklisted[task.peer] != 0 {
            self.task_failed(i, Error::Authentication, false)?;
            return Ok(true);
        }
        if expired {
            self.task_failed(i, Error::Deadline, false)?;
            return Ok(true);
        }
        let incoming = if task.key.peer2 as usize == self.local {
            self.offers
                .iter()
                .find(|o| {
                    o.available(self.now) && o.peer == task.peer && Self::key_eq(o.key, task.key)
                })
                .map(|o| o.id)
        } else {
            None
        };
        if task.key.peer2 as usize == self.local && incoming.is_none() {
            return Ok(false);
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
        Ok(true)
    }
    pub(super) fn gradecast_step(&mut self) -> Result<bool, Error> {
        if self
            .leaders
            .iter()
            .all(|leader| leader.stage == LeaderStage::Done)
        {
            if self.unfinished != 0 || !self.tasks.is_empty() || !self.sets.is_empty() {
                return Err(Error::Conflict);
            }
            // The previous phase-wide scheduler applied these exclusions only
            // after every confirmation was terminal. Keep that same boundary:
            // a fast leader cannot change another live leader's electorate.
            for (index, leader) in self.leaders.iter().enumerate() {
                if leader.confidence <= 1 {
                    self.blacklisted[index] = 1;
                }
            }
            self.stage = Stage::Apply;
            self.work_cursor = 0;
            self.apply_worst = usize::MAX;
            return Ok(true);
        }
        self.gradecast_task_turn = !self.gradecast_task_turn;
        if self.task_scan != 0 && (self.gradecast_task_turn || self.leader_scan == 0) {
            self.run_cursor %= self.tasks.len();
            let at = self.run_cursor;
            self.run_cursor += 1;
            self.task_scan -= 1;
            let changed = self.gradecast_task(at)?;
            if changed {
                self.leader_scan = self.leaders.len();
            }
            return Ok(changed || self.task_scan != 0 || self.leader_scan != 0);
        }
        if self.leader_scan != 0 {
            self.work_leader %= self.leaders.len();
            let l = self.work_leader;
            self.work_leader += 1;
            self.leader_scan -= 1;
            let changed = match self.leaders[l].stage {
                LeaderStage::Setup(kind) => self.leader_setup(l, kind)?,
                LeaderStage::Run(kind) => self.leader_run(l, kind)?,
                LeaderStage::EchoGrade => self.echo_grade_step(l)?,
                LeaderStage::ConfirmGrade => self.confirm_grade_step(l)?,
                LeaderStage::Done => false,
            };
            if changed {
                self.wake_gradecast();
            }
            return Ok(changed || self.task_scan != 0 || self.leader_scan != 0);
        }
        Ok(false)
    }
    pub(super) fn faults(&self) -> usize {
        self.peers.len().saturating_sub(1) / 3
    }
    pub(super) fn strong(&self) -> usize {
        self.peers.len() - self.faults()
    }
    pub(super) fn init_rep_step(&mut self) -> Result<bool, Error> {
        let n = self.peers.len();
        if n.checked_mul(n).ok_or(Error::Overflow)? > self.limits.tasks || n > self.limits.sets {
            return Err(Error::Capacity);
        }
        if self.leaders.len() < self.peers.len() {
            let mut free = self.available()?;
            let proposal = self.current.copy(&mut free)?;
            let echo = Members::new();
            let echo_ballot = Ballot::new(self.peers.len(), self.local, &mut free)?;
            let confirm_ballot = Ballot::new(self.peers.len(), self.local, &mut free)?;
            state::reserve(&mut self.leaders, 1, self.limits.peers, &mut free)?;
            self.leaders.push(Leader {
                proposal,
                echo,
                echo_ballot,
                confirm_ballot,
                contested: false,
                confidence: 0,
                confirm_worst: usize::MAX,
                stage: LeaderStage::Setup(Round::Lead),
                source: None,
                cursor: 0,
            });
            return Ok(true);
        }
        let mut free = self.available()?;
        let mut ballot = Ballot::new(self.peers.len(), self.local, &mut free)?;
        ballot.uncommit(self.local)?;
        self.round_ballot = Some(ballot);
        self.kind = Round::Lead;
        self.stage = Stage::Gradecast;
        self.work_leader = 0;
        self.run_cursor = 0;
        self.wake_gradecast();
        Ok(true)
    }
    pub(super) fn echo_grade_step(&mut self, l: usize) -> Result<bool, Error> {
        if self.leaders[l].cursor == 0 && self.leaders[l].echo.ids.is_empty() {
            let mut free = self.available()?;
            self.leaders[l].echo = self.leaders[l].proposal.copy(&mut free)?;
        }
        let count = self.leaders[l].echo_ballot.votes.len();
        if self.leaders[l].cursor < count {
            let vote = &self.leaders[l].echo_ballot.votes[self.leaders[l].cursor];
            let element = vote.element;
            let (change, majority) = self.leaders[l].echo_ballot.majority(vote);
            if majority < self.strong() {
                self.leaders[l].contested = true;
            }
            let mut free = self.available()?;
            match change {
                Change::Add => self.leaders[l].echo.add(element, self.limits, &mut free)?,
                Change::Remove => self.leaders[l].echo.remove(element),
                Change::Stay => {}
            }
            self.leaders[l].cursor += 1;
            return Ok(true);
        }
        if self.leaders[l].echo_ballot.count() < self.strong() {
            self.leaders[l].contested = true;
        }
        if self.leaders[l].contested {
            self.leaders[l].confirm_ballot.contest(self.local)?;
        }
        self.leaders[l].stage = LeaderStage::Setup(Round::Confirm);
        self.leaders[l].cursor = 0;
        Ok(true)
    }
    pub(super) fn confirm_grade_step(&mut self, l: usize) -> Result<bool, Error> {
        let votes = self.leaders[l].confirm_ballot.votes.len();
        if self.leaders[l].cursor < votes {
            let vote = &self.leaders[l].confirm_ballot.votes[self.leaders[l].cursor];
            let element = vote.element;
            let (change, majority) = self.leaders[l].confirm_ballot.confirmation_majority(vote);
            self.leaders[l].confirm_worst = self.leaders[l].confirm_worst.min(majority);
            let mut free = self.available()?;
            match change {
                Change::Add => self.leaders[l].echo.add(element, self.limits, &mut free)?,
                Change::Remove => self.leaders[l].echo.remove(element),
                Change::Stay => {}
            }
            self.leaders[l].cursor += 1;
            return Ok(true);
        }
        if self.leaders[l].cursor == votes {
            let ballot = &self.leaders[l].confirm_ballot;
            let noncontested = ballot.noncontested();
            let worst = if self.leaders[l].confirm_worst == usize::MAX {
                noncontested
            } else {
                self.leaders[l].confirm_worst
            };
            // A failed direct LEAD does not invalidate actual t+1 matching
            // CONFIRMs. Their original completed SET operations supply the
            // grade; requiring our LEAD to succeed would permit grades 0 and 2
            // at two correct receivers of the same Byzantine leader.
            let confidence = if noncontested >= self.strong() && worst >= self.strong() {
                2
            } else if noncontested > self.faults() && worst > self.faults() {
                1
            } else {
                0
            };
            self.leaders[l].confidence = confidence;
            if confidence > 0 {
                self.round_ballot
                    .as_mut()
                    .ok_or(Error::Conflict)?
                    .commit(l)?;
                self.leaders[l].cursor += 1;
            } else {
                self.leaders[l].stage = LeaderStage::Done;
                self.leaders[l].cursor = 0;
            }
            return Ok(true);
        }
        let index = self.leaders[l].cursor - votes - 1;
        if index < self.pool.elements.len() {
            if self.leaders[l].confidence > 0 {
                let id = u32::try_from(index).map_err(|_| Error::Overflow)?;
                let current = self.current.contains(id);
                let proposed = self.leaders[l].echo.contains(id);
                if current != proposed {
                    let mut free = self.available()?;
                    self.round_ballot.as_mut().ok_or(Error::Conflict)?.record(
                        id,
                        if proposed {
                            Change::Add
                        } else {
                            Change::Remove
                        },
                        l,
                        self.limits,
                        &mut free,
                    )?;
                }
            }
            self.leaders[l].cursor += 1;
            return Ok(true);
        }
        self.leaders[l].stage = LeaderStage::Done;
        self.leaders[l].cursor = 0;
        Ok(true)
    }
    pub(super) fn apply_step(&mut self) -> Result<bool, Error> {
        let ballot = self.round_ballot.as_ref().ok_or(Error::Conflict)?;
        if ballot.count() < self.strong() {
            return Err(Error::Unavailable);
        }
        if let Some(vote) = ballot.votes.get(self.work_cursor) {
            let id = vote.element;
            let (change, count) = ballot.union_majority(vote);
            self.apply_worst = self.apply_worst.min(count);
            let mut free = self.available()?;
            match change {
                Change::Add => self.current.add(id, self.limits, &mut free)?,
                Change::Remove => self.current.remove(id),
                Change::Stay => {}
            }
            self.work_cursor += 1;
            return Ok(true);
        }
        // The construction permits early stopping only after an n-f majority,
        // with the same original fault bound used by grade and round admission.
        let adequate = self.apply_worst >= self.strong();
        if adequate {
            self.early = self.early.saturating_add(1);
        } else if self.early != 0 {
            return Err(Error::Authentication);
        }
        self.round_ballot = None;
        self.leaders.clear();
        if self.early >= 2 || self.rep + 1 == self.schedule.repetitions() {
            self.stage = Stage::Finish;
            self.output_cursor = 0;
        } else {
            self.rep += 1;
            self.stage = Stage::InitRep;
            self.work_leader = 0;
            self.work_cursor = 0;
        }
        Ok(true)
    }
}
