use super::*;
impl<'a, E: crypto::Entropy, const N: usize> Api<'a, E, N> {
    pub(crate) fn drive_frontiers(&mut self, now: u64) -> Result<(), Error> {
        for _ in 0..self.limits.work_per_poll.min(self.rooms.len()) {
            let index = self.frontier_cursor % self.rooms.len();
            self.frontier_cursor = (index + 1) % self.rooms.len();
            let Some(mut fence) = self.rooms[index].frontier else {
                continue;
            };
            if fence.blocked {
                continue;
            }
            let room = self.rooms[index].room;
            let (_, source, epoch) = self.live_source(room)?;
            if source != fence.source || epoch != fence.epoch {
                return Err(Fault::StaleGeneration.into());
            }
            if fence.span.expired(Some(now)) {
                return Err(Fault::Timeout.into());
            }
            if let Some(trigger) = fence.trigger
                && matches!(
                    self.core.operation_phase(trigger)?,
                    OperationPhase::Failed | OperationPhase::Cancelled
                )
            {
                return Err(Fault::Closed.into());
            }
            if fence.bootstrap
                && let Some(trigger) = fence.trigger
                && self.core.bootstrap_join_observed(source, trigger)?
            {
                fence.trigger_observed = true;
                self.rooms[index]
                    .frontier
                    .as_mut()
                    .ok_or(Fault::Conflict)?
                    .trigger_observed = true;
            }
            if let Some(sync) = fence.sync {
                if matches!(
                    self.core.operation_phase(sync)?,
                    OperationPhase::Failed | OperationPhase::Cancelled
                ) {
                    return Err(Fault::Closed.into());
                }
                if !fence.sync_observed {
                    continue;
                }
                if self.core.operation_phase(sync)? != OperationPhase::Complete {
                    return Err(Fault::Conflict.into());
                }
                if self.core.frontier_sync_required(room)? {
                    if fence.sync_view == Some(self.core.frontier_version(room)?)
                        || fence.trigger == Some(sync) && !fence.retire_trigger
                    {
                        self.rooms[index]
                            .frontier
                            .as_mut()
                            .ok_or(Fault::Conflict)?
                            .blocked = true;
                        continue;
                    }
                    // Only a new observed view permits a new read; keep the
                    // first logical/native budget rather than replaying work.
                    let next = self.rooms[index].frontier.as_mut().ok_or(Fault::Conflict)?;
                    next.sync = None;
                    next.sync_observed = false;
                    next.retire_sync = false;
                    if next.trigger == Some(sync) {
                        next.trigger = None;
                        next.trigger_observed = true;
                        next.retire_trigger = false;
                    }
                    self.retire(sync)?;
                    continue;
                }
                self.rooms[index].frontier = None;
                if fence.trigger != Some(sync) || fence.retire_trigger {
                    self.retire(sync)?;
                }
                if fence.retire_trigger && fence.trigger != Some(sync) {
                    self.retire(fence.trigger.ok_or(Fault::Conflict)?)?;
                }
                self.rooms[index].frontier_required = false;
                self.wake_domain();
            } else if fence.trigger_observed {
                if fence.bootstrap_required && !fence.bootstrap {
                    // A fresh service handle authorizes GET only after its
                    // actual signed JOIN. Retain the opening budget, while
                    // releasing an already-consumed internal OPEN receipt.
                    let pending = self.rooms[index].frontier.as_mut().ok_or(Fault::Conflict)?;
                    pending.trigger = None;
                    pending.retire_trigger = false;
                    if fence.retire_trigger {
                        self.retire(fence.trigger.ok_or(Fault::Conflict)?)?;
                    }
                    if !self.initialize_room(index, now)? {
                        self.rooms[index]
                            .frontier
                            .as_mut()
                            .ok_or(Fault::Conflict)?
                            .blocked = true;
                    }
                    continue;
                }
                if !self.protocol_available(Intent::Frontier) {
                    self.rooms[index]
                        .frontier
                        .as_mut()
                        .ok_or(Fault::Conflict)?
                        .blocked = true;
                    continue;
                }
                self.next_job.checked_add(1).ok_or(Fault::Overflow)?;
                let view = self.core.frontier_version(room)?;
                let sync = match self.core.synchronize(source, fence.span.logical) {
                    Ok(sync) => sync,
                    Err(domain::Error::Protocol(
                        Fault::NotReady | Fault::WouldBlock | Fault::Capacity,
                    )) => {
                        self.rooms[index]
                            .frontier
                            .as_mut()
                            .ok_or(Fault::Conflict)?
                            .blocked = true;
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                let pending = self.rooms[index].frontier.as_mut().ok_or(Fault::Conflict)?;
                pending.sync = Some(sync);
                pending.sync_view = Some(view);
                self.record_job(room, source, epoch, sync, fence.span, Intent::Frontier)?;
            }
        }
        Ok(())
    }
}
