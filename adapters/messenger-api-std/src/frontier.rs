//! Same-source frontier convergence and shared protocol admission capacity.
use crate::{clock::Span, types::*, *};
use domain::{OperationPhase, RoomPhase};
use gnunet_types::Error as Fault;
use std::time::Duration;
mod drive;

#[derive(Clone, Copy)]
pub(crate) struct Frontier<'a> {
    trigger: Option<Operation<'a>>,
    source: Source<'a>,
    epoch: native::Epoch<'a>,
    pub(crate) span: Span,
    sync: Option<Operation<'a>>,
    sync_view: Option<u64>,
    trigger_observed: bool,
    sync_observed: bool,
    retire_trigger: bool,
    retire_sync: bool,
    bootstrap_required: bool,
    bootstrap: bool,
    blocked: bool,
}
impl<'a> Frontier<'a> {
    fn new(
        source: Source<'a>,
        epoch: native::Epoch<'a>,
        span: Span,
        trigger: Option<Operation<'a>>,
    ) -> Self {
        Self {
            trigger,
            source,
            epoch,
            span,
            sync: None,
            sync_view: None,
            trigger_observed: trigger.is_none(),
            sync_observed: false,
            retire_trigger: false,
            retire_sync: false,
            bootstrap_required: false,
            bootstrap: false,
            blocked: false,
        }
    }
    fn contains(&self, operation: Operation<'a>) -> bool {
        self.trigger == Some(operation) || self.sync == Some(operation)
    }
}

/// Two shared lanes keep a proof's SYNC and dependency retrieval independent of
/// ordinary room jobs, including retained terminal application receipts.
#[derive(Clone, Copy)]
pub(crate) enum JobClass {
    Ordinary,
    Sync,
    Dependency,
}
impl JobClass {
    fn of(intent: &Intent) -> Self {
        match intent {
            Intent::Frontier | Intent::Synchronization => Self::Sync,
            Intent::Dependency
            | Intent::DependencyRequest
            | Intent::HistoryRequest { dependency: true } => Self::Dependency,
            _ => Self::Ordinary,
        }
    }
}
pub(crate) struct Capacity {
    limit: usize,
    ordinary: usize,
    sync: usize,
    dependency: usize,
    reserved: usize,
}
impl Capacity {
    pub(crate) fn ordinary_free(&self) -> usize {
        self.limit
            .saturating_sub(2)
            .saturating_sub(self.ordinary.saturating_add(self.reserved))
            .min(self.raw_free())
    }
    fn raw_free(&self) -> usize {
        self.limit.saturating_sub(
            self.ordinary
                .saturating_add(self.sync)
                .saturating_add(self.dependency)
                .saturating_add(self.reserved),
        )
    }
    fn available(&self, class: JobClass) -> bool {
        self.raw_free() > 0
            && match class {
                JobClass::Ordinary => self.ordinary_free() > 0,
                JobClass::Sync => self.sync == 0,
                JobClass::Dependency => self.dependency == 0,
            }
    }
}
impl<'a, E: crypto::Entropy, const N: usize> Api<'a, E, N> {
    pub(crate) fn capacity(&self) -> Capacity {
        let mut value = Capacity {
            limit: self.limits.operations,
            ordinary: 0,
            sync: 0,
            dependency: 0,
            reserved: self.reservations,
        };
        for lease in &self.leases {
            match JobClass::of(&lease.intent) {
                JobClass::Ordinary => value.ordinary += 1,
                JobClass::Sync => value.sync += 1,
                JobClass::Dependency => value.dependency += 1,
            }
        }
        value
    }
    pub(crate) fn protocol_available(&self, intent: Intent) -> bool {
        self.capacity().available(JobClass::of(&intent))
    }
    pub(crate) fn protocol_admission(
        &mut self,
        timeout: Duration,
        intent: Intent,
    ) -> Result<(u64, Span), Error> {
        let deadline = self.deadline(timeout)?;
        self.protocol_admission_bounded(deadline, intent)
    }
    pub(crate) fn protocol_admission_bounded(
        &mut self,
        deadline: Deadline,
        intent: Intent,
    ) -> Result<(u64, Span), Error> {
        if deadline.owner != self.owner {
            return Err(Fault::StaleGeneration.into());
        }
        if deadline.expired(None) {
            return Err(Fault::Timeout.into());
        }
        if !self.ready() || self.pending_loss.is_some() {
            return Err(Fault::NotReady.into());
        }
        if !self.protocol_available(intent) {
            return Err(Fault::WouldBlock.into());
        }
        self.next_job.checked_add(1).ok_or(Fault::Overflow)?;
        let now = self.sample()?;
        if deadline.expired(Some(now)) {
            return Err(Fault::Timeout.into());
        }
        Ok((now, deadline.span))
    }
    pub(crate) fn frontier_capacity(&self) -> Result<(), Error> {
        if self.free_jobs() == 0 {
            return Err(Fault::WouldBlock.into());
        }
        self.next_job.checked_add(2).ok_or(Fault::Overflow)?;
        Ok(())
    }
    pub(crate) fn frontier_clear(&self, room: Room<'a>) -> Result<(), Error> {
        let row = &self.rooms[self.room_index(room)?];
        if row.frontier.is_some()
            || row.frontier_required
            || self.core.frontier_sync_required(room)?
        {
            return Err(Fault::WouldBlock.into());
        }
        Ok(())
    }
    pub(crate) fn bind_frontier(
        &mut self,
        room: Room<'a>,
        source: Source<'a>,
        epoch: native::Epoch<'a>,
        operation: Operation<'a>,
        span: Span,
        intent: &Intent,
    ) -> Result<(), Error> {
        let index = self.room_index(room)?;
        if matches!(intent, Intent::Initialization)
            && let Some(fence) = &mut self.rooms[index].frontier
            && fence.trigger.is_none()
            && fence.sync.is_none()
        {
            fence.trigger = Some(operation);
            fence.trigger_observed = false;
            fence.bootstrap = true;
            return Ok(());
        }
        if matches!(intent, Intent::Synchronization) {
            if self.rooms[index].frontier.is_some() {
                return Err(Fault::Conflict.into());
            }
            let mut frontier = Frontier::new(source, epoch, span, Some(operation));
            frontier.sync = Some(operation);
            frontier.sync_view = Some(self.core.frontier_version(room)?);
            self.rooms[index].frontier = Some(frontier);
            return Ok(());
        }
        let historical = self.core.frontier_control(room)? == Some(operation);
        let replacement = self.rooms[index].frontier_required
            && self.rooms[index].frontier.is_none()
            && matches!(
                self.core.phase(room)?,
                RoomPhase::Opening | RoomPhase::Entering
            );
        if historical || replacement {
            self.frontier_capacity()?;
            if self.rooms[index].frontier.is_some() {
                return Err(Fault::Conflict.into());
            }
            let mut fence = Frontier::new(source, epoch, span, Some(operation));
            fence.bootstrap_required = replacement;
            self.rooms[index].frontier = Some(fence);
        }
        Ok(())
    }
    pub(crate) fn frontier_holds(&self, operation: Operation<'a>) -> bool {
        self.rooms
            .iter()
            .any(|r| r.frontier.is_some_and(|f| f.contains(operation)))
    }
    pub(crate) fn frontier_bootstrap_allowed(&self, index: usize) -> bool {
        self.rooms[index].frontier.is_some_and(|fence| {
            fence.bootstrap_required
                && fence.trigger.is_none()
                && fence.trigger_observed
                && fence.sync.is_none()
        })
    }
    pub(crate) fn frontier_get_ready(&self, index: usize) -> Result<bool, Error> {
        let Some(fence) = self.rooms[index].frontier else {
            let room = &self.rooms[index];
            if let Some(source) = room.source
                && self.core.source_joined(source)?
            {
                return Ok(true);
            }
            for original in self.leases.iter().filter(|l| {
                Some(l.source) == room.source && matches!(l.intent, Intent::Initialization)
            }) {
                if self
                    .core
                    .bootstrap_join_observed(original.source, original.operation)?
                {
                    return Ok(true);
                }
            }
            return Ok(false);
        };
        if !fence.bootstrap_required {
            return Ok(self.core.source_joined(fence.source)?);
        }
        match fence.trigger {
            Some(operation) if fence.bootstrap => {
                Ok(self.core.bootstrap_join_observed(fence.source, operation)?)
            }
            _ => Ok(false),
        }
    }
    /// Consume a public terminal receipt while retaining its distinct original
    /// convergence debt. No terminal event is delayed or changed into an ACK.
    pub(crate) fn defer_frontier_retirement(
        &mut self,
        operation: Operation<'a>,
    ) -> Result<bool, Error> {
        let phase = self.core.operation_phase(operation)?;
        for room in &mut self.rooms {
            let Some(fence) = &mut room.frontier else {
                continue;
            };
            if !fence.contains(operation) {
                continue;
            }
            if !matches!(
                phase,
                OperationPhase::Complete | OperationPhase::Failed | OperationPhase::Cancelled
            ) {
                return Err(Fault::NotReady.into());
            }
            let retired = if fence.trigger == Some(operation) {
                &mut fence.retire_trigger
            } else {
                &mut fence.retire_sync
            };
            if *retired {
                return Err(Fault::Replay.into());
            }
            *retired = true;
            return Ok(true);
        }
        Ok(false)
    }
    pub(crate) fn observe_frontier(&mut self, operation: Operation<'a>, phase: OperationPhase) {
        let internal = self.leases.iter().any(|l| {
            l.operation == operation
                && !matches!(
                    l.intent,
                    Intent::User | Intent::Synchronization | Intent::DependencyRequest
                )
        });
        for room in &mut self.rooms {
            let Some(fence) = &mut room.frontier else {
                continue;
            };
            if fence.trigger == Some(operation) {
                fence.trigger_observed = phase == OperationPhase::Complete;
                if internal
                    && matches!(
                        phase,
                        OperationPhase::Complete
                            | OperationPhase::Failed
                            | OperationPhase::Cancelled
                    )
                {
                    fence.retire_trigger = true;
                }
            }
            if fence.sync == Some(operation) {
                fence.sync_observed = phase == OperationPhase::Complete;
            }
        }
    }
    pub(crate) fn wake_frontiers(&mut self) {
        for room in &mut self.rooms {
            if let Some(fence) = &mut room.frontier {
                fence.blocked = false;
            }
        }
    }
    pub(crate) fn frontier_runnable(&self) -> Result<bool, Error> {
        for room in &self.rooms {
            let Some(fence) = room.frontier else { continue };
            if !fence.blocked
                && (fence.trigger_observed
                    && fence.sync.is_none()
                    && self.protocol_available(Intent::Frontier)
                    || fence.sync_observed
                        && (!self.core.frontier_sync_required(room.room)?
                            || fence.sync_view != Some(self.core.frontier_version(room.room)?)))
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
    pub(crate) fn expired_frontier(&self, now: Option<u64>) -> Option<StopCause<'a>> {
        self.rooms
            .iter()
            .filter_map(|r| r.frontier)
            .find(|f| f.span.expired(now))
            .map(|f| {
                f.trigger
                    .or(f.sync)
                    .map_or(StopCause::Initialization, StopCause::Deadline)
            })
    }
    pub(crate) fn observe_frontier_need(&mut self, index: usize, now: u64) -> Result<(), Error> {
        let row = &self.rooms[index];
        if row.frontier.is_some()
            || row.frontier_required
            || row.close_after.is_some()
            || row.source.is_none()
            || !self.core.frontier_sync_required(row.room)?
        {
            return Ok(());
        }
        if self.core.frontier_control(row.room)?.is_some()
            || self.core.frontier_sync_in_flight(row.room)?
        {
            return Err(Fault::Conflict.into());
        }
        let room = row.room;
        let (_, source, epoch) = self.live_source(room)?;
        let span = Span::new(now, self.limits.operation_lifetime)?;
        let mut fence = Frontier::new(source, epoch, span, None);
        fence.bootstrap_required = !self.core.source_joined(source)?;
        self.rooms[index].frontier = Some(fence);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
