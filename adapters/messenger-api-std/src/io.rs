//! Actual native epoch/frame mapping, clock-independent hard retirement and
//! retained notification backpressure. There is no SEND ACK or invented RID.
use crate::{api::Control, clock::Span, types::*, *};
use domain::{Event, OperationPhase};
use gnunet_types::Error as Fault;
use std::{
    future::poll_fn,
    task::{Context, Poll},
};
use tokio::time::Instant;
pub(crate) fn original_write_head(
    rows: impl Iterator<Item = (usize, Option<u64>, bool)>,
) -> Option<usize> {
    rows.filter_map(|(index, order, pending)| {
        pending.then_some(order.map(|o| (index, o))).flatten()
    })
    .min_by_key(|(_, order)| *order)
    .map(|(index, _)| index)
}
impl<'a, E: crypto::Entropy, const N: usize> Api<'a, E, N> {
    fn live_job(&self, lease: &Lease<'a>) -> bool {
        self.core.operation_phase(lease.operation).is_ok_and(|p| {
            !matches!(
                p,
                OperationPhase::Complete | OperationPhase::Failed | OperationPhase::Cancelled
            )
        })
    }
    fn hard_target(&self) -> Option<Instant> {
        self.leases
            .iter()
            .filter(|l| self.live_job(l))
            .map(|l| l.span.hard)
            .chain(
                self.records
                    .as_ref()
                    .and_then(crate::records::Records::hard),
            )
            .chain(self.subscription_hard())
            .chain(self.control.as_ref().map(|c| c.span.hard))
            .chain((!self.ready).then_some(self.initial.hard))
            .chain(self.held_notification.as_ref().map(|n| n.span.hard))
            .chain(self.rooms.iter().filter_map(|r| {
                r.identity_operation.and_then(|op| {
                    self.leases
                        .iter()
                        .find(|l| l.operation == op)
                        .map(|l| l.span.hard)
                })
            }))
            .chain(
                self.rooms
                    .iter()
                    .filter_map(|r| r.join.as_ref().map(|j| j.span.hard)),
            )
            .chain(
                self.rooms
                    .iter()
                    .filter_map(|r| r.closing_span.map(|s| s.hard)),
            )
            .min()
    }
    fn expired(&self, logical: Option<u64>) -> Option<StopCause<'a>> {
        if let Some(operation) = self.expired_subscription(logical) {
            return Some(StopCause::Deadline(operation));
        }
        if self.records.as_ref().is_some_and(|r| r.expired(logical)) {
            return Some(StopCause::Initialization);
        }
        if !self.ready && self.initial.expired(logical) {
            return Some(StopCause::Initialization);
        }
        if self
            .control
            .as_ref()
            .is_some_and(|c| c.span.expired(logical))
            || self
                .held_notification
                .as_ref()
                .is_some_and(|n| n.span.expired(logical))
            || self.rooms.iter().any(|r| {
                r.join.as_ref().is_some_and(|j| j.span.expired(logical))
                    || r.closing_span.is_some_and(|s| s.expired(logical))
                    || r.identity_operation.is_some_and(|op| {
                        self.leases
                            .iter()
                            .find(|l| l.operation == op)
                            .is_some_and(|l| l.span.expired(logical))
                    })
            })
        {
            return Some(StopCause::Initialization);
        }
        self.leases
            .iter()
            .find(|l| self.live_job(l) && l.span.expired(logical))
            .map(|l| StopCause::Deadline(l.operation))
    }
    fn logical_target(&self) -> Result<Option<u64>, Error> {
        let mut target = self
            .leases
            .iter()
            .filter(|l| self.live_job(l))
            .map(|l| l.span.logical)
            .chain(
                self.records
                    .as_ref()
                    .and_then(crate::records::Records::logical),
            )
            .chain(self.subscription_effect_target())
            .chain(self.control.as_ref().map(|c| c.span.logical))
            .chain((!self.ready).then_some(self.initial.logical))
            .chain(self.held_notification.as_ref().map(|n| n.span.logical))
            .chain(self.rooms.iter().filter_map(|r| {
                r.identity_operation.and_then(|op| {
                    self.leases
                        .iter()
                        .find(|l| l.operation == op)
                        .map(|l| l.span.logical)
                })
            }))
            .chain(
                self.rooms
                    .iter()
                    .filter_map(|r| r.join.as_ref().map(|j| j.span.logical)),
            )
            .chain(
                self.rooms
                    .iter()
                    .filter_map(|r| r.closing_span.map(|s| s.logical)),
            )
            .min();
        if let Some(due) = self.subscription_target() {
            target = Some(target.map_or(due, |old| old.min(due)));
        }
        for r in &self.rooms {
            if !self.domain_blocked
                && r.source.is_some()
                && let Some(d) = self.core.next_deadline(r.room)?
            {
                target = Some(target.map_or(d, |old| old.min(d)));
            }
        }
        Ok(target)
    }
    fn progress_state(&mut self) -> Option<Progress<'a>> {
        let event = self.core.pop_event()?;
        self.wake_domain();
        if let Event::OperationChanged(operation, phase) = event
            && matches!(
                phase,
                OperationPhase::Complete | OperationPhase::Failed | OperationPhase::Cancelled
            )
            && self.leases.iter().any(|l| {
                l.operation == operation
                    && matches!(
                        l.intent,
                        Intent::Initialization
                            | Intent::Epoch
                            | Intent::Subscription
                            | Intent::Transcript
                            | Intent::Membership
                    )
            })
        {
            self.retire_next = Some(operation);
        }
        Some(Progress::State(event))
    }
    pub(crate) fn capture_error(&mut self, error: Error) {
        if self.pending_loss.is_some() {
            self.native.close();
            return;
        }
        let cause = match &error {
            Error::Native(_) => StopCause::Native,
            Error::Domain(e) => StopCause::Domain(*e),
            Error::Clock(e) => StopCause::Clock(*e),
            Error::Local(e) => StopCause::Local(*e),
        };
        let mut loss = self.stop(cause, false, None);
        loss.failure = Some(error);
        self.pending_loss = Some(loss);
    }
    fn handle_native(
        &mut self,
        event: native::Progress<'a>,
    ) -> Result<Option<Progress<'a>>, Error> {
        match event {
            native::Progress::Attached(epoch) => {
                if self.epoch.is_some() || self.ready {
                    return Err(Fault::StaleGeneration.into());
                }
                self.epoch = Some(epoch);
                let operation = self.native.submit_bounded(
                    wire::Request::Create,
                    self.initial.logical,
                    self.initial.hard,
                )?;
                self.control = Some(Control {
                    operation,
                    epoch,
                    span: self.initial,
                    kind: native::Kind::Create,
                    queued: false,
                    exposure: Exposure::Unsent,
                });
                Ok(Some(Progress::Attached(epoch)))
            }
            native::Progress::Queued {
                epoch,
                operation,
                kind,
            } => {
                if self.epoch != Some(epoch) {
                    return Err(Fault::StaleGeneration.into());
                }
                let binding =
                    if let Some(c) = self.control.as_mut().filter(|c| c.operation == operation) {
                        if c.epoch != epoch || c.kind != kind || c.queued {
                            return Err(Fault::Conflict.into());
                        }
                        c.queued = true;
                        None
                    } else {
                        let l = self
                            .leases
                            .iter_mut()
                            .find(|l| l.native == Some(operation))
                            .ok_or(Fault::StaleGeneration)?;
                        if l.epoch != epoch || l.kind != Some(kind) || l.queued {
                            return Err(Fault::Conflict.into());
                        }
                        l.queued = true;
                        Some(l.binding.ok_or(Fault::Conflict)?)
                    };
                Ok(Some(Progress::Queued {
                    epoch,
                    native: operation,
                    binding,
                    kind,
                }))
            }
            native::Progress::Activity {
                read_bytes,
                written_bytes,
            } => {
                if written_bytes > 0 {
                    if let Some(c) = self
                        .control
                        .as_mut()
                        .filter(|c| c.queued && !matches!(c.exposure, Exposure::Written { .. }))
                    {
                        let previous = match c.exposure {
                            Exposure::Partial { bytes, .. } => bytes,
                            _ => 0,
                        };
                        let total = 4;
                        let bytes = previous.checked_add(written_bytes).ok_or(Fault::Overflow)?;
                        if bytes >= total {
                            return Err(Fault::Conflict.into());
                        }
                        c.exposure = Exposure::Partial { bytes, total };
                    } else {
                        let index =
                            original_write_head(self.leases.iter().enumerate().map(|(i, l)| {
                                (
                                    i,
                                    l.native_serial,
                                    l.queued && !matches!(l.exposure, Exposure::Written { .. }),
                                )
                            }))
                            .ok_or(Fault::Conflict)?;
                        let l = &mut self.leases[index];
                        let total = match l.exposure {
                            Exposure::Partial { total, .. } => total,
                            Exposure::Unsent => l.frame_len,
                            _ => return Err(Fault::Conflict.into()),
                        };
                        let previous = match l.exposure {
                            Exposure::Partial { bytes, .. } => bytes,
                            _ => 0,
                        };
                        let bytes = previous.checked_add(written_bytes).ok_or(Fault::Overflow)?;
                        if bytes >= total {
                            return Err(Fault::Conflict.into());
                        }
                        let binding = l.binding.ok_or(Fault::Conflict)?;
                        l.exposure = Exposure::Partial { bytes, total };
                        self.core.write_progress(binding, written_bytes, false)?;
                    }
                }
                Ok(Some(Progress::Activity {
                    read_bytes,
                    written_bytes,
                }))
            }
            native::Progress::Written {
                epoch,
                operation,
                kind,
                bytes,
            } => {
                if self.epoch != Some(epoch) {
                    return Err(Fault::StaleGeneration.into());
                }
                if let Some(c) = self.control.as_mut().filter(|c| c.operation == operation) {
                    if c.epoch != epoch || c.kind != kind || bytes != 4 {
                        return Err(Fault::Conflict.into());
                    }
                    c.exposure = Exposure::Written { bytes };
                    let original_span = c.span;
                    let observed = self.sample()?;
                    if original_span.expired(Some(observed)) {
                        self.capture_stop(StopCause::Initialization, false, None);
                        return Ok(None);
                    }
                    if kind == native::Kind::Destroy {
                        self.closed = true;
                        self.capture_stop(StopCause::Closed, false, None);
                        return Ok(None);
                    }
                    self.control = None;
                    if kind == native::Kind::Create {
                        self.ready = true;
                        return Ok(Some(Progress::Ready(epoch)));
                    }
                    return Err(Fault::Conflict.into());
                }
                let index = self
                    .leases
                    .iter()
                    .position(|l| l.native == Some(operation))
                    .ok_or(Fault::StaleGeneration)?;
                let l = &mut self.leases[index];
                if l.epoch != epoch || l.kind != Some(kind) || !l.queued || bytes != l.frame_len {
                    return Err(Fault::Conflict.into());
                }
                let previous = match l.exposure {
                    Exposure::Partial { bytes, .. } => bytes,
                    Exposure::Unsent => 0,
                    _ => return Err(Fault::Replay.into()),
                };
                let delta = bytes.checked_sub(previous).ok_or(Fault::Conflict)?;
                let binding = l.binding.ok_or(Fault::Conflict)?;
                self.core.write_progress(binding, delta, true)?;
                l.exposure = Exposure::Written { bytes };
                let core_operation = l.operation;
                let original_span = l.span;
                let observed = self.sample()?;
                if original_span.expired(Some(observed)) {
                    self.capture_stop(StopCause::Deadline(core_operation), false, None);
                    return Ok(None);
                }
                self.start_close_after_write(core_operation)?;
                self.native_blocked = false;
                self.wake_domain();
                Ok(Some(Progress::Written {
                    epoch,
                    native: operation,
                    binding: Some(binding),
                    kind,
                    bytes,
                }))
            }
            native::Progress::Notification {
                epoch,
                notification,
            } => {
                if self.epoch != Some(epoch) || !self.ready || self.held_notification.is_some() {
                    return Err(Fault::StaleGeneration.into());
                }
                let now = self.sample()?;
                let span = Span::new(now, self.limits.native.input_lifetime)?;
                let job_span = Span::new(now, self.limits.operation_lifetime)?;
                self.native_blocked = false;
                self.wake_domain();
                let serial = self
                    .next_notification
                    .checked_add(1)
                    .ok_or(Fault::Overflow)?;
                self.next_notification = serial;
                self.held_notification = Some(HeldNotification {
                    serial,
                    layout: None,
                    need: None,
                    need_reported: false,
                    epoch,
                    notification,
                    span,
                    job_span,
                    applied: false,
                });
                Ok(None)
            }
            native::Progress::Lost(loss) => {
                self.capture_stop(StopCause::Native, false, Some(loss));
                Ok(None)
            }
        }
    }
    pub(crate) fn process_notification(&mut self, now: u64) -> Result<bool, Error> {
        let Some(mut held) = self.held_notification.take() else {
            return Ok(false);
        };
        if Some(held.epoch) != self.epoch {
            return Err(Fault::StaleGeneration.into());
        }
        let response = held.notification.view()?;
        let key = match response {
            wire::Response::MemberId { key, .. }
            | wire::Response::Missing { key, .. }
            | wire::Response::Receive { key, .. } => key,
            wire::Response::Open(r)
            | wire::Response::Entry(r)
            | wire::Response::Close(r)
            | wire::Response::Sync(r) => r.key,
        };
        let index = self
            .rooms
            .iter()
            .position(|r| r.key == *key && r.epoch == Some(held.epoch) && r.source.is_some())
            .ok_or(Fault::StaleGeneration)?;
        let source = self.rooms[index].source.ok_or(Fault::StaleGeneration)?;
        if !held.applied {
            let layout = match self.original_layout(index, source, response, held.layout)? {
                crate::layouts::Selection::Ready(layout) => layout,
                crate::layouts::Selection::Need {
                    requirement,
                    identifier,
                } => {
                    let wire::Response::Receive { hash, sender, .. } = response else {
                        return Err(Fault::Conflict.into());
                    };
                    held.need = Some(crate::LayoutNeed {
                        owner: self.owner,
                        epoch: held.epoch,
                        serial: held.serial,
                        room: self.rooms[index].room,
                        hash: *hash,
                        sender: *sender,
                        identifier,
                        requirement,
                    });
                    self.held_notification = Some(held);
                    return Ok(false);
                }
            };
            match self
                .core
                .on_notification_profiled(source, response, layout, now)
            {
                Ok(()) => {}
                Err(domain::Error::Protocol(Fault::WouldBlock | Fault::Capacity)) => {
                    self.held_notification = Some(held);
                    return Ok(false);
                }
                Err(e) => return Err(e.into()),
            }
            if let wire::Response::MemberId { id, reset, .. } = response {
                let room = &mut self.rooms[index];
                if room.join.is_none() {
                    room.join = Some(Join {
                        span: held.job_span,
                        recipient: None,
                        id: *id,
                    });
                } else if let Some(join) = room.join.as_mut()
                    && (reset == 1 || join.id != *id)
                {
                    join.id = *id;
                }
            }
            held.applied = true;
            self.reset_decryption();
            self.wake_domain();
        }
        match self.core.advance(self.rooms[index].room, now) {
            Ok(_) => {}
            Err(domain::Error::Protocol(Fault::WouldBlock | Fault::Capacity)) => {
                self.held_notification = Some(held);
                return Ok(false);
            }
            Err(e) => return Err(e.into()),
        }
        self.core.pause_subscription_renewals(source)?;
        self.observe_rooms()?;
        self.observe_memberships();
        self.observe_subscriptions(Some(now))
            .map_err(|(_, error)| Error::Domain(error))?;
        Ok(true)
    }
    /// Drive one bounded owner turn. Fixed original native deadlines and wake
    /// registration precede canonical clock coherence and all queued callbacks.
    /// Dropping a wait retains work; explicit cancellation physically stops MQ.
    pub fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress<'a>, Error>> {
        if let Some(loss) = self.pending_loss.take() {
            return Poll::Ready(Ok(Progress::Lost(loss)));
        }
        if !self.running {
            return Poll::Ready(Err(if self.closed {
                Fault::Closed
            } else {
                Fault::NotReady
            }
            .into()));
        }
        if let Some(operation) = self.retire_next.take()
            && let Err(error) = self.retire(operation)
        {
            self.capture_error(error);
        }
        if let Some(cause) = self.expired(None) {
            self.capture_stop(cause, false, None);
        }
        let target = self.hard_target();
        self.clock.poll_native(cx, target);
        if let Some(cause) = self.expired(None) {
            self.capture_stop(cause, false, None);
        }
        if let Some(loss) = self.pending_loss.take() {
            return Poll::Ready(Ok(Progress::Lost(loss)));
        }
        if let Some(at) = self.reconnect_not_before {
            if Instant::now() < at {
                self.clock
                    .poll_native(cx, Some(target.map_or(at, |hard| hard.min(at))));
                return Poll::Pending;
            }
            self.reconnect_not_before = None;
        }
        if self.record_turn {
            self.record_turn = false;
            match self.poll_records(cx) {
                Poll::Ready(Ok(event)) => return Poll::Ready(Ok(Progress::Records(event))),
                Poll::Ready(Err(error)) => self.capture_error(error),
                Poll::Pending => {}
            }
            if let Some(loss) = self.pending_loss.take() {
                return Poll::Ready(Ok(Progress::Lost(loss)));
            }
        }
        // Poll native even if domain observations are queued, so native first-
        // byte hard bounds cannot be starved by a slow application event drain.
        if self.held_notification.is_none() {
            match self.native.poll_progress(cx) {
                Poll::Ready(Ok(event)) => match self.handle_native(event) {
                    Ok(progress) => {
                        if let Some(cause) = self.expired(None) {
                            self.capture_stop(cause, false, None);
                        }
                        if let Some(loss) = self.pending_loss.take() {
                            return Poll::Ready(Ok(Progress::Lost(loss)));
                        }
                        if let Some(progress) = progress {
                            self.record_turn = true;
                            return Poll::Ready(Ok(progress));
                        }
                    }
                    Err(error) => self.capture_error(error),
                },
                Poll::Ready(Err(error)) => self.capture_error(error.into()),
                Poll::Pending => {}
            }
        }
        if let Some(loss) = self.pending_loss.take() {
            return Poll::Ready(Ok(Progress::Lost(loss)));
        }
        match self.poll_records(cx) {
            Poll::Ready(Ok(event)) => return Poll::Ready(Ok(Progress::Records(event))),
            Poll::Ready(Err(error)) => self.capture_error(error),
            Poll::Pending => {}
        }
        if let Some(loss) = self.pending_loss.take() {
            return Poll::Ready(Ok(Progress::Lost(loss)));
        }
        if let Some(event) = self.progress_state() {
            return Poll::Ready(Ok(event));
        }
        let now = match self.clock.poll_now(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => {
                self.capture_error(Error::Clock(e));
                return Poll::Ready(Ok(Progress::Lost(
                    self.pending_loss.take().ok_or(Fault::Conflict)?,
                )));
            }
            Poll::Ready(Ok(now)) => now,
        };
        if let Some(cause) = self.expired(Some(now)) {
            self.capture_stop(cause, false, None);
        }
        if let Some(loss) = self.pending_loss.take() {
            return Poll::Ready(Ok(Progress::Lost(loss)));
        }
        let result = (|| {
            let logical = self.logical_target()?;
            if self.clock.poll_logical(cx, logical).map_err(Error::Clock)? {
                self.wake_domain();
            }
            self.process_notification(now)?;
            if let Some(need) = self.layout_progress() {
                return Ok(Some(need));
            }
            let closed = self.finish_room_closures()?;
            if let Some(event) = closed {
                return Ok(Some(event));
            }
            if self.yield_due {
                self.yield_due = false;
                cx.waker().wake_by_ref();
                return Ok(None);
            }
            self.drive_domain(now)?;
            // Jobs/key transitions may introduce an earlier timer this turn.
            let logical = self.logical_target()?;
            self.clock.poll_logical(cx, logical).map_err(Error::Clock)?;
            if self.local_runnable()? {
                cx.waker().wake_by_ref();
            }
            if let Some(cause) = self.expired(Some(now)) {
                self.capture_stop(cause, false, None);
            }
            Ok(self.progress_state())
        })();
        match result {
            Ok(event) => {
                if let Some(loss) = self.pending_loss.take() {
                    return Poll::Ready(Ok(Progress::Lost(loss)));
                }
                if let Some(event) = event {
                    self.yield_due = true;
                    Poll::Ready(Ok(event))
                } else {
                    Poll::Pending
                }
            }
            Err(error) => {
                self.capture_error(error);
                Poll::Ready(Ok(Progress::Lost(
                    self.pending_loss.take().ok_or(Fault::Conflict)?,
                )))
            }
        }
    }
    /// Wait for one real original progress observation. This creates no actor;
    /// cancelled wait futures retain every partial cursor and original hard bound.
    pub async fn progress(&mut self) -> Result<Progress<'a>, Error> {
        poll_fn(|cx| self.poll_progress(cx)).await
    }
}
