//! Native original RECLAIM cursors, actual replies and finite source deadlines.
use super::{Client, Mode, Origin};
use crate::{
    ControlKind, Epoch, Error, Kind, LocalReason, LossCause, Outcome, Progress, Reply, ipc,
};
use gnunet_client_host::channel::ConnectionStep;
use gnunet_service_runtime::{
    clock::Deadline,
    framing::{Class, OwnedFrame, ReadStep},
};
use gnunet_types::Error as Fault;
use std::{
    future::{Future, poll_fn},
    task::{Context, Poll},
};
use tokio::time::Instant;
impl<'id> Client<'id> {
    fn reply(&self) -> Result<Reply, Error> {
        let bytes = self
            .channel
            .framing()
            .and_then(|f| f.frame())
            .ok_or(Fault::NotReady)?;
        // One persistent reply copy; retained RX is released immediately by its
        // original dispatch. Never build a second parsed secret/payload cache.
        Ok(Reply {
            frame: OwnedFrame::copy_from(bytes)?,
        })
    }
    fn release(&mut self) -> Result<(), Fault> {
        self.channel
            .framing_mut()
            .ok_or(Fault::NotReady)?
            .release_frame();
        Ok(())
    }
    fn list_limit(&self, response: ipc::Response<'_>) -> Result<(), Fault> {
        let count = match response {
            ipc::Response::Ticket { presentations, .. } => presentations.len(),
            ipc::Response::Consumed {
                attributes,
                presentations,
                ..
            } => attributes.len().max(presentations.len()),
            _ => 0,
        };
        if count > self.limits.list_items {
            return Err(Fault::TooLarge);
        }
        Ok(())
    }
    fn dispatch(&mut self, epoch: Epoch<'id>) -> Result<Progress<'id>, Error> {
        let input = self
            .channel
            .framing()
            .and_then(|f| f.frame())
            .ok_or(Fault::NotReady)?;
        let response = ipc::Response::decode(input)?;
        self.list_limit(response)?;
        let rid = response.request_id();
        let row = self.slots.iter().position(|s| {
            s.as_ref()
                .is_some_and(|s| s.rid == rid && s.outcome.is_none())
        });
        let Some(row) = row else {
            self.release()?;
            return Ok(Progress::Ignored {
                epoch,
                request_id: rid,
            });
        };
        let state = self.slots[row].as_ref().ok_or(Fault::StaleGeneration)?;
        if !state.queued || !state.written || state.epoch != Some(epoch) {
            return Err(Fault::Malformed.into());
        }
        let operation = state.operation;
        if self.mode == Mode::Iterator {
            let item = match (state.kind, response) {
                (
                    Kind::Attributes,
                    ipc::Response::Attribute {
                        identity,
                        attribute,
                        ..
                    },
                ) => identity.is_some() && attribute.is_some(),
                (
                    Kind::Credentials,
                    ipc::Response::Credential {
                        identity,
                        credential,
                        ..
                    },
                ) => identity.is_some() && credential.is_some(),
                (
                    Kind::Tickets,
                    ipc::Response::Ticket {
                        ticket,
                        uri,
                        presentations,
                        ..
                    },
                ) => {
                    if ticket.is_none() && (uri.is_some() || !presentations.is_empty()) {
                        return Err(Fault::Malformed.into());
                    }
                    ticket.is_some()
                }
                _ => return Err(Fault::Malformed.into()),
            };
            if item {
                let stream = self.stream.as_ref().ok_or(Fault::Conflict)?;
                if stream.stopping {
                    self.release()?;
                    return Ok(Progress::Ignored {
                        epoch,
                        request_id: rid,
                    });
                }
                // Active C ticket collect_tickets_cb advances its NAMESTORE
                // iterator unconditionally, so legitimate ticket items can be
                // pushed without another NEXT. Do not invent strict wire credit
                // for that producer. All paths still retain at most one RX/item.
                if stream.credit == 0 && stream.kind != ipc::Iteration::Tickets {
                    return Err(Fault::Malformed.into());
                }
                let reply = self.reply()?;
                self.release()?;
                let stream = self.stream.as_mut().ok_or(Fault::Conflict)?;
                stream.credit = stream.credit.saturating_sub(1);
                return Ok(Progress::Item {
                    epoch,
                    operation,
                    reply,
                });
            }
        } else {
            match (state.kind, response) {
                (
                    Kind::StoreAttribute
                    | Kind::StoreCredential
                    | Kind::DeleteAttribute
                    | Kind::DeleteCredential,
                    ipc::Response::Success { .. },
                ) => {}
                (Kind::IssueTicket, ipc::Response::Ticket { .. }) => {}
                (Kind::RevokeTicket, ipc::Response::Revoked { .. }) => {}
                (Kind::ConsumeTicket, ipc::Response::Consumed { .. }) => {}
                _ => return Err(Fault::Malformed.into()),
            }
        }
        let reply = self.reply()?;
        self.release()?;
        self.slots[row]
            .as_mut()
            .ok_or(Fault::StaleGeneration)?
            .outcome = Some(Outcome::Reply(reply));
        Ok(Progress::Completed(self.complete().ok_or(Fault::Conflict)?))
    }
    fn prepare(&mut self, epoch: Epoch<'id>) -> Result<Option<Progress<'id>>, Error> {
        if let Some(event) = self.prepare_control(epoch)? {
            return Ok(Some(event));
        }
        let framed = self.channel.framing_mut().ok_or(Fault::NotReady)?;
        if framed.queued_frames() != 0 {
            return Ok(None);
        }
        let row = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(row, slot)| {
                slot.as_ref()
                    .filter(|s| !s.queued && s.reason.is_none() && s.outcome.is_none())
                    .map(|s| (row, s.operation.serial))
            })
            .min_by_key(|(_, serial)| *serial)
            .map(|(row, _)| row);
        let Some(row) = row else {
            return Ok(None);
        };
        let s = self.slots[row].as_mut().ok_or(Fault::StaleGeneration)?;
        match framed.reserve(s.len, Class::Ordinary) {
            Ok(()) => {}
            Err(Fault::WouldBlock) => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        let frame = s.source.take().ok_or(Fault::Conflict)?;
        let origin = Origin::Request {
            epoch,
            operation: s.operation,
            rid: s.rid,
        };
        if let Err(rejected) = framed.enqueue_owned(frame, origin, Class::Ordinary) {
            s.source = Some(rejected.value.0);
            return Err(rejected.reason.into());
        }
        s.queued = true;
        s.epoch = Some(epoch);
        Ok(Some(Progress::Queued {
            epoch,
            operation: s.operation,
            request_id: s.rid,
        }))
    }
    fn write(
        &mut self,
        cx: &mut Context<'_>,
        epoch: Epoch<'id>,
    ) -> Poll<Result<Progress<'id>, Error>> {
        let p = match self
            .channel
            .framing_mut()
            .ok_or(Fault::NotReady)?
            .poll_write(cx)
        {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Ok(self.lost(LossCause::Io(error)))),
            Poll::Ready(Ok(p)) => p,
        };
        self.read_first = true;
        match p.origin {
            Origin::Request {
                epoch: original,
                operation,
                rid,
            } => {
                if original != epoch {
                    return Poll::Ready(Err(Fault::StaleGeneration.into()));
                }
                let row = self.index(operation)?;
                let s = self.slots[row].as_mut().ok_or(Fault::StaleGeneration)?;
                if s.rid != rid
                    || s.epoch != Some(epoch)
                    || !s.queued
                    || s.written
                    || s.outcome.is_some()
                {
                    return Poll::Ready(Err(Fault::StaleGeneration.into()));
                }
                s.sent = s.sent.checked_add(p.bytes).ok_or(Fault::Overflow)?;
                if s.sent > s.len {
                    return Poll::Ready(Err(Fault::Conflict.into()));
                }
                if p.complete {
                    if s.sent != s.len {
                        return Poll::Ready(Err(Fault::Conflict.into()));
                    }
                    s.written = true;
                    self.bytes = self.bytes.checked_sub(s.len).ok_or(Fault::Conflict)?;
                    if let Some(reason) = s.reason {
                        Self::local(s, reason);
                    } else if s.kind.iteration().is_some() {
                        self.stream.as_mut().ok_or(Fault::Conflict)?.credit = 1;
                    }
                    return Poll::Ready(Ok(Progress::Written {
                        epoch,
                        operation,
                        request_id: rid,
                    }));
                }
            }
            Origin::Control {
                epoch: original,
                control,
            } => {
                if original != epoch {
                    return Poll::Ready(Err(Fault::StaleGeneration.into()));
                }
                let c = self.control.as_mut().ok_or(Fault::StaleGeneration)?;
                if c.id != control || c.epoch != Some(epoch) || !c.queued {
                    return Poll::Ready(Err(Fault::StaleGeneration.into()));
                }
                c.sent = c.sent.checked_add(p.bytes).ok_or(Fault::Overflow)?;
                if c.sent > c.len {
                    return Poll::Ready(Err(Fault::Conflict.into()));
                }
                if p.complete {
                    let c = self.control.take().ok_or(Fault::Conflict)?;
                    if c.sent != c.len {
                        return Poll::Ready(Err(Fault::Conflict.into()));
                    }
                    self.bytes = self.bytes.checked_sub(c.len).ok_or(Fault::Conflict)?;
                    match c.kind {
                        ControlKind::Next => {
                            let meta = self.stream.as_mut().ok_or(Fault::Conflict)?;
                            if meta.credit != 0 {
                                return Poll::Ready(Err(Fault::Conflict.into()));
                            }
                            meta.credit = 1;
                        }
                        ControlKind::Stop => {
                            let op = self.stream.as_ref().ok_or(Fault::Conflict)?.operation;
                            let row = self.index(op)?;
                            self.slots[row].as_mut().ok_or(Fault::Conflict)?.reason =
                                Some(LocalReason::Cancelled);
                            self.control_close = self.close();
                        }
                    }
                    return Poll::Ready(Ok(Progress::ControlWritten {
                        epoch,
                        control,
                        kind: c.kind,
                    }));
                }
            }
        }
        Poll::Ready(Ok(Progress::Activity {
            read_bytes: 0,
            written_bytes: p.bytes,
        }))
    }
    fn read(
        &mut self,
        cx: &mut Context<'_>,
        epoch: Epoch<'id>,
    ) -> Poll<Result<Progress<'id>, Error>> {
        match self
            .channel
            .framing_mut()
            .ok_or(Fault::NotReady)?
            .poll_read(cx)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Ok(self.lost(LossCause::Io(error)))),
            Poll::Ready(Ok(ReadStep::Eof)) => Poll::Ready(Ok(self.lost(LossCause::Eof))),
            Poll::Ready(Ok(ReadStep::Progress { bytes, complete })) => {
                self.read_first = false;
                if complete {
                    self.input_deadline = None;
                    Poll::Ready(self.dispatch(epoch))
                } else {
                    if bytes > 0 && self.input_deadline.is_none() {
                        self.input_deadline = Some(
                            Instant::now()
                                .checked_add(self.limits.input_lifetime)
                                .ok_or(Fault::Overflow)?,
                        );
                    }
                    Poll::Ready(Ok(Progress::Activity {
                        read_bytes: bytes,
                        written_bytes: 0,
                    }))
                }
            }
        }
    }
    fn expire(&mut self, now: Option<u64>) -> Result<Option<Progress<'id>>, Error> {
        let native = Instant::now();
        if self.input_deadline.is_some_and(|until| native >= until) {
            return Ok(Some(self.lost(LossCause::InputDeadline)));
        }
        if self
            .control
            .as_ref()
            .is_some_and(|c| now.is_some_and(|now| now >= c.expires) || native >= c.hard)
        {
            return Ok(Some(self.lost(LossCause::RetirementDeadline)));
        }
        if self.slots.iter().flatten().any(|state| {
            state.outcome.is_none() && state.retirement.is_some_and(|until| native >= until)
        }) {
            return Ok(Some(self.lost(LossCause::RetirementDeadline)));
        }
        for row in 0..self.slots.len() {
            if self.slots[row].as_ref().is_some_and(|state| {
                state.outcome.is_none()
                    && state.reason.is_none()
                    && (now.is_some_and(|now| now >= state.expires) || native >= state.hard)
            }) {
                self.retire_request(row, LocalReason::Deadline)?;
            }
        }
        // A late first observation can create an already-expired capped drain.
        // Stop before any further syscall on this same poll, not one poll later.
        if self.slots.iter().flatten().any(|state| {
            state.outcome.is_none() && state.retirement.is_some_and(|end| native >= end)
        }) {
            return Ok(Some(self.lost(LossCause::RetirementDeadline)));
        }
        Ok(self.complete().map(Progress::Completed))
    }
    /// Earliest original logical deadline. Never renewed by observation waits,
    /// retries or cancellation; native-time bounds independently prevent drift.
    #[must_use]
    pub fn next_deadline(&self) -> Option<u64> {
        self.slots
            .iter()
            .flatten()
            .filter(|state| state.outcome.is_none() && state.reason.is_none())
            .map(|state| state.expires)
            .chain(self.control.as_ref().map(|c| c.expires))
            .min()
    }
    fn poll_alarm(
        &mut self,
        cx: &mut Context<'_>,
        until: Option<Instant>,
    ) -> Poll<Result<(), Fault>> {
        if let Some(target) = self.next_deadline() {
            if self.alarm_at != Some(target) {
                self.alarm = Some(Box::pin(Deadline::at(
                    self.clock.clone(),
                    gnunet_types::AbsoluteTime::from_micros(target),
                )?));
                self.alarm_at = Some(target);
            }
            match self
                .alarm
                .as_mut()
                .ok_or(Fault::NotReady)?
                .as_mut()
                .poll(cx)
            {
                Poll::Pending => {}
                Poll::Ready(result) => {
                    self.alarm = None;
                    self.alarm_at = None;
                    result?;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }
        } else {
            self.alarm = None;
            self.alarm_at = None;
        }
        self.poll_native_alarm(cx, until)?;
        Poll::Pending
    }
    fn poll_native_alarm(
        &mut self,
        cx: &mut Context<'_>,
        until: Option<Instant>,
    ) -> Result<(), Fault> {
        let native = self
            .slots
            .iter()
            .flatten()
            .filter(|state| state.outcome.is_none())
            .map(|state| state.retirement.unwrap_or(state.hard))
            .chain(self.control.as_ref().map(|c| c.hard))
            .chain(self.input_deadline)
            .chain(until)
            .min();
        if let Some(target) = native {
            if self.native_at != Some(target) {
                self.native_alarm = Some(Box::pin(tokio::time::sleep_until(target)));
                self.native_at = Some(target);
            }
            if self
                .native_alarm
                .as_mut()
                .ok_or(Fault::NotReady)?
                .as_mut()
                .poll(cx)
                .is_ready()
            {
                cx.waker().wake_by_ref();
            }
        } else {
            self.native_alarm = None;
            self.native_at = None;
        }
        Ok(())
    }
    fn port_loss(&mut self, error: Error) -> Progress<'id> {
        self.blocked = true;
        self.lost(LossCause::Ports(error))
    }
    fn poll_step(
        &mut self,
        cx: &mut Context<'_>,
        until: Option<Instant>,
    ) -> Poll<Result<Progress<'id>, Error>> {
        if let Some((report, cause)) = self.admission_loss.take() {
            return Poll::Ready(Ok(Progress::Lost {
                report,
                cause: LossCause::Ports(cause.into()),
            }));
        }
        if let Some(done) = self.complete() {
            return Poll::Ready(Ok(Progress::Completed(done)));
        }
        if self.closed {
            return Poll::Ready(Ok(Progress::Closed));
        }
        // Native hard/input/control/suffix boundaries remain enforceable even
        // when a live canonical subscription returns Pending due to repeated
        // revision races. Register this timer before awaiting that source too.
        if let Some(event) = self.expire(None)? {
            return Poll::Ready(Ok(event));
        }
        self.poll_native_alarm(cx, until)?;
        if until.is_some_and(|target| Instant::now() >= target) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        if self.blocked || self.paused {
            if until.is_some_and(|target| Instant::now() >= target) {
                return Poll::Ready(Ok(Progress::WaitDeadline));
            }
            return self
                .channel
                .poll_wait(cx, until)
                .map_ok(|()| Progress::WaitDeadline);
        }
        match self.channel.poll_clock(cx) {
            Poll::Pending => {
                return self
                    .channel
                    .poll_wait(cx, until)
                    .map_ok(|()| Progress::WaitDeadline);
            }
            Poll::Ready(Err(error)) => return Poll::Ready(Ok(self.port_loss(error))),
            Poll::Ready(Ok(())) => {}
        }
        let now = match self.clock.sample() {
            Ok(sample) => sample.now.as_micros(),
            Err(error) => return Poll::Ready(Ok(self.port_loss(error.into()))),
        };
        if let Some(event) = self.expire(Some(now))? {
            return Poll::Ready(Ok(event));
        }
        if until.is_some_and(|target| Instant::now() >= target) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        if let Poll::Ready(Err(error)) = self.poll_alarm(cx, until) {
            return Poll::Ready(Ok(self.port_loss(error.into())));
        }
        if self.retry {
            self.channel.schedule_retry()?;
            self.retry = false;
        }
        if self.channel.framing().is_none() {
            return match self.channel.poll_connect(cx) {
                Poll::Pending => self
                    .channel
                    .poll_wait(cx, until)
                    .map_ok(|()| Progress::WaitDeadline),
                Poll::Ready(Err(error)) => Poll::Ready(Ok(self.port_loss(error))),
                Poll::Ready(Ok(ConnectionStep::Attached)) => {
                    let epoch = self.scope.epoch()?;
                    self.epoch = Some(epoch);
                    Poll::Ready(Ok(Progress::Connected(epoch)))
                }
                Poll::Ready(Ok(ConnectionStep::Retry { error, retry_after })) => {
                    Poll::Ready(Ok(Progress::ConnectRetry { error, retry_after }))
                }
                Poll::Ready(Ok(ConnectionStep::Unavailable(error))) => {
                    Poll::Ready(Ok(Progress::Unavailable(error)))
                }
            };
        }
        let epoch = self.epoch.ok_or(Fault::StaleGeneration)?;
        if self
            .channel
            .framing()
            .is_some_and(|framed| framed.frame().is_some())
        {
            return Poll::Ready(self.dispatch(epoch));
        }
        if let Some(event) = self.prepare(epoch)? {
            return Poll::Ready(Ok(event));
        }
        if self.read_first {
            if let Poll::Ready(event) = self.read(cx, epoch) {
                return Poll::Ready(event);
            }
            if let Poll::Ready(event) = self.write(cx, epoch) {
                return Poll::Ready(event);
            }
        } else {
            if let Poll::Ready(event) = self.write(cx, epoch) {
                return Poll::Ready(event);
            }
            if let Poll::Ready(event) = self.read(cx, epoch) {
                return Poll::Ready(event);
            }
        }
        self.channel
            .poll_wait(cx, until)
            .map_ok(|()| Progress::WaitDeadline)
    }
    /// Poll one bounded original native step. Canceling the containing future
    /// preserves original partial cursors. The optional wait is observation-only.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        until: Option<Instant>,
    ) -> Poll<Result<Progress<'id>, Error>> {
        if self.yield_due {
            self.yield_due = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let event = match self.poll_step(cx, until) {
            Poll::Ready(Err(error)) if !self.closed => {
                let cause = match error {
                    Error::Protocol(error)
                        if matches!(error, Fault::Capacity | Fault::Overflow | Fault::TooLarge) =>
                    {
                        LossCause::Resource(error)
                    }
                    Error::Protocol(error) => LossCause::Protocol(error),
                    other => {
                        self.blocked = true;
                        LossCause::Ports(other)
                    }
                };
                Poll::Ready(Ok(self.lost(cause)))
            }
            other => other,
        };
        if matches!(&event,Poll::Ready(Ok(progress))if !matches!(progress,Progress::Closed|Progress::WaitDeadline))
        {
            self.yield_due = true;
        }
        event
    }
    /// Caller-driven wrapper. No task/thread is started, and cancellation of the
    /// wait does not remove/replace an actual original MQ or request suffix.
    pub async fn drive(&mut self, until: Option<Instant>) -> Result<Progress<'id>, Error> {
        poll_fn(|cx| self.poll(cx, until)).await
    }
}
