//! Actual original NAMESTORE source cursors and opaque checked responses.
use super::{Client, Mode, Origin};
use crate::{
    ControlKind, Epoch, Error, Kind, LocalReason, LossCause, Outcome, Progress, Reply, SecretKey,
    ipc,
};
use gnunet_client_host::channel::ConnectionStep;
use gnunet_service_runtime::{
    clock::Deadline,
    framing::{Class, OwnedFrame, ReadStep},
};
use gnunet_types::Error as Fault;
use gnunet_wire::official::identity::SecretKeyView;
use std::{
    future::{Future, poll_fn},
    task::{Context, Poll},
};
use tokio::time::Instant;
impl<'id> Client<'id> {
    fn zone(expected: Option<&SecretKey>, actual: SecretKeyView<'_>) -> Result<(), Fault> {
        if let Some(expected) = expected {
            let returned = SecretKey::from_serialized(actual.expose_serialized())?;
            if !expected.constant_time_eq(&returned) {
                return Err(Fault::Authentication);
            }
        }
        Ok(())
    }
    fn records(&self, label: ipc::CString<'_>, records: ipc::Records<'_>) -> Result<(), Fault> {
        if label.wire_bytes().len() > self.limits.label_bytes
            || usize::from(records.count()) > self.limits.records
        {
            return Err(Fault::TooLarge);
        }
        Ok(())
    }
    fn reply(&self) -> Result<Reply, Error> {
        let bytes = self
            .channel
            .framing()
            .and_then(|f| f.frame())
            .ok_or(Fault::NotReady)?;
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
    fn dispatch(&mut self, epoch: Epoch<'id>) -> Result<Progress<'id>, Error> {
        let input = self
            .channel
            .framing()
            .and_then(|f| f.frame())
            .ok_or(Fault::NotReady)?;
        let response = ipc::Response::decode(input)?;
        let row = if self.mode == Mode::Monitor {
            let op = self.stream.as_ref().ok_or(Fault::Conflict)?.operation;
            Some(self.index(op)?)
        } else {
            let rid = response.request_id().ok_or(Fault::Malformed)?;
            self.slots.iter().position(|slot| {
                slot.as_ref()
                    .is_some_and(|s| s.rid == rid && s.outcome.is_none())
            })
        };
        let Some(row) = row else {
            let request_id = response.request_id().ok_or(Fault::Malformed)?;
            self.release()?;
            return Ok(Progress::Ignored { epoch, request_id });
        };
        let state = self.slots[row].as_ref().ok_or(Fault::StaleGeneration)?;
        if !state.queued || !state.written || state.epoch != Some(epoch) || state.outcome.is_some()
        {
            return Err(Fault::Malformed.into());
        }
        let operation = state.operation;
        let expected = state.zone.as_ref();
        if self.mode != Mode::General {
            match response {
                ipc::Response::Records {
                    rid,
                    zone,
                    label,
                    records,
                    ..
                } => {
                    if rid != state.rid {
                        return Err(Fault::Malformed.into());
                    }
                    Self::zone(expected, zone)?;
                    self.records(label, records)?;
                    let stream = self.stream.as_ref().ok_or(Fault::Conflict)?;
                    if stream.stopping {
                        self.release()?;
                        return Ok(Progress::Ignored {
                            epoch,
                            request_id: rid,
                        });
                    }
                    if stream.credit == 0 {
                        return Err(Fault::Malformed.into());
                    }
                    let reply = self.reply()?;
                    self.release()?;
                    self.stream.as_mut().ok_or(Fault::Conflict)?.credit -= 1;
                    return Ok(Progress::Record {
                        epoch,
                        operation,
                        reply,
                    });
                }
                ipc::Response::MonitorSync if self.mode == Mode::Monitor => {
                    if self.stream.as_ref().ok_or(Fault::Conflict)?.synced {
                        return Err(Fault::Malformed.into());
                    }
                    self.release()?;
                    self.stream.as_mut().ok_or(Fault::Conflict)?.synced = true;
                    return Ok(Progress::Synchronized { epoch, operation });
                }
                ipc::Response::End { rid } if self.mode == Mode::Iterator && rid == state.rid => {}
                _ => return Err(Fault::Malformed.into()),
            }
        } else {
            match response {
                ipc::Response::Generic { .. }
                    if matches!(state.kind, Kind::Store | Kind::EditCancel) => {}
                ipc::Response::Lookup {
                    zone,
                    label,
                    records,
                    found,
                    reserved,
                    ..
                } if state.kind == Kind::Lookup => {
                    if reserved != 0 || (found == 0 && records.count() != 0) {
                        return Err(Fault::Malformed.into());
                    }
                    Self::zone(expected, zone)?;
                    self.records(label, records)?;
                }
                ipc::Response::Records {
                    zone,
                    label,
                    records,
                    ..
                } if state.kind == Kind::Lookup => {
                    Self::zone(expected, zone)?;
                    self.records(label, records)?;
                }
                ipc::Response::ZoneToName {
                    zone,
                    label,
                    records,
                    code,
                    ..
                } if state.kind == Kind::ZoneToName => {
                    if let Some(zone) = zone {
                        Self::zone(expected, zone)?;
                    } else if code == 0 {
                        return Err(Fault::Malformed.into());
                    }
                    if let Some(label) = label {
                        self.records(label, records)?;
                    } else if code == 0 || records.count() != 0 {
                        return Err(Fault::Malformed.into());
                    }
                }
                ipc::Response::Edit { hint, records, .. } if state.kind == Kind::EditBegin => {
                    if hint.is_some_and(|h| h.wire_bytes().len() > self.limits.hint_bytes)
                        || usize::from(records.count()) > self.limits.records
                    {
                        return Err(Fault::TooLarge.into());
                    }
                }
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
            request_id: if s.kind == Kind::Monitor {
                None
            } else {
                Some(s.rid)
            },
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
                    } else if matches!(s.kind, Kind::Iterator | Kind::Monitor) {
                        self.stream.as_mut().ok_or(Fault::Conflict)?.credit = 1;
                    }
                    return Poll::Ready(Ok(Progress::Written {
                        epoch,
                        operation,
                        request_id: if s.kind == Kind::Monitor {
                            None
                        } else {
                            Some(rid)
                        },
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
                        ControlKind::Next { limit } => {
                            let meta = self.stream.as_mut().ok_or(Fault::Conflict)?;
                            meta.credit = meta.credit.checked_add(limit).ok_or(Fault::Overflow)?;
                            if meta.credit > self.limits.credit {
                                return Poll::Ready(Err(Fault::Conflict.into()));
                            }
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
                    Poll::Ready(self.dispatch(epoch))
                } else {
                    Poll::Ready(Ok(Progress::Activity {
                        read_bytes: bytes,
                        written_bytes: 0,
                    }))
                }
            }
        }
    }
    // None checks only original native bounds. Canonical source time is used
    // only after the actual shared clock is ready and sampled successfully.
    fn expire(&mut self, now: Option<u64>) -> Result<Option<Progress<'id>>, Error> {
        let native = Instant::now();
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
        let retirement_now = Instant::now();
        if self.slots.iter().flatten().any(|state| {
            state.outcome.is_none() && state.retirement.is_some_and(|end| retirement_now >= end)
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
    // Register the existing native target before any canonical-clock wait.
    // This sleep is only a wake source: it never changes hard/retirement bounds.
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
            .chain(until)
            .min();
        if let Some(target) = native {
            if self.native_at != Some(target) {
                let alarm = self
                    .native_alarm
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(target)));
                alarm.as_mut().reset(target);
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
    fn poll_alarm(
        &mut self,
        cx: &mut Context<'_>,
        until: Option<Instant>,
    ) -> Poll<Result<(), Fault>> {
        self.poll_native_alarm(cx, until)?;
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
        Poll::Pending
    }
    fn port_loss(&mut self, error: Error) -> Progress<'id> {
        self.blocked = true;
        self.lost(LossCause::Ports(error))
    }
    fn classified_loss(&mut self, error: Error) -> Progress<'id> {
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
        self.lost(cause)
    }
    /// Check and arm original native operation/control/drain deadlines before an
    /// outer owner's canonical-clock wait. Performs no socket IO, logical-clock
    /// sampling, decoding or crypto. Returns one actual prior admission loss,
    /// settled completion or native expiry; this never renews original targets.
    /// Any returned loss already physically retired the original MQ. Local
    /// completion preserves actual Unsent/Unknown exposure, not a service ACK.
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<Progress<'id>> {
        self.native_guard(cx, None)
    }
    fn native_guard(
        &mut self,
        cx: &mut Context<'_>,
        until: Option<Instant>,
    ) -> Option<Progress<'id>> {
        if let Some((report, cause)) = self.admission_loss.take() {
            return Some(Progress::Lost {
                report,
                cause: LossCause::Ports(cause.into()),
            });
        }
        if let Some(done) = self.complete() {
            return Some(Progress::Completed(done));
        }
        if self.closed || self.blocked || self.paused {
            return None;
        }
        match self.expire(None) {
            Ok(Some(event)) => return Some(event),
            Ok(None) => {}
            Err(error) => return Some(self.classified_loss(error)),
        }
        if let Err(error) = self.poll_native_alarm(cx, until) {
            return Some(self.port_loss(error.into()));
        }
        None
    }
    fn poll_step(
        &mut self,
        cx: &mut Context<'_>,
        until: Option<Instant>,
    ) -> Poll<Result<Progress<'id>, Error>> {
        if let Some(event) = self.native_guard(cx, until) {
            return Poll::Ready(Ok(event));
        }
        if self.closed {
            return Poll::Ready(Ok(Progress::Closed));
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
        // A continuously racing clock revision may keep poll_clock pending.
        // Native hard/initial/control/drain bounds must still retire the original
        // source, and their wake must be registered before that independent wait.
        if until.is_some_and(|target| Instant::now() >= target) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
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
            Poll::Ready(Err(error)) if !self.closed => Poll::Ready(Ok(self.classified_loss(error))),
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
