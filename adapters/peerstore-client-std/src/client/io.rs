//! Shared CLIENT/reactor steps and one earliest original absolute deadline.
use super::{Client, Mode};
use crate::{
    Command, Epoch, Error, Kind, LossCause, Observation, Outcome, Progress, Reason, RecordPhase,
    Submission,
    ipc::{Request, Response},
};
use gnunet_client_host::channel::ConnectionStep;
use gnunet_service_runtime::{
    clock::Deadline,
    framing::{OwnedFrame, ReadStep},
};
use gnunet_types::Error as ProtocolError;
use std::{
    future::{Future, poll_fn},
    task::{Context, Poll},
};
use tokio::time::Instant;
impl<'a> Client<'a> {
    fn release_input(&mut self) -> Result<(), Error> {
        if !self
            .channel
            .framing_mut()
            .ok_or(ProtocolError::NotReady)?
            .release_frame()
        {
            return Err(ProtocolError::Stale.into());
        }
        Ok(())
    }
    fn dispatch(&mut self, epoch: Epoch<'a>, now: u64) -> Result<Progress<'a>, Error> {
        let input = self
            .channel
            .framing()
            .and_then(|frame| frame.frame())
            .ok_or(ProtocolError::NotReady)?;
        let response = match Response::decode(input) {
            Ok(response) => response,
            Err(ProtocolError::Unsupported) => {
                self.release_input()?;
                return Ok(Progress::Ignored(epoch));
            }
            Err(error) => return self.retire(LossCause::Protocol(error), true),
        };
        let rid = match response {
            Response::Record(envelope) => Some(envelope.rid),
            Response::StoreResult { rid, .. } | Response::IterateEnd { rid, .. } => Some(rid),
            Response::MonitorSync => None,
        };
        let index = if self.mode == Mode::Monitor {
            self.slots.iter().position(|state| {
                state
                    .as_ref()
                    .is_some_and(|state| state.kind == Kind::Monitor && state.epoch == Some(epoch))
            })
        } else {
            rid.and_then(|rid| {
                self.slots.iter().position(|state| {
                    state
                        .as_ref()
                        .is_some_and(|state| state.rid == rid && state.epoch == Some(epoch))
                })
            })
        };
        let Some(index) = index else {
            self.release_input()?;
            return Ok(Progress::Ignored(epoch));
        };
        let state = self.slots[index].as_ref().ok_or(ProtocolError::Stale)?;
        if state.done || state.reason.is_some() {
            self.release_input()?;
            return Ok(Progress::Ignored(epoch));
        }
        if !state.started {
            return self.retire(LossCause::Protocol(ProtocolError::Malformed), true);
        }
        let operation = state.operation;
        match response {
            Response::Record(envelope) => {
                if state.kind == Kind::Store
                    || (state.kind == Kind::Monitor && envelope.rid != 0)
                    || state.credit == 0
                {
                    return self.retire(LossCause::Protocol(ProtocolError::Malformed), true);
                }
                let filter = match Request::decode(
                    state.source.as_ref().ok_or(ProtocolError::Stale)?.bytes(),
                )? {
                    Request::IterateStart(start) => start.filter,
                    Request::MonitorStart(start) => start.filter,
                    _ => return Err(ProtocolError::Stale.into()),
                };
                if !filter.matches(envelope.record) {
                    return self.retire(LossCause::Protocol(ProtocolError::Malformed), true);
                }
                let phase = if state.kind == Kind::Iteration {
                    RecordPhase::Iteration
                } else if state.synced {
                    RecordPhase::Live
                } else {
                    RecordPhase::Initial
                };
                let frame = match OwnedFrame::copy_from(input) {
                    Ok(frame) => frame,
                    Err(ProtocolError::Capacity) => return Ok(Progress::Capacity(epoch)),
                    Err(error) => return Err(error.into()),
                };
                self.slots[index]
                    .as_mut()
                    .ok_or(ProtocolError::Stale)?
                    .credit -= 1;
                self.release_input()?;
                Ok(Progress::Record(Observation {
                    epoch,
                    operation,
                    phase,
                    frame,
                }))
            }
            Response::StoreResult { result, .. } => {
                if self.mode != Mode::Requests || state.kind != Kind::Store {
                    return self.retire(LossCause::Protocol(ProtocolError::Malformed), true);
                }
                self.release_input()?;
                self.complete(index, Outcome::StoreResult(result), now)?;
                self.next_event().ok_or_else(|| ProtocolError::Stale.into())
            }
            Response::IterateEnd { result, .. } => {
                if self.mode != Mode::Requests || state.kind != Kind::Iteration {
                    return self.retire(LossCause::Protocol(ProtocolError::Malformed), true);
                }
                self.release_input()?;
                // An already arriving END can race a caller's newly queued NEXT.
                // Remove only wholly unwritten originals; any actual partial
                // suffix retains this debt slot and its finite physical bound.
                self.remove_unwritten(index)?;
                self.complete(index, Outcome::IterationEnd(result), now)?;
                self.next_event().ok_or_else(|| ProtocolError::Stale.into())
            }
            Response::MonitorSync => {
                if self.mode != Mode::Monitor || state.kind != Kind::Monitor || state.synced {
                    return self.retire(LossCause::Protocol(ProtocolError::Malformed), true);
                }
                self.slots[index]
                    .as_mut()
                    .ok_or(ProtocolError::Stale)?
                    .synced = true;
                self.release_input()?;
                Ok(Progress::Sync { epoch, operation })
            }
        }
    }
    fn write(
        &mut self,
        cx: &mut Context<'_>,
        epoch: Epoch<'a>,
        now: u64,
    ) -> Poll<Result<Progress<'a>, Error>> {
        let result = self
            .channel
            .framing_mut()
            .ok_or(ProtocolError::NotReady)?
            .poll_write(cx);
        let progress = match result {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => {
                return Poll::Ready(self.retire(LossCause::Io(error), true));
            }
            Poll::Ready(Ok(progress)) => progress,
        };
        let original = progress.origin;
        if original.epoch != epoch {
            return Poll::Ready(self.retire(LossCause::Protocol(ProtocolError::Stale), true));
        }
        let index = self.index(original.operation)?;
        let state = self.slots[index].as_mut().ok_or(ProtocolError::Stale)?;
        if original.command == Command::Start {
            state.exposed = true;
        }
        self.read_first = true;
        if !progress.complete {
            return Poll::Ready(Ok(Progress::Activity {
                epoch,
                read_bytes: 0,
                written_bytes: progress.bytes,
            }));
        }
        state.pending = state.pending.checked_sub(1).ok_or(ProtocolError::Stale)?;
        match original.command {
            Command::Start => {
                state.started = true;
                if state.kind != Kind::Store && !state.done && state.reason.is_none() {
                    state.credit = 1;
                }
            }
            Command::Next { limit } => {
                state.next_pending = false;
                if !state.done && state.reason.is_none() {
                    state.credit = state
                        .credit
                        .checked_add(limit)
                        .ok_or(ProtocolError::Overflow)?;
                }
            }
            Command::Stop => {
                let reason = state.reason.ok_or(ProtocolError::Stale)?;
                self.complete(
                    index,
                    Outcome::Local {
                        reason,
                        submission: Submission::StopSubmitted,
                    },
                    now,
                )?;
            }
        }
        if let Some(state) = &self.slots[index]
            && state.kind == Kind::Store
            && state.started
        {
            self.drop_source(index);
        }
        if let Some(state) = &self.slots[index] {
            if state.done && state.pending == 0 {
                self.remove(index);
            } else if state.kind == Kind::Store && state.reason.is_some() && state.pending == 0 {
                let reason = state.reason.ok_or(ProtocolError::Stale)?;
                let submission = Self::submission(state);
                self.complete(index, Outcome::Local { reason, submission }, now)?;
            }
        }
        Poll::Ready(Ok(Progress::Written {
            epoch,
            operation: original.operation,
            write: original.write,
            command: original.command,
        }))
    }
    fn read(
        &mut self,
        cx: &mut Context<'_>,
        epoch: Epoch<'a>,
        now: u64,
    ) -> Poll<Result<Progress<'a>, Error>> {
        match self
            .channel
            .framing_mut()
            .ok_or(ProtocolError::NotReady)?
            .poll_read(cx)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(self.retire(LossCause::Io(error), true)),
            Poll::Ready(Ok(ReadStep::Eof)) => Poll::Ready(self.retire(LossCause::Eof, true)),
            Poll::Ready(Ok(ReadStep::Progress { bytes, complete })) => {
                self.read_first = false;
                if complete {
                    Poll::Ready(self.dispatch(epoch, now))
                } else {
                    Poll::Ready(Ok(Progress::Activity {
                        epoch,
                        read_bytes: bytes,
                        written_bytes: 0,
                    }))
                }
            }
        }
    }
    fn expire(&mut self, now: u64) -> Result<Option<Progress<'a>>, Error> {
        for index in 0..self.slots.len() {
            let Some(state) = &self.slots[index] else {
                continue;
            };
            if let Some(hard) = state.hard {
                if now >= hard {
                    return self.retire(LossCause::Deadline, true).map(Some);
                }
            } else if now >= state.expires {
                self.retire_operation(index, Reason::Deadline, now)?;
                return Ok(self.next_event());
            }
        }
        Ok(None)
    }
    fn poll_alarm(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), ProtocolError>> {
        let Some(target) = self.next_deadline() else {
            self.alarm = None;
            self.alarm_at = None;
            return Poll::Pending;
        };
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
            .ok_or(ProtocolError::NotReady)?
            .as_mut()
            .poll(cx)
        {
            Poll::Ready(result) => {
                self.alarm = None;
                self.alarm_at = None;
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_step(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Option<Instant>,
    ) -> Poll<Result<Progress<'a>, Error>> {
        if let Some(event) = self.next_event() {
            return Poll::Ready(Ok(event));
        }
        if self.closed {
            return Poll::Ready(Ok(Progress::Closed));
        }
        if let Some(error) = self.clock_fault {
            return Poll::Ready(Err(error.into()));
        }
        if self.port_blocked {
            return Poll::Ready(Err(ProtocolError::Unavailable.into()));
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        match self.channel.poll_clock(cx) {
            // The canonical clock can stay pending while it stabilizes. Keep
            // this borrow's original native observation target registered on
            // the same Channel; it does not cancel or renew any operation.
            Poll::Pending => {
                return self
                    .channel
                    .poll_wait(cx, deadline)
                    .map_ok(|()| Progress::WaitDeadline);
            }
            Poll::Ready(Err(error)) => {
                return Poll::Ready(self.refuse_ports(error));
            }
            Poll::Ready(Ok(())) => {}
        }
        let now = match self.now() {
            Ok(now) => now,
            Err(error) => return Poll::Ready(self.refuse_clock(error)),
        };
        if let Some(progress) = self.expire(now)? {
            return Poll::Ready(Ok(progress));
        }
        match self.poll_alarm(cx) {
            Poll::Ready(Err(error)) => {
                return Poll::Ready(self.refuse_clock(error));
            }
            Poll::Ready(Ok(())) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Pending => {}
        }
        if self.channel.framing().is_none() {
            match self.channel.poll_connect(cx) {
                Poll::Pending => {
                    return self
                        .channel
                        .poll_wait(cx, deadline)
                        .map_ok(|()| Progress::WaitDeadline);
                }
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(self.refuse_ports(error));
                }
                Poll::Ready(Ok(ConnectionStep::Attached)) => {
                    let epoch = match self.scope.epoch() {
                        Ok(epoch) => epoch,
                        Err(error) => {
                            self.channel.detach();
                            return Poll::Ready(Err(error.into()));
                        }
                    };
                    self.epoch = Some(epoch);
                    return Poll::Ready(Ok(Progress::Connected(epoch)));
                }
                Poll::Ready(Ok(ConnectionStep::Retry { error, retry_after })) => {
                    return Poll::Ready(Ok(Progress::ConnectRetry { error, retry_after }));
                }
                Poll::Ready(Ok(ConnectionStep::Unavailable(error))) => {
                    return Poll::Ready(Ok(Progress::Unavailable(error)));
                }
            }
        }
        let epoch = self.epoch.ok_or(ProtocolError::NotReady)?;
        if self
            .channel
            .framing()
            .is_some_and(|frame| frame.frame().is_some())
        {
            return Poll::Ready(self.dispatch(epoch, now));
        }
        if let Err(error) = self.prepare() {
            return Poll::Ready(match error {
                Error::Protocol(reason) => self.retire(LossCause::Resource(reason), true),
                other => self.refuse_ports(other),
            });
        }
        if self.read_first {
            if let Poll::Ready(progress) = self.read(cx, epoch, now) {
                return Poll::Ready(progress);
            }
            if let Poll::Ready(progress) = self.write(cx, epoch, now) {
                return Poll::Ready(progress);
            }
        } else {
            if let Poll::Ready(progress) = self.write(cx, epoch, now) {
                return Poll::Ready(progress);
            }
            if let Poll::Ready(progress) = self.read(cx, epoch, now) {
                return Poll::Ready(progress);
            }
        }
        self.channel
            .poll_wait(cx, deadline)
            .map_ok(|()| Progress::WaitDeadline)
    }
    /// Drive one bounded real action. Dropped futures retain original native
    /// attempts, RX/TX suffixes, finite absolute deadlines and source retry timers.
    pub async fn drive(&mut self, deadline: Option<Instant>) -> Result<Progress<'a>, Error> {
        poll_fn(|cx| {
            if self.yield_due { self.yield_due = false; cx.waker().wake_by_ref(); return Poll::Pending; }
            let progress = self.poll_step(cx, deadline);
            if matches!(&progress, Poll::Ready(Ok(event)) if !matches!(event, Progress::Closed | Progress::WaitDeadline | Progress::Capacity(_))) { self.yield_due = true; }
            progress
        }).await
    }
}
