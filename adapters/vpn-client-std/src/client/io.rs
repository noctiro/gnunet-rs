//! Retained native cursors and one earliest original absolute deadline.
use super::Client;
use crate::{Epoch, Error, LossCause, Outcome, Progress, Reason, ipc::Response};
use gnunet_client_host::channel::ConnectionStep;
use gnunet_service_runtime::{clock::Deadline, framing::ReadStep};
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
    fn dispatch(&mut self, cx: &mut Context<'_>, epoch: Epoch<'a>) -> Result<Progress<'a>, Error> {
        if let Some(progress) = self.poll_native_guard(cx) {
            return progress;
        }
        let input = self
            .channel
            .framing()
            .and_then(|f| f.frame())
            .ok_or(ProtocolError::NotReady)?;
        if gnunet_wire::official::Frame::decode(input)?
            .header()
            .message_type()
            != gnunet_wire::official::message_type::VPN_CLIENT_USE_IP
        {
            self.release_input()?;
            return Ok(Progress::Ignored(epoch));
        }
        let response = match Response::decode_with_profile(input, self.profile) {
            Ok(response) => response,
            Err(error) => return self.retire(LossCause::Protocol(error), true),
        };
        if response.request_id == [0; 8] {
            return self.retire(LossCause::Protocol(ProtocolError::Malformed), true);
        }
        let index = self.slots.iter().position(|slot| {
            slot.as_ref()
                .is_some_and(|s| s.epoch == Some(epoch) && s.rid == response.request_id)
        });
        let Some(index) = index else {
            self.release_input()?;
            return Ok(Progress::Ignored(epoch));
        };
        let state = self.slots[index].as_ref().ok_or(ProtocolError::Stale)?;
        if state.reason.is_some() {
            self.release_input()?;
            return Ok(Progress::Ignored(epoch));
        }
        if !state.written
            || state.desired.is_some_and(|desired| {
                response
                    .address
                    .is_some_and(|address| address.family() != desired)
            })
        {
            return self.retire(LossCause::Protocol(ProtocolError::Malformed), true);
        }
        self.release_input()?;
        self.finish(index, Outcome::Allocation(response.address))?;
        self.next_event().ok_or_else(|| ProtocolError::Stale.into())
    }
    fn write(
        &mut self,
        cx: &mut Context<'_>,
        epoch: Epoch<'a>,
    ) -> Poll<Result<Progress<'a>, Error>> {
        if let Some(progress) = self.poll_native_guard(cx) {
            return Poll::Ready(progress);
        }
        let progress = match self
            .channel
            .framing_mut()
            .ok_or(ProtocolError::NotReady)?
            .poll_write(cx)
        {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(self.retire(LossCause::Io(error), true)),
            Poll::Ready(Ok(progress)) => progress,
        };
        let original = progress.origin;
        if original.epoch != epoch {
            return Poll::Ready(self.retire(LossCause::Protocol(ProtocolError::Stale), true));
        }
        let index = self.index(original.operation)?;
        let state = self.slots[index].as_mut().ok_or(ProtocolError::Stale)?;
        state.exposed = true;
        self.read_first = true;
        if !progress.complete {
            return Poll::Ready(Ok(Progress::Activity {
                epoch,
                read_bytes: 0,
                written_bytes: progress.bytes,
            }));
        }
        state.pending = false;
        state.written = true;
        if let Some(reason) = state.reason {
            let submission = Self::submission(state);
            self.finish(index, Outcome::Local { reason, submission })?;
        }
        Poll::Ready(Ok(Progress::Written {
            epoch,
            operation: original.operation,
            write: original.write,
        }))
    }
    fn read(
        &mut self,
        cx: &mut Context<'_>,
        epoch: Epoch<'a>,
    ) -> Poll<Result<Progress<'a>, Error>> {
        if let Some(progress) = self.poll_native_guard(cx) {
            return Poll::Ready(progress);
        }
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
                    if let Some(progress) = self.poll_native_guard(cx) {
                        return Poll::Ready(progress);
                    }
                    Poll::Ready(self.dispatch(cx, epoch))
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
            if let Some(retirement) = state.retirement {
                if now >= retirement.expires() {
                    return self.retire(LossCause::Deadline, true).map(Some);
                }
            } else if now >= state.bounds.expires() {
                self.cancel_index(index, Reason::Deadline, Instant::now())?;
                if self.slots[index]
                    .as_ref()
                    .and_then(|state| state.retirement)
                    .is_some_and(|bound| now >= bound.expires())
                {
                    return self.retire(LossCause::Deadline, true).map(Some);
                }
            }
        }
        self.retire_idle_connect();
        Ok(None)
    }
    fn expire_native(&mut self, now: Instant) -> Result<Option<Progress<'a>>, Error> {
        for index in 0..self.slots.len() {
            let Some(state) = &self.slots[index] else {
                continue;
            };
            if let Some(retirement) = state.retirement {
                if now >= retirement.hard() {
                    return self.retire(LossCause::Deadline, true).map(Some);
                }
            } else if now >= state.bounds.hard() {
                self.cancel_index(index, Reason::Deadline, now)?;
                if self.slots[index]
                    .as_ref()
                    .and_then(|state| state.retirement)
                    .is_some_and(|bound| now >= bound.hard())
                {
                    return self.retire(LossCause::Deadline, true).map(Some);
                }
            }
        }
        self.retire_idle_connect();
        Ok(None)
    }
    /// Check and arm original native response/retirement targets before a
    /// containing owner's clock wait. Cancellation and this guard sample no
    /// canonical clock or advance socket cursors. Returned losses have already
    /// detached the original MQ; local completions confer no remote receipt.
    pub fn poll_native_guard(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Option<Result<Progress<'a>, Error>> {
        if self.closed {
            return None;
        }
        loop {
            let progress = match self.expire_native(Instant::now()) {
                Ok(progress) => progress,
                Err(Error::Protocol(error)) => {
                    return Some(self.retire(LossCause::Resource(error), true));
                }
                Err(error) => return Some(self.refuse_ports(error)),
            };
            if let Some(progress) = progress {
                return Some(Ok(progress));
            }
            if let Some(target) = self.next_native_deadline() {
                let alarm = self
                    .native_alarm
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(target)));
                alarm.as_mut().reset(target);
                if alarm.as_mut().poll(cx).is_ready() {
                    if Instant::now() >= target {
                        continue;
                    }
                    cx.waker().wake_by_ref();
                }
            } else {
                self.native_alarm = None;
            }
            return if matches!(
                self.events.front(),
                Some(Progress::Completed {
                    outcome: Outcome::Local { .. },
                    ..
                })
            ) {
                self.next_event().map(Ok)
            } else {
                None
            };
        }
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
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.alarm = None;
                self.alarm_at = None;
                Poll::Ready(result)
            }
        }
    }
    fn poll_step(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Option<Instant>,
    ) -> Poll<Result<Progress<'a>, Error>> {
        if let Some(progress) = self.poll_native_guard(cx) {
            return Poll::Ready(progress);
        }
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
        if deadline.is_some_and(|until| Instant::now() >= until) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        if self.channel.framing().is_none() && self.slots.iter().all(Option::is_none) {
            return self
                .channel
                .poll_wait(cx, deadline)
                .map_ok(|()| Progress::WaitDeadline);
        }
        match self.channel.poll_clock(cx) {
            // The caller's fixed native observation target remains live even
            // while the canonical clock is waiting for a consistent revision.
            Poll::Pending => {
                return self
                    .channel
                    .poll_wait(cx, deadline)
                    .map_ok(|()| Progress::WaitDeadline);
            }
            Poll::Ready(Err(error)) => return Poll::Ready(self.refuse_ports(error)),
            Poll::Ready(Ok(())) => {}
        }
        let now = match self.now() {
            Ok(now) => now,
            Err(error) => return Poll::Ready(self.refuse_clock(error)),
        };
        if let Some(progress) = self.poll_native_guard(cx) {
            return Poll::Ready(progress);
        }
        if let Some(progress) = self.expire(now)? {
            return Poll::Ready(Ok(progress));
        }
        if let Some(progress) = self.poll_native_guard(cx) {
            return Poll::Ready(progress);
        }
        match self.poll_alarm(cx) {
            Poll::Ready(Err(error)) => return Poll::Ready(self.refuse_clock(error)),
            Poll::Ready(Ok(())) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Pending => {}
        }
        if self.channel.framing().is_none() {
            if let Some(progress) = self.poll_native_guard(cx) {
                return Poll::Ready(progress);
            }
            return match self.channel.poll_connect(cx) {
                Poll::Pending => self
                    .channel
                    .poll_wait(cx, deadline)
                    .map_ok(|()| Progress::WaitDeadline),
                Poll::Ready(Err(error)) => Poll::Ready(self.refuse_ports(error)),
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
        let epoch = self.epoch.ok_or(ProtocolError::NotReady)?;
        if self
            .channel
            .framing()
            .is_some_and(|frame| frame.frame().is_some())
        {
            return Poll::Ready(self.dispatch(cx, epoch));
        }
        if let Err(error) = self.prepare() {
            return Poll::Ready(match error {
                Error::Protocol(error) => self.retire(LossCause::Resource(error), true),
                other => self.refuse_ports(other),
            });
        }
        if self.read_first {
            if let Poll::Ready(result) = self.read(cx, epoch) {
                return Poll::Ready(result);
            }
            if let Poll::Ready(result) = self.write(cx, epoch) {
                return Poll::Ready(result);
            }
        } else {
            if let Poll::Ready(result) = self.write(cx, epoch) {
                return Poll::Ready(result);
            }
            if let Poll::Ready(result) = self.read(cx, epoch) {
                return Poll::Ready(result);
            }
        }
        self.channel
            .poll_wait(cx, deadline)
            .map_ok(|()| Progress::WaitDeadline)
    }
    /// Drive one bounded native/protocol step. Dropping this future preserves
    /// original RX/TX suffixes, request identity and absolute deadlines.
    pub async fn drive(&mut self, deadline: Option<Instant>) -> Result<Progress<'a>, Error> {
        poll_fn(|cx| {
            if self.yield_due { self.yield_due = false; cx.waker().wake_by_ref(); return Poll::Pending; }
            let progress = self.poll_step(cx, deadline);
            let progress = match progress {
                Poll::Ready(Err(error)) if self.channel.framing().is_some() => {
                    Poll::Ready(match error {
                        Error::Protocol(error) => self.retire(LossCause::Protocol(error), true),
                        other => self.refuse_ports(other),
                    })
                }
                other => other,
            };
            if matches!(&progress, Poll::Ready(Ok(event)) if !matches!(event, Progress::Closed | Progress::WaitDeadline)) {
                self.yield_due = true;
            }
            progress
        }).await
    }
}
