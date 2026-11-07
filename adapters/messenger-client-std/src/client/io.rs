use super::{Client, Origin, Phase};
use crate::{Error, Kind, LossCause, Notification, Progress};
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
impl<'a> Client<'a> {
    fn initial_pending(&self) -> bool {
        matches!(
            self.phase,
            Phase::Connecting | Phase::Attached | Phase::Creating
        )
    }
    fn expired(&mut self, logical: Option<u64>) -> Option<Progress<'a>> {
        let now = Instant::now();
        let cause = if self.input_hard.is_some_and(|until| now >= until) {
            Some(LossCause::InputDeadline)
        } else if self.initial_pending()
            && (now >= self.initial_hard || logical.is_some_and(|v| v >= self.initial_expires))
        {
            Some(LossCause::InitialDeadline)
        } else {
            self.queue
                .iter()
                .find(|p| now >= p.hard || logical.is_some_and(|v| v >= p.expires))
                .map(|p| LossCause::FrameDeadline(p.operation))
        };
        cause.map(|cause| Progress::Lost(self.lose(cause)))
    }
    fn native_alarm(&mut self, cx: &mut Context<'_>) {
        let target = self
            .queue
            .iter()
            .map(|p| p.hard)
            .chain(self.input_hard)
            .chain(self.initial_pending().then_some(self.initial_hard))
            .min();
        if let Some(target) = target {
            if self.native_at != Some(target) {
                self.native_alarm = Some(Box::pin(tokio::time::sleep_until(target)));
                self.native_at = Some(target);
            }
            if let Some(alarm) = &mut self.native_alarm
                && alarm.as_mut().poll(cx).is_ready()
            {
                cx.waker().wake_by_ref();
            }
        } else {
            self.native_alarm = None;
            self.native_at = None;
        }
    }
    fn logical_alarm(&mut self, cx: &mut Context<'_>) -> Result<(), Fault> {
        let target = self
            .queue
            .iter()
            .map(|p| p.expires)
            .chain(self.initial_pending().then_some(self.initial_expires))
            .min();
        if let Some(target) = target {
            if self.alarm_at != Some(target) {
                self.alarm = Some(Box::pin(Deadline::at(
                    self.clock.clone(),
                    gnunet_types::AbsoluteTime::from_micros(target),
                )?));
                self.alarm_at = Some(target);
            }
            if let Some(alarm) = &mut self.alarm
                && let Poll::Ready(result) = alarm.as_mut().poll(cx)
            {
                result?;
                self.alarm = None;
                self.alarm_at = None;
                cx.waker().wake_by_ref();
            }
        } else {
            self.alarm = None;
            self.alarm_at = None;
        }
        Ok(())
    }
    fn prepare(&mut self) -> Result<Option<Progress<'a>>, Error> {
        let epoch = self.epoch.ok_or(Fault::NotReady)?;
        let Some(p) = self.queue.front_mut().filter(|p| !p.queued) else {
            return Ok(None);
        };
        let framed = self.channel.framing_mut().ok_or(Fault::NotReady)?;
        // Only one original frame is admitted at once, maintaining FIFO CREATE/
        // ordinary/DESTROY ordering without a hidden control-priority queue.
        if framed.queued_frames() != 0 {
            return Err(Fault::Conflict.into());
        }
        framed.reserve(p.len, Class::Ordinary)?;
        let origin = Origin {
            epoch,
            operation: p.operation,
        };
        let frame = p.frame.take().ok_or(Fault::Conflict)?;
        if let Err(rejected) = framed.enqueue_owned(frame, origin, Class::Ordinary) {
            p.frame = Some(rejected.value.0);
            return Err(rejected.reason.into());
        }
        p.queued = true;
        Ok(Some(Progress::Queued {
            epoch,
            operation: p.operation,
            kind: p.kind,
        }))
    }
    fn write(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress<'a>, Error>> {
        let p = match self
            .channel
            .framing_mut()
            .ok_or(Fault::NotReady)?
            .poll_write(cx)
        {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result?,
        };
        let front = self.queue.front_mut().ok_or(Fault::Conflict)?;
        if self.epoch != Some(p.origin.epoch)
            || front.operation != p.origin.operation
            || !front.queued
        {
            return Poll::Ready(Err(Fault::StaleGeneration.into()));
        }
        front.sent = front.sent.checked_add(p.bytes).ok_or(Fault::Overflow)?;
        if front.sent > front.len || p.complete != (front.sent == front.len) {
            return Poll::Ready(Err(Fault::Conflict.into()));
        }
        self.read_first = true;
        if p.complete {
            let front = self.queue.pop_front().ok_or(Fault::Conflict)?;
            self.bytes = self
                .bytes
                .checked_sub(front.charge)
                .ok_or(Fault::Conflict)?;
            if front.kind == Kind::Create {
                self.phase = Phase::Active;
            }
            if front.kind == Kind::Destroy {
                if !self.queue.is_empty() {
                    return Poll::Ready(Err(Fault::Conflict.into()));
                }
                self.channel.close();
                self.epoch = None;
                self.phase = Phase::Closed;
                self.input_hard = None;
                self.alarm = None;
                self.alarm_at = None;
                self.native_alarm = None;
                self.native_at = None;
            }
            return Poll::Ready(Ok(Progress::Written {
                epoch: p.origin.epoch,
                operation: p.origin.operation,
                kind: front.kind,
                bytes: front.len,
            }));
        }
        Poll::Ready(Ok(Progress::Activity {
            read_bytes: 0,
            written_bytes: p.bytes,
        }))
    }
    fn read(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress<'a>, Error>> {
        let epoch = self.epoch.ok_or(Fault::NotReady)?;
        // Domain notifications have no meaning before the actual CREATE write.
        if !matches!(self.phase, Phase::Active | Phase::Destroying) {
            return Poll::Pending;
        }
        let framed = self.channel.framing_mut().ok_or(Fault::NotReady)?;
        let step = match framed.poll_read(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result?,
        };
        match step {
            ReadStep::Eof => Poll::Ready(Ok(Progress::Lost(self.lose(LossCause::Eof)))),
            ReadStep::Progress { bytes, complete } => {
                self.read_first = false;
                if bytes > 0 && self.input_hard.is_none() {
                    self.input_hard = Some(
                        Instant::now()
                            .checked_add(self.limits.input_lifetime)
                            .ok_or(Fault::Overflow)?,
                    );
                }
                if complete {
                    let frame = framed.frame().ok_or(Fault::NotReady)?;
                    crate::ipc::Response::decode(frame, self.limits.profile)?;
                    let notification = Notification {
                        frame: OwnedFrame::copy_from(frame)?,
                        profile: self.limits.profile,
                    };
                    framed.release_frame();
                    self.input_hard = None;
                    return Poll::Ready(Ok(Progress::Notification {
                        epoch,
                        notification,
                    }));
                }
                Poll::Ready(Ok(Progress::Activity {
                    read_bytes: bytes,
                    written_bytes: 0,
                }))
            }
        }
    }
    fn poll_step(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress<'a>, Error>> {
        if let Some(loss) = self.pending_loss.take() {
            return Poll::Ready(Ok(Progress::Lost(loss)));
        }
        if matches!(self.phase, Phase::Closed | Phase::Disconnected) {
            return Poll::Ready(Err(Fault::NotReady.into()));
        }
        if let Some(event) = self.expired(None) {
            return Poll::Ready(Ok(event));
        }
        // Fixed native bounds and wake registration precede canonical clock
        // readiness, so adjustment races cannot postpone physical retirement.
        self.native_alarm(cx);
        if self.yield_due {
            self.yield_due = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        match self.channel.poll_clock(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result?,
        }
        let now = self.clock.sample()?.now.as_micros();
        if let Some(event) = self.expired(Some(now)) {
            return Poll::Ready(Ok(event));
        }
        self.logical_alarm(cx)?;
        if self.phase == Phase::Connecting {
            match self.channel.poll_connect(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(ConnectionStep::Attached)) => {
                    let epoch = self.scope.epoch()?;
                    self.epoch = Some(epoch);
                    self.phase = Phase::Attached;
                    return Poll::Ready(Ok(Progress::Attached(epoch)));
                }
                Poll::Ready(Ok(ConnectionStep::Retry { error, .. })) => {
                    return Poll::Ready(Err(error.into()));
                }
                Poll::Ready(Ok(ConnectionStep::Unavailable(error))) => {
                    return Poll::Ready(Err(error));
                }
            }
        }
        if let Some(event) = self.prepare()? {
            return Poll::Ready(Ok(event));
        }
        let result = if self.read_first {
            let result = self.read(cx);
            if result.is_ready() {
                result
            } else {
                self.write(cx)
            }
        } else {
            let result = self.write(cx);
            if result.is_ready() {
                result
            } else {
                self.read(cx)
            }
        };
        if result.is_pending() {
            self.native_alarm(cx);
        }
        result
    }
    /// Drive at most one native byte step/connection event. Every returned
    /// positive write is reported before another service read. Polling creates
    /// no background task; cancelled waits retain all original partial cursors.
    pub fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress<'a>, Error>> {
        if matches!(self.phase, Phase::Closed | Phase::Disconnected) && self.pending_loss.is_none()
        {
            return Poll::Ready(Err(Fault::Closed.into()));
        }
        match self.poll_step(cx) {
            Poll::Ready(Ok(event)) => {
                self.yield_due = true;
                Poll::Ready(Ok(event))
            }
            Poll::Ready(Err(error)) => {
                Poll::Ready(Ok(Progress::Lost(self.lose(LossCause::Failure(error)))))
            }
            Poll::Pending => Poll::Pending,
        }
    }
    /// Wait for one original progress event. Dropping this future cancels only
    /// the wait; explicit cancel/close physically retires the source itself.
    pub async fn progress(&mut self) -> Result<Progress<'a>, Error> {
        poll_fn(|cx| self.poll_progress(cx)).await
    }
}
