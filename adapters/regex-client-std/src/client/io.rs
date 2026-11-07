//! Bounded shared CLIENT/framing steps; no implicit job rebuild or replay.
use super::{Client, Mode};
use crate::{EndCause, Epoch, Error, Progress, ipc::SearchResult};
use gnunet_client_host::channel::ConnectionStep;
use gnunet_service_runtime::{clock::Deadline, framing::ReadStep};
use gnunet_types::Error as ProtocolError;
use std::{
    future::{Future, poll_fn},
    task::{Context, Poll},
};
use tokio::time::Instant;
impl<'id> Client<'id> {
    fn dispatch(&mut self, epoch: Epoch<'id>, now: u64) -> Result<Progress<'id>, Error> {
        if self.mode != Mode::Search || !self.written || self.grace.is_some() {
            return Ok(Progress::Ended(
                self.end(EndCause::Protocol(ProtocolError::Malformed)),
            ));
        }
        let input = self
            .channel
            .framing()
            .and_then(|f| f.frame())
            .ok_or(ProtocolError::NotReady)?;
        let result = SearchResult::decode(input)?;
        let len = result
            .get_path
            .len()
            .checked_add(result.put_path.len())
            .ok_or(ProtocolError::Capacity)?;
        if len > self.limits.path_entries {
            return Err(ProtocolError::Capacity.into());
        }
        self.ordinal = self.ordinal.checked_add(1).ok_or(ProtocolError::Overflow)?;
        self.result_at = Some(now);
        self.first_result = true;
        self.channel.reset_backoff();
        self.alarm = None;
        self.alarm_at = None;
        Ok(Progress::ResultReady {
            job: self.scope.job(),
            epoch,
            ordinal: self.ordinal,
        })
    }
    fn write(
        &mut self,
        cx: &mut Context<'_>,
        epoch: Epoch<'id>,
    ) -> Poll<Result<Progress<'id>, Error>> {
        let progress = match self
            .channel
            .framing_mut()
            .ok_or(ProtocolError::NotReady)?
            .poll_write(cx)
        {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => {
                return Poll::Ready(self.source_lost(EndCause::Io(error)));
            }
            Poll::Ready(Ok(progress)) => progress,
        };
        let origin = progress.origin;
        if origin.epoch != epoch
            || origin.job != self.scope.job()
            || origin.write != self.scope.write()
        {
            return Poll::Ready(Err(ProtocolError::Stale.into()));
        }
        self.sent = self
            .sent
            .checked_add(progress.bytes)
            .ok_or(ProtocolError::Overflow)?;
        if self.sent > self.total {
            return Poll::Ready(Err(ProtocolError::Stale.into()));
        }
        self.read_first = true;
        if !progress.complete {
            return Poll::Ready(Ok(Progress::Activity {
                epoch,
                read_bytes: 0,
                written_bytes: progress.bytes,
            }));
        }
        if self.sent != self.total {
            return Poll::Ready(Err(ProtocolError::Stale.into()));
        }
        self.written = true;
        self.first_written = true;
        self.alarm = None;
        self.alarm_at = None;
        if self.grace.is_some() {
            let end = self.end(EndCause::Graceful);
            self.pending_end = Some(end);
        }
        Poll::Ready(Ok(Progress::Submitted {
            job: origin.job,
            epoch,
            write: origin.write,
        }))
    }
    fn read(
        &mut self,
        cx: &mut Context<'_>,
        epoch: Epoch<'id>,
        now: u64,
    ) -> Poll<Result<Progress<'id>, Error>> {
        if self.grace.is_some() {
            return Poll::Pending;
        }
        match self
            .channel
            .framing_mut()
            .ok_or(ProtocolError::NotReady)?
            .poll_read(cx)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(self.source_lost(EndCause::Io(error))),
            Poll::Ready(Ok(ReadStep::Eof)) => Poll::Ready(self.source_lost(EndCause::Eof)),
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
    fn poll_alarm(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), ProtocolError>> {
        let Some(target) = self.next_deadline() else {
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
        until: Option<Instant>,
    ) -> Poll<Result<Progress<'id>, Error>> {
        if let Some(end) = self.pending_end.take() {
            return Poll::Ready(Ok(Progress::Ended(end)));
        }
        if self.closed {
            return Poll::Ready(Ok(Progress::Closed));
        }
        match self.channel.poll_clock(cx) {
            // The caller's fixed native observation target remains live even
            // while the canonical clock is waiting for a consistent revision.
            Poll::Pending => {
                return self
                    .channel
                    .poll_wait(cx, until)
                    .map_ok(|()| Progress::WaitDeadline);
            }
            Poll::Ready(Err(error)) => {
                return Poll::Ready(Ok(Progress::Ended(self.end(EndCause::Ports(error)))));
            }
            Poll::Ready(Ok(())) => {}
        }
        let now = match self.clock.sample() {
            Ok(sample) => sample.now.as_micros(),
            Err(error) => {
                return Poll::Ready(Ok(Progress::Ended(self.end(EndCause::Clock(error)))));
            }
        };
        if let Some(end) = self.expire(now) {
            return Poll::Ready(Ok(end));
        }
        match self.poll_alarm(cx) {
            Poll::Ready(Err(error)) => {
                return Poll::Ready(Ok(Progress::Ended(self.end(EndCause::Clock(error)))));
            }
            Poll::Ready(Ok(())) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Pending => {}
        }
        // Caller observation timeout is checked only after original source and
        // logical deadlines, so it cannot hide a clock refusal or expired job.
        if until.is_some_and(|deadline| Instant::now() >= deadline) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        if self.result_at.is_some() {
            return Poll::Ready(Ok(Progress::ResultReady {
                job: self.scope.job(),
                epoch: self.epoch.ok_or(ProtocolError::Stale)?,
                ordinal: self.ordinal,
            }));
        }
        if self.channel.framing().is_none() {
            // Counter exhaustion is refused before any replacement native IO.
            // The reserved token becomes observable only on actual attachment.
            let epoch = self.scope.attachment()?;
            return match self.channel.poll_connect(cx) {
                Poll::Pending => self
                    .channel
                    .poll_wait(cx, until)
                    .map_ok(|()| Progress::WaitDeadline),
                Poll::Ready(Err(error)) => {
                    Poll::Ready(Ok(Progress::Ended(self.end(EndCause::Ports(error)))))
                }
                Poll::Ready(Ok(ConnectionStep::Attached)) => {
                    self.scope.attached(epoch);
                    self.epoch = Some(epoch);
                    self.queued = false;
                    self.written = false;
                    self.sent = 0;
                    Poll::Ready(Ok(Progress::Connected {
                        job: self.scope.job(),
                        epoch,
                    }))
                }
                Poll::Ready(Ok(ConnectionStep::Retry { error, retry_after })) => {
                    Poll::Ready(Ok(Progress::ConnectRetry { error, retry_after }))
                }
                Poll::Ready(Ok(ConnectionStep::Unavailable(error))) => {
                    Poll::Ready(Ok(Progress::Unavailable(error)))
                }
            };
        }
        let epoch = self.epoch.ok_or(ProtocolError::Stale)?;
        if let Some(queued) = self.prepare()? {
            return Poll::Ready(Ok(queued));
        }
        if self.channel.framing().is_some_and(|f| f.frame().is_some()) {
            return Poll::Ready(self.dispatch(epoch, now));
        }
        if self.read_first {
            if let Poll::Ready(step) = self.read(cx, epoch, now) {
                return Poll::Ready(step);
            }
            if let Poll::Ready(step) = self.write(cx, epoch) {
                return Poll::Ready(step);
            }
        } else {
            if let Poll::Ready(step) = self.write(cx, epoch) {
                return Poll::Ready(step);
            }
            if let Poll::Ready(step) = self.read(cx, epoch, now) {
                return Poll::Ready(step);
            }
        }
        self.channel
            .poll_wait(cx, until)
            .map_ok(|()| Progress::WaitDeadline)
    }
    pub(super) async fn drive(&mut self, until: Option<Instant>) -> Result<Progress<'id>, Error> {
        poll_fn(|cx| {
            if self.yield_due { self.yield_due = false; cx.waker().wake_by_ref(); return Poll::Pending; }
            let step = self.poll_step(cx, until);
            let step = match step {
                Poll::Ready(Err(error)) if !self.closed => {
                    let cause = match error {
                        Error::Protocol(error) if matches!(error, ProtocolError::Capacity | ProtocolError::Overflow) => EndCause::Resource(error),
                        Error::Protocol(error) => EndCause::Protocol(error),
                        other => EndCause::Ports(other),
                    };
                    Poll::Ready(Ok(Progress::Ended(self.end(cause))))
                }
                other => other,
            };
            if matches!(&step, Poll::Ready(Ok(event)) if !matches!(event, Progress::Closed | Progress::WaitDeadline)) {
                self.yield_due = true;
            }
            step
        }).await
    }
}
