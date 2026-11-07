//! Native polling and one earliest original clock deadline; metadata lives above.
use super::Client;
use crate::{Cause, Command, Error, Step, Submission};
use gnunet_client_host::channel::ConnectionStep;
use gnunet_service_runtime::{clock::Deadline, framing::ReadStep};
use gnunet_types::Error as ProtocolError;
use std::{
    future::{Future, poll_fn},
    task::{Context, Poll},
};
use tokio::time::Instant;
impl<'id> Client<'id> {
    fn read(&mut self, cx: &mut Context<'_>) -> Poll<Result<Step<'id>, Error>> {
        match self
            .channel
            .framing_mut()
            .ok_or(ProtocolError::NotReady)?
            .poll_read(cx)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Ok(self.retire(Cause::Io(e)))),
            Poll::Ready(Ok(ReadStep::Eof)) => Poll::Ready(Ok(self.retire(Cause::Eof))),
            Poll::Ready(Ok(ReadStep::Progress { bytes, complete })) => {
                self.read_first = false;
                if complete {
                    Poll::Ready(self.dispatch())
                } else {
                    Poll::Ready(Ok(Step::Activity(bytes, 0)))
                }
            }
        }
    }
    fn write(&mut self, cx: &mut Context<'_>) -> Poll<Result<Step<'id>, Error>> {
        let progress = match self
            .channel
            .framing_mut()
            .ok_or(ProtocolError::NotReady)?
            .poll_write(cx)
        {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Ok(self.retire(Cause::Io(e)))),
            Poll::Ready(Ok(p)) => p,
        };
        let original = progress.origin;
        let index = original.operation.map(|op| self.index(op)).transpose()?;
        if let Some(index) = index {
            let s = self.operations[index]
                .as_mut()
                .ok_or(ProtocolError::Stale)?;
            s.exposed |= progress.bytes > 0;
        }
        self.read_first = true;
        if !progress.complete {
            return Poll::Ready(Ok(Step::Activity(0, progress.bytes)));
        }
        let position = self
            .writes
            .iter()
            .position(|q| q.origin.write == original.write)
            .ok_or(ProtocolError::Stale)?;
        self.writes.remove(position).ok_or(ProtocolError::Stale)?;
        if matches!(original.command, Command::Create | Command::Listen) {
            self.initialized = true;
        }
        if let Some(index) = index {
            let s = self.operations[index]
                .as_mut()
                .ok_or(ProtocolError::Stale)?;
            s.pending = s.pending.checked_sub(1).ok_or(ProtocolError::Stale)?;
            if original.command == Command::Cancel {
                let reason = s.reason.ok_or(ProtocolError::Stale)?;
                self.finish(index, reason, Submission::CancelSubmitted)?;
            } else {
                s.started = true;
                s.incoming = None;
            }
        }
        Poll::Ready(Ok(Step::Written(
            original.epoch,
            original.write,
            original.command,
        )))
    }
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<Instant>,
    ) -> Poll<Result<Step<'id>, Error>> {
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(Ok(event));
        }
        if self.closed {
            return Poll::Ready(Ok(Step::Closed));
        }
        if wait.is_some_and(|at| Instant::now() >= at) {
            return Poll::Ready(Ok(Step::WaitDeadline));
        }
        match self.channel.poll_clock(cx) {
            // The caller's fixed native observation target remains live even
            // while the canonical clock is waiting for a consistent revision.
            Poll::Pending => {
                return self
                    .channel
                    .poll_wait(cx, wait)
                    .map_ok(|()| Step::WaitDeadline);
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Ok(self.retire(Cause::Ports(e)))),
            Poll::Ready(Ok(())) => {}
        }
        let now = self.clock.sample()?.now.as_micros();
        if let Some(step) = self.expire(now)? {
            return Poll::Ready(Ok(step));
        }
        if let Some(target) = self.target() {
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
                .ok_or(ProtocolError::Stale)?
                .as_mut()
                .poll(cx)
            {
                Poll::Ready(result) => {
                    result?;
                    self.alarm = None;
                    self.alarm_at = None;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Pending => {}
            }
        } else {
            self.alarm = None;
            self.alarm_at = None;
        }
        if self.epoch.is_none() {
            match self.channel.poll_connect(cx) {
                Poll::Pending => {
                    return self
                        .channel
                        .poll_wait(cx, wait)
                        .map_ok(|()| Step::WaitDeadline);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Ok(self.retire(Cause::Ports(e)))),
                Poll::Ready(Ok(ConnectionStep::Retry { error, retry_after })) => {
                    return Poll::Ready(Ok(Step::Retry(error, retry_after)));
                }
                Poll::Ready(Ok(ConnectionStep::Unavailable(e))) => {
                    return Poll::Ready(Ok(self.retire(Cause::Ports(e))));
                }
                Poll::Ready(Ok(ConnectionStep::Attached)) => {
                    let epoch = self.scope.epoch()?;
                    self.epoch = Some(epoch);
                    self.source.set(epoch.diagnostic());
                    return Poll::Ready(Ok(Step::Connected(epoch)));
                }
            }
        }
        match self.prepare(now) {
            Ok(()) | Err(Error::Protocol(ProtocolError::WouldBlock)) => {}
            Err(e) => return Poll::Ready(Err(e)),
        }
        if self.channel.framing().is_some_and(|f| f.frame().is_some()) {
            return match self.dispatch()? {
                Step::Capacity => match self.write(cx) {
                    Poll::Ready(step) => Poll::Ready(step),
                    Poll::Pending => Poll::Ready(Ok(Step::Capacity)),
                },
                step => Poll::Ready(Ok(step)),
            };
        }
        if self.read_first {
            if let Poll::Ready(step) = self.read(cx) {
                return Poll::Ready(step);
            }
            if let Poll::Ready(step) = self.write(cx) {
                return Poll::Ready(step);
            }
        } else {
            if let Poll::Ready(step) = self.write(cx) {
                return Poll::Ready(step);
            }
            if let Poll::Ready(step) = self.read(cx) {
                return Poll::Ready(step);
            }
        }
        self.channel
            .poll_wait(cx, wait)
            .map_ok(|()| Step::WaitDeadline)
    }
    /// Drive one bounded original source action. Dropping this future preserves
    /// actual cursors/partial frames. Any clock/internal protocol error physically
    /// closes first, then retains local ends before returning the original error.
    pub async fn drive(&mut self, wait: Option<Instant>) -> Result<Step<'id>, Error> {
        poll_fn(|cx| {
            if self.yield_due {
                self.yield_due = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let step = self.poll(cx, wait);
            match &step {
                Poll::Ready(Err(_)) => {
                    let _lost = self.retire(Cause::Protocol(ProtocolError::Unavailable));
                }
                Poll::Ready(Ok(Step::Closed | Step::WaitDeadline | Step::Capacity)) => {}
                Poll::Ready(Ok(_)) => self.yield_due = true,
                Poll::Pending => {}
            }
            step
        })
        .await
    }
}
