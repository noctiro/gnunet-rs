//! Bounded local I/O; only the original completion settles an admitted reply.
use super::report::CompletionStop;
use super::{
    Endpoint, OriginalInput, PacketExposure, Phase, SourceEvent, StopRequest, Token, Wfp, Write,
    input, record, report,
};
use gnunet_service_runtime::framing::OwnedFrame;
use std::{
    future::Future,
    io,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::time::Instant;

fn notification_error(cx: &Context<'_>, result: Poll<io::Result<()>>) -> Option<io::Error> {
    match result {
        Poll::Pending => None,
        Poll::Ready(Ok(())) => {
            // The shared auto-reset event can be raised after the completion
            // probe. Schedule a fresh probe and let other work run this turn.
            cx.waker().wake_by_ref();
            None
        }
        Poll::Ready(Err(error)) => Some(error),
    }
}

impl<'id> Wfp<'id> {
    pub(super) fn completion(&mut self) -> io::Result<Option<SourceEvent<'id>>> {
        let Some(started) = &mut self.started else {
            return Ok(None);
        };
        let completion = match started.read_completion() {
            Ok(Some(completion)) => completion,
            Ok(None) => return Ok(None),
            Err(error) => {
                self.record_error(error);
                return Err(report::device_error(error));
            }
        };
        self.apply_completion(completion).map(Some)
    }

    pub(super) fn apply_completion(
        &mut self,
        completion: record::Completion,
    ) -> io::Result<SourceEvent<'id>> {
        if let Some(report) = &mut self.report {
            report.last_completion = Some(completion);
        }
        if !self.output.as_ref().is_some_and(|output| {
            output.phase.is_submitted() && output.endpoint.token.request == completion.request
        }) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "WFP completion lost its original submitted request",
            ));
        }
        let Some(output) = self.output.take() else {
            return Err(io::ErrorKind::InvalidData.into());
        };
        self.retire_token(&output.endpoint.token);
        if let Some(report) = &mut self.report {
            report.pending_packet = None;
        }
        let stop = if let Some(reason) = output.phase.stop_request() {
            Some(CompletionStop::Requested(reason))
        } else if self.closing {
            Some(CompletionStop::Closing)
        } else if let Some(recovery) = &self.recovery {
            Some(CompletionStop::SourceLost(recovery.reason))
        } else if Instant::now() >= output.until {
            Some(CompletionStop::Requested(StopRequest::Deadline))
        } else {
            None
        };
        if stop.is_none() && completion.status >= 0 && completion.authorized {
            return Ok(SourceEvent::Written {
                effect: output.effect,
                observation: Write::Wfp {
                    bytes: output.bytes,
                    native_status: completion.status,
                    authorized: completion.authorized,
                },
            });
        }
        Ok(SourceEvent::OutputStopped {
            effect: output.effect,
            exposure: PacketExposure::WfpCompleted {
                native_status: completion.status,
                authorized: completion.authorized,
            },
            total: output.bytes,
            reason: report::CompletionFailure {
                completion,
                stop,
                cancel_error: output.phase.cancellation_error(),
            }
            .into_io()
            .into(),
        })
    }

    pub(super) fn record_error(&mut self, error: gnunet_wfp_dns_host::device::Error) {
        if let Some(report) = &mut self.report
            && report.device_error.is_none()
        {
            report.device_error = Some(error);
        }
    }

    fn record_write_error(&mut self, error: gnunet_wfp_dns_host::device::Error) {
        if error.is_write_not_ready() {
            self.begin_recovery(error);
        } else {
            self.record_error(error);
        }
    }

    fn discard_abandoned(&mut self) -> Option<SourceEvent<'id>> {
        // Retain this exact token while removing its source slot after I/O.
        let token = self
            .slots
            .iter()
            .flatten()
            .find(|token| token.abandoned())
            .cloned()?;
        let Some(started) = &mut self.started else {
            return Some(SourceEvent::Failed(io::ErrorKind::NotConnected.into()));
        };
        let result = started.write(
            record::Reply::Discard(token.request),
            &mut self.write_buffer,
        );
        self.retire_token(&token);
        Some(match result {
            Ok(()) => SourceEvent::Activity,
            Err(error) => {
                self.record_write_error(error);
                SourceEvent::Refused(report::device_error(error).into())
            }
        })
    }

    fn queued(&mut self) -> Option<SourceEvent<'id>> {
        let output = self.output.as_ref()?;
        let stop = match &output.phase {
            Phase::DiscardQueued(reason) => Some(*reason),
            Phase::Queued(_) if Instant::now() >= output.until => Some(StopRequest::Deadline),
            Phase::Queued(_) => None,
            _ => return None,
        };
        if let Some(stop) = stop {
            let output = self.output.take()?;
            let Some(started) = &mut self.started else {
                return Some(SourceEvent::Failed(io::ErrorKind::NotConnected.into()));
            };
            let result = started.write(
                record::Reply::Discard(output.endpoint.token.request),
                &mut self.write_buffer,
            );
            self.retire_token(&output.endpoint.token);
            let reason = match result {
                Ok(()) => stop.fault().into(),
                Err(error) => {
                    self.record_write_error(error);
                    io::Error::other(report::DiscardFailure { stop, error }).into()
                }
            };
            return Some(SourceEvent::OutputStopped {
                effect: output.effect,
                exposure: PacketExposure::UnsubmittedPacket,
                total: output.bytes,
                reason,
            });
        }
        let output = self.output.as_mut()?;
        // Publish submission ownership before the synchronous command: its real
        // completion can already be queued when WriteFile returns.
        let Phase::Queued(frame) = std::mem::replace(&mut output.phase, Phase::Submitted) else {
            return None;
        };
        output.endpoint.token.submitted();
        let Some(started) = &mut self.started else {
            return Some(SourceEvent::Failed(io::ErrorKind::NotConnected.into()));
        };
        let result = started.write(
            record::Reply::Datagram(output.endpoint.token.request, frame.bytes()),
            &mut self.write_buffer,
        );
        Some(match result {
            Ok(()) => SourceEvent::Activity,
            Err(error) => {
                // No replay and no synthetic completion on an ambiguous local
                // command failure. STOP/retirement keeps the original facts.
                self.record_write_error(error);
                SourceEvent::Failed(report::device_error(error))
            }
        })
    }

    fn cancellation(&mut self) -> Option<SourceEvent<'id>> {
        let output = self.output.as_mut()?;
        let now = Instant::now();
        if now >= output.until {
            output.phase.request_cancel(
                StopRequest::Deadline,
                output.until,
                now,
                self.limits.retirement_timeout,
            );
        }
        match output.phase.begin_cancel(now) {
            Ok(true) => {}
            Ok(false) => return None,
            Err(error) => return Some(SourceEvent::Failed(error)),
        }
        let Some(started) = &mut self.started else {
            return Some(SourceEvent::Failed(io::ErrorKind::NotConnected.into()));
        };
        let result = started.write(
            record::Reply::Discard(output.endpoint.token.request),
            &mut self.write_buffer,
        );
        // Discard revokes pending receive authority, but retains original native
        // debt and any actual earlier authorization. Only completion settles it.
        if let Err(error) = result {
            if let Phase::Cancelling {
                error: cancel_error,
                ..
            } = &mut output.phase
            {
                *cancel_error = Some(error);
            }
            self.record_write_error(error);
            return Some(SourceEvent::Refused(report::device_error(error).into()));
        }
        Some(SourceEvent::Activity)
    }

    pub(super) fn wait(&mut self, cx: &mut Context<'_>) -> Poll<SourceEvent<'id>> {
        let Some(wait) = &mut self.wait else {
            return Poll::Pending;
        };
        let result = wait.poll_ready(cx);
        let Some(error) = notification_error(cx, result) else {
            return Poll::Pending;
        };
        self.wait = None;
        if let Some(report) = &mut self.report {
            report.wait_failed = true;
        }
        Poll::Ready(SourceEvent::Failed(error))
    }

    pub fn poll_guard(&mut self, cx: &mut Context<'_>) -> Poll<SourceEvent<'id>> {
        if self.closing {
            return self.poll_retirement(cx).map(SourceEvent::Retired);
        }
        if self.recovery.is_some() {
            return self.poll_recovery(cx);
        }
        self.owner.register(cx);
        match self.completion() {
            Ok(Some(event)) => return Poll::Ready(event),
            Err(error) => {
                if let Some(reason) = super::recovery::source_unavailable(&error) {
                    self.begin_recovery(reason);
                    return self.poll_recovery(cx);
                }
                return Poll::Ready(SourceEvent::Failed(error));
            }
            Ok(None) => {}
        }
        if let Some(event) = self
            .cancellation()
            .or_else(|| self.queued())
            .or_else(|| self.discard_abandoned())
        {
            // A locally retired queued packet still needs its exact terminal
            // event. Suspension follows on the next poll before any more I/O.
            if self.recovery.is_some() && !matches!(event, SourceEvent::OutputStopped { .. }) {
                return self.poll_recovery(cx);
            }
            return Poll::Ready(event);
        }
        if let Some(output) = &self.output {
            let deadline = output.phase.cancellation_deadline().unwrap_or(output.until);
            self.timer.as_mut().reset(deadline);
            if self.timer.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
        self.wait(cx)
    }

    pub fn poll(&mut self, cx: &mut Context<'_>, admit: bool) -> Poll<SourceEvent<'id>> {
        if let ready @ Poll::Ready(_) = self.poll_guard(cx) {
            return ready;
        }
        if self.closing || !self.initialized() || !admit {
            return Poll::Pending;
        }
        let Some(index) = self.slots.iter().position(Option::is_none) else {
            return Poll::Pending;
        };
        let Some(started) = &mut self.started else {
            return Poll::Ready(SourceEvent::Failed(io::ErrorKind::NotConnected.into()));
        };
        let query = match started.read_query(&mut self.read_buffer) {
            Ok(Some(query)) => query,
            Ok(None) => return Poll::Pending,
            Err(error) => {
                self.record_error(error);
                if error.is_policy_loss() {
                    self.begin_recovery(error);
                    return self.poll_recovery(cx);
                }
                return Poll::Ready(SourceEvent::Failed(report::device_error(error)));
            }
        };
        let request = query.request;
        if self
            .slots
            .iter()
            .flatten()
            .any(|token| token.request == request)
        {
            return Poll::Ready(SourceEvent::Failed(io::Error::new(
                io::ErrorKind::InvalidData,
                "WFP device repeated a live original request token",
            )));
        }
        let frame = OwnedFrame::copy_from(query.dns);
        let token = Token::new(request, index, Arc::clone(&self.owner));
        self.slots[index] = Some(Arc::clone(&token));
        let endpoint = Endpoint::new(token);
        Poll::Ready(SourceEvent::Input(match frame {
            Ok(frame) => {
                let bytes = frame.len();
                Ok(OriginalInput::checked(
                    frame,
                    0..bytes,
                    input::ReplyOwner::Wfp(endpoint),
                ))
            }
            Err(error) => {
                drop(endpoint);
                Err(error.into())
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        task::{Wake, Waker},
        time::Duration,
    };

    #[derive(Default)]
    struct Wakes(AtomicUsize);

    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn shared_notification_only_reschedules_original_work() {
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let cx = Context::from_waker(&waker);

        assert!(notification_error(&cx, Poll::Pending).is_none());
        assert_eq!(wakes.0.load(Ordering::Relaxed), 0);
        assert!(notification_error(&cx, Poll::Ready(Ok(()))).is_none());
        assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
        let error = io::Error::from_raw_os_error(6);
        assert_eq!(
            notification_error(&cx, Poll::Ready(Err(error))).and_then(|error| error.raw_os_error()),
            Some(6)
        );
        assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn queued_discard_keeps_the_first_stop_reason() {
        let now = Instant::now();
        let grace = Duration::from_secs(5);
        let hard = now + Duration::from_secs(10);
        let mut cancelled = Phase::Queued(OwnedFrame::new(Vec::new()));
        cancelled.request_cancel(StopRequest::Cancelled, hard, now, grace);
        cancelled.request_cancel(StopRequest::Deadline, hard, hard, grace);
        assert_eq!(cancelled.stop_request(), Some(StopRequest::Cancelled));
        assert!(!cancelled.is_submitted());

        let mut expired = Phase::Queued(OwnedFrame::new(Vec::new()));
        expired.request_cancel(StopRequest::Deadline, hard, hard, grace);
        assert_eq!(expired.stop_request(), Some(StopRequest::Deadline));
        assert!(!expired.is_submitted());
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions check submitted reply and cancellation deadlines while native setup errors propagate"
    )]
    fn submitted_reply_cancels_once_and_keeps_its_first_deadline() -> io::Result<()> {
        let now = Instant::now();
        let grace = Duration::from_secs(5);
        let hard = now + Duration::from_secs(10);
        let mut phase = Phase::Submitted;
        phase.request_cancel(StopRequest::Cancelled, hard, now, grace);
        assert!(phase.is_submitted());
        assert_eq!(phase.cancellation_deadline(), Some(now + grace));
        assert!(phase.begin_cancel(now)?);

        let again = now + Duration::from_secs(1);
        phase.request_cancel(StopRequest::Deadline, hard, again, grace);
        assert_eq!(phase.stop_request(), Some(StopRequest::Cancelled));
        assert!(!phase.begin_cancel(again)?);
        assert_eq!(phase.cancellation_deadline(), Some(now + grace));
        assert!(matches!(
            phase.begin_cancel(now + grace),
            Err(error) if error.kind() == io::ErrorKind::TimedOut
        ));
        assert!(phase.is_submitted());
        Ok(())
    }

    #[test]
    fn delayed_expiry_cannot_extend_the_original_reply_bound() {
        let hard = Instant::now();
        let grace = Duration::from_secs(5);
        let late = hard + grace;
        let mut phase = Phase::Submitted;
        phase.request_cancel(StopRequest::Deadline, hard, late, grace);
        assert_eq!(phase.stop_request(), Some(StopRequest::Deadline));
        assert_eq!(phase.cancellation_deadline(), Some(late));
        assert!(matches!(
            phase.begin_cancel(late),
            Err(error) if error.kind() == io::ErrorKind::TimedOut
        ));
        assert!(phase.is_submitted());
    }
}
