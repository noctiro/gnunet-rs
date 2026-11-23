//! Retire one original file off-reactor and report only observed native results.
use super::{Retirement, SourceEvent, Wfp, report, worker};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::time::Instant;

impl<'id> Wfp<'id> {
    pub fn close(&mut self) {
        if self.closing {
            return;
        }
        self.closing = true;
        self.ready = false;
        self.owner.close();
        if let Some(recovery) = self.recovery.take()
            && recovery
                .connector
                .as_ref()
                .is_some_and(super::connect::Connector::in_flight)
            && let Some(report) = &mut self.report
        {
            report.detached_open = true;
        }
        self.retire_file();
    }

    pub(super) fn retire_file(&mut self) {
        if self.retirement_until.is_some() {
            return;
        }
        let now = Instant::now();
        let until = now
            .checked_add(self.limits.retirement_timeout)
            .unwrap_or(now);
        self.retirement_until = Some(until);
        let submitted = self
            .output
            .as_ref()
            .is_some_and(|output| output.phase.is_submitted());
        if let Some(report) = &mut self.report {
            report.pending_packet = self
                .output
                .as_ref()
                .filter(|_| submitted)
                .map(|out| out.bytes);
        }
        self.wait = None;
        if let Some(original) = &self.reservations
            && let Some(started) = self.started.take()
        {
            let job = Box::new(worker::Job {
                file: started,
                reservations: Arc::clone(original),
                observe_reply: submitted,
                until,
            });
            match self.worker.submit(job) {
                Ok(receive) => self.retiring = Some(receive),
                Err(job) => {
                    // This worker cannot stop while its sender is live unless
                    // it failed. Retain original custody for final Drop.
                    self.started = Some(job.file);
                    if let Some(report) = &mut self.report {
                        report.retirement_worker_failed = true;
                    }
                }
            }
        }
    }

    pub fn take_retirement(&mut self) -> Option<Retirement> {
        if !self.closing || self.started.is_some() || self.retiring.is_some() {
            return None;
        }
        self.release_packet_owners();
        self.reservations = None;
        self.report.take().map(Retirement::Wfp)
    }

    pub(super) fn release_packet_owners(&mut self) {
        if let Some(output) = self.output.take() {
            self.retire_token(&output.endpoint.token);
        }
        for slot in &mut self.slots {
            if let Some(token) = slot.take() {
                token.retire();
            }
        }
    }

    pub(super) fn poll_retired_file(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Option<SourceEvent<'id>>>> {
        let Some(receive) = &mut self.retiring else {
            if self.started.is_some() {
                return Poll::Ready(Err(io::Error::other("WFP retirement worker unavailable")));
            }
            return Poll::Ready(Ok(None));
        };
        let result = match Pin::new(receive).poll(cx) {
            Poll::Ready(result) => result,
            Poll::Pending => {
                let now = Instant::now();
                let until = self.retirement_until.unwrap_or(now);
                if now < until {
                    self.timer.as_mut().reset(until);
                    if self.timer.as_mut().poll(cx).is_ready() {
                        cx.waker().wake_by_ref();
                    }
                    return Poll::Pending;
                }
                // The worker still owns the original file and socket lease,
                // even when the gateway must stop observing it.
                self.retiring = None;
                if let Some(report) = &mut self.report {
                    report.detached_retirement = true;
                }
                return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
            }
        };
        self.retiring = None;
        let receipt = match result {
            Ok(receipt) => receipt,
            Err(error) => {
                if let Some(report) = &mut self.report {
                    report.retirement_worker_failed = true;
                }
                return Poll::Ready(Err(io::Error::other(error)));
            }
        };
        if let Some(read_error) = receipt.read_error {
            self.record_error(read_error);
        }
        if let Some(report) = &mut self.report {
            report.stop_confirmed = receipt.stop.is_ok();
            report.stop_error = receipt.stop.err();
            report.file_closed = receipt.close.is_ok();
            report.file_close_error = receipt.close.err();
            report.wait_failed |= receipt.wait_error.is_some();
        }
        let completion = receipt
            .completion
            .map(|original| self.apply_completion(original))
            .transpose();
        if let Err(error) = receipt.close {
            return Poll::Ready(Err(report::device_error(error)));
        }
        if let Some(error) = receipt.wait_error {
            return Poll::Ready(Err(error));
        }
        if let Some(error) = receipt.read_error.filter(|error| !error.is_policy_loss()) {
            return Poll::Ready(Err(report::device_error(error)));
        }
        Poll::Ready(completion)
    }

    pub fn poll_retirement(&mut self, cx: &mut Context<'_>) -> Poll<Retirement> {
        if !self.closing || self.report.is_none() {
            return Poll::Pending;
        }
        if let Some(retired) = self.take_retirement() {
            return Poll::Ready(retired);
        }
        if self.poll_retired_file(cx).is_pending() {
            return Poll::Pending;
        }
        self.release_packet_owners();
        if self.started.is_none() {
            self.reservations = None;
        }
        self.report
            .take()
            .map_or(Poll::Pending, |report| Poll::Ready(Retirement::Wfp(report)))
    }
}

impl Drop for Wfp<'_> {
    fn drop(&mut self) {
        self.close();
    }
}
