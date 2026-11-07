use super::{Error, Report, RevocationReport, revocation};
use crate::{Bounds, Close, Operation, Value};
use gnunet_types::{AbsoluteTime, Error as Fault};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::time::{Instant, Sleep};

pub(super) struct Query<'id> {
    client: revocation::Client<'id>,
    bounds: Bounds,
    alarm: Option<Pin<Box<Sleep>>>,
    report: Option<RevocationReport<'id>>,
    closing: bool,
    delivered: bool,
}
impl<'id> Query<'id> {
    pub(super) fn new(client: revocation::Client<'id>, bounds: Bounds) -> Self {
        let report = RevocationReport {
            job: Some(client.job()),
            submission: Some(client.submission()),
            ..RevocationReport::default()
        };
        Self {
            client,
            bounds,
            alarm: None,
            report: Some(report),
            closing: false,
            delivered: false,
        }
    }
    fn report_mut(&mut self) -> Result<&mut RevocationReport<'id>, Error<'id>> {
        self.report.as_mut().ok_or_else(|| Fault::Closed.into())
    }
    fn note_end(&mut self, end: &revocation::End<'id>) {
        if let Some(report) = &mut self.report {
            report.job = Some(end.job);
            report.epoch = end.epoch;
            report.submission = Some(end.submission);
            report.closed = true;
        }
    }
}
impl<'id> Operation for Query<'id> {
    type Error = Error<'id>;
    type Report = Report<'id>;
    fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<Self::Error> {
        if self.closing || self.report.as_ref().is_none_or(|report| report.closed) {
            return None;
        }
        let alarm = self
            .alarm
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(self.bounds.hard())));
        if Instant::now() >= self.bounds.hard() || alarm.as_mut().poll(cx).is_ready() {
            self.closing = true;
            if let Some(end) = self.client.cancel() {
                self.note_end(&end);
                if let Some(report) = &mut self.report {
                    report.native_end = Some(end);
                }
            }
            self.alarm = None;
            return Some(Fault::Timeout.into());
        }
        None
    }
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        _now: AbsoluteTime,
    ) -> Poll<Result<Value, Self::Error>> {
        if self.closing || self.delivered {
            return Poll::Pending;
        }
        if let Some(error) = self.poll_native_guard(cx) {
            return Poll::Ready(Err(error));
        }
        match self.client.poll(cx, Some(self.bounds.hard())) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                // This public method physically stops its original MQ on Err.
                if let Some(report) = &mut self.report {
                    report.closed = true;
                }
                self.delivered = true;
                Poll::Ready(Err(error.into()))
            }
            Poll::Ready(Ok(progress)) => {
                match progress {
                    revocation::Progress::Reply(reply) => {
                        self.delivered = true;
                        self.alarm = None;
                        let report = self.report_mut()?;
                        report.job = Some(reply.job);
                        report.epoch = Some(reply.epoch);
                        report.response = Some(reply.response);
                        report.closed = true; // public Reply follows actual MQ close
                        match reply.response.revoked() {
                            Some(revoked) => Poll::Ready(Ok(Value::Revocation(revoked))),
                            None => Poll::Ready(Err(Error::RevocationStatus(reply.response.raw()))),
                        }
                    }
                    revocation::Progress::Ended(end) => {
                        self.note_end(&end);
                        self.delivered = true;
                        self.alarm = None;
                        Poll::Ready(Err(Error::Revocation(end)))
                    }
                    revocation::Progress::Connected(epoch) => {
                        self.report_mut()?.epoch = Some(epoch);
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    revocation::Progress::Queued(job, epoch) => {
                        let report = self.report_mut()?;
                        report.job = Some(job);
                        report.epoch = Some(epoch);
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    revocation::Progress::Submitted(job, epoch) => {
                        let report = self.report_mut()?;
                        report.job = Some(job);
                        report.epoch = Some(epoch);
                        report.submission = Some(revocation::Submission::Written {
                            bytes: revocation::ipc::QUERY_BYTES,
                        });
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    revocation::Progress::Retry(error, _) => {
                        let report = self.report_mut()?;
                        report.connect_failures = report.connect_failures.saturating_add(1);
                        report.first_connect_error.get_or_insert(error);
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    revocation::Progress::Unavailable(error) => {
                        self.delivered = true;
                        Poll::Ready(Err(error.into()))
                    }
                    revocation::Progress::Closed => {
                        self.report_mut()?.closed = true;
                        self.delivered = true;
                        Poll::Ready(Err(Fault::Closed.into()))
                    }
                    revocation::Progress::Activity(_, _) => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    revocation::Progress::WaitDeadline => Poll::Pending,
                }
            }
        }
    }
    fn begin_close(&mut self) -> Option<Self::Error> {
        if !self.closing {
            self.closing = true;
            self.alarm = None;
            if let Some(end) = self.client.cancel() {
                self.note_end(&end);
                if let Some(report) = &mut self.report {
                    report.native_end = Some(end);
                }
            }
        }
        None
    }
    fn poll_close(&mut self, _cx: &mut Context<'_>) -> Poll<Close<Self::Report, Self::Error>> {
        if !self.closing {
            return Poll::Pending;
        }
        match self.report.take() {
            Some(report) if report.closed => Poll::Ready(Close::Closed(Report::Revocation(report))),
            Some(report) => {
                self.report = Some(report);
                Poll::Pending
            }
            None => Poll::Pending,
        }
    }
}
