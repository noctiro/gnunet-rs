//! Original stop subscriptions, one readiness future and native entropy.
use super::Reports;
use crate::Failure;
use gnunet_service_startup::StopSignals;
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
/// One caller-owned asynchronous parent notification. Polling begins only after
/// real service readiness; waiting does not create another status submission.
pub struct Readiness(Pin<Box<dyn Future<Output = Result<(), Failure>>>>);
impl Readiness {
    /// Transfer the original notification future and its exclusively owned ports.
    pub fn new(future: impl Future<Output = Result<(), Failure>> + 'static) -> Self {
        Self(Box::pin(future))
    }
}
pub(crate) struct Signals {
    reports: Reports,
    reporting_stop: bool,
    native: StopSignals,
    ready: Option<Readiness>,
    deadline: Option<Pin<Box<Sleep>>>,
    ready_failed: bool,
}
impl Signals {
    pub(crate) fn new(native: StopSignals, ready: Option<Readiness>, reports: Reports) -> Self {
        Self {
            reports,
            reporting_stop: false,
            native,
            ready,
            deadline: None,
            ready_failed: false,
        }
    }
    pub(crate) fn reports(&self) -> Reports {
        self.reports.clone()
    }
    pub(crate) fn readiness_failed(&self) -> bool {
        self.ready_failed
    }
    pub(crate) fn finish_readiness(&self) -> Result<(), Failure> {
        if self.ready.is_some() {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "TRANSPORT stopped before original readiness acknowledgement",
            )
            .into())
        } else {
            Ok(())
        }
    }
    fn poll_readiness(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Failure>> {
        if !self.reports.ready_observed() || self.ready.is_none() {
            return Poll::Pending;
        }
        if self.deadline.is_none() {
            let hard = Instant::now()
                .checked_add(Duration::from_secs(10))
                .ok_or_else(|| io::Error::other("TRANSPORT readiness deadline overflow"))?;
            self.deadline = Some(Box::pin(tokio::time::sleep_until(hard)));
        }
        if self
            .deadline
            .as_mut()
            .is_some_and(|alarm| alarm.as_mut().poll(cx).is_ready())
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TRANSPORT readiness acknowledgement deadline",
            )
            .into()));
        }
        let Some(ready) = self.ready.as_mut() else {
            return Poll::Pending;
        };
        match ready.0.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => {
                self.ready = None;
                self.deadline = None;
                Poll::Pending
            }
            other => other,
        }
    }
    pub(crate) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Failure>> {
        self.reports.register(cx);
        if self.reports.failed() && !self.reporting_stop {
            self.reporting_stop = true;
            return Poll::Ready(Ok(()));
        }
        if let Poll::Ready(result) = self.native.poll_stop(cx) {
            return Poll::Ready(result.map_err(|cause| Box::new(cause) as Failure));
        }
        if self.reports.failed() {
            return Poll::Pending;
        }
        if self.ready_failed {
            return Poll::Ready(Err(io::Error::other(
                "TRANSPORT original readiness already failed",
            )
            .into()));
        }
        let result = self.poll_readiness(cx);
        if matches!(result, Poll::Ready(Err(_))) {
            self.ready_failed = true;
        }
        result
    }
}
pub(crate) struct Entropy;
impl Entropy {
    pub(crate) fn new() -> Self {
        Self
    }
}
impl gnunet_crypto::Entropy for Entropy {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), gnunet_types::Error> {
        gnunet_native::entropy::fill(bytes).map_err(|_| gnunet_types::Error::EntropyUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, rc::Rc};
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Original readiness must be gated, polled once and retain failure without replay"
    )]
    fn original_notification_waits_for_business_ready_and_failure_cannot_restart_it()
    -> Result<(), Failure> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let reports = Reports::new(|_| Ok(()));
            let polls = Rc::new(Cell::new(0));
            let count = polls.clone();
            let ready = Readiness::new(std::future::poll_fn(move |_| {
                count.set(count.get() + 1);
                Poll::Ready(Err(Box::new(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "original ready refusal",
                )) as Failure))
            }));
            let mut signals = Signals::new(StopSignals::new(None)?, Some(ready), reports.clone());
            let before = std::future::poll_fn(|cx| Poll::Ready(signals.poll(cx))).await;
            assert!(before.is_pending());
            assert_eq!(polls.get(), 0);
            assert!(signals.finish_readiness().is_err());
            reports.ready(gnunet_transport::PeerId([1; 32]));
            let failed = std::future::poll_fn(|cx| signals.poll(cx)).await;
            assert_eq!(
                failed
                    .err()
                    .and_then(|cause| cause.downcast::<io::Error>().ok())
                    .map(|cause| cause.kind()),
                Some(io::ErrorKind::PermissionDenied)
            );
            assert!(signals.readiness_failed());
            assert_eq!(polls.get(), 1);
            assert!(std::future::poll_fn(|cx| signals.poll(cx)).await.is_err());
            assert_eq!(polls.get(), 1);
            assert!(signals.finish_readiness().is_err());
            Ok(())
        })
    }
}
