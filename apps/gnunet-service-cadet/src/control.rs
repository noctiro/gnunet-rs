//! Sticky process stop intent over one original shared native subscription.
use gnunet_service_startup::{StopError, StopSignals, StopSubscription};
use std::task::{Context, Poll};

pub(super) struct Signals {
    original: StopSignals,
    requested: bool,
}
impl Signals {
    pub(super) fn new(original: StopSignals) -> Self {
        Self {
            original,
            requested: false,
        }
    }
    pub(super) fn requested(&self) -> bool {
        self.requested
    }
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StopError>> {
        if self.requested {
            return Poll::Ready(Ok(()));
        }
        self.original.poll_stop(cx).map(|result| {
            if result.is_ok() {
                self.requested = true;
            }
            result
        })
    }
}
impl StopSubscription for Signals {
    fn poll_stop(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StopError>> {
        self.poll(cx)
    }
}
