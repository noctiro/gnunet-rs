//! One stop observation followed by pending teardown, over the original native source.
use gnunet_service_startup::{StopError, StopSignals, StopSubscription};
use std::task::{Context, Poll};
pub(crate) struct Control {
    original: StopSignals,
    stopped: bool,
}
impl Control {
    pub(crate) fn new(original: StopSignals) -> Self {
        Self {
            original,
            stopped: false,
        }
    }
    pub(crate) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StopError>> {
        if self.stopped {
            return Poll::Pending;
        }
        self.original.poll_stop(cx).map(|result| {
            self.stopped = true;
            result
        })
    }
}
impl StopSubscription for Control {
    fn poll_stop(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StopError>> {
        self.poll(cx)
    }
}
