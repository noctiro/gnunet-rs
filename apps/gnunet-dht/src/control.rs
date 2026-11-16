//! Shared PROGRAM stop latch, native signals and original parent receiver.
use crate::Cause;
use gnunet_program_host::reporting::Reporter;
use gnunet_service_startup::{ParentControl, StopSignals};
use std::{
    cell::Cell,
    rc::Rc,
    task::{Context, Poll},
};
pub(super) struct Control {
    signals: StopSignals,
    stop: Rc<Cell<bool>>,
    reporter: Reporter,
}
impl Control {
    pub(super) fn new(
        parent: Option<ParentControl>,
        stop: Rc<Cell<bool>>,
        reporter: Reporter,
    ) -> Result<Self, Cause> {
        Ok(Self {
            signals: StopSignals::for_client(parent)?,
            stop,
            reporter,
        })
    }
    pub(super) fn stopped(&self) -> bool {
        self.stop.get() || self.reporter.failed()
    }
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Cause>> {
        self.reporter.register(cx);
        if self.stopped() {
            return Poll::Ready(Ok(()));
        }
        if let Poll::Ready(result) = self.signals.poll_stop(cx) {
            self.stop.set(true);
            return Poll::Ready(result.map_err(|error| Box::new(error) as Cause));
        }
        Poll::Pending
    }
}
