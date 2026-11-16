//! Shared native termination and the same PROGRAM stop/diagnostic latch.
use crate::Cause;
use gnunet_program_host::reporting::Reporter;
use gnunet_service_startup::{ParentControl, StopError, StopSignals};
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
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StopError>> {
        self.reporter.register(cx);
        if self.stop.get() || self.reporter.failed() {
            return Poll::Ready(Ok(()));
        }
        let result = self.signals.poll_stop(cx);
        if result.is_ready() {
            self.stop.set(true);
        }
        result
    }
}
