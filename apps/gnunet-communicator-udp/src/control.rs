//! Native stop events, original parent control and selected logger failure.
use crate::Cause;
use gnunet_program_host::reporting::Reporter;
use gnunet_service_startup::{ParentControl, StopSignals};
use std::{
    cell::Cell,
    io,
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
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.reporter.register(cx);
        if self.stopped() {
            self.stop.set(true);
            return Poll::Ready(Ok(()));
        }
        match self.signals.poll_stop(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.stop.set(true);
                Poll::Ready(result.map_err(io::Error::other))
            }
        }
    }
}
