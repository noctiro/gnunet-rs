//! Native stop sources and permanent PROGRAM/logger cancellation.
use gnunet_program_host::reporting::Reporter;
use gnunet_service_startup::{ParentControl, StopSignals};
use std::{
    cell::Cell,
    error::Error,
    io,
    rc::Rc,
    task::{Context, Poll},
};
pub(super) struct Control {
    native: StopSignals,
    stop: Rc<Cell<bool>>,
    reporter: Reporter,
}
impl Control {
    pub fn new(
        parent: Option<ParentControl>,
        stop: Rc<Cell<bool>>,
        reporter: Reporter,
    ) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            native: StopSignals::for_client(parent)?,
            stop,
            reporter,
        })
    }
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.reporter.register(cx);
        if self.reporter.failed() {
            self.stop.set(true);
            return Poll::Ready(Err(io::Error::other("selected DNS utility logger failed")));
        }
        if self.stop.get() {
            return Poll::Ready(Ok(()));
        }
        match self.native.poll_stop(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.stop.set(true);
                Poll::Ready(result.map_err(io::Error::other))
            }
        }
    }
}
