//! Shared PROGRAM stop latch and original native/parent subscriptions.
use crate::reporting::Reporter;
use gnunet_service_startup::{ParentControl, StopError, StopSignals};
use std::{
    cell::Cell,
    rc::Rc,
    task::{Context, Poll},
};

/// One native/parent subscription tied to the original PROGRAM cancellation
/// latch and selected diagnostics. It creates no task or replacement receiver.
pub struct Stop {
    signals: StopSignals,
    stop: Rc<Cell<bool>>,
    reporter: Reporter,
}
impl Stop {
    /// Register within the caller's runtime, after fresh client startup capture.
    /// Parent registration failures retain their original native causes.
    pub fn new(
        parent: Option<ParentControl>,
        stop: Rc<Cell<bool>>,
        reporter: Reporter,
    ) -> Result<Self, gnunet_service_startup::ClientError> {
        Ok(Self {
            signals: StopSignals::for_client(parent)?,
            stop,
            reporter,
        })
    }
    /// Original scheduler cancellation or selected diagnostic failure.
    pub fn stopped(&self) -> bool {
        self.stop.get() || self.reporter.failed()
    }
    /// Poll the original subscriptions; every terminal result sets the same latch.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StopError>> {
        self.reporter.register(cx);
        if self.stopped() {
            self.stop.set(true);
            return Poll::Ready(Ok(()));
        }
        match self.signals.poll_stop(cx) {
            Poll::Ready(result) => {
                self.stop.set(true);
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
