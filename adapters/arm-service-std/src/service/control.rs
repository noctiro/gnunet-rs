//! Selected diagnostic stop and one shared original native stop subscription.
use super::{Failure, reporting::Reports};
use gnunet_service_startup::{ControlReceiver, StopSignals};
use std::task::{Context, Poll};
pub(super) struct Control {
    stop: StopSignals,
    diagnostic_stop: bool,
}
impl Control {
    pub(super) fn new(parent: Option<ControlReceiver>) -> Result<Self, Failure> {
        Ok(Self {
            stop: StopSignals::new(parent)?,
            diagnostic_stop: false,
        })
    }
    pub(super) fn poll(
        &mut self,
        cx: &mut Context<'_>,
        reports: &Reports<'_, '_>,
    ) -> Poll<Result<(), Failure>> {
        reports.register(cx);
        if reports.failed() && !self.diagnostic_stop {
            self.diagnostic_stop = true;
            return Poll::Ready(Ok(()));
        }
        self.stop
            .poll_stop(cx)
            .map_err(|error| Box::new(error) as Failure)
    }
}
