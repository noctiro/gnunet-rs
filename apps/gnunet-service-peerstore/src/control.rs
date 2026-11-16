//! Registered native stop source; logging remains an independent stop reason.
use crate::{Failure, reporting::Reports};
use gnunet_service_startup::{ControlReceiver, StopSignals};
use std::task::{Context, Poll};
pub(crate) struct Control {
    native: StopSignals,
    diagnostic_stop: bool,
}
impl Control {
    pub(crate) fn new(parent: Option<ControlReceiver>) -> Result<Self, Failure> {
        Ok(Self {
            native: StopSignals::new(parent)?,
            diagnostic_stop: false,
        })
    }
    pub(crate) fn native(&mut self) -> &mut StopSignals {
        &mut self.native
    }
    pub(crate) fn poll(
        &mut self,
        cx: &mut Context<'_>,
        reports: &Reports,
    ) -> Poll<Result<(), Failure>> {
        reports.register(cx);
        if reports.failed() && !self.diagnostic_stop {
            self.diagnostic_stop = true;
            return Poll::Ready(Ok(()));
        }
        self.native
            .poll_stop(cx)
            .map(|result| result.map_err(|error| Box::new(error) as Failure))
    }
}
