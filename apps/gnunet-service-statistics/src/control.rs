//! Original signal/control ownership, plus an actual diagnostic-stop request.
use crate::{Failure, reporting::Reports};
use gnunet_service_runtime::signals::Termination;
use gnunet_service_startup::ControlReceiver;
use std::task::{Context, Poll};
pub(crate) struct Control {
    parent: Option<ControlReceiver>,
    signals: Termination,
    diagnostic_stop: bool,
}
impl Control {
    pub(crate) fn new(parent: Option<ControlReceiver>) -> Result<Self, Failure> {
        Ok(Self {
            parent,
            signals: Termination::new()?,
            diagnostic_stop: false,
        })
    }
    pub(crate) fn poll(
        &mut self,
        cx: &mut Context<'_>,
        reports: &Reports<'_, '_>,
    ) -> Poll<Result<(), Failure>> {
        reports.register(cx);
        if reports.failed() && !self.diagnostic_stop {
            self.diagnostic_stop = true;
            return Poll::Ready(Ok(()));
        }
        if let Some(parent) = &mut self.parent {
            match parent.poll_signal(cx) {
                Poll::Ready(Ok(Some(2 | 15))) => {
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(Some(_))) => cx.waker().wake_by_ref(),
                Poll::Ready(Ok(None)) => self.parent = None,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(Box::new(error))),
                Poll::Pending => {}
            }
        }
        self.signals
            .poll_stop(cx)
            .map(|result| result.map_err(|error| Box::new(error) as Failure))
    }
}
