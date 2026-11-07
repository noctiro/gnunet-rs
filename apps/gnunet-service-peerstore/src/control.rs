//! Original signal/control ownership, plus an actual diagnostic-stop request.
use crate::{Failure, reporting::Reports};
use gnunet_service_startup::{ControlReceiver, ParentControl};
use std::task::{Context, Poll};
use tokio::signal::unix::{Signal, SignalKind};
pub(crate) struct Control {
    parent: Option<ControlReceiver>,
    interrupt: Signal,
    terminate: Signal,
    diagnostic_stop: bool,
}
impl Control {
    pub(crate) fn new(parent: Option<ParentControl>) -> Result<Self, Failure> {
        Ok(Self {
            parent: parent
                .map(|p| p.register().map_err(|error| error.error))
                .transpose()?,
            interrupt: tokio::signal::unix::signal(SignalKind::interrupt())?,
            terminate: tokio::signal::unix::signal(SignalKind::terminate())?,
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
                Poll::Ready(Ok(Some(signal)))
                    if i32::from(signal) == SignalKind::interrupt().as_raw_value()
                        || i32::from(signal) == SignalKind::terminate().as_raw_value() =>
                {
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(Some(_))) => cx.waker().wake_by_ref(),
                Poll::Ready(Ok(None)) => self.parent = None,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(Box::new(error))),
                Poll::Pending => {}
            }
        }
        for signal in [&mut self.interrupt, &mut self.terminate] {
            match signal.poll_recv(cx) {
                Poll::Ready(Some(())) => return Poll::Ready(Ok(())),
                Poll::Ready(None) => {
                    return Poll::Ready(Err("PEERSTORE signal stream ended".into()));
                }
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }
}
