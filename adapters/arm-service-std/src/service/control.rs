//! Real original parent control and owned process signals, no polling thread.
use super::{Failure, reporting::Reports};
use gnunet_service_startup::{ControlReceiver, ParentControl};
use std::task::{Context, Poll};
use tokio::signal::unix::{Signal, SignalKind};
pub(super) struct Control {
    parent: Option<ControlReceiver>,
    interrupt: Signal,
    terminate: Signal,
    diagnostic_stop: bool,
}
impl Control {
    pub(super) fn new(parent: Option<ParentControl>) -> Result<Self, Failure> {
        Ok(Self {
            parent: parent
                .map(|p| p.register().map_err(|e| e.error))
                .transpose()?,
            interrupt: tokio::signal::unix::signal(SignalKind::interrupt())?,
            terminate: tokio::signal::unix::signal(SignalKind::terminate())?,
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
                Poll::Ready(Err(e)) => return Poll::Ready(Err(Box::new(e))),
                Poll::Pending => {}
            }
        }
        for signal in [&mut self.interrupt, &mut self.terminate] {
            match signal.poll_recv(cx) {
                Poll::Ready(Some(())) => return Poll::Ready(Ok(())),
                Poll::Ready(None) => return Poll::Ready(Err("ARM signal stream ended".into())),
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }
}
