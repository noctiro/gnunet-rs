//! Native stop subscriptions and the shared parent-control byte protocol.
use gnunet_service_runtime::signals::Termination;
use gnunet_service_startup::ControlReceiver;
use std::{
    io,
    task::{Context, Poll},
};
pub(super) struct Signals {
    parent: Option<ControlReceiver>,
    signals: Termination,
}
impl Signals {
    pub(super) fn new(parent: Option<ControlReceiver>) -> io::Result<Self> {
        Ok(Self {
            parent,
            signals: Termination::new()?,
        })
    }
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), crate::Cause>> {
        if let Some(parent) = &mut self.parent {
            match parent.poll_signal(cx) {
                Poll::Ready(Ok(Some(2 | 15))) => return Poll::Ready(Ok(())),
                Poll::Ready(Ok(Some(_))) => cx.waker().wake_by_ref(),
                Poll::Ready(Ok(None)) => self.parent = None,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(Box::new(error))),
                Poll::Pending => {}
            }
        }
        self.signals
            .poll_stop(cx)
            .map(|result| result.map_err(|error| Box::new(error) as crate::Cause))
    }
}
