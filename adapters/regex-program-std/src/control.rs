//! Original parent-control descriptor and actual installed Unix signals.
use gnunet_service_startup::{ControlReceiver, ParentControl};
use std::{
    io,
    task::{Context, Poll},
};
use tokio::signal::unix::{Signal, SignalKind, signal};
pub(crate) struct Control {
    parent: Option<ControlReceiver>,
    interrupt: Signal,
    terminate: Signal,
    stopped: bool,
}
impl Control {
    pub(crate) fn new(parent: Option<ParentControl>) -> io::Result<Self> {
        Ok(Self {
            parent: parent
                .map(|p| p.register().map_err(|e| e.error))
                .transpose()?,
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
            stopped: false,
        })
    }
    pub(crate) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.stopped {
            return Poll::Pending;
        }
        if let Some(parent) = &mut self.parent {
            match parent.poll_signal(cx) {
                Poll::Ready(Ok(Some(s)))
                    if i32::from(s) == SignalKind::interrupt().as_raw_value()
                        || i32::from(s) == SignalKind::terminate().as_raw_value() =>
                {
                    self.stopped = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(Some(_))) => cx.waker().wake_by_ref(),
                Poll::Ready(Ok(None)) => self.parent = None,
                Poll::Ready(Err(e)) => {
                    self.stopped = true;
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {}
            }
        }
        for port in [&mut self.interrupt, &mut self.terminate] {
            match port.poll_recv(cx) {
                Poll::Ready(Some(())) => {
                    self.stopped = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(None) => {
                    self.stopped = true;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "REGEX installed signal stream closed",
                    )));
                }
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }
}
