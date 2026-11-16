use gnunet_service_runtime::signals::Termination;
use gnunet_service_startup::{ControlReceiver, ParentControl};
use std::{
    io,
    task::{Context, Poll},
};
pub(crate) struct Signals {
    parent: Option<ControlReceiver>,
    termination: Termination,
}
impl Signals {
    pub(crate) fn new(parent: Option<ParentControl>) -> io::Result<Self> {
        Ok(Self {
            parent: parent.map(register).transpose()?,
            termination: Termination::new()?,
        })
    }
    pub(crate) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(parent) = &mut self.parent {
            match parent.poll_signal(cx) {
                Poll::Ready(Ok(Some(2 | 15))) => {
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(Some(_))) => cx.waker().wake_by_ref(),
                Poll::Ready(Ok(None)) => self.parent = None,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(control_error(error))),
                Poll::Pending => {}
            }
        }
        self.termination.poll_stop(cx)
    }
}
#[cfg(unix)]
fn control_error(error: io::Error) -> io::Error {
    error
}
#[cfg(windows)]
fn control_error(error: gnunet_service_runtime::pipe::PipeError) -> io::Error {
    io::Error::other(error)
}
#[cfg(unix)]
fn register(control: ParentControl) -> io::Result<ControlReceiver> {
    control.register().map_err(|failure| failure.error)
}
#[cfg(windows)]
fn register(control: ParentControl) -> io::Result<ControlReceiver> {
    // A PROGRAM consumes only its cooperative control direction. It never sends
    // a SERVICE readiness byte or claims listener acceptance.
    control.register().map(|parent| parent.control)
}
