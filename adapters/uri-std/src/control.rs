//! Original process and parent-control notifications, never child-exit proofs.
use gnunet_service_startup::{ControlReceiver, ParentControl};
use std::{
    io,
    task::{Context, Poll},
};
use tokio::signal::unix::{Signal, SignalKind, signal};
#[derive(Clone, Copy, Debug)]
pub(crate) enum Wake {
    Stop(i32),
    Child,
}
pub(crate) struct Signals {
    parent: Option<ControlReceiver>,
    interrupt: Signal,
    terminate: Signal,
    child: Signal,
}
impl Signals {
    pub fn new(parent: Option<ParentControl>) -> io::Result<Self> {
        Ok(Self {
            parent: parent
                .map(|control| control.register().map_err(|failure| failure.error))
                .transpose()?,
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
            child: signal(SignalKind::child())?,
        })
    }
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Wake>> {
        if let Some(parent) = &mut self.parent {
            match parent.poll_signal(cx) {
                Poll::Ready(Ok(Some(value)))
                    if i32::from(value) == SignalKind::interrupt().as_raw_value()
                        || i32::from(value) == SignalKind::terminate().as_raw_value() =>
                {
                    return Poll::Ready(Ok(Wake::Stop(i32::from(value))));
                }
                Poll::Ready(Ok(Some(_))) => cx.waker().wake_by_ref(),
                Poll::Ready(Ok(None)) => self.parent = None,
                Poll::Ready(Err(cause)) => {
                    self.parent = None;
                    return Poll::Ready(Err(cause));
                }
                Poll::Pending => {}
            }
        }
        for (stream, code) in [
            (&mut self.interrupt, SignalKind::interrupt().as_raw_value()),
            (&mut self.terminate, SignalKind::terminate().as_raw_value()),
        ] {
            match stream.poll_recv(cx) {
                Poll::Ready(Some(())) => return Poll::Ready(Ok(Wake::Stop(code))),
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "original termination signal stream ended",
                    )));
                }
                Poll::Pending => {}
            }
        }
        match self.child.poll_recv(cx) {
            Poll::Ready(Some(())) => Poll::Ready(Ok(Wake::Child)),
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "original child signal stream ended",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}
