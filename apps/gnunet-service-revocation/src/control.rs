use gnunet_service_startup::{ControlReceiver, ParentControl};
use std::{
    io,
    task::{Context, Poll},
};
use tokio::signal::unix::{Signal, SignalKind};
#[derive(Clone, Copy)]
pub(super) enum Stop {
    Signal,
    Diagnostic,
}
pub(super) struct Signals {
    parent: Option<ControlReceiver>,
    interrupt: Signal,
    terminate: Signal,
    reports: gnunet_program_host::reporting::Reporter,
    diagnostic_reported: bool,
}
impl Signals {
    pub(super) fn new(
        parent: Option<ParentControl>,
        reports: gnunet_program_host::reporting::Reporter,
    ) -> io::Result<Self> {
        Ok(Self {
            parent: parent
                .map(|control| control.register().map_err(|failure| failure.error))
                .transpose()?,
            interrupt: tokio::signal::unix::signal(SignalKind::interrupt())?,
            terminate: tokio::signal::unix::signal(SignalKind::terminate())?,
            reports,
            diagnostic_reported: false,
        })
    }
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Stop>> {
        self.reports.register(cx);
        if self.reports.failed() && !self.diagnostic_reported {
            self.diagnostic_reported = true;
            return Poll::Ready(Ok(Stop::Diagnostic));
        }
        if let Some(parent) = &mut self.parent {
            match parent.poll_signal(cx) {
                Poll::Ready(Ok(Some(signal)))
                    if i32::from(signal) == SignalKind::interrupt().as_raw_value()
                        || i32::from(signal) == SignalKind::terminate().as_raw_value() =>
                {
                    return Poll::Ready(Ok(Stop::Signal));
                }
                Poll::Ready(Ok(Some(_))) => cx.waker().wake_by_ref(),
                Poll::Ready(Ok(None)) => self.parent = None,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {}
            }
        }
        for signal in [&mut self.interrupt, &mut self.terminate] {
            match signal.poll_recv(cx) {
                Poll::Ready(Some(())) => {
                    return Poll::Ready(Ok(Stop::Signal));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "installed signal stream ended",
                    )));
                }
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }
}
