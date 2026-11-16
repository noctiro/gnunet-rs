//! Same original native stop source and selected-diagnostic stop reason.
use gnunet_program_host::reporting::Reporter;
use gnunet_service_startup::{ControlReceiver, StopError, StopSignals};
use std::{
    io,
    task::{Context, Poll},
};
#[derive(Clone, Copy)]
pub(super) enum Stop {
    Signal,
    Diagnostic,
}
pub(super) struct Signals {
    native: StopSignals,
    reports: Reporter,
    diagnostic_reported: bool,
}
impl Signals {
    pub(super) fn new(parent: Option<ControlReceiver>, reports: Reporter) -> io::Result<Self> {
        Ok(Self {
            native: StopSignals::new(parent)?,
            reports,
            diagnostic_reported: false,
        })
    }
    pub(super) fn native(&mut self) -> &mut StopSignals {
        &mut self.native
    }
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Stop, StopError>> {
        self.reports.register(cx);
        if self.reports.failed() && !self.diagnostic_reported {
            self.diagnostic_reported = true;
            return Poll::Ready(Ok(Stop::Diagnostic));
        }
        self.native
            .poll_stop(cx)
            .map(|result| result.map(|()| Stop::Signal))
    }
}
