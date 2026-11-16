//! Native stop observations for operations that must settle their own work.
use gnunet_service_runtime::signals::Termination;
use std::{
    error::Error,
    fmt, io,
    task::{Context, Poll},
};
type Cause = Box<dyn Error>;
pub(super) struct StopEvents {
    source: Termination,
    stopped: bool,
    failure: Option<io::Error>,
}
impl StopEvents {
    pub(super) fn new() -> io::Result<Self> {
        Ok(Self {
            source: Termination::new()?,
            stopped: false,
            failure: None,
        })
    }
    /// Latch the native event without abandoning the caller's original future.
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> bool {
        if !self.stopped
            && let Poll::Ready(result) = self.source.poll_stop(cx)
        {
            self.stopped = true;
            self.failure = result.err();
        }
        self.stopped
    }
    pub(super) fn take_failure(&mut self) -> Option<io::Error> {
        self.failure.take()
    }
    pub(super) fn failure(&self) -> Option<&io::Error> {
        self.failure.as_ref()
    }
    pub(super) fn finish(self, result: Result<(), Cause>) -> Result<(), Cause> {
        retain(result, self.failure)
    }
}
#[derive(Debug)]
struct StopFailure {
    original: Option<Cause>,
    native: io::Error,
}
impl fmt::Display for StopFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FS operation={:?}; independent stop source: {}",
            self.original, self.native
        )
    }
}
impl Error for StopFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original.as_deref().or(Some(&self.native))
    }
}
pub(super) fn retain(result: Result<(), Cause>, failure: Option<io::Error>) -> Result<(), Cause> {
    match failure {
        Some(native) => Err(Box::new(StopFailure {
            original: result.err(),
            native,
        })),
        None => result,
    }
}
