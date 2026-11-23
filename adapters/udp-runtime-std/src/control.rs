//! Caller-defined cancellation without process signal ownership.

use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};

/// One original stop source for the communicator's startup and run loop.
pub trait Stop {
    /// Inspect an already observed or synchronously latched stop request.
    fn stopped(&self) -> bool;

    /// Poll the stop request and register the original caller task for wakeup.
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
}

pub(super) struct ApplicationStop<F> {
    shutdown: F,
    stopped: bool,
}

impl<F> ApplicationStop<F> {
    pub(super) fn new(shutdown: F) -> Self {
        Self {
            shutdown,
            stopped: false,
        }
    }
}

impl<F: Future<Output = io::Result<()>> + Unpin> Stop for ApplicationStop<F> {
    fn stopped(&self) -> bool {
        self.stopped
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.stopped {
            return Poll::Ready(Ok(()));
        }
        let result = Pin::new(&mut self.shutdown).poll(cx);
        self.stopped = result.is_ready();
        result
    }
}
