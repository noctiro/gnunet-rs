//! One original parent-control stream plus native termination subscriptions.
use crate::ControlReceiver;
use gnunet_service_runtime::signals::Termination;
use std::{
    fmt, io,
    task::{Context, Poll},
};

#[cfg(unix)]
type ParentError = io::Error;
#[cfg(windows)]
type ParentError = gnunet_service_runtime::pipe::PipeError;

#[derive(Debug)]
enum Cause {
    Parent(ParentError),
    Native(io::Error),
}

/// Original stop-subscription or parent-control read failure.
#[derive(Debug)]
pub struct StopError {
    cause: Cause,
}

/// Caller-polled stop observation. Wrappers may retain application cancellation
/// state while delegating the original native subscription and error unchanged.
/// A successful stop requests local cancellation; it grants no peer or process
/// identity, termination receipt or permission to replace an original source.
pub trait StopSubscription {
    /// Observe one stop request or original subscription failure.
    fn poll_stop(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StopError>>;
}
impl fmt::Display for StopError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.cause {
            Cause::Parent(error) => write!(out, "parent control: {error}"),
            Cause::Native(error) => write!(out, "native stop subscription: {error}"),
        }
    }
}
impl std::error::Error for StopError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match &self.cause {
            Cause::Parent(error) => error,
            Cause::Native(error) => error,
        })
    }
}

/// Caller-driven termination observation. Construction registers native streams
/// within the caller's current runtime; no polling task or runtime is created.
/// Parent EOF releases only that stream and does not fabricate a stop signal.
pub struct StopSignals {
    parent: Option<ControlReceiver>,
    native: Termination,
}
impl StopSubscription for StopSignals {
    fn poll_stop(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StopError>> {
        StopSignals::poll_stop(self, cx)
    }
}
impl StopSignals {
    /// Register native subscriptions and retain the original parent receiver.
    /// Console detachment must precede this call on Windows.
    pub fn new(parent: Option<ControlReceiver>) -> io::Result<Self> {
        Ok(Self {
            parent,
            native: Termination::new()?,
        })
    }

    /// Observe Unix interrupt/terminate or Windows console termination, plus
    /// the official parent-control interrupt/terminate bytes (2 and 15). Other
    /// parent bytes consume one bounded turn and schedule another observation.
    /// Every actual stop is returned separately so callers own grace policy.
    pub fn poll_stop(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StopError>> {
        if let Some(parent) = &mut self.parent {
            match parent.poll_signal(cx) {
                Poll::Ready(Ok(Some(2 | 15))) => return Poll::Ready(Ok(())),
                Poll::Ready(Ok(Some(_))) => cx.waker().wake_by_ref(),
                Poll::Ready(Ok(None)) => self.parent = None,
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Err(StopError {
                        cause: Cause::Parent(error),
                    }));
                }
                Poll::Pending => {}
            }
        }
        self.native.poll_stop(cx).map(|result| {
            result.map_err(|error| StopError {
                cause: Cause::Native(error),
            })
        })
    }
}
