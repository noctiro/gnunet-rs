//! Original completion observations, independent of handle admission and wakeups.
use std::{
    fmt, io,
    sync::Mutex,
    task::{Context, Poll, Waker},
};

/// Native I/O completed, but its status could not be queried on the original handle.
#[derive(Debug)]
#[non_exhaustive]
pub struct CompletionStatusUnavailable {
    /// Original refusal to borrow the capture handle for its completion query.
    pub original: io::Error,
}
impl fmt::Display for CompletionStatusUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WinDivert completion status unavailable: {}",
            self.original
        )
    }
}
impl std::error::Error for CompletionStatusUnavailable {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}

enum Outcome {
    Pending,
    Ready(io::Result<u32>),
    Taken,
}
struct State {
    outcome: Outcome,
    waker: Option<Waker>,
}
pub(super) struct Notice(Mutex<State>);
impl Notice {
    pub fn new() -> Self {
        Self(Mutex::new(State {
            outcome: Outcome::Pending,
            waker: None,
        }))
    }

    pub fn pending(&self) -> bool {
        matches!(
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .outcome,
            Outcome::Pending
        )
    }

    /// Discard only the waiter. A callback may still publish its original result.
    pub fn detach_observer(&self) {
        let waker = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .waker
            .take();
        drop(waker);
    }

    /// The outer result records original-handle admission, while the inner
    /// result exists only when the native completion query actually ran.
    pub fn publish(&self, observation: io::Result<io::Result<u32>>) -> Option<Waker> {
        let outcome = observation.unwrap_or_else(|original| {
            Err(io::Error::new(
                original.kind(),
                CompletionStatusUnavailable { original },
            ))
        });
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.outcome = Outcome::Ready(outcome);
        state.waker.take()
    }

    pub fn poll(&self, cx: &mut Context<'_>) -> Poll<io::Result<u32>> {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match std::mem::replace(&mut state.outcome, Outcome::Taken) {
            Outcome::Pending => {
                state.outcome = Outcome::Pending;
                if state
                    .waker
                    .as_ref()
                    .is_none_or(|old| !old.will_wake(cx.waker()))
                {
                    state.waker = Some(cx.waker().clone());
                }
                Poll::Pending
            }
            Outcome::Ready(outcome) => Poll::Ready(outcome),
            Outcome::Taken => Poll::Ready(Err(io::Error::other(
                "WinDivert original result already consumed",
            ))),
        }
    }
}

#[cfg(test)]
#[path = "status/tests.rs"]
mod tests;
