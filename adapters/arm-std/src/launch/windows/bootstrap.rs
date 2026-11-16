//! Unique bootstrap driver with immutable, independently owned observation.
use gnunet_service_startup::{ParentFailure, launch};
use std::{
    io,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
};
type Outcome = Result<(), Arc<ParentFailure>>;
pub(super) struct Prepared(Arc<OnceLock<Outcome>>);
impl Prepared {
    pub(super) fn new() -> Self {
        Self(Arc::new(OnceLock::new()))
    }
    pub(super) fn finish(self, parent: launch::Parent) -> (Pending, StartupSignal) {
        let observation = StartupSignal(self.0.clone());
        (
            Pending {
                parent,
                outcome: self.0,
            },
            observation,
        )
    }
}
pub(super) struct Pending {
    parent: launch::Parent,
    outcome: Arc<OnceLock<Outcome>>,
}
impl Pending {
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Outcome> {
        match self.parent.poll_ready(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                let outcome = result.map(|_| ()).map_err(Arc::new);
                // The launcher removes this unique driver after completion.
                let _original = self.outcome.set(outcome.clone());
                Poll::Ready(outcome)
            }
        }
    }
}
pub(crate) struct StartupSignal(Arc<OnceLock<Outcome>>);
impl StartupSignal {
    pub(crate) fn poll_completion(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The launcher polls the original kernel source on this same reactor.
        // Observation neither creates another wait nor drives the bootstrap.
        match self.0.get() {
            None => Poll::Pending,
            Some(Ok(())) => Poll::Ready(Ok(())),
            Some(Err(error)) => Poll::Ready(Err(io::Error::other(error.clone()))),
        }
    }
}
