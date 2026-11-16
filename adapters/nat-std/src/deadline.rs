//! Original finite NAT work with shared deadline checks and exclusive wake ownership.
use crate::Error;
/// Original process-clock and native targets shared with helper admission.
pub use gnunet_service_runtime::clock::{Bounds, BoundsError};
use gnunet_service_runtime::clock::{DeadlineGuard, RuntimeClock};
use gnunet_types::Error as Fault;
use std::{
    future::{Future, poll_fn},
    sync::Arc,
    task::{Context, Poll},
};
/// NAT error mapping and retained-result execution over one shared deadline guard.
pub struct Gate(DeadlineGuard);
impl Gate {
    /// Reserve exactly one clock waiter for the unchanged original targets.
    pub fn new(clock: Arc<dyn RuntimeClock>, bounds: Bounds) -> Result<Self, Error> {
        DeadlineGuard::new(clock, bounds)
            .map(Self)
            .map_err(Into::into)
    }
    /// Original source clock, shared by identity with the selected Resolver.
    pub fn clock(&self) -> &Arc<dyn RuntimeClock> {
        self.0.clock()
    }
    /// Original immutable targets.
    pub const fn bounds(&self) -> Bounds {
        self.0.bounds()
    }
    /// Check both original targets at the current effect boundary.
    pub fn check(&self) -> Result<u64, Error> {
        self.0.check().map_err(Into::into)
    }
    /// Stabilize the original source while retaining its independent native bound.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<u64, Error>> {
        self.0.poll(cx).map(|result| {
            result
                .map(|sample| sample.now.as_micros())
                .map_err(Into::into)
        })
    }
    /// Run real bounded IO, retaining an actual completed result during a clock
    /// revision race instead of polling an already-completed future again.
    pub async fn run<T>(
        &mut self,
        future: impl Future<Output = std::io::Result<T>>,
    ) -> Result<T, Error> {
        let mut future = std::pin::pin!(future);
        let mut result = None;
        poll_fn(|cx| {
            match self.poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(_)) => {}
            }
            if result.is_none() {
                match future.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(value) => result = Some(value),
                }
            }
            match self.poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Ready(Ok(_)) => Poll::Ready(
                    result
                        .take()
                        .ok_or(Fault::NotReady.into())
                        .and_then(|r| r.map_err(Error::Io)),
                ),
            }
        })
        .await
    }
}

/// Whether a direct NAT/runtime failure is original expiry, rather than a
/// clock source that itself failed with a Deadline-valued cause.
pub fn is_expired(error: &(dyn std::error::Error + 'static)) -> bool {
    error.downcast_ref::<Fault>() == Some(&Fault::Deadline)
        || error.downcast_ref::<BoundsError>() == Some(&BoundsError::Deadline)
        || error
            .downcast_ref::<Error>()
            .is_some_and(|error| matches!(error, Error::Protocol(Fault::Deadline)))
}
