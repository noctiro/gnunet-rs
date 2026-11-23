//! Original finite NAT work with shared deadline checks and exclusive wake ownership.
use crate::Error;
/// Original process-clock and native targets shared with helper admission.
pub use gnunet_service_runtime::clock::{Bounds, BoundsError};
use gnunet_service_runtime::{
    clock::{DeadlineGuard, RuntimeClock},
    network::SocketPolicy,
};
use gnunet_types::Error as Fault;
use std::{
    future::{Future, poll_fn},
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll},
};
/// NAT error mapping and retained-result execution over one shared deadline guard.
pub struct Gate {
    deadline: DeadlineGuard,
    socket_policy: SocketPolicy,
}
impl Gate {
    /// Reserve exactly one clock waiter for the unchanged original targets.
    pub fn new(clock: Arc<dyn RuntimeClock>, bounds: Bounds) -> Result<Self, Error> {
        Self::new_with_socket_policy(clock, bounds, SocketPolicy::default())
    }
    /// Retain the original native egress policy for every socket of this job.
    pub fn new_with_socket_policy(
        clock: Arc<dyn RuntimeClock>,
        bounds: Bounds,
        socket_policy: SocketPolicy,
    ) -> Result<Self, Error> {
        Ok(Self {
            deadline: DeadlineGuard::new(clock, bounds)?,
            socket_policy,
        })
    }
    /// Application policy for the exact native sockets created on this job.
    pub fn socket_policy(&self) -> &SocketPolicy {
        &self.socket_policy
    }
    /// Bind one original UDP socket under both the deadline and the egress policy.
    pub async fn bind_udp(&mut self, address: SocketAddr) -> Result<tokio::net::UdpSocket, Error> {
        let policy = self.socket_policy.clone();
        self.run(async move { policy.udp_bind(address) }).await
    }
    /// Original source clock, shared by identity with the selected Resolver.
    pub fn clock(&self) -> &Arc<dyn RuntimeClock> {
        self.deadline.clock()
    }
    /// Original immutable targets.
    pub const fn bounds(&self) -> Bounds {
        self.deadline.bounds()
    }
    /// Check both original targets at the current effect boundary.
    pub fn check(&self) -> Result<u64, Error> {
        self.deadline.check().map_err(Into::into)
    }
    /// Stabilize the original source while retaining its independent native bound.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<u64, Error>> {
        self.deadline.poll(cx).map(|result| {
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
