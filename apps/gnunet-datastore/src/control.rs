//! Shared native termination and original parent-control subscription.
use crate::Failure;
use gnunet_service_startup::{ParentControl, StopError, StopSignals};
use std::task::{Context, Poll};
pub(super) struct Signals(StopSignals);
impl Signals {
    pub(super) fn new(parent: Option<ParentControl>) -> Result<Self, Failure> {
        Ok(Self(StopSignals::for_client(parent)?))
    }
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StopError>> {
        self.0.poll_stop(cx)
    }
}
