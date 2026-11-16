//! Retained once-only native startup notification on the caller's reactor.
use super::Failure;
use std::task::{Context, Poll};
pub(super) trait Readiness {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Failure>>;
}
#[cfg(unix)]
impl Readiness for gnunet_service_startup::daemon::ChildReady {
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Failure>> {
        Poll::Ready(self.ready().map_err(|error| Box::new(error) as Failure))
    }
}
#[cfg(windows)]
impl Readiness for Option<gnunet_service_startup::ReadyWriter> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Failure>> {
        let Some(writer) = self else {
            return Poll::Ready(Ok(()));
        };
        if let Err(error) = writer.begin(gnunet_service_startup::ReadyStatus::AcceptRegistered) {
            return Poll::Ready(Err(Box::new(error)));
        }
        writer.poll_signal(cx).map(|result| {
            result
                .map(|_| ())
                .map_err(|error| Box::new(error) as Failure)
        })
    }
}
