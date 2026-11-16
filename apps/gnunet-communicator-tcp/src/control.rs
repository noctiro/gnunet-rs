//! Native PROGRAM stop subscriptions retain the original parent-control owner.
use gnunet_program_host::reporting::Reporter;
use gnunet_service_startup::{ParentControl, StopSignals};
use std::{future::Future, io, task::Poll};
pub(super) fn shutdown(
    reporter: Reporter,
    parent: Option<ParentControl>,
) -> io::Result<impl Future<Output = io::Result<()>>> {
    let mut stop = StopSignals::for_client(parent).map_err(io::Error::other)?;
    Ok(std::future::poll_fn(move |cx| {
        reporter.register(cx);
        if reporter.failed() {
            return Poll::Ready(Ok(()));
        }
        stop.poll_stop(cx)
            .map(|result| result.map_err(io::Error::other))
    }))
}
