//! Native stop subscriptions and Unix child hints, never inferred child exits.
use crate::Cause;
use gnunet_service_startup::{ParentControl, StopSignals};
use std::task::{Context, Poll};
#[cfg(unix)]
use tokio::signal::unix::{Signal, SignalKind, signal};

pub(crate) enum Wake {
    Stop,
    #[cfg(unix)]
    Child,
}
pub(crate) struct Signals {
    stops: StopSignals,
    #[cfg(unix)]
    child: Signal,
}
impl Signals {
    pub fn new(parent: Option<ParentControl>) -> Result<Self, Cause> {
        Ok(Self {
            stops: StopSignals::for_client(parent).map_err(Cause::Startup)?,
            #[cfg(unix)]
            child: signal(SignalKind::child())?,
        })
    }
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Wake, Cause>> {
        match self.stops.poll_stop(cx) {
            Poll::Ready(Ok(())) => return Poll::Ready(Ok(Wake::Stop)),
            Poll::Ready(Err(error)) => return Poll::Ready(Err(Cause::Control(error))),
            Poll::Pending => {}
        }
        #[cfg(unix)]
        {
            self.child.poll_recv(cx).map(|value| {
                value.map_or_else(
                    || {
                        Err(Cause::Io(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "original URI child signal stream ended",
                        )))
                    },
                    |()| Ok(Wake::Child),
                )
            })
        }
        #[cfg(windows)]
        Poll::Pending
    }
}
