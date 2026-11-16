//! Caller-owned platform notifications; EOF remains an observation failure.
use std::{
    io,
    task::{Context, Poll},
};
pub(super) enum Event {
    Stop,
    #[cfg(unix)]
    Continue,
}
pub(super) struct Signals {
    termination: gnunet_service_runtime::signals::Termination,
    #[cfg(unix)]
    hangup: tokio::signal::unix::Signal,
    #[cfg(unix)]
    quit: tokio::signal::unix::Signal,
    #[cfg(unix)]
    pipe: tokio::signal::unix::Signal,
}
impl Signals {
    pub(super) fn new() -> io::Result<Self> {
        #[cfg(unix)]
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            termination: gnunet_service_runtime::signals::Termination::new()?,
            #[cfg(unix)]
            hangup: signal(SignalKind::hangup())?,
            #[cfg(unix)]
            quit: signal(SignalKind::quit())?,
            // The official Unix scheduler catches SIGPIPE with a no-op handler.
            // Caught dispositions reset at exec, unlike an inherited SIG_IGN.
            #[cfg(unix)]
            pipe: signal(SignalKind::pipe())?,
        })
    }
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Event>> {
        if let Poll::Ready(result) = self.termination.poll_stop(cx) {
            return Poll::Ready(result.map(|()| Event::Stop));
        }
        #[cfg(unix)]
        for (signal, event) in [
            (&mut self.hangup, Event::Stop),
            (&mut self.quit, Event::Stop),
            (&mut self.pipe, Event::Continue),
        ] {
            match signal.poll_recv(cx) {
                Poll::Ready(Some(())) => return Poll::Ready(Ok(event)),
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "ARM CLI signal stream ended",
                    )));
                }
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }
}
