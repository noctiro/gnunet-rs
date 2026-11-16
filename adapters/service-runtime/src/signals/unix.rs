//! Kernel interrupt and terminate signals on Unix hosts.
use std::{
    io,
    task::{Context, Poll},
};
use tokio::signal::unix::{Signal, SignalKind};
/// Caller-owned native stop subscriptions. Drop releases these subscriptions;
/// it does not restore process-global signal handlers installed by Tokio.
#[derive(Debug)]
pub struct Termination {
    interrupt: Signal,
    terminate: Signal,
}
impl Termination {
    /// Register under an entered I/O-enabled runtime after startup detachment.
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            interrupt: tokio::signal::unix::signal(SignalKind::interrupt())?,
            terminate: tokio::signal::unix::signal(SignalKind::terminate())?,
        })
    }
    /// Observe a real stop event; an ended subscription remains an I/O failure.
    pub fn poll_stop(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        for signal in [&mut self.interrupt, &mut self.terminate] {
            match signal.poll_recv(cx) {
                Poll::Ready(Some(())) => return Poll::Ready(Ok(())),
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "native termination stream ended",
                    )));
                }
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }
}
