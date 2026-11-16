use super::super::{Facts, Problem};
use std::{
    fmt, io,
    task::{Context, Poll},
};
use tokio::signal::unix::{Signal, SignalKind, signal};
#[derive(Debug)]
struct Cancelled(i32);
impl fmt::Display for Cancelled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "original conversion cancelled by signal {}", self.0)
    }
}
impl std::error::Error for Cancelled {}
pub(crate) struct Signals {
    interrupt: Signal,
    terminate: Signal,
}
impl Signals {
    pub(crate) fn new() -> io::Result<Self> {
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
        })
    }
    pub(crate) fn check(&mut self, cx: &mut Context<'_>, facts: &mut Facts) -> Result<(), Problem> {
        for (port, number) in [
            (&mut self.interrupt, SignalKind::interrupt().as_raw_value()),
            (&mut self.terminate, SignalKind::terminate().as_raw_value()),
        ] {
            match port.poll_recv(cx) {
                Poll::Ready(Some(())) => {
                    facts.cancelled = Some(number);
                    return Err(Problem::new(
                        u8::try_from(128 + number).unwrap_or(1),
                        Cancelled(number),
                    ));
                }
                Poll::Ready(None) => return Err(Problem::message(1, "original signal port ended")),
                Poll::Pending => {}
            }
        }
        Ok(())
    }
}
