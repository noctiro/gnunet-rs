//! Original signal/parent/PROGRAM stop source, with a permanent logger gate.
use crate::Cause;
use gnunet_program_host::reporting::Reporter;
use gnunet_service_startup::{ControlReceiver, ParentControl};
use std::{
    cell::Cell,
    io,
    rc::Rc,
    task::{Context, Poll},
};
use tokio::signal::unix::{Signal, SignalKind, signal};
pub(super) struct Control {
    interrupt: Signal,
    terminate: Signal,
    parent: Option<ControlReceiver>,
    stop: Rc<Cell<bool>>,
    reporter: Reporter,
}
impl Control {
    pub(super) fn new(
        parent: Option<ParentControl>,
        stop: Rc<Cell<bool>>,
        reporter: Reporter,
    ) -> Result<Self, Cause> {
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
            parent: parent
                .map(ParentControl::register)
                .transpose()
                .map_err(|failure| Box::new(failure.error) as Cause)?,
            stop,
            reporter,
        })
    }
    pub(super) fn stopped(&self) -> bool {
        self.stop.get() || self.reporter.failed()
    }
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.reporter.register(cx);
        if self.stopped() {
            return Poll::Ready(Ok(()));
        }
        for original in [&mut self.interrupt, &mut self.terminate] {
            if let Poll::Ready(event) = original.poll_recv(cx) {
                self.stop.set(true);
                return Poll::Ready(
                    event
                        .ok_or_else(|| io::Error::other("original zoneimport signal stream ended")),
                );
            }
        }
        let mut consumed = 0;
        for _ in 0..4 {
            let Some(parent) = &mut self.parent else {
                break;
            };
            match parent.poll_signal(cx) {
                Poll::Ready(Ok(Some(code)))
                    if i32::from(code) == nix::libc::SIGINT
                        || i32::from(code) == nix::libc::SIGTERM =>
                {
                    self.stop.set(true);
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(Some(_))) => consumed += 1,
                Poll::Ready(Ok(None)) => {
                    self.parent = None;
                    break;
                }
                Poll::Ready(Err(error)) => {
                    self.stop.set(true);
                    return Poll::Ready(Err(error));
                }
                Poll::Pending => break,
            }
        }
        if consumed == 4 {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
}
