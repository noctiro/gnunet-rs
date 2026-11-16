//! Kernel console interrupt, break, close, logoff and shutdown notifications.
use std::{
    io,
    task::{Context, Poll},
};
use tokio::signal::windows::{CtrlBreak, CtrlC, CtrlClose, CtrlLogoff, CtrlShutdown};
/// Caller-owned native stop subscriptions. Register after console detachment;
/// Drop releases subscriptions without promising restoration of global handlers.
#[derive(Debug)]
pub struct Termination {
    interrupt: CtrlC,
    console_break: CtrlBreak,
    close: CtrlClose,
    logoff: CtrlLogoff,
    shutdown: CtrlShutdown,
}
impl Termination {
    /// Register all actual console stop sources under an entered runtime.
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            interrupt: tokio::signal::windows::ctrl_c()?,
            console_break: tokio::signal::windows::ctrl_break()?,
            close: tokio::signal::windows::ctrl_close()?,
            logoff: tokio::signal::windows::ctrl_logoff()?,
            shutdown: tokio::signal::windows::ctrl_shutdown()?,
        })
    }
    /// Observe a real stop event; an ended subscription is not synthesized stop.
    pub fn poll_stop(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let observations = [
            self.interrupt.poll_recv(cx),
            self.console_break.poll_recv(cx),
            self.close.poll_recv(cx),
            self.logoff.poll_recv(cx),
            self.shutdown.poll_recv(cx),
        ];
        for observation in observations {
            match observation {
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
