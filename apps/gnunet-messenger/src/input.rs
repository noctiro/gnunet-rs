//! Sole caller-owned stdin; no background reader or shared-OFD flag changes.
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use std::{
    future::Future,
    io::{self, Read, Stdin},
    os::fd::AsFd,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
pub(super) struct Input {
    stdin: Stdin,
    alarm: Pin<Box<Sleep>>,
}
impl Input {
    pub(super) fn new() -> Self {
        Self {
            stdin: io::stdin(),
            alarm: Box::pin(tokio::time::sleep_until(Instant::now())),
        }
    }
    pub(super) fn poll(
        &mut self,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if self.alarm.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        self.alarm
            .as_mut()
            .reset(Instant::now() + Duration::from_millis(25));
        let mut fds = [PollFd::new(self.stdin.as_fd(), PollFlags::POLLIN)];
        if let Err(error) = poll(&mut fds, PollTimeout::ZERO) {
            return Poll::Ready(Err(error.into()));
        }
        let flags = fds[0].revents().unwrap_or(PollFlags::empty());
        if flags.intersects(PollFlags::POLLNVAL | PollFlags::POLLERR) {
            return Poll::Ready(Err(io::Error::other("stdin descriptor readiness failed")));
        }
        let readable = flags.intersects(PollFlags::POLLIN | PollFlags::POLLHUP);
        if readable {
            // The CLI is the sole reader. The actual bounded syscall may still
            // block in the OS (notably regular-file IO); no hard-preemption claim
            // is made. No thread/task or changed parent OFD flags outlive cleanup.
            match self.stdin.read(output) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                result => return Poll::Ready(result),
            }
        }
        let _armed = self.alarm.as_mut().poll(cx);
        Poll::Pending
    }
}
