//! Exclusive bounded stdio readiness. No threads, tasks or OFD flag changes.
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use std::{
    future::Future,
    io::{self, Stdin, Stdout},
    os::fd::AsFd,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
pub(super) struct Stdio {
    input: Stdin,
    output: Stdout,
    read: Pin<Box<Sleep>>,
    write: Pin<Box<Sleep>>,
}
impl Stdio {
    pub(super) fn new(input: Stdin, output: Stdout) -> Self {
        Self {
            input,
            output,
            read: Box::pin(tokio::time::sleep(Duration::ZERO)),
            write: Box::pin(tokio::time::sleep(Duration::ZERO)),
        }
    }
    pub(super) fn read(
        &mut self,
        cx: &mut Context<'_>,
        bytes: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if self.read.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        self.read
            .as_mut()
            .reset(Instant::now() + Duration::from_millis(25));
        let mut fds = [PollFd::new(self.input.as_fd(), PollFlags::POLLIN)];
        let result = poll(&mut fds, PollTimeout::ZERO);
        if let Err(error) = result {
            if error != nix::errno::Errno::EINTR {
                return Poll::Ready(Err(error.into()));
            }
        } else {
            let flags = fds[0].revents().unwrap_or(PollFlags::empty());
            if flags.intersects(PollFlags::POLLNVAL | PollFlags::POLLERR) {
                return Poll::Ready(Err(io::Error::other("stdin readiness failed")));
            }
            if flags.intersects(PollFlags::POLLIN | PollFlags::POLLHUP) {
                // A bounded synchronous read may still block in the OS, notably on
                // regular files. No claim of timer-preemptible syscalls is made.
                match nix::unistd::read(self.input.as_fd(), bytes) {
                    Err(nix::errno::Errno::EINTR | nix::errno::Errno::EAGAIN) => {}
                    result => {
                        self.read.as_mut().reset(Instant::now());
                        return Poll::Ready(result.map_err(Into::into));
                    }
                }
            }
        }
        let _registered = self.read.as_mut().poll(cx);
        Poll::Pending
    }
    pub(super) fn write(&mut self, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        if self.write.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        self.write
            .as_mut()
            .reset(Instant::now() + Duration::from_millis(25));
        let mut fds = [PollFd::new(self.output.as_fd(), PollFlags::POLLOUT)];
        let result = poll(&mut fds, PollTimeout::ZERO);
        if let Err(error) = result {
            if error != nix::errno::Errno::EINTR {
                return Poll::Ready(Err(error.into()));
            }
        } else {
            let flags = fds[0].revents().unwrap_or(PollFlags::empty());
            if flags.intersects(PollFlags::POLLNVAL | PollFlags::POLLERR | PollFlags::POLLHUP) {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "stdout readiness failed",
                )));
            }
            if flags.contains(PollFlags::POLLOUT) {
                // Write directly through the borrowed original fd, without a stdio
                // buffer or a later flush that could obscure an exposed prefix.
                match nix::unistd::write(self.output.as_fd(), bytes) {
                    Err(nix::errno::Errno::EINTR | nix::errno::Errno::EAGAIN) => {}
                    result => {
                        self.write.as_mut().reset(Instant::now());
                        return Poll::Ready(result.map_err(Into::into));
                    }
                }
            }
        }
        let _registered = self.write.as_mut().poll(cx);
        Poll::Pending
    }
}
