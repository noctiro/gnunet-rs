//! Actual callback bytes copied before returning their borrowed delivery lease.
use crate::Cause;
use gnunet_resolver_broker::{Completion, Hostname, Reply};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use std::{
    future::Future,
    io::{self, Stdout, Write},
    os::fd::AsFd,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
use zeroize::Zeroizing;
pub(super) struct Line {
    bytes: Zeroizing<Vec<u8>>,
    offset: usize,
}
impl Line {
    pub(super) fn len(&self) -> usize {
        self.bytes.len()
    }
    pub(super) fn offset(&self) -> usize {
        self.offset
    }
    pub(super) fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
pub(super) enum Callback {
    Line(Line),
    Complete(Completion),
}
pub(super) fn copy(reply: Reply<'_>, reverse: bool) -> Result<Callback, Cause> {
    let mut bytes = Vec::new();
    match reply {
        Reply::Complete(reason) => return Ok(Callback::Complete(reason)),
        Reply::Address(value) if !reverse => {
            bytes.try_reserve_exact(64)?;
            writeln!(bytes, "{value}")?;
        }
        Reply::Hostname(Hostname::Numeric(value)) if reverse => {
            bytes.try_reserve_exact(64)?;
            writeln!(bytes, "{value}")?;
        }
        Reply::Hostname(Hostname::Resolved(value)) if reverse => {
            if value.len() > 65535 {
                return Err("Resolver hostname exceeds bounded native frame".into());
            }
            bytes.try_reserve_exact(value.len() + 1)?;
            bytes.extend_from_slice(value);
            bytes.push(b'\n');
        }
        _ => return Err("Resolver callback role does not match the original query".into()),
    }
    Ok(Callback::Line(Line {
        bytes: Zeroizing::new(bytes),
        offset: 0,
    }))
}
pub(super) struct Output {
    stdout: Stdout,
    alarm: Pin<Box<Sleep>>,
}
impl Output {
    pub(super) fn new(stdout: Stdout) -> Self {
        Self {
            stdout,
            alarm: Box::pin(tokio::time::sleep(Duration::ZERO)),
        }
    }
    pub(super) fn poll(
        &mut self,
        cx: &mut Context<'_>,
        line: &mut Line,
    ) -> Poll<io::Result<usize>> {
        if self.alarm.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        self.alarm
            .as_mut()
            .reset(Instant::now() + Duration::from_millis(25));
        let mut fds = [PollFd::new(self.stdout.as_fd(), PollFlags::POLLOUT)];
        match poll(&mut fds, PollTimeout::ZERO) {
            Err(nix::errno::Errno::EINTR) => {}
            Err(error) => return Poll::Ready(Err(error.into())),
            Ok(_) => {
                let flags = fds[0].revents().unwrap_or(PollFlags::empty());
                if flags.intersects(PollFlags::POLLNVAL | PollFlags::POLLHUP | PollFlags::POLLERR) {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "stdout readiness failed",
                    )));
                }
                if flags.contains(PollFlags::POLLOUT) {
                    let end = line.bytes.len().min(line.offset + 512);
                    // Sole original stdout fd; no hidden stdio buffer/flush and
                    // no changed OFD flags. The synchronous OS write itself is
                    // not claimed to be forcibly interruptible by an async timer.
                    match nix::unistd::write(self.stdout.as_fd(), &line.bytes[line.offset..end]) {
                        Err(nix::errno::Errno::EINTR | nix::errno::Errno::EAGAIN) => {}
                        Err(error) => return Poll::Ready(Err(error.into())),
                        Ok(0) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "stdout wrote zero bytes of a result line",
                            )));
                        }
                        Ok(count) => {
                            line.offset += count;
                            self.alarm.as_mut().reset(Instant::now());
                            return Poll::Ready(Ok(count));
                        }
                    }
                }
            }
        }
        let _registered = self.alarm.as_mut().poll(cx);
        Poll::Pending
    }
}
