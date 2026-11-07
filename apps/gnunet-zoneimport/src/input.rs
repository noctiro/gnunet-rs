//! Sole stdin reader; no blocking task, detached thread or OFD flag mutation.
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use std::{
    future::Future,
    io::{self, Read, Stdin},
    ops::Range,
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
    pub(super) fn new(stdin: Stdin) -> Self {
        Self {
            stdin,
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
        match poll(&mut fds, PollTimeout::ZERO) {
            Err(nix::errno::Errno::EINTR) => {
                let _registered = self.alarm.as_mut().poll(cx);
                return Poll::Pending;
            }
            Err(error) => return Poll::Ready(Err(error.into())),
            Ok(_) => {}
        }
        let flags = fds[0].revents().unwrap_or(PollFlags::empty());
        if flags.intersects(PollFlags::POLLNVAL | PollFlags::POLLERR) {
            return Poll::Ready(Err(io::Error::other("original stdin readiness failed")));
        }
        if flags.intersects(PollFlags::POLLIN | PollFlags::POLLHUP) {
            // This sole reader consumes at most the caller chunk after readiness.
            // A synchronous OS read (notably regular-file IO) cannot be forcibly
            // interrupted by an async deadline. No untracked work is spawned.
            match self.stdin.read(output) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) => {}
                result => {
                    // A ready bounded chunk need not wait another polling period.
                    // The outer round-robin still yields and polls control/Resolver.
                    self.alarm.as_mut().reset(Instant::now());
                    return Poll::Ready(result);
                }
            }
        }
        let _registered = self.alarm.as_mut().poll(cx);
        Poll::Pending
    }
}
#[derive(Debug)]
pub(super) struct Names {
    bytes: Vec<u8>,
    lines: Vec<Range<usize>>,
    start: usize,
    maximum_bytes: usize,
    maximum_names: usize,
    line_bytes: usize,
    finished: bool,
}
impl Names {
    pub(super) fn new(
        maximum_bytes: usize,
        maximum_names: usize,
        initial_names: usize,
    ) -> io::Result<Self> {
        let mut lines = Vec::new();
        lines
            .try_reserve_exact(initial_names.min(maximum_names))
            .map_err(io::Error::other)?;
        Ok(Self {
            bytes: Vec::new(),
            lines,
            start: 0,
            maximum_bytes,
            maximum_names,
            line_bytes: 4096,
            finished: false,
        })
    }
    pub(super) fn push(&mut self, input: &[u8]) -> io::Result<()> {
        if self.finished
            || self
                .bytes
                .len()
                .checked_add(input.len())
                .is_none_or(|n| n > self.maximum_bytes)
        {
            return Err(io::Error::other(
                "bounded zoneimport input byte limit exceeded",
            ));
        }
        let required = self.bytes.len() + input.len();
        if required > self.bytes.capacity() {
            let target = self
                .bytes
                .capacity()
                .saturating_mul(2)
                .max(4096)
                .max(required)
                .min(self.maximum_bytes);
            self.bytes
                .try_reserve_exact(target - self.bytes.len())
                .map_err(io::Error::other)?;
        }
        let previous = self.bytes.len();
        self.bytes.extend_from_slice(input);
        for position in previous..self.bytes.len() {
            if self.bytes[position] == b'\n' {
                self.line(position)?;
                self.start = position + 1;
            } else if position - self.start >= self.line_bytes {
                return Err(io::Error::other(
                    "zoneimport input hostname exceeds4096bytes",
                ));
            }
        }
        Ok(())
    }
    fn line(&mut self, end: usize) -> io::Result<()> {
        let end = if end > self.start && self.bytes[end - 1] == b'\r' {
            end - 1
        } else {
            end
        };
        if self.lines.len() == self.maximum_names {
            return Err(io::Error::other(
                "bounded zoneimport input name limit exceeded",
            ));
        }
        if self.lines.len() == self.lines.capacity() {
            let target = self
                .lines
                .capacity()
                .saturating_mul(2)
                .max(1)
                .min(self.maximum_names);
            self.lines
                .try_reserve_exact(target - self.lines.len())
                .map_err(io::Error::other)?;
        }
        self.lines.push(self.start..end);
        Ok(())
    }
    pub(super) fn finish(&mut self) -> io::Result<()> {
        if !self.finished {
            if self.start < self.bytes.len() {
                self.line(self.bytes.len())?;
            }
            self.finished = true;
        }
        Ok(())
    }
    pub(super) fn len(&self) -> usize {
        self.lines.len()
    }
    pub(super) fn get(&self, index: usize) -> Option<&[u8]> {
        self.lines.get(index).map(|line| &self.bytes[line.clone()])
    }
}
