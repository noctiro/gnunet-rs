//! Original unbuffered stdin; readiness polling never changes shared OFD flags.
use gnunet_program_host::binary_io::StartError;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use std::{
    fs::File,
    future::Future,
    io::{self, Read},
    os::fd::AsFd,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
pub(crate) struct Input {
    stdin: File,
    alarm: Pin<Box<Sleep>>,
}
impl Input {
    pub(crate) fn new(stdin: File) -> Result<Self, StartError> {
        let problem = match stdin.metadata() {
            Ok(metadata) if metadata.is_dir() => Some(io::Error::new(
                io::ErrorKind::InvalidInput,
                "directory is not a text input stream",
            )),
            Ok(_) => None,
            Err(error) => Some(error),
        };
        if let Some(cause) = problem {
            return Err(StartError {
                cause,
                close: gnunet_native::filesystem::close(stdin).err(),
            });
        }
        Ok(Self {
            stdin,
            alarm: Box::pin(tokio::time::sleep_until(Instant::now())),
        })
    }
    pub(crate) fn poll(
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
    pub(crate) fn retire(self, hard: Instant) -> impl std::future::Future<Output = Retired> {
        let close = gnunet_native::filesystem::close(self.stdin).err();
        let deadline = (Instant::now() >= hard).then(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "original input close exceeded its retirement target",
            )
        });
        std::future::ready(Retired { close, deadline })
    }
}
#[derive(Debug)]
pub(crate) struct Retired {
    close: Option<io::Error>,
    deadline: Option<io::Error>,
}
impl Retired {
    pub(crate) fn successful(&self) -> bool {
        self.close.is_none() && self.deadline.is_none()
    }
}
impl std::fmt::Display for Retired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "original stdin close: {:?}; deadline: {:?}",
            self.close, self.deadline
        )
    }
}
impl std::error::Error for Retired {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.close
            .as_ref()
            .or(self.deadline.as_ref())
            .map(|error| error as _)
    }
}
