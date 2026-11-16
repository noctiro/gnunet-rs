//! Borrowed Unix stdout readiness and one bounded native write.
use nix::{
    poll::{PollFd, PollFlags, PollTimeout},
    sys::stat::{self, SFlag},
};
use std::{
    io::{self, Write},
    os::fd::AsFd,
};
pub(crate) struct Stdout {
    output: io::Stdout,
    regular: bool,
}
impl Stdout {
    pub(crate) fn new() -> io::Result<Self> {
        let output = io::stdout();
        let metadata = stat::fstat(output.as_fd())?;
        let kind = SFlag::from_bits_truncate(metadata.st_mode);
        Ok(Self {
            output,
            regular: (kind & SFlag::S_IFMT) == SFlag::S_IFREG,
        })
    }
    pub(crate) fn write(&mut self, bytes: &[u8]) -> io::Result<Option<usize>> {
        if !self.regular {
            let mut descriptors = [PollFd::new(self.output.as_fd(), PollFlags::POLLOUT)];
            match nix::poll::poll(&mut descriptors, PollTimeout::ZERO) {
                Ok(_) => {
                    let event = descriptors[0]
                        .revents()
                        .ok_or_else(|| io::Error::other("unknown stdout poll bits"))?;
                    if event.contains(PollFlags::POLLNVAL) {
                        return Err(io::Error::from_raw_os_error(nix::libc::EBADF));
                    }
                    if !event
                        .intersects(PollFlags::POLLOUT | PollFlags::POLLERR | PollFlags::POLLHUP)
                    {
                        return Ok(None);
                    }
                }
                Err(nix::errno::Errno::EINTR) => return Ok(None),
                Err(error) => return Err(error.into()),
            }
        }
        let end = if self.regular {
            bytes.len()
        } else {
            bytes.len().min(512)
        };
        match nix::unistd::write(self.output.as_fd(), &bytes[..end]) {
            Ok(n) => Ok(Some(n)),
            Err(nix::errno::Errno::EINTR | nix::errno::Errno::EAGAIN) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
    pub(crate) fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}
