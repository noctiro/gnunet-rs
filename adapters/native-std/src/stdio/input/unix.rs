use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use std::{io, os::fd::AsFd};
/// Observe the original stdin route before admitting a potentially blocking read.
/// The caller excludes route changes and competing readers. Readiness does not
/// make a regular-file/device syscall preemptible or prove successful reading.
///
/// # Errors
/// Preserves native poll errors and invalid original descriptor observations.
pub fn stdin_ready() -> io::Result<bool> {
    let input = io::stdin();
    let mut fds = [PollFd::new(input.as_fd(), PollFlags::POLLIN)];
    match poll(&mut fds, PollTimeout::ZERO) {
        Err(nix::errno::Errno::EINTR) => return Ok(false),
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    let flags = fds[0].revents().unwrap_or(PollFlags::empty());
    if flags.intersects(PollFlags::POLLNVAL | PollFlags::POLLERR) {
        return Err(io::Error::other("original stdin readiness failed"));
    }
    Ok(flags.intersects(PollFlags::POLLIN | PollFlags::POLLHUP))
}
