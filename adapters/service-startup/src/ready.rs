//! The daemonize status pipe is separate from CLOSE_LSOCKS and signal control.
use std::{
    fs::File,
    io::{self, Write},
    os::fd::OwnedFd,
};
/// The exact bytes implemented by service.c, rather than the stale'!' comment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadyStatus {
    /// Reference accept-registration byte '.'. A Rust caller may require its
    /// actual Host-ready callback before reporting this stronger startup fact.
    AcceptRegistered,
    /// Startup failed after daemonizing: 'I'.
    InitializationFailed,
    /// Server/scheduler did not start before shutdown: 'S'.
    ServerNotStarted,
}
impl ReadyStatus {
    /// One native parent-pipe byte, not a GNUnet IPC frame.
    pub const fn byte(self) -> u8 {
        match self {
            Self::AcceptRegistered => b'.',
            Self::InitializationFailed => b'I',
            Self::ServerNotStarted => b'S',
        }
    }
}
/// Unique owned status writer. Drop without signal releases it as failed startup.
pub struct ReadyWriter {
    file: File,
}
impl ReadyWriter {
    /// Consume an already owned pipe/file; no late raw descriptor lookup occurs.
    pub fn from_owned(fd: OwnedFd) -> Self {
        Self {
            file: File::from(fd),
        }
    }
    /// Attempt exactly one actual byte write and release ownership on success or
    /// error. The result confirms only that write, never parent processing. As
    /// in C, EINTR/EAGAIN is reported rather than a synthetic successful signal.
    pub fn signal(mut self, status: ReadyStatus) -> io::Result<()> {
        match self.file.write(&[status.byte()]) {
            Ok(1) => Ok(()),
            Ok(_) => Err(io::ErrorKind::WriteZero.into()),
            Err(e) => Err(e),
        }
    }
}
