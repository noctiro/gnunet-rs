//! The daemonize status pipe is separate from CLOSE_LSOCKS and signal control.
use crate::ReadyStatus;
use std::{
    fs::File,
    io::{self, Write},
    os::fd::OwnedFd,
};
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
