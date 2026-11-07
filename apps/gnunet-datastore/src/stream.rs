//! Synchronous regular-file syscalls and readiness-gated borrowed stdio.
//! No OFD flag change, hidden stdin thread or copied whole-backup buffer exists.
use crate::{
    Failure,
    foreground::{Budget, Driver},
};
use nix::poll::{PollFd, PollFlags, PollTimeout};
use std::{
    cell::RefCell,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsFd, BorrowedFd},
        unix::fs::OpenOptionsExt,
    },
    path::Path,
    rc::Rc,
};
#[derive(Debug)]
pub(super) struct CloseError {
    pub flush: Option<io::Error>,
    pub close: Option<nix::errno::Errno>,
}
impl std::fmt::Display for CloseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "original stream flush={:?}; consumed close={:?} (no close retry)",
            self.flush, self.close
        )
    }
}
impl std::error::Error for CloseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.flush
            .as_ref()
            .map(|e| e as &dyn std::error::Error)
            .or_else(|| self.close.as_ref().map(|e| e as &dyn std::error::Error))
    }
}
#[derive(Debug, Default)]
pub(super) struct Cleanup {
    pub errors: [Option<CloseError>; 2],
    pub overflowed: bool,
}
pub(super) type Retained = Rc<RefCell<Cleanup>>;
#[derive(Debug)]
struct Transfer {
    stage: &'static str,
    completed: usize,
    expected: usize,
    cause: io::Error,
}
impl std::fmt::Display for Transfer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} transferred {}/{} bytes: {}",
            self.stage, self.completed, self.expected, self.cause
        )
    }
}
impl std::error::Error for Transfer {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
enum Endpoint {
    File(Option<File>),
    Input(io::Stdin),
    Output(io::Stdout),
}
pub(super) struct Stream {
    endpoint: Endpoint,
    writing: bool,
    poll: bool,
    closed: bool,
    retained: Retained,
}
impl Stream {
    pub fn input(path: Option<&Path>, retained: Retained) -> Result<Self, Failure> {
        let endpoint = match path {
            Some(path) => Endpoint::File(Some(File::open(path)?)),
            None => Endpoint::Input(io::stdin()),
        };
        Self::new(endpoint, false, retained)
    }
    pub fn output(path: Option<&Path>, retained: Retained) -> Result<Self, Failure> {
        let endpoint = match path {
            Some(path) => Endpoint::File(Some(
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(path)?,
            )),
            None => Endpoint::Output(io::stdout()),
        };
        Self::new(endpoint, true, retained)
    }
    fn new(endpoint: Endpoint, writing: bool, retained: Retained) -> Result<Self, Failure> {
        // Establish actual close ownership before even metadata may fail.
        let mut stream = Self {
            endpoint,
            writing,
            poll: true,
            closed: false,
            retained,
        };
        // fstat observes the actual descriptor, including redirected stdio.
        // It neither follows a replacement pathname nor changes shared OFD flags.
        let metadata = nix::sys::stat::fstat(stream.fd()?)?;
        let kind = nix::sys::stat::SFlag::from_bits_truncate(metadata.st_mode);
        stream.poll = (kind & nix::sys::stat::SFlag::S_IFMT) != nix::sys::stat::SFlag::S_IFREG;
        Ok(stream)
    }
    fn fd(&self) -> io::Result<BorrowedFd<'_>> {
        match &self.endpoint {
            Endpoint::File(Some(file)) => Ok(file.as_fd()),
            Endpoint::Input(input) => Ok(input.as_fd()),
            Endpoint::Output(output) => Ok(output.as_fd()),
            Endpoint::File(None) => Err(io::Error::other("original stream already consumed")),
        }
    }
    async fn ready(
        &self,
        driver: &mut Driver<'_, '_, '_, '_>,
        budget: &mut Budget,
    ) -> Result<(), Failure> {
        loop {
            driver.check(budget).await?;
            if !self.poll {
                return Ok(());
            }
            let flags = if self.writing {
                PollFlags::POLLOUT
            } else {
                PollFlags::POLLIN
            };
            let mut descriptors = [PollFd::new(self.fd()?, flags)];
            match nix::poll::poll(&mut descriptors, PollTimeout::ZERO) {
                Ok(_) => {
                    let actual = descriptors[0]
                        .revents()
                        .ok_or("unrecognized original poll events")?;
                    if actual.contains(PollFlags::POLLNVAL) {
                        return Err(io::Error::from_raw_os_error(nix::libc::EBADF).into());
                    }
                    if actual.intersects(flags | PollFlags::POLLERR | PollFlags::POLLHUP) {
                        driver.check(budget).await?;
                        return Ok(());
                    }
                }
                Err(nix::errno::Errno::EINTR) => {}
                Err(error) => return Err(io::Error::from(error).into()),
            }
            // Actual poll(2) says not ready. Wait a bounded native cadence while
            // the same Resolver/Stop/hard sources progress, then poll the same fd.
            driver.pause(budget).await?;
        }
    }
    pub async fn read_exact(
        &mut self,
        driver: &mut Driver<'_, '_, '_, '_>,
        budget: &mut Budget,
        out: &mut [u8],
        eof: bool,
        stage: &'static str,
    ) -> Result<bool, Failure> {
        let mut used = 0;
        while used < out.len() {
            self.ready(driver, budget).await?;
            let n = match &mut self.endpoint {
                Endpoint::File(Some(file)) => file.read(&mut out[used..]),
                Endpoint::Input(input) => {
                    nix::unistd::read(input, &mut out[used..]).map_err(io::Error::from)
                }
                _ => Err(io::Error::other("not an original readable stream")),
            };
            match n {
                Ok(0) if used == 0 && eof => {
                    driver.check(budget).await?;
                    return Ok(false);
                }
                Ok(0) => {
                    return Err(Box::new(Transfer {
                        stage,
                        completed: used,
                        expected: out.len(),
                        cause: io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated original input",
                        ),
                    }));
                }
                Ok(n) => used = used.checked_add(n).ok_or("input count overflow")?,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) =>
                {
                    driver.pause(budget).await?;
                }
                Err(cause) => {
                    return Err(Box::new(Transfer {
                        stage,
                        completed: used,
                        expected: out.len(),
                        cause,
                    }));
                }
            }
            driver.check(budget).await?;
        }
        Ok(true)
    }
    pub async fn write_all(
        &mut self,
        driver: &mut Driver<'_, '_, '_, '_>,
        budget: &mut Budget,
        data: &[u8],
        stage: &'static str,
    ) -> Result<(), Failure> {
        let mut used = 0;
        while used < data.len() {
            self.ready(driver, budget).await?;
            // A readiness observation is advisory; keeping borrowed stdio writes
            // <=POSIX minimum PIPE_BUF avoids a large blocking pipe write. Other
            // readers/writers and regular-file syscalls retain OS race/blocking semantics.
            let end = if self.poll {
                used.saturating_add(512).min(data.len())
            } else {
                data.len()
            };
            let n = match &mut self.endpoint {
                Endpoint::File(Some(file)) => file.write(&data[used..end]),
                Endpoint::Output(output) => {
                    nix::unistd::write(output, &data[used..end]).map_err(io::Error::from)
                }
                _ => Err(io::Error::other("not an original writable stream")),
            };
            match n {
                Ok(0) => {
                    return Err(Box::new(Transfer {
                        stage,
                        completed: used,
                        expected: data.len(),
                        cause: io::Error::new(io::ErrorKind::WriteZero, "zero original write"),
                    }));
                }
                Ok(n) => used = used.checked_add(n).ok_or("output count overflow")?,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) =>
                {
                    driver.pause(budget).await?;
                }
                Err(cause) => {
                    return Err(Box::new(Transfer {
                        stage,
                        completed: used,
                        expected: data.len(),
                        cause,
                    }));
                }
            }
            driver.check(budget).await?;
        }
        Ok(())
    }
    fn close(&mut self) -> Result<(), CloseError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let flush = if self.writing {
            match &mut self.endpoint {
                Endpoint::File(Some(file)) => file.flush().err(),
                Endpoint::Output(output) => output.flush().err(),
                _ => None,
            }
        } else {
            None
        };
        let close = match &mut self.endpoint {
            Endpoint::File(file) => file.take().and_then(|file| nix::unistd::close(file).err()),
            _ => None,
        };
        if flush.is_some() || close.is_some() {
            Err(CloseError { flush, close })
        } else {
            Ok(())
        }
    }
    pub fn finish(mut self) -> Result<(), CloseError> {
        self.close()
    }
}
impl Drop for Stream {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            let mut retained = self.retained.borrow_mut();
            if let Some(slot) = retained.errors.iter_mut().find(|s| s.is_none()) {
                *slot = Some(error);
            } else {
                retained.overflowed = true;
            }
        }
    }
}
