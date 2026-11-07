//! Explicit fresh-process detach and original child readiness ownership.
use crate::{ReadyStatus, ReadyWriter};
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use std::{
    fmt,
    fs::{File, OpenOptions},
    io::{self, Read},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

/// The original fork's parent or the one process permitted to run the service.
#[must_use = "the parent must wait on its original status pipe; only Service may initialize listeners/runtime"]
pub enum Branch {
    /// Original parent, which must release its captured service resources first.
    Parent(Parent),
    /// Foreground process or the actual detached child, holding one status writer.
    Service(ChildReady),
}
/// Actual failure creating/detaching the child plus an independent status error.
#[derive(Debug)]
pub struct StartError {
    /// Original pipe/fork/setsid/stdio error.
    pub original: io::Error,
    /// Actual failure reporting initialization failure from the child, if any.
    pub status: Option<io::Error>,
}
impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "service detach: {}", self.original)?;
        if let Some(error) = &self.status {
            write!(f, "; independent child status write: {error}")?;
        }
        Ok(())
    }
}
impl std::error::Error for StartError {}
impl From<io::Error> for StartError {
    fn from(original: io::Error) -> Self {
        Self {
            original,
            status: None,
        }
    }
}
/// A real startup-ready byte from the original child. The parent must exit
/// afterwards; it does not wait for the live daemon's eventual termination.
/// This reports initial readiness, never a promise of continued daemon health.
#[derive(Debug)]
pub struct ReadyReceipt {
    /// PID returned by the original fork, not a later name/PID lookup.
    pub child_pid: u32,
}
/// Exact failure to receive child startup success.
#[derive(Debug)]
pub enum ParentCause {
    /// The original status pipe closed without any ready/failure byte.
    Eof,
    /// The child explicitly reported initialization or server-start failure.
    Reported(ReadyStatus),
    /// An actual unexpected status byte, preserved without reinterpretation.
    UnknownStatus(u8),
    /// Original blocking pipe-read failure.
    Read(io::Error),
}
/// Parent startup failure preserves the original actual pipe/status cause.
#[derive(Debug)]
pub struct ParentFailure {
    /// Original exact child PID.
    pub child_pid: u32,
    /// Original actual status-byte/EOF/read failure.
    pub cause: ParentCause,
}
impl fmt::Display for ParentFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "service child {} startup: {:?}",
            self.child_pid, self.cause
        )
    }
}
impl std::error::Error for ParentFailure {}
/// Unique parent's original status-pipe read end and exact native child PID.
/// Drop closes only this read end; it sends no kill or readiness acknowledgement.
pub struct Parent {
    status: File,
    child: libc::pid_t,
}
impl Parent {
    /// Block on the original pipe until one actual child byte, EOF or I/O error.
    /// Only '.' from the real ready callback is success; EOF is always failure.
    /// EINTR retries the same read, without a new operation or socket deadline.
    /// This synchronous OS read is not force-cancelable by an async/native
    /// network deadline. It never waits for a live daemon to exit or infers a
    /// successful startup from child exit/EOF. After returning the caller exits;
    /// the kernel reparents the child and its new parent owns later reaping.
    /// This API reports no child-exit or reaping receipt.
    pub fn wait(mut self) -> Result<ReadyReceipt, ParentFailure> {
        let mut byte = [0u8; 1];
        let status = loop {
            match self.status.read(&mut byte) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                other => break other,
            }
        };
        let cause = match status {
            Ok(1) if byte[0] == ReadyStatus::AcceptRegistered.byte() => None,
            Ok(1) if byte[0] == ReadyStatus::InitializationFailed.byte() => {
                Some(ParentCause::Reported(ReadyStatus::InitializationFailed))
            }
            Ok(1) if byte[0] == ReadyStatus::ServerNotStarted.byte() => {
                Some(ParentCause::Reported(ReadyStatus::ServerNotStarted))
            }
            Ok(0) => Some(ParentCause::Eof),
            Ok(_) => Some(ParentCause::UnknownStatus(byte[0])),
            Err(error) => Some(ParentCause::Read(error)),
        };
        if let Some(cause) = cause {
            Err(ParentFailure {
                child_pid: self.child as u32,
                cause,
            })
        } else {
            Ok(ReadyReceipt {
                child_pid: self.child as u32,
            })
        }
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum ChildState {
    Foreground,
    Waiting,
    Ready,
    Failed,
}
/// Once-only child startup notifier. Rotation may call `ready` again after its
/// real ready byte, but cannot send a second status or mint another child epoch.
#[must_use = "pass ready to the actual Host callback, then finish the service result"]
pub struct ChildReady {
    writer: Option<ReadyWriter>,
    state: ChildState,
}
impl ChildReady {
    /// Whether this owner is the actual forked service child.
    #[must_use]
    pub fn is_daemon(&self) -> bool {
        self.state != ChildState::Foreground
    }
    /// Signal only from the actual service/Host readiness callback. Consumes the
    /// original writer even if the native write fails. Subsequent true readiness
    /// events after a successful signal are no-ops, not parent notifications.
    pub fn ready(&mut self) -> io::Result<()> {
        match self.state {
            ChildState::Foreground | ChildState::Ready => Ok(()),
            ChildState::Failed => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "service startup status already failed",
            )),
            ChildState::Waiting => {
                let writer = self
                    .writer
                    .take()
                    .ok_or_else(|| io::Error::other("missing original service status writer"))?;
                let result = writer.signal(ReadyStatus::AcceptRegistered);
                self.state = if result.is_ok() {
                    ChildState::Ready
                } else {
                    ChildState::Failed
                };
                result
            }
        }
    }
    /// Complete the actual service result, preserving an independent failure
    /// reporting startup status. A clean stop before daemon readiness is still
    /// failed startup ('S'); a later error after ready cannot retract that real
    /// historical readiness byte or pretend the parent is still waiting.
    pub fn finish<T, E>(mut self, result: Result<T, E>) -> Result<T, CompletionFailure<E>> {
        let not_ready = matches!(self.state, ChildState::Waiting | ChildState::Failed);
        let status = self.writer.take().and_then(|writer| {
            self.state = ChildState::Failed;
            writer
                .signal(if result.is_err() {
                    ReadyStatus::InitializationFailed
                } else {
                    ReadyStatus::ServerNotStarted
                })
                .err()
        });
        match result {
            Err(original) => Err(CompletionFailure {
                original: Some(original),
                status,
                not_ready,
            }),
            Ok(_) if not_ready => Err(CompletionFailure {
                original: None,
                status,
                not_ready: true,
            }),
            Ok(value) => Ok(value),
        }
    }
}
impl Drop for ChildReady {
    fn drop(&mut self) {
        if let Some(writer) = self.writer.take() {
            // A dropped/abandoned startup never becomes ready. On a failed byte
            // write the parent's actual EOF/read/child observation remains fail.
            let _actual = writer.signal(ReadyStatus::InitializationFailed);
        }
    }
}
/// Original service failure and independent status-write failure. No result
/// represents an ACK from the parent, remote peer, worker or storage backend.
#[derive(Debug)]
pub struct CompletionFailure<E> {
    /// Original actual service error, or None for clean shutdown before ready.
    pub original: Option<E>,
    /// Independent actual status-write error, if reporting failed.
    pub status: Option<io::Error>,
    /// This child never produced a successful startup-ready status byte.
    pub not_ready: bool,
}
impl<E: fmt::Display> fmt::Display for CompletionFailure<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(original) = &self.original {
            original.fmt(f)?;
        } else {
            f.write_str("service stopped before actual startup readiness")?;
        }
        if let Some(error) = &self.status {
            write!(f, "; independent startup status write: {error}")?;
        }
        Ok(())
    }
}
impl<E: fmt::Debug + fmt::Display> std::error::Error for CompletionFailure<E> {}

/// Explicit foreground or actual single-fork service detachment. This performs
/// no account lookup, runtime construction, listener bind, key/proof work or
/// parent-control re-registration. The child retains the original captured FDs
/// and selected logger descriptor. Only its stdin/stdout become /dev/null;
/// stderr/logfile and inherited listener/control owners are not reconstructed.
///
/// # Safety
/// Call only in a fresh single-threaded exec process, after once-only inherited
/// capture and option/logfile selection, before NSS/account lookup, runtime or
/// thread creation, path guards, children, active async work or other resources
/// with process-wide/destructor side effects. No Rust/native allocator, stdio,
/// logging, clock or other lock/borrow may be held across this call. Any pre-fork
/// output must be flushed. Parent must drop its own captured listener/control
/// copies without initializing them, wait on Parent, then exit. Only Service may
/// continue startup. Do not call from general asynchronous embedding or repeat
/// a failed split. A failed child setup exits startup; no rollback is attempted.
#[expect(
    unsafe_code,
    reason = "The explicit fresh-exec caller guarantees a single thread and no held Rust/native locks or active process owners across fork"
)]
pub unsafe fn split(daemonize: bool) -> Result<Branch, StartError> {
    if !daemonize {
        return Ok(Branch::Service(ChildReady {
            writer: None,
            state: ChildState::Foreground,
        }));
    }
    let (read, write) = nix::unistd::pipe().map_err(io::Error::from)?;
    let read = lift(read)?;
    let write = lift(write)?;
    for fd in [&read, &write] {
        fcntl(fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).map_err(io::Error::from)?;
    }
    let null = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")?;
    let null = lift(null.into())?;
    // SAFETY: the caller's documented fresh single-thread/lock-free boundary
    // permits the child to continue Rust; all these FD owners are process local.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if pid > 0 {
        drop(write);
        drop(null);
        return Ok(Branch::Parent(Parent {
            status: File::from(read),
            child: pid,
        }));
    }
    drop(read);
    let mut child = ChildReady {
        writer: Some(ReadyWriter::from_owned(write)),
        state: ChildState::Waiting,
    };
    let setup = child_setup(&null);
    drop(null);
    if let Err(original) = setup {
        let status = child
            .writer
            .take()
            .and_then(|writer| writer.signal(ReadyStatus::InitializationFailed).err());
        child.state = ChildState::Failed;
        return Err(StartError { original, status });
    }
    Ok(Branch::Service(child))
}
#[expect(
    unsafe_code,
    reason = "Each successful F_DUPFD_CLOEXEC returns a new uniquely owned FD above stdio from this live owned original"
)]
fn lift(fd: OwnedFd) -> io::Result<OwnedFd> {
    if fd.as_raw_fd() > 2 {
        return Ok(fd);
    }
    let duplicated = fcntl(&fd, FcntlArg::F_DUPFD_CLOEXEC(3)).map_err(io::Error::from)?;
    // SAFETY: this is the fresh successful duplicate, owned nowhere else.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}
#[expect(
    unsafe_code,
    reason = "Only the freshly forked single-thread child calls setsid and redirects reserved stdin/stdout from a stable private /dev/null FD above 2"
)]
fn child_setup(null: &OwnedFd) -> io::Result<()> {
    // SAFETY: setsid has no pointer arguments and acts only on this fork child.
    if unsafe { libc::setsid() } < 0 {
        return Err(io::Error::last_os_error());
    }
    for target in [libc::STDIN_FILENO, libc::STDOUT_FILENO] {
        // SAFETY: null stays owned above stdio; only the child's reserved standard
        // slot is replaced. Inherited listener/control/log owners stay untouched.
        if unsafe { libc::dup2(null.as_raw_fd(), target) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
