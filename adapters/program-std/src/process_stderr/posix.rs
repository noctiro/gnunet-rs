//! Explicit process stderr installation. This is an early-startup capability,
//! separate from caller-owned logging and never granted by a safe constructor.
use std::{
    fs::File,
    io,
    marker::PhantomData,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
};
static CLAIMED: AtomicBool = AtomicBool::new(false);
/// Unique permission to replace process fd2. Its Drop releases only the logical
/// claim: the installed stderr destination persists, like GNUnet's global stream.
/// This capability is deliberately neither Send nor Sync.
pub struct ProcessStderr {
    _thread: PhantomData<Rc<()>>,
}
impl ProcessStderr {
    /// Claim exclusive early-startup stderr installation authority.
    ///
    /// # Safety
    /// Until the capability is dropped, no unrelated code or thread may close,
    /// replace, claim ownership of, or change flags on process fd2. Any borrowed
    /// stderr writers must not retain buffered data across installation. Every
    /// Rust/foreign thread that can use stderr must be quiescent during each
    /// installation. This gate coordinates only users of this Rust API; it cannot
    /// establish whole-process exclusivity on the caller's behalf.
    #[expect(
        unsafe_code,
        reason = "The caller must establish global fd2 exclusivity; the API makes this unavoidable native precondition explicit"
    )]
    pub unsafe fn claim() -> io::Result<Self> {
        CLAIMED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| io::Error::other("process stderr capability already claimed"))?;
        Ok(Self {
            _thread: PhantomData,
        })
    }
    pub(crate) fn install(&mut self, file: &File) -> io::Result<()> {
        // Lift the source even if open reused a closed standard slot. The unique
        // OwnedFd always owns a number >=3; libstd's fd2 is never an OwnedFd.
        #[expect(
            unsafe_code,
            reason = "Borrowed File remains live; F_DUPFD_CLOEXEC returns a fresh descriptor >=3, independent of process standard slots"
        )]
        // SAFETY: file owns a live fd and the command has one integer argument.
        let duplicate = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate < 0 {
            return Err(io::Error::last_os_error());
        }
        #[expect(
            unsafe_code,
            reason = "Successful F_DUPFD_CLOEXEC returned one fresh fd owned only by this scope"
        )]
        // SAFETY: duplicate is a newly created positive fd and has no other owner.
        let source = unsafe { OwnedFd::from_raw_fd(duplicate) };
        #[expect(
            unsafe_code,
            reason = "The ProcessStderr caller guarantees exclusive replacement; source is live and cannot equal fd2"
        )]
        // SAFETY: both descriptor arguments are valid integer fd slots; dup2
        // atomically replaces reserved process fd2 without transferring ownership.
        let status = unsafe { libc::dup2(source.as_raw_fd(), 2) };
        if status < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
impl Drop for ProcessStderr {
    fn drop(&mut self) {
        CLAIMED.store(false, Ordering::Release);
    }
}

/// Keep private ownership out of libstd standard slots, including a process
/// whose stderr was closed before open. This also prevents a later File Drop
/// from closing the fd2 that dup2 just installed.
pub(crate) fn lift(file: File) -> io::Result<File> {
    if file.as_raw_fd() >= 3 {
        return Ok(file);
    }
    #[expect(
        unsafe_code,
        reason = "Borrowed File is live and F_DUPFD_CLOEXEC returns fresh private ownership above standard slots"
    )]
    // SAFETY: the source is borrowed live and the command receives one integer.
    let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    #[expect(
        unsafe_code,
        reason = "The successful fcntl returned a fresh descriptor with unique ownership"
    )]
    // SAFETY: this scope is the first and only owner of the new descriptor.
    let owned = unsafe { OwnedFd::from_raw_fd(result) };
    drop(file);
    Ok(File::from(owned))
}
