//! UCRT errors are not Win32 GetLastError values.
use std::{ffi::c_int, fmt, io};

#[expect(
    unsafe_code,
    reason = "UCRT exposes the calling thread's initialized errno cell through _errno"
)]
unsafe extern "C" {
    fn _errno() -> *mut c_int;
}

/// An original UCRT errno, with its operation and numeric error domain retained.
#[derive(Debug)]
pub struct CrtError {
    operation: &'static str,
    code: c_int,
}
impl CrtError {
    /// Capture the current thread's CRT errno immediately after a failed UCRT
    /// operation. This reads no Win32 error and preserves the original domain.
    #[must_use]
    pub fn last(operation: &'static str) -> io::Error {
        crt_error(operation)
    }
    /// Operation that reported the error.
    #[must_use]
    pub fn operation(&self) -> &'static str {
        self.operation
    }
    /// Original UCRT errno; this is not a Win32 error number.
    #[must_use]
    pub fn code(&self) -> c_int {
        self.code
    }
}
impl fmt::Display for CrtError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            output,
            "{} failed (CRT errno {})",
            self.operation, self.code
        )
    }
}
impl std::error::Error for CrtError {}

#[expect(
    unsafe_code,
    reason = "Only the current UCRT thread's initialized errno storage is read"
)]
pub(crate) fn errno() -> c_int {
    // SAFETY: _errno returns this thread's live errno cell.
    unsafe { *_errno() }
}
#[expect(
    unsafe_code,
    reason = "Only the current UCRT thread's writable errno storage is changed"
)]
fn set_errno(value: c_int) {
    // SAFETY: no other thread's errno or Win32 error storage is accessed.
    unsafe { *_errno() = value };
}
/// Restore the current thread's UCRT errno when this guard drops. This does not
/// read or restore Win32 GetLastError storage and installs no global state.
pub struct CrtErrnoGuard(c_int);
impl CrtErrnoGuard {
    /// Retain the current thread's errno without changing its current value.
    #[must_use]
    pub fn preserve() -> Self {
        Self(errno())
    }
    pub(crate) fn clear() -> Self {
        let saved = Self::preserve();
        set_errno(0);
        saved
    }
}
impl Drop for CrtErrnoGuard {
    fn drop(&mut self) {
        set_errno(self.0);
    }
}
pub(crate) type Errno = CrtErrnoGuard;
pub(crate) fn crt_error(operation: &'static str) -> io::Error {
    crt_error_code(operation, errno())
}
pub(crate) fn crt_error_code(operation: &'static str, code: c_int) -> io::Error {
    let kind = match code {
        libc::ENOMEM => io::ErrorKind::OutOfMemory,
        libc::EINVAL => io::ErrorKind::InvalidInput,
        libc::EACCES | libc::EPERM => io::ErrorKind::PermissionDenied,
        libc::ENOENT => io::ErrorKind::NotFound,
        libc::EEXIST => io::ErrorKind::AlreadyExists,
        libc::EINTR => io::ErrorKind::Interrupted,
        libc::EPIPE => io::ErrorKind::BrokenPipe,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, CrtError { operation, code })
}
