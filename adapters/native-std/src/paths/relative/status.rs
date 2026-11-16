//! Preserve native NT status alongside its Win32 error-kind classification.
use std::{error::Error, fmt, io};
use windows_sys::Win32::Foundation::RtlNtStatusToDosError;
/// Original NT filesystem failure and the separately mapped Win32 code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatusError {
    operation: &'static str,
    status: i32,
    win32: u32,
}
impl StatusError {
    /// Native operation that refused the request.
    pub const fn operation(&self) -> &'static str {
        self.operation
    }
    /// Original signed NTSTATUS, unchanged by Win32 classification.
    pub const fn status(&self) -> i32 {
        self.status
    }
    /// Win32 mapping used only to classify the surrounding `io::Error`.
    pub const fn win32_code(&self) -> u32 {
        self.win32
    }
}
impl fmt::Display for StatusError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            out,
            "{}: NT status {:#010x}, Win32 {}",
            self.operation, self.status as u32, self.win32
        )
    }
}
impl Error for StatusError {}
#[expect(
    unsafe_code,
    reason = "RtlNtStatusToDosError maps one scalar status and retains no pointer or resource"
)]
pub(crate) fn check(operation: &'static str, status: i32) -> io::Result<()> {
    if status >= 0 {
        return Ok(());
    }
    // SAFETY: scalar status conversion only.
    let win32 = unsafe { RtlNtStatusToDosError(status) };
    let kind = io::Error::from_raw_os_error(win32 as i32).kind();
    Err(io::Error::new(
        kind,
        StatusError {
            operation,
            status,
            win32,
        },
    ))
}
