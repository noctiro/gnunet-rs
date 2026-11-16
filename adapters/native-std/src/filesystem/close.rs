//! Consuming native file close without retrying a numeric identifier.
use std::{fs::File, io};
/// Consume one owned file and attempt its native close exactly once.
/// An error is retained as an error; the consumed identifier is never retried.
#[expect(
    unsafe_code,
    reason = "The unique File transfers its descriptor/handle into exactly one native close call"
)]
pub fn close(file: File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::IntoRawFd;
        // SAFETY: ownership leaves File before the sole close; Drop cannot retry.
        if unsafe { libc::close(file.into_raw_fd()) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::IntoRawHandle;
        // SAFETY: the original unique kernel handle is consumed exactly once.
        if unsafe { windows_sys::Win32::Foundation::CloseHandle(file.into_raw_handle()) } != 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}
