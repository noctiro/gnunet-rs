use std::{io, os::windows::io::AsRawHandle, thread::JoinHandle};
use windows_sys::Win32::{
    Foundation::{
        ERROR_BROKEN_PIPE, ERROR_HANDLE_EOF, ERROR_NO_DATA, ERROR_NOT_FOUND,
        ERROR_OPERATION_ABORTED,
    },
    Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType},
    System::{IO::CancelSynchronousIo, Pipes::PeekNamedPipe},
};
/// Observe the original stdin pipe without consuming bytes. Other native routes
/// are handed to the original blocking worker; console reads can be canceled
/// only by targeting that worker and observing its real result.
///
/// # Errors
/// Preserves pipe-query failures other than an actual EOF/closed writer.
#[expect(
    unsafe_code,
    reason = "Native classification and PeekNamedPipe borrow the live original stdin route and initialized outputs"
)]
pub fn stdin_ready() -> io::Result<bool> {
    let input = io::stdin();
    let handle = input.as_raw_handle();
    // SAFETY: the original route stays live; callers exclude route replacement.
    if unsafe { GetFileType(handle) } != FILE_TYPE_PIPE {
        return Ok(true);
    }
    let mut available = 0;
    // SAFETY: this is a non-consuming query; available is a live DWORD output.
    if unsafe {
        PeekNamedPipe(
            handle,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            &mut available,
            std::ptr::null_mut(),
        )
    } != 0
    {
        return Ok(available != 0);
    }
    let error = io::Error::last_os_error();
    if matches!(error.raw_os_error(), Some(code) if code == ERROR_BROKEN_PIPE as i32 || code == ERROR_HANDLE_EOF as i32 || code == ERROR_NO_DATA as i32)
    {
        Ok(true)
    } else {
        Err(error)
    }
}
/// Request cancellation on the original exclusively owned synchronous reader.
/// A true result acknowledges only the request. The caller must observe the
/// original read and close; a not-yet-issued read may require another request.
///
/// # Errors
/// Preserves native cancellation errors. ERROR_NOT_FOUND returns false.
/// See [CancelSynchronousIo](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelsynchronousio).
#[expect(
    unsafe_code,
    reason = "CancelSynchronousIo borrows the retained original worker thread HANDLE, never a reused numeric thread id"
)]
pub fn cancel_synchronous_read(thread: &JoinHandle<()>) -> io::Result<bool> {
    // SAFETY: JoinHandle keeps this exact native thread object live. The caller
    // owns its one reader and closes admission before requesting cancellation.
    if unsafe { CancelSynchronousIo(thread.as_raw_handle()) } != 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(ERROR_NOT_FOUND as i32) {
        Ok(false)
    } else {
        Err(error)
    }
}
/// Classify only the original operation's native canceled completion code.
pub fn is_cancelled_read(error: &io::Error) -> bool {
    error.raw_os_error() == Some(ERROR_OPERATION_ABORTED as i32)
}
