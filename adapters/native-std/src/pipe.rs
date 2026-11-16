//! Private local named-pipe locations and kernel peer observations.
mod stdio;
use std::{
    ffi::{OsStr, OsString},
    fmt, io,
    os::windows::io::{AsRawHandle, BorrowedHandle},
};
pub use stdio::{InputWriteHandle, InputWriter, OutputReadHandle, input_pair, output_pair};
use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId};
const PREFIX: &str = r"\\.\pipe\gnunet-rs-";

/// Implementation-local pipe location. The name is not peer identity or a
/// GNUnet wire address. Constructors reject remote, arbitrary or malformed names.
#[derive(Clone, Eq, PartialEq)]
pub struct Endpoint(OsString);
impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PipeEndpoint").finish_non_exhaustive()
    }
}
impl Endpoint {
    /// Generate a local name with 128 bits of operating-system entropy. The
    /// entropy error is retained as a source, without guessing another name.
    pub fn generate() -> io::Result<Self> {
        let mut entropy = [0; 16];
        getrandom::fill(&mut entropy).map_err(io::Error::other)?;
        let mut name = String::with_capacity(PREFIX.len() + 32);
        name.push_str(PREFIX);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in entropy {
            name.push(char::from(HEX[usize::from(byte >> 4)]));
            name.push(char::from(HEX[usize::from(byte & 15)]));
        }
        Ok(Self(name.into()))
    }
    /// Validate a captured local bootstrap location without opening any handle.
    pub fn parse(name: OsString) -> io::Result<Self> {
        let text = name.to_str().ok_or(io::ErrorKind::InvalidInput)?;
        if !text.strip_prefix(PREFIX).is_some_and(|token| {
            token.len() == 32
                && token
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid private pipe endpoint",
            ));
        }
        Ok(Self(name))
    }
    /// Original native endpoint spelling for the local pipe constructor.
    #[must_use]
    pub fn as_os_str(&self) -> &OsStr {
        &self.0
    }
}
/// EOF classes for reads on an already connected local pipe. These do not turn
/// an unsuccessful open/connect or write into success.
pub fn is_peer_closed(error: &io::Error) -> bool {
    use windows_sys::Win32::Foundation::{
        ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED,
    };
    error.kind() == io::ErrorKind::BrokenPipe
        || error.raw_os_error().is_some_and(|code| {
            matches!(
                code as u32,
                ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED
            )
        })
}
/// Observe the kernel client PID on this actual connected server endpoint.
/// A PID alone grants no original-process authority; callers must pin and match
/// their actual process object before accepting a bootstrap result.
#[expect(
    unsafe_code,
    reason = "GetNamedPipeClientProcessId borrows the original live pipe handle and fills one scalar output without retaining pointers"
)]
pub fn client_process_id(pipe: BorrowedHandle<'_>) -> io::Result<u32> {
    let mut id = 0;
    // SAFETY: the borrowed native handle stays live and output has exact size.
    if unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle(), &mut id) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(id)
}
/// Observe the kernel server PID of this connected client endpoint. This is an
/// observation, not a process handle, liveness receipt or GNUnet peer credential.
#[expect(
    unsafe_code,
    reason = "GetNamedPipeServerProcessId borrows the original live pipe handle and fills one scalar output without retaining pointers"
)]
pub fn server_process_id(pipe: BorrowedHandle<'_>) -> io::Result<u32> {
    let mut id = 0;
    // SAFETY: the borrowed native handle stays live and output has exact size.
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut id) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(id)
}

/// Actual cancellation-request outcome, never native completion evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationRequest {
    /// The kernel accepted a request to cancel outstanding operations.
    Submitted,
    /// No outstanding operation was found at that instant.
    NotFound,
}
/// Request cancellation of all this process's outstanding operations on the
/// borrowed original pipe without waiting. The I/O owner must keep its native
/// OVERLAPPED structures and buffers alive until actual completion; this call
/// never frees them. No operation result is inferred from a request outcome.
#[expect(
    unsafe_code,
    reason = "CancelIoEx borrows the live original pipe with a null selector and retains no caller output pointer; the existing I/O owner keeps all native loans alive"
)]
pub fn request_cancellation(pipe: BorrowedHandle<'_>) -> io::Result<CancellationRequest> {
    use windows_sys::Win32::{Foundation::ERROR_NOT_FOUND, System::IO::CancelIoEx};
    // SAFETY: the original handle stays live through this nonblocking request.
    // Null selects all operations without supplying or freeing any OVERLAPPED.
    if unsafe { CancelIoEx(pipe.as_raw_handle(), std::ptr::null()) } != 0 {
        return Ok(CancellationRequest::Submitted);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(ERROR_NOT_FOUND as i32) {
        Ok(CancellationRequest::NotFound)
    } else {
        Err(error)
    }
}
