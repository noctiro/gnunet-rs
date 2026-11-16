//! Native regex, calendar and process boundaries selected by platform.
#[cfg(unix)]
use std::ffi::CStr;
use std::io;
#[cfg(unix)]
use std::{ffi::CString, mem::MaybeUninit};
#[cfg(unix)]
fn cstring(bytes: &[u8]) -> io::Result<CString> {
    CString::new(&bytes[..bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len())])
        .map_err(io::Error::other)
}
mod regex;
pub(crate) use regex::{Regex, RegexCompileFailure};

/// Widen the platform signed microsecond type without changing prior native narrowing.
#[cfg(unix)]
pub(crate) fn wide_micros(value: impl Into<i64>) -> i64 {
    value.into()
}

mod calendar;
pub(crate) use calendar::{Calendar, wall_time};

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn errno_ptr() -> *mut libc::c_int {
    #[expect(
        unsafe_code,
        reason = "Darwin and FreeBSD provide a live thread-local errno pointer"
    )]
    // SAFETY: __error has no input and returns this thread's errno address.
    unsafe {
        libc::__error()
    }
}
#[cfg(target_os = "linux")]
fn errno_ptr() -> *mut libc::c_int {
    #[expect(
        unsafe_code,
        reason = "Linux provides a live thread-local errno pointer"
    )]
    // SAFETY: __errno_location has no input and returns this thread's errno address.
    unsafe {
        libc::__errno_location()
    }
}
#[cfg(windows)]
pub(crate) use gnunet_native::CrtErrnoGuard as ErrnoGuard;
#[cfg(unix)]
pub(crate) struct ErrnoGuard(libc::c_int);
#[cfg(unix)]
impl ErrnoGuard {
    pub(crate) fn preserve() -> Self {
        #[expect(unsafe_code, reason = "Read only current thread's valid errno cell")]
        // SAFETY: errno_ptr points to this thread's initialized errno cell.
        Self(unsafe { *errno_ptr() })
    }
}
#[cfg(unix)]
impl Drop for ErrnoGuard {
    fn drop(&mut self) {
        #[expect(unsafe_code, reason = "Restore only this thread's errno after logging")]
        // SAFETY: errno_ptr points to this thread's writable errno cell.
        unsafe {
            *errno_ptr() = self.0;
        }
    }
}
#[cfg(unix)]
pub(crate) fn strerror(number: i32) -> Vec<u8> {
    #[expect(
        unsafe_code,
        reason = "Native strerror returns process-owned C text, copied immediately without mutation"
    )]
    // SAFETY: strerror permits every integer errno; a null fallback is handled.
    let text = unsafe { libc::strerror(number) };
    if text.is_null() {
        return b"unknown error".to_vec();
    }
    #[expect(
        unsafe_code,
        reason = "Non-null native strerror text is NUL terminated and copied before another call"
    )]
    // SAFETY: native strerror returned a valid C string for this call.
    unsafe {
        CStr::from_ptr(text).to_bytes().to_vec()
    }
}

/// Format the original error in its own native domain. Win32 errors and typed
/// UCRT errors must never be interpreted as POSIX errno numbers.
pub(crate) fn error_text(error: &io::Error) -> Vec<u8> {
    #[cfg(unix)]
    if let Some(code) = error.raw_os_error() {
        return strerror(code);
    }
    error.to_string().into_bytes()
}

pub(crate) fn upper(byte: u8) -> i32 {
    #[expect(
        unsafe_code,
        reason = "POSIX toupper accepts every unsigned-char value; preserves native LC_CTYPE sorting semantics"
    )]
    // SAFETY: u8 promoted to int is in the required unsigned-char domain.
    unsafe {
        libc::toupper(i32::from(byte))
    }
}
pub(crate) fn whitespace(byte: u8) -> bool {
    #[expect(
        unsafe_code,
        reason = "POSIX isspace accepts every unsigned-char value; native locale is installed separately"
    )]
    // SAFETY: u8 promoted to int is in the required unsigned-char domain.
    unsafe {
        libc::isspace(i32::from(byte)) != 0
    }
}
mod date;
pub(crate) use date::absolute_calendar;

#[cfg(unix)]
pub(crate) fn errno() -> i32 {
    #[expect(
        unsafe_code,
        reason = "Read only the calling thread's initialized native errno cell"
    )]
    // SAFETY: errno_ptr returns the live thread-local cell.
    unsafe {
        *errno_ptr()
    }
}
#[cfg(unix)]
pub(crate) fn path_access(path: &[u8], mode: i32) -> io::Result<()> {
    let path = cstring(path)?;
    #[expect(
        unsafe_code,
        reason = "Live NUL-terminated native path and POSIX access mode, with no retained pointer"
    )]
    // SAFETY: access reads this C string only during the call.
    let status = unsafe { libc::access(path.as_ptr(), mode) };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
#[cfg(unix)]
pub(crate) fn path_is_directory(path: &[u8]) -> io::Result<bool> {
    let path = cstring(path)?;
    let mut value = MaybeUninit::uninit();
    #[expect(
        unsafe_code,
        reason = "stat receives live native path and exclusive aligned output storage"
    )]
    // SAFETY: pointers remain valid through stat, which does not retain them.
    let status = unsafe { libc::stat(path.as_ptr(), value.as_mut_ptr()) };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    #[expect(
        unsafe_code,
        reason = "Successful native stat initialized the complete output structure"
    )]
    // SAFETY: this exact stat call returned success for this output storage.
    let value = unsafe { value.assume_init() };
    Ok(value.st_mode & libc::S_IFMT == libc::S_IFDIR)
}
#[cfg(unix)]
pub(crate) fn path_mkdir(path: &[u8]) -> io::Result<()> {
    let path = cstring(path)?;
    #[expect(
        unsafe_code,
        reason = "Caller explicitly selected the log destination; mkdir receives only a live C path and official 0755 mode"
    )]
    // SAFETY: mkdir reads the path during this call and creates no retained borrow.
    let status = unsafe { libc::mkdir(path.as_ptr(), 0o755) };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(unix)]
#[expect(
    unsafe_code,
    reason = "Exact POSIX inet_ntop ABI uses executing libc family/socklen_t and caller-owned aligned native structures"
)]
unsafe extern "C" {
    fn inet_ntop(
        family: libc::c_int,
        source: *const libc::c_void,
        destination: *mut libc::c_char,
        size: libc::socklen_t,
    ) -> *const libc::c_char;
}
/// Format without DNS or any socket operation, exactly as source GNUNET_a2s.
#[cfg(unix)]
pub(crate) fn ipv6_text(address: [u8; 16]) -> io::Result<Vec<u8>> {
    let source = libc::in6_addr { s6_addr: address };
    let mut destination = [0 as libc::c_char; 46];
    #[expect(
        unsafe_code,
        reason = "Aligned initialized in6_addr input and 46-byte writable destination cover the exact POSIX IPv6 conversion contract"
    )]
    // SAFETY: both native objects are live and nonoverlapping; inet_ntop neither retains pointers nor exceeds the supplied capacity.
    let result = unsafe {
        inet_ntop(
            libc::AF_INET6,
            (&source as *const libc::in6_addr).cast(),
            destination.as_mut_ptr(),
            46,
        )
    };
    if result.is_null() {
        return Err(io::Error::last_os_error());
    }
    let length = destination
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| io::Error::other("native IPv6 formatter omitted terminator"))?;
    Ok(destination[..length].iter().map(|&b| b as u8).collect())
}
#[cfg(windows)]
pub(crate) use gnunet_native::ipv6_text;
