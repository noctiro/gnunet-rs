//! POSIX loader calls and immediate bounded, lossless diagnostic capture.
use std::{
    ffi::{CStr, CString, c_void},
    fmt, io,
    os::unix::ffi::OsStrExt,
    path::Path,
    ptr::NonNull,
};
#[cfg(any(target_os = "linux", target_os = "android"))]
#[expect(
    unsafe_code,
    reason = "POSIX loader symbols require the platform dl link library"
)]
#[link(name = "dl")]
unsafe extern "C" {}
/// A POSIX loader diagnostic captured before another loader call can replace it.
#[derive(Debug)]
pub struct Diagnostic {
    bytes: Vec<u8>,
    truncated: bool,
}
impl Diagnostic {
    /// Original diagnostic prefix, without its terminator or Unicode rewriting.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Whether the native diagnostic exceeded the fixed 1 KiB bound or its copy failed.
    #[must_use]
    pub fn truncated(&self) -> bool {
        self.truncated
    }
}
impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("POSIX dynamic loader failure")
    }
}
impl std::error::Error for Diagnostic {}
#[expect(
    unsafe_code,
    reason = "The OS supplies a live terminated thread-local diagnostic; only its bounded prefix is copied"
)]
fn error(raw: *const libc::c_char) -> io::Error {
    let mut bytes = Vec::new();
    let mut truncated = false;
    if !raw.is_null() {
        // SAFETY: original OS diagnostic is terminated and remains live here.
        let n = unsafe { libc::strnlen(raw, 1025) };
        if bytes.try_reserve_exact(n.min(1024)).is_ok() {
            // SAFETY: bounded prefix lies within the original diagnostic.
            bytes.extend_from_slice(unsafe { std::slice::from_raw_parts(raw.cast(), n.min(1024)) });
            truncated = n > 1024;
        } else {
            truncated = true;
        }
    }
    io::Error::other(Diagnostic { bytes, truncated })
}
#[expect(
    unsafe_code,
    reason = "The caller certifies native code; dlopen transfers one NOW/LOCAL reference"
)]
pub(super) unsafe fn load(path: &Path) -> io::Result<NonNull<c_void>> {
    let raw = path.as_os_str().as_bytes();
    if raw.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NUL in library path",
        ));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(
            raw.len()
                .checked_add(1)
                .ok_or(io::ErrorKind::InvalidInput)?,
        )
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    bytes.extend_from_slice(raw);
    bytes.push(0);
    let path = CString::from_vec_with_nul(bytes).map_err(|_| io::ErrorKind::InvalidInput)?;
    // SAFETY: caller certifies native code; the path remains terminated/live.
    unsafe { load_name(&path) }
}
#[expect(
    unsafe_code,
    reason = "Caller certifies native code and loader context; dlopen transfers one original NOW/LOCAL reference"
)]
pub(super) unsafe fn load_name(name: &CStr) -> io::Result<NonNull<c_void>> {
    // SAFETY: trusted code and live terminated native path.
    let handle = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    NonNull::new(handle).ok_or_else(|| {
        // SAFETY: consume the immediately preceding failed dlopen diagnostic.
        error(unsafe { libc::dlerror() })
    })
}
#[expect(
    unsafe_code,
    reason = "The private caller retains a live library; POSIX requires clearing and immediately consuming dlsym diagnostics"
)]
pub(super) fn symbol(handle: NonNull<c_void>, name: &CStr) -> io::Result<*mut c_void> {
    // SAFETY: original reference and static/owned terminated symbol name.
    let (address, diagnostic) = unsafe {
        let _old = libc::dlerror();
        let address = libc::dlsym(handle.as_ptr(), name.as_ptr());
        (address, libc::dlerror())
    };
    if !diagnostic.is_null() || address.is_null() {
        return Err(error(diagnostic));
    }
    Ok(address)
}
#[expect(
    unsafe_code,
    reason = "The private caller consumes exactly one original loader reference, with no later export use"
)]
pub(super) fn close(handle: NonNull<c_void>) -> io::Result<()> {
    // SAFETY: original reference removed from Library before this one attempt.
    if unsafe { libc::dlclose(handle.as_ptr()) } == 0 {
        Ok(())
    } else {
        // SAFETY: capture this close's immediate thread-local diagnostic.
        Err(error(unsafe { libc::dlerror() }))
    }
}
