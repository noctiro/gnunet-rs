//! Darwin's exclusive, descriptor-relative directory publication boundary.
use std::{
    ffi::CStr,
    io,
    os::fd::{AsRawFd, BorrowedFd},
};

/// Move one prepared sibling entry without replacing any destination entry.
///
/// Both names must be single nonempty components beneath the same live parent
/// descriptor. The caller owns marker qualification and synchronization. An
/// unsupported filesystem or an existing destination is a real error; this
/// function never falls back to replacing `rename`.
#[expect(
    unsafe_code,
    reason = "renameatx_np borrows a live directory fd and two validated NUL-terminated single-component names"
)]
pub fn publish_noreplace(parent: BorrowedFd<'_>, from: &CStr, to: &CStr) -> io::Result<()> {
    for name in [from, to] {
        let bytes = name.to_bytes();
        if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "directory publication requires sibling component names",
            ));
        }
    }
    // SAFETY: parent remains live for the call; both CStr pointers are valid
    // NUL-terminated names. Neither the fd nor either allocation is transferred.
    // RENAME_EXCL requests the kernel's no-replacement operation, not an
    // existence check followed by an overwriting rename.
    let result = unsafe {
        libc::renameatx_np(
            parent.as_raw_fd(),
            from.as_ptr(),
            parent.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
