//! FreeBSD native operations on the original directory descriptor.
use super::{Directory, unix::leaf};
use nix::NixPath;
use std::{ffi::OsStr, io, os::fd::AsRawFd, sync::OnceLock};

type RenameAt2 = unsafe extern "C" fn(
    libc::c_int,
    *const libc::c_char,
    libc::c_int,
    *const libc::c_char,
    libc::c_uint,
) -> libc::c_int;

/// Try a kernel-enforced exclusive rename. A kernel or userland without this
/// operation leaves both names untouched and returns `Ok(false)`.
#[expect(
    unsafe_code,
    reason = "Call the optional FreeBSD libc entry point with the published signature, live directory descriptor and two validated C strings"
)]
pub(super) fn rename_noreplace(parent: &Directory, from: &OsStr, to: &OsStr) -> io::Result<bool> {
    leaf(from)?;
    leaf(to)?;
    static RENAME: OnceLock<Option<RenameAt2>> = OnceLock::new();
    let rename = *RENAME.get_or_init(|| {
        // SAFETY: RTLD_DEFAULT covers the permanently linked libc. Consume
        // the thread-local loader diagnostic even when the symbol is absent.
        let (symbol, error) = unsafe {
            libc::dlerror();
            let symbol = libc::dlsym(libc::RTLD_DEFAULT, c"renameat2".as_ptr());
            (symbol, libc::dlerror())
        };
        if symbol.is_null() || !error.is_null() {
            None
        } else {
            // SAFETY: dlsym returned the non-null address of the libc function.
            Some(unsafe { std::mem::transmute::<*mut libc::c_void, RenameAt2>(symbol) })
        }
    });
    let Some(rename) = rename else {
        return Ok(false);
    };
    let fd = parent.as_file().as_raw_fd();
    let result = from.with_nix_path(|from| {
        to.with_nix_path(|to| {
            // SAFETY: the validated C strings and directory are live through
            // the synchronous syscall. No pointer or fd ownership transfers.
            unsafe { rename(fd, from.as_ptr(), fd, to.as_ptr(), libc::RENAME_NOREPLACE) }
        })
    })??;
    if result == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENOSYS | libc::EOPNOTSUPP) => Ok(false),
        _ => Err(error),
    }
}
