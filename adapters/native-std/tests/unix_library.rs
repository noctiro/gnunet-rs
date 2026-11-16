//! Real POSIX loader references over this process's already trusted C runtime.
#![cfg(unix)]
use gnunet_native::library::{Diagnostic, Library};
use std::{
    ffi::{CStr, c_void},
    io,
    path::PathBuf,
};
#[expect(
    unsafe_code,
    reason = "dladdr borrows this process's known live getpid export and returns its trusted terminated native loader path"
)]
fn system_library() -> io::Result<PathBuf> {
    // SAFETY: initialized scalar/pointer output, known live C runtime symbol.
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    // SAFETY: getpid is already linked into this test; dladdr is synchronous.
    if unsafe { libc::dladdr(libc::getpid as *const () as *const c_void, &mut info) } == 0
        || info.dli_fname.is_null()
    {
        return Err(io::Error::other("missing original C runtime loader path"));
    }
    // SAFETY: dladdr supplies a terminated path from the retained process image.
    let path = unsafe { CStr::from_ptr(info.dli_fname) };
    use std::os::unix::ffi::OsStrExt;
    let path = PathBuf::from(std::ffi::OsStr::from_bytes(path.to_bytes()));
    if !path.is_absolute() {
        return Err(io::Error::other("C runtime loader path is not absolute"));
    }
    Ok(path)
}
#[test]
#[expect(
    unsafe_code,
    reason = "The OS identifies the already trusted C runtime; getpid uses its exact public C ABI while a loader reference remains owned"
)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions compare actual process identity and independent loader-owner results"
)]
fn explicit_references_preserve_symbols_and_original_diagnostics_until_close() -> io::Result<()> {
    let path = system_library()?;
    // SAFETY: same already trusted system C runtime, normal loader state.
    let (mut first, mut second) = unsafe { (Library::load(&path)?, Library::load(&path)?) };
    let address = second.symbol(c"getpid")?;
    assert!(first.close()?);
    assert!(!first.close()?);
    // SAFETY: exact linked getpid ABI; second retains its native reference.
    let pid = unsafe {
        std::mem::transmute::<*mut c_void, unsafe extern "C" fn() -> libc::pid_t>(address)()
    };
    assert_eq!(
        u32::try_from(pid).map_err(io::Error::other)?,
        std::process::id()
    );
    let failure = second
        .symbol(c"gnunet_native_missing_export_53bfbca2")
        .err()
        .ok_or_else(|| io::Error::other("missing export was found"))?;
    let diagnostic = failure
        .get_ref()
        .and_then(|e| e.downcast_ref::<Diagnostic>())
        .ok_or_else(|| io::Error::other("lost native POSIX diagnostic"))?;
    assert!(!diagnostic.bytes().is_empty());
    assert!(!diagnostic.truncated());
    assert!(second.close()?);
    assert_eq!(
        second
            .symbol(c"getpid")
            .err()
            .ok_or_else(|| io::Error::other("closed owner resolved export"))?
            .kind(),
        io::ErrorKind::NotConnected
    );
    Ok(())
}
