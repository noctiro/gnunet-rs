//! Actual Windows loader references and export lookup; no external DLL fixture.
#![cfg(windows)]
use gnunet_native::library::Library;
use std::{
    ffi::{OsString, c_void},
    io,
    os::windows::ffi::OsStringExt,
    path::PathBuf,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleW};

fn system_library() -> io::Result<PathBuf> {
    let name = "kernel32.dll\0".encode_utf16().collect::<Vec<_>>();
    let mut path = vec![0; 32768];
    #[expect(
        unsafe_code,
        reason = "Kernel32 is already loaded by this ordinary native Rust executable; the borrowed module handle is never adopted or released"
    )]
    // SAFETY: the terminated module name and initialized writable path are live.
    let length = unsafe {
        let handle = GetModuleHandleW(name.as_ptr());
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        GetModuleFileNameW(handle, path.as_mut_ptr(), path.len() as u32)
    } as usize;
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    if length >= path.len() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(PathBuf::from(OsString::from_wide(&path[..length])))
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Known system exports independently check native ABI, original Win32 errors and retained loader ownership"
)]
fn owned_native_loader_references_retain_exports_and_original_errors() -> io::Result<()> {
    let path = system_library()?;
    #[expect(
        unsafe_code,
        reason = "The path identifies this process's already trusted Windows Kernel32; this test uses only its documented thread-safe ABI and retains its own references"
    )]
    // SAFETY: normal system loader state and the native system DLL are trusted.
    let (first, mut second) = unsafe { (Library::load(&path)?, Library::load(&path)?) };
    let address = second.symbol(c"GetCurrentProcessId")?;
    drop(first);
    #[expect(
        unsafe_code,
        reason = "The named Windows export has the documented no-argument WINAPI u32 ABI, and second retains its loader reference through the call"
    )]
    // SAFETY: exact function ABI and module lifetime are independently known.
    let process_id = unsafe {
        let function =
            std::mem::transmute::<*mut c_void, unsafe extern "system" fn() -> u32>(address);
        function()
    };
    assert_eq!(process_id, std::process::id());
    let error = second
        .symbol(c"gnunet_native_missing_export_88aeff79")
        .err()
        .ok_or_else(|| io::Error::other("nonexistent export was found"))?;
    assert_eq!(error.raw_os_error(), Some(127)); // ERROR_PROC_NOT_FOUND
    assert!(second.close()?);
    assert!(!second.close()?);
    assert_eq!(
        second
            .symbol(c"GetCurrentProcessId")
            .err()
            .ok_or_else(|| io::Error::other("closed owner resolved an export"))?
            .kind(),
        io::ErrorKind::NotConnected
    );
    #[expect(
        unsafe_code,
        reason = "A relative path is rejected before executing any loader code, so no external DLL trust is needed on this error path"
    )]
    // SAFETY: this input cannot reach LoadLibraryExW.
    let error = unsafe { Library::load(std::path::Path::new("kernel32.dll")) }
        .err()
        .ok_or_else(|| io::Error::other("relative DLL path was accepted"))?;
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    Ok(())
}
