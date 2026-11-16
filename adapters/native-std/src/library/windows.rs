//! Windows loader calls; all handles originate in this module's successful load.
use std::{
    ffi::{CStr, c_void},
    io,
    path::Path,
    ptr::NonNull,
};
use windows_sys::Win32::{
    Foundation::FreeLibrary,
    System::LibraryLoader::{
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_PIN, GetModuleHandleExW,
        GetProcAddress, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
        LoadLibraryExW,
    },
};
#[expect(
    unsafe_code,
    reason = "The caller certifies DLL code; one successful native reference transfers into Library"
)]
pub(super) unsafe fn load(path: &Path) -> io::Result<NonNull<c_void>> {
    let path = crate::paths::absolute_wide_path(path)?;
    // SAFETY: live bounded terminated path, reserved hFile NULL, trusted code.
    let handle = unsafe {
        LoadLibraryExW(
            path.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };
    NonNull::new(handle).ok_or_else(io::Error::last_os_error)
}
#[expect(
    unsafe_code,
    reason = "GetProcAddress borrows one live owned library reference and terminated export name"
)]
pub(super) fn symbol(handle: NonNull<c_void>, name: &CStr) -> io::Result<*mut c_void> {
    // SAFETY: private caller retains the original live loader reference.
    let address = unsafe { GetProcAddress(handle.as_ptr(), name.as_ptr().cast()) }
        .ok_or_else(io::Error::last_os_error)?;
    Ok(address as *const () as *mut c_void)
}
#[expect(
    unsafe_code,
    reason = "Release consumes exactly one original loader reference after all export use ends"
)]
pub(super) fn close(handle: NonNull<c_void>) -> io::Result<()> {
    // SAFETY: original reference, now removed from the owning Library.
    if unsafe { FreeLibrary(handle.as_ptr()) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[expect(
    unsafe_code,
    reason = "FROM_ADDRESS selects the exact live owned module mapping; PIN retains its native code/storage for the process lifetime without another name lookup"
)]
pub(super) fn pin_for_process(handle: NonNull<c_void>) -> io::Result<()> {
    let mut pinned = std::ptr::null_mut();
    // SAFETY: the caller retains its original loader reference; FROM_ADDRESS
    // interprets this live module-base address as an address, never a string.
    let result = unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
            handle.as_ptr().cast(),
            &mut pinned,
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    if pinned != handle.as_ptr() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native process pin selected a different module",
        ));
    }
    Ok(())
}
