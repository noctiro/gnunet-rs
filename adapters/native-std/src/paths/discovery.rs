//! Native system and primary-token profile path discovery.
use super::encoding::MAX_PATH_UNITS;
use crate::identity::primary_token;
use std::{
    ffi::OsString,
    io,
    os::windows::{ffi::OsStringExt, io::AsRawHandle},
    path::PathBuf,
    ptr,
};
use windows_sys::Win32::{
    Foundation::ERROR_INSUFFICIENT_BUFFER, UI::Shell::GetUserProfileDirectoryW,
};

/// Obtain the native system-directory path through GetSystemDirectoryW. No
/// environment spelling is substituted. This is a path observation, not an open
/// directory or write capability. Native failures retain their Win32 code.
#[expect(
    unsafe_code,
    reason = "GetSystemDirectoryW fills initialized bounded UTF-16 storage; the returned length is validated before copying into an owned native path"
)]
pub fn system_directory() -> io::Result<PathBuf> {
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
    let mut buffer = Vec::new();
    let mut capacity = 260;
    for _ in 0..3 {
        buffer
            .try_reserve_exact(capacity - buffer.len())
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        buffer.resize(capacity, 0);
        // SAFETY: the initialized allocation has the exact supplied writable extent.
        let count = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), capacity as u32) } as usize;
        if count == 0 {
            return Err(io::Error::last_os_error());
        }
        if count < capacity {
            if buffer[..count].contains(&0) {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let path = PathBuf::from(OsString::from_wide(&buffer[..count]));
            if !path.is_absolute() {
                return Err(io::ErrorKind::InvalidData.into());
            }
            return Ok(path);
        }
        capacity = count.max(capacity + 1);
        if capacity > MAX_PATH_UNITS + 1 {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::Interrupted,
        "system directory changed during bounded query",
    ))
}

/// Query the actual primary-token user's profile directory. The token is owned
/// for both native calls and closes once. At most 32768 UTF-16 units, including
/// NUL, are admitted; lookup races retain the second call's original error.
/// No directory is opened, created or authenticated by this observation.
#[expect(
    unsafe_code,
    reason = "GetUserProfileDirectoryW borrows one live query-token handle and bounded initialized UTF-16 output; no native allocation or pointer escapes"
)]
pub fn profile_directory() -> io::Result<PathBuf> {
    let token = primary_token()?;
    let mut count = 0;
    // SAFETY: null output plus zero capacity requests the required WCHAR count.
    let sized =
        unsafe { GetUserProfileDirectoryW(token.as_raw_handle(), ptr::null_mut(), &mut count) };
    let error = io::Error::last_os_error();
    if sized != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "profile query supplied no path storage",
        ));
    }
    if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
        return Err(error);
    }
    if !(2..=32768).contains(&count) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid native profile path capacity",
        ));
    }
    let mut path = Vec::new();
    path.try_reserve_exact(count as usize)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    path.resize(count as usize, 0_u16);
    // SAFETY: count is the full initialized output capacity, in WCHAR units.
    if unsafe { GetUserProfileDirectoryW(token.as_raw_handle(), path.as_mut_ptr(), &mut count) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    let length = count as usize;
    if length < 2 || length > path.len() || path[length - 1] != 0 || path[..length - 1].contains(&0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid native profile path extent",
        ));
    }
    let path = PathBuf::from(OsString::from_wide(&path[..length - 1]));
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native profile path is not absolute",
        ));
    }
    Ok(path)
}
