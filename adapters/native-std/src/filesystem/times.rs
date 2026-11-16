//! Original-handle change fences; access-time changes are deliberately excluded.
use std::{fs::File, io};
/// Nanosecond-scaled native filesystem times. Their epoch is platform-specific;
/// compare only within one native identity, never as portable wall-clock values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileTimes {
    /// Native last-data-modification value.
    pub modified: i128,
    /// Native metadata-change value.
    pub changed: i128,
}
#[cfg(unix)]
impl FileTimes {
    /// Derive native fences from the same Unix metadata snapshot used for size
    /// and identity, without another filesystem query.
    pub fn from_metadata(meta: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            modified: i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec()),
            changed: i128::from(meta.ctime()) * 1_000_000_000 + i128::from(meta.ctime_nsec()),
        }
    }
}
/// Query change fences on a still-held original file or directory. Native
/// metadata failures remain errors; no pathname or timestamp substitute is used.
pub fn file_times(file: &File) -> io::Result<FileTimes> {
    #[cfg(unix)]
    {
        let meta = file.metadata()?;
        Ok(FileTimes::from_metadata(&meta))
    }
    #[cfg(windows)]
    {
        windows(file)
    }
}
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "GetFileInformationByHandleEx fills one exact initialized SDK output for a live original file"
)]
fn windows(file: &File) -> io::Result<FileTimes> {
    use std::{mem::size_of, os::windows::io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_BASIC_INFO, FileBasicInfo, GetFileInformationByHandleEx,
    };
    let mut info = FILE_BASIC_INFO::default();
    // SAFETY: original remains borrowed, and exact initialized output and size
    // stay live through the synchronous native metadata request.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileBasicInfo,
            (&mut info as *mut FILE_BASIC_INFO).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(FileTimes {
        modified: i128::from(info.LastWriteTime) * 100,
        changed: i128::from(info.ChangeTime) * 100,
    })
}
