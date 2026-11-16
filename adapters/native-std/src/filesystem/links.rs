//! Native hard-link observations on original ordinary files.
use std::{fs::File, io};
/// Observe the native hard-link count without reconstructing a pathname. This
/// time-local count is not namespace authority; callers revalidate mappings.
pub fn file_links(file: &File) -> io::Result<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(file.metadata()?.nlink())
    }
    #[cfg(windows)]
    {
        windows(file)
    }
}
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "GetFileInformationByHandleEx synchronously fills the exact initialized FILE_STANDARD_INFO for one borrowed live original handle"
)]
fn windows(file: &File) -> io::Result<u64> {
    use std::{mem::size_of, os::windows::io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_STANDARD_INFO, FileStandardInfo, GetFileInformationByHandleEx,
    };
    let mut info = FILE_STANDARD_INFO::default();
    // SAFETY: exact initialized SDK structure and original handle remain live.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileStandardInfo,
            (&mut info as *mut FILE_STANDARD_INFO).cast(),
            size_of::<FILE_STANDARD_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(u64::from(info.NumberOfLinks))
}
