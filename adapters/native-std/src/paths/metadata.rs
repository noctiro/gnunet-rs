//! Original file-object classification and stable filesystem identity observations.
use std::{fs::File, io, mem::size_of, os::windows::io::AsRawHandle};
use windows_sys::Win32::{
    Foundation::SetLastError,
    Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
        FILE_ID_INFO, FILE_TYPE_DISK, FILE_TYPE_UNKNOWN, FileAttributeTagInfo, FileIdInfo,
        GetFileInformationByHandleEx, GetFileType,
    },
    System::SystemServices::IO_REPARSE_TAG_AF_UNIX,
};

#[expect(
    unsafe_code,
    reason = "Native file type and metadata queries borrow one original live File and initialized exact SDK output records"
)]
pub(crate) fn attributes(file: &File) -> io::Result<FILE_ATTRIBUTE_TAG_INFO> {
    let mut value = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: exact matching initialized record; the original file stays live.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileAttributeTagInfo,
            (&mut value as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}
#[expect(
    unsafe_code,
    reason = "GetFileType borrows one original live handle; clearing the documented thread-local error distinguishes unknown type from native failure"
)]
pub(crate) fn disk(file: &File) -> io::Result<bool> {
    // SAFETY: scalar thread-local error state; no pointer or resource transfer.
    unsafe {
        SetLastError(0);
    }
    // SAFETY: the borrowed original handle remains owned throughout.
    let kind = unsafe { GetFileType(file.as_raw_handle()) };
    if kind == FILE_TYPE_UNKNOWN {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(0) {
            return Err(error);
        }
    }
    Ok(kind == FILE_TYPE_DISK)
}
/// Whether this actual handle represents a regular disk-file stream. This does
/// not follow a pathname, prove privacy, or authorize cleanup. AF_UNIX reparse
/// nodes and unopened name-surrogate targets are not ordinary file contents.
pub fn is_regular_file(file: &File) -> io::Result<bool> {
    if !disk(file)? {
        return Ok(false);
    }
    let info = attributes(file)?;
    const NAME_SURROGATE: u32 = 0x2000_0000;
    Ok(info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        && (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
            || info.ReparseTag != IO_REPARSE_TAG_AF_UNIX && info.ReparseTag & NAME_SURROGATE == 0))
}

/// One observed volume/file ID. IDs alone are not live ownership or cleanup
/// authority; actions retain and compare original file handles as well.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct FileIdentity {
    volume: u64,
    id: [u8; 16],
}
impl FileIdentity {
    /// Observed volume identity; the number alone is not a live capability.
    pub const fn volume(self) -> u64 {
        self.volume
    }
    /// Complete observed file ID, without truncating the native 128-bit value.
    pub const fn id(self) -> [u8; 16] {
        self.id
    }
    /// Query the held original object without reopening its pathname.
    ///
    /// # Errors
    /// Preserves native file-information errors. Filesystems returning an empty
    /// ID are refused rather than replaced with a path-based identity.
    #[expect(
        unsafe_code,
        reason = "GetFileInformationByHandleEx fills an exact initialized FILE_ID_INFO for one original borrowed live file"
    )]
    pub fn of(file: &File) -> io::Result<Self> {
        let mut info = FILE_ID_INFO::default();
        // SAFETY: initialized exact output/size and a retained original handle.
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileIdInfo,
                (&mut info as *mut FILE_ID_INFO).cast(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if info.FileId.Identifier == [0; 16] {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "filesystem returned no stable file ID",
            ));
        }
        Ok(Self {
            volume: info.VolumeSerialNumber,
            id: info.FileId.Identifier,
        })
    }
}
