//! Native directory flush qualified by the filesystem of the held object.
use super::{open, status};
use crate::DirectorySync;
use std::{fs::File, io, mem::size_of, os::windows::io::AsRawHandle, ptr};
use windows_sys::{
    Wdk::{
        Storage::FileSystem::{
            FileFsDeviceInformation, NtFlushBuffersFileEx, NtQueryVolumeInformationFile,
        },
        System::SystemServices::{
            FILE_FS_DEVICE_INFORMATION, FILE_REMOTE_DEVICE, FILE_REMOTE_DEVICE_VSMB,
        },
    },
    Win32::{
        Foundation::{ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION, STATUS_SUCCESS},
        Storage::FileSystem::{
            FILE_APPEND_DATA, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA,
            GetVolumeInformationByHandleW,
        },
        System::IO::IO_STATUS_BLOCK,
    },
};

/// A writable lease of the original directory on a qualified local NTFS volume.
struct LocalDirectory(File);

impl LocalDirectory {
    fn open(original: &File) -> io::Result<Option<Self>> {
        if !is_local_ntfs(original)? {
            return Ok(None);
        }
        let reopen = |access| {
            open::reopen(
                original,
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            )
        };
        let reopened = match reopen(FILE_WRITE_DATA) {
            // The flush also accepts FILE_APPEND_DATA (FILE_ADD_SUBDIRECTORY).
            Err(error) if error.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => {
                reopen(FILE_APPEND_DATA)
            }
            result => result,
        };
        match reopened {
            Ok(directory) => Ok(Some(Self(directory))),
            // Directory access or a read-only source fence can exclude the lease.
            Err(error)
                if error.raw_os_error().is_some_and(|code| {
                    matches!(code as u32, ERROR_ACCESS_DENIED | ERROR_SHARING_VIOLATION)
                }) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    #[expect(
        unsafe_code,
        reason = "NtFlushBuffersFileEx uses the live synchronous directory handle and one status block"
    )]
    fn flush(self) -> io::Result<DirectorySync> {
        let mut observed = IO_STATUS_BLOCK::default();
        // SAFETY: the qualified directory is owned until the synchronous flush returns.
        let result = unsafe {
            NtFlushBuffersFileEx(self.0.as_raw_handle(), 0, ptr::null(), 0, &mut observed)
        };
        status::check("NtFlushBuffersFileEx(directory)", result)?;
        if result != STATUS_SUCCESS {
            return Err(io::Error::other(
                "directory flush returned without synchronous completion",
            ));
        }
        Ok(DirectorySync::Synchronized)
    }
}

pub(super) fn directory(original: &File) -> io::Result<DirectorySync> {
    match LocalDirectory::open(original)? {
        Some(directory) => directory.flush(),
        None => Ok(DirectorySync::Unavailable),
    }
}

#[expect(
    unsafe_code,
    reason = "volume queries borrow the original live handle and write only bounded SDK outputs"
)]
pub(super) fn is_local_ntfs(original: &File) -> io::Result<bool> {
    let mut filesystem = [0_u16; 32];
    // SAFETY: the filesystem name is the only requested output and fits the
    // supplied initialized buffer. The native call does no pathname lookup.
    let found = unsafe {
        GetVolumeInformationByHandleW(
            original.as_raw_handle(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    };
    if found == 0 {
        return Err(io::Error::last_os_error());
    }
    if !filesystem.starts_with(&[b'N' as u16, b'T' as u16, b'F' as u16, b'S' as u16, 0]) {
        return Ok(false);
    }

    let mut device = FILE_FS_DEVICE_INFORMATION::default();
    let mut observed = IO_STATUS_BLOCK::default();
    // SAFETY: the handle and ABI-sized outputs remain live for this synchronous
    // fixed-size query of the same original directory.
    let result = unsafe {
        NtQueryVolumeInformationFile(
            original.as_raw_handle(),
            &mut observed,
            (&raw mut device).cast(),
            size_of::<FILE_FS_DEVICE_INFORMATION>() as u32,
            FileFsDeviceInformation,
        )
    };
    status::check(
        "NtQueryVolumeInformationFile(FileFsDeviceInformation)",
        result,
    )?;
    if result != STATUS_SUCCESS || observed.Information != size_of::<FILE_FS_DEVICE_INFORMATION>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incomplete directory volume device information",
        ));
    }
    Ok(device.Characteristics & (FILE_REMOTE_DEVICE | FILE_REMOTE_DEVICE_VSMB) == 0)
}
