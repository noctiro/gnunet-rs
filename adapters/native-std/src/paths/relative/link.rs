//! Atomic no-replacement hard links and identity-checked original-link removal.
use super::{
    leaf::{Leaf, MAX_UNITS},
    open, status,
};
use crate::paths::metadata::{self, FileIdentity};
use std::{
    ffi::OsStr,
    fs::File,
    io,
    mem::{MaybeUninit, offset_of, size_of},
    os::windows::io::AsRawHandle,
    ptr,
};
use windows_sys::{
    Wdk::Storage::FileSystem::{
        FILE_DIRECTORY_FILE, FILE_LINK_INFORMATION, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
        FileLinkInformation, NtSetInformationFile,
    },
    Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{
            DELETE, FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
            FILE_DISPOSITION_INFO_EX, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
            FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            FileDispositionInfoEx, SetFileInformationByHandle,
        },
        System::IO::IO_STATUS_BLOCK,
    },
};
const SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
#[repr(C)]
struct LinkRequest {
    flags: u32,
    root: HANDLE,
    length: u32,
    name: [u16; MAX_UNITS],
}
const _: () = {
    assert!(offset_of!(LinkRequest, flags) == offset_of!(FILE_LINK_INFORMATION, Anonymous));
    assert!(offset_of!(LinkRequest, root) == offset_of!(FILE_LINK_INFORMATION, RootDirectory));
    assert!(offset_of!(LinkRequest, length) == offset_of!(FILE_LINK_INFORMATION, FileNameLength));
    assert!(offset_of!(LinkRequest, name) == offset_of!(FILE_LINK_INFORMATION, FileName));
};

#[expect(
    unsafe_code,
    reason = "A synchronous original-object reopen owns source lifetime; exact SDK-checked link layout and all padding are initialized before NtSetInformationFile borrows the bounded request and output"
)]
pub(super) fn create(parent: &File, source: &File, name: &OsStr) -> io::Result<()> {
    let leaf = Leaf::new(name)?;
    let source = open::reopen(
        source,
        FILE_GENERIC_READ | DELETE,
        SHARE,
        FILE_FLAG_OPEN_REPARSE_POINT,
    )?;
    if !metadata::is_regular_file(&source)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ordinary source file required",
        ));
    }
    let mut request = MaybeUninit::<LinkRequest>::zeroed();
    let value = request.as_mut_ptr();
    // SAFETY: initialized stable backing, exact field offsets checked above;
    // the native call borrows it before any move/drop. No padding is uninitialized.
    unsafe {
        ptr::addr_of_mut!((*value).root).write(parent.as_raw_handle());
        ptr::addr_of_mut!((*value).length).write((leaf.units().len() * 2) as u32);
        ptr::copy_nonoverlapping(
            leaf.units().as_ptr(),
            ptr::addr_of_mut!((*value).name).cast::<u16>(),
            leaf.units().len(),
        );
    }
    let length = (offset_of!(LinkRequest, name) + leaf.units().len() * 2)
        .max(size_of::<FILE_LINK_INFORMATION>());
    let mut observed = IO_STATUS_BLOCK::default();
    // SAFETY: source was reopened synchronously; all original handles and exact
    // request/output storage remain live until this metadata operation completes.
    let result = unsafe {
        NtSetInformationFile(
            source.as_raw_handle(),
            &mut observed,
            value.cast(),
            length as u32,
            FileLinkInformation,
        )
    };
    status::check("NtSetInformationFile(FileLinkInformation)", result)
}

pub(super) fn remove(parent: &File, name: &OsStr, original: &File) -> io::Result<()> {
    remove_link(parent, name, original, FILE_NON_DIRECTORY_FILE)
}

pub(crate) fn remove_directory(parent: &File, name: &OsStr, original: &File) -> io::Result<()> {
    remove_link(parent, name, original, FILE_DIRECTORY_FILE)
}

fn remove_link(parent: &File, name: &OsStr, original: &File, kind: u32) -> io::Result<()> {
    let mut leaf = Leaf::new(name)?;
    let (file, _) = open::child(
        parent,
        &mut leaf,
        FILE_GENERIC_READ | DELETE,
        SHARE,
        FILE_OPEN,
        kind,
        None,
    )?;
    if kind == FILE_DIRECTORY_FILE {
        super::Directory::from_file(&file)?;
    } else if !metadata::is_regular_file(&file)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ordinary file required",
        ));
    }
    if FileIdentity::of(&file)? != FileIdentity::of(original)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "named file no longer matches its held original",
        ));
    }
    dispose(&file)
}

pub(crate) fn remove_special(parent: &File, name: &OsStr) -> io::Result<()> {
    let mut leaf = Leaf::new(name)?;
    let (file, _) = open::child(
        parent,
        &mut leaf,
        FILE_READ_ATTRIBUTES | DELETE,
        SHARE,
        FILE_OPEN,
        0,
        None,
    )?;
    if crate::filesystem::file_info(&file)? != crate::filesystem::EntryInfo::Other {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "special entry required",
        ));
    }
    dispose(&file)
}

#[expect(
    unsafe_code,
    reason = "SetFileInformationByHandle synchronously borrows an exact initialized disposition record for the captured and identity-checked original link handle"
)]
fn dispose(file: &File) -> io::Result<()> {
    let information = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    };
    // SAFETY: this exact original named-link handle stays live through the
    // synchronous call. Later pathname replacements cannot retarget its owner.
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfoEx,
            (&information as *const FILE_DISPOSITION_INFO_EX).cast(),
            size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
