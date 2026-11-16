//! Original-link atomic replacement under one retained directory.
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
        FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_RENAME_INFORMATION,
        FILE_RENAME_POSIX_SEMANTICS, FILE_RENAME_REPLACE_IF_EXISTS, FileRenameInformationEx,
        NtSetInformationFile,
    },
    Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{
            DELETE, FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        },
        System::IO::IO_STATUS_BLOCK,
    },
};

#[repr(C)]
struct Request {
    flags: u32,
    root: HANDLE,
    length: u32,
    name: [u16; MAX_UNITS],
}
const _: () = {
    assert!(offset_of!(Request, flags) == offset_of!(FILE_RENAME_INFORMATION, Anonymous));
    assert!(offset_of!(Request, root) == offset_of!(FILE_RENAME_INFORMATION, RootDirectory));
    assert!(offset_of!(Request, length) == offset_of!(FILE_RENAME_INFORMATION, FileNameLength));
    assert!(offset_of!(Request, name) == offset_of!(FILE_RENAME_INFORMATION, FileName));
};

pub(super) fn replace(
    parent: &File,
    name: &OsStr,
    original: &File,
    target: &OsStr,
) -> io::Result<()> {
    let mut source = Leaf::new(name)?;
    let target = Leaf::new(target)?;
    let (file, _) = open::child(
        parent,
        &mut source,
        FILE_GENERIC_READ | DELETE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
        None,
    )?;
    if !metadata::is_regular_file(&file)?
        || FileIdentity::of(&file)? != FileIdentity::of(original)?
        || crate::filesystem::file_links(&file)? != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "original single-link rename source changed",
        ));
    }
    rename(
        parent,
        &file,
        &target,
        FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS,
    )
}

pub(crate) fn publish_directory(
    parent: &File,
    name: &OsStr,
    original: &File,
    target: &OsStr,
) -> io::Result<()> {
    let mut source = Leaf::new(name)?;
    let target = Leaf::new(target)?;
    let (file, _) = open::child(
        parent,
        &mut source,
        FILE_GENERIC_READ | DELETE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_DIRECTORY_FILE,
        None,
    )?;
    // Directory's checked constructor refuses name-surrogate reparse points.
    super::Directory::from_file(&file)?;
    if FileIdentity::of(&file)? != FileIdentity::of(original)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "original directory rename source changed",
        ));
    }
    rename(parent, &file, &target, 0)
}

#[expect(
    unsafe_code,
    reason = "NtSetInformationFile synchronously borrows a fully initialized, SDK-layout-checked bounded rename record and an identity-checked synchronous original link handle"
)]
fn rename(parent: &File, file: &File, target: &Leaf, flags: u32) -> io::Result<()> {
    let mut request = MaybeUninit::<Request>::zeroed();
    let value = request.as_mut_ptr();
    // SAFETY: the entire record, including padding, is initialized; all field
    // offsets match the SDK and the validated name fits its fixed backing.
    unsafe {
        ptr::addr_of_mut!((*value).flags).write(flags);
        ptr::addr_of_mut!((*value).root).write(parent.as_raw_handle());
        ptr::addr_of_mut!((*value).length).write((target.units().len() * 2) as u32);
        ptr::copy_nonoverlapping(
            target.units().as_ptr(),
            ptr::addr_of_mut!((*value).name).cast::<u16>(),
            target.units().len(),
        );
    }
    let length = (offset_of!(Request, name) + target.units().len() * 2)
        .max(size_of::<FILE_RENAME_INFORMATION>());
    let mut observed = IO_STATUS_BLOCK::default();
    // SAFETY: original parent, synchronous source, request backing and exact
    // status output stay live through this synchronous metadata operation.
    let result = unsafe {
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut observed,
            value.cast(),
            length as u32,
            FileRenameInformationEx,
        )
    };
    status::check("NtSetInformationFile(FileRenameInformationEx)", result)
}
