//! Synchronous NT opens relative to one original live directory handle.
use super::{leaf::Leaf, status};
use std::{
    fs::File,
    io,
    mem::size_of,
    os::windows::io::{AsRawHandle, FromRawHandle},
    ptr,
};
use windows_sys::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
        },
    },
    Win32::{
        Foundation::INVALID_HANDLE_VALUE,
        Security::SECURITY_DESCRIPTOR,
        Storage::FileSystem::{
            FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, ReOpenFile, SYNCHRONIZE,
        },
        System::IO::IO_STATUS_BLOCK,
    },
};

#[expect(
    unsafe_code,
    reason = "NtCreateFile synchronously borrows an exact SDK object description, bounded native name, optional live security descriptor and original parent; success transfers one noninheritable synchronous file handle"
)]
pub(super) fn child(
    parent: &File,
    leaf: &mut Leaf,
    access: u32,
    share: u32,
    disposition: u32,
    options: u32,
    descriptor: Option<&crate::identity::SecurityDescriptor>,
) -> io::Result<(File, usize)> {
    let mut name = leaf.unicode();
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &mut name,
        Attributes: 0,
        SecurityDescriptor: descriptor.map_or(ptr::null(), |descriptor| {
            descriptor.0.cast::<SECURITY_DESCRIPTOR>().cast_const()
        }),
        SecurityQualityOfService: ptr::null_mut(),
    };
    let mut handle = ptr::null_mut();
    let mut observed = IO_STATUS_BLOCK::default();
    // SAFETY: every input/output remains live through this synchronous call.
    // The leaf cannot traverse, synchronous flags include SYNCHRONIZE through
    // the selected access mask, and no overlapped operation/buffer escapes.
    let result = unsafe {
        NtCreateFile(
            &mut handle,
            access | SYNCHRONIZE,
            &attributes,
            &mut observed,
            ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            share,
            disposition,
            options | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null(),
            0,
        )
    };
    status::check("NtCreateFile", result)?;
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native open returned no original file handle",
        ));
    }
    // SAFETY: successful completed NtCreateFile transfers exactly one owner.
    Ok((
        unsafe { File::from_raw_handle(handle) },
        observed.Information,
    ))
}
#[expect(
    unsafe_code,
    reason = "ReOpenFile obtains one independent synchronous original-object handle without any pathname lookup"
)]
pub(crate) fn reopen(original: &File, access: u32, share: u32, flags: u32) -> io::Result<File> {
    // SAFETY: borrowed original remains live; no OVERLAPPED flag is supplied.
    let handle = unsafe {
        ReOpenFile(
            original.as_raw_handle(),
            access | SYNCHRONIZE,
            share,
            flags & !FILE_FLAG_OVERLAPPED,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful ReOpenFile returned one unique owned file handle.
    Ok(unsafe { File::from_raw_handle(handle) })
}
