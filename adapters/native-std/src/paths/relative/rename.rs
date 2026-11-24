//! Atomic renames of captured links under one retained directory.
use super::{
    Directory,
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
        Foundation::{ERROR_SHARING_VIOLATION, HANDLE},
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

pub(super) enum Mode {
    Create,
    Replace,
}

enum EntryKind {
    File,
    Directory,
}

/// The checked synchronous handle to the original captured link.
struct RenameSource(File);

impl RenameSource {
    fn open(
        parent: &File,
        name: &OsStr,
        original: &File,
        kind: EntryKind,
        share: u32,
    ) -> io::Result<Self> {
        let mut source = Leaf::new(name)?;
        let options = match kind {
            EntryKind::File => FILE_NON_DIRECTORY_FILE,
            EntryKind::Directory => FILE_DIRECTORY_FILE,
        };
        let (file, _) = open::child(
            parent,
            &mut source,
            FILE_GENERIC_READ | DELETE,
            share,
            FILE_OPEN,
            options,
            None,
        )?;
        if FileIdentity::of(&file)? != FileIdentity::of(original)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "original rename source changed",
            ));
        }
        match kind {
            EntryKind::File => {
                if !metadata::is_regular_file(&file)? || crate::filesystem::file_links(&file)? != 1
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "original single-link rename source required",
                    ));
                }
            }
            EntryKind::Directory => super::Directory::validate_handle(&file)?,
        }
        Ok(Self(file))
    }
}

pub(super) fn regular_file(
    parent: &File,
    name: &OsStr,
    original: &File,
    target: &OsStr,
    mode: Mode,
) -> io::Result<()> {
    let target = Leaf::new(target)?;
    let source = RenameSource::open(
        parent,
        name,
        original,
        EntryKind::File,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    )?;
    rename(parent, &source, &target, mode)
}

/// Exclusive DELETE access to one original directory link. Other owners may
/// read and write the directory with compatible sharing, but cannot claim or
/// rename the link until this lease closes.
pub struct DirectoryClaim<'a> {
    parent: &'a Directory,
    original: &'a Directory,
    source: RenameSource,
}

impl Directory {
    /// Claim the original directory link without acquiring any child handles.
    /// Incompatible native sharing returns `WouldBlock`.
    pub fn claim_directory<'a>(
        &'a self,
        name: &OsStr,
        original: &'a Directory,
    ) -> io::Result<DirectoryClaim<'a>> {
        let source = RenameSource::open(
            self.as_file(),
            name,
            original.as_file(),
            EntryKind::Directory,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
        )
        .map_err(|error| {
            if error
                .get_ref()
                .and_then(|cause| cause.downcast_ref::<status::StatusError>())
                .is_some_and(|cause| cause.win32_code() == ERROR_SHARING_VIOLATION)
            {
                io::Error::new(io::ErrorKind::WouldBlock, error)
            } else {
                error
            }
        })?;
        Ok(DirectoryClaim {
            parent: self,
            original,
            source,
        })
    }
}

impl DirectoryClaim<'_> {
    /// Publish at an absent name while retaining the exclusive link lease.
    /// Close all open child handles before calling this method.
    pub fn publish(&self, target: &OsStr) -> io::Result<()> {
        let leaf = Leaf::new(target)?;
        if self
            .parent
            .same_directory(target, self.original)
            .is_ok_and(|same| same)
        {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        rename(self.parent.as_file(), &self.source, &leaf, Mode::Create)?;
        // Never classify an error after the native rename as a collision.
        match self.parent.same_directory(target, self.original) {
            Ok(true) => Ok(()),
            Ok(false) => Err(io::Error::other("published original directory changed")),
            Err(error) => Err(io::Error::other(error)),
        }
    }
}

#[expect(
    unsafe_code,
    reason = "NtSetInformationFile synchronously borrows a fully initialized, SDK-layout-checked bounded rename record and an identity-checked synchronous original link handle"
)]
fn rename(parent: &File, source: &RenameSource, target: &Leaf, mode: Mode) -> io::Result<()> {
    let flags = match mode {
        Mode::Create => 0,
        Mode::Replace => FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS,
    };
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
            source.0.as_raw_handle(),
            &mut observed,
            value.cast(),
            length as u32,
            FileRenameInformationEx,
        )
    };
    status::check("NtSetInformationFile(FileRenameInformationEx)", result)
}
