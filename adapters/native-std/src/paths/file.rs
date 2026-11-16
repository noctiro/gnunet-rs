//! Native file admission, private creation and ACL-preserving publication.
use super::encoding::{absolute_wide_path, native_path_length};
use crate::identity::private_file_descriptor;
use std::{
    fs::File,
    io,
    os::windows::{ffi::OsStrExt, io::FromRawHandle},
    path::Path,
    ptr,
};

/// Test final-node existence with GetFileAttributesW, including AF_UNIX reparse
/// nodes. This grants no access or liveness evidence. Missing nodes return false;
/// other Win32 errors and invalid native paths remain errors. No target handle
/// is opened and no reparse node is followed to infer a socket's existence.
#[expect(
    unsafe_code,
    reason = "GetFileAttributesW borrows one bounded terminated native path and returns only scalar attributes"
)]
pub fn exists(path: &Path) -> io::Result<bool> {
    use windows_sys::Win32::Storage::FileSystem::GetFileAttributesW;
    use windows_sys::Win32::Storage::FileSystem::INVALID_FILE_ATTRIBUTES;
    let path = absolute_wide_path(path)?;
    // SAFETY: the original UTF-16 allocation stays terminated and live.
    if unsafe { GetFileAttributesW(path.as_ptr()) } != INVALID_FILE_ATTRIBUTES {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        Ok(false)
    } else {
        Err(error)
    }
}

/// Validate an ordinary file leaf and native bounds without filesystem I/O.
/// Alternate streams share base-file security and are not private file targets.
pub fn validate_file_path(path: &Path) -> io::Result<()> {
    if path.file_name().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a file leaf",
        ));
    }
    native_path_length(path)?;
    if path.components().any(|component| matches!(component,
        std::path::Component::Normal(name) if name.encode_wide().any(|unit| unit == u16::from(b':')))) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "alternate data streams cannot have independent private permissions"));
    }
    Ok(())
}

/// Open one existing ordinary disk-file stream for reading. Caller-selected
/// links resolve normally; the returned original handle is checked before data
/// reads. Alternate streams and AF_UNIX nodes are refused. This does not prove
/// content integrity, ownership, privacy or a preemptible filesystem operation.
///
/// # Errors
/// Preserves native open/metadata errors and rejects nonregular handles.
pub fn open_regular_file(path: &Path) -> io::Result<File> {
    validate_file_path(path)?;
    let file = File::open(path)?;
    if !super::metadata::is_regular_file(&file)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a regular disk file",
        ));
    }
    Ok(file)
}

/// Create one new noninheritable disk file with a protected DACL granting only
/// the current primary-token user full control. Existing names are refused by
/// CREATE_NEW; no data is written and no existing ACL or token privilege changes.
/// Alternate data streams are refused: they share their base file's security.
pub fn create_private_file(path: &Path) -> io::Result<File> {
    create_new_file(path, &private_file_descriptor()?)
}

#[expect(
    unsafe_code,
    reason = "CreateFileW borrows live bounded UTF-16 and SECURITY_ATTRIBUTES; a successful unique handle transfers into File and its actual disk type is checked"
)]
pub(super) fn create_new_file(
    path: &Path,
    descriptor: &crate::identity::SecurityDescriptor,
) -> io::Result<File> {
    use windows_sys::Win32::{
        Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE},
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{
            CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        },
    };
    validate_file_path(path)?;
    let name = absolute_wide_path(path)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    // SAFETY: attributes and descriptor remain owned through this synchronous call.
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful CreateFileW returned an owned non-pseudo handle.
    let file = unsafe { File::from_raw_handle(raw) };
    if !super::metadata::is_regular_file(&file)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private output is not a regular disk file",
        ));
    }
    Ok(file)
}

/// Publication policy selected from the caller's destination observation. A
/// raced-in destination is refused by Create; Replace never falls back to Create.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Publication {
    /// Publish at an absent name without replacing a raced-in destination.
    Create,
    /// Replace an existing file while retaining its native ACL and metadata.
    Replace,
}

/// Publish a prepared same-volume file. Existing targets use ReplaceFileW with
/// ACL merge errors enabled; new targets use a no-replacement native move.
/// On failure the caller must preserve any still-named prepared file and inspect
/// both paths: ReplaceFileW can report a partially completed replacement. No
/// automatic fallback or retry can silently drop destination ACLs.
#[expect(
    unsafe_code,
    reason = "ReplaceFileW/MoveFileExW synchronously borrow bounded native paths only; zero flags retain ACL errors and disallow replacement in the new-target branch"
)]
pub fn publish_file(
    temporary: &Path,
    destination: &Path,
    publication: Publication,
) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, ReplaceFileW};
    let source = absolute_wide_path(temporary)?;
    let target = absolute_wide_path(destination)?;
    // SAFETY: paths live through either synchronous native publication call.
    let result = unsafe {
        if publication == Publication::Replace {
            ReplaceFileW(
                target.as_ptr(),
                source.as_ptr(),
                ptr::null(),
                0,
                ptr::null(),
                ptr::null(),
            )
        } else {
            MoveFileExW(source.as_ptr(), target.as_ptr(), 0)
        }
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
