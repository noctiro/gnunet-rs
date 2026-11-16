//! Native directory creation and original directory-handle access.
use super::encoding::native_path_length;
use std::{fs::File, io, os::windows::fs::OpenOptionsExt, path::Path};

/// Create missing directories with native path and inherited-security rules.
/// Existing directories, including concurrent creations, succeed. A regular file
/// never counts as a directory. Creation is iterative with borrowed ancestor
/// paths, avoiding recursion and copies of every pathname prefix.
///
/// The absolute path is resolved once and checked for NUL and a finite UTF-16
/// bound before creation. This does not grant an authorization lease: subsequent
/// file opens still enforce their own access rights. Failure preserves the native
/// creation error and can leave already created parents; no rollback removes them.
pub fn create_directory_all(path: &Path) -> io::Result<()> {
    native_path_length(path)?;
    let absolute = std::path::absolute(path)?;
    native_path_length(&absolute)?;
    let mut missing = Vec::new();
    let mut current = absolute.as_path();
    loop {
        match std::fs::create_dir(current) {
            Ok(()) => break,
            Err(error) => {
                if std::fs::metadata(current).is_ok_and(|metadata| metadata.is_dir()) {
                    break;
                }
                if error.kind() != io::ErrorKind::NotFound {
                    return Err(error);
                }
                let Some(parent) = current
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                else {
                    return Err(error);
                };
                missing
                    .try_reserve(1)
                    .map_err(|_| io::ErrorKind::OutOfMemory)?;
                missing.push(current);
                current = parent;
            }
        }
    }
    for path in missing.into_iter().rev() {
        if let Err(error) = std::fs::create_dir(path)
            && !std::fs::metadata(path).is_ok_and(|metadata| metadata.is_dir())
        {
            return Err(error);
        }
    }
    Ok(())
}

/// Open a native directory with traverse access and optional read/list access, following ordinary
/// filesystem reparse resolution. The returned original File owns one handle;
/// metadata is checked on that handle, not on a subsequent pathname lookup.
/// This changes neither permissions nor token privileges.
pub fn open_directory(path: &Path, readable: bool) -> io::Result<File> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ,
    };
    let directory = File::options()
        .access_mode(FILE_GENERIC_EXECUTE | if readable { FILE_GENERIC_READ } else { 0 })
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    if !directory.metadata()?.is_dir() {
        return Err(io::ErrorKind::NotADirectory.into());
    }
    Ok(directory)
}
