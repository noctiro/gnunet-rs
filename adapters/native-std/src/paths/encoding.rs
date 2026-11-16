//! Bounded native path validation and lossless UTF-16 encoding.
use std::{io, os::windows::ffi::OsStrExt, path::Path};
pub(super) const MAX_PATH_UNITS: usize = 32767;

pub(super) fn native_path_length(path: &Path) -> io::Result<usize> {
    let mut length = 0;
    for unit in path.as_os_str().encode_wide() {
        if unit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "NUL in native file path",
            ));
        }
        length += 1;
        if length > MAX_PATH_UNITS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native path exceeds UTF-16 bound",
            ));
        }
    }
    Ok(length)
}

/// Resolve a native path into one owned NUL-terminated UTF-16 buffer. Embedded
/// NUL and paths above 32767 code units are refused. Long ordinary drive/UNC
/// paths gain a verbatim prefix; existing verbatim namespaces are preserved.
/// This performs no file access and no Unicode replacement or UTF-8 conversion.
pub fn absolute_wide_path(path: &Path) -> io::Result<Vec<u16>> {
    use std::path::{Component, Prefix};
    native_path_length(path)?;
    let absolute = std::path::absolute(path)?;
    let length = native_path_length(&absolute)?;
    // Extend long ordinary drive/UNC paths without rewriting verbatim namespaces.
    let (prefix, skip) = if length >= 260 {
        match absolute.components().next() {
            Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_)) => ("\\\\?\\", 0),
            Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::UNC(..)) => {
                ("\\\\?\\UNC\\", 2)
            }
            _ => ("", 0),
        }
    } else {
        ("", 0)
    };
    let length = length + prefix.len() - skip;
    if length > MAX_PATH_UNITS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native path exceeds UTF-16 bound",
        ));
    }
    let mut wide = Vec::new();
    wide.try_reserve_exact(length + 1)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    wide.extend(prefix.encode_utf16());
    wide.extend(absolute.as_os_str().encode_wide().skip(skip));
    wide.push(0);
    Ok(wide)
}
