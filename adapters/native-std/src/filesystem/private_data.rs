//! Private ordinary data-file qualification on the original object.
use super::FileInfo;
use std::{fs::File, io};

/// Qualify a private, single-link ordinary data file and capture its native fences.
/// Unix requires effective ownership, owner read permission and no executable,
/// special, group or other permission bits. Windows checks process ownership and
/// a restrictive DACL. This observation grants no namespace or mutation authority.
///
/// # Errors
/// Preserves native query failures and refuses an unqualified original file.
pub fn private_data_file_info(file: &File) -> io::Result<FileInfo> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = super::unix::private_metadata(file)?;
        if metadata.mode() & 0o7177 != 0 || metadata.mode() & 0o400 == 0 || metadata.nlink() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private single-link readable data file required",
            ));
        }
        Ok(FileInfo {
            identity: super::FileIdentity::from_metadata(&metadata),
            bytes: metadata.len(),
            times: super::FileTimes::from_metadata(&metadata),
        })
    }
    #[cfg(windows)]
    {
        super::private_single_file_identity(file)?;
        match super::file_info(file)? {
            super::EntryInfo::File(info) => Ok(info),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private ordinary data file required",
            )),
        }
    }
}
