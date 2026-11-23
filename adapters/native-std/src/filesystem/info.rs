//! No-follow entry observations and metadata on held original objects.
use super::{FileIdentity, FileTimes};
use std::{fs::File, io};
/// Complete native identity, size and change observations, excluding access time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileInfo {
    /// Full platform-tagged identity; this is not an object capability.
    pub identity: FileIdentity,
    /// Native data/directory length observation.
    pub bytes: u64,
    /// Native modification and metadata-change fences.
    pub times: FileTimes,
}
/// Observed ordinary file/directory or an unsupported special/name-surrogate entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryInfo {
    /// Actual ordinary file, not a name-surrogate or AF_UNIX node.
    File(FileInfo),
    /// Actual ordinary directory, not a name-surrogate.
    Directory(FileInfo),
    /// A symlink, name-surrogate, socket, pipe or another special object.
    Other,
}
/// Observe a held object without resolving its original pathname. No data is
/// read and native query errors remain errors. Metadata is time-local; callers
/// revalidate around data operations and namespace changes.
pub fn file_info(file: &File) -> io::Result<EntryInfo> {
    #[cfg(unix)]
    {
        let metadata = file.metadata()?;
        if !metadata.is_file() && !metadata.is_dir() {
            return Ok(EntryInfo::Other);
        }
        let info = FileInfo {
            identity: FileIdentity::from_metadata(&metadata),
            bytes: metadata.len(),
            times: FileTimes::from_metadata(&metadata),
        };
        Ok(if metadata.is_dir() {
            EntryInfo::Directory(info)
        } else {
            EntryInfo::File(info)
        })
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        };
        use windows_sys::Win32::System::SystemServices::IO_REPARSE_TAG_AF_UNIX;
        if !crate::paths::metadata::disk(file)? {
            return Ok(EntryInfo::Other);
        }
        let attributes = crate::paths::metadata::attributes(file)?;
        if attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            && (attributes.ReparseTag & 0x2000_0000 != 0
                || attributes.ReparseTag == IO_REPARSE_TAG_AF_UNIX)
        {
            return Ok(EntryInfo::Other);
        }
        let info = FileInfo {
            identity: FileIdentity::of(file)?,
            bytes: file.metadata()?.len(),
            times: super::file_times(file)?,
        };
        Ok(
            if attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                EntryInfo::Directory(info)
            } else {
                EntryInfo::File(info)
            },
        )
    }
}
#[cfg(unix)]
pub(super) fn at(parent: &File, name: &std::ffi::OsStr) -> io::Result<EntryInfo> {
    use nix::{fcntl::AtFlags, sys::stat::fstatat};
    let stat = fstatat(parent, name, AtFlags::AT_SYMLINK_NOFOLLOW)?;
    let kind = super::stat_file_kind(&stat);
    if kind != libc::S_IFREG && kind != libc::S_IFDIR {
        return Ok(EntryInfo::Other);
    }
    let info = FileInfo {
        identity: FileIdentity::from_stat(&stat),
        bytes: u64::try_from(stat.st_size).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "negative native file length")
        })?,
        times: FileTimes {
            modified: i128::from(stat.st_mtime) * 1_000_000_000 + i128::from(stat.st_mtime_nsec),
            changed: i128::from(stat.st_ctime) * 1_000_000_000 + i128::from(stat.st_ctime_nsec),
        },
    };
    Ok(if kind == libc::S_IFDIR {
        EntryInfo::Directory(info)
    } else {
        EntryInfo::File(info)
    })
}
