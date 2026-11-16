//! POSIX directory descriptors; no reconstructed child paths or symlink fallback.
use crate::DirectorySync;
use nix::{
    errno::Errno,
    fcntl::{AtFlags, OFlag, open, openat},
    sys::stat::{Mode, SFlag, fstat, fstatat, mkdirat},
    unistd::{UnlinkatFlags, geteuid, linkat, unlinkat},
};
use std::{
    ffi::OsStr,
    fs::File,
    io,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::Path,
};
const FLAGS: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_DIRECTORY)
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_CLOEXEC);
fn leaf(name: &OsStr) -> io::Result<()> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 255
        || bytes.contains(&0)
        || bytes.contains(&b'/')
        || matches!(bytes, b"." | b"..")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "one ordinary native component required",
        ));
    }
    Ok(())
}
/// Held ordinary directory. Renaming its selected path cannot redirect child
/// operations. Callers serialize administrative changes within that directory.
#[derive(Debug)]
pub struct Directory(File);
/// Qualify a regular file owned by the effective user with no group/other data
/// access. This neither changes permissions nor grants pathname authority.
pub fn validate_private_file(file: &File) -> io::Result<()> {
    private_metadata(file).map(|_| ())
}
pub(super) fn private_metadata(file: &File) -> io::Result<std::fs::Metadata> {
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != geteuid().as_raw() || meta.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private effective-user file required",
        ));
    }
    Ok(meta)
}
impl Directory {
    /// Select a no-follow source directory. POSIX descriptor admission remains
    /// independent of caller-controlled namespace and content exclusion.
    pub fn open_source(path: &Path) -> io::Result<Self> {
        Self::open(path)
    }
    /// Retain the same original source-directory object without path resolution.
    pub fn from_source_file(file: &File) -> io::Result<Self> {
        Self::from_file(file)
    }
    /// Open one no-follow source child through this original parent.
    pub fn open_source_directory(&self, name: &OsStr) -> io::Result<Self> {
        self.open_directory(name)
    }
    /// Open the selected directory without following its final symlink. Ancestors
    /// resolve normally; this selects a root rather than a pathname sandbox.
    pub fn open(path: &Path) -> io::Result<Self> {
        let bytes = path.as_os_str().as_bytes();
        let end = bytes
            .iter()
            .rposition(|b| *b != b'/')
            .map_or(bytes.len().min(1), |p| p + 1);
        Ok(Self(File::from(open(
            OsStr::from_bytes(&bytes[..end]),
            FLAGS,
            Mode::empty(),
        )?)))
    }
    /// Duplicate the original directory descriptor; no path is reopened.
    pub fn from_file(file: &File) -> io::Result<Self> {
        if !file.metadata()?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "directory handle required",
            ));
        }
        Ok(Self(file.try_clone()?))
    }
    /// Borrow the original directory without granting a pathname binding.
    pub fn as_file(&self) -> &File {
        &self.0
    }
    /// Transfer the original directory handle without a pathname lookup.
    pub fn into_file(self) -> File {
        self.0
    }
    /// Inspect one child without following a symlink or opening device contents.
    pub fn entry_info(&self, name: &OsStr) -> io::Result<super::EntryInfo> {
        leaf(name)?;
        super::info::at(&self.0, name)
    }
    /// Enumerate this original directory through an independent native cursor.
    /// Collection, entry validation and change detection remain caller-owned.
    pub fn entries(&self) -> io::Result<super::Entries> {
        super::Entries::open(&self.0)
    }
    /// Duplicate this owner without resolving any pathname.
    pub fn duplicate(&self) -> io::Result<Self> {
        Ok(Self(self.0.try_clone()?))
    }
    /// Qualify the held directory's effective owner and private permissions.
    /// Existing permissions are retained and no path is reopened.
    pub fn validate_private(&self) -> io::Result<()> {
        let meta = self.0.metadata()?;
        if meta.uid() != geteuid().as_raw() || meta.mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private effective-user directory required",
            ));
        }
        Ok(())
    }
    /// Require an effective-user-owned directory without group/other writes.
    /// Read/traverse permission is allowed; this protects names, not file data.
    pub fn validate_namespace(&self) -> io::Result<()> {
        let meta = self.0.metadata()?;
        if meta.uid() != geteuid().as_raw() || meta.mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "effective-user-owned namespace without foreign writes required",
            ));
        }
        Ok(())
    }
    /// Open one existing ordinary child directory without following a symlink.
    pub fn open_directory(&self, name: &OsStr) -> io::Result<Self> {
        leaf(name)?;
        Ok(Self(File::from(openat(
            &self.0,
            name,
            FLAGS,
            Mode::empty(),
        )?)))
    }
    /// Create one owner-only child directory, refusing an existing name.
    /// A later open/metadata failure can leave the new directory present.
    pub fn create_private_directory(&self, name: &OsStr) -> io::Result<Self> {
        leaf(name)?;
        mkdirat(&self.0, name, Mode::S_IRWXU)?;
        self.open_directory(name)
    }
    /// Create an owner-only directory or open an existing ordinary directory.
    /// Existing permissions are retained and require separate qualification.
    pub fn ensure_directory(&self, name: &OsStr) -> io::Result<Self> {
        leaf(name)?;
        match mkdirat(&self.0, name, Mode::S_IRWXU) {
            Ok(()) | Err(Errno::EEXIST) => self.open_directory(name),
            Err(error) => Err(error.into()),
        }
    }
    /// Ensure an effective-user-owned directory with exact private permissions.
    /// Existing permissions are checked rather than silently repaired.
    pub fn ensure_private_directory(&self, name: &OsStr) -> io::Result<Self> {
        let directory = self.ensure_directory(name)?;
        let meta = directory.0.metadata()?;
        if meta.uid() != geteuid().as_raw() || meta.mode() & 0o7777 != 0o700 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private directory owner/mode required",
            ));
        }
        Ok(directory)
    }
    /// Complete an actual directory synchronization request.
    pub fn sync(&self) -> io::Result<DirectorySync> {
        self.0.sync_all()?;
        Ok(DirectorySync::Synchronized)
    }
    /// Exclusively create one private ordinary file, without replacing a name.
    pub fn create_private_file(&self, name: &OsStr) -> io::Result<File> {
        leaf(name)?;
        Ok(File::from(openat(
            &self.0,
            name,
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::S_IRUSR | Mode::S_IWUSR,
        )?))
    }
    /// Open one ordinary child for reading. Nonblocking admission refuses FIFOs
    /// without waiting for a writer; ordinary filesystem I/O can still block.
    pub fn open_file(&self, name: &OsStr) -> io::Result<File> {
        self.open_regular(name, OFlag::O_RDONLY)
    }
    /// Open an existing ordinary stream for data synchronization and updates.
    /// This never creates or truncates the file.
    pub fn open_file_for_update(&self, name: &OsStr) -> io::Result<File> {
        self.open_regular(name, OFlag::O_RDWR)
    }
    /// Open with the access needed for file-data synchronization. Unix supports
    /// synchronization on its ordinary read handle.
    pub fn open_file_for_sync(&self, name: &OsStr) -> io::Result<File> {
        self.open_file(name)
    }
    fn open_regular(&self, name: &OsStr, access: OFlag) -> io::Result<File> {
        leaf(name)?;
        let file = File::from(openat(
            &self.0,
            name,
            access | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?);
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ordinary file required",
            ));
        }
        Ok(file)
    }
    /// Compare a current ordinary file entry with a still-held original object.
    pub fn same_file(&self, name: &OsStr, original: &File) -> io::Result<bool> {
        leaf(name)?;
        let held = fstat(original)?;
        let named = fstatat(&self.0, name, AtFlags::AT_SYMLINK_NOFOLLOW)?;
        Ok(held.st_dev == named.st_dev
            && held.st_ino == named.st_ino
            && SFlag::from_bits_truncate(held.st_mode) == SFlag::S_IFREG
            && SFlag::from_bits_truncate(named.st_mode) == SFlag::S_IFREG)
    }
    /// Atomically replace a child name with the original single-link source.
    /// Callers exclude namespace replacement around POSIX lookup and renameat.
    /// Existing target handles retain their old objects. No data or directory
    /// synchronization is performed; an error can follow visible replacement.
    pub fn replace_file(
        &self,
        source_name: &OsStr,
        original: &File,
        target_name: &OsStr,
    ) -> io::Result<()> {
        leaf(source_name)?;
        leaf(target_name)?;
        if !self.same_file(source_name, original)? || super::file_links(original)? != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "original single-link rename source changed",
            ));
        }
        nix::fcntl::renameat(&self.0, source_name, &self.0, target_name)?;
        if !self.same_file(target_name, original)? {
            return Err(io::Error::other("original replacement target changed"));
        }
        Ok(())
    }
    /// Publish a new hard link from an explicitly held source directory/name.
    /// Existing destinations are refused. Callers serialize source namespace
    /// administration; POSIX linkat selects a name rather than a file handle.
    /// An error after the native request can leave publication uncertain.
    pub fn link_file_from(
        &self,
        source_parent: &Self,
        source_name: &OsStr,
        original: &File,
        name: &OsStr,
    ) -> io::Result<()> {
        leaf(name)?;
        if !source_parent.same_file(source_name, original)? {
            return Err(io::Error::other("original link source changed"));
        }
        linkat(
            &source_parent.0,
            source_name,
            &self.0,
            name,
            AtFlags::empty(),
        )?;
        Ok(())
    }
    /// Remove only a name matching the still-held original. Callers exclude
    /// namespace replacement between POSIX identity lookup and unlinkat.
    /// This performs no directory synchronization.
    pub fn remove_file(&self, name: &OsStr, original: &File) -> io::Result<()> {
        if !self.same_file(name, original)? {
            return Err(io::Error::other("original removal entry changed"));
        }
        unlinkat(&self.0, name, UnlinkatFlags::NoRemoveDir)?;
        Ok(())
    }
}
