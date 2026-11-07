//! Explicit durable directory ownership and descriptor-only recovery helpers.
use super::FileIdentity;
use super::{DIRECTORY, OutputDir, components, invalid_name};
use crate::{Error, Result};
use nix::{
    fcntl::{OFlag, openat},
    sys::stat::{Mode, mkdirat},
    unistd::{UnlinkatFlags, unlinkat},
};
use std::{
    ffi::OsStr,
    fmt,
    fs::File,
    io::{self, Read, Write},
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    path::Path,
};

/// Reserved per-directory task metadata basename. Durable tree selection must
/// refuse authenticated user entries with this exact basename.
pub const OWNER_MARKER_NAME: &str = ".gnunet-fs-owner-v1";
const MAGIC: &[u8; 8] = b"GNOFOWN1";
const REGULAR: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_NONBLOCK)
    .union(OFlag::O_CLOEXEC);
/// Actual ownership/durability phase reached by a directory operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryStage {
    /// This invocation established neither a new directory nor ownership proof.
    Unverified,
    /// mkdir succeeded, but complete synced owner proof is not established.
    Created,
    /// Exact owner proof was written/read; naming barriers may still be uncertain.
    OwnerVerified,
}
/// Native directory failure retaining observed ownership and creation facts.
#[derive(Debug)]
pub struct OwnedDirectoryFailure {
    /// Actual phase, independently of the original error.
    pub stage: DirectoryStage,
    /// Whether this invocation's own mkdir returned success.
    pub created: bool,
    /// Actual opened directory identity when available.
    pub identity: Option<FileIdentity>,
    /// Original filesystem, identity or ownership refusal.
    pub operation: Error,
}
impl fmt::Display for OwnedDirectoryFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "owned FS directory {:?}: {}", self.stage, self.operation)
    }
}
impl std::error::Error for OwnedDirectoryFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.operation)
    }
}
fn same_name(parent: &File, name: &OsStr, expected: FileIdentity, directory: bool) -> Result<()> {
    let file = File::from(openat(
        parent,
        name,
        if directory { DIRECTORY } else { REGULAR },
        Mode::empty(),
    )?);
    if FileIdentity::of(&file)? != expected
        || (directory && !file.metadata()?.is_dir())
        || (!directory && !file.metadata()?.is_file())
    {
        return Err(Error::SourceChanged);
    }
    Ok(())
}
fn private(file: &File, directory: bool) -> Result<()> {
    let metadata = file.metadata()?;
    if (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(invalid_name());
    }
    Ok(())
}
impl OutputDir {
    /// Identity of this actual directory descriptor, never its old pathname.
    pub fn identity(&self) -> Result<FileIdentity> {
        Ok(FileIdentity::of(&self.root)?)
    }
    pub(super) fn parent_existing(&self, parts: &[&OsStr]) -> Result<File> {
        let mut parent = self.root.try_clone()?;
        for name in parts {
            parent = File::from(openat(&parent, *name, DIRECTORY, Mode::empty())?);
        }
        Ok(parent)
    }
    /// Identity of a relative directory, without creating missing ancestors.
    /// Empty relative bytes denote this anchored directory itself.
    pub fn directory_identity(&self, relative: impl AsRef<Path>) -> Result<FileIdentity> {
        if relative.as_ref().as_os_str().is_empty() {
            return self.identity();
        }
        Ok(FileIdentity::of(
            &self.parent_existing(&components(relative.as_ref())?)?,
        )?)
    }
    /// Create one new 0700 directory and its exclusive synced task-owner marker.
    /// Existing ancestors must already exist; an existing final name is refused.
    /// Failures never remove/adopt a directory through an unverified pathname.
    pub fn create_owned_directory(
        &mut self,
        relative: impl AsRef<Path>,
        owner: [u8; 32],
    ) -> std::result::Result<Self, OwnedDirectoryFailure> {
        let mut stage = DirectoryStage::Unverified;
        let mut created = false;
        let mut identity = None;
        let result = (|| -> Result<Self> {
            let parts = components(relative.as_ref())?;
            let (name, ancestors) = parts.split_last().ok_or_else(invalid_name)?;
            let parent = self.parent_existing(ancestors)?;
            mkdirat(&parent, *name, Mode::S_IRWXU)?;
            created = true;
            stage = DirectoryStage::Created;
            let root = File::from(openat(&parent, *name, DIRECTORY, Mode::empty())?);
            let id = FileIdentity::of(&root)?;
            identity = Some(id);
            private(&root, true)?;
            let mut marker = File::from(openat(
                &root,
                OWNER_MARKER_NAME,
                OFlag::O_WRONLY
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC,
                Mode::S_IRUSR | Mode::S_IWUSR,
            )?);
            let marker_id = FileIdentity::of(&marker)?;
            marker.write_all(MAGIC)?;
            marker.write_all(&owner)?;
            marker.sync_all()?;
            same_name(&root, OsStr::new(OWNER_MARKER_NAME), marker_id, false)?;
            stage = DirectoryStage::OwnerVerified;
            same_name(&parent, name, id, true)?;
            root.sync_all()?;
            parent.sync_all()?;
            same_name(&parent, name, id, true)?;
            Ok(Self { root, nonce: 0 })
        })();
        result.map_err(|operation| OwnedDirectoryFailure {
            stage,
            created,
            identity,
            operation,
        })
    }
    /// Attach only an exact owner-marker directory through anchored no-follow
    /// components. Missing/foreign markers never authorize adoption. None permits
    /// recovery of a matching RootIntent whose identity record was not written.
    pub fn attach_owned_directory(
        &mut self,
        relative: impl AsRef<Path>,
        owner: [u8; 32],
        expected: Option<FileIdentity>,
    ) -> std::result::Result<Self, OwnedDirectoryFailure> {
        let mut stage = DirectoryStage::Unverified;
        let mut identity = None;
        let result = (|| -> Result<Self> {
            let parts = components(relative.as_ref())?;
            let (name, ancestors) = parts.split_last().ok_or_else(invalid_name)?;
            let parent = self.parent_existing(ancestors)?;
            let root = File::from(openat(&parent, *name, DIRECTORY, Mode::empty())?);
            let id = FileIdentity::of(&root)?;
            identity = Some(id);
            if expected.is_some_and(|expected| expected != id) {
                return Err(Error::SourceChanged);
            }
            private(&root, true)?;
            let mut marker = File::from(openat(&root, OWNER_MARKER_NAME, REGULAR, Mode::empty())?);
            private(&marker, false)?;
            let marker_id = FileIdentity::of(&marker)?;
            if marker.metadata()?.len() != 40 {
                return Err(Error::Corrupt);
            }
            let mut bytes = [0; 40];
            marker.read_exact(&mut bytes)?;
            let mut extra = [0];
            loop {
                match marker.read(&mut extra) {
                    Ok(0) => break,
                    Ok(_) => return Err(Error::Corrupt),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e.into()),
                }
            }
            if &bytes[..8] != MAGIC || bytes[8..] != owner {
                return Err(Error::Corrupt);
            }
            same_name(&root, OsStr::new(OWNER_MARKER_NAME), marker_id, false)?;
            stage = DirectoryStage::OwnerVerified;
            marker.sync_all()?;
            same_name(&parent, name, id, true)?;
            root.sync_all()?;
            parent.sync_all()?;
            same_name(&parent, name, id, true)?;
            Ok(Self { root, nonce: 0 })
        })();
        result.map_err(|operation| OwnedDirectoryFailure {
            stage,
            created: false,
            identity,
            operation,
        })
    }
    /// Inspect one actual regular final inode; only actual final-name absence is
    /// None. Missing parents, symlinks and special files preserve their refusal.
    pub fn inspect_file(&self, relative: impl AsRef<Path>) -> Result<Option<FileIdentity>> {
        let parts = components(relative.as_ref())?;
        let (name, ancestors) = parts.split_last().ok_or_else(invalid_name)?;
        let parent = self.parent_existing(ancestors)?;
        let file = match openat(&parent, *name, REGULAR, Mode::empty()) {
            Ok(file) => File::from(file),
            Err(nix::errno::Errno::ENOENT) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if !file.metadata()?.is_file() {
            return Err(invalid_name());
        }
        Ok(Some(FileIdentity::of(&file)?))
    }
    /// Remove only the exact recorded private temporary from its original parent.
    /// Absence can complete cleanup; foreign replacements remain untouched.
    pub fn cleanup_recorded_temp(
        &self,
        relative_temp: impl AsRef<Path>,
        parent_id: FileIdentity,
        temp_id: FileIdentity,
    ) -> Result<()> {
        let parts = components(relative_temp.as_ref())?;
        let (temp_name, ancestors) = parts.split_last().ok_or_else(invalid_name)?;
        let temp_name = *temp_name;
        let raw = temp_name.as_bytes();
        if !raw.starts_with(super::TEMP_PREFIX.as_bytes())
            || raw.contains(&b'/')
            || raw.contains(&0)
            || raw.is_empty()
        {
            return Err(invalid_name());
        }
        let parent = self.parent_existing(ancestors)?;
        if FileIdentity::of(&parent)? != parent_id {
            return Err(Error::SourceChanged);
        }
        match openat(&parent, temp_name, REGULAR, Mode::empty()) {
            Ok(file) => {
                let file = File::from(file);
                if !file.metadata()?.is_file() || FileIdentity::of(&file)? != temp_id {
                    return Err(Error::SourceChanged);
                }
                same_name(&parent, temp_name, temp_id, false)?;
                unlinkat(&parent, temp_name, UnlinkatFlags::NoRemoveDir)?;
            }
            Err(nix::errno::Errno::ENOENT) => {}
            Err(error) => return Err(error.into()),
        }
        parent.sync_all()?;
        Ok(())
    }
    /// Enumerate one existing anchored directory without retaining its children.
    /// Each raw name is bound by no-follow stat; symlinks/special files refuse.
    /// A partial callback prefix is possible on limit/change/refusal. No entry
    /// is removed, and the caller must compare returned facts to its ledger.
    #[cfg(feature = "service")]
    pub(crate) fn visit_children(
        &self,
        relative: &Path,
        max_entries: usize,
        mut visit: impl FnMut(&OsStr, FileIdentity, bool) -> Result<()>,
    ) -> Result<()> {
        use std::os::unix::fs::MetadataExt as _;
        let parts = if relative.as_os_str().is_empty() {
            Vec::new()
        } else {
            components(relative)?
        };
        let parent = self.parent_existing(&parts)?;
        let original = parent.metadata()?;
        let original_id = FileIdentity::of(&parent)?;
        // openat(".") creates an independent open description at offset zero;
        // dup/try_clone alone would share and mutate the caller's readdir cursor.
        let enumeration = openat(&parent, c".", DIRECTORY, Mode::empty())?;
        let mut directory = nix::dir::Dir::from_fd(enumeration)?;
        let mut count = 0;
        for entry in directory.iter() {
            let entry = entry?;
            let bytes = entry.file_name().to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            if count == max_entries {
                return Err(Error::Limit);
            }
            count += 1;
            if bytes.is_empty() || bytes.contains(&0) || bytes.contains(&b'/') {
                return Err(invalid_name());
            }
            let name = OsStr::from_bytes(bytes);
            let actual =
                nix::sys::stat::fstatat(&parent, name, nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW)?;
            let kind = nix::sys::stat::SFlag::from_bits_truncate(actual.st_mode)
                & nix::sys::stat::SFlag::S_IFMT;
            let is_dir = kind == nix::sys::stat::SFlag::S_IFDIR;
            if !is_dir && kind != nix::sys::stat::SFlag::S_IFREG {
                return Err(invalid_name());
            }
            visit(
                name,
                FileIdentity {
                    device: actual.st_dev as u64,
                    inode: actual.st_ino as u64,
                },
                is_dir,
            )?;
        }
        let current = parent.metadata()?;
        if FileIdentity::of(&parent)? != original_id
            || current.len() != original.len()
            || current.mtime() != original.mtime()
            || current.mtime_nsec() != original.mtime_nsec()
            || current.ctime() != original.ctime()
            || current.ctime_nsec() != original.ctime_nsec()
            || FileIdentity::of(&self.parent_existing(&parts)?)? != original_id
        {
            return Err(Error::SourceChanged);
        }
        Ok(())
    }
}
