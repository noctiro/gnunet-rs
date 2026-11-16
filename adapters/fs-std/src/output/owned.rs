//! Explicit directory ownership and original-handle recovery helpers.
use super::FileIdentity;
use super::{OutputDir, components, invalid_name};
use crate::{Error, Result};
use gnunet_native::filesystem::{Directory, validate_private_file};
use std::{
    ffi::OsStr,
    fmt,
    io::{self, Read, Write},
    path::Path,
};

/// Reserved per-directory task metadata basename. Durable tree selection must
/// refuse authenticated user entries with this exact basename.
pub const OWNER_MARKER_NAME: &str = ".gnunet-fs-owner-v1";
const MAGIC: &[u8; 8] = b"GNOFOWN1";
/// Actual ownership/creation phase reached by a directory operation.
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
fn same_name(
    parent: &Directory,
    name: &OsStr,
    expected: FileIdentity,
    directory: bool,
) -> Result<()> {
    let actual = if directory {
        FileIdentity::of(parent.open_directory(name)?.as_file())?
    } else {
        FileIdentity::of(&parent.open_file(name)?)?
    };
    if actual != expected {
        return Err(Error::SourceChanged);
    }
    Ok(())
}
impl OutputDir {
    /// Identity of this actual directory handle, never its old pathname.
    pub fn identity(&self) -> Result<FileIdentity> {
        Ok(FileIdentity::of(self.root.as_file())?)
    }
    pub(super) fn parent_existing(&self, parts: &[&OsStr]) -> Result<Directory> {
        let mut parent = self.root.duplicate()?;
        for name in parts {
            parent = parent.open_directory(name)?;
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
            self.parent_existing(&components(relative.as_ref())?)?
                .as_file(),
        )?)
    }
    /// Create one native private directory and its exclusive synced owner marker.
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
            let root = parent.create_private_directory(name)?;
            created = true;
            stage = DirectoryStage::Created;
            let id = FileIdentity::of(root.as_file())?;
            identity = Some(id);
            root.validate_private()?;
            let mut marker = root.create_private_file(OsStr::new(OWNER_MARKER_NAME))?;
            let marker_id = FileIdentity::of(&marker)?;
            marker.write_all(MAGIC)?;
            marker.write_all(&owner)?;
            marker.sync_all()?;
            same_name(&root, OsStr::new(OWNER_MARKER_NAME), marker_id, false)?;
            stage = DirectoryStage::OwnerVerified;
            same_name(&parent, name, id, true)?;
            root.sync()?;
            parent.sync()?;
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
            let root = parent.open_directory(name)?;
            let id = FileIdentity::of(root.as_file())?;
            identity = Some(id);
            if expected.is_some_and(|expected| expected != id) {
                return Err(Error::SourceChanged);
            }
            root.validate_private()?;
            let mut marker = root.open_file_for_sync(OsStr::new(OWNER_MARKER_NAME))?;
            validate_private_file(&marker)?;
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
            root.sync()?;
            parent.sync()?;
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
        let file = match parent.open_file(name) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
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
        if !super::temporary_name_valid(temp_name) {
            return Err(invalid_name());
        }
        let parent = self.parent_existing(ancestors)?;
        if FileIdentity::of(parent.as_file())? != parent_id {
            return Err(Error::SourceChanged);
        }
        match parent.open_file(temp_name) {
            Ok(file) => {
                if !file.metadata()?.is_file() || FileIdentity::of(&file)? != temp_id {
                    return Err(Error::SourceChanged);
                }
                same_name(&parent, temp_name, temp_id, false)?;
                parent.remove_file(temp_name, &file)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        parent.sync()?;
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
        use gnunet_native::filesystem::{EntryInfo, file_info};
        let parts = if relative.as_os_str().is_empty() {
            Vec::new()
        } else {
            components(relative)?
        };
        let parent = self.parent_existing(&parts)?;
        let original = file_info(parent.as_file())?;
        for (count, entry) in parent.entries()?.enumerate() {
            if count == max_entries {
                return Err(Error::Limit);
            }
            let name = entry?;
            let (actual, is_dir) = match parent.entry_info(&name)? {
                EntryInfo::Directory(info) => (info, true),
                EntryInfo::File(info) => (info, false),
                EntryInfo::Other => return Err(invalid_name()),
            };
            visit(&name, actual.identity, is_dir)?;
        }
        if file_info(parent.as_file())? != original
            || file_info(self.parent_existing(&parts)?.as_file())? != original
        {
            return Err(Error::SourceChanged);
        }
        Ok(())
    }
}
