//! Ownership guards for service-created filesystem paths.
#![forbid(unsafe_code)]
use std::{
    fs, io,
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
};

/// Remove an owned path on drop only while its device and inode still match.
///
/// Callers must capture only paths they own and exclude hostile concurrent path
/// replacement during metadata/unlink. This guard detects an already replaced
/// inode; it does not make the separate metadata and unlink syscalls atomic.
#[derive(Debug)]
pub struct CreatedPath {
    path: PathBuf,
    device: u64,
    inode: u64,
}
impl CreatedPath {
    /// Path whose observed inode this guard owns.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub(crate) fn from_observed(path: PathBuf, device: u64, inode: u64) -> Self {
        Self {
            path,
            device,
            inode,
        }
    }
    /// Observe the current inode of a newly created, caller-owned path.
    pub fn capture(path: PathBuf) -> io::Result<Self> {
        let metadata = fs::symlink_metadata(&path)?;
        Ok(Self {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    /// Remove the observed inode, or leave an absent/replaced path alone.
    /// The guard remains armed; subsequent drop repeats the same identity check.
    pub fn remove(&self) -> io::Result<()> {
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) if metadata.dev() == self.device && metadata.ino() == self.inode => {
                fs::remove_file(&self.path)
            }
            Ok(_) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}
impl Drop for CreatedPath {
    fn drop(&mut self) {
        match self.remove() {
            Ok(()) | Err(_) => {}
        }
    }
}

fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}
/// Create missing parent directories with mode 0700; existing directories keep
/// their permissions. Existing path components follow normal OS path resolution.
/// A parentless relative path uses the current directory.
pub fn private_parents(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent(path))
}
