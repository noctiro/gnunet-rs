//! Descriptor-bound writer authority, shared by process and per-peer scopes.
use super::{JournalError, LOCK, Outcome, Stage, invalid, native};
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub(super) struct Fence {
    pub directory: PathBuf,
    parent: File,
    guard: File,
    parent_id: (u64, u64),
    pub identity: (u64, u64),
}
impl Fence {
    pub fn open(directory: &Path) -> Result<Self, JournalError> {
        let directory = fs::canonicalize(directory)
            .map_err(|e| native(Stage::Fence, Outcome::NotCommitted, e))?;
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&directory)
            .map_err(|e| native(Stage::Fence, Outcome::NotCommitted, e))?;
        let metadata = parent
            .metadata()
            .map_err(|e| native(Stage::Fence, Outcome::NotCommitted, e))?;
        let parent_id = (metadata.dev(), metadata.ino());
        let guard = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(directory.join(LOCK))
            .map_err(|e| native(Stage::Fence, Outcome::NotCommitted, e))?;
        guard
            .try_lock()
            .map_err(|e| native(Stage::Fence, Outcome::NotCommitted, e.into()))?;
        let metadata = guard
            .metadata()
            .map_err(|e| native(Stage::Fence, Outcome::NotCommitted, e))?;
        let owner = Self {
            directory,
            parent,
            guard,
            parent_id,
            identity: (metadata.dev(), metadata.ino()),
        };
        owner.check()?;
        Ok(owner)
    }
    pub fn check(&self) -> Result<(), JournalError> {
        let observed = || -> io::Result<bool> {
            let parent = fs::symlink_metadata(&self.directory)?;
            let held_parent = self.parent.metadata()?;
            let actual = fs::symlink_metadata(self.directory.join(LOCK))?;
            let held = self.guard.metadata()?;
            Ok(parent.is_dir()
                && held_parent.is_dir()
                && (parent.dev(), parent.ino()) == self.parent_id
                && (held_parent.dev(), held_parent.ino()) == self.parent_id
                && actual.is_file()
                && held.is_file()
                && actual.nlink() == 1
                && held.nlink() == 1
                && (actual.dev(), actual.ino()) == self.identity
                && (held.dev(), held.ino()) == self.identity)
        };
        if !observed().map_err(|e| native(Stage::Fence, Outcome::Unknown, e))? {
            return Err(invalid(
                Stage::Fence,
                Outcome::Unknown,
                "original UDP writer fence or parent changed",
            ));
        }
        Ok(())
    }
    pub fn sync(&self) -> io::Result<()> {
        self.parent.sync_all()
    }
}
