//! Original native directory and private process/identity writer exclusion.
use super::{JournalError, LOCK, Outcome, Stage, invalid, native};
use gnunet_native::{
    DirectorySync,
    filesystem::{Directory, FileIdentity, private_single_file_identity},
};
use std::{
    ffi::OsStr,
    fs::{self, File},
    io,
    path::{Path, PathBuf},
};
pub(super) struct Fence {
    pub directory: PathBuf,
    pub parent: Directory,
    guard: File,
    parent_id: FileIdentity,
    pub identity: FileIdentity,
    pub fresh: bool,
    pub barrier: DirectorySync,
}
impl Fence {
    pub fn open(directory: &Path) -> Result<Self, JournalError> {
        let parent = Directory::open(directory)
            .map_err(|cause| native(Stage::Fence, Outcome::NotCommitted, cause))?;
        Self::adopt(parent, directory)
    }
    pub fn adopt(parent: Directory, selected: &Path) -> Result<Self, JournalError> {
        parent
            .validate_private()
            .map_err(|cause| native(Stage::Fence, Outcome::NotCommitted, cause))?;
        let directory = fs::canonicalize(selected)
            .map_err(|cause| native(Stage::Fence, Outcome::NotCommitted, cause))?;
        let parent_id = FileIdentity::of(parent.as_file())
            .map_err(|cause| native(Stage::Fence, Outcome::NotCommitted, cause))?;
        let (guard, fresh) = match parent.open_file_for_update(OsStr::new(LOCK)) {
            Ok(file) => (file, false),
            Err(cause) if cause.kind() == io::ErrorKind::NotFound => (
                parent
                    .create_private_file(OsStr::new(LOCK))
                    .map_err(|cause| native(Stage::Fence, Outcome::NotCommitted, cause))?,
                true,
            ),
            Err(cause) => return Err(native(Stage::Fence, Outcome::NotCommitted, cause)),
        };
        let identity = private_single_file_identity(&guard)
            .map_err(|cause| native(Stage::Fence, Outcome::NotCommitted, cause))?;
        guard
            .try_lock()
            .map_err(|cause| native(Stage::Fence, Outcome::NotCommitted, cause.into()))?;
        let barrier = parent
            .sync()
            .map_err(|cause| native(Stage::DirectorySync, Outcome::Unknown, cause))?;
        let owner = Self {
            directory,
            parent,
            guard,
            parent_id,
            identity,
            fresh,
            barrier,
        };
        owner.check()?;
        Ok(owner)
    }
    pub fn check(&self) -> Result<(), JournalError> {
        let observed = (|| -> io::Result<bool> {
            let selected = Directory::open(&self.directory)?;
            self.parent.validate_private()?;
            Ok(FileIdentity::of(selected.as_file())? == self.parent_id
                && FileIdentity::of(self.parent.as_file())? == self.parent_id
                && private_single_file_identity(&self.guard)? == self.identity
                && self.parent.same_file(OsStr::new(LOCK), &self.guard)?)
        })()
        .map_err(|cause| native(Stage::Fence, Outcome::Unknown, cause))?;
        if !observed {
            return Err(invalid(
                Stage::Fence,
                Outcome::Unknown,
                "original UDP writer fence or directory changed",
            ));
        }
        Ok(())
    }
    pub fn sync(&self) -> io::Result<DirectorySync> {
        self.parent.sync()
    }
}
