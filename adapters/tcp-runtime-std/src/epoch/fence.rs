//! Original native parent and non-replaced kernel writer fence.
use super::{Failure, Outcome, Stage, failure};
use gnunet_native::{
    DirectorySync,
    filesystem::{Directory, ExclusiveFile, FileIdentity, private_single_file_identity},
};
use std::{
    cell::Cell,
    ffi::OsString,
    fs, io,
    path::{Path, PathBuf},
};
pub(super) struct Fence {
    pub parent: Directory,
    pub name: OsString,
    path: PathBuf,
    guard_name: OsString,
    guard: ExclusiveFile,
    parent_id: FileIdentity,
    pub guard_id: FileIdentity,
    pub barrier: Cell<DirectorySync>,
}
impl Fence {
    pub fn open(path: &Path) -> Result<Self, Failure> {
        let map = |cause| failure(Stage::Fence, Outcome::NotCommitted, cause);
        gnunet_service_runtime::private_parents(path).map_err(map)?;
        let parent_path = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = Directory::open(parent_path).map_err(map)?;
        parent.validate_namespace().map_err(map)?;
        let selected = fs::canonicalize(parent_path).map_err(map)?;
        let name = path
            .file_name()
            .ok_or_else(|| map(io::ErrorKind::InvalidInput.into()))?
            .to_owned();
        let mut guard_name = name.clone();
        guard_name.push(".tcp-lock");
        let guard = match parent.open_file_for_update(&guard_name) {
            Ok(file) => file,
            Err(cause) if cause.kind() == io::ErrorKind::NotFound => {
                parent.create_private_file(&guard_name).map_err(map)?
            }
            Err(cause) => return Err(map(cause)),
        };
        let guard_id = private_single_file_identity(&guard).map_err(map)?;
        let guard = ExclusiveFile::try_lock(guard).map_err(|cause| map(cause.into()))?;
        let parent_id = FileIdentity::of(parent.as_file()).map_err(map)?;
        let barrier = parent
            .sync()
            .map_err(|cause| failure(Stage::DirectorySync, Outcome::Unknown, cause))?;
        let owner = Self {
            parent,
            name,
            path: selected,
            guard_name,
            guard,
            parent_id,
            guard_id,
            barrier: Cell::new(barrier),
        };
        owner.check()?;
        Ok(owner)
    }
    pub fn check(&self) -> Result<(), Failure> {
        let map = |cause| failure(Stage::Fence, Outcome::Unknown, cause);
        self.parent.validate_namespace().map_err(map)?;
        let selected = Directory::open(&self.path).map_err(map)?;
        selected.validate_namespace().map_err(map)?;
        if FileIdentity::of(selected.as_file()).map_err(map)? != self.parent_id
            || FileIdentity::of(self.parent.as_file()).map_err(map)? != self.parent_id
            || private_single_file_identity(self.guard.as_file()).map_err(map)? != self.guard_id
            || !self
                .parent
                .same_file(&self.guard_name, self.guard.as_file())
                .map_err(map)?
        {
            return Err(map(io::Error::other(
                "original TCP frontier fence/namespace changed",
            )));
        }
        Ok(())
    }
    pub fn sync(&self) -> io::Result<DirectorySync> {
        let observed = self.parent.sync()?;
        self.barrier.set(observed);
        Ok(observed)
    }
}
