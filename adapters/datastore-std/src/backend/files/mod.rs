//! Original directories and writer ownership, independent of host path APIs.
mod format;
mod garbage;
mod object;
mod temporary;
#[cfg(test)]
mod tests;
use super::Error;
use gnunet_native::{
    DirectorySync,
    filesystem::{Directory, Entries, ExclusiveFile, FileIdentity, private_single_file_identity},
};
use gnunet_types::Error as ProtocolError;
use std::{
    ffi::OsStr,
    fs::{self, File, TryLockError},
    io,
    path::{Path, PathBuf},
};
pub(super) use temporary::Temporary;
pub(super) const WAL: &str = "transactions.wal";
pub(super) const SNAPSHOT: &str = "index.snapshot";
const LOCK: &str = ".writer.lock";
const VALUES: &str = "values";

pub(super) struct Files {
    path: PathBuf,
    parent: Directory,
    root_name: std::ffi::OsString,
    root: Directory,
    values: Directory,
    pub(super) wal: File,
    lock: ExclusiveFile,
    root_id: FileIdentity,
    values_id: FileIdentity,
    wal_id: FileIdentity,
    lock_id: FileIdentity,
    snapshot_pin: Option<File>,
    snapshot_candidate: Option<File>,
    garbage: Option<Entries>,
    garbage_root: Option<Entries>,
    garbage_values_done: bool,
    nonce: u64,
    names: Naming,
}
#[derive(Default)]
struct Naming {
    parent: Option<DirectorySync>,
    root: Option<DirectorySync>,
    values: Option<DirectorySync>,
}
impl Files {
    pub(super) fn open(path: &Path) -> Result<Self, Error> {
        let name = path
            .file_name()
            .ok_or_else(|| Error::protocol("root-name", ProtocolError::InvalidInput))?;
        let parent_path = fs::canonicalize(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )
        .map_err(|e| Error::io("root-parent", e))?;
        let parent = Directory::open(&parent_path).map_err(|e| Error::io("root-parent-open", e))?;
        let root = parent
            .ensure_private_directory(name)
            .map_err(|e| Error::io("root-open", e))?;
        let lock = open_update(&root, LOCK)?;
        let lock_id =
            private_single_file_identity(&lock).map_err(|e| Error::io("writer-metadata", e))?;
        let lock = match ExclusiveFile::try_lock(lock) {
            Ok(lock) => lock,
            Err(TryLockError::WouldBlock) => {
                return Err(Error::protocol("writer-busy", ProtocolError::Conflict));
            }
            Err(TryLockError::Error(error)) => return Err(Error::io("writer-lock", error)),
        };
        format::ensure(&root)?;
        let values = root
            .ensure_private_directory(OsStr::new(VALUES))
            .map_err(|e| Error::io("values-open", e))?;
        let wal = open_update(&root, WAL)?;
        let wal_id =
            private_single_file_identity(&wal).map_err(|e| Error::io("wal-metadata", e))?;
        let root_id =
            FileIdentity::of(root.as_file()).map_err(|e| Error::io("root-metadata", e))?;
        let values_id =
            FileIdentity::of(values.as_file()).map_err(|e| Error::io("values-metadata", e))?;
        let mut files = Self {
            path: parent_path.join(name),
            parent,
            root_name: name.to_owned(),
            root,
            values,
            wal,
            lock,
            root_id,
            values_id,
            wal_id,
            lock_id,
            snapshot_pin: None,
            snapshot_candidate: None,
            garbage: None,
            garbage_root: None,
            garbage_values_done: false,
            nonce: 0,
            names: Naming::default(),
        };
        files.snapshot_pin = files.snapshot()?;
        files.verify()?;
        files.sync_names()?;
        Ok(files)
    }
    pub(super) fn verify(&self) -> Result<(), Error> {
        self.root
            .validate_private()
            .map_err(|e| Error::io("root-private", e))?;
        self.values
            .validate_private()
            .map_err(|e| Error::io("values-private", e))?;
        let named_root = Directory::open(&self.path).map_err(|e| Error::io("root-authority", e))?;
        let parent_root = self
            .parent
            .open_directory(&self.root_name)
            .map_err(|e| Error::io("root-parent-authority", e))?;
        for (file, expected) in [
            (self.root.as_file(), self.root_id),
            (named_root.as_file(), self.root_id),
            (parent_root.as_file(), self.root_id),
            (self.values.as_file(), self.values_id),
        ] {
            if FileIdentity::of(file).map_err(|e| Error::io("directory-authority", e))? != expected
            {
                return Err(Error::protocol(
                    "directory-authority",
                    ProtocolError::Conflict,
                ));
            }
        }
        for (name, original, expected) in [
            (LOCK, self.lock.as_file(), self.lock_id),
            (WAL, &self.wal, self.wal_id),
        ] {
            if private_single_file_identity(original).map_err(|e| Error::io("held-authority", e))?
                != expected
                || !self
                    .root
                    .same_file(OsStr::new(name), original)
                    .map_err(|e| Error::io("named-authority", e))?
            {
                return Err(Error::protocol("named-authority", ProtocolError::Conflict));
            }
        }
        let values = self
            .root
            .open_directory(OsStr::new(VALUES))
            .map_err(|e| Error::io("values-authority", e))?;
        if FileIdentity::of(values.as_file())
            .map_err(|e| Error::io("values-authority-metadata", e))?
            != self.values_id
        {
            return Err(Error::protocol("values-authority", ProtocolError::Conflict));
        }
        let snapshot = self
            .snapshot()?
            .as_ref()
            .map(private_single_file_identity)
            .transpose()
            .map_err(|e| Error::io("snapshot-authority", e))?;
        let selected = self
            .snapshot_pin
            .as_ref()
            // An applied replacement can unlink the old image before returning
            // an error. Its still-held object continues to pin the old ID.
            .map(FileIdentity::of)
            .transpose()
            .map_err(|e| Error::io("snapshot-held-authority", e))?;
        let candidate = self
            .snapshot_candidate
            .as_ref()
            .map(FileIdentity::of)
            .transpose()
            .map_err(|e| Error::io("snapshot-held-candidate", e))?;
        if snapshot != selected && !candidate.is_some_and(|id| snapshot == Some(id)) {
            return Err(Error::protocol(
                "snapshot-authority",
                ProtocolError::Conflict,
            ));
        }
        Ok(())
    }
    pub(super) fn snapshot(&self) -> Result<Option<File>, Error> {
        // Windows requires write access for FlushFileBuffers during recovery.
        match self.root.open_file_for_sync(OsStr::new(SNAPSHOT)) {
            Ok(file) => {
                private_single_file_identity(&file).map_err(|e| Error::io("snapshot-kind", e))?;
                Ok(Some(file))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::io("snapshot-open", e)),
        }
    }
    pub(super) fn install_snapshot(&mut self, temporary: &mut Temporary) -> Result<(), Error> {
        temporary.verify()?;
        self.verify()?;
        self.snapshot_candidate = Some(
            temporary
                .file
                .try_clone()
                .map_err(|e| Error::io("snapshot-pin-candidate", e))?,
        );
        self.dirty(false);
        // A failed native replacement may already have changed the namespace.
        // Never clean up or retry the candidate by name after this point.
        temporary.published = true;
        self.root
            .replace_file(
                OsStr::new(&temporary.name),
                &temporary.file,
                OsStr::new(SNAPSHOT),
            )
            .map_err(|e| Error::io("snapshot-rename", e))?;
        let installed = self.snapshot()?.ok_or_else(|| {
            Error::protocol("installed-snapshot-missing", ProtocolError::Conflict)
        })?;
        if private_single_file_identity(&installed)
            .map_err(|e| Error::io("installed-snapshot-metadata", e))?
            != temporary.identity
        {
            return Err(Error::protocol(
                "installed-snapshot-authority",
                ProtocolError::Conflict,
            ));
        }
        self.snapshot_pin = Some(installed);
        self.sync_names()?;
        self.snapshot_candidate = None;
        Ok(())
    }
    pub(super) fn adopt_snapshot(&mut self) -> Result<(), Error> {
        self.snapshot_pin = self.snapshot()?;
        self.snapshot_candidate = None;
        Ok(())
    }
    pub(super) fn sync_names(&mut self) -> Result<(), Error> {
        for (directory, observation, stage) in [
            (&self.values, &mut self.names.values, "values-sync"),
            (&self.root, &mut self.names.root, "root-sync"),
            (&self.parent, &mut self.names.parent, "root-parent-sync"),
        ] {
            if observation.is_none() {
                *observation = Some(directory.sync().map_err(|e| Error::io(stage, e))?);
            }
        }
        Ok(())
    }
    fn dirty(&mut self, values: bool) {
        if values {
            self.names.values = None;
        } else {
            self.names.root = None;
        }
    }
    pub(super) fn directory_sync(&self) -> Option<DirectorySync> {
        let observations = [self.names.parent?, self.names.root?, self.names.values?];
        Some(if observations.contains(&DirectorySync::Unavailable) {
            DirectorySync::Unavailable
        } else {
            DirectorySync::Synchronized
        })
    }
}
fn open_update(directory: &Directory, name: &str) -> Result<File, Error> {
    match directory.open_file_for_update(OsStr::new(name)) {
        Ok(file) => Ok(file),
        Err(e) if e.kind() == io::ErrorKind::NotFound => directory
            .create_private_file(OsStr::new(name))
            .map_err(|e| Error::io("file-create", e)),
        Err(e) => Err(Error::io("file-open", e)),
    }
}
