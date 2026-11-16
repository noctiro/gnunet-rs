//! Original private directory, writer lock and anchored WAL namespace.
use super::{Failure, native, protocol};
use gnunet_native::{
    DirectorySync,
    filesystem::{Directory, FileIdentity, private_single_file_identity},
};
use gnunet_types::Error;
use std::{
    ffi::{OsStr, OsString},
    fs::{self, File},
    io,
    path::{Path, PathBuf},
};
const LOCK: &str = ".peerstore-rust.lock";
const WAL: &str = "records.wal";
pub(super) struct Files {
    path: PathBuf,
    directory: Directory,
    directory_id: FileIdentity,
    lock: File,
    lock_id: FileIdentity,
    pub(super) file: File,
    file_id: FileIdentity,
    pub(super) directory_sync: DirectorySync,
}
fn open(directory: &Directory, name: &OsStr) -> io::Result<File> {
    match directory.open_file_for_update(name) {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            directory.create_private_file(name)
        }
        Err(error) => Err(error),
    }
}
impl Files {
    pub(super) fn open(path: &Path) -> Result<Self, Failure> {
        gnunet_service_runtime::private_parents(&path.join(WAL))
            .map_err(|error| native("private-directory", error))?;
        let directory = Directory::open(path).map_err(|error| native("directory-open", error))?;
        directory
            .validate_private()
            .map_err(|error| native("directory-private", error))?;
        let directory_id =
            FileIdentity::of(directory.as_file()).map_err(|error| native("directory-id", error))?;
        let path = fs::canonicalize(path).map_err(|error| native("directory-name", error))?;
        let lock =
            open(&directory, OsStr::new(LOCK)).map_err(|error| native("lock-open", error))?;
        let lock_id =
            private_single_file_identity(&lock).map_err(|error| native("lock-id", error))?;
        lock.try_lock().map_err(|error| match error {
            fs::TryLockError::Error(error) => native("writer-lock", error),
            error @ fs::TryLockError::WouldBlock => Failure {
                stage: "writer-lock",
                classification: Error::Conflict,
                io: Some(error.into()),
                cleanup: None,
            },
        })?;
        let file = open(&directory, OsStr::new(WAL)).map_err(|error| native("wal-open", error))?;
        let file_id =
            private_single_file_identity(&file).map_err(|error| native("wal-id", error))?;
        if file_id == lock_id {
            return Err(protocol("wal-lock-alias", Error::Conflict));
        }
        let directory_sync = directory
            .sync()
            .map_err(|error| native("directory-sync", error))?;
        let files = Self {
            path,
            directory,
            directory_id,
            lock,
            lock_id,
            file,
            file_id,
            directory_sync,
        };
        files
            .verify()
            .map_err(|error| native("open-authority", error))?;
        Ok(files)
    }
    pub(super) fn verify(&self) -> io::Result<()> {
        let selected = Directory::open(&self.path)?;
        if FileIdentity::of(selected.as_file())? != self.directory_id
            || FileIdentity::of(self.directory.as_file())? != self.directory_id
            || FileIdentity::of(&self.lock)? != self.lock_id
            || FileIdentity::of(&self.file)? != self.file_id
            || !self.directory.same_file(OsStr::new(LOCK), &self.lock)?
            || !self.directory.same_file(OsStr::new(WAL), &self.file)?
        {
            return Err(io::Error::other(
                "original physical PEERSTORE authority changed",
            ));
        }
        Ok(())
    }
    pub(super) fn sync_directory(&mut self) -> io::Result<()> {
        self.directory_sync = self.directory_sync.combine(self.directory.sync()?);
        Ok(())
    }
    pub(super) fn staging(&self, nonce: [u8; 16]) -> io::Result<(OsString, File)> {
        let name = OsString::from(format!(
            ".peerstore-tmp-{:032x}",
            u128::from_be_bytes(nonce)
        ));
        let file = self.directory.create_private_file(&name)?;
        Ok((name, file))
    }
    pub(super) fn publish(&mut self, name: &OsStr, original: &File) -> io::Result<()> {
        self.directory
            .replace_file(name, original, OsStr::new(WAL))?;
        self.sync_directory()
    }
    pub(super) fn install(&mut self, original: File) -> io::Result<()> {
        self.file_id = private_single_file_identity(&original)?;
        self.file = original;
        self.verify()
    }
    pub(super) fn discard(&self, name: &OsStr, original: &File) -> io::Result<()> {
        match self.directory.remove_file(name, original) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}
