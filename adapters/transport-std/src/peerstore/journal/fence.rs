//! Original directory, full native file identities and private writer exclusion.
use super::{JournalFailure, MAX_BYTES, OWNER_FILE, TEMP_PREFIX};
use gnunet_native::{
    DirectorySync,
    filesystem::{Directory, EntryInfo, FileIdentity, file_info, private_single_file_identity},
};
use gnunet_types::Error;
use std::{
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::{self, Read},
    mem::DropGuard,
    path::{Path, PathBuf},
    sync::Arc,
};
pub(super) type Inode = FileIdentity;
pub(super) struct Authority {
    pub(super) parent: PathBuf,
    pub(super) directory: Directory,
    directory_id: FileIdentity,
    lock: File,
    pub(super) lock_id: FileIdentity,
    pub(super) barrier: DirectorySync,
}
impl Authority {
    pub(super) fn open(parent: &Path) -> Result<Self, JournalFailure> {
        let directory =
            Directory::open(parent).map_err(|cause| JournalFailure::io("directory-open", cause))?;
        directory
            .validate_namespace()
            .map_err(|cause| JournalFailure::io("directory-policy", cause))?;
        let directory_id = FileIdentity::of(directory.as_file())
            .map_err(|cause| JournalFailure::io("directory-id", cause))?;
        let parent = fs::canonicalize(parent)
            .map_err(|cause| JournalFailure::io("directory-name", cause))?;
        let name = OsStr::new(OWNER_FILE);
        let lock = match directory.open_file_for_update(name) {
            Ok(file) => file,
            Err(cause) if cause.kind() == io::ErrorKind::NotFound => directory
                .create_private_file(name)
                .map_err(|cause| JournalFailure::io("lock-create", cause))?,
            Err(cause) => return Err(JournalFailure::io("lock-open", cause)),
        };
        let lock_id = private_single_file_identity(&lock)
            .map_err(|cause| JournalFailure::io("lock-policy", cause))?;
        lock.try_lock().map_err(|cause| match cause {
            fs::TryLockError::Error(cause) => JournalFailure::io("writer-lock", cause),
            cause @ fs::TryLockError::WouldBlock => JournalFailure {
                stage: "writer-lock",
                classification: Error::Conflict,
                io: Some(cause.into()),
                cleanup: None,
            },
        })?;
        let barrier = directory
            .sync()
            .map_err(|cause| JournalFailure::io("directory-sync", cause))?;
        let authority = Self {
            parent,
            directory,
            directory_id,
            lock,
            lock_id,
            barrier,
        };
        authority.verify()?;
        Ok(authority)
    }
    pub(super) fn verify(&self) -> Result<(), JournalFailure> {
        let selected = Directory::open(&self.parent)
            .map_err(|cause| JournalFailure::io("directory-authority", cause))?;
        let named = FileIdentity::of(selected.as_file())
            .map_err(|cause| JournalFailure::io("directory-id", cause))?;
        let held = FileIdentity::of(self.directory.as_file())
            .map_err(|cause| JournalFailure::io("retained-directory", cause))?;
        let lock = FileIdentity::of(&self.lock)
            .map_err(|cause| JournalFailure::io("retained-lock", cause))?;
        let same = self
            .directory
            .same_file(OsStr::new(OWNER_FILE), &self.lock)
            .map_err(|cause| JournalFailure::io("lock-authority", cause))?;
        if named != self.directory_id || held != self.directory_id || lock != self.lock_id || !same
        {
            return Err(JournalFailure::protocol(
                "physical-authority",
                Error::Conflict,
            ));
        }
        self.directory
            .validate_namespace()
            .map_err(|cause| JournalFailure::io("directory-policy", cause))?;
        private_single_file_identity(&self.lock)
            .map_err(|cause| JournalFailure::io("lock-policy", cause))?;
        Ok(())
    }
    pub(super) fn read(
        &self,
        name: &OsStr,
    ) -> Result<Option<(Vec<u8>, FileIdentity)>, JournalFailure> {
        let mut file = match self.directory.open_file(name) {
            Ok(file) => file,
            Err(cause) if cause.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(cause) => return Err(JournalFailure::io("readback-open", cause)),
        };
        let before = match file_info(&file)
            .map_err(|cause| JournalFailure::io("readback-metadata", cause))?
        {
            EntryInfo::File(info) if info.identity != self.lock_id => info,
            _ => return Err(JournalFailure::protocol("readback-kind", Error::Conflict)),
        };
        if before.bytes > MAX_BYTES as u64 {
            return Err(JournalFailure::protocol("read-capacity", Error::Capacity));
        }
        let mut raw = Vec::new();
        raw.try_reserve_exact(before.bytes as usize)
            .map_err(|_| JournalFailure::protocol("read-allocation", Error::Capacity))?;
        raw.resize(before.bytes as usize, 0);
        file.read_exact(&mut raw)
            .map_err(|cause| JournalFailure::io("read", cause))?;
        let mut trailing = [0];
        if file
            .read(&mut trailing)
            .map_err(|cause| JournalFailure::io("read", cause))?
            != 0
        {
            return Err(JournalFailure::protocol("read-growth", Error::Capacity));
        }
        if file_info(&file).map_err(|cause| JournalFailure::io("readback-metadata", cause))?
            != EntryInfo::File(before)
            || !self
                .directory
                .same_file(name, &file)
                .map_err(|cause| JournalFailure::io("readback-name", cause))?
        {
            return Err(JournalFailure::protocol(
                "readback-changed",
                Error::Conflict,
            ));
        }
        Ok(Some((raw, before.identity)))
    }
    pub(super) fn sync(&self) -> Result<DirectorySync, JournalFailure> {
        self.verify()?;
        let observed = self
            .directory
            .sync()
            .map_err(|cause| JournalFailure::io("directory-sync", cause))?;
        self.verify()?;
        Ok(observed)
    }
}
pub(super) struct Temporary {
    authority: Arc<Authority>,
    name: OsString,
    pub(super) file: File,
    pub(super) inode: FileIdentity,
    cleaned: bool,
}
impl Temporary {
    pub(super) fn create(authority: Arc<Authority>) -> Result<Self, JournalFailure> {
        for _ in 0..16 {
            let mut nonce = [0; 16];
            getrandom::fill(&mut nonce)
                .map_err(|_| JournalFailure::protocol("temporary-entropy", Error::Entropy))?;
            let name = OsString::from(format!("{TEMP_PREFIX}{:032x}", u128::from_be_bytes(nonce)));
            let file = match authority.directory.create_private_file(&name) {
                Ok(file) => file,
                Err(cause) if cause.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(cause) => return Err(JournalFailure::io("temporary-open", cause)),
            };
            let mut cleanup = None;
            let pending = DropGuard::new(file, |file| {
                cleanup = discard(&authority.directory, &name, &file).err();
            });
            let inode = match private_single_file_identity(&pending) {
                Ok(inode) => inode,
                Err(cause) => {
                    drop(pending);
                    let mut failure = JournalFailure::io("temporary-metadata", cause);
                    failure.cleanup = cleanup;
                    return Err(failure);
                }
            };
            let file = DropGuard::dismiss(pending);
            return Ok(Self {
                authority,
                name,
                file,
                inode,
                cleaned: false,
            });
        }
        Err(JournalFailure::protocol(
            "temporary-collision",
            Error::Capacity,
        ))
    }
    pub(super) fn publish(&self, target: &OsStr) -> io::Result<()> {
        self.authority
            .directory
            .replace_file(&self.name, &self.file, target)
    }
    pub(super) fn present(&self) -> io::Result<bool> {
        match self.authority.directory.same_file(&self.name, &self.file) {
            Err(cause) if cause.kind() == io::ErrorKind::NotFound => Ok(false),
            result => result,
        }
    }
    pub(super) fn discard(&mut self) -> io::Result<()> {
        self.cleaned = true;
        discard(&self.authority.directory, &self.name, &self.file)
    }
}
fn discard(directory: &Directory, name: &OsStr, file: &File) -> io::Result<()> {
    match directory.remove_file(name, file) {
        Err(cause) if cause.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        if !self.cleaned {
            let _cleanup = self.discard();
        }
    }
}
