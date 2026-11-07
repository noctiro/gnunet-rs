//! Physical writer authority, bounded filesystem reads and original temp inode.
use super::{JournalFailure, MAX_BYTES, OWNER_FILE, TEMP_PREFIX};
use gnunet_types::Error;
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct Inode {
    dev: u64,
    ino: u64,
}
impl Inode {
    pub(super) fn of(metadata: &Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    }
}
pub(super) struct Authority {
    pub(super) parent: PathBuf,
    pub(super) directory: File,
    pub(super) directory_id: Inode,
    pub(super) lock: File,
    pub(super) lock_id: Inode,
}
impl Authority {
    pub(super) fn verify(&self) -> Result<(), JournalFailure> {
        let parent = fs::symlink_metadata(&self.parent)
            .map_err(|e| JournalFailure::io("directory-authority", e))?;
        let lock = fs::symlink_metadata(self.parent.join(OWNER_FILE))
            .map_err(|e| JournalFailure::io("lock-authority", e))?;
        let retained_dir = self
            .directory
            .metadata()
            .map_err(|e| JournalFailure::io("retained-directory", e))?;
        let retained_lock = self
            .lock
            .metadata()
            .map_err(|e| JournalFailure::io("retained-lock", e))?;
        if !parent.is_dir()
            || !lock.is_file()
            || parent.file_type().is_symlink()
            || lock.file_type().is_symlink()
            || Inode::of(&parent) != self.directory_id
            || Inode::of(&retained_dir) != self.directory_id
            || Inode::of(&lock) != self.lock_id
            || Inode::of(&retained_lock) != self.lock_id
        {
            return Err(JournalFailure::protocol(
                "physical-authority",
                Error::Conflict,
            ));
        }
        Ok(())
    }
}

pub(super) struct Temporary {
    pub(super) path: PathBuf,
    pub(super) file: File,
    pub(super) inode: Inode,
}
impl Drop for Temporary {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path)
            .is_ok_and(|m| m.is_file() && Inode::of(&m) == self.inode)
        {
            let _cleanup = fs::remove_file(&self.path);
        }
    }
}
pub(super) fn open_data(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}
pub(super) fn read_bounded(file: &mut File) -> Result<Vec<u8>, JournalFailure> {
    let size = file
        .metadata()
        .map_err(|e| JournalFailure::io("read-size", e))?
        .len();
    if size > MAX_BYTES as u64 {
        return Err(JournalFailure::protocol("read-capacity", Error::Capacity));
    }
    let mut raw = Vec::new();
    raw.try_reserve_exact(size as usize)
        .map_err(|_| JournalFailure::protocol("read-allocation", Error::Capacity))?;
    file.take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|e| JournalFailure::io("read", e))?;
    if raw.len() > MAX_BYTES {
        return Err(JournalFailure::protocol("read-growth", Error::Capacity));
    }
    Ok(raw)
}
pub(super) fn temporary_file(parent: &Path) -> Result<Temporary, JournalFailure> {
    for _ in 0..16 {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce)
            .map_err(|_| JournalFailure::protocol("temporary-entropy", Error::Entropy))?;
        let path = parent.join(format!("{TEMP_PREFIX}{:032x}", u128::from_be_bytes(nonce)));
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(file) => {
                let inode = Inode::of(
                    &file
                        .metadata()
                        .map_err(|e| JournalFailure::io("temporary-metadata", e))?,
                );
                return Ok(Temporary { path, file, inode });
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(JournalFailure::io("temporary-open", e)),
        }
    }
    Err(JournalFailure::protocol(
        "temporary-collision",
        Error::Capacity,
    ))
}
