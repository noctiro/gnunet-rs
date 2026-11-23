//! One original physical file-lock owner, without process-local substitutes.
use std::{
    fs::{File, TryLockError},
    io,
    mem::DropGuard,
};
/// A nonblocking exclusive whole-file lock on one original native file. The
/// file is never unlinked by this owner. Native file closure releases the lock;
/// no duplicate lock-file handles are created here.
#[derive(Debug)]
pub struct ExclusiveFile {
    file: File,
}
impl ExclusiveFile {
    /// Lock this original file using Rust's native flock/LockFileEx backend.
    /// Contention remains WouldBlock; other failures preserve their I/O source.
    pub fn try_lock(file: File) -> Result<Self, TryLockError> {
        file.try_lock()?;
        Ok(Self { file })
    }
    /// Lock the guarded original without cloning its handle. On failure the
    /// guard runs its rollback with that original; on success it is dismissed.
    pub fn try_lock_guarded(
        file: DropGuard<File, impl FnOnce(File)>,
    ) -> Result<Self, TryLockError> {
        file.try_lock()?;
        Ok(Self {
            file: DropGuard::dismiss(file),
        })
    }
    /// Borrow the original locked file. Cloning this handle or issuing another
    /// lock/unlock changes native ownership semantics and is caller-controlled.
    #[must_use]
    pub fn as_file(&self) -> &File {
        &self.file
    }
    /// Synchronize the actual lock file, independently of namespace barriers.
    pub fn sync_all(&self) -> io::Result<()> {
        self.file.sync_all()
    }
}
