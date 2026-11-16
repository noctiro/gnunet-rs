//! Native namespace publication and explicit directory synchronization receipts.
use std::{fs, io, path::Path};

pub use gnunet_native::DirectorySync;

/// Real namespace operations, separate from the snapshot file's `sync_all`.
/// Implementations perform the requested rename/removal and preserve errors.
/// Directory barriers return an explicit observation; an unavailable primitive
/// must never be represented by `DirectorySync::Synchronized`.
pub trait CommitBackend {
    /// Replace the destination with the complete same-directory source file.
    fn rename(&mut self, source: &Path, destination: &Path) -> io::Result<()>;
    /// Remove an obsolete destination entry.
    fn remove(&mut self, destination: &Path) -> io::Result<()>;
    /// Synchronize this directory or explicitly report the missing primitive.
    fn sync_directory(&mut self, directory: &Path) -> io::Result<DirectorySync>;
}

/// Native same-volume replacement/removal with platform-specific barrier receipts.
/// Unix synchronizes directory handles. Windows performs native rename/removal
/// but reports its absent directory barrier separately from actual file sync.
#[derive(Debug, Default)]
pub struct NativeCommit;
impl CommitBackend for NativeCommit {
    fn rename(&mut self, source: &Path, destination: &Path) -> io::Result<()> {
        fs::rename(source, destination)
    }
    fn remove(&mut self, destination: &Path) -> io::Result<()> {
        fs::remove_file(destination)
    }
    fn sync_directory(&mut self, directory: &Path) -> io::Result<DirectorySync> {
        #[cfg(unix)]
        {
            fs::File::open(directory)?.sync_all()?;
            Ok(DirectorySync::Synchronized)
        }
        #[cfg(windows)]
        {
            let _ = directory;
            Ok(DirectorySync::Unavailable)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = directory;
            Err(io::ErrorKind::Unsupported.into())
        }
    }
}
