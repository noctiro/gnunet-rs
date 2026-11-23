//! Publication and synchronization through an original directory and file.
use gnunet_native::filesystem::Directory;
use std::{ffi::OsStr, fs::File, io};

mod staged;
pub(crate) use staged::Candidate;

pub use gnunet_native::DirectorySync;

/// Real namespace operations, separate from the snapshot file's `sync_all`.
/// Implementations perform the requested rename/removal and preserve errors.
/// Directory barriers return an explicit observation; an unavailable primitive
/// must never be represented by `DirectorySync::Synchronized`.
pub trait CommitBackend {
    /// Replace the destination with the original complete source in this directory.
    fn rename(
        &mut self,
        directory: &Directory,
        source: &OsStr,
        original: &File,
        destination: &OsStr,
    ) -> io::Result<()>;
    /// Remove the original database entry from this directory.
    fn remove(
        &mut self,
        directory: &Directory,
        destination: &OsStr,
        original: &File,
    ) -> io::Result<()>;
    /// Synchronize this original directory or report the unavailable primitive.
    fn sync_directory(&mut self, directory: &Directory) -> io::Result<DirectorySync>;
}

/// Native same-volume replacement/removal with platform-specific barrier receipts.
#[derive(Debug, Default)]
pub struct NativeCommit;
impl CommitBackend for NativeCommit {
    fn rename(
        &mut self,
        directory: &Directory,
        source: &OsStr,
        original: &File,
        destination: &OsStr,
    ) -> io::Result<()> {
        directory.replace_file(source, original, destination)
    }
    fn remove(
        &mut self,
        directory: &Directory,
        destination: &OsStr,
        original: &File,
    ) -> io::Result<()> {
        directory.remove_file(destination, original)
    }
    fn sync_directory(&mut self, directory: &Directory) -> io::Result<DirectorySync> {
        directory.sync()
    }
}
