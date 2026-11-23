//! Select the configured directory once before relative namespace operations.
use crate::{CommitBackend, DirectorySync, Stage, StoreError};
use gnunet_native::filesystem::Directory;
use gnunet_types::Error;
use std::{fs, io, path::Path};

/// Allow configured directory aliases at selection. All subsequent I/O for
/// this transaction uses the captured original directory.
pub(crate) fn open(path: &Path) -> io::Result<Directory> {
    Directory::open(&fs::canonicalize(path)?)
}

pub(crate) fn prepare(
    path: &Path,
    commit: &mut impl CommitBackend,
) -> Result<(Directory, DirectorySync), StoreError> {
    let mut cursor = path;
    let mut missing = Vec::new();
    let mut directory = loop {
        match open(cursor) {
            Ok(original) => break original,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let child = cursor.file_name().ok_or_else(|| {
                    StoreError::protocol(Stage::Prepare, None, Error::InvalidInput)
                })?;
                Directory::validate_name(child)
                    .map_err(|error| StoreError::io(Stage::Prepare, None, error))?;
                missing
                    .try_reserve(1)
                    .map_err(|_| StoreError::protocol(Stage::Prepare, None, Error::Capacity))?;
                missing.push(child);
                cursor = cursor
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                    .unwrap_or(Path::new("."));
            }
            Err(error) => return Err(StoreError::io(Stage::Prepare, None, error)),
        }
    };

    let mut barrier = DirectorySync::Synchronized;
    let failed = |error| StoreError::io(Stage::Prepare, None, error);
    for name in missing.into_iter().rev() {
        let child = directory.ensure_directory(name).map_err(failed)?;
        let child_barrier = commit.sync_directory(&child).map_err(failed)?;
        let parent_barrier = commit.sync_directory(&directory).map_err(failed)?;
        if !directory.same_directory(name, &child).map_err(failed)? {
            return Err(failed(io::Error::other(
                "original STATISTICS parent directory name changed",
            )));
        }
        barrier = barrier.combine(child_barrier).combine(parent_barrier);
        directory = child;
    }
    Ok((directory, barrier))
}
