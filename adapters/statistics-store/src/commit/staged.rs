//! The original private file and its parent stay held through publication.
use crate::{CommitBackend, DirectorySync, Stage, StoreError};
use gnunet_native::filesystem::{Directory, publication};
use gnunet_types::Error;
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

pub(crate) struct Candidate<'a> {
    directory: &'a Directory,
    name: OsString,
    file: File,
    clean: bool,
}

impl<'a> Candidate<'a> {
    pub(crate) fn create(directory: &'a Directory, target: &OsStr) -> Result<Self, StoreError> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for _ in 0..64 {
            let ordinal = NEXT
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_add(1)
                })
                .map_err(|_| StoreError::protocol(Stage::CreateTemporary, None, Error::Overflow))?;
            // Keep the stage name bounded independently of the target basename.
            let name = OsString::from(format!(
                ".gnunet-statistics-{}-{ordinal}.tmp",
                std::process::id()
            ));
            if name == target || (cfg!(windows) && name.eq_ignore_ascii_case(target)) {
                continue;
            }
            match directory.create_private_file(&name) {
                Ok(file) => {
                    return Ok(Self {
                        directory,
                        name,
                        file,
                        clean: true,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(StoreError::io(Stage::CreateTemporary, None, error)),
            }
        }
        Err(StoreError::protocol(
            Stage::CreateTemporary,
            None,
            Error::Capacity,
        ))
    }

    pub(crate) fn writer(&mut self) -> &mut File {
        &mut self.file
    }

    pub(crate) fn failed(mut self, error: StoreError) -> StoreError {
        self.clean = false;
        match self.directory.remove_file(&self.name, &self.file) {
            Ok(()) => error,
            Err(cleanup) => error.with_cleanup(cleanup),
        }
    }

    pub(crate) fn publish(
        mut self,
        bytes: u64,
        target: &OsStr,
        configured_parent: &Path,
        commit: &mut impl CommitBackend,
    ) -> Result<DirectorySync, StoreError> {
        if let Err(error) =
            publication::seal_retained(self.directory, &self.name, &mut self.file, bytes)
        {
            let cause = io::Error::new(error.cause.kind(), error);
            return Err(self.failed(StoreError::io(Stage::SyncFile, None, cause)));
        }
        // Retain any surviving original stage once the rename can affect the
        // final name. The configured path is a diagnostic, not recovery custody.
        self.clean = false;
        commit
            .rename(self.directory, &self.name, &self.file, target)
            .map_err(|error| {
                StoreError::io(Stage::Rename, None, error)
                    .unknown(Some(configured_parent.join(&self.name)))
            })?;
        let directory_sync = commit
            .sync_directory(self.directory)
            .map_err(|error| StoreError::io(Stage::SyncDirectory, None, error).unknown(None))?;
        if directory_sync == DirectorySync::Unavailable {
            publication::sync_original(self.directory, target, &self.file)
                .map_err(|error| StoreError::io(Stage::SyncPublished, None, error).unknown(None))?;
        }
        if !self
            .directory
            .same_file(target, &self.file)
            .map_err(|error| StoreError::io(Stage::Inspect, None, error).unknown(None))?
        {
            return Err(StoreError::io(
                Stage::Inspect,
                None,
                io::Error::other("original STATISTICS database name changed"),
            )
            .unknown(None));
        }
        Ok(directory_sync)
    }
}

impl Drop for Candidate<'_> {
    fn drop(&mut self) {
        if self.clean {
            let _cleanup = self.directory.remove_file(&self.name, &self.file);
        }
    }
}
