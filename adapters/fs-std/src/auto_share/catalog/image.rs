//! Sealed snapshot replacement, retained read leases and independent naming barriers.
use super::{Error, IMAGE, MAX_IMAGE, NEXT, io as failure};
use gnunet_native::{
    DirectorySync,
    filesystem::{
        self, Directory, EntryInfo, FileInfo, PrivateFileSnapshot, PrivateSnapshotError,
        private_data_file_info, publication,
    },
};
use std::{
    ffi::OsStr,
    fmt,
    fs::File,
    io::{self, Read, Write},
};
#[cfg(test)]
mod tests;

pub(super) struct Image {
    directory: Directory,
    original: Option<Original>,
    naming_sync: Option<DirectorySync>,
}
struct Original {
    file: File,
    snapshot: PrivateFileSnapshot,
}
#[derive(Debug)]
struct FenceError {
    stage: &'static str,
    cause: FenceCause,
}
#[derive(Debug)]
enum FenceCause {
    Native(io::Error),
    Extent {
        before: FileInfo,
        read_bytes: usize,
    },
    Metadata {
        before: FileInfo,
        after: FileInfo,
    },
    Named {
        held: FileInfo,
        observed_after_rejection: io::Result<EntryInfo>,
    },
}
impl fmt::Display for FenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "catalog {}: ", self.stage)?;
        match &self.cause {
            FenceCause::Native(error) => error.fmt(f),
            FenceCause::Extent { before, read_bytes } => {
                write!(
                    f,
                    "original read extent changed: before={before:?}, read_bytes={read_bytes}"
                )
            }
            FenceCause::Metadata { before, after } => write!(
                f,
                "original held metadata changed: identity={}, bytes={}, modified={}, changed={}, before={before:?}, after={after:?}",
                before.identity != after.identity,
                before.bytes != after.bytes,
                before.times.modified != after.times.modified,
                before.times.changed != after.times.changed,
            ),
            FenceCause::Named {
                held,
                observed_after_rejection,
            } => write!(
                f,
                "original name no longer selects held file: held={held:?}, observed_after_rejection={observed_after_rejection:?}"
            ),
        }
    }
}
impl std::error::Error for FenceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.cause {
            FenceCause::Native(error) => Some(error),
            FenceCause::Named {
                observed_after_rejection: Err(error),
                ..
            } => Some(error),
            _ => None,
        }
    }
}
fn refusal(stage: &'static str, cause: FenceCause) -> Error {
    let kind = match &cause {
        FenceCause::Native(error) => error.kind(),
        _ => io::ErrorKind::InvalidData,
    };
    Error::Io(io::Error::new(kind, FenceError { stage, cause }))
}
fn observe<T>(stage: &'static str, result: io::Result<T>) -> Result<T, Error> {
    result.map_err(|error| refusal(stage, FenceCause::Native(error)))
}
fn publication_failure(error: publication::Failure) -> Error {
    failure(
        "atomic catalog commit",
        error.may_have_published,
        io::Error::new(error.cause.kind(), error),
        None,
    )
}
impl Image {
    pub(super) fn new(directory: &File) -> io::Result<Self> {
        Ok(Self {
            directory: Directory::from_file(directory)?,
            original: None,
            naming_sync: None,
        })
    }
    pub(super) fn read(&mut self) -> Result<Option<Vec<u8>>, Error> {
        let file = match self.directory.open_file(OsStr::new(IMAGE)) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        observe("read access", filesystem::validate_readonly(&file))?;
        let info = observe("read file policy", private_data_file_info(&file))?;
        if info.bytes > MAX_IMAGE as u64 {
            return Err(Error::Binding("catalog image exceeds bound"));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(info.bytes as usize + 1)
            .map_err(|_| Error::Binding("catalog allocation"))?;
        (&file).take(info.bytes + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 != info.bytes {
            return Err(refusal(
                "read",
                FenceCause::Extent {
                    before: info,
                    read_bytes: bytes.len(),
                },
            ));
        }
        let after = observe("read file policy", private_data_file_info(&file))?;
        if after != info {
            return Err(refusal(
                "read",
                FenceCause::Metadata {
                    before: info,
                    after,
                },
            ));
        }
        self.selected_name("read name", &file, info)?;
        self.original = Some(Original {
            file,
            snapshot: PrivateFileSnapshot::new(info, &bytes),
        });
        Ok(Some(bytes))
    }
    pub(super) fn selected(&self) -> Result<(), Error> {
        match &self.original {
            Some(original) => original
                .snapshot
                .verify_detailed(&self.directory, OsStr::new(IMAGE), &original.file)
                .map_err(|error| match error {
                    PrivateSnapshotError::Held(error) => {
                        refusal("selected file policy", FenceCause::Native(error))
                    }
                    PrivateSnapshotError::Metadata { before, after } => refusal(
                        "selected",
                        FenceCause::Metadata {
                            before,
                            after: *after,
                        },
                    ),
                    PrivateSnapshotError::Name { held, observed } => {
                        if let Err(error) = *observed {
                            refusal("selected name", FenceCause::Native(error))
                        } else {
                            refusal(
                                "selected name",
                                FenceCause::Named {
                                    held,
                                    observed_after_rejection: *observed,
                                },
                            )
                        }
                    }
                    PrivateSnapshotError::Readback(error) => {
                        refusal("selected readback", FenceCause::Native(error))
                    }
                })?,
            None => match self.directory.entry_info(OsStr::new(IMAGE)) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
                Ok(_) => return Err(Error::Binding("unexpected catalog image")),
            },
        }
        Ok(())
    }
    fn selected_name(&self, stage: &'static str, file: &File, held: FileInfo) -> Result<(), Error> {
        if !observe(stage, self.directory.same_file(OsStr::new(IMAGE), file))? {
            // This later observation explains a rejected name; it cannot
            // override the original mismatch, even if the name changes again.
            return Err(refusal(
                stage,
                FenceCause::Named {
                    held,
                    observed_after_rejection: self.directory.entry_info(OsStr::new(IMAGE)),
                },
            ));
        }
        Ok(())
    }
    pub(super) fn recover_temp(&mut self) -> Result<(), Error> {
        self.selected()?;
        let file = match self.directory.open_file(OsStr::new(NEXT)) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        private_data_file_info(&file)?;
        self.naming_sync = None;
        self.directory.remove_file(OsStr::new(NEXT), &file)?;
        self.naming_sync = Some(self.directory.sync()?);
        Ok(())
    }
    pub(super) fn write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.selected()?;
        let mut file = self.directory.create_private_file(OsStr::new(NEXT))?;
        self.naming_sync = None;
        let prepare = (|| -> io::Result<()> {
            private_data_file_info(&file)?;
            let mut offset = 0;
            while offset < bytes.len() {
                let count = file.write(&bytes[offset..])?;
                if count == 0 {
                    return Err(io::ErrorKind::WriteZero.into());
                }
                offset += count;
            }
            Ok(())
        })();
        if let Err(cause) = prepare {
            let cleanup = match self.directory.remove_file(OsStr::new(NEXT), &file) {
                Ok(()) => publication::Cleanup::Retired,
                Err(error) => publication::Cleanup::Failed(error),
            };
            return Err(publication_failure(publication::Failure {
                stage: "temporary-write-sync",
                cause,
                may_have_published: false,
                writer_close: filesystem::close(file).err(),
                cleanup,
            }));
        }
        let sealed = publication::seal(&self.directory, OsStr::new(NEXT), file, bytes.len() as u64)
            .map_err(publication_failure)?;
        if let Err(original) = self.selected() {
            return Err(match sealed.discard() {
                Ok(()) => original,
                Err(cleanup) => Error::WithCleanup {
                    original: Box::new(original),
                    cleanup: Box::new(Error::Io(cleanup)),
                },
            });
        }
        // The native replacement may change names even when it fails. Its
        // read lease can close, but no cleanup or retry is authorized afterward.
        let (file, replaced) = sealed
            .replace(OsStr::new(IMAGE))
            .map_err(publication_failure)?;
        let info = (|| -> io::Result<FileInfo> {
            replaced?;
            self.naming_sync = Some(self.directory.sync()?);
            if !self.directory.same_file(OsStr::new(IMAGE), &file)? {
                return Err(io::Error::other("published catalog image changed"));
            }
            filesystem::validate_readonly(&file)?;
            private_data_file_info(&file)
        })()
        .map_err(|error| failure("atomic catalog commit", true, error, None))?;
        self.original = Some(Original {
            file,
            snapshot: PrivateFileSnapshot::new(info, bytes),
        });
        Ok(())
    }
    pub(super) fn create_version(&mut self, name: &OsStr) -> Result<(), Error> {
        drop(self.directory.create_private_directory(name)?);
        self.naming_sync = None;
        self.naming_sync = Some(self.directory.sync()?);
        Ok(())
    }
    pub(super) fn directory_sync(&self) -> Option<DirectorySync> {
        self.naming_sync
    }
}
