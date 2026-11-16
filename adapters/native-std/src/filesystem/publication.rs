//! Atomic private-file publication under one caller-owned directory.
use super::{self as filesystem, Directory};
use crate::DirectorySync;
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Write},
    sync::atomic::{AtomicU64, Ordering},
};

/// Actual cleanup of the original staged link.
#[derive(Debug)]
pub enum Cleanup {
    /// No temporary file was created.
    NotNeeded,
    /// The original temporary link was removed or renamed into its destination.
    Retired,
    /// Original-link cleanup failed; the destination may independently exist.
    Failed(io::Error),
}
/// Independent native publication and cleanup facts, without file bytes.
#[derive(Debug)]
pub struct Failure {
    /// Last native boundary entered.
    pub stage: &'static str,
    /// Original refusal or native error.
    pub cause: io::Error,
    /// A link or rename was attempted; absence of a receipt does not prove no publication.
    pub may_have_published: bool,
    /// Independent close error from the original writer, when another error won.
    pub writer_close: Option<io::Error>,
    /// Original temporary-link cleanup observation.
    pub cleanup: Cleanup,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "anchored file publication: {self:?}")
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
/// Actual synchronized file, consumed writer close and atomic name publication.
/// Directory synchronization is a separate native capability observation.
#[derive(Debug)]
pub struct Published {
    file: File,
    directory_sync: DirectorySync,
}
impl Published {
    /// Consume the original read lease and actual directory barrier observation.
    pub fn into_parts(self) -> (File, DirectorySync) {
        (self.file, self.directory_sync)
    }
}
/// Construct a refusal before creating a temporary or attempting publication.
pub fn refused(stage: &'static str, cause: io::Error) -> Failure {
    Failure {
        stage,
        cause,
        may_have_published: false,
        writer_close: None,
        cleanup: Cleanup::NotNeeded,
    }
}
struct Staged<'a> {
    directory: &'a Directory,
    name: OsString,
    writer: Option<File>,
    lease: Option<File>,
    attempted: bool,
    renamed: bool,
}
impl Staged<'_> {
    fn failure(mut self, stage: &'static str, cause: io::Error) -> Failure {
        let cleanup = if self.renamed {
            Cleanup::Retired
        } else if let Some(original) = self.lease.as_ref().or(self.writer.as_ref()) {
            match self.directory.remove_file(&self.name, original) {
                Ok(()) => Cleanup::Retired,
                Err(error) => Cleanup::Failed(error),
            }
        } else {
            Cleanup::NotNeeded
        };
        let writer_close = self
            .writer
            .take()
            .and_then(|file| filesystem::close(file).err());
        Failure {
            stage,
            cause,
            may_have_published: self.attempted,
            writer_close,
            cleanup,
        }
    }
}
/// Requested destination operation. Neither variant grants target authority.
#[derive(Clone, Copy, Debug)]
pub enum Destination {
    /// Refuse an existing destination instead of replacing another owner's file.
    Create,
    /// Replace a caller-authorized destination atomically.
    Replace,
}
/// Stage private bytes, synchronize and explicitly close their writer, then
/// publish relative to this original directory. The caller excludes namespace
/// administration and supplies its original target/deadline fence. The returned
/// read lease retains the actual published object. No parent path is resolved.
pub fn publish(
    directory: &Directory,
    target: &OsStr,
    contents: &[u8],
    destination: Destination,
    before_publish: impl FnOnce() -> io::Result<()>,
) -> Result<Published, Failure> {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    directory
        .validate_namespace()
        .map_err(|error| refused("namespace", error))?;
    let mut opened = None;
    for _ in 0..16 {
        let serial = NEXT
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| refused("temporary-serial", io::ErrorKind::StorageFull.into()))?;
        let name = OsString::from(format!(".gnunet-file-{}-{serial}.new", std::process::id()));
        if name == target {
            continue;
        }
        match directory.create_private_file(&name) {
            Ok(file) => {
                opened = Some((name, file));
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(refused("temporary-create", error)),
        }
    }
    let (name, file) =
        opened.ok_or_else(|| refused("temporary-capacity", io::ErrorKind::AlreadyExists.into()))?;
    let mut staged = Staged {
        directory,
        name,
        writer: Some(file),
        lease: None,
        attempted: false,
        renamed: false,
    };
    let prepare = (|| {
        let file = staged.writer.as_mut().ok_or(io::ErrorKind::NotFound)?;
        file.write_all(contents)?;
        file.sync_all()?;
        let lease = directory.open_file(&staged.name)?;
        if !directory.same_file(&staged.name, file)?
            || filesystem::FileIdentity::of(file)? != filesystem::FileIdentity::of(&lease)?
        {
            return Err(io::Error::other("original file temporary changed"));
        }
        staged.lease = Some(lease);
        Ok::<_, io::Error>(())
    })();
    if let Err(error) = prepare {
        return Err(staged.failure("temporary-write-sync", error));
    }
    if let Some(file) = staged.writer.take()
        && let Err(error) = filesystem::close(file)
    {
        return Err(staged.failure("writer-close", error));
    }
    if let Err(error) = before_publish() {
        return Err(staged.failure("before-publication", error));
    }
    let Some(lease) = staged.lease.as_ref() else {
        return Err(staged.failure("original-lease", io::ErrorKind::NotFound.into()));
    };
    staged.attempted = true;
    match destination {
        Destination::Replace => {
            if let Err(error) = directory.replace_file(&staged.name, lease, target) {
                return Err(staged.failure("rename", error));
            }
        }
        Destination::Create => {
            if let Err(error) = directory.link_file_from(directory, &staged.name, lease, target) {
                return Err(staged.failure("publish-create", error));
            }
            if let Err(error) = directory.remove_file(&staged.name, lease) {
                // The actual unlink was attempted once. Do not retry an uncertain
                // removal, replace the destination or discard its original error.
                return Err(Failure {
                    stage: "temporary-retirement",
                    cause: io::Error::other("published file retains an unresolved temporary link"),
                    may_have_published: true,
                    writer_close: None,
                    cleanup: Cleanup::Failed(error),
                });
            }
        }
    }
    staged.renamed = true;
    let directory_sync = match directory.sync() {
        Ok(observation) => observation,
        Err(error) => return Err(staged.failure("directory-sync", error)),
    };
    let selected = match directory.same_file(target, lease) {
        Ok(selected) => selected,
        Err(error) => return Err(staged.failure("published-selection", error)),
    };
    if !selected {
        return Err(staged.failure(
            "published-selection",
            io::Error::other("original publication changed"),
        ));
    }
    let Some(file) = staged.lease.take() else {
        return Err(staged.failure("original-lease", io::ErrorKind::NotFound.into()));
    };
    Ok(Published {
        file,
        directory_sync,
    })
}

#[cfg(test)]
mod tests;
