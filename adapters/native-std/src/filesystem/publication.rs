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

fn after_publication(stage: &'static str, cause: io::Error) -> Failure {
    Failure {
        may_have_published: true,
        cleanup: Cleanup::Retired,
        ..refused(stage, cause)
    }
}

fn cleanup(directory: &Directory, name: &OsStr, original: &File) -> Cleanup {
    match directory.remove_file(name, original) {
        Ok(()) => Cleanup::Retired,
        Err(error) => Cleanup::Failed(error),
    }
}

fn writer_failed(
    directory: &Directory,
    name: &OsStr,
    writer: File,
    stage: &'static str,
    cause: io::Error,
) -> Failure {
    Failure {
        cleanup: cleanup(directory, name, &writer),
        writer_close: filesystem::close(writer).err(),
        ..refused(stage, cause)
    }
}

/// Original read-only stage after its synchronized writer has closed.
/// Dropping the lease leaves the name for its caller's recovery policy.
#[must_use]
pub struct Sealed<'a> {
    directory: &'a Directory,
    name: &'a OsStr,
    file: File,
    info: filesystem::FileInfo,
}

enum SealFailure {
    Writer(&'static str, io::Error),
    Reader(&'static str, io::Error),
}

fn verify_selection(
    directory: &Directory,
    name: &OsStr,
    held: filesystem::FileInfo,
) -> io::Result<()> {
    let named = directory.entry_info(name)?;
    if named != filesystem::EntryInfo::File(held) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("original staged file differs from its name: held={held:?}, named={named:?}"),
        ));
    }
    Ok(())
}

fn prepare(
    directory: &Directory,
    name: &OsStr,
    file: &mut File,
    expected_bytes: u64,
) -> Result<filesystem::FileInfo, SealFailure> {
    file.sync_all()
        .map_err(|error| SealFailure::Writer("file-sync", error))?;
    let opened = (|| {
        let lease = directory.open_file(name)?;
        if filesystem::FileIdentity::of(file)? != filesystem::FileIdentity::of(&lease)? {
            return Err(io::Error::other("original staged file changed"));
        }
        Ok(lease)
    })();
    let lease = opened.map_err(|error| SealFailure::Writer("stage-lease", error))?;
    filesystem::close(std::mem::replace(file, lease))
        .map_err(|error| SealFailure::Reader("writer-close", error))?;
    let info = filesystem::private_data_file_info(file)
        .map_err(|error| SealFailure::Reader("prepared-fence", error))?;
    if info.bytes != expected_bytes {
        return Err(SealFailure::Reader(
            "prepared-fence",
            io::Error::new(
                io::ErrorKind::InvalidData,
                "original staged file length differs from synchronized input",
            ),
        ));
    }
    verify_selection(directory, name, info)
        .map_err(|error| SealFailure::Reader("prepared-fence", error))?;
    Ok(info)
}

/// Synchronize and close a staging writer while keeping its original object
/// held. On success the supplied file is a separate read-only lease. On failure
/// it still holds the original object for caller-owned cleanup. A failure before
/// opening the reader leaves the writer in place. No name is changed.
pub fn seal_retained(
    directory: &Directory,
    name: &OsStr,
    file: &mut File,
    expected_bytes: u64,
) -> Result<filesystem::FileInfo, Failure> {
    prepare(directory, name, file, expected_bytes).map_err(|error| match error {
        SealFailure::Writer(stage, cause) | SealFailure::Reader(stage, cause) => {
            refused(stage, cause)
        }
    })
}

/// Synchronize the private stage, consume its writer and retain a separate
/// read-only handle to the same file. Failures remove only the original stage
/// when possible and retain independent writer-close or name cleanup failures.
pub fn seal<'a>(
    directory: &'a Directory,
    name: &'a OsStr,
    writer: File,
    expected_bytes: u64,
) -> Result<Sealed<'a>, Failure> {
    let mut file = writer;
    let info = match prepare(directory, name, &mut file, expected_bytes) {
        Ok(info) => info,
        Err(SealFailure::Writer(stage, cause)) => {
            return Err(writer_failed(directory, name, file, stage, cause));
        }
        Err(SealFailure::Reader(stage, cause)) => {
            return Err(Failure {
                cleanup: cleanup(directory, name, &file),
                ..refused(stage, cause)
            });
        }
    };
    Ok(Sealed {
        directory,
        name,
        file,
        info,
    })
}

impl Sealed<'_> {
    fn verify(&self) -> io::Result<()> {
        let observed = filesystem::private_data_file_info(&self.file)?;
        if observed != self.info {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "original staged file changed before publication: expected={:?}, observed={observed:?}",
                    self.info
                ),
            ));
        }
        verify_selection(self.directory, self.name, observed)
    }

    fn failed(&self, stage: &'static str, cause: io::Error) -> Failure {
        Failure {
            cleanup: cleanup(self.directory, self.name, &self.file),
            ..refused(stage, cause)
        }
    }

    /// Discard the stage by its original identity before any replacement.
    pub fn discard(self) -> io::Result<()> {
        self.directory.remove_file(self.name, &self.file)
    }

    /// Recheck the sealed file, attempt one native replacement and return the
    /// original read lease with its actual replacement result. An outer error
    /// means replacement was never attempted. After the attempt the caller owns
    /// recovery, including original-file readback and any naming barrier.
    pub fn replace(self, target: &OsStr) -> Result<(File, io::Result<()>), Failure> {
        if target == self.name {
            return Err(self.failed("replacement-target", io::ErrorKind::InvalidInput.into()));
        }
        if let Err(cause) = self.verify() {
            return Err(self.failed("before-publication-fence", cause));
        }
        let replaced = self.directory.replace_file(self.name, &self.file, target);
        Ok((self.file, replaced))
    }
}

/// Synchronize the held original at its selected name. Windows requires a
/// separate sync-capable handle, which is checked against the held identity and
/// explicitly closed before returning. This operation never removes a name.
pub fn sync_original(directory: &Directory, name: &OsStr, original: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        if !directory.same_file(name, original)? {
            return Err(io::Error::other(
                "original file changed before synchronization",
            ));
        }
        original.sync_all()
    }
    #[cfg(windows)]
    {
        let file = directory.open_file_for_sync(name)?;
        let sync = (|| {
            if filesystem::FileIdentity::of(original)? != filesystem::FileIdentity::of(&file)? {
                return Err(io::Error::other(
                    "original file changed before synchronization",
                ));
            }
            file.sync_all()
        })();
        let close = filesystem::close(file);
        match (sync, close) {
            (Err(sync), Err(close)) => {
                Err(io::Error::new(sync.kind(), SyncCloseFailed { sync, close }))
            }
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }
}

#[cfg(windows)]
#[derive(Debug)]
struct SyncCloseFailed {
    sync: io::Error,
    close: io::Error,
}
#[cfg(windows)]
impl std::fmt::Display for SyncCloseFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}. Independent sync handle close: {}",
            self.sync, self.close
        )
    }
}
#[cfg(windows)]
impl std::error::Error for SyncCloseFailed {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.sync)
    }
}

/// After publication and retirement of the staging link, synchronize the held
/// directory. If its barrier is unavailable, flush the original file at its new
/// name. The file flush leaves the directory barrier result unchanged.
pub fn synchronize_published(
    directory: &Directory,
    target: &OsStr,
    original: &File,
) -> Result<DirectorySync, Failure> {
    let directory_sync = directory
        .sync()
        .map_err(|cause| after_publication("directory-sync", cause))?;
    if directory_sync == DirectorySync::Unavailable {
        sync_original(directory, target, original)
            .map_err(|cause| after_publication("published-file-sync", cause))?;
    }
    Ok(directory_sync)
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
/// publish relative to this original directory. The caller excludes namespace,
/// content and permission administration and supplies its original target/deadline
/// fence. That callback must not change the prepared file; the original private
/// data fences are checked around it. The returned read lease retains the actual
/// published object. No parent path is resolved.
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
        if name == target || (cfg!(windows) && name.eq_ignore_ascii_case(target)) {
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
    let (name, mut writer) =
        opened.ok_or_else(|| refused("temporary-capacity", io::ErrorKind::AlreadyExists.into()))?;
    let written = (|| {
        let mut remaining = contents;
        while !remaining.is_empty() {
            // Advance only on reported writes. Preserve native errors, including
            // interruption, without resubmitting the same stage prefix.
            let count = writer.write(remaining)?;
            if count == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            remaining = &remaining[count..];
        }
        Ok(())
    })();
    if let Err(cause) = written {
        return Err(writer_failed(
            directory,
            &name,
            writer,
            "temporary-write-sync",
            cause,
        ));
    }
    let staged = seal(directory, &name, writer, contents.len() as u64).map_err(|mut error| {
        if error.stage == "file-sync" {
            error.stage = "temporary-write-sync";
        }
        error
    })?;
    before_publish().map_err(|cause| staged.failed("before-publication", cause))?;
    staged
        .verify()
        .map_err(|cause| staged.failed("before-publication-fence", cause))?;
    let lease = &staged.file;
    let rename_failure = |stage, cause| Failure {
        may_have_published: true,
        ..staged.failed(stage, cause)
    };
    match destination {
        Destination::Replace => directory
            .replace_file(&name, lease, target)
            .map_err(|cause| rename_failure("rename", cause))?,
        Destination::Create => {
            #[cfg(windows)]
            directory
                .rename_new_file(&name, lease, target)
                .map_err(|cause| rename_failure("publish-create", cause))?;
            #[cfg(unix)]
            {
                #[cfg(target_os = "freebsd")]
                let renamed = filesystem::freebsd::rename_noreplace(directory, &name, target)
                    .map_err(|cause| rename_failure("publish-create", cause))?;
                #[cfg(not(target_os = "freebsd"))]
                let renamed = false;
                if !renamed {
                    directory
                        .link_file_from(directory, &name, lease, target)
                        .map_err(|cause| rename_failure("publish-create", cause))?;
                    if let Err(error) = directory.remove_file(&name, lease) {
                        // The actual unlink was attempted once. Its result is independent
                        // of the already published destination.
                        return Err(Failure {
                            stage: "temporary-retirement",
                            cause: io::Error::other(
                                "published file retains an unresolved temporary link",
                            ),
                            may_have_published: true,
                            writer_close: None,
                            cleanup: Cleanup::Failed(error),
                        });
                    }
                }
            }
        }
    }
    let directory_sync = synchronize_published(directory, target, lease)?;
    if !directory
        .same_file(target, lease)
        .map_err(|cause| after_publication("published-selection", cause))?
    {
        return Err(after_publication(
            "published-selection",
            io::Error::other("original publication changed"),
        ));
    }
    Ok(Published {
        file: staged.file,
        directory_sync,
    })
}

#[cfg(test)]
mod tests;
