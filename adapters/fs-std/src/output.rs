//! Anchored, authenticated and no-clobber plaintext output.
mod artifact;
mod existing;
mod observed;
mod owned;
mod path;
pub(crate) use path::components;
#[cfg(feature = "service")]
pub(crate) use path::from_protocol_name;
#[cfg(feature = "service")]
mod range;
pub(crate) use crate::FileIdentity;
use crate::{BlockSource, Buffers, Control, Error, Limits, Progress, ReadFile, Result};
pub use artifact::{ArtifactFailure, ArtifactReport};
pub use existing::{RevalidateFailure, RevalidateStage, RevalidatedFile};
use gnunet_fs::Content;
use gnunet_native::{DirectorySync, filesystem::Directory};
#[cfg(any(feature = "service", test))]
pub(crate) use observed::OutputObservation;
#[cfg(feature = "service")]
pub(crate) use observed::TempRecord;
pub use observed::{CommitStage, ObservedFailure};
pub use owned::{DirectoryStage, OWNER_MARKER_NAME, OwnedDirectoryFailure};
#[cfg(feature = "service")]
pub use range::{RevalidateRangeFailure, RevalidatedRange};
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io,
    path::Path,
};

// An eight-digit DOS-compatible name needs neither case folding nor a generated
// 8.3 alias. A matching final name is skipped before exclusive creation.
fn temporary_name(nonce: u64) -> OsString {
    const SPACE: u64 = 10_000_000;
    OsString::from(format!(
        "0{:07}",
        (u64::from(std::process::id()) + nonce % SPACE) % SPACE
    ))
}
pub(crate) fn temporary_name_valid(name: &OsStr) -> bool {
    let bytes = name.as_encoded_bytes();
    bytes.len() == 8 && bytes[0] == b'0' && bytes.iter().all(u8::is_ascii_digit)
}
fn invalid_name() -> Error {
    gnunet_types::Error::InvalidInput.into()
}

/// A caller-selected existing directory, held by its actual descriptor. Renaming
/// or replacing the original root pathname cannot redirect an extraction.
/// Metadata paths are relative and bounded by 4096 native units/128 components
/// (Unix bytes or Windows UTF-16 units). Symlinks/name surrogates are refused.
/// Callers exclude administrative replacement within held directories. Parent
/// directories may be created; existing final targets are never replaced.
pub struct OutputDir {
    root: Directory,
    nonce: u64,
}
impl OutputDir {
    /// Duplicate the held directory descriptor, without reopening its pathname.
    #[cfg(feature = "service")]
    pub(crate) fn duplicate(&self) -> Result<Self> {
        Ok(Self {
            root: self.root.duplicate()?,
            nonce: self.nonce,
        })
    }
    #[cfg(feature = "network")]
    pub(crate) fn from_directory(root: File) -> Result<Self> {
        Ok(Self {
            root: Directory::from_file(&root)?,
            nonce: 0,
        })
    }
    /// Open an existing caller-selected directory; a final root symlink is refused.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let root = Directory::open(path.as_ref())?;
        Ok(Self { root, nonce: 0 })
    }
    /// Create a new private directory below this descriptor without replacing
    /// an existing name. The returned owner anchors all later output to its FD.
    /// A failure after mkdir can leave that directory present; it is not removed
    /// through an unverified pathname, and callers retain the requested name.
    pub fn create_directory(&mut self, relative: impl AsRef<Path>) -> Result<Self> {
        let parts = components(relative.as_ref())?;
        let (name, ancestors) = parts.split_last().ok_or_else(invalid_name)?;
        let parent = self.parent(ancestors)?;
        let root = parent.create_private_directory(name)?;
        root.sync()?;
        parent.sync()?;
        Ok(Self { root, nonce: 0 })
    }
    /// Synchronize the held directory or explicitly report an unavailable native
    /// barrier. This never substitutes file synchronization for directory sync.
    pub fn sync_directory(&self) -> Result<DirectorySync> {
        Ok(self.root.sync()?)
    }
    fn parent(&self, parts: &[&OsStr]) -> Result<Directory> {
        let mut parent = self.root.duplicate()?;
        for name in parts {
            let next = parent.ensure_directory(name)?;
            next.sync()?;
            parent.sync()?;
            parent = next;
        }
        Ok(parent)
    }
    fn temporary<'a>(
        &mut self,
        parent: &'a Directory,
        final_name: &OsStr,
    ) -> Result<Temporary<'a>> {
        for _ in 0..1024 {
            let nonce = self.nonce;
            self.nonce = nonce.checked_add(1).ok_or(Error::Limit)?;
            let name = temporary_name(nonce);
            // A legal metadata name may itself use this prefix. Creating our
            // temporary at that same name would expose an unauthenticated prefix.
            if name.as_os_str() == final_name {
                continue;
            }
            match parent.create_private_file(&name) {
                Ok(file) => {
                    let identity = match FileIdentity::of(&file) {
                        Ok(identity) => identity,
                        Err(source) => {
                            let cause = Error::Io(source);
                            return match parent.remove_file(&name, &file) {
                                Ok(()) => Err(cause),
                                Err(source) => Err(Error::CleanupFailed {
                                    cause: Box::new(cause),
                                    source,
                                }),
                            };
                        }
                    };
                    return Ok(Temporary {
                        parent,
                        name,
                        file,
                        identity,
                        removed: false,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(Error::Limit)
    }
    /// Authenticate and stream a file to an owned temporary in its destination
    /// directory. A completed receipt requires full authentication, actual file
    /// synchronization, no-replace publication and checked final identity.
    /// `ReadFile::directory_sync` separately reports directory-barrier support.
    ///
    /// Cancellation is sampled between blocks and immediately before linking.
    /// Once linked, an uncertain final sync returns CommitUnknown and keeps the
    /// target. CleanupAfterCommit preserves the actual final retention. The query is
    /// content.query; callers must retain the destination
    /// too, since the query alone does not identify a named output to reconcile.
    pub fn write_file(
        &mut self,
        relative: impl AsRef<Path>,
        source: &mut impl BlockSource,
        content: Content,
        buffers: &mut Buffers,
        limits: Limits,
        mut control: impl FnMut(Progress) -> Control,
    ) -> Result<ReadFile> {
        self.write_file_inner(
            relative,
            source,
            content,
            buffers,
            limits,
            &mut control,
            true,
            observed::noop,
        )
        .map_err(observed::unobserved_failure)
    }

    /// Download an actual official FS file into an anchored private temporary,
    /// then use the same authenticated, synced, no-clobber commit as write_file.
    /// The optional repository caches only authenticated encrypted blocks.
    ///
    /// Dropping this future closes its dedicated service MQ and removes its own
    /// temporary; the final name is never linked before full authentication.
    /// Tokio file work is drained before the final descriptor sync/link barriers.
    /// Directory traversal and the final durability barriers use native blocking
    /// filesystem calls; the caller should place those calls on a host worker
    /// when its executor must not block on filesystem operations.
    ///
    /// Transfer preserves the original network error, including its cause and
    /// outcome; CleanupFailed additionally retains any temporary cleanup error.
    #[cfg(feature = "service")]
    #[expect(
        clippy::too_many_arguments,
        reason = "Destination, service, file, reusable buffers, cache and cancellation have independent ownership"
    )]
    pub async fn download_file(
        &mut self,
        relative: impl AsRef<Path>,
        source: gnunet_client_host::EndpointSource,
        content: Content,
        buffers: &mut Buffers,
        cache: Option<&mut crate::Repository>,
        options: crate::network::DownloadOptions,
        mut control: impl FnMut(Progress) -> Control,
    ) -> Result<ReadFile> {
        self.download_file_inner(
            relative,
            source,
            content,
            buffers,
            cache,
            options,
            &mut control,
            true,
            observed::noop,
        )
        .await
        .map_err(observed::unobserved_failure)
    }
}

fn ensure_absent(parent: &Directory, name: &OsStr) -> Result<()> {
    match parent.open_file(name) {
        Ok(_) => {
            Err(io::Error::new(io::ErrorKind::AlreadyExists, "FS output already exists").into())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
struct Temporary<'a> {
    parent: &'a Directory,
    name: OsString,
    file: File,
    identity: FileIdentity,
    removed: bool,
}
impl Temporary<'_> {
    fn check_link_at(&self, parent: &Directory, name: &OsStr) -> io::Result<()> {
        if parent.same_file(name, &self.file)? {
            Ok(())
        } else {
            Err(io::Error::other(
                "FS output entry no longer names its owned file",
            ))
        }
    }
    fn check_name(&self) -> io::Result<()> {
        self.check_link_at(self.parent, &self.name)
    }
    fn remove(&mut self) -> io::Result<()> {
        if self.removed {
            return Ok(());
        }
        match self.parent.remove_file(&self.name, &self.file) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        self.removed = true;
        Ok(())
    }
}
impl Drop for Temporary<'_> {
    fn drop(&mut self) {
        let _cleanup = self.remove();
    }
}

#[cfg(test)]
mod tests;
