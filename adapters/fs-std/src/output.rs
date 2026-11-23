//! Anchored, authenticated and no-clobber plaintext output.
mod artifact;
mod existing;
mod observed;
mod owned;
mod path;
#[cfg(feature = "service")]
mod retained;
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
#[cfg(feature = "service")]
pub use retained::IncompleteOutput;
use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    fs::File,
    io,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

#[derive(Clone, Copy)]
pub(crate) struct TemporaryNames<'a> {
    location: TemporaryLocation<'a>,
    next: &'a AtomicU64,
}

#[derive(Clone, Copy)]
#[cfg_attr(
    not(feature = "service"),
    expect(
        dead_code,
        reason = "Native tree extraction is enabled by the service feature"
    )
)]
enum TemporaryLocation<'a> {
    Parent(&'a BTreeSet<OsString>),
    Stage(&'a Directory),
}

impl<'a> TemporaryNames<'a> {
    #[cfg(feature = "service")]
    pub(crate) fn in_parent(reserved: &'a BTreeSet<OsString>, next: &'a AtomicU64) -> Self {
        Self {
            location: TemporaryLocation::Parent(reserved),
            next,
        }
    }
    #[cfg(feature = "service")]
    pub(crate) fn in_stage(directory: &'a Directory, next: &'a AtomicU64) -> Self {
        Self {
            location: TemporaryLocation::Stage(directory),
            next,
        }
    }
}

#[derive(Clone, Copy)]
struct FilePlacement<'a> {
    create_parents: bool,
    temporary: Option<TemporaryNames<'a>>,
}

impl FilePlacement<'_> {
    const CREATE_PARENTS: Self = Self {
        create_parents: true,
        temporary: None,
    };
    #[cfg(any(test, feature = "service"))]
    const EXISTING_PARENT: Self = Self {
        create_parents: false,
        temporary: None,
    };

    fn temporary_parent<'a>(
        self,
        parent: &'a Directory,
        identity: FileIdentity,
    ) -> io::Result<(&'a Directory, FileIdentity)>
    where
        Self: 'a,
    {
        match self.temporary.map(|names| names.location) {
            Some(TemporaryLocation::Stage(stage)) => {
                Ok((stage, FileIdentity::of(stage.as_file())?))
            }
            _ => Ok((parent, identity)),
        }
    }
}

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
    #[cfg(feature = "service")]
    pub(crate) fn stage_next_to(&self, relative: &Path) -> Result<FileStage> {
        let parts = components(relative)?;
        let (_, ancestors) = parts.split_last().ok_or_else(invalid_name)?;
        let parent = self.parent_existing(ancestors)?;
        for _ in 0..32 {
            let mut random = [0; 8];
            gnunet_native::entropy::fill(&mut random)?;
            let name = OsString::from(format!(".gnunet-fs-{:016x}", u64::from_ne_bytes(random)));
            match parent.create_private_directory(&name) {
                Ok(directory) => {
                    return Ok(FileStage {
                        parent,
                        name,
                        directory,
                        removed: false,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(Error::Limit)
    }
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
        self.temporary_with_reservations(parent, final_name, None)
    }
    fn temporary_with_reservations<'a>(
        &mut self,
        parent: &'a Directory,
        final_name: &OsStr,
        names: Option<TemporaryNames<'_>>,
    ) -> Result<Temporary<'a>> {
        let reserved = match names.map(|names| names.location) {
            Some(TemporaryLocation::Parent(reserved)) => Some(reserved),
            _ => None,
        };
        let limit = 1024 + reserved.map_or(0, BTreeSet::len).min(10_000_000);
        for _ in 0..limit {
            let nonce = if let Some(names) = names {
                names
                    .next
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
                    .map_err(|_| Error::Limit)?
            } else {
                let nonce = self.nonce;
                self.nonce = nonce.checked_add(1).ok_or(Error::Limit)?;
                nonce
            };
            let name = temporary_name(nonce);
            // A legal metadata name may itself use this prefix. Creating our
            // temporary at that same name would expose an unauthenticated prefix.
            if name.as_os_str() == final_name || reserved.is_some_and(|names| names.contains(&name))
            {
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
            FilePlacement::CREATE_PARENTS,
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
            FilePlacement::CREATE_PARENTS,
            observed::noop,
        )
        .await
        .map_err(observed::unobserved_failure)
    }

    #[cfg(feature = "service")]
    #[expect(
        clippy::too_many_arguments,
        reason = "Tree admission provides independent source, anchored output and sibling names"
    )]
    pub(crate) async fn download_tree_file(
        &mut self,
        path: &Path,
        source: &gnunet_client_host::EndpointSource,
        content: Content,
        buffers: &mut Buffers,
        cache: Option<&mut crate::Repository>,
        options: crate::network::DownloadOptions,
        inline: Option<&mut crate::network::tree_download::inline::InlineBlocks>,
        temporary: TemporaryNames<'_>,
        control: impl FnMut(Progress) -> Control,
    ) -> Result<ReadFile> {
        let placement = FilePlacement {
            temporary: Some(temporary),
            ..FilePlacement::EXISTING_PARENT
        };
        match inline {
            Some(blocks) => self.write_file_inner(
                path,
                blocks,
                content,
                buffers,
                options.limits,
                control,
                placement,
                observed::noop,
            ),
            None => {
                self.download_file_inner(
                    path,
                    source.duplicate().map_err(crate::network::Error::from)?,
                    content,
                    buffers,
                    cache,
                    options,
                    control,
                    placement,
                    observed::noop,
                )
                .await
            }
        }
        .map_err(observed::unobserved_failure)
    }
}

#[cfg(feature = "service")]
pub(crate) struct FileStage {
    parent: Directory,
    name: OsString,
    pub directory: Directory,
    removed: bool,
}

#[cfg(feature = "service")]
impl FileStage {
    pub(crate) fn cleanup(&mut self) -> io::Result<()> {
        if !self.removed {
            self.parent.remove_directory(&self.name, &self.directory)?;
            self.removed = true;
            self.parent.sync()?;
        }
        Ok(())
    }
}

#[cfg(feature = "service")]
impl Drop for FileStage {
    fn drop(&mut self) {
        let _cleanup = self.cleanup();
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
