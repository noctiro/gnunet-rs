//! Anchored, authenticated and no-clobber plaintext output.
mod artifact;
mod existing;
mod observed;
mod owned;
#[cfg(feature = "service")]
mod range;
use crate::{BlockSource, Buffers, Control, Error, Limits, Progress, ReadFile, Result};
pub use artifact::{ArtifactFailure, ArtifactReport};
pub use existing::{RevalidateFailure, RevalidateStage, RevalidatedFile};
use gnunet_fs::Content;
use nix::{
    errno::Errno,
    fcntl::{AtFlags, OFlag, open, openat},
    sys::stat::{FileStat, Mode, fstat, fstatat, mkdirat},
    unistd::{UnlinkatFlags, unlinkat},
};
#[cfg(any(feature = "service", test))]
pub(crate) use observed::OutputObservation;
#[cfg(feature = "service")]
pub(crate) use observed::TempRecord;
pub use observed::{CommitStage, FileIdentity, ObservedFailure};
pub use owned::{DirectoryStage, OWNER_MARKER_NAME, OwnedDirectoryFailure};
#[cfg(feature = "service")]
pub use range::{RevalidateRangeFailure, RevalidatedRange};
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io,
    os::unix::ffi::OsStrExt,
    path::Path,
};

const MAX_PATH_BYTES: usize = 4096;
const MAX_COMPONENTS: usize = 128;
const TEMP_PREFIX: &str = ".gnunet-fs-output-";
const DIRECTORY: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_DIRECTORY)
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_CLOEXEC);

fn invalid_name() -> Error {
    gnunet_types::Error::InvalidInput.into()
}
fn native(error: Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}
fn components(path: &Path) -> Result<Vec<&OsStr>> {
    // Path::components normalizes '.' before the caller can reject it. Inspect
    // the actual metadata bytes first, before mkdir or source/block operations.
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() > MAX_PATH_BYTES {
        return Err(Error::Limit);
    }
    if bytes.is_empty() || bytes[0] == b'/' || bytes.contains(&0) || bytes.contains(&b'\\') {
        return Err(invalid_name());
    }
    let mut result = Vec::new();
    for part in bytes.split(|byte| *byte == b'/') {
        if part.is_empty()
            || part == b"."
            || part == b".."
            || (part.len() >= 2 && part[0].is_ascii_alphabetic() && part[1] == b':')
        {
            return Err(invalid_name());
        }
        if result.len() == MAX_COMPONENTS {
            return Err(Error::Limit);
        }
        result.try_reserve(1).map_err(|_| Error::Limit)?;
        result.push(OsStr::from_bytes(part));
    }
    Ok(result)
}

/// A caller-selected existing directory, held by its actual descriptor. Renaming
/// or replacing the original root pathname cannot redirect an extraction.
/// Metadata paths are relative, at most4096 bytes/128 components, and never follow
/// symlinks. Parent directories may be created, but existing targets never change.
pub struct OutputDir {
    root: File,
    nonce: u64,
}
impl OutputDir {
    /// Duplicate the held directory descriptor, without reopening its pathname.
    #[cfg(feature = "service")]
    pub(crate) fn duplicate(&self) -> Result<Self> {
        Ok(Self {
            root: self.root.try_clone()?,
            nonce: self.nonce,
        })
    }
    #[cfg(feature = "network")]
    pub(crate) fn from_directory(root: File) -> Result<Self> {
        if !root.metadata()?.is_dir() {
            return Err(invalid_name());
        }
        Ok(Self { root, nonce: 0 })
    }
    /// Open an existing caller-selected directory; a final root symlink is refused.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let root = File::from(open(path.as_ref(), DIRECTORY, Mode::empty())?);
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
        mkdirat(&parent, *name, Mode::S_IRWXU)?;
        let root = File::from(openat(&parent, *name, DIRECTORY, Mode::empty())?);
        root.sync_all()?;
        parent.sync_all()?;
        Ok(Self { root, nonce: 0 })
    }
    /// Sync the actual anchored directory, including its completed child names.
    pub fn sync_directory(&self) -> Result<()> {
        self.root.sync_all()?;
        Ok(())
    }
    fn parent(&self, parts: &[&OsStr]) -> Result<File> {
        let mut parent = self.root.try_clone()?;
        for name in parts {
            let next = match openat(&parent, *name, DIRECTORY, Mode::empty()) {
                Ok(fd) => File::from(fd),
                Err(Errno::ENOENT) => {
                    match mkdirat(&parent, *name, Mode::S_IRWXU) {
                        Ok(()) | Err(Errno::EEXIST) => {}
                        Err(error) => return Err(error.into()),
                    }
                    let next = File::from(openat(&parent, *name, DIRECTORY, Mode::empty())?);
                    next.sync_all()?;
                    next
                }
                Err(error) => return Err(error.into()),
            };
            // Also repairs a prior interrupted mkdir that is now observed as
            // an existing component; each traversed parent naming barrier holds.
            parent.sync_all()?;
            parent = next;
        }
        Ok(parent)
    }
    fn temporary<'a>(&mut self, parent: &'a File, final_name: &OsStr) -> Result<Temporary<'a>> {
        for _ in 0..1024 {
            let nonce = self.nonce;
            self.nonce = nonce.checked_add(1).ok_or(Error::Limit)?;
            let name = OsString::from(format!("{TEMP_PREFIX}{}-{nonce}", std::process::id()));
            // A legal metadata name may itself use this prefix. Creating our
            // temporary at that same name would expose an unauthenticated prefix.
            if name.as_os_str() == final_name {
                continue;
            }
            match openat(
                parent,
                name.as_os_str(),
                OFlag::O_WRONLY
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC,
                Mode::S_IRUSR | Mode::S_IWUSR,
            ) {
                Ok(fd) => {
                    let file = File::from(fd);
                    // Retain cleanup ownership before any subsequent fallible call.
                    let identity = match fstat(&file) {
                        Ok(identity) => identity,
                        Err(error) => {
                            // The descriptor was created exclusively by this call;
                            // no other output pathname has been admitted.
                            let _cleanup =
                                unlinkat(parent, name.as_os_str(), UnlinkatFlags::NoRemoveDir);
                            return Err(error.into());
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
                Err(Errno::EEXIST) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(Error::Limit)
    }
    /// Authenticate and stream a file to an owned temporary in its destination
    /// directory. Only a fully authenticated, file-synced and no-clobber-linked
    /// file whose directory has been synced returns a completed receipt.
    ///
    /// Cancellation is sampled between blocks and immediately before linking.
    /// Once linked, an uncertain final sync returns CommitUnknown and keeps the
    /// target. CleanupAfterCommit preserves a known durable target. The query is
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

fn ensure_absent(parent: &File, name: &OsStr) -> Result<()> {
    match fstatat(parent, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(_) => {
            Err(io::Error::new(io::ErrorKind::AlreadyExists, "FS output already exists").into())
        }
        Err(Errno::ENOENT) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

struct Temporary<'a> {
    parent: &'a File,
    name: OsString,
    file: File,
    identity: FileStat,
    removed: bool,
}
impl Temporary<'_> {
    fn matches(&self, current: &FileStat) -> bool {
        current.st_dev == self.identity.st_dev && current.st_ino == self.identity.st_ino
    }
    fn check_link_at(&self, parent: &File, name: &OsStr) -> io::Result<()> {
        let current = fstatat(parent, name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(native)?;
        if !self.matches(&current) {
            return Err(io::Error::other(
                "FS output entry no longer names its owned file",
            ));
        }
        Ok(())
    }
    fn check_name(&self) -> io::Result<()> {
        self.check_link_at(self.parent, self.name.as_os_str())
    }
    fn remove(&mut self) -> io::Result<()> {
        if self.removed {
            return Ok(());
        }
        match fstatat(
            self.parent,
            self.name.as_os_str(),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        ) {
            Ok(current) if self.matches(&current) => {
                unlinkat(
                    self.parent,
                    self.name.as_os_str(),
                    UnlinkatFlags::NoRemoveDir,
                )
                .map_err(native)?;
            }
            Err(Errno::ENOENT) => {}
            Ok(_) => {
                return Err(io::Error::other(
                    "FS output temporary was replaced; foreign entry retained",
                ));
            }
            Err(error) => return Err(native(error)),
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
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions check actual authenticated output and filesystem safety boundaries"
)]
mod tests {
    use super::*;
    use crate::{BlockSink, Insert};
    use gnunet_fs::content::{BLOCK_BYTES, EncodedNode, NodeRef};
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Cleanup(std::path::PathBuf);
    impl Cleanup {
        fn new() -> io::Result<Self> {
            let path = std::env::temp_dir().join(format!(
                "gnunet-fs-output-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path)?;
            Ok(Self(path))
        }
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _cleanup = fs::remove_dir_all(&self.0);
        }
    }
    #[derive(Default)]
    struct Blocks {
        rows: Vec<([u8; 64], Vec<u8>)>,
        data_reads: usize,
        corrupt_second: bool,
    }
    impl BlockSink for Blocks {
        fn insert_block(&mut self, encoded: EncodedNode<'_>) -> Result<Insert> {
            self.rows.push((
                encoded.block().key().query,
                encoded.block().bytes().to_vec(),
            ));
            Ok(Insert::Created)
        }
    }
    impl BlockSource for Blocks {
        fn read_block(&mut self, request: NodeRef, output: &mut [u8]) -> Result<usize> {
            let bytes = &self
                .rows
                .iter()
                .find(|row| row.0 == request.key().query)
                .ok_or(Error::Corrupt)?
                .1;
            output
                .get_mut(..bytes.len())
                .ok_or(Error::Corrupt)?
                .copy_from_slice(bytes);
            if request.node().level() == 0 {
                self.data_reads += 1;
                if self.corrupt_second && self.data_reads == 2 {
                    output[bytes.len() - 1] ^= 1;
                }
            }
            Ok(bytes.len())
        }
    }
    fn input() -> Vec<u8> {
        (0..BLOCK_BYTES + 1).map(|n| (n % 251) as u8).collect()
    }
    fn published(bytes: &[u8]) -> Result<(Content, Blocks)> {
        let mut source = Blocks::default();
        let file = Buffers::new().publish(
            &mut &bytes[..],
            bytes.len() as u64,
            &mut source,
            Limits::default(),
            |_| Control::Continue,
        )?;
        Ok((file.content, source))
    }
    #[test]
    fn nested_authenticated_output_stays_on_the_original_directory_descriptor() -> Result<()> {
        let root = Cleanup::new()?;
        let selected = root.0.join("selected");
        fs::create_dir(&selected)?;
        let mut output = OutputDir::open(&selected)?;
        let moved = root.0.join("original");
        fs::rename(&selected, &moved)?;
        fs::create_dir(&selected)?;
        let bytes = input();
        let (content, mut source) = published(&bytes)?;
        let read = output.write_file(
            "a/b/file.bin",
            &mut source,
            content,
            &mut Buffers::new(),
            Limits::default(),
            |_| Control::Continue,
        )?;
        assert_eq!(read.verified.content(), content);
        assert_eq!(read.progress.plaintext_bytes, bytes.len() as u64);
        assert_eq!(fs::read(moved.join("a/b/file.bin"))?, bytes);
        assert!(!selected.join("a").exists());
        assert_eq!(fs::read_dir(moved.join("a/b"))?.count(), 1);
        Ok(())
    }
    #[test]
    fn unsafe_names_symlinks_and_existing_targets_leave_all_sentinels_unchanged() -> Result<()> {
        let root = Cleanup::new()?;
        let selected = root.0.join("selected");
        let outside = root.0.join("outside");
        fs::create_dir(&selected)?;
        fs::create_dir(&outside)?;
        fs::write(selected.join("existing"), b"keep-existing")?;
        fs::write(outside.join("sentinel"), b"keep-outside")?;
        std::os::unix::fs::symlink(&outside, selected.join("escape"))?;
        std::os::unix::fs::symlink(outside.join("sentinel"), selected.join("final-link"))?;
        let (content, mut source) = published(b"authenticated")?;
        let mut output = OutputDir::open(&selected)?;
        let mut buffers = Buffers::new();
        for name in [
            "/absolute",
            "../outside/sentinel",
            "safe/../bad",
            "C:/bad",
            "C:bad",
            "a/C:bad",
            "a\\b",
            "nul\0bad",
            ".",
            "a//b",
            "a/",
        ] {
            assert!(matches!(
                output.write_file(
                    name,
                    &mut source,
                    content,
                    &mut buffers,
                    Limits::default(),
                    |_| Control::Continue
                ),
                Err(Error::Protocol(gnunet_types::Error::InvalidInput))
            ));
        }
        for name in ["escape/sentinel", "final-link", "existing"] {
            assert!(
                output
                    .write_file(
                        name,
                        &mut source,
                        content,
                        &mut buffers,
                        Limits::default(),
                        |_| Control::Continue
                    )
                    .is_err()
            );
        }
        assert_eq!(fs::read(selected.join("existing"))?, b"keep-existing");
        assert_eq!(fs::read(outside.join("sentinel"))?, b"keep-outside");
        assert!(!selected.join("safe").exists());
        assert!(!selected.join("a").exists());
        assert_eq!(source.data_reads, 0);
        assert_eq!(fs::read_dir(&outside)?.count(), 1);
        Ok(())
    }
    #[test]
    fn failed_authentication_and_cancelled_prefix_never_publish_or_leave_own_temporary()
    -> Result<()> {
        let root = Cleanup::new()?;
        let selected = root.0.join("selected");
        fs::create_dir(&selected)?;
        fs::write(selected.join("sentinel"), b"keep")?;
        let bytes = input();
        let (content, mut source) = published(&bytes)?;
        source.corrupt_second = true;
        let mut output = OutputDir::open(&selected)?;
        let mut buffers = Buffers::new();
        assert!(
            output
                .write_file(
                    "partial/corrupt",
                    &mut source,
                    content,
                    &mut buffers,
                    Limits::default(),
                    |_| Control::Continue
                )
                .is_err()
        );
        assert!(!selected.join("partial/corrupt").exists());
        assert_eq!(fs::read_dir(selected.join("partial"))?.count(), 0);
        source.corrupt_second = false;
        source.data_reads = 0;
        let mut output = OutputDir::open(&selected)?;
        let final_name = format!("{TEMP_PREFIX}{}-0", std::process::id());
        let mut saw_prefix = false;
        let result = output.write_file(
            &final_name,
            &mut source,
            content,
            &mut buffers,
            Limits::default(),
            |progress| {
                assert!(!selected.join(&final_name).exists());
                if progress.plaintext_bytes != 0 {
                    saw_prefix = true;
                    Control::Cancel
                } else {
                    Control::Continue
                }
            },
        );
        assert!(matches!(result, Err(Error::Cancelled)));
        assert!(saw_prefix);
        assert!(!selected.join(final_name).exists());
        assert_eq!(fs::read(selected.join("sentinel"))?, b"keep");
        assert!(fs::read_dir(&selected)?.all(|entry| {
            entry.is_ok_and(|entry| {
                entry.file_name() == "sentinel" || entry.file_name() == "partial"
            })
        }));
        Ok(())
    }

    #[cfg(feature = "service")]
    #[tokio::test(flavor = "current_thread")]
    async fn network_download_cache_uses_the_same_owned_no_clobber_commit() -> Result<()> {
        let root = Cleanup::new()?;
        let selected = root.0.join("selected");
        fs::create_dir(&selected)?;
        let bytes = input();
        let mut repository = crate::Repository::open(root.0.join("repository"))?;
        let content = Buffers::new()
            .publish(
                &mut bytes.as_slice(),
                bytes.len() as u64,
                &mut repository,
                Limits::default(),
                |_| Control::Continue,
            )?
            .content;
        let mut output = OutputDir::open(&selected)?;
        let mut buffers = Buffers::new();
        let options =
            crate::network::DownloadOptions::new(gnunet_types::AbsoluteTime::from_micros(u64::MAX));
        let read = output
            .download_file(
                "a/b/download.bin",
                gnunet_client_host::EndpointSource::unix(root.0.join("not-running.sock")),
                content,
                &mut buffers,
                Some(&mut repository),
                options,
                |_| Control::Continue,
            )
            .await?;
        assert_eq!(read.verified.content(), content);
        assert_eq!(read.progress.plaintext_bytes, bytes.len() as u64);
        assert_eq!(fs::read(selected.join("a/b/download.bin"))?, bytes);
        assert_eq!(fs::read_dir(selected.join("a/b"))?.count(), 1);
        assert!(matches!(
            output
                .download_file(
                    "a/b/download.bin",
                    gnunet_client_host::EndpointSource::unix(root.0.join("not-running.sock")),
                    content,
                    &mut buffers,
                    Some(&mut repository),
                    options,
                    |_| Control::Continue,
                )
                .await,
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists
        ));
        assert_eq!(fs::read(selected.join("a/b/download.bin"))?, bytes);
        Ok(())
    }

    #[cfg(feature = "service")]
    #[tokio::test(flavor = "current_thread")]
    async fn network_failure_and_dropped_pending_download_remove_only_the_owned_temporary()
    -> Result<()> {
        use std::{future::Future, task::Poll};
        let root = Cleanup::new()?;
        let selected = root.0.join("selected");
        fs::create_dir(&selected)?;
        fs::write(selected.join("sentinel"), b"keep")?;
        let (content, _) = published(b"authenticated")?;
        let mut output = OutputDir::open(&selected)?;
        let mut buffers = Buffers::new();
        let mut options =
            crate::network::DownloadOptions::new(gnunet_types::AbsoluteTime::from_micros(u64::MAX));
        options.io_slice_bytes = 0;
        let refused = output
            .download_file(
                "refused",
                gnunet_client_host::EndpointSource::unix(root.0.join("not-running.sock")),
                content,
                &mut buffers,
                None,
                options,
                |_| Control::Continue,
            )
            .await;
        assert!(matches!(
            refused,
            Err(Error::Transfer(error))
                if matches!(*error, crate::network::Error::Protocol(gnunet_types::Error::InvalidInput))
        ));
        assert!(!selected.join("refused").exists());
        assert_eq!(fs::read_dir(&selected)?.count(), 1);
        options.io_slice_bytes = 1;
        let mut waiting = Box::pin(output.download_file(
            "pending",
            gnunet_client_host::EndpointSource::unix(root.0.join("not-running.sock")),
            content,
            &mut buffers,
            None,
            options,
            |_| Control::Continue,
        ));
        std::future::poll_fn(|cx| {
            assert!(waiting.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert!(!selected.join("pending").exists());
        assert_eq!(fs::read_dir(&selected)?.count(), 2);
        drop(waiting);
        assert!(!selected.join("pending").exists());
        assert_eq!(fs::read_dir(&selected)?.count(), 1);
        assert_eq!(fs::read(selected.join("sentinel"))?, b"keep");
        Ok(())
    }
    #[test]
    fn commit_intent_observer_failure_vetoes_link_and_retains_real_read_receipt() -> Result<()> {
        let directory = Cleanup::new()?;
        let mut output = OutputDir::open(&directory.0)?;
        let (content, mut source) = published(b"authenticated")?;
        let mut events = Vec::new();
        let result = output.write_file_observed(
            "veto",
            &mut source,
            content,
            &mut Buffers::new(),
            Limits::default(),
            |_| Control::Continue,
            |event| {
                let code = match event {
                    OutputObservation::TempOwned(_) => 0,
                    OutputObservation::CommitIntent { .. } => 1,
                    OutputObservation::FileCommitted { .. } => 2,
                    OutputObservation::Cleanup { .. } => 3,
                };
                events.push(code);
                if code == 1 {
                    Err("intent storage failed")
                } else {
                    Ok(())
                }
            },
        );
        let error = match result {
            Err(error) => error,
            Ok(_) => return Err(Error::Corrupt),
        };
        assert_eq!(error.stage, CommitStage::NotLinked);
        assert!(error.operation.is_none());
        assert_eq!(error.observer, Some("intent storage failed"));
        assert!(error.cleanup.is_none());
        assert_eq!(
            error.receipt.map(|read| read.verified.content()),
            Some(content)
        );
        assert_eq!(events, vec![0, 1]);
        assert!(!directory.0.join("veto").exists());
        assert_eq!(fs::read_dir(&directory.0)?.count(), 0);
        Ok(())
    }
    #[test]
    fn committed_observer_failure_preserves_durable_output_and_exact_cleanup() -> Result<()> {
        let directory = Cleanup::new()?;
        let mut output = OutputDir::open(&directory.0)?;
        let (content, mut source) = published(b"authenticated")?;
        let result = output.write_file_observed(
            "committed",
            &mut source,
            content,
            &mut Buffers::new(),
            Limits::default(),
            |_| Control::Continue,
            |event| {
                if matches!(event, OutputObservation::FileCommitted { .. }) {
                    Err("commit record failed")
                } else {
                    Ok(())
                }
            },
        );
        let error = match result {
            Err(error) => error,
            Ok(_) => return Err(Error::Corrupt),
        };
        assert_eq!(error.stage, CommitStage::Durable);
        assert!(error.operation.is_none());
        assert_eq!(error.observer, Some("commit record failed"));
        assert!(error.cleanup.is_none());
        assert_eq!(
            error.receipt.map(|read| read.verified.content()),
            Some(content)
        );
        assert_eq!(fs::read(directory.0.join("committed"))?, b"authenticated");
        assert_eq!(fs::read_dir(&directory.0)?.count(), 1);
        Ok(())
    }
    #[cfg(feature = "service")]
    #[tokio::test(flavor = "current_thread")]
    async fn staged_range_retains_absolute_offsets_and_revalidates_only_selected_bytes()
    -> Result<()> {
        use crate::network::range::{Completion, Options};
        use std::{convert::Infallible, os::unix::fs::FileExt};
        let root = Cleanup::new()?;
        let selected = root.0.join("selected");
        fs::create_dir(&selected)?;
        let mut output = OutputDir::open(&selected)?;
        let owner = [73; 32];
        let mut staging = output
            .create_owned_directory("stage", owner)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let parent_id = output.identity()?;
        let stage_id = staging.identity()?;
        let moved = root.0.join("original");
        fs::rename(&selected, &moved)?;
        fs::create_dir(&selected)?;
        fs::write(selected.join("sentinel"), b"foreign")?;
        let bytes = input();
        let mut cache = crate::Repository::open(root.0.join("cache"))?;
        let mut buffers = Buffers::new();
        let content = buffers
            .publish(
                &mut bytes.as_slice(),
                bytes.len() as u64,
                &mut cache,
                Limits::default(),
                |_| Control::Continue,
            )?
            .content;
        let selection = BLOCK_BYTES as u64 - 5..bytes.len() as u64;
        let options = Options {
            download: crate::network::DownloadOptions::new(gnunet_types::AbsoluteTime::NEVER),
            native_deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(5),
        };
        let mut committed = false;
        let read = output
            .download_range_observed(
                "range.bin",
                &mut staging,
                gnunet_client_host::EndpointSource::unix(root.0.join("absent.sock")),
                content,
                selection.clone(),
                &mut buffers,
                Some(&mut cache),
                options,
                |_| Control::Continue,
                |event| {
                    if let OutputObservation::FileCommitted {
                        temporary,
                        final_parent,
                        ..
                    } = event
                    {
                        assert_eq!(temporary.parent, stage_id);
                        assert_eq!(final_parent, parent_id);
                        committed = true;
                    }
                    Ok::<_, Infallible>(())
                },
            )
            .await
            .map_err(|error| io::Error::other(error.to_string()))?;
        assert!(committed);
        assert_eq!(read.delivered_bytes, 6);
        assert_eq!(
            read.destination,
            crate::network::range::Destination::SinkCompleted
        );
        assert!(
            matches!(read.completion, Completion::Verified(proof) if proof.range() == selection)
        );
        let actual = fs::read(moved.join("range.bin"))?;
        assert_eq!(actual.len(), bytes.len());
        assert!(
            actual[..selection.start as usize]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert_eq!(
            &actual[selection.start as usize..],
            &bytes[selection.start as usize..]
        );
        assert!(!selected.join("range.bin").exists());
        assert_eq!(fs::read(selected.join("sentinel"))?, b"foreign");
        assert_eq!(fs::read_dir(moved.join("stage"))?.count(), 1);
        drop(staging);
        let _stage = output
            .attach_owned_directory("stage", owner, Some(stage_id))
            .map_err(|error| io::Error::other(error.to_string()))?;
        let identity = output.inspect_file("range.bin")?.ok_or(Error::Corrupt)?;
        // A change outside the selected interval does not acquire or invalidate
        // a whole-file claim: only the actual selected bytes are compared.
        let held = fs::OpenOptions::new()
            .write(true)
            .open(moved.join("range.bin"))?;
        held.write_all_at(b"X", 0)?;
        let reread = output
            .revalidate_range(
                "range.bin",
                content,
                selection.clone(),
                identity,
                Some(parent_id),
                &mut buffers,
                &mut cache,
                Limits::default(),
                |_| Control::Continue,
            )
            .map_err(|error| io::Error::other(error.to_string()))?;
        assert_eq!(reread.read.delivered_bytes, 6);
        assert_eq!(
            reread.read.destination,
            crate::network::range::Destination::ExistingFileCompared
        );
        held.write_all_at(b"!", selection.start)?;
        let refused = output.revalidate_range(
            "range.bin",
            content,
            selection,
            identity,
            Some(parent_id),
            &mut buffers,
            &mut cache,
            Limits::default(),
            |_| Control::Continue,
        );
        assert!(
            matches!(refused, Err(error) if matches!(error.operation, Error::SourceChanged) && error.receipt.is_none())
        );
        assert!(moved.join("range.bin").exists());
        Ok(())
    }
}
