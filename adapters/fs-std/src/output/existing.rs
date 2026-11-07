//! Complete anchored plaintext revalidation with genuine core reader receipts.
use super::{FileIdentity, OutputDir, components, invalid_name};
use crate::{Buffers, Control, Error, Limits, Progress, ReadFile, Repository, Result};
use gnunet_fs::Content;
use nix::{
    fcntl::{OFlag, openat},
    sys::stat::Mode,
};
use std::{
    fmt,
    fs::{File, Metadata},
    io,
    os::unix::fs::MetadataExt,
    path::Path,
};

/// Actual complete verification phase reached before a failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevalidateStage {
    /// No matching regular descriptor has been established.
    Unopened,
    /// A matching regular descriptor is held; plaintext is not yet certified.
    Opened,
    /// Complete plaintext was encoded, but expected Content/receipt may still fail.
    Encoded,
    /// A real FileReader authenticated expected Content; source/barriers may fail.
    Verified,
}
/// Revalidation failure retaining real authentication separately from output
/// naming/durability. A saved receipt alone never implies final-name success.
#[derive(Debug)]
pub struct RevalidateFailure<R = ReadFile> {
    /// Actual completed phase, independent of the original error.
    pub stage: RevalidateStage,
    /// Opened native file identity, if available.
    pub identity: Option<FileIdentity>,
    /// Real expected-content authentication receipt when actually obtained.
    pub receipt: Option<R>,
    /// Original source/cache/protocol/cancellation or uncertain barrier failure
    /// of this attempt.
    pub operation: Error,
    /// Earlier rejected attempt, if a fresh verification also failed. Its
    /// receipt is historical authentication, never final-name success.
    pub previous: Option<Box<Self>>,
    pub(super) fence: Fence,
}
impl<R> RevalidateFailure<R> {
    /// Source verification attempts represented by this failure, at most two.
    #[must_use]
    pub fn source_attempts(&self) -> u8 {
        if self.previous.is_some() { 2 } else { 1 }
    }
    fn can_stabilize(&self) -> bool {
        matches!(&self.operation, Error::SourceChanged)
            && self.fence.is_some_and(|(_, expected, observed)| {
                expected != observed
                    && Stamp {
                        changed: observed.changed,
                        changed_nanos: observed.changed_nanos,
                        ..expected
                    } == observed
            })
    }
}
// Soft updates may retire a prior unlink after fsync and update only ctime.
// Never waive a fence: restart the complete read once against fresh metadata.
// Other source changes, cancellation and uncertain barriers are not retried.
pub(super) fn stabilize<T, R>(
    mut operation: impl FnMut() -> std::result::Result<T, Box<RevalidateFailure<R>>>,
) -> std::result::Result<(T, u8), Box<RevalidateFailure<R>>> {
    let previous = match operation() {
        Ok(value) => return Ok((value, 1)),
        Err(failure) if failure.can_stabilize() => failure,
        Err(failure) => return Err(failure),
    };
    match operation() {
        Ok(value) => Ok((value, 2)),
        Err(mut failure) => {
            failure.previous = Some(previous);
            Err(failure)
        }
    }
}
impl<R> fmt::Display for RevalidateFailure<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FS existing-file revalidation {:?}: {}",
            self.stage, self.operation
        )?;
        if let Some((boundary, expected, observed)) = &self.fence {
            write!(
                f,
                "; {boundary}: expected {expected:?}, observed {observed:?}"
            )?;
        }
        if let Some(previous) = &self.previous {
            write!(f, "; earlier refusal: {previous}")?;
        }
        Ok(())
    }
}
impl<R: fmt::Debug> std::error::Error for RevalidateFailure<R> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.operation)
    }
}
/// Complete plaintext, path identity and refreshed naming/durability barriers.
#[derive(Clone, Copy, Debug)]
pub struct RevalidatedFile {
    /// Genuine core FileReader authentication receipt.
    pub read: ReadFile,
    /// Exact verified final file identity.
    pub identity: FileIdentity,
    /// Actual anchored parent whose naming barrier was refreshed.
    pub parent: FileIdentity,
    /// Source verification attempts, at most two. The receipt belongs exclusively
    /// to the final successful attempt; progress remains per encoding/read pass.
    pub source_attempts: u8,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Stamp {
    pub(super) identity: FileIdentity,
    pub(super) bytes: u64,
    modified: i64,
    modified_nanos: i64,
    changed: i64,
    changed_nanos: i64,
}
pub(super) type Fence = Option<(&'static str, Stamp, Stamp)>;
impl Stamp {
    fn metadata(metadata: Metadata) -> Result<Self> {
        if !metadata.is_file() {
            return Err(invalid_name());
        }
        Ok(Self {
            identity: FileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
            bytes: metadata.len(),
            modified: metadata.mtime(),
            modified_nanos: metadata.mtime_nsec(),
            changed: metadata.ctime(),
            changed_nanos: metadata.ctime_nsec(),
        })
    }
    pub(super) fn file(file: &File) -> Result<Self> {
        Self::metadata(file.metadata()?)
    }
    pub(super) fn check(
        self,
        file: &File,
        boundary: &'static str,
        fence: &mut Fence,
    ) -> Result<()> {
        let observed = Self::file(file)?;
        if observed != self {
            *fence = Some((boundary, self, observed));
            return Err(Error::SourceChanged);
        }
        Ok(())
    }
}
pub(super) const REGULAR: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_NONBLOCK)
    .union(OFlag::O_CLOEXEC);
impl OutputDir {
    /// Fully re-read an existing final name through its original regular FD,
    /// encode exact plaintext into the private cache, compare all Content fields
    /// and run the real FileReader to obtain a genuine VerifiedFile receipt.
    /// Original FD/path stamps and parent identity are checked around this work;
    /// size/mtime or cached byte counts alone never certify output. expected_parent
    /// additionally binds a recorded CommitIntent parent when supplied.
    ///
    /// File and parent fsync refresh uncertain barriers. Any failure preserves
    /// its actual receipt and original typed error, including CommitUnknown.
    /// A ctime-only drift permits one fresh complete verification; every stamp
    /// and barrier is checked again. Other changes/cancellation are not retried.
    #[expect(
        clippy::too_many_arguments,
        reason = "Expected content, original file/parent identity, bounded cache work and control have independent ownership"
    )]
    pub fn revalidate_file(
        &self,
        relative: impl AsRef<Path>,
        expected: Content,
        expected_identity: FileIdentity,
        expected_parent: Option<FileIdentity>,
        buffers: &mut Buffers,
        cache: &mut Repository,
        limits: Limits,
        mut control: impl FnMut(Progress) -> Control,
    ) -> std::result::Result<RevalidatedFile, Box<RevalidateFailure>> {
        let (mut verified, attempts) = stabilize(|| {
            self.revalidate_file_once(
                relative.as_ref(),
                expected,
                expected_identity,
                expected_parent,
                buffers,
                cache,
                limits,
                &mut control,
            )
        })?;
        verified.source_attempts = attempts;
        Ok(verified)
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "One complete attempt preserves the original source, content, bounded work and caller control"
    )]
    fn revalidate_file_once(
        &self,
        relative: &Path,
        expected: Content,
        expected_identity: FileIdentity,
        expected_parent: Option<FileIdentity>,
        buffers: &mut Buffers,
        cache: &mut Repository,
        limits: Limits,
        mut control: impl FnMut(Progress) -> Control,
    ) -> std::result::Result<RevalidatedFile, Box<RevalidateFailure>> {
        let mut stage = RevalidateStage::Unopened;
        let mut identity = None;
        let mut receipt = None;
        let mut fence = None;
        let result = (|| -> Result<RevalidatedFile> {
            let parts = components(relative)?;
            let (name, ancestors) = parts.split_last().ok_or_else(invalid_name)?;
            let parent = self.parent_existing(ancestors)?;
            let parent_id = FileIdentity::of(&parent)?;
            if expected_parent.is_some_and(|expected| expected != parent_id) {
                return Err(Error::SourceChanged);
            }
            let mut file = File::from(openat(&parent, *name, REGULAR, Mode::empty())?);
            let original = Stamp::file(&file)?;
            identity = Some(original.identity);
            if original.identity != expected_identity || original.bytes != expected.size {
                return Err(Error::SourceChanged);
            }
            stage = RevalidateStage::Opened;
            let encoded = buffers.publish(&mut file, expected.size, cache, limits, &mut control)?;
            stage = RevalidateStage::Encoded;
            if encoded.content != expected {
                return Err(Error::SourceChanged);
            }
            original.check(&file, "source-after-encoding", &mut fence)?;
            let read = buffers.copy_to(cache, expected, &mut io::sink(), limits, &mut control)?;
            receipt = Some(read);
            stage = RevalidateStage::Verified;
            let mut check = |source_boundary, name_boundary| -> Result<()> {
                original.check(&file, source_boundary, &mut fence)?;
                let current_parent = self.parent_existing(ancestors)?;
                if FileIdentity::of(&current_parent)? != parent_id {
                    return Err(Error::SourceChanged);
                }
                let current = File::from(openat(&current_parent, *name, REGULAR, Mode::empty())?);
                original.check(&current, name_boundary, &mut fence)?;
                Ok(())
            };
            check("source-before-sync", "name-before-sync")?;
            if control(read.progress) == Control::Cancel {
                return Err(Error::Cancelled);
            }
            file.sync_all().map_err(|source| Error::CommitUnknown {
                query: expected.query,
                source,
            })?;
            parent.sync_all().map_err(|source| Error::CommitUnknown {
                query: expected.query,
                source,
            })?;
            check("source-after-sync", "name-after-sync")?;
            Ok(RevalidatedFile {
                read,
                identity: original.identity,
                parent: parent_id,
                source_attempts: 1,
            })
        })();
        result.map_err(|operation| {
            Box::new(RevalidateFailure {
                stage,
                identity,
                receipt,
                operation,
                previous: None,
                fence,
            })
        })
    }
}
