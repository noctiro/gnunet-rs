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
    /// Original source/cache/protocol/cancellation or uncertain barrier failure.
    pub operation: Error,
}
impl<R> fmt::Display for RevalidateFailure<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FS existing-file revalidation {:?}: {}",
            self.stage, self.operation
        )
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
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct Stamp {
    pub(super) identity: FileIdentity,
    pub(super) bytes: u64,
    modified: i64,
    modified_nanos: i64,
    changed: i64,
    changed_nanos: i64,
}
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
        let mut stage = RevalidateStage::Unopened;
        let mut identity = None;
        let mut receipt = None;
        let result = (|| -> Result<RevalidatedFile> {
            let parts = components(relative.as_ref())?;
            let (name, ancestors) = parts.split_last().ok_or_else(invalid_name)?;
            let parent = self.parent_existing(ancestors)?;
            let parent_id = FileIdentity::of(&parent)?;
            if expected_parent.is_some_and(|expected| expected != parent_id) {
                return Err(Error::SourceChanged);
            }
            let mut file = File::from(openat(&parent, *name, REGULAR, Mode::empty())?);
            // Settle pending filesystem metadata before anchoring the read fence.
            #[cfg(target_os = "freebsd")]
            file.sync_all().map_err(|source| Error::CommitUnknown {
                query: expected.query,
                source,
            })?;
            let original = Stamp::file(&file)?;
            identity = Some(original.identity);
            if original.identity != expected_identity || original.bytes != expected.size {
                return Err(Error::SourceChanged);
            }
            stage = RevalidateStage::Opened;
            let encoded = buffers.publish(&mut file, expected.size, cache, limits, &mut control)?;
            stage = RevalidateStage::Encoded;
            if encoded.content != expected || Stamp::file(&file)? != original {
                return Err(Error::SourceChanged);
            }
            let read = buffers.copy_to(cache, expected, &mut io::sink(), limits, &mut control)?;
            receipt = Some(read);
            stage = RevalidateStage::Verified;
            let check = || -> Result<()> {
                if Stamp::file(&file)? != original {
                    return Err(Error::SourceChanged);
                }
                let current_parent = self.parent_existing(ancestors)?;
                if FileIdentity::of(&current_parent)? != parent_id {
                    return Err(Error::SourceChanged);
                }
                let current = File::from(openat(&current_parent, *name, REGULAR, Mode::empty())?);
                if Stamp::file(&current)? != original {
                    return Err(Error::SourceChanged);
                }
                Ok(())
            };
            check()?;
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
            check()?;
            Ok(RevalidatedFile {
                read,
                identity: original.identity,
                parent: parent_id,
            })
        })();
        result.map_err(|operation| {
            Box::new(RevalidateFailure {
                stage,
                identity,
                receipt,
                operation,
            })
        })
    }
}
