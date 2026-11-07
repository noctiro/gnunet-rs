//! Bounded descriptor-anchored full or explicitly indexed native tree publication.
//!
//! Every file and postorder directory uses actual DATASTORE acknowledgements.
//! Sources are regular files/directories only. Directories always use full
//! insertion. Remote replication, symlink following, replay and rollback are
//! never inferred.
pub(crate) mod plan;
mod runner;
use super::{
    Error as NetworkError, IndexPublishError, IndexedFile, PublishOptions, StoreFailure, StoredFile,
};
use crate::Progress;
use crate::input_tree::{InputDir, SourceError};
use gnunet_datastore_host::{Limits as NativeLimits, ProtocolLimits};
use gnunet_fs::{Content, directory as dir, metadata as md};
use gnunet_types::Error as ProtocolError;
use std::{
    fmt,
    path::{Path, PathBuf},
};

/// Global bounds apply to the whole operation, not independently to each node.
#[derive(Clone, Copy, Debug)]
pub struct TreeLimits {
    /// Maximum relative component depth. The root itself has depth zero.
    pub max_depth: usize,
    /// Total file/directory entries, excluding the selected root.
    pub max_entries: u64,
    /// Maximum immediate children retained for any one directory.
    pub max_children: usize,
    /// Maximum raw Unix basename bytes and complete relative path bytes.
    pub max_name_bytes: usize,
    /// Maximum complete root-relative Unix path bytes.
    pub max_path_bytes: usize,
    /// Name bytes retained across the entire live DFS stack.
    pub max_retained_name_bytes: usize,
    /// One complete metadata artifact and one prepared directory record.
    pub max_metadata_bytes: usize,
    /// Maximum one URI/metadata record arena.
    pub max_record_bytes: usize,
    /// Metadata and record arenas retained across the live DFS stack.
    pub max_retained_metadata_bytes: usize,
    /// Maximum record arenas across all live ancestor frames.
    pub max_retained_record_bytes: usize,
    /// Total planned metadata and record arenas across all directories.
    pub max_total_metadata_bytes: u64,
    /// Maximum sum of all prepared record arena bounds.
    pub max_total_record_bytes: u64,
    /// Total regular-file plaintext and generated directory artifact bytes.
    pub max_file_bytes: u64,
    /// Maximum sum of actual generated directory extents.
    pub max_directory_bytes: u64,
    /// Maximum one generated directory artifact, including official padding.
    pub max_directory_extent: u64,
    /// Total computed ciphertext bytes, including indexed leaves whose real
    /// stored payload is instead an official type6 descriptor.
    pub max_encoded_bytes: u128,
    /// Total actual DATASTORE payload bytes, including each 72-byte type6 leaf.
    pub max_stored_bytes: u128,
}
impl Default for TreeLimits {
    fn default() -> Self {
        let source = crate::input_tree::Limits::default();
        Self {
            max_depth: source.max_depth,
            max_entries: source.max_entries,
            max_children: source.max_children,
            max_name_bytes: source.max_name_bytes,
            max_path_bytes: source.max_path_bytes,
            max_retained_name_bytes: source.max_retained_name_bytes,
            max_metadata_bytes: 64 * 1024,
            max_record_bytes: 128 * 1024,
            max_retained_metadata_bytes: 16 * 1024 * 1024,
            max_retained_record_bytes: 32 * 1024 * 1024,
            max_total_metadata_bytes: 128 * 1024 * 1024,
            max_total_record_bytes: 256 * 1024 * 1024,
            max_file_bytes: 256 * 1024 * 1024 * 1024,
            max_directory_bytes: 256 * 1024 * 1024,
            max_directory_extent: 64 * 1024 * 1024,
            max_encoded_bytes: 512 * 1024 * 1024 * 1024,
            max_stored_bytes: 512 * 1024 * 1024 * 1024,
        }
    }
}
/// Caller-selected service, insertion policy and whole-operation resource bounds.
#[derive(Clone, Copy, Debug)]
pub struct TreePublishOptions {
    /// One original source-clock deadline and exact official block policy.
    pub publish: PublishOptions,
    /// Global tree traversal, metadata, record and payload bounds.
    pub limits: TreeLimits,
    /// Each artifact owns one fresh request slot and its own original MQ.
    pub protocol: ProtocolLimits,
    /// Explicit native framing/reply bounds for each dedicated client.
    pub native: NativeLimits,
}
impl TreePublishOptions {
    /// Use bounded tree policy and one dedicated DATASTORE slot per artifact.
    #[must_use]
    pub fn new(publish: PublishOptions) -> Self {
        Self {
            publish,
            limits: TreeLimits::default(),
            protocol: ProtocolLimits {
                max_pending: 1,
                ..Default::default()
            },
            native: NativeLimits {
                reply_frames: 1,
                reply_bytes: 65535,
                ..Default::default()
            },
        }
    }
}
/// Completed actual object acknowledgements. Partial current-object ACKs remain
/// separate in TreeEvent/TreePublishFailure so no arithmetic can erase them.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TreeProgress {
    /// Entries discovered in bounded sorted listings, excluding the root.
    pub entries: u64,
    /// Objects whose complete CHKs were acknowledged, independent of source
    /// coherence checks or a later cleanup/final verification failure.
    pub files: u64,
    /// Complete acknowledged indexed file objects, including duplicate IDs.
    pub indexed_files: u64,
    /// Complete acknowledged directory objects, including the root.
    pub directories: u64,
    /// Plaintext bytes of complete acknowledged regular-file objects.
    pub file_bytes: u64,
    /// Wire artifact bytes of complete acknowledged directory objects.
    pub directory_bytes: u64,
    /// Actual acknowledged plaintext/node/ciphertext totals of those objects.
    pub acknowledged: Progress,
    /// Actual accepted payload bytes; indexed leaves count 72 descriptor bytes,
    /// independently of the computed ciphertext bytes in acknowledged.
    pub stored_bytes: u128,
}
/// Publication phase; verification performs no DATASTORE mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TreeStage {
    /// Regular-file insertion, full or explicitly indexed.
    File,
    /// Full postorder directory insertion.
    Directory,
    /// Final source-coherence pass, with no DATASTORE writes.
    Verify,
}
/// The caller may explicitly journal each completed CHK without forcing this
/// publisher to retain an entire-tree receipt/manifest in memory.
#[derive(Clone, Copy, Debug)]
pub struct TreeEvent<'a> {
    /// Exact root-relative Unix path. Empty means the selected root directory.
    pub path: &'a Path,
    /// Current filesystem/publication phase.
    pub stage: TreeStage,
    /// Whole-operation completed-object accounting.
    pub progress: TreeProgress,
    /// Current object's exact acknowledged prefix in addition to progress.
    pub current: Progress,
    /// Present only after the entire object's actual acknowledgement.
    pub completed: Option<Content>,
    /// Actual whole-source hash on completed indexed-file events only.
    pub file_id: Option<[u8; 64]>,
}
/// Exact global budget class which refused additional work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TreeBudget {
    /// Relative component depth.
    Depth,
    /// Total discovered entries.
    Entries,
    /// Retained names or one relative path.
    Path,
    /// Metadata artifact, retained or cumulative metadata bytes.
    Metadata,
    /// Record artifact, retained or cumulative record bytes.
    Records,
    /// Whole-operation regular-file plaintext.
    FileBytes,
    /// Whole-operation generated directory extents.
    DirectoryBytes,
    /// Per-object or whole-operation encoded payload bytes.
    EncodedBytes,
    /// Actual DATASTORE payload bytes, including indexed descriptors.
    StoredBytes,
}
/// Original typed failure. No accepted object is automatically removed/replayed.
#[derive(Debug)]
pub enum TreePublishCause {
    /// Original descriptor, path/type or source-change refusal.
    Source(SourceError),
    /// Original native DATASTORE cause, certainty and retained response.
    Transfer(NetworkError),
    /// Original indexed registration certainty, actual ACK prefix and cause.
    Indexed(Box<IndexPublishError>),
    /// A complete indexed CHK was acknowledged but FS retirement or DATASTORE
    /// cleanup failed. Both independent cleanup outcomes and the file ID remain.
    IndexedCleanup(Box<IndexedFile>),
    /// Original checked directory artifact/placement refusal.
    Directory(dir::Error),
    /// Original official metadata planning refusal.
    Metadata(md::Error),
    /// Caller policy, capacity, counter or representation refusal.
    Protocol(ProtocolError),
    /// Explicit resource bound refused further work.
    Limit(TreeBudget),
    /// The whole current CHK was acknowledged before independent cleanup failed.
    Cleanup(Box<StoreFailure>),
    /// Caller stopped before another mutation, or after a reported actual ACK.
    Cancelled,
}
impl fmt::Display for TreePublishCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(e) => e.fmt(f),
            Self::Transfer(e) => e.fmt(f),
            Self::Indexed(e) => e.fmt(f),
            Self::IndexedCleanup(receipt) => {
                f.write_str("indexed tree file acknowledged with cleanup failure")?;
                if let Some(error) = &receipt.index_retirement_error {
                    write!(f, ": {error}")?;
                }
                if let Some(error) = &receipt.stored.cleanup {
                    write!(f, ": {error}")?;
                }
                Ok(())
            }
            Self::Directory(e) => e.fmt(f),
            Self::Metadata(e) => e.fmt(f),
            Self::Protocol(e) => e.fmt(f),
            Self::Cleanup(e) => e.fmt(f),
            Self::Limit(b) => write!(f, "FS tree publication exceeds {b:?} limit"),
            Self::Cancelled => f.write_str("FS tree publication cancelled"),
        }
    }
}
impl std::error::Error for TreePublishCause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Source(e) => Some(e),
            Self::Transfer(e) => Some(e),
            Self::Indexed(e) => Some(e.as_ref()),
            Self::IndexedCleanup(receipt) => {
                if let Some(error) = &receipt.index_retirement_error {
                    Some(error)
                } else {
                    receipt
                        .stored
                        .cleanup
                        .as_ref()
                        .map(|error| error as &(dyn std::error::Error + 'static))
                }
            }
            Self::Directory(e) => Some(e),
            Self::Metadata(e) => Some(e),
            Self::Protocol(e) => Some(e),
            Self::Cleanup(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}
impl From<SourceError> for TreePublishCause {
    fn from(e: SourceError) -> Self {
        Self::Source(e)
    }
}
impl From<NetworkError> for TreePublishCause {
    fn from(e: NetworkError) -> Self {
        Self::Transfer(e)
    }
}
impl From<dir::Error> for TreePublishCause {
    fn from(e: dir::Error) -> Self {
        Self::Directory(e)
    }
}
impl From<md::Error> for TreePublishCause {
    fn from(e: md::Error) -> Self {
        Self::Metadata(e)
    }
}
impl From<ProtocolError> for TreePublishCause {
    fn from(e: ProtocolError) -> Self {
        Self::Protocol(e)
    }
}

/// Exact original failure, completed objects and incomplete-object ACK prefix.
#[derive(Debug)]
pub struct TreePublishFailure {
    /// Root-relative raw path; empty denotes whole-root coherence or admission.
    pub path: PathBuf,
    /// Whole-operation completed-object accounting.
    pub progress: TreeProgress,
    /// Exact actual ACKs of an incomplete current object, in addition to progress.
    pub current: Progress,
    /// Actual DATASTORE payload bytes in the separate current prefix.
    pub current_stored_bytes: u128,
    /// Present when a complete CHK was accepted before source/cleanup refusal.
    pub acknowledged_content: Option<Content>,
    /// Actual source hash when an indexed-file failure or late refusal retained it.
    pub indexed_file_id: Option<[u8; 64]>,
    /// Original typed refusal, including uncertain original mutations.
    pub cause: TreePublishCause,
}
impl fmt::Display for TreePublishFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FS tree publication at {:?} after {} files/{} directories: {}",
            self.path, self.progress.files, self.progress.directories, self.cause
        )
    }
}
impl std::error::Error for TreePublishFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
/// Every file and postorder directory was actually acknowledged and all final
/// source observations matched. This is not a filesystem snapshot capability.
#[derive(Debug)]
pub struct StoredTree {
    /// Actual acknowledged CHK of the generated root directory.
    pub root: StoredFile,
    /// Whole-operation completed-object accounting.
    pub progress: TreeProgress,
    /// Private source-stat fingerprint, not a GNUnet wire artifact or file hash.
    pub source_fingerprint: [u8; 64],
}
