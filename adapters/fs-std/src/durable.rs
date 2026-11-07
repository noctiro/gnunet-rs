//! Durable local download tasks over the original official FS protocol owners.
mod codec;
mod file;
mod model;
mod namespace;
pub mod store;
mod target;
mod task;
use crate::network::tree_download::TreeDownloadProgress;
use crate::{
    CommitStage, Error, FileIdentity, ObservedFailure, OwnedDirectoryFailure, ReadFile,
    RevalidateFailure,
};
pub use file::{FileOptions, FileProgress};
use gnunet_fs::directory::walk;
pub use model::{
    EntryBinding, EntryState, Manifest, ModelError, Phase, RootMode, SelectionRef, TempFact,
};
use std::{fmt, path::PathBuf};
pub use task::{Status, Task};

/// Cooperative run control. Pause preserves the task, authenticated cache and
/// known output; neither pause nor cancel authorizes deleting completed files.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskControl {
    /// Keep progressing the original run.
    Continue,
    /// Persist a pause request and settle original work before returning Paused.
    Pause,
    /// Persist cancellation intent; committed output remains intact.
    Cancel,
}
/// Explicit settled outcome. A dropped run future remains Interrupted in state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    /// Every current entry was verified and the Complete state record synced.
    Complete,
    /// Requested pause settled without outstanding intent or cleanup.
    Paused,
    /// Cancellation settled; committed output is retained.
    Cancelled,
}
/// Historical durable facts and currently revalidated output remain distinct.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TaskProgress {
    /// Actual confirmed output barriers during this run.
    pub output: TreeDownloadProgress,
    /// Known committed files present in the ledger when this run began.
    pub historical_files: usize,
    /// Existing files fully authenticated and synced again during this run.
    pub revalidated_files: usize,
    /// New links observed durable in this run, even if subsequent state writing failed.
    pub new_files: usize,
    /// Original recorded temporaries without successful cleanup facts.
    pub cleanup_pending: usize,
    /// Recorded commit intents without a confirmed final identity.
    pub uncertain_commits: usize,
    /// Number of complete original records admitted by the WAL.
    pub state_records: usize,
    /// Actual current file-transfer observations. Reopening history never
    /// reconstructs an authentication receipt from these counters.
    pub file: Option<FileProgress>,
}
/// Settled explicit run result, after native work and durable state barriers.
#[derive(Clone, Debug)]
pub struct Outcome {
    /// Settled task outcome; existence alone never produces Complete.
    pub disposition: Disposition,
    /// Historical and current-run progress, independently of failure.
    pub progress: TaskProgress,
    /// Actual current walk observations; only Complete certifies all tasks finished.
    pub walk: Option<walk::Summary>,
    /// Genuine selected retrieval/revalidation performed by this file run.
    /// None for directory tasks; a partial range certifies only that interval.
    pub file: Option<crate::network::range::ReadRange>,
}
/// Typed original failures; no ledger failure can turn a known output commit
/// into an uncommitted file or erase an independent native cleanup failure.
#[derive(Debug)]
pub enum Cause {
    /// Original storage certainty, stage and native cause.
    Storage(store::Error),
    /// Strict local state or immutable entry binding refusal.
    Model(ModelError),
    /// Original native transfer, output or caller-control failure.
    Operation(Error),
    /// Independent operation, state observation and cleanup failures with actual output stage.
    Output(Box<ObservedFailure<Cause>>),
    /// Original selected-file operation, state observer and physical cleanup.
    RangeOutput(Box<ObservedFailure<Cause, crate::network::range::ReadRange>>),
    /// Original directory creation/ownership facts and failure.
    Directory(Box<OwnedDirectoryFailure>),
    /// Original full-content revalidation failure and any real receipt.
    Revalidate(Box<RevalidateFailure>),
    /// Original selected-file revalidation and its actual range receipt.
    RangeRevalidate(Box<crate::RevalidateRangeFailure>),
    /// Known authenticated durable file whose later state/cleanup operation failed.
    Committed(Box<CommitFailure>),
    /// A selected file is known committed; a later independent action failed.
    RangeCommitted(Box<RangeCommitFailure>),
    /// Output differs from recorded ownership or has unclaimed entries; no deletion is implied.
    Reconcile {
        /// Exact root-relative location requiring explicit reconciliation.
        path: PathBuf,
        /// Stable semantic reason, separate from an OS error string.
        reason: &'static str,
    },
    /// A local task ownership or lifecycle precondition refused the operation.
    State(&'static str),
}
impl Cause {
    pub(super) fn range_receipt(&self) -> Option<&crate::network::range::ReadRange> {
        match self {
            Self::RangeOutput(error) => error.receipt.as_ref(),
            Self::RangeRevalidate(error) => error.receipt.as_ref(),
            Self::RangeCommitted(error) => Some(&error.receipt),
            _ => None,
        }
    }
    pub(super) fn committed(&self) -> bool {
        matches!(self, Self::Output(error) if error.stage == CommitStage::Durable)
            || matches!(self, Self::RangeOutput(error) if error.stage == CommitStage::Durable)
            || matches!(
                self,
                Self::Operation(Error::CleanupAfterCommit { .. })
                    | Self::Committed(_)
                    | Self::RangeCommitted(_)
            )
    }
    pub(super) fn clean_cancel(&self) -> bool {
        match self {
            Self::Operation(Error::Cancelled) => true,
            Self::Operation(Error::Transfer(error)) => matches!(error.as_ref(), crate::network::Error::Cancelled(_)),
            Self::Operation(Error::Range(error)) => matches!(&error.cause, crate::network::Error::Cancelled(_)),
            Self::Revalidate(error) => matches!(&error.operation, Error::Cancelled)
                || matches!(&error.operation, Error::Transfer(e) if matches!(e.as_ref(),crate::network::Error::Cancelled(_))),
            Self::Output(error) => error.observer.is_none() && error.cleanup.is_none()
                && error.operation.as_ref().is_some_and(|e| matches!(e, Error::Cancelled)
                    || matches!(e, Error::Transfer(e) if matches!(e.as_ref(),crate::network::Error::Cancelled(_)))),
            Self::RangeRevalidate(error) => matches!(&error.operation, Error::Cancelled)
                || matches!(&error.operation, Error::Range(e) if matches!(&e.cause,crate::network::Error::Cancelled(_))),
            Self::RangeOutput(error) => error.observer.is_none() && error.cleanup.is_none()
                && error.operation.as_ref().is_some_and(|e| matches!(e, Error::Cancelled)
                    || matches!(e, Error::Range(e) if matches!(&e.cause,crate::network::Error::Cancelled(_)))),
            _ => false,
        }
    }
}
impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(e) => e.fmt(f),
            Self::Model(e) => e.fmt(f),
            Self::Operation(e) => e.fmt(f),
            Self::Output(e) => e.fmt(f),
            Self::RangeOutput(e) => e.fmt(f),
            Self::Directory(e) => e.fmt(f),
            Self::Revalidate(e) => e.fmt(f),
            Self::RangeRevalidate(e) => e.fmt(f),
            Self::Committed(e) => write!(f, "file committed; {}", e.cause),
            Self::RangeCommitted(e) => write!(f, "selected file committed; {}", e.cause),
            Self::Reconcile { path, reason } => {
                write!(f, "output {:?} requires reconciliation: {reason}", path)
            }
            Self::State(message) => write!(f, "FS durable task: {message}"),
        }
    }
}
impl std::error::Error for Cause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(e) => Some(e),
            Self::Model(e) => Some(e),
            Self::Operation(e) => Some(e),
            Self::Output(e) => Some(e.as_ref()),
            Self::RangeOutput(e) => Some(e.as_ref()),
            Self::Directory(e) => Some(e.as_ref()),
            Self::Revalidate(e) => Some(e.as_ref()),
            Self::RangeRevalidate(e) => Some(e.as_ref()),
            Self::Committed(e) => Some(e.cause.as_ref()),
            Self::RangeCommitted(e) => Some(e.cause.as_ref()),
            Self::State(_) | Self::Reconcile { .. } => None,
        }
    }
}
impl From<store::Error> for Cause {
    fn from(e: store::Error) -> Self {
        Self::Storage(e)
    }
}
impl From<ModelError> for Cause {
    fn from(e: ModelError) -> Self {
        Self::Model(e)
    }
}
impl From<Error> for Cause {
    fn from(e: Error) -> Self {
        Self::Operation(e)
    }
}
/// Real known file commit plus a later independent error.
#[derive(Debug)]
pub struct CommitFailure {
    /// Actual original final inode identity.
    pub identity: FileIdentity,
    /// Real full-file authentication receipt from this invocation.
    pub receipt: ReadFile,
    /// Independent subsequent failure; the original commit remains known.
    pub cause: Box<Cause>,
}
/// Real selected-file commit followed by an independent refusal.
#[derive(Debug)]
pub struct RangeCommitFailure {
    /// Original final inode identity.
    pub identity: FileIdentity,
    /// Actual selected retrieval; it never certifies an unselected extent.
    pub receipt: crate::network::range::ReadRange,
    /// Independent subsequent failure.
    pub cause: Box<Cause>,
}
/// Complete original run failure with known progress and independent interruption.
#[derive(Debug)]
pub struct Failure {
    /// Original relative output path associated with this fact or failure.
    pub path: PathBuf,
    /// Historical and current-run progress, independently of failure.
    pub progress: TaskProgress,
    /// Actual current walk observations; only Complete certifies all tasks finished.
    pub walk: Option<walk::Summary>,
    /// Actual successful selected-file completion before a later task-state
    /// failure. None never erases receipts retained inside the original cause.
    pub file: Option<crate::network::range::ReadRange>,
    /// Original typed failure, without rewriting its certainty.
    pub cause: Cause,
    /// Independent failure persisting or settling task state.
    pub state_failure: Option<Cause>,
    /// Original control-checkpoint cancellation, clock or deadline refusal.
    pub interruption: Option<Error>,
    /// Independent retirement failure from an original namespace query.
    pub namespace_cleanup: Option<crate::search::Error>,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FS durable task at {:?}: {}", self.path, self.cause)?;
        if let Some(error) = &self.state_failure {
            write!(f, "; state: {error}")?;
        }
        Ok(())
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
