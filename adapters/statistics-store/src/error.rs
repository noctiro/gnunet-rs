use gnunet_types::Error;
use std::{fmt, io, path::PathBuf};

/// Whether an unsuccessful save might already have changed the destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitOutcome {
    /// No namespace commit was attempted. Temporary files/directories may have
    /// been created, but the previous database entry was not replaced/removed.
    DestinationUnchanged,
    /// Rename/removal was attempted, or directory synchronization failed after
    /// that operation. Inspect/reload the destination before retrying a change.
    Unknown,
}

/// Exact filesystem or validation stage at which an operation failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    /// Path, capacities, live-client state or encoded snapshot admission.
    Preflight,
    /// Opening the existing database for reading.
    Open,
    /// Inspecting file type/length or detecting a concurrent length change.
    Inspect,
    /// Reading complete message bytes.
    Read,
    /// Decoding or replaying an official SET.
    Replay,
    /// Creating and synchronizing missing parent directories.
    Prepare,
    /// Exclusively creating a temporary file beside the destination.
    CreateTemporary,
    /// Writing the new snapshot's official SET bytes.
    Write,
    /// Synchronizing the complete temporary file before publication.
    SyncFile,
    /// Attempting the atomic destination replacement.
    Rename,
    /// Removing an obsolete database for an empty persistent set.
    Remove,
    /// Synchronizing the directory after replacement/removal.
    SyncDirectory,
}

/// An original OS failure or a bounded official message/state failure.
#[derive(Debug)]
pub enum Cause {
    /// Original filesystem error, including its OS error code.
    Io(io::Error),
    /// Invalid official bytes, exhausted limits or conflicting service lifetime.
    Protocol(Error),
}
impl fmt::Display for Cause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(formatter),
            Self::Protocol(error) => error.fmt(formatter),
        }
    }
}
impl std::error::Error for Cause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Protocol(error) => Some(error),
        }
    }
}

/// A failed load/save with its actual stage and conservative commit outcome.
#[derive(Debug)]
pub struct StoreError {
    stage: Stage,
    outcome: CommitOutcome,
    offset: Option<u64>,
    temporary: Option<PathBuf>,
    cause: Cause,
}
impl StoreError {
    pub(crate) fn protocol(stage: Stage, offset: Option<u64>, error: Error) -> Self {
        Self {
            stage,
            outcome: CommitOutcome::DestinationUnchanged,
            offset,
            temporary: None,
            cause: Cause::Protocol(error),
        }
    }
    pub(crate) fn io(stage: Stage, offset: Option<u64>, error: io::Error) -> Self {
        Self {
            stage,
            outcome: CommitOutcome::DestinationUnchanged,
            offset,
            temporary: None,
            cause: Cause::Io(error),
        }
    }
    pub(crate) fn unknown(mut self, temporary: Option<PathBuf>) -> Self {
        self.outcome = CommitOutcome::Unknown;
        self.temporary = temporary;
        self
    }
    /// Stage whose actual operation or validation failed.
    #[must_use]
    pub const fn stage(&self) -> Stage {
        self.stage
    }
    /// Whether the destination is known unchanged or publication is ambiguous.
    #[must_use]
    pub const fn outcome(&self) -> CommitOutcome {
        self.outcome
    }
    /// Start byte of the failing file record, when applicable.
    #[must_use]
    pub const fn offset(&self) -> Option<u64> {
        self.offset
    }
    /// Candidate snapshot path retained after an ambiguous failed rename, if
    /// it still exists. Successful rename may already have consumed this name.
    #[must_use]
    pub fn temporary_path(&self) -> Option<&std::path::Path> {
        self.temporary.as_deref()
    }
    /// Original filesystem or protocol error.
    #[must_use]
    pub const fn cause(&self) -> &Cause {
        &self.cause
    }
}
impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "statistics database {:?} ({:?})",
            self.stage, self.outcome
        )?;
        if let Some(offset) = self.offset {
            write!(formatter, " at byte {offset}")?;
        }
        write!(formatter, ": {}", self.cause)
    }
}
impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
