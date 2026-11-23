//! Checkpoint/native ownership composition; no private metadata grants a TUN.
mod recover;
use super::{Intent, Journal, Observation, Record, State};
use crate::{
    Limits, OwnedTun,
    platform::{self, CreationFailure},
};
use std::{error::Error, fmt, io, path::Path};
/// Recoverable provisioning boundary at which the original operation failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenStage {
    /// Arguments or checkpoint open/private-owner qualification.
    Prepare,
    /// Saved native owner could not be physically retired.
    Recover,
    /// A previous allocation intent lacks a complete native selector.
    PendingAllocation,
    /// Allocation intent could not be confirmed durable.
    Begin,
    /// Native creation/configuration failed.
    Create,
    /// Complete identity could not be confirmed durable before publication.
    Checkpoint,
    /// Final native device qualification failed.
    Qualify,
}
/// Original provisioning failure and separately retained followup cleanup error.
/// A checkpoint lock stays owned here unless it moved into a native cleanup
/// error. Dropping this error never clears outstanding on-disk state.
#[derive(Debug)]
#[must_use]
pub struct OpenError {
    stage: OpenStage,
    original: io::Error,
    cleanup: Option<io::Error>,
    journal: Option<Box<Journal>>,
}
impl OpenError {
    /// Actual failing boundary.
    #[must_use]
    pub const fn stage(&self) -> OpenStage {
        self.stage
    }
    /// Original native or persistence error, without string flattening.
    #[must_use]
    pub const fn original(&self) -> &io::Error {
        &self.original
    }
    /// Independent cleanup/checkpoint-retirement error, if one occurred.
    #[must_use]
    pub const fn cleanup(&self) -> Option<&io::Error> {
        self.cleanup.as_ref()
    }
    /// Inspect the same checkpoint owner; state is None after uncertain writes.
    #[must_use]
    pub fn journal(&self) -> Option<&Journal> {
        self.journal.as_deref()
    }
    /// Consume the error and retain both causes and its original checkpoint.
    #[must_use]
    pub fn into_parts(self) -> (OpenStage, io::Error, Option<io::Error>, Option<Journal>) {
        (
            self.stage,
            self.original,
            self.cleanup,
            self.journal.map(|journal| *journal),
        )
    }
}
impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "recoverable TUN {:?}: {}", self.stage, self.original)?;
        if let Some(error) = &self.cleanup {
            write!(f, "; independent retirement: {error}")?;
        }
        Ok(())
    }
}
impl Error for OpenError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.original)
    }
}
fn fail(
    stage: OpenStage,
    original: io::Error,
    journal: Option<Journal>,
    cleanup: Option<io::Error>,
) -> OpenError {
    OpenError {
        stage,
        original,
        cleanup,
        journal: journal.map(Box::new),
    }
}
fn failed_checkpoint(
    mut journal: Journal,
    intent: &Intent,
    record: &Record,
    original: io::Error,
    native: io::Result<()>,
) -> OpenError {
    let cleanup = match native {
        Err(error) => Some(error),
        Ok(()) => journal.finish_failed_creation(intent, Some(record)).err(),
    };
    fail(OpenStage::Checkpoint, original, Some(journal), cleanup)
}
pub(crate) fn open(name: Option<&str>, path: &Path, limits: Limits) -> Result<OwnedTun, OpenError> {
    limits
        .validate()
        .map_err(|error| fail(OpenStage::Prepare, error, None, None))?;
    if let Some(name) = name {
        platform::name(name).map_err(|error| fail(OpenStage::Prepare, error, None, None))?;
    }
    let journal =
        Journal::open(path).map_err(|error| fail(OpenStage::Prepare, error, None, None))?;
    let journal = recover::restore(journal)?;
    create(journal, name, limits, Scope::Startup)
}

pub(crate) enum Scope {
    Startup,
    Recreation {
        fib: u32,
        until: tokio::time::Instant,
    },
}

impl Scope {
    fn fib(&self) -> Option<u32> {
        match *self {
            Self::Startup => None,
            Self::Recreation { fib, .. } => Some(fib),
        }
    }

    fn check_deadline(&self) -> io::Result<()> {
        if matches!(*self, Self::Recreation { until, .. } if tokio::time::Instant::now() >= until) {
            Err(io::ErrorKind::TimedOut.into())
        } else {
            Ok(())
        }
    }
}

pub(crate) fn create(
    mut journal: Journal,
    name: Option<&str>,
    limits: Limits,
    scope: Scope,
) -> Result<OwnedTun, OpenError> {
    if let Err(error) = scope.check_deadline() {
        return Err(fail(OpenStage::Begin, error, Some(journal), None));
    }
    let intent = match journal.begin(name) {
        Ok(intent) => intent,
        Err(error) => return Err(fail(OpenStage::Begin, error, Some(journal), None)),
    };
    if let Err(error) = scope.check_deadline() {
        let cleanup = journal.abort(&intent).err();
        return Err(fail(OpenStage::Begin, error, Some(journal), cleanup));
    }
    let mut handle = match platform::open_recorded(name, intent.nonce, scope.fib()) {
        Ok(handle) => handle,
        Err(CreationFailure::Unknown(error)) => {
            return Err(fail(OpenStage::Create, error, Some(journal), None));
        }
        Err(CreationFailure::Before(error) | CreationFailure::Reclaimed(error)) => {
            let cleanup = journal.abort(&intent).err();
            return Err(fail(OpenStage::Create, error, Some(journal), cleanup));
        }
    };
    let record = match handle.recovery_record().cloned() {
        Some(record) => record,
        None => {
            let error = io::Error::other("created TUN lacks its admitted recovery identity");
            let cleanup = handle.close().err();
            return Err(fail(OpenStage::Checkpoint, error, Some(journal), cleanup));
        }
    };
    if let Err(error) = journal.activate(record.clone()) {
        let native = handle.close();
        return Err(failed_checkpoint(journal, &intent, &record, error, native));
    }
    match handle.interface.as_mut() {
        Some(lease) => lease.checkpoint = Some(Box::new(journal)),
        None => {
            let error = io::Error::other("created TUN lost its checkpoint retirement owner");
            let native = handle.close();
            return Err(failed_checkpoint(journal, &intent, &record, error, native));
        }
    }
    OwnedTun::from_handle(handle, limits)
        .map_err(|error| fail(OpenStage::Qualify, error, None, None))
}
