//! First transaction cause, naming exposure and independent cleanup failure.
use gnunet_types::Error;
use std::io;
/// Publication exposure of an original filesystem transaction, not an IPC ACK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Exposure {
    /// Original canonical snapshot was not replaced. An owned temporary may still
    /// need cleanup; its independent cleanup error is retained.
    NotPublished,
    /// Replacement was attempted; committed outcome cannot be asserted.
    Unknown,
}
/// Original storage cause and independent actual cleanup failure. No secret body
/// or key is printable through this value.
#[derive(Debug)]
pub struct Failure {
    /// Original operation stage.
    pub stage: &'static str,
    /// Original known/unknown publication state.
    pub exposure: Exposure,
    /// Original protocol/resource classification.
    pub reason: Error,
    /// Original OS error, if any.
    pub io: Option<io::Error>,
    /// Independent owned temporary cleanup failure.
    pub cleanup: Option<io::Error>,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "snapshot store {}: {:?} ({:?})",
            self.stage, self.reason, self.exposure
        )?;
        if let Some(e) = &self.io {
            write!(f, ": {e}")?;
        }
        if let Some(e) = &self.cleanup {
            write!(f, "; independent cleanup: {e}")?;
        }
        Ok(())
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.io.as_ref().map(|e| e as _)
    }
}
pub(super) fn failure(stage: &'static str, reason: Error, io: Option<io::Error>) -> Failure {
    Failure {
        stage,
        exposure: Exposure::NotPublished,
        reason,
        io,
        cleanup: None,
    }
}
pub(super) fn os(stage: &'static str, e: io::Error) -> Failure {
    failure(stage, Error::Storage, Some(e))
}
