//! Original native errors and independent explicit cleanup observations.
use std::fmt;

/// One exact native DWORD, including WFP and RPC errors without reinterpretation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeFailure {
    /// SDK operation that produced the error.
    pub operation: &'static str,
    /// Original nonzero native error code.
    pub code: u32,
}
impl fmt::Display for NativeFailure {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "{} returned {:#010x}", self.operation, self.code)
    }
}
impl std::error::Error for NativeFailure {}

/// One cleanup call's observation, without claiming application or driver drain.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Cleanup {
    /// No corresponding owner was acquired or the call was unnecessary.
    #[default]
    NotNeeded,
    /// The actual original native cleanup call succeeded.
    Succeeded,
    /// The actual original native cleanup call returned this error.
    Failed(NativeFailure),
}
impl Cleanup {
    pub(super) fn from_result(result: Result<(), NativeFailure>) -> Self {
        match result {
            Ok(()) => Self::Succeeded,
            Err(error) => Self::Failed(error),
        }
    }
    /// Whether this individual cleanup call failed.
    #[must_use]
    pub const fn has_failure(self) -> bool {
        matches!(self, Self::Failed(_))
    }
}
