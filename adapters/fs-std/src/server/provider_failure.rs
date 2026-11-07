//! Failure scope is chosen by the actual FS provider before type erasure.
use std::{error::Error, fmt};

/// Existing recovery boundary for one FS provider refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureScope {
    /// The failed operation/provider retires under its existing recovery policy.
    Operation,
    /// An original shared source, worker or uncertain storage stops all FS.
    Service,
}
/// Original concrete cause and its producer-selected recovery scope. Wrapping
/// a cause for diagnostics cannot make a shared failure operation-local.
#[derive(Debug)]
pub struct ProviderFailure {
    cause: Box<dyn Error + Send + Sync>,
    scope: FailureScope,
}
impl ProviderFailure {
    /// Preserve the original allocation and explicitly select its actual scope.
    #[must_use]
    pub fn new(cause: Box<dyn Error + Send + Sync>, scope: FailureScope) -> Self {
        Self { cause, scope }
    }
    /// Admit an explicitly operation/provider-local original cause.
    #[must_use]
    pub fn operation(cause: impl Into<Box<dyn Error + Send + Sync>>) -> Self {
        Self::new(cause.into(), FailureScope::Operation)
    }
    /// Admit an explicitly service-wide original source/storage/worker cause.
    #[must_use]
    pub fn service(cause: impl Into<Box<dyn Error + Send + Sync>>) -> Self {
        Self::new(cause.into(), FailureScope::Service)
    }
    /// Actual producer classification, independent of the concrete error type.
    #[must_use]
    pub const fn scope(&self) -> FailureScope {
        self.scope
    }
    /// Whether the containing FS service must stop under its existing policy.
    #[must_use]
    pub fn is_fatal(&self) -> bool {
        self.scope == FailureScope::Service
    }
    /// Original concrete cause without replacing its native/source chain.
    #[must_use]
    pub fn cause(&self) -> &(dyn Error + Send + Sync + 'static) {
        self.cause.as_ref()
    }
}
impl fmt::Display for ProviderFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.cause.fmt(f)
    }
}
impl Error for ProviderFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.cause.as_ref())
    }
}
