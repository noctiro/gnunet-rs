//! Operation-specific failure scope, chosen where the failure is observed.
use super::{Error, Protocol, runtime};

/// Required local disposition of one original Bridge task attempt.
/// This is not a native write, peer-delivery or shared-source liveness receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskFailureScope {
    /// No task admission occurred; retain the same task and original budget.
    Deferred,
    /// End only this original input/output task; settle its actual native debt.
    Task,
    /// The shared source or its cleanup cannot safely continue.
    Source,
}
/// Preserve the original cause and independent cleanup with its observing scope.
/// There is deliberately no blanket conversion which guesses scope from a code.
#[derive(Debug)]
pub struct TaskFailure {
    /// Explicit disposition chosen at the actual failure boundary.
    pub scope: TaskFailureScope,
    /// Unmodified triggering cause and independent cleanup cause.
    pub error: Error,
}
impl TaskFailure {
    /// Retain the same task after a no-admission resource refusal. An independent
    /// cleanup failure instead requires source-level handling.
    pub(crate) fn deferred(error: Error) -> Self {
        Self::with_scope(TaskFailureScope::Deferred, error)
    }
    /// Retire only the same original task. An independent cleanup failure
    /// instead requires source-level handling.
    pub(crate) fn task(error: Error) -> Self {
        Self::with_scope(TaskFailureScope::Task, error)
    }
    /// Preserve a shared source/provider/invariant failure without retrying it
    /// as an ordinary task refusal.
    pub(crate) fn source(error: Error) -> Self {
        Self::with_scope(TaskFailureScope::Source, error)
    }
    fn with_scope(scope: TaskFailureScope, error: Error) -> Self {
        Self {
            scope: if error.cleanup.is_some() {
                TaskFailureScope::Source
            } else {
                scope
            },
            error,
        }
    }
}
impl core::fmt::Display for TaskFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DV task {:?}: {}", self.scope, self.error)
    }
}
impl std::error::Error for TaskFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}
/// Runtime's explicit original-task expiry is different from a numeric
/// Deadline/Capacity returned by its shared Clock, source or provider.
pub(crate) fn actor(error: runtime::Error) -> TaskFailure {
    match error {
        runtime::Error::TaskBudgetExpired => TaskFailure::task(error.into()),
        _ => TaskFailure::source(error.into()),
    }
}
/// Only for synchronous common-Job admission after this Bridge has checked the
/// exact shared Engine source and Times. This port has no signer/provider call.
pub(crate) fn enqueue(error: Protocol) -> TaskFailure {
    match error {
        Protocol::Capacity => TaskFailure::deferred(error.into()),
        Protocol::Stale
        | Protocol::Deadline
        | Protocol::Malformed
        | Protocol::Truncated
        | Protocol::Unsupported => TaskFailure::task(error.into()),
        _ => TaskFailure::source(error.into()),
    }
}

#[cfg(test)]
#[path = "task_failure/tests.rs"]
mod tests;
