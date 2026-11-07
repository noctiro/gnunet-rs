//! Scope regressions over the production boundary-specific mapping functions.
//! These local causes are not PILS, physical-write or C peer receipts.
use super::*;
use crate::Cause;

#[test]
fn shared_numeric_deadline_is_not_an_original_task_expiry() {
    let shared = actor(runtime::Error::Protocol(Protocol::Deadline));
    assert_eq!(shared.scope, TaskFailureScope::Source);
    assert!(matches!(
        shared.error.cause,
        Cause::Actor(runtime::Error::Protocol(Protocol::Deadline))
    ));
    let original = actor(runtime::Error::TaskBudgetExpired);
    assert_eq!(original.scope, TaskFailureScope::Task);
    assert!(matches!(
        original.error.cause,
        Cause::Actor(runtime::Error::TaskBudgetExpired)
    ));
}

#[test]
fn an_independent_cleanup_failure_cannot_be_deferred_or_task_local() {
    for constructor in [TaskFailure::deferred, TaskFailure::task] {
        let actual = constructor(Error {
            cause: Cause::Protocol(Protocol::Capacity),
            cleanup: Some(Cause::Protocol(Protocol::Io)),
        });
        assert_eq!(actual.scope, TaskFailureScope::Source);
        assert!(matches!(
            actual.error.cause,
            Cause::Protocol(Protocol::Capacity)
        ));
        assert!(matches!(
            actual.error.cleanup,
            Some(Cause::Protocol(Protocol::Io))
        ));
    }
}

#[test]
fn a_prechecked_queue_refusal_does_not_reclassify_an_actor_source_failure() {
    let queue = enqueue(Protocol::Stale);
    assert_eq!(queue.scope, TaskFailureScope::Task);
    assert!(matches!(
        queue.error.cause,
        Cause::Protocol(Protocol::Stale)
    ));
    let source = actor(runtime::Error::Protocol(Protocol::Stale));
    assert_eq!(source.scope, TaskFailureScope::Source);
    assert!(matches!(
        source.error.cause,
        Cause::Actor(runtime::Error::Protocol(Protocol::Stale))
    ));
    assert_eq!(
        enqueue(Protocol::Capacity).scope,
        TaskFailureScope::Deferred
    );
    assert_eq!(
        actor(runtime::Error::Protocol(Protocol::Capacity)).scope,
        TaskFailureScope::Source
    );
}
