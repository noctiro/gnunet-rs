//! Final delivery keeps original-task refusals separate from provider faults.
use super::*;

pub(super) struct ObservedSigner<'a, S> {
    signer: &'a mut S,
    expected: PeerId,
    failure: std::cell::Cell<Option<Protocol>>,
}
impl<'a, S> ObservedSigner<'a, S> {
    pub(super) fn new(signer: &'a mut S, expected: PeerId) -> Self {
        Self {
            signer,
            expected,
            failure: std::cell::Cell::new(None),
        }
    }
    fn record(&self, error: Protocol) {
        if self.failure.get().is_none() {
            self.failure.set(Some(error));
        }
    }
    pub(super) fn failure(&self) -> Option<Protocol> {
        self.failure.get()
    }
}
impl<S: Signer> Signer for ObservedSigner<'_, S> {
    fn identity(&self) -> PeerId {
        let actual = self.signer.identity();
        if actual != self.expected {
            self.record(Protocol::Authentication);
        }
        actual
    }
    fn sign_validation(&mut self, region: &[u8; 48]) -> Result<[u8; 64], Protocol> {
        let result = self.signer.sign_validation(region);
        if let Err(error) = result {
            self.record(error);
        }
        result
    }
    fn validation_mode(&self) -> gnunet_transport::signing::ValidationMode {
        self.signer.validation_mode()
    }
}

pub(super) fn grant_failure(error: box_admission::Reason) -> TaskFailure {
    match error {
        box_admission::Reason::Deadline => TaskFailure::task(error.into()),
        _ => TaskFailure::source(error.into()),
    }
}
/// The shared Engine epoch, time and signer identity were checked before this
/// synchronous call. Native IO is not performed here. A real signer refusal
/// retains its own source scope rather than impersonating packet capacity.
pub(super) fn engine_failure(error: Protocol, provider: Option<Protocol>) -> TaskFailure {
    if let Some(original) = provider {
        return TaskFailure::source(original.into());
    }
    match error {
        Protocol::Capacity | Protocol::WouldBlock | Protocol::NotReady => {
            TaskFailure::deferred(error.into())
        }
        Protocol::Malformed
        | Protocol::Truncated
        | Protocol::TooLarge
        | Protocol::Unsupported
        | Protocol::Authentication
        | Protocol::PermissionDenied
        | Protocol::Replay
        | Protocol::Stale
        | Protocol::NotFound
        | Protocol::Deadline => TaskFailure::task(error.into()),
        _ => TaskFailure::source(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct RefusingSigner;
    impl Signer for RefusingSigner {
        fn identity(&self) -> PeerId {
            PeerId([7; 32])
        }
        fn sign_validation(&mut self, _: &[u8; 48]) -> Result<[u8; 64], Protocol> {
            Err(Protocol::Capacity)
        }
        fn validation_mode(&self) -> gnunet_transport::signing::ValidationMode {
            gnunet_transport::signing::ValidationMode::Deferred
        }
    }
    #[test]
    fn actual_signer_capacity_is_not_engine_buffer_pressure() {
        let mut signer = RefusingSigner;
        let mut observed = ObservedSigner::new(&mut signer, PeerId([7; 32]));
        assert_eq!(observed.identity(), PeerId([7; 32]));
        assert!(matches!(
            observed.sign_validation(&[0; 48]),
            Err(Protocol::Capacity)
        ));
        let source = engine_failure(Protocol::Capacity, observed.failure());
        assert_eq!(source.scope, TaskFailureScope::Source);
        assert!(matches!(
            source.error.cause,
            Cause::Protocol(Protocol::Capacity)
        ));
        assert_eq!(
            engine_failure(Protocol::Capacity, None).scope,
            TaskFailureScope::Deferred
        );
        assert!(matches!(
            observed.validation_mode(),
            gnunet_transport::signing::ValidationMode::Deferred
        ));
    }
    #[test]
    fn signer_identity_drift_keeps_actual_identity_and_source_scope() {
        struct Changing(std::cell::Cell<bool>);
        impl Signer for Changing {
            fn identity(&self) -> PeerId {
                let changed = self.0.replace(true);
                PeerId([if changed { 8 } else { 7 }; 32])
            }
            fn sign_validation(&mut self, _: &[u8; 48]) -> Result<[u8; 64], Protocol> {
                Err(Protocol::Unsupported)
            }
        }
        let mut signer = Changing(std::cell::Cell::new(false));
        let observed = ObservedSigner::new(&mut signer, PeerId([7; 32]));
        assert_eq!(observed.identity(), PeerId([7; 32]));
        assert!(observed.failure().is_none());
        assert_eq!(observed.identity(), PeerId([8; 32]));
        let actual = engine_failure(Protocol::Authentication, observed.failure());
        assert_eq!(actual.scope, TaskFailureScope::Source);
        assert!(matches!(
            actual.error.cause,
            Cause::Protocol(Protocol::Authentication)
        ));
        assert_eq!(
            engine_failure(Protocol::Authentication, None).scope,
            TaskFailureScope::Task
        );
    }
    #[test]
    fn grant_clock_deadline_keeps_its_source_and_cause() {
        let source = grant_failure(box_admission::Reason::Clock(Protocol::Deadline));
        assert_eq!(source.scope, TaskFailureScope::Source);
        assert!(matches!(
            source.error.cause,
            Cause::Grant(box_admission::Reason::Clock(Protocol::Deadline))
        ));
        assert_eq!(
            grant_failure(box_admission::Reason::Deadline).scope,
            TaskFailureScope::Task
        );
    }
}
