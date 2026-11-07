//! Explicit registration recovery after observing the original physical loss.
use super::*;

pub(super) struct Registration {
    pub port: [u8; 64],
    pub initial: Bounds,
    pub established: bool,
}

pub(super) fn allowed(cause: &Cause) -> bool {
    matches!(
        cause,
        Cause::Eof
            | Cause::Failure(Error::Io(_))
            | Cause::Failure(Error::Native(gnunet_client_host::ConnectError::Io(_)))
            | Cause::CallEnded(_)
    )
}

impl Line {
    pub(super) fn registration_established(&self) -> bool {
        self.registration
            .as_ref()
            .is_some_and(|r| r.established || self.initializer.complete)
    }
    pub(super) fn replacement_registration(&self) -> bool {
        self.registration.as_ref().is_some_and(|r| r.established)
            && !self.initializer.complete
            && self.input.is_none()
            && self.rows.iter().all(Option::is_none)
            && self.pending.len() == 1
            && self
                .pending
                .front()
                .is_some_and(|p| p.receipt.kind == Kind::Register)
    }
    /// Whether this physically closed registration may be explicitly replaced.
    /// The original Loss must already have been observed, and no explicit close
    /// may have withdrawn the intent. This does not sample the clock or promise
    /// capacity, an unexpired target, or returned caller-owned Audio leases.
    /// Outgoing calls, cancellation, whole/input/control expiry and protocol or
    /// clock/provider refusal never authorize registration recovery. A finite
    /// replacement-init/write timeout is eligible only for an established phone
    /// with no calls/input and only its new registration pending. CallEnded means
    /// a real733 invalidated an already partial old control, forcing physical
    /// stream retirement.
    #[must_use]
    pub fn can_reregister(&self) -> bool {
        self.closed
            && self.mode == Mode::Register
            && self.registration.is_some()
            && self.recoverable
            && self.pending_loss.is_none()
    }

    /// Consume an eligible retired Line and create only a new731 registration.
    /// Callers retain its actual Loss and stop their old media before calling;
    /// all original Audio quota must actually be returned. No old Call, control,
    /// private734 or audio bytes move into the replacement Domain/Epoch.
    ///
    /// The exact original endpoint, port and whole canonical/native Bounds stay
    /// fixed. Until a registration has really written whole, its original init
    /// and write targets also stay fixed across replacement attempts. After a
    /// whole731, that fact survives all replacement attempts: a registration-only
    /// phase timeout may retire one attempt and allow another finite phase capped
    /// by the same whole lifetime. A whole write is never a service-ready ACK.
    /// The old capacities are freed before allocating the replacement; failure
    /// consumes this already physically closed owner, never a live native debt.
    pub fn reregister(self) -> Result<Self, Error> {
        if !self.can_reregister() {
            return Err(Fault::NotReady.into());
        }
        if self.audio.snapshot().ok_or(Fault::Conflict)? != (0, 0) {
            return Err(Fault::WouldBlock.into());
        }
        let registration = self.registration.as_ref().ok_or(Fault::Conflict)?;
        let port = registration.port;
        let original = self.overall.targets;
        let established = self.registration_established();
        let unconfirmed = (!established).then_some((registration.initial, self.initializer.bounds));
        original.check(self.source.clock().as_ref())?;
        if let Some((initial, write)) = unconfirmed {
            initial.check(self.source.clock().as_ref())?;
            write.check(self.source.clock().as_ref())?;
        }
        let source = self.source.duplicate()?;
        let limits = self.limits;
        drop(self);
        let mut next = Self::register(source, &port, limits, original)?;
        next.registration
            .as_mut()
            .ok_or(Fault::Conflict)?
            .established = established;
        if let Some((initial, write)) = unconfirmed {
            next.initial = Some(Bound::new(initial));
            next.registration.as_mut().ok_or(Fault::Conflict)?.initial = initial;
            next.initializer.bounds = write;
            let pending = next.pending.front_mut().ok_or(Fault::Conflict)?;
            pending.receipt.bounds = write;
            pending.bound = Bound::new(write);
        }
        next.check()?;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gnunet_service_runtime::clock::SystemClock;
    use std::time::Duration;

    fn line() -> Result<Line, Error> {
        let source = EndpointSource::unix_with_clock(
            std::path::PathBuf::from("/no-connection-created-by-this-constructor"),
            Arc::new(SystemClock),
        );
        let whole = Bounds::new(source.clock().as_ref(), Duration::from_secs(60))?;
        Line::register(source, &[7; 64], Limits::default(), whole)
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Source assertions exercise the actual SDK recovery gate; no native or crypto result is claimed"
    )]
    fn unconfirmed_recovery_keeps_targets_and_retires_old_handles() -> Result<(), Error> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let _entered = runtime.enter();
        let mut old = line()?;
        let original = old.bounds();
        let initial = old.initial.as_ref().ok_or(Fault::NotReady)?.targets;
        let write = old.initializer.bounds;
        let operation = old.initializer.operation.clone();
        let stale_call = Call {
            domain: old.domain.clone(),
            serial: 1,
        };
        // Explicit original-source EOF fixture, independent of any receipt.
        let loss = old.lost(Cause::Eof);
        assert!(!loss.initializer.complete && loss.initializer.written_bytes == 0);
        let mut next = old.reregister()?;
        assert_eq!(next.bounds().hard, original.hard);
        assert_eq!(next.bounds().expires, original.expires);
        assert_eq!(
            next.initial.as_ref().ok_or(Fault::NotReady)?.targets.hard,
            initial.hard
        );
        assert_eq!(
            next.initial
                .as_ref()
                .ok_or(Fault::NotReady)?
                .targets
                .expires,
            initial.expires
        );
        assert_eq!(next.initializer.bounds.hard, write.hard);
        assert_eq!(next.initializer.bounds.expires, write.expires);
        assert_ne!(next.initializer.operation, operation);
        assert!(matches!(
            next.info(&stale_call),
            Err(Error::Protocol(Fault::StaleGeneration))
        ));
        assert_eq!(next.pending.len(), 1);
        assert_eq!(
            next.pending.front().ok_or(Fault::NotReady)?.receipt.kind,
            Kind::Register
        );
        assert!(next.rows.iter().all(Option::is_none));
        let original_loss = next.lost(Cause::Eof);
        assert!(next.can_reregister());
        assert!(next.close().is_none());
        assert!(matches!(original_loss.cause, Cause::Eof));
        assert!(!next.can_reregister());
        assert!(matches!(
            next.reregister(),
            Err(Error::Protocol(Fault::NotReady))
        ));
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Explicit source fixtures test actual phase/cause policy without socket, clock or protocol execution claims"
    )]
    fn established_registration_never_renews_whole_or_revives_cancelled_intent() -> Result<(), Error>
    {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let _entered = runtime.enter();
        let mut old = line()?;
        let whole = old.bounds();
        // Explicit native whole-write fixture; this is not a service-ready ACK.
        old.initializer.complete = true;
        old.initializer.written_bytes = old.initializer.total_bytes;
        old.pending.clear();
        old.queued_bytes = 0;
        old.initial = None;
        let loss = old.lost(Cause::Eof);
        assert!(loss.initializer.complete);
        let mut next = old.reregister()?;
        assert_eq!(next.bounds().hard, whole.hard);
        assert_eq!(next.bounds().expires, whole.expires);
        assert!(!next.initializer.complete && next.initializer.written_bytes == 0);
        assert!(next.initializer.bounds.hard <= whole.hard);
        // An established phone remains established when a later physical
        // registration times out without any call/input/control admitted.
        next.initial.as_mut().ok_or(Fault::NotReady)?.targets.hard = Instant::now();
        assert!(matches!(
            next.check(),
            Err(Error::Protocol(Fault::Deadline))
        ));
        let phase_loss = next.lost(Cause::Deadline);
        assert!(matches!(phase_loss.cause, Cause::Deadline));
        assert!(next.can_reregister());
        let mut resumed = next.reregister()?;
        assert!(resumed.registration_established());
        assert_eq!(resumed.bounds().hard, whole.hard);
        assert_eq!(resumed.bounds().expires, whole.expires);
        // The same eligibility can never renew the original whole native cap.
        resumed.overall.targets.hard = Instant::now();
        assert!(matches!(
            resumed.check(),
            Err(Error::Protocol(Fault::Deadline))
        ));
        let _whole_loss = resumed.lost(Cause::Deadline);
        assert!(!resumed.can_reregister());
        assert!(matches!(
            resumed.reregister(),
            Err(Error::Protocol(Fault::NotReady))
        ));
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "The actual SDK must reject an expired retained target before constructing replacement native IO"
    )]
    fn expired_unconfirmed_registration_cannot_start_again() -> Result<(), Error> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let _entered = runtime.enter();
        let mut old = line()?;
        old.registration
            .as_mut()
            .ok_or(Fault::NotReady)?
            .initial
            .hard = Instant::now();
        let _source_loss = old.lost(Cause::Eof);
        assert!(matches!(
            old.reregister(),
            Err(Error::Protocol(Fault::Deadline))
        ));
        Ok(())
    }
}
