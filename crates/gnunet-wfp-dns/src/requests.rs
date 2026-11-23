//! Reservation and receive authorization for one original intercepted datagram.
use super::{
    Association, ClassifiedFlow, Error, Flow, FlowId, Key, Path, ReceivePath, SessionId, State,
};
use core::num::NonZeroU64;

/// Opaque handle for one original captured request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestId(Key);

impl RequestId {
    /// Decode a numeric observation from an original WFP injection handle.
    /// The caller must verify SDK injection provenance before using this value.
    pub const fn from_context(value: NonZeroU64) -> Self {
        Self(Key::from_context(value))
    }

    /// The original opaque value in a local device record.
    pub const fn context(self) -> NonZeroU64 {
        self.0.context()
    }
}

/// Native injection reservation. The context is an integer, not a pointer to
/// a request allocation. Delayed reclassification must look it up again.
#[derive(Debug)]
#[must_use]
pub struct Injection {
    key: RequestId,
    session: SessionId,
    /// Original captured path for the reversed UDP packet.
    pub path: Path,
    /// Original native association facts.
    pub flow: Flow,
}

impl Injection {
    /// Original device session that submitted this reservation.
    pub const fn session(&self) -> SessionId {
        self.session
    }

    /// Opaque non-reused value to round-trip through native injection callbacks.
    pub const fn context(&self) -> NonZeroU64 {
        self.key.0.context()
    }
}

/// Verdict at the original WFP receive layer for a packet from our injection
/// handle. A successful match records one authorization at that layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Gate {
    /// The original request matches and no receiving verdict was given before.
    Authorize,
    /// The original request, flow, session, path or lifetime refused delivery.
    Deny,
}

/// What the gate observed before a real completion of the original injection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InjectionObservation {
    /// The receive gate authorized this original once.
    Authorized,
    /// No affirmative receive-gate observation preceded completion.
    NoAuthorization,
}

pub(super) struct Original {
    session: SessionId,
    flow: FlowId,
    path: Path,
    expires_at: u64,
    phase: Phase,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Queued,
    Dequeued,
    Pending,
    Revoked,
    Authorized,
}

impl<const F: usize, const R: usize> State<F, R> {
    /// Reserve one captured request for this device session. The driver must
    /// verify the outbound callback's flow context or successfully associate
    /// that callback's original native flow before calling.
    ///
    /// # Errors
    /// Refuses stale or contradictory classification, inconsistent path,
    /// expired request or capacity.
    pub fn capture(
        &mut self,
        session: SessionId,
        flow: ClassifiedFlow,
        path: Path,
        now: u64,
        expires_at: u64,
    ) -> Result<RequestId, Error> {
        self.check_session(session)?;
        let native = self.classified_flow(flow).ok_or(Error::Stale)?;
        if native.family != path.family() || native.compartment != path.compartment() {
            return Err(Error::Path);
        }
        if now >= expires_at {
            return Err(Error::Expired);
        }
        self.requests
            .insert(Original {
                session,
                flow: flow.id,
                path,
                expires_at,
                phase: Phase::Queued,
            })
            .map(RequestId)
            .ok_or(Error::Capacity)
    }

    /// Whether an idle, unexpired capture still belongs to this session and
    /// live native flow, before it can be returned through a device queue.
    pub fn has_capture(&self, session: SessionId, request: RequestId, now: u64) -> bool {
        self.session == Some(session)
            && self.requests.get(request.0).is_some_and(|original| {
                original.session == session
                    && original.phase == Phase::Queued
                    && now < original.expires_at
                    && self.flow(original.flow).is_some()
            })
    }

    /// Issue the original queued capture to this authenticated device file.
    ///
    /// # Errors
    /// Refuses stale, previously dequeued or expired captures.
    pub fn dequeue_capture(
        &mut self,
        session: SessionId,
        request: RequestId,
        now: u64,
    ) -> Result<(), Error> {
        if !self.has_capture(session, request, now) {
            return Err(Error::Stale);
        }
        self.requests.get_mut(request.0).ok_or(Error::Stale)?.phase = Phase::Dequeued;
        Ok(())
    }

    /// Abandon an original still-queued capture which cannot be published.
    pub fn cancel_queued_capture(&mut self, session: SessionId, request: RequestId) {
        if self
            .requests
            .get(request.0)
            .is_some_and(|original| original.session == session && original.phase == Phase::Queued)
        {
            self.requests.remove(request.0);
        }
    }

    /// Reserve the native callback before calling the injection routine. This
    /// permits a racing synchronous classify/completion to observe the
    /// original reservation. The caller records an immediate SDK refusal with
    /// `reject_injection`, or waits for the original completion if accepted.
    ///
    /// # Errors
    /// Refuses stale, expired or already submitted requests.
    pub fn begin_injection(
        &mut self,
        session: SessionId,
        request: RequestId,
        now: u64,
    ) -> Result<Injection, Error> {
        self.check_session(session)?;
        let original = self.requests.get_mut(request.0).ok_or(Error::Stale)?;
        if original.session != session {
            return Err(Error::Stale);
        }
        if original.phase != Phase::Dequeued {
            return Err(Error::InFlight);
        }
        if now >= original.expires_at {
            return Err(Error::Expired);
        }
        let flow = self
            .flows
            .get(original.flow.0)
            .and_then(Association::open)
            .ok_or(Error::Stale)?;
        original.phase = Phase::Pending;
        self.native_debt += 1;
        Ok(Injection {
            key: request,
            session,
            path: original.path,
            flow,
        })
    }

    /// Revoke an issued capture or a submitted reply's receive authority.
    /// A native owner still settles its original completion. An observed
    /// authorization cannot be undone retroactively.
    ///
    /// # Errors
    /// Refuses an unissued, unknown or other session's request.
    pub fn revoke_reply(&mut self, session: SessionId, request: RequestId) -> Result<(), Error> {
        self.check_session(session)?;
        let original = self.requests.get_mut(request.0).ok_or(Error::Stale)?;
        if original.session != session {
            return Err(Error::Stale);
        }
        match original.phase {
            Phase::Queued => return Err(Error::InFlight),
            Phase::Dequeued => {
                self.requests.remove(request.0);
            }
            Phase::Pending => original.phase = Phase::Revoked,
            Phase::Revoked | Phase::Authorized => {}
        }
        Ok(())
    }

    /// Decide receive authorization for a packet already identified as
    /// originating from this driver's native injection handle. The original
    /// classification supplies its flow context and each reported native handle.
    /// Validate the original session and flow ownership even when tuples match.
    pub fn authorize_receive(
        &mut self,
        request: RequestId,
        flow: ClassifiedFlow,
        path: ReceivePath,
        now: u64,
    ) -> Gate {
        let Some(original) = self.requests.get_mut(request.0) else {
            return Gate::Deny;
        };
        if original.phase != Phase::Pending
            || self.session != Some(original.session)
            || original.flow != flow.id
            || self
                .flows
                .get(original.flow.0)
                .and_then(Association::open)
                .filter(|native| flow.agrees_with(native))
                .is_none()
            || now >= original.expires_at
            || !original.path.agrees_with(path)
        {
            return Gate::Deny;
        }
        original.phase = Phase::Authorized;
        Gate::Authorize
    }

    /// Retire an original injection that the native SDK refused before it
    /// accepted ownership. Consumes the reservation and prevents a replay.
    ///
    /// # Errors
    /// Refuses an unknown context or a reservation already seen at receive.
    pub fn reject_injection(&mut self, loan: Injection) -> Result<(), Error> {
        let original = self.requests.get(loan.key.0).ok_or(Error::Stale)?;
        if !matches!(original.phase, Phase::Pending | Phase::Revoked) {
            return Err(Error::InFlight);
        }
        self.settle(loan.key)?;
        Ok(())
    }

    /// Settle the original native completion. Its gate observation does not
    /// establish socket delivery or application consumption.
    ///
    /// # Errors
    /// Refuses a forged, duplicate or unsubmitted request context.
    pub fn complete_injection(
        &mut self,
        request: RequestId,
    ) -> Result<InjectionObservation, Error> {
        let original = self.requests.get(request.0).ok_or(Error::Stale)?;
        if matches!(original.phase, Phase::Queued | Phase::Dequeued) {
            return Err(Error::Stale);
        }
        let settled = self.settle(request)?;
        Ok(if settled.phase == Phase::Authorized {
            InjectionObservation::Authorized
        } else {
            InjectionObservation::NoAuthorization
        })
    }

    /// Reclaim idle captures by inspecting at most `budget` physical slots.
    /// Captures with native debt are always left for their original callback.
    pub fn sweep(&mut self, now: u64, budget: usize) -> usize {
        let capacity = R.min(usize::from(u16::MAX));
        let mut reclaimed = 0;
        for _ in 0..budget.min(capacity) {
            let index = self.sweep_cursor;
            self.sweep_cursor = if index + 1 == capacity { 0 } else { index + 1 };
            if let Some((key, original)) = self.requests.at(index)
                && matches!(original.phase, Phase::Queued | Phase::Dequeued)
                && (self.session != Some(original.session)
                    || self.flow(original.flow).is_none()
                    || now >= original.expires_at)
                && self.requests.remove(key).is_some()
            {
                reclaimed += 1;
            }
        }
        reclaimed
    }

    fn settle(&mut self, request: RequestId) -> Result<Original, Error> {
        let original = self.requests.remove(request.0).ok_or(Error::Stale)?;
        self.native_debt -= 1;
        Ok(original)
    }
}
