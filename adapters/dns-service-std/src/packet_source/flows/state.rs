//! Pure flow admission and original output ownership, without native objects.
use crate::core;
use gnunet_types::Error;
use std::io;
use tokio::time::Instant;

#[derive(Clone, Copy)]
pub(super) enum Phase {
    Opening { until: Instant },
    Open,
    Closing { reason: Error, notified: bool },
}
pub(super) struct Output<'id> {
    pub effect: core::Effect<'id>,
    pub bytes: usize,
    until: Instant,
}
pub(super) enum Disposition {
    Written,
    Stopped {
        accepted: bool,
        reason: crate::Error,
    },
}
pub(super) struct Finished<'id> {
    pub output: Output<'id>,
    pub disposition: Disposition,
}
pub(super) struct FlowState<'id> {
    phase: Phase,
    output: Option<Output<'id>>,
}
/// An exclusive reservation cannot overlap another admission or state change.
/// Dropping it before SDK admission leaves the original state unchanged.
pub(super) struct Reservation<'state, 'id> {
    state: &'state mut FlowState<'id>,
    output: Output<'id>,
}
impl Reservation<'_, '_> {
    /// Called only after actual SDK submission; installation cannot fail.
    pub fn submitted(self) {
        self.state.output = Some(self.output);
    }
}
impl<'id> FlowState<'id> {
    pub fn opening(until: Instant) -> Self {
        Self {
            phase: Phase::Opening { until },
            output: None,
        }
    }
    pub const fn phase(&self) -> Phase {
        self.phase
    }
    pub fn opened(&mut self) {
        if matches!(self.phase, Phase::Opening { .. }) {
            self.phase = Phase::Open;
        }
    }
    pub const fn can_write(&self) -> bool {
        matches!(self.phase, Phase::Open) && self.output.is_none()
    }
    pub fn begin(
        &mut self,
        effect: core::Effect<'id>,
        bytes: usize,
        now: Instant,
        until: Instant,
    ) -> Result<Reservation<'_, 'id>, Error> {
        if !matches!(effect.destination(), core::Destination::Source(_)) {
            return Err(Error::InvalidInput);
        }
        if !self.can_write() {
            return Err(Error::WouldBlock);
        }
        if now >= until {
            return Err(Error::Deadline);
        }
        Ok(Reservation {
            state: self,
            output: Output {
                effect,
                bytes,
                until,
            },
        })
    }
    pub const fn pending(&self) -> Option<&Output<'id>> {
        self.output.as_ref()
    }
    pub fn stop(&mut self, reason: Error, notified: bool) {
        if !matches!(self.phase, Phase::Closing { .. }) {
            self.phase = Phase::Closing { reason, notified };
        }
    }
    pub fn notify_closed(&mut self) -> Option<Error> {
        if let Phase::Closing {
            reason,
            notified: false,
        } = self.phase
        {
            self.phase = Phase::Closing {
                reason,
                notified: true,
            };
            Some(reason)
        } else {
            None
        }
    }
    /// Only a still-active deadline can request the original native close.
    pub fn expire(&mut self, now: Instant) -> bool {
        if !matches!(self.phase, Phase::Closing { .. })
            && self.deadline().is_some_and(|until| now >= until)
        {
            self.stop(Error::Deadline, false);
            true
        } else {
            false
        }
    }
    pub fn deadline(&self) -> Option<Instant> {
        match self.phase {
            Phase::Opening { until } => Some(until),
            Phase::Open => self.output.as_ref().map(|output| output.until),
            Phase::Closing { .. } => None,
        }
    }
    pub fn can_retire(&self) -> bool {
        matches!(self.phase, Phase::Closing { .. }) && self.output.is_none()
    }
    /// The caller supplies the original effect only after native callback and
    /// argument disposal. Pending callbacks cannot clear or overwrite this debt.
    pub fn finish(
        &mut self,
        effect: core::Effect<'id>,
        result: io::Result<()>,
        now: Instant,
    ) -> Result<Finished<'id>, Error> {
        let output = self.output.as_ref().ok_or(Error::StaleGeneration)?;
        if output.effect != effect {
            return Err(Error::StaleGeneration);
        }
        let accepted = result.is_ok();
        let reason = match self.phase {
            Phase::Closing { reason, .. } => Some(reason.into()),
            _ if now >= output.until => {
                self.stop(Error::Deadline, false);
                Some(Error::Deadline.into())
            }
            _ => result.err().map(|error| {
                self.stop(Error::Closed, false);
                error.into()
            }),
        };
        let output = self.output.take().ok_or(Error::StaleGeneration)?;
        let disposition = if let Some(reason) = reason {
            Disposition::Stopped { accepted, reason }
        } else {
            Disposition::Written
        };
        Ok(Finished {
            output,
            disposition,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Disposition, FlowState};
    use crate::core;
    use gnunet_types::Error;
    use std::time::Duration;
    use tokio::time::Instant;

    const QUERY: [u8; 12] = [0x12, 0x34, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    fn effect<'id>(
        engine: &mut core::Engine<'id>,
        source: core::Source<'id>,
    ) -> Result<core::Effect<'id>, Error> {
        let request = engine.intercept(source, core::Query::decode(&QUERY)?, 1, 100)?;
        if engine.next_work(request)? != core::Work::Resolve(request) {
            return Err(Error::Conflict);
        }
        let resolver = engine.resolving(request)?;
        let mut answer = QUERY;
        answer[2] |= 0x80;
        engine.resolved(resolver, &answer)?;
        if !matches!(engine.next_work(request)?, core::Work::Source { .. }) {
            return Err(Error::Conflict);
        }
        Ok(engine.prepare_source(request)?.effect())
    }
    fn opened<'id>(now: Instant) -> FlowState<'id> {
        let mut state = FlowState::opening(now + Duration::from_secs(5));
        state.opened();
        state
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Pure ownership fixture checks real engine effects without constructing native SDK objects"
    )]
    fn closing_debt_isolated_from_healthy_flow_and_late_acceptance() -> Result<(), Error> {
        let instance = core::Instance::new();
        let mut engine = core::Engine::new(&instance, core::Limits::default())?;
        let source = engine.attach_source()?;
        let first = effect(&mut engine, source)?;
        let second = effect(&mut engine, source)?;
        let now = Instant::now();
        let until = now + Duration::from_secs(10);
        let mut a = opened(now);
        let mut b = opened(now);
        a.begin(first, QUERY.len(), now, until)?.submitted();
        b.begin(second, QUERY.len(), now, until)?.submitted();
        engine.queued(first)?;
        engine.queued(second)?;
        a.stop(Error::Cancelled, false);
        engine.abort(first.request())?;
        assert!(!a.can_write());
        assert!(!a.can_retire());
        assert_eq!(a.notify_closed(), Some(Error::Cancelled));
        assert!(a.notify_closed().is_none());
        assert_eq!(engine.retire(first.request()), Err(Error::WouldBlock));
        assert!(matches!(
            b.finish(second, Ok(()), now)?.disposition,
            Disposition::Written
        ));
        engine.written(second)?;
        engine.retire(second.request())?;
        assert!(b.can_write());
        assert!(a.pending().is_some());
        assert!(matches!(
            a.finish(first, Ok(()), now)?.disposition,
            Disposition::Stopped {
                accepted: true,
                reason: crate::Error::Protocol(Error::Cancelled)
            }
        ));
        engine.source_stopped(first)?;
        engine.retire(first.request())?;
        assert!(a.can_retire());
        a.opened();
        assert!(!a.can_write());
        assert_eq!(engine.payload_bytes(), 0);
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Pure output lifecycle fixture verifies stale and duplicate effects preserve current ownership"
    )]
    fn reservations_and_original_effects_cannot_overwrite_or_settle_other_work() -> Result<(), Error>
    {
        let instance = core::Instance::new();
        let mut engine = core::Engine::new(&instance, core::Limits::default())?;
        let source = engine.attach_source()?;
        let old = effect(&mut engine, source)?;
        let current = effect(&mut engine, source)?;
        let now = Instant::now();
        let until = now + Duration::from_secs(10);
        let mut state = opened(now);
        {
            let _unsubmitted = state.begin(old, QUERY.len(), now, until)?;
        }
        assert!(state.can_write());
        state.begin(old, QUERY.len(), now, until)?.submitted();
        assert!(matches!(
            state.begin(current, QUERY.len(), now, until),
            Err(Error::WouldBlock)
        ));
        assert!(matches!(
            state.finish(current, Ok(()), now),
            Err(Error::StaleGeneration)
        ));
        assert_eq!(state.pending().map(|output| output.effect), Some(old));
        assert!(matches!(
            state.finish(old, Ok(()), now)?.disposition,
            Disposition::Written
        ));
        assert!(matches!(
            state.finish(old, Ok(()), now),
            Err(Error::StaleGeneration)
        ));
        state.begin(current, QUERY.len(), now, until)?.submitted();
        assert!(matches!(
            state.finish(old, Ok(()), now),
            Err(Error::StaleGeneration)
        ));
        assert_eq!(state.pending().map(|output| output.effect), Some(current));
        assert!(state.expire(until));
        assert!(!state.expire(until));
        assert!(!state.can_retire());
        assert!(matches!(
            state.finish(current, Ok(()), until)?.disposition,
            Disposition::Stopped {
                accepted: true,
                reason: crate::Error::Protocol(Error::Deadline)
            }
        ));
        assert!(state.can_retire());
        Ok(())
    }
}
