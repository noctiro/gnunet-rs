//! One original public observer, durable per-identity state and bounded recovery.
mod retirement;
use crate::Cause;
use gnunet_pils::client::{Epoch, Identity as Observation};
use gnunet_pils_host::client::{Client, ConnectionLoss};
use gnunet_service_runtime::clock::{Deadline, RuntimeClock};
use gnunet_types::Error;
use gnunet_udp_communicator_host::{
    communicator::{Communicator, IdentityRetirement},
    identity::IdentityEpoch,
    replay::{Journal, Namespace},
};
use gnunet_wire::official::AbsoluteTime;
pub(super) use retirement::observe as observe_retirement;
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};

struct Window {
    hard: Instant,
    until: AbsoluteTime,
    started: AbsoluteTime,
    native: Pin<Box<Sleep>>,
    canonical: Pin<Box<Deadline>>,
}
impl Window {
    fn new(clock: Arc<dyn RuntimeClock>) -> Result<Self, Cause> {
        Self::since(clock, Instant::now())
    }
    fn since(clock: Arc<dyn RuntimeClock>, started: Instant) -> Result<Self, Cause> {
        let hard = started
            .checked_add(Duration::from_secs(30))
            .ok_or(Error::Overflow)?;
        let canonical_start = clock.sample()?.now;
        let until = canonical_start
            .as_micros()
            .checked_add(30_000_000)
            .filter(|v| *v != u64::MAX)
            .ok_or(Error::Overflow)?;
        Ok(Self {
            hard,
            until: AbsoluteTime::from_micros(until),
            started: canonical_start,
            native: Box::pin(tokio::time::sleep_until(hard)),
            canonical: Box::pin(Deadline::at(clock, AbsoluteTime::from_micros(until))?),
        })
    }
    fn guard(&mut self, cx: &mut Context<'_>) -> Result<(), Cause> {
        if Instant::now() >= self.hard || self.native.as_mut().poll(cx).is_ready() {
            return Err(Error::Deadline.into());
        }
        if let Poll::Ready(result) = self.canonical.as_mut().poll(cx) {
            result?;
            return Err(Error::Deadline.into());
        }
        if Instant::now() >= self.hard {
            return Err(Error::Deadline.into());
        }
        Ok(())
    }
}
struct Generation<'id> {
    binding: IdentityEpoch<'id>,
    journal: Journal,
}
#[expect(
    clippy::large_enum_variant,
    reason = "One process owns this inline exclusive key/journal phase; boxing would add an allocation at each identity cut"
)]
enum Phase<'id> {
    Active(Generation<'id>),
    Paused {
        previous: Observation<'id>,
        lost: Epoch<'id>,
    },
    Retired,
}
pub(super) struct State<'id> {
    namespace: Namespace,
    phase: Phase<'id>,
    epoch: Epoch<'id>,
    peers: usize,
    clock: Arc<dyn RuntimeClock>,
    window: Option<Window>,
    first_loss: Option<ConnectionLoss>,
}
impl<'id> State<'id> {
    pub fn new(
        namespace: Namespace,
        source: &Client<'id, 32>,
        peers: usize,
        clock: Arc<dyn RuntimeClock>,
        now: AbsoluteTime,
    ) -> Result<Self, Cause> {
        let binding = IdentityEpoch::from_native(source, now)?;
        let epoch = binding.observation().epoch();
        let journal = namespace.journal(binding.peer(), peers)?;
        let current = clock.sample()?.now;
        if current < now {
            return Err(Error::TimeUncertain.into());
        }
        binding.current_native(source, current)?;
        Ok(Self {
            namespace,
            phase: Phase::Active(Generation { binding, journal }),
            epoch,
            peers,
            clock,
            window: None,
            first_loss: None,
        })
    }
    pub fn binding(&self) -> Result<&IdentityEpoch<'id>, Error> {
        match &self.phase {
            Phase::Active(v) => Ok(&v.binding),
            Phase::Paused { .. } => Err(Error::NotReady),
            Phase::Retired => Err(Error::Closed),
        }
    }
    pub fn ports(&mut self) -> Result<(&IdentityEpoch<'id>, &mut Journal), Error> {
        match &mut self.phase {
            Phase::Active(v) => Ok((&v.binding, &mut v.journal)),
            Phase::Paused { .. } => Err(Error::NotReady),
            Phase::Retired => Err(Error::Closed),
        }
    }
    fn failure(&mut self, terminal: Cause) -> Cause {
        match self.first_loss.take() {
            Some(first) => Box::new(RecoveryFailure { first, terminal }),
            None => terminal,
        }
    }
    pub fn guard(&mut self, cx: &mut Context<'_>) -> Result<(), Cause> {
        if let Some(window) = &mut self.window
            && let Err(error) = window.guard(cx)
        {
            return Err(self.failure(error));
        }
        Ok(())
    }
    /// The native PILS driver calls this again after its own fallible clock
    /// provider and before each connect/read/write, without renewing targets.
    pub fn guard_io(&mut self) -> Result<(), Cause> {
        let Some(window) = &self.window else {
            return Ok(());
        };
        let (hard, until, started) = (window.hard, window.until, window.started);
        if Instant::now() >= hard {
            return Err(self.failure(Error::Deadline.into()));
        }
        let sampled = self.clock.sample();
        if Instant::now() >= hard {
            return Err(self.failure(Error::Deadline.into()));
        }
        let now = sampled.map_err(|error| self.failure(error.into()))?.now;
        if now >= until {
            return Err(self.failure(Error::Deadline.into()));
        }
        if now < started {
            return Err(self.failure(Error::TimeUncertain.into()));
        }
        Ok(())
    }
    pub fn paused(&self) -> bool {
        matches!(self.phase, Phase::Paused { .. })
    }
    pub fn first_loss(&self) -> Option<&ConnectionLoss> {
        self.first_loss.as_ref()
    }
    /// The caller has consumed an actual native connection loss. No network
    /// operation may use the previous key after this synchronous boundary.
    pub fn pause(
        &mut self,
        epoch: Epoch<'id>,
        first: ConnectionLoss,
        comm: &mut Communicator<'_>,
    ) -> Result<Option<IdentityRetirement>, Cause> {
        let started = Instant::now();
        match &mut self.phase {
            Phase::Active(current) => {
                if current.binding.observation().epoch() != epoch {
                    return Err(Error::StaleGeneration.into());
                }
                let previous = current.binding.observation();
                let retired = comm.retire_identity()?;
                current.binding.close();
                if !current.journal.quiescent()? {
                    return Err(Error::OutcomeUnknown.into());
                }
                // Drop the closed generation before opening any replacement
                // key/journal; the process namespace and original IO stay owned.
                self.phase = Phase::Paused {
                    previous,
                    lost: epoch,
                };
                self.first_loss.get_or_insert(first);
                if self.window.is_none() {
                    self.window = Some(Window::since(self.clock.clone(), started)?);
                }
                Ok(Some(retired))
            }
            Phase::Paused { lost, .. } => {
                if epoch != *lost && !epoch.is_successor_of(*lost) {
                    return Err(Error::StaleGeneration.into());
                }
                *lost = epoch;
                Ok(None)
            }
            Phase::Retired => Err(Error::Closed.into()),
        }
    }
    /// Original source branding, revision and freshness precede any key access.
    pub(super) fn verify(&self, next: Observation<'id>, now: AbsoluteTime) -> Result<(), Error> {
        let valid = match &self.phase {
            Phase::Active(current) => {
                let previous = current.binding.observation();
                next.epoch() == self.epoch
                    && next.revision() >= previous.revision()
                    && (next.revision() != previous.revision() || next == previous)
            }
            Phase::Paused { previous, lost } => {
                next.epoch().is_successor_of(*lost) && next.revision() > previous.revision()
            }
            Phase::Retired => return Err(Error::Closed),
        };
        if !valid {
            return Err(Error::StaleGeneration);
        }
        if next.expiration() <= now {
            return Err(Error::Timeout);
        }
        Ok(())
    }
    /// Retire actual old IO before replacing keys or history. A failed rebuild
    /// grants no active signer/journal facade.
    pub fn select(
        &mut self,
        source: &Client<'id, 32>,
        comm: &mut Communicator<'_>,
        now: AbsoluteTime,
        observe: &mut impl FnMut(IdentityRetirement) -> Result<(), Cause>,
    ) -> Result<bool, Cause> {
        let next = source.identity().ok_or(Error::NotReady)?;
        self.verify(next, now)?;
        if let Phase::Active(current) = &mut self.phase
            && next.peer().as_bytes() == &current.binding.peer()
        {
            current.binding.refresh_native(source, now)?;
            return Ok(false);
        }
        if self.window.is_none() {
            self.window = Some(Window::new(self.clock.clone())?);
        }
        if self
            .window
            .as_ref()
            .is_some_and(|v| Instant::now() >= v.hard || now >= v.until)
        {
            return Err(Error::Deadline.into());
        }
        if let Phase::Active(current) = &mut self.phase {
            let retired = comm.retire_identity()?;
            current.binding.close();
            if !current.journal.quiescent()? {
                return Err(Error::OutcomeUnknown.into());
            }
            let old = std::mem::replace(&mut self.phase, Phase::Retired);
            drop(old);
            observe(retired)?;
        }
        if self
            .window
            .as_ref()
            .is_some_and(|v| Instant::now() >= v.hard)
        {
            return Err(Error::Deadline.into());
        }
        // The original worker-free synchronous journal/IO owners have retired.
        // No second generation of packet backing or replay rows is retained.
        let binding = IdentityEpoch::from_native(source, now)?;
        let journal = self.namespace.journal(binding.peer(), self.peers)?;
        if self
            .window
            .as_ref()
            .is_some_and(|v| Instant::now() >= v.hard)
        {
            return Err(Error::Deadline.into());
        }
        let current = self.clock.sample()?.now;
        if current < now {
            return Err(Error::TimeUncertain.into());
        }
        if self.window.as_ref().is_some_and(|v| current >= v.until) {
            return Err(Error::Deadline.into());
        }
        if self
            .window
            .as_ref()
            .is_some_and(|v| Instant::now() >= v.hard)
        {
            return Err(Error::Deadline.into());
        }
        comm.resume_identity(binding.current_native(source, current)?, &journal)?;
        self.phase = Phase::Active(Generation { binding, journal });
        self.epoch = next.epoch();
        Ok(true)
    }
    /// Called only after the real replacement REGISTER/restoration whole writes.
    pub fn restored(&mut self) -> bool {
        self.first_loss = None;
        self.window.take().is_some()
    }
    pub fn close(&mut self) {
        let old = std::mem::replace(&mut self.phase, Phase::Retired);
        drop(old);
        self.window = None;
        self.first_loss = None;
    }
}

#[derive(Debug)]
struct RecoveryFailure {
    first: ConnectionLoss,
    terminal: Cause,
}
impl std::fmt::Display for RecoveryFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PILS recovery ended: {}; first connection loss: {}",
            self.terminal, self.first
        )
    }
}
impl std::error::Error for RecoveryFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.terminal.as_ref())
    }
}

#[cfg(test)]
mod tests;
