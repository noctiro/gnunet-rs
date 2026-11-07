//! One original public observer, durable per-identity state and bounded recovery.
use crate::Cause;
use gnunet_pils::client::{Epoch, Identity as Observation};
use gnunet_pils_host::client::Client;
use gnunet_service_runtime::clock::{Deadline, RuntimeClock};
use gnunet_types::Error;
use gnunet_udp_communicator_host::{
    communicator::{Communicator, IdentityRetirement},
    identity::IdentityEpoch,
    replay::{Journal, Namespace},
};
use gnunet_wire::official::AbsoluteTime;
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
    native: Pin<Box<Sleep>>,
    canonical: Pin<Box<Deadline>>,
}
impl Window {
    fn new(clock: Arc<dyn RuntimeClock>) -> Result<Self, Cause> {
        let hard = Instant::now()
            .checked_add(Duration::from_secs(30))
            .ok_or(Error::Overflow)?;
        let until = clock
            .sample()?
            .now
            .as_micros()
            .checked_add(30_000_000)
            .filter(|v| *v != u64::MAX)
            .ok_or(Error::Overflow)?;
        Ok(Self {
            hard,
            until: AbsoluteTime::from_micros(until),
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
    Retired,
}
pub(super) struct State<'id> {
    namespace: Namespace,
    phase: Phase<'id>,
    epoch: Epoch<'id>,
    peers: usize,
    clock: Arc<dyn RuntimeClock>,
    window: Option<Window>,
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
        })
    }
    pub fn binding(&self) -> Result<&IdentityEpoch<'id>, Error> {
        match &self.phase {
            Phase::Active(v) => Ok(&v.binding),
            Phase::Retired => Err(Error::Closed),
        }
    }
    pub fn ports(&mut self) -> Result<(&IdentityEpoch<'id>, &mut Journal), Error> {
        match &mut self.phase {
            Phase::Active(v) => Ok((&v.binding, &mut v.journal)),
            Phase::Retired => Err(Error::Closed),
        }
    }
    pub fn guard(&mut self, cx: &mut Context<'_>) -> Result<(), Cause> {
        if let Some(window) = &mut self.window {
            window.guard(cx)?;
        }
        Ok(())
    }
    /// Original source branding, revision and freshness precede any key access.
    fn verify(&self, next: Observation<'id>, now: AbsoluteTime) -> Result<(), Error> {
        let previous = self.binding()?.observation();
        if next.epoch() != self.epoch
            || next.revision() < previous.revision()
            || (next.revision() == previous.revision() && next != previous)
        {
            return Err(Error::StaleGeneration);
        }
        if next.expiration() <= now {
            return Err(Error::Timeout);
        }
        Ok(())
    }
    /// Retire actual old IO before replacing keys or history. A failed rebuild
    /// leaves an explicit Retired phase, with no active signer/journal facade.
    pub fn select(
        &mut self,
        source: &Client<'id, 32>,
        comm: &mut Communicator<'_>,
        now: AbsoluteTime,
        observe: &mut impl FnMut(IdentityRetirement) -> Result<(), Cause>,
    ) -> Result<bool, Cause> {
        let next = source.identity().ok_or(Error::NotReady)?;
        self.verify(next, now)?;
        let Phase::Active(current) = &mut self.phase else {
            return Err(Error::Closed.into());
        };
        if next.peer().as_bytes() == &current.binding.peer() {
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
        if !current.journal.quiescent()? {
            return Err(Error::OutcomeUnknown.into());
        }
        let retired = comm.retire_identity()?;
        let old = std::mem::replace(&mut self.phase, Phase::Retired);
        drop(old);
        observe(retired)?;
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
        Ok(true)
    }
    /// Called only after the real replacement REGISTER/restoration whole writes.
    pub fn restored(&mut self) -> bool {
        self.window.take().is_some()
    }
    pub fn close(&mut self) {
        if let Phase::Active(v) = &mut self.phase {
            v.binding.close();
        }
    }
}

#[cfg(test)]
mod tests;
