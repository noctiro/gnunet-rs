//! Verified public identities and one fixed native/canonical recovery window.
use crate::Fault;
use gnunet_pils::client::{Epoch, Identity};
use gnunet_pils_host::client::ConnectionLoss;
use gnunet_types::Error as Protocol;
use std::time::Duration;
use tokio::time::Instant;

#[derive(Clone, Copy)]
struct Window {
    hard: Instant,
    until: u64,
}
impl Window {
    fn new(utc: u64, hard: Instant, until: u64) -> Result<Self, Fault> {
        Ok(Self {
            hard: Instant::now()
                .checked_add(Duration::from_secs(30))
                .ok_or(Protocol::Overflow)?
                .min(hard),
            until: utc
                .checked_add(30_000_000)
                .filter(|value| *value != u64::MAX)
                .ok_or(Protocol::Overflow)?
                .min(until),
        })
    }
}
enum Phase<'pils> {
    Awaiting,
    Active(Identity<'pils>),
    Retiring {
        original: Option<Identity<'pils>>,
        target: Option<Identity<'pils>>,
        window: Window,
    },
    Restoring {
        identity: Identity<'pils>,
        window: Window,
    },
}
struct SourceLoss<'pils> {
    lost: Epoch<'pils>,
    previous: Option<Identity<'pils>>,
    first_epoch: Epoch<'pils>,
    first: ConnectionLoss,
}
pub(in crate::runtime) struct Owner<'pils> {
    phase: Phase<'pils>,
    source_loss: Option<SourceLoss<'pils>>,
}
pub(in crate::runtime) enum Change {
    Refresh,
    Begin {
        previous: Option<[u8; 32]>,
        next: Option<[u8; 32]>,
    },
}
impl<'pils> Owner<'pils> {
    pub fn new() -> Self {
        Self {
            phase: Phase::Awaiting,
            source_loss: None,
        }
    }
    fn window(&self) -> Option<Window> {
        match &self.phase {
            Phase::Retiring { window, .. } | Phase::Restoring { window, .. } => Some(*window),
            _ => None,
        }
    }
    pub fn observation(&self) -> Option<Identity<'pils>> {
        match &self.phase {
            Phase::Awaiting => None,
            Phase::Active(identity) | Phase::Restoring { identity, .. } => Some(*identity),
            Phase::Retiring { target, .. } => *target,
        }
    }
    pub fn selected(&self) -> Option<[u8; 32]> {
        match &self.phase {
            Phase::Active(identity) | Phase::Restoring { identity, .. } => {
                Some(*identity.peer().as_bytes())
            }
            _ => None,
        }
    }
    pub fn retiring(&self) -> bool {
        matches!(self.phase, Phase::Retiring { .. })
    }
    pub fn source_lost(&self) -> bool {
        self.source_loss.is_some() && self.observation().is_none()
    }
    pub fn bound(&self) -> Option<Instant> {
        self.window().map(|window| window.hard)
    }
    pub fn bounds(&self) -> Option<(Instant, u64)> {
        self.window().map(|window| (window.hard, window.until))
    }
    pub fn failure(&mut self, terminal: Fault) -> Fault {
        match self.source_loss.take() {
            Some(loss) => Fault::IdentityRecoveryFailure {
                epoch: loss.first_epoch.value(),
                cause: loss.first,
                terminal: Box::new(terminal),
            },
            None => terminal,
        }
    }
    fn timeout(&mut self) -> Fault {
        match self.source_loss.take() {
            Some(loss) => Fault::IdentityRecoveryTimeout {
                epoch: loss.first_epoch.value(),
                cause: loss.first,
            },
            None => Protocol::Deadline.into(),
        }
    }
    pub fn guard_native(&mut self) -> Result<(), Fault> {
        if self.bound().is_some_and(|hard| Instant::now() >= hard) {
            return Err(self.timeout());
        }
        Ok(())
    }
    pub fn guard(&mut self, utc: u64) -> Result<(), Fault> {
        self.guard_native()?;
        if self.window().is_some_and(|window| utc >= window.until) {
            return Err(self.timeout());
        }
        if self
            .observation()
            .is_some_and(|identity| utc >= identity.expiration().as_micros())
        {
            return Err(Fault::IdentityLost);
        }
        Ok(())
    }
    pub fn observe(
        &mut self,
        next: Identity<'pils>,
        utc: u64,
        hard: Instant,
        until: u64,
    ) -> Result<Change, Fault> {
        self.guard(utc)?;
        if next.expiration().as_micros() <= utc {
            return Err(Fault::IdentityLost);
        }
        let valid = if let Some(previous) = self.observation() {
            next.epoch() == previous.epoch()
                && next.revision() >= previous.revision()
                && (next.revision() != previous.revision() || next == previous)
        } else if let Some(loss) = &self.source_loss {
            next.epoch().is_successor_of(loss.lost)
                && loss
                    .previous
                    .is_none_or(|previous| next.revision() > previous.revision())
        } else {
            true
        };
        if !valid {
            return Err(Protocol::StaleGeneration.into());
        }
        match &mut self.phase {
            Phase::Awaiting => self.phase = Phase::Active(next),
            Phase::Active(previous) if previous.peer() == next.peer() => *previous = next,
            Phase::Active(previous) => {
                let previous = *previous;
                self.phase = Phase::Retiring {
                    original: Some(previous),
                    target: Some(next),
                    window: Window::new(utc, hard, until)?,
                };
                return Ok(Change::Begin {
                    previous: Some(*previous.peer().as_bytes()),
                    next: Some(*next.peer().as_bytes()),
                });
            }
            Phase::Retiring { target, .. } => *target = Some(next),
            Phase::Restoring { identity, .. } if identity.peer() == next.peer() => *identity = next,
            Phase::Restoring { .. } => {
                let Phase::Restoring { identity, window } =
                    std::mem::replace(&mut self.phase, Phase::Awaiting)
                else {
                    return Err(Protocol::Conflict.into());
                };
                self.phase = Phase::Retiring {
                    original: Some(identity),
                    target: Some(next),
                    window,
                };
                return Ok(Change::Begin {
                    previous: Some(*identity.peer().as_bytes()),
                    next: Some(*next.peer().as_bytes()),
                });
            }
        }
        Ok(Change::Refresh)
    }
    /// Consume only an actual idle native observer's connection-loss receipt.
    /// A missing target cannot authorize IPC or endpoint admission.
    pub fn lose(
        &mut self,
        epoch: Epoch<'pils>,
        cause: ConnectionLoss,
        utc: u64,
        hard: Instant,
        until: u64,
    ) -> Result<Change, Fault> {
        let previous = self.observation();
        if previous.is_some_and(|identity| identity.epoch() != epoch)
            || previous.is_none()
                && self
                    .source_loss
                    .as_ref()
                    .is_some_and(|loss| epoch != loss.lost && !epoch.is_successor_of(loss.lost))
        {
            return Err(Protocol::StaleGeneration.into());
        }
        let window = match self.window() {
            Some(window) => window,
            None => Window::new(utc, hard, until)?,
        };
        if let Some(loss) = &mut self.source_loss {
            loss.lost = epoch;
            loss.previous = previous.or(loss.previous);
        } else {
            self.source_loss = Some(SourceLoss {
                lost: epoch,
                previous,
                first_epoch: epoch,
                first: cause,
            });
        }
        let old = std::mem::replace(&mut self.phase, Phase::Awaiting);
        let (original, begin) = match old {
            Phase::Retiring { original, .. } => (original, false),
            Phase::Active(identity) | Phase::Restoring { identity, .. } => (Some(identity), true),
            Phase::Awaiting => (None, true),
        };
        self.phase = Phase::Retiring {
            original,
            target: None,
            window,
        };
        Ok(if begin {
            Change::Begin {
                previous: original.map(|identity| *identity.peer().as_bytes()),
                next: None,
            }
        } else {
            Change::Refresh
        })
    }
    pub fn connected(&self, epoch: Epoch<'pils>) -> Result<(), Fault> {
        if let Some(loss) = &self.source_loss
            && !epoch.is_successor_of(loss.lost)
        {
            return Err(Protocol::StaleGeneration.into());
        }
        Ok(())
    }
    pub fn can_admit(&self) -> bool {
        matches!(
            self.phase,
            Phase::Retiring {
                target: Some(_),
                ..
            }
        )
    }
    /// Original rows, drivers and frame loans must already be retired.
    pub fn admit(&mut self) -> Result<(Option<[u8; 32]>, [u8; 32]), Fault> {
        self.guard_native()?;
        if !self.can_admit() {
            return Err(Protocol::NotReady.into());
        }
        let Phase::Retiring {
            original,
            target: Some(target),
            window,
        } = std::mem::replace(&mut self.phase, Phase::Awaiting)
        else {
            return Err(Protocol::Conflict.into());
        };
        let peers = (
            original.map(|identity| *identity.peer().as_bytes()),
            *target.peer().as_bytes(),
        );
        self.phase = Phase::Restoring {
            identity: target,
            window,
        };
        Ok(peers)
    }
    pub fn restored(&mut self) -> Result<bool, Fault> {
        self.guard_native()?;
        if !matches!(self.phase, Phase::Restoring { .. }) {
            return Ok(false);
        }
        if let Phase::Restoring { identity, .. } =
            std::mem::replace(&mut self.phase, Phase::Awaiting)
        {
            self.phase = Phase::Active(identity);
        }
        self.source_loss = None;
        Ok(true)
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
