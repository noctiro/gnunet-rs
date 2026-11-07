//! Original PILS authority and one coalescing native/canonical recovery window.
use super::*;
use gnunet_pils::client::Identity;

struct Window {
    hard: Instant,
    until: u64,
}
enum Phase<'pils> {
    Awaiting,
    Active(Identity<'pils>),
    Retiring {
        original: Identity<'pils>,
        target: Identity<'pils>,
        window: Window,
    },
    Restoring {
        identity: Identity<'pils>,
        window: Window,
    },
}
pub(super) struct Owner<'pils> {
    phase: Phase<'pils>,
}
pub(super) enum Change {
    Refresh,
    Begin { previous: [u8; 32], next: [u8; 32] },
}
impl<'pils> Owner<'pils> {
    pub fn new() -> Self {
        Self {
            phase: Phase::Awaiting,
        }
    }
    pub fn observation(&self) -> Option<Identity<'pils>> {
        match &self.phase {
            Phase::Awaiting => None,
            Phase::Active(v) => Some(*v),
            Phase::Retiring { target, .. } => Some(*target),
            Phase::Restoring { identity, .. } => Some(*identity),
        }
    }
    pub fn selected(&self) -> Option<[u8; 32]> {
        match &self.phase {
            Phase::Active(v) | Phase::Restoring { identity: v, .. } => Some(*v.peer().as_bytes()),
            _ => None,
        }
    }
    pub fn retiring(&self) -> bool {
        matches!(self.phase, Phase::Retiring { .. })
    }
    pub fn bound(&self) -> Option<Instant> {
        match &self.phase {
            Phase::Retiring { window, .. } | Phase::Restoring { window, .. } => Some(window.hard),
            _ => None,
        }
    }
    pub fn guard_native(&self) -> Result<(), Fault> {
        if self.bound().is_some_and(|hard| Instant::now() >= hard) {
            return Err(Protocol::Deadline.into());
        }
        Ok(())
    }
    pub fn guard(&self, utc: u64) -> Result<(), Fault> {
        self.guard_native()?;
        if self
            .observation()
            .is_some_and(|v| utc >= v.expiration().as_micros())
        {
            return Err(Fault::IdentityLost);
        }
        if matches!(&self.phase,Phase::Retiring {window,..}|Phase::Restoring {window,..} if utc>=window.until)
        {
            return Err(Protocol::Deadline.into());
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
        self.guard_native()?;
        if matches!(&self.phase,Phase::Retiring {window,..}|Phase::Restoring {window,..} if utc>=window.until)
        {
            return Err(Protocol::Deadline.into());
        }
        if next.expiration().as_micros() <= utc {
            return Err(Fault::IdentityLost);
        }
        if let Some(previous) = self.observation()
            && (next.epoch() != previous.epoch()
                || next.revision() < previous.revision()
                || (next.revision() == previous.revision() && next != previous))
        {
            return Err(Protocol::StaleGeneration.into());
        }
        let peer = *next.peer().as_bytes();
        match &mut self.phase {
            Phase::Awaiting => self.phase = Phase::Active(next),
            Phase::Active(previous) if previous.peer() == next.peer() => *previous = next,
            Phase::Active(previous) => {
                let previous = *previous;
                let window = Window {
                    hard: Instant::now()
                        .checked_add(Duration::from_secs(30))
                        .ok_or(Protocol::Overflow)?
                        .min(hard),
                    until: utc
                        .checked_add(30_000_000)
                        .filter(|v| *v != u64::MAX)
                        .ok_or(Protocol::Overflow)?
                        .min(until),
                };
                self.phase = Phase::Retiring {
                    original: previous,
                    target: next,
                    window,
                };
                return Ok(Change::Begin {
                    previous: *previous.peer().as_bytes(),
                    next: peer,
                });
            }
            Phase::Retiring { target, .. } => *target = next,
            Phase::Restoring { identity, .. } if identity.peer() == next.peer() => *identity = next,
            Phase::Restoring { .. } => {
                let Phase::Restoring { identity, window } =
                    std::mem::replace(&mut self.phase, Phase::Awaiting)
                else {
                    return Err(Protocol::Conflict.into());
                };
                self.phase = Phase::Retiring {
                    original: identity,
                    target: next,
                    window,
                };
                return Ok(Change::Begin {
                    previous: *identity.peer().as_bytes(),
                    next: peer,
                });
            }
        }
        Ok(Change::Refresh)
    }
    /// Called only after all original rows/drivers and frame loans really retire.
    pub fn admit(&mut self) -> Result<([u8; 32], [u8; 32]), Fault> {
        self.guard_native()?;
        if !self.retiring() {
            return Err(Protocol::NotReady.into());
        }
        let Phase::Retiring {
            original,
            target,
            window,
        } = std::mem::replace(&mut self.phase, Phase::Awaiting)
        else {
            return Err(Protocol::Conflict.into());
        };
        let peers = (*original.peer().as_bytes(), *target.peer().as_bytes());
        self.phase = Phase::Restoring {
            identity: target,
            window,
        };
        Ok(peers)
    }
    pub fn restored(&mut self) -> bool {
        if !matches!(self.phase, Phase::Restoring { .. }) {
            return false;
        }
        if let Phase::Restoring { identity, .. } =
            std::mem::replace(&mut self.phase, Phase::Awaiting)
        {
            self.phase = Phase::Active(identity);
        }
        true
    }
}

#[cfg(test)]
mod tests;

impl<'id, 'pils, 'pool, 'slots, 'buf> Runtime<'id, 'pils, 'pool, 'slots, 'buf> {
    pub(super) fn retire_identity(
        &mut self,
        previous: [u8; 32],
        next: [u8; 32],
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Fault> {
        let facts = self.ipc.retire_source(|generation, role, bytes| {
            observe(Event::TransportOutputRetired {
                generation,
                kind: role.kind(),
                queue: role.queue(),
                message_id: role.message(),
                flow_id: role.flow(),
                bytes,
            })
        })?;
        self.attached = false;
        self.register_queued = false;
        self.register_written = false;
        self.ready = false;
        self.restored = false;
        self.local_advertised = false;
        self.local_address_wire = 0;
        self.local_address_written = false;
        for advert in &mut self.advertisements {
            advert.wire = 0;
            advert.written = false;
        }
        let bound = self
            .deadline(self.limits.close_grace)?
            .min(self.identity.bound().ok_or(Protocol::NotReady)?);
        observe(Event::IdentityRetiring {
            epoch: self.epoch,
            previous,
            next,
            facts,
        });
        for row in self.rows.iter_mut().flatten() {
            capture_send(row)?;
            if let Some(send) = row.send.take()
                && !send.orphaned
            {
                self.sends_retired += 1;
                observe(Event::SendRetired {
                    epoch: self.epoch,
                    queue: send.queue,
                    message_id: send.mid,
                    accepted: send.accepted,
                    total: send.total,
                    result_written: send.result_written,
                    result_bytes: send.result_bytes,
                    unknown: send.unknown,
                });
            }
            if let Some(incoming) = row.incoming.take() {
                self.incoming_lost += 1;
                observe(Event::IncomingRetired {
                    generation: facts.generation,
                    flow_id: incoming.id,
                    written: incoming.written,
                });
            }
            drop(row.connecting.take());
            if let Some(link) = &mut row.link {
                link.close();
            }
            if !row.closing {
                observe(Event::QueueRetired {
                    epoch: self.epoch,
                    queue: row.id,
                });
            }
            row.closing = true;
            row.advertised = false;
            row.down = true;
            row.down_written = true;
            row.input = None;
            row.retire_hard = Some(row.retire_hard.map_or(bound, |old| old.min(bound)));
        }
        for row in self.rows.iter().flatten() {
            self.endpoint
                .as_mut()
                .ok_or(Protocol::Closed)?
                .retire_driver_at(&row.driver, row.retire_hard.ok_or(Protocol::Conflict)?)?;
        }
        Ok(())
    }
    pub(super) fn poll_identity_retirement(
        &mut self,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Fault> {
        if !self.identity.retiring() {
            return Ok(false);
        }
        let mut progress = false;
        for i in 0..self.rows.len() {
            let Some(row) = &self.rows[i] else {
                continue;
            };
            let endpoint = self.endpoint.as_ref().ok_or(Protocol::Closed)?;
            let done = endpoint.driver_done(&row.driver)?;
            if done {
                let forced = endpoint.driver_was_canceled(&row.driver)?;
                self.identity_forced_drivers += usize::from(forced);
                observe(Event::IdentityDriverRetired {
                    epoch: self.epoch,
                    queue: row.id,
                    forced,
                });
                self.reap_row(i)?;
                progress = true;
                continue;
            }
            if row.retire_hard.is_some_and(|t| Instant::now() >= t) {
                let driver = row.driver.clone();
                let forced = self
                    .endpoint
                    .as_mut()
                    .ok_or(Protocol::Closed)?
                    .cancel_driver(&driver)?;
                self.identity_forced_drivers += usize::from(forced);
                observe(Event::IdentityDriverRetired {
                    epoch: self.epoch,
                    queue: row.id,
                    forced,
                });
                self.reap_row(i)?;
                progress = true;
            }
        }
        if self.rows.iter().all(Option::is_none) {
            if !self.loans.available() {
                return Err(Protocol::Conflict.into());
            }
            let _original = self.identity.admit()?;
            self.ipc.resume_source()?;
            progress = true;
        }
        Ok(progress)
    }
}
