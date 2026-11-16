//! Original connection and frame-loan retirement before selecting fresh authority.
mod owner;
use super::*;
pub(super) use owner::{Change, Owner};

impl<'id, 'pils, 'pool, 'slots, 'buf> Runtime<'id, 'pils, 'pool, 'slots, 'buf> {
    pub(super) fn retire_identity(
        &mut self,
        previous: Option<[u8; 32]>,
        next: Option<[u8; 32]>,
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
        self.ipc.set_recovery_bound(self.identity.bounds())?;
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
            if self.identity.can_admit() {
                let _original = self.identity.admit()?;
                self.ipc.resume_source()?;
                progress = true;
            }
        }
        Ok(progress)
    }
}
