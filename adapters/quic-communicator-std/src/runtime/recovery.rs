//! Local TRANSPORT replacement; native endpoint/stream ownership is independent.
use super::*;
impl<'id, 'pils, 'pool, 'slots, 'buf> Runtime<'id, 'pils, 'pool, 'slots, 'buf> {
    pub(super) fn transport_lost(
        &mut self,
        facts: TransportLoss,
        cause: Fault,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Fault> {
        if facts.next_generation != self.ipc.generation() {
            return Err(Protocol::Conflict.into());
        }
        self.attached = false;
        self.register_queued = false;
        self.register_written = false;
        self.ready = false;
        self.restored = false;
        self.local_advertised = false;
        self.local_address_wire = 0;
        self.local_address_written = false;
        for address in &mut self.advertisements {
            address.wire = 0;
            address.written = false;
        }
        // Ipc already detached the physical source and retired every original
        // input/output tag. Native reliable-stream prefixes cannot be canceled
        // and then submitted again; keep that exact send until it really drains.
        for row in self.rows.iter_mut().flatten() {
            capture_send(row)?;
            if let Some(send) = &mut row.send
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
                send.orphaned = true;
            }
            if let Some(incoming) = row.incoming.take() {
                // This is local retirement of failed callback authority, not a
                // successful Received and not a message replay on the new MQ.
                row.link
                    .as_mut()
                    .ok_or(Protocol::Stale)?
                    .release_frame(incoming.frame)?;
                self.incoming_lost += 1;
                row.input = None;
                observe(Event::IncomingRetired {
                    generation: facts.generation,
                    flow_id: incoming.id,
                    written: incoming.written,
                });
            }
            if row.advertised {
                observe(Event::QueueRetired {
                    epoch: self.epoch,
                    queue: row.id,
                });
            }
            row.advertised = false;
            row.queue_written = false;
            row.capacity_needed = false;
            if row.closing {
                // Its old DOWN/SENT debt is retired with that physical MQ.
                // The original native driver must still actually finish.
                row.send = None;
                row.down = true;
                row.down_written = true;
            } else {
                let fresh = self.next_queue.checked_add(1).ok_or(Protocol::Overflow)?;
                self.next_queue = fresh;
                row.id = fresh;
                row.down = false;
                row.down_written = true;
            }
        }
        observe(Event::TransportLost { facts, cause });
        Ok(())
    }
    pub(super) fn addresses_restored(&self) -> Result<bool, Fault> {
        if let Some(nat) = &self.nat {
            Ok(nat.notification()?.is_none()
                && self.advertisements.iter().all(|a| a.wire != 0 && a.written)
                // Every change is applied to this bounded cache before its
                // original NAT notification is released. With no pending
                // notification, matching counts plus the per-claim whole-write
                // facts cover the current population without a quadratic scan.
                && nat.addresses().count() == self.advertisements.len())
        } else {
            Ok(self.local_advertised && self.local_address_written)
        }
    }
    pub(super) fn advertise_current(&mut self, utc: u64) -> Result<bool, Fault> {
        if !self.attached || !self.register_queued {
            return Ok(false);
        }
        // Process the original NAT notification before rebuilding its cache.
        // A pending removal must never be reannounced as a current claim.
        if let Some(nat) = &self.nat {
            if nat.notification()?.is_some() {
                return Ok(false);
            }
            for offset in 0..self.advertisements.len() {
                let i = (self.advert_cursor + offset) % self.advertisements.len();
                let advert = &self.advertisements[i];
                if advert.wire != 0 {
                    continue;
                }
                let address = nat.address(advert.id)?.address()?;
                let socket = socket_address(address.address()).ok_or(Protocol::Unsupported)?;
                let canonical = Address::new(self.profile, socket)?.canonical()?;
                if !self.ipc.room(1, 21 + canonical.as_bytes().len()) {
                    return Ok(false);
                }
                let wire = self.next_address.checked_add(1).ok_or(Protocol::Overflow)?;
                self.ipc.enqueue(
                    Request::AddAddress {
                        id: wire,
                        validity: self
                            .until
                            .saturating_sub(utc)
                            .min(micros(self.hard.saturating_duration_since(Instant::now()))?),
                        network: self.scanner.classify(socket),
                        address: canonical.as_bytes(),
                    },
                    ipc::Role::Advert(wire),
                    self.hard,
                )?;
                self.advertisements[i].wire = wire;
                self.advertisements[i].written = false;
                self.next_address = wire;
                self.advert_cursor = (i + 1) % self.advertisements.len();
                return Ok(true);
            }
            return Ok(false);
        }
        if self.local_advertised {
            return Ok(false);
        }
        let socket = self.local_addr()?;
        if socket.ip().is_unspecified() {
            self.local_advertised = true;
            self.local_address_written = true;
            return Ok(true);
        }
        let canonical = Address::new(self.profile, socket)?.canonical()?;
        if !self.ipc.room(1, 21 + canonical.as_bytes().len()) {
            return Ok(false);
        }
        let wire = self.next_address.checked_add(1).ok_or(Protocol::Overflow)?;
        self.ipc.enqueue(
            Request::AddAddress {
                id: wire,
                validity: self
                    .until
                    .saturating_sub(utc)
                    .min(micros(self.hard.saturating_duration_since(Instant::now()))?),
                network: self.scanner.classify(socket),
                address: canonical.as_bytes(),
            },
            ipc::Role::Advert(wire),
            self.hard,
        )?;
        self.next_address = wire;
        self.local_address_wire = wire;
        self.local_address_written = false;
        self.local_advertised = true;
        Ok(true)
    }
}
