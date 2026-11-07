//! Actual bounded IPC response/address leases; no phantom route/connect success.
use super::*;
impl<'id, 'store, 'bytes> Engine<'id, 'store, 'bytes> {
    /// Call only for an actual accepted original IPC MQ, never from a wire RID.
    pub fn attach_client(&mut self) -> Result<Client<'id>, Error> {
        let row = self
            .store
            .clients
            .iter()
            .position(|c| c.state.is_none())
            .ok_or(Error::Capacity)?;
        let serial = self.serial()?;
        self.store.clients[row].state = Some(ClientState {
            serial,
            pending: None,
        });
        Ok(Client(self.handle(Reference { row, serial })))
    }
    fn allocation_address(
        &self,
        prefix: Prefix,
        victim: usize,
        now: AbsoluteTime,
    ) -> Result<Option<Address>, Error> {
        let start = number(prefix.network);
        let max = self
            .store
            .leases
            .len()
            .checked_add(self.store.flows.len())
            .and_then(|n| n.checked_add(4))
            .ok_or(Error::Overflow)?;
        let mask = prefix.mask()?;
        for offset in 1..=max {
            let Some(n) = start.checked_add(offset as u128) else {
                break;
            };
            if n & mask != start
                || (prefix.network.family() == Family::V4 && n > u128::from(u32::MAX))
            {
                break;
            }
            let candidate = address(prefix.network.family(), n);
            if candidate == prefix.interface
                || (prefix.network.family() == Family::V4
                    && prefix.bits < 31
                    && n | mask == u128::from(u32::MAX))
            {
                continue;
            }
            if self.store.leases.iter().enumerate().any(|(i, l)| {
                i != victim
                    && l.state
                        .is_some_and(|l| l.expires > now && l.address == candidate)
            }) {
                continue;
            }
            // A lease may expire/evict, but an original active tuple still owns
            // its virtual address until its actual channel/packet debt retires.
            if self
                .store
                .flows
                .iter()
                .any(|f| f.state.is_some_and(|f| f.tuple.destination == candidate))
            {
                continue;
            }
            return Ok(Some(candidate));
        }
        Ok(None)
    }
    fn choose_address(
        &self,
        af: u32,
        victim: usize,
        now: AbsoluteTime,
    ) -> Result<Option<Address>, Error> {
        let family = if af == 0 {
            None
        } else {
            Some(self.limits.ipc_af.family(af)?)
        };
        if (family.is_none() || family == Some(Family::V4))
            && let Some(p) = self.limits.ipv4
            && let Some(a) = self.allocation_address(p, victim, now)?
        {
            return Ok(Some(a));
        }
        if (family.is_none() || family == Some(Family::V6))
            && let Some(p) = self.limits.ipv6
            && let Some(a) = self.allocation_address(p, victim, now)?
        {
            return Ok(Some(a));
        }
        Ok(None)
    }
    /// Admit the actual official redirection. Its response records address
    /// allocation only, never a discovered/connected exit, native packet write or
    /// remote application delivery. No OS-ready route means real AF_UNSPEC failure.
    pub fn redirect(
        &mut self,
        client: Client<'id>,
        request: WireRequest,
        now: AbsoluteTime,
    ) -> Result<Request<'id>, Error> {
        let c = self.client_ref(client)?;
        request.encoded_len()?;
        let (expires, result_af, id, target) = match request {
            WireRequest::Internet {
                expires,
                result_af,
                request_id,
                destination,
                ..
            } => (
                expires,
                result_af,
                request_id,
                Target::Internet(destination),
            ),
            WireRequest::Service {
                expires,
                result_af,
                request_id,
                peer,
                service,
                ..
            } => (
                expires,
                result_af,
                request_id,
                Target::Service {
                    peer,
                    descriptor: service,
                },
            ),
        };
        let expires = AbsoluteTime::from_micros(expires);
        if id == [0; 8] {
            return Err(Error::InvalidInput);
        }
        if result_af != 0 {
            self.limits.ipc_af.family(result_af)?;
        }
        if self
            .store
            .requests
            .iter()
            .any(|r| r.state.is_some_and(|r| r.client == c && r.id == id))
        {
            return Err(Error::Conflict);
        }
        let row = self
            .store
            .requests
            .iter()
            .position(|r| r.state.is_none())
            .ok_or(Error::Capacity)?;
        // Never silently retarget an unexpired virtual address retained by an
        // application. Bounded exhaustion returns official AF_UNSPEC failure.
        let victim = self
            .store
            .leases
            .iter()
            .position(|l| l.state.is_none())
            .or_else(|| {
                self.store
                    .leases
                    .iter()
                    .enumerate()
                    .filter_map(|(i, l)| l.state.filter(|l| l.expires <= now).map(|l| (i, l.used)))
                    .min_by_key(|(_, used)| *used)
                    .map(|(i, _)| i)
            });
        let address = if expires <= now || self.current_tun().is_err() {
            None
        } else if let Some(victim) = victim {
            self.choose_address(result_af, victim, now)?
        } else {
            None
        };
        self.preflight(if address.is_some() { 2 } else { 1 })?;
        let mut bytes = [0; 32];
        let len = Response {
            request_id: id,
            address,
        }
        .encode_with_profile(&mut bytes, self.limits.ipc_af)?;
        let serial = self.serial()?;
        let lease = if let (Some(address), Some(victim)) = (address, victim) {
            let serial = self.serial()?;
            let r = Reference {
                row: victim,
                serial,
            };
            self.store.leases[victim].state = Some(LeaseState {
                serial,
                address,
                target,
                expires,
                used: now,
            });
            Some(r)
        } else {
            None
        };
        self.store.requests[row].state = Some(RequestState {
            serial,
            client: c,
            id,
            lease,
            bytes,
            len,
            status: Outcome::Buffered,
            attempt: None,
            canceled: false,
            dead: false,
        });
        Ok(Request(self.handle(Reference { row, serial })))
    }
    /// Explicit local-only callback suppression. This never encodes a wire CANCEL
    /// or claims the already allocated mapping was remotely revoked.
    pub fn cancel_request(&mut self, request: Request<'id>) -> Result<(), Error> {
        let r = self.request_ref(request)?;
        let s = self.store.requests[r.row]
            .state
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        s.canceled = true;
        if s.status == Outcome::Buffered {
            s.status = Outcome::Canceled
        }
        Ok(())
    }
    /// Actual original local MQ stopped before logical request retirement.
    /// Allocation leases intentionally outlive callback/socket ownership.
    pub fn client_lost(&mut self, client: Client<'id>, reason: Error) -> Result<Loss, Error> {
        let c = self.client_ref(client)?;
        let mut loss = Loss {
            outputs: 0,
            exposed: 0,
            reason,
        };
        for r in &mut *self.store.requests {
            if let Some(r) = r.state.as_mut()
                && r.client == c
            {
                r.dead = true;
                r.canceled = true;
                if !r.status.terminal() {
                    loss.outputs += 1;
                    if r.status.exposed() {
                        loss.exposed += 1
                    }
                    r.status = Outcome::Lost {
                        queued: r.status.queued(),
                        exposed: r.status.exposed(),
                        reason,
                    }
                }
            }
        }
        self.store.clients[c.row].state = None;
        Ok(loss)
    }
    /// Release an original settled callback/result row. Late callbacks cannot
    /// select a reused row, and this does not revoke its separate logical lease.
    pub fn retire_request(&mut self, request: Request<'id>) -> Result<(), Error> {
        let r = self.request_ref(request)?;
        let s = self.store.requests[r.row]
            .state
            .ok_or(Error::StaleGeneration)?;
        if !s.status.terminal() {
            return Err(Error::WouldBlock);
        }
        if let Some(c) = self
            .store
            .clients
            .get_mut(s.client.row)
            .and_then(|c| c.state.as_mut())
            && c.serial == s.client.serial
            && c.pending == Some(r)
        {
            c.pending = None
        }
        self.store.requests[r.row].state = None;
        Ok(())
    }
    /// Expire wire address leases against actual absolute time, and local idle
    /// flows against their original native activity epoch. Logical adjustments
    /// cannot renew or prematurely consume an idle budget.
    pub fn expire(
        &mut self,
        absolute: AbsoluteTime,
        activity: MonoInstant,
    ) -> Result<usize, Error> {
        self.observe_activity(activity)?;
        let mut count = 0;
        for l in &mut *self.store.leases {
            if l.state.is_some_and(|l| absolute >= l.expires) {
                l.state = None;
                count += 1
            }
        }
        let mut next = 0;
        while next < self.store.flows.len() {
            let expired = self.store.flows[next]
                .state
                .filter(|f| {
                    f.phase != Phase::Closing
                        && activity
                            .duration_since(f.used)
                            .is_ok_and(|elapsed| elapsed.0 >= self.limits.idle_micros)
                })
                .map(|f| Reference {
                    row: next,
                    serial: f.serial,
                });
            if let Some(r) = expired {
                self.close_flow(self.flow(r), Error::Deadline)?;
                count += 1
            }
            next += 1;
        }
        Ok(count)
    }
}
