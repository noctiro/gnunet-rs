//! Original immutable output, actual source loss, and independent retirement debt.
use super::*;
impl<'id, 'store, 'bytes> Engine<'id, 'store, 'bytes> {
    /// Prepare one original response on the actual original local MQ. The bytes
    /// were allocated inline before request admission; no fake service ACK exists.
    pub fn prepare_client(
        &mut self,
        client: Client<'id>,
    ) -> Result<Option<Prepared<'_, 'id>>, Error> {
        let c = self.client_ref(client)?;
        if self.store.clients[c.row]
            .state
            .is_some_and(|c| c.pending.is_some())
        {
            return Ok(None);
        }
        let found = (0..self.store.requests.len())
            .map(|n| (self.request_cursor + n) % self.store.requests.len())
            .find(|row| {
                self.store.requests[*row]
                    .state
                    .is_some_and(|r| r.client == c && !r.canceled && r.status == Outcome::Buffered)
            });
        let Some(row) = found else { return Ok(None) };
        let attempt = self.serial()?;
        let r = self.store.requests[row]
            .state
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        let reference = Reference {
            row,
            serial: r.serial,
        };
        r.status = Outcome::Prepared;
        r.attempt = Some(attempt);
        self.store.clients[c.row]
            .state
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .pending = Some(reference);
        self.request_cursor = (row + 1) % self.store.requests.len();
        let effect = Effect {
            origin: Origin::Request(reference),
            destination: Destination::Client(client),
            serial: attempt,
        };
        let r = self.store.requests[row]
            .state
            .as_ref()
            .ok_or(Error::StaleGeneration)?;
        Ok(Some(Prepared {
            effect,
            bytes: &r.bytes[..r.len],
        }))
    }
    /// Prepare the oldest original buffered peer packet for this actual source.
    /// One prepared/native attempt per flow preserves TCP start/data ordering.
    pub fn prepare_peer(&mut self, peer: Peer<'id>) -> Result<Option<Prepared<'_, 'id>>, Error> {
        let r = self.peer_ref(peer)?;
        let f = self.store.flows[r.row]
            .state
            .ok_or(Error::StaleGeneration)?;
        if f.peer_ended || f.phase != Phase::Ready {
            return Err(Error::Closed);
        }
        if f.pending.is_some() {
            return Ok(None);
        }
        let found = self
            .store
            .packets
            .iter()
            .enumerate()
            .filter_map(|(i, p)| {
                p.state
                    .filter(|p| {
                        p.flow == r
                            && matches!(p.kind, PacketKind::Peer)
                            && p.status == Outcome::Buffered
                    })
                    .map(|p| (i, p.serial))
            })
            .min_by_key(|(_, s)| *s);
        let Some((row, serial)) = found else {
            return Ok(None);
        };
        let attempt = self.serial()?;
        let p = self.store.packets[row]
            .state
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        p.status = Outcome::Prepared;
        p.attempt = Some(attempt);
        p.bound = Some(peer.serial);
        let reference = Reference { row, serial };
        self.store.flows[r.row]
            .state
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .pending = Some(reference);
        let effect = Effect {
            origin: Origin::Packet(reference),
            destination: Destination::Peer(peer),
            serial: attempt,
        };
        let p = &self.store.packets[row];
        Ok(Some(Prepared {
            effect,
            bytes: &p.bytes[..p.state.ok_or(Error::StaleGeneration)?.len],
        }))
    }
    /// Prepare one original raw TUN packet. Semantic peer receive_done remains
    /// unavailable until this complete packet actually writes on the original TUN.
    pub fn prepare_tun(&mut self, tun: Tun<'id>) -> Result<Option<Prepared<'_, 'id>>, Error> {
        self.tun_ref(tun, true)?;
        if self.current_tun()? != tun {
            return Err(Error::StaleGeneration);
        }
        let found = self
            .store
            .packets
            .iter()
            .enumerate()
            .filter_map(|(i, p)| {
                p.state
                    .filter(|p| {
                        matches!(p.kind,PacketKind::Tun{tun:serial,..}if serial==tun.serial)
                            && p.status == Outcome::Buffered
                    })
                    .map(|p| (i, p.serial))
            })
            .min_by_key(|(_, s)| *s);
        let Some((row, serial)) = found else {
            return Ok(None);
        };
        let state = self.store.packets[row]
            .state
            .ok_or(Error::StaleGeneration)?;
        let f = self.store.flows[state.flow.row]
            .state
            .ok_or(Error::StaleGeneration)?;
        if f.serial != state.flow.serial || f.phase != Phase::Ready {
            return Err(Error::Closed);
        }
        let attempt = self.serial()?;
        let p = self.store.packets[row]
            .state
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        p.status = Outcome::Prepared;
        p.attempt = Some(attempt);
        let effect = Effect {
            origin: Origin::Packet(Reference { row, serial }),
            destination: Destination::Tun(tun),
            serial: attempt,
        };
        let p = &self.store.packets[row];
        Ok(Some(Prepared {
            effect,
            bytes: &p.bytes[..p.state.ok_or(Error::StaleGeneration)?.len],
        }))
    }
    fn effect_state(&self, effect: Effect<'id>) -> Result<Outcome, Error> {
        match effect.origin {
            Origin::Request(r) => {
                let rr = self.request_ref(Request(self.handle(r)))?;
                let s = self.store.requests[rr.row]
                    .state
                    .ok_or(Error::StaleGeneration)?;
                if s.attempt != Some(effect.serial)
                    || effect.destination != Destination::Client(Client(self.handle(s.client)))
                {
                    return Err(Error::StaleGeneration);
                }
                Ok(s.status)
            }
            Origin::Packet(r) => {
                let rr = self.buffer_ref(Buffer(self.handle(r)))?;
                let p = self.store.packets[rr.row]
                    .state
                    .ok_or(Error::StaleGeneration)?;
                if p.attempt != Some(effect.serial) {
                    return Err(Error::StaleGeneration);
                }
                match (p.kind, effect.destination) {
                    (PacketKind::Peer, Destination::Peer(peer)) => {
                        if peer.flow != self.flow(p.flow) || p.bound != Some(peer.serial) {
                            return Err(Error::StaleGeneration);
                        }
                    }
                    (PacketKind::Tun { tun, .. }, Destination::Tun(source)) => {
                        if source.serial != tun || !ptr::eq(source.domain, self.domain) {
                            return Err(Error::StaleGeneration);
                        }
                    }
                    _ => return Err(Error::StaleGeneration),
                }
                Ok(p.status)
            }
        }
    }
    fn set_effect_state(&mut self, effect: Effect<'id>, status: Outcome) -> Result<(), Error> {
        self.effect_state(effect)?;
        match effect.origin {
            Origin::Request(r) => {
                self.store.requests[r.row]
                    .state
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?
                    .status = status
            }
            Origin::Packet(r) => {
                self.store.packets[r.row]
                    .state
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?
                    .status = status
            }
        }
        Ok(())
    }
    fn destination_live(&self, d: Destination<'id>) -> Result<(), Error> {
        match d {
            Destination::Client(c) => {
                self.client_ref(c)?;
            }
            Destination::Tun(t) => {
                self.tun_ref(t, true)?;
            }
            Destination::Peer(p) => {
                self.peer_ref(p)?;
            }
        }
        Ok(())
    }
    /// Preflight actual new queue admission. Local cancellation revokes only new
    /// admissions; already queued immutable original writes may still settle.
    pub fn can_queue(&self, effect: Effect<'id>) -> Result<(), Error> {
        if self.effect_state(effect)? != Outcome::Prepared {
            return Err(Error::Conflict);
        }
        self.destination_live(effect.destination)?;
        match effect.origin {
            Origin::Request(r) => {
                let r = self.store.requests[r.row]
                    .state
                    .ok_or(Error::StaleGeneration)?;
                if r.canceled || r.dead {
                    return Err(Error::Closed);
                }
            }
            Origin::Packet(r) => {
                let p = self.store.packets[r.row]
                    .state
                    .ok_or(Error::StaleGeneration)?;
                let f = self.store.flows[p.flow.row]
                    .state
                    .ok_or(Error::StaleGeneration)?;
                if f.serial != p.flow.serial || f.phase != Phase::Ready {
                    return Err(Error::Closed);
                }
                if f.peer_ended && matches!(effect.destination, Destination::Peer(_)) {
                    return Err(Error::Closed);
                }
                if matches!(effect.destination, Destination::Tun(_)) {
                    self.current_tun()?;
                }
            }
        }
        Ok(())
    }
    /// Original final immutable frame actually admitted by its real native port.
    pub fn queued(&mut self, effect: Effect<'id>) -> Result<(), Error> {
        self.can_queue(effect)?;
        self.set_effect_state(effect, Outcome::Queued)
    }
    /// Real positive write on the original physical destination, never enqueue.
    pub fn exposed(&mut self, effect: Effect<'id>) -> Result<(), Error> {
        let s = self.effect_state(effect)?;
        if !matches!(s, Outcome::Queued | Outcome::Exposed) {
            return Err(Error::StaleGeneration);
        }
        self.destination_live(effect.destination)?;
        self.set_effect_state(effect, Outcome::Exposed)
    }
    fn clear_pending(&mut self, effect: Effect<'id>) -> Result<(), Error> {
        match effect.origin {
            Origin::Request(r) => {
                let request = self.store.requests[r.row]
                    .state
                    .ok_or(Error::StaleGeneration)?;
                if let Some(c) = self
                    .store
                    .clients
                    .get_mut(request.client.row)
                    .and_then(|c| c.state.as_mut())
                    && c.serial == request.client.serial
                    && c.pending == Some(r)
                {
                    c.pending = None
                }
            }
            Origin::Packet(r) => {
                let p = self.store.packets[r.row]
                    .state
                    .ok_or(Error::StaleGeneration)?;
                if let Some(f) = self
                    .store
                    .flows
                    .get_mut(p.flow.row)
                    .and_then(|f| f.state.as_mut())
                    && f.serial == p.flow.serial
                    && f.pending == Some(r)
                {
                    f.pending = None
                }
            }
        }
        Ok(())
    }
    /// Whole original packet/frame actually wrote. TUN short writes must become
    /// real loss/unknown outcome; a partial packet is never a success or replay.
    pub fn written(&mut self, effect: Effect<'id>) -> Result<(), Error> {
        if self.effect_state(effect)? != Outcome::Exposed {
            return Err(Error::StaleGeneration);
        }
        self.destination_live(effect.destination)?;
        self.set_effect_state(effect, Outcome::Written)?;
        self.clear_pending(effect)
    }
    /// Actual port refused before any native queue admission. Reuse retains the
    /// exact immutable original bytes and mints a new attempt id, never a replay
    /// of exposed application data. A canceled waiting future is insufficient.
    pub fn reject_prepared(&mut self, effect: Effect<'id>) -> Result<(), Error> {
        if self.effect_state(effect)? != Outcome::Prepared {
            return Err(Error::WouldBlock);
        }
        let canceled = match effect.origin {
            Origin::Request(r) => self.store.requests[r.row]
                .state
                .is_none_or(|r| r.canceled || r.dead),
            Origin::Packet(r) => {
                let p = self.store.packets[r.row]
                    .state
                    .ok_or(Error::StaleGeneration)?;
                self.store.flows[p.flow.row].state.is_none_or(|f| {
                    f.serial != p.flow.serial
                        || f.phase == Phase::Closing
                        || (f.peer_ended && matches!(p.kind, PacketKind::Peer))
                })
            }
        };
        self.set_effect_state(
            effect,
            if canceled {
                Outcome::Canceled
            } else {
                Outcome::Buffered
            },
        )?;
        self.clear_pending(effect)?;
        match effect.origin {
            Origin::Request(r) => {
                self.store.requests[r.row]
                    .state
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?
                    .attempt = None
            }
            Origin::Packet(r) => {
                self.store.packets[r.row]
                    .state
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?
                    .attempt = None
            }
        }
        Ok(())
    }
    /// Original queued frame actually settled conclusively with zero exposure.
    /// This never calls written; packet-flow failure closes the source before any
    /// following TCP DATA could bypass a missing original start/packet.
    pub fn unsent(&mut self, effect: Effect<'id>, reason: Error) -> Result<(), Error> {
        let s = self.effect_state(effect)?;
        if !matches!(s, Outcome::Queued | Outcome::Prepared) {
            return Err(Error::WouldBlock);
        }
        self.set_effect_state(effect, Outcome::Unsent)?;
        self.clear_pending(effect)?;
        if let Origin::Packet(r) = effect.origin {
            let p = self.store.packets[r.row]
                .state
                .ok_or(Error::StaleGeneration)?;
            self.close_flow(self.flow(p.flow), reason)?;
        }
        Ok(())
    }
    /// Actual semantic processing permission after the complete original raw TUN
    /// packet wrote. This grants no proof that the native CADET ACK itself wrote.
    pub fn receive_done(&mut self, delivery: Delivery<'id>) -> Result<(), Error> {
        let f = self.peer_ref(delivery.peer)?;
        let b = self.buffer_ref(delivery.buffer)?;
        let flow = self.store.flows[f.row]
            .state
            .ok_or(Error::StaleGeneration)?;
        let p = self.store.packets[b.row]
            .state
            .ok_or(Error::StaleGeneration)?;
        if flow.receive != Some((delivery.serial, b)) || p.flow != f || p.status != Outcome::Written
        {
            return Err(Error::NotReady);
        }
        match p.kind {
            PacketKind::Tun {
                delivery: serial,
                credited: false,
                ..
            } if serial == delivery.serial => {}
            _ => return Err(Error::StaleGeneration),
        }
        if let Some(p) = self.store.packets[b.row].state.as_mut()
            && let PacketKind::Tun { credited, .. } = &mut p.kind
        {
            *credited = true
        }
        self.store.flows[f.row]
            .state
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .receive = None;
        Ok(())
    }
    /// The exact original CADET channel has ended. Stop new peer-facing work,
    /// retaining its source only for already received input and original native
    /// receipts. The caller must not admit more input and must eventually call
    /// `peer_lost` after that input drains or its original deadline/cancel wins.
    /// This does not acknowledge reception, close the TUN or grant a new source.
    pub fn peer_ended(&mut self, flow: Flow<'id>) -> Result<(), Error> {
        let r = self.flow_ref(flow)?;
        self.store.flows[r.row]
            .state
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .peer_ended = true;
        for p in &mut *self.store.packets {
            if let Some(p) = p.state.as_mut()
                && p.flow == r
                && matches!(p.kind, PacketKind::Peer)
                && p.status == Outcome::Buffered
            {
                p.status = Outcome::Canceled;
            }
        }
        Ok(())
    }
    /// Revoke only new work; actual original discovery/open/source/packet debt is
    /// retained. No callback cancellation is mistaken for physical quiescence.
    pub fn close_flow(&mut self, flow: Flow<'id>, reason: Error) -> Result<(), Error> {
        let r = self.flow_ref(flow)?;
        let f = self.store.flows[r.row]
            .state
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        f.phase = Phase::Closing;
        if f.failure.is_none() {
            f.failure = Some(reason)
        }
        if let Some(w) = f.discovery.as_mut() {
            w.revoked = true
        }
        if let Some(w) = f.open.as_mut() {
            w.revoked = true
        }
        for p in &mut *self.store.packets {
            if let Some(p) = p.state.as_mut()
                && p.flow == r
                && p.status == Outcome::Buffered
            {
                p.status = Outcome::Canceled
            }
        }
        Ok(())
    }
    /// Actual source requiring native channel close, not a synthetic stop receipt.
    pub fn close_required(&self) -> Option<Peer<'id>> {
        self.store.flows.iter().enumerate().find_map(|(row, f)| {
            f.state
                .filter(|f| f.phase == Phase::Closing && f.source.is_some())
                .and_then(|f| {
                    self.peer(Reference {
                        row,
                        serial: f.serial,
                    })
                    .ok()
                })
        })
    }
    /// Original actual CADET source physically stopped. Already queued TUN writes
    /// stay on their original TUN and may still drain; they are independent debt.
    pub fn peer_lost(&mut self, peer: Peer<'id>, reason: Error) -> Result<PeerLoss<'id>, Error> {
        let r = self.peer_ref(peer)?;
        let old = self.store.flows[r.row]
            .state
            .ok_or(Error::StaleGeneration)?;
        self.close_flow(self.flow(r), reason)?;
        let mut loss = Loss {
            outputs: 0,
            exposed: 0,
            reason,
        };
        for p in &mut *self.store.packets {
            if let Some(p) = p.state.as_mut()
                && p.flow == r
            {
                match &mut p.kind {
                    PacketKind::Peer => {
                        if !p.status.terminal() {
                            loss.outputs += 1;
                            if p.status.exposed() {
                                loss.exposed += 1
                            }
                            p.status = Outcome::Lost {
                                queued: p.status.queued(),
                                exposed: p.status.exposed(),
                                reason,
                            }
                        }
                    }
                    PacketKind::Tun { credited, .. } => *credited = true,
                }
            }
        }
        let f = self.store.flows[r.row]
            .state
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        f.source = None;
        f.pending = None;
        f.receive = None;
        Ok(PeerLoss {
            peer,
            loss,
            delivery: old.receive.map(|(serial, b)| Delivery {
                peer,
                serial,
                buffer: Buffer(self.handle(b)),
            }),
        })
    }
    /// Original raw TUN actually stopped before these logical effects retire.
    /// Already queued peer frames still drain on the original CADET source; OS
    /// route jobs remain separately owed until their actual provider retirement.
    pub fn tun_lost(&mut self, tun: Tun<'id>, reason: Error) -> Result<TunLoss<'id>, Error> {
        let old = self.tun_ref(tun, true)?;
        let t = self.tun.as_mut().ok_or(Error::StaleGeneration)?;
        t.dead = true;
        t.ready = false;
        t.failure = Some(reason);
        if matches!(
            t.routes,
            RouteState::BorrowedVerified | RouteState::BorrowedUnverified
        ) {
            t.routes = RouteState::BorrowedUnverified;
        } else if !t.routes.is_borrowed() && t.routing.is_some_and(|w| w.queued) {
            t.routes = RouteState::Unknown;
        }
        if t.routing_action == RouteAction::Install
            && let Some(w) = t.routing.as_mut()
        {
            w.revoked = true;
        }
        let mut loss = Loss {
            outputs: 0,
            exposed: 0,
            reason,
        };
        for p in &mut *self.store.packets {
            if let Some(p) = p.state.as_mut()
                && matches!(p.kind,PacketKind::Tun{tun:serial,..}if serial==tun.serial)
                && !p.status.terminal()
            {
                loss.outputs += 1;
                if p.status.exposed() {
                    loss.exposed += 1
                }
                p.status = Outcome::Lost {
                    queued: p.status.queued(),
                    exposed: p.status.exposed(),
                    reason,
                }
            }
        }
        for row in 0..self.store.flows.len() {
            if let Some(f) = self.store.flows[row].state {
                self.close_flow(
                    self.flow(Reference {
                        row,
                        serial: f.serial,
                    }),
                    reason,
                )?;
            }
        }
        Ok(TunLoss {
            tun,
            routing: old.routing.map(|w| Routing {
                tun,
                serial: w.serial,
            }),
            loss,
            routes: self.tun.ok_or(Error::StaleGeneration)?.routes,
        })
    }
    /// Release only actual settled output, preserving uncredited live input.
    pub fn release_buffer(&mut self, buffer: Buffer<'id>) -> Result<(), Error> {
        let r = self.buffer_ref(buffer)?;
        let p = self.store.packets[r.row]
            .state
            .ok_or(Error::StaleGeneration)?;
        if !p.status.terminal() {
            return Err(Error::WouldBlock);
        }
        if matches!(
            p.kind,
            PacketKind::Tun {
                credited: false,
                ..
            }
        ) {
            return Err(Error::WouldBlock);
        }
        self.store.packets[r.row].state = None;
        Ok(())
    }
    /// Retire original flow only after all real source/job/packet debt is gone.
    pub fn retire_flow(&mut self, flow: Flow<'id>) -> Result<(), Error> {
        let r = self.flow_ref(flow)?;
        let f = self.store.flows[r.row]
            .state
            .ok_or(Error::StaleGeneration)?;
        if f.phase != Phase::Closing
            || f.source.is_some()
            || f.discovery.is_some()
            || f.open.is_some()
            || f.receive.is_some()
            || self
                .store
                .packets
                .iter()
                .any(|p| p.state.is_some_and(|p| p.flow == r))
        {
            return Err(Error::WouldBlock);
        }
        self.store.flows[r.row].state = None;
        Ok(())
    }
    /// Retire the old TUN tombstone only after its original OS route job and all
    /// independent channels/packets quiesced; permits bounded safe device reuse.
    pub fn retire_tun(&mut self, tun: Tun<'id>) -> Result<(), Error> {
        let t = self.tun_ref(tun, false)?;
        if !t.dead
            || !matches!(t.routes, RouteState::Absent | RouteState::BorrowedReleased)
            || t.routing.is_some()
            || self.store.flows.iter().any(|f| f.state.is_some())
            || self.store.packets.iter().any(|p| p.state.is_some())
        {
            return Err(Error::WouldBlock);
        }
        self.tun = None;
        Ok(())
    }
}
