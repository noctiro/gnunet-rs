//! Room admission over the original app, CADET and PILS owners.
use super::*;

impl<'c> CadetAdmissionTarget<'c> {
    const fn room(self) -> Room<'c> {
        match self {
            Self::Channel { room, .. } | Self::Port { room, .. } => room,
        }
    }

    fn matches(self, route: AdmissionRoute<'c>) -> bool {
        match (self, route) {
            (Self::Port { port, .. }, AdmissionRoute::Open(original)) => {
                original.is_none_or(|original| original == port)
            }
            (Self::Channel { peer, channel, .. }, AdmissionRoute::Entry(route)) => {
                match route.step() {
                    EntryStep::Local => false,
                    EntryStep::Connect(door) => door.peer() == peer,
                    EntryStep::Observe {
                        door,
                        channel: original,
                    } => door.peer() == peer && original == channel,
                }
            }
            _ => false,
        }
    }
}

impl<'c, 'slots, 'p, E: Entropy, const O: usize> Server<'c, 'slots, 'p, E, O> {
    // Other admitted room requests independently keep this exact native owner
    // useful. Expiry of one request cannot revoke a different request's route.
    pub(super) fn cadet_admission_demand(
        &self,
        target: CadetAdmissionTarget<'c>,
        now: Instant,
    ) -> Option<Instant> {
        self.apps
            .iter()
            .flatten()
            .flat_map(|app| &app.rooms)
            .filter(|lease| lease.room == target.room())
            .filter_map(|lease| match lease.phase {
                LeasePhase::Admitting(initial) if target.matches(initial.route) => {
                    Some(initial.until)
                }
                LeasePhase::Active => match target {
                    CadetAdmissionTarget::Port { .. } => lease.pending_open.and_then(|open| {
                        target
                            .matches(AdmissionRoute::Open(open.port))
                            .then_some(open.request.until)
                    }),
                    CadetAdmissionTarget::Channel { .. } => lease.pending_entry.and_then(|entry| {
                        target
                            .matches(AdmissionRoute::Entry(entry.route))
                            .then_some(entry.until)
                    }),
                },
                LeasePhase::Admitting(_) | LeasePhase::Closing => None,
            })
            .filter(|until| *until > now)
            .max()
    }

    pub(super) fn resolve_entry(&mut self, row: usize) -> Result<(EntryInput, EntryTarget), Error> {
        let local = self.current_peer().ok_or(Fault::NotReady)?;
        let request = self.apps[row]
            .as_mut()
            .and_then(|app| app.entry_input.as_mut())
            .ok_or(Fault::Conflict)?;
        let target = *request
            .target
            .get_or_insert_with(|| EntryTarget::resolve(request.door, local));
        Ok((*request, target))
    }
    pub(super) fn admit_open(
        &mut self,
        row: usize,
        index: usize,
        public: Option<wire::PublicKey<'_>>,
        observe: &mut impl FnMut(Event),
    ) -> Result<bool, Error> {
        let app = self.apps[row].as_ref().ok_or(Fault::Stale)?;
        let request = app.open_input.ok_or(Fault::Conflict)?;
        let capabilities = self.core.room_capabilities(app.rooms[index].room)?;
        let refusal = if Instant::now() >= request.until {
            Some(Fault::Deadline)
        } else if public.is_some_and(|p| app.public != Some(*p.as_bytes())) {
            Some(Fault::Conflict)
        } else if !capabilities.allows_open() {
            Some(Fault::Unsupported)
        } else {
            None
        };
        if let Some(reason) = refusal {
            self.fail_open_input(row, reason.into(), observe);
            return Ok(true);
        }
        if app.rooms[index].pending_open.is_some() {
            return Ok(false);
        }
        let room = app.rooms[index].room;
        let room_index = self.room_index(room)?;
        let port = self.rooms[room_index].as_ref().ok_or(Fault::Stale)?.port;
        self.apps[row].as_mut().ok_or(Fault::Stale)?.rooms[index].pending_open =
            Some(PendingOpen { request, port });
        self.rooms[room_index].as_mut().ok_or(Fault::Stale)?.hosting = true;
        Ok(true)
    }
    fn open_step(
        &mut self,
        row: usize,
        index: usize,
        observe: &mut impl FnMut(Event),
    ) -> Result<bool, Error> {
        let lease = &self.apps[row].as_ref().ok_or(Fault::Stale)?.rooms[index];
        let Some(pending) = lease.pending_open else {
            return Ok(false);
        };
        let (room, source, phase) = (lease.room, lease.source, lease.phase);
        let result = (|| -> Result<bool, Error> {
            if !phase.is_active() {
                return Err(Fault::Closed.into());
            }
            if Instant::now() >= pending.request.until {
                return Err(Fault::Deadline.into());
            }
            let route = AdmissionRoute::Open(pending.port);
            let door = match self.step_room_route(room, source, route, pending.request.until)? {
                AdmissionProgress::Waiting => return Ok(false),
                AdmissionProgress::Bound(AdmissionRoute::Open(port)) => {
                    self.apps[row].as_mut().ok_or(Fault::Stale)?.rooms[index]
                        .pending_open
                        .as_mut()
                        .ok_or(Fault::Conflict)?
                        .port = port;
                    return Ok(true);
                }
                AdmissionProgress::Bound(AdmissionRoute::Entry(_)) => {
                    return Err(Fault::Conflict.into());
                }
                AdmissionProgress::Ready(door) => door,
            };
            self.room_reply_at(
                row,
                source,
                room,
                door,
                RoomReply::Open,
                Some(pending.request.until),
            )?;
            self.apps[row].as_mut().ok_or(Fault::Stale)?.rooms[index].pending_open = None;
            self.statistics.opened(false);
            Ok(true)
        })();
        match result {
            Err(error) if busy(&error) => Ok(false),
            Err(error) => {
                self.fail_open(row, index, error, observe);
                Ok(true)
            }
            result => result,
        }
    }
    // Additional doors are independent of the already active membership. One
    // complete input can wait behind one pending entry; neither budget is renewed.
    pub(super) fn admit_entry(
        &mut self,
        row: usize,
        index: usize,
        public: Option<wire::PublicKey<'_>>,
        observe: &mut impl FnMut(Event),
    ) -> Result<bool, Error> {
        let app = self.apps[row].as_ref().ok_or(Fault::Stale)?;
        let request = app.entry_input.ok_or(Fault::Conflict)?;
        let refusal = if Instant::now() >= request.until {
            Some(Fault::Deadline)
        } else if public.is_some_and(|p| app.public != Some(*p.as_bytes())) {
            Some(Fault::Conflict)
        } else {
            None
        };
        if let Some(reason) = refusal {
            self.fail_entry_input(row, reason.into(), observe);
            return Ok(true);
        }
        if app.rooms[index].pending_entry.is_some() {
            return Ok(false);
        }
        let (request, target) = self.resolve_entry(row)?;
        self.apps[row].as_mut().ok_or(Fault::Stale)?.rooms[index].pending_entry =
            Some(PendingEntry {
                key: request.key,
                requested_door: request.door,
                until: request.until,
                route: EntryRoute::new(target),
            });
        Ok(true)
    }
    // A real existing room+door route is shared. A new route is owned in the
    // original bounded tunnel table before any later work or error can return.
    pub(super) fn start_room_channel(
        &mut self,
        room: Room<'c>,
        door: [u8; 32],
        admission: ChannelAdmission,
    ) -> Result<Option<cadet::Channel<'c>>, Error> {
        let (until, automatic) = match admission {
            ChannelAdmission::Entry(until) => (until, None),
            ChannelAdmission::Automatic(until) => (until, Some(until)),
        };
        if Instant::now() >= until {
            return Err(Fault::Deadline.into());
        }
        if let Some(tunnel) = self
            .tunnels
            .iter()
            .flatten()
            .find(|t| t.room == room && t.peer == door && !t.closing && !t.remote_closed)
        {
            return Ok(Some(tunnel.channel));
        }
        if self.cadet.pending_transmit().is_some() {
            return Ok(None);
        }
        let target = self
            .tunnels
            .iter()
            .position(Option::is_none)
            .ok_or(Fault::Capacity)?;
        let key = *self.core.room_key(room)?;
        let port = carrier::port(&key, self.layouts.relay(&door));
        let hard = self.until()?;
        if Instant::now() >= until {
            return Err(Fault::Deadline.into());
        }
        let source = self.core.attach_source(
            room,
            SourceRole::Peer(door),
            padding::Decode::Required,
            None,
        )?;
        let opened = if Instant::now() >= until {
            Err(Fault::Deadline.into())
        } else {
            self.cadet.open(door, port).map_err(Error::from)
        };
        let channel = match opened {
            Ok(channel) => channel,
            Err(original) => {
                self.drain_events();
                if let Err(error) = self.core.source_stopped(source) {
                    self.remember(error.into());
                }
                return Err(original);
            }
        };
        self.tunnels[target] = Some(Tunnel {
            room,
            source,
            channel,
            peer: door,
            handshake: PeerHandshake::default(),
            info_queued: false,
            closing: false,
            remote_closed: false,
            bootstrap: 0,
            until,
        });
        self.track_cadet_admission(
            CadetAdmissionTarget::Channel {
                room,
                peer: door,
                channel,
            },
            hard,
            until,
            automatic,
        )?;
        // room_step queues the original INFO using this same retained tunnel.
        Ok(Some(channel))
    }
    fn entry_step(
        &mut self,
        row: usize,
        index: usize,
        observe: &mut impl FnMut(Event),
    ) -> Result<bool, Error> {
        let lease = &self.apps[row].as_ref().ok_or(Fault::Stale)?.rooms[index];
        let Some(pending) = lease.pending_entry else {
            return Ok(false);
        };
        let (room, source, phase) = (lease.room, lease.source, lease.phase);
        let result = (|| -> Result<bool, Error> {
            if !phase.is_active() {
                return Err(Fault::Closed.into());
            }
            let route = AdmissionRoute::Entry(pending.route);
            let door = match self.step_room_route(room, source, route, pending.until)? {
                AdmissionProgress::Waiting => return Ok(false),
                AdmissionProgress::Bound(AdmissionRoute::Entry(route)) => {
                    self.apps[row].as_mut().ok_or(Fault::Stale)?.rooms[index]
                        .pending_entry
                        .as_mut()
                        .ok_or(Fault::Conflict)?
                        .route = route;
                    return Ok(true);
                }
                AdmissionProgress::Bound(AdmissionRoute::Open(_)) => {
                    return Err(Fault::Conflict.into());
                }
                AdmissionProgress::Ready(door) => door,
            };
            self.room_reply_at(
                row,
                source,
                room,
                door,
                RoomReply::Entry,
                Some(pending.until),
            )?;
            self.apps[row].as_mut().ok_or(Fault::Stale)?.rooms[index].pending_entry = None;
            self.statistics.opened(true);
            Ok(true)
        })();
        match result {
            Err(error) if busy(&error) => Ok(false),
            Err(error) => {
                self.fail_entry(row, index, error, observe);
                Ok(true)
            }
            result => result,
        }
    }

    fn step_room_route(
        &mut self,
        room: Room<'c>,
        source: Source<'c>,
        route: AdmissionRoute<'c>,
        until: Instant,
    ) -> Result<AdmissionProgress<'c>, Error> {
        if Instant::now() >= until {
            return Err(Fault::Deadline.into());
        }
        match route {
            AdmissionRoute::Open(original) => {
                if !self.identity_ready() {
                    return Ok(AdmissionProgress::Waiting);
                }
                let peer = self.current_peer().ok_or(Fault::NotReady)?;
                let Some(port) = self.hosting_port(room, until)? else {
                    return Ok(AdmissionProgress::Waiting);
                };
                match original {
                    None => Ok(AdmissionProgress::Bound(AdmissionRoute::Open(Some(port)))),
                    Some(original) if original != port => Err(Fault::StaleGeneration.into()),
                    Some(_) if self.cadet.port_announced(port)? => {
                        Ok(AdmissionProgress::Ready(peer))
                    }
                    Some(_) => Ok(AdmissionProgress::Waiting),
                }
            }
            AdmissionRoute::Entry(mut route) => match route.step() {
                EntryStep::Local => {
                    if !self.identity_ready() {
                        return Ok(AdmissionProgress::Waiting);
                    }
                    self.core.service_client(source)?;
                    Ok(AdmissionProgress::Ready(
                        self.current_peer().ok_or(Fault::NotReady)?,
                    ))
                }
                EntryStep::Connect(door) => {
                    let Some(channel) =
                        self.start_room_channel(room, door.peer(), ChannelAdmission::Entry(until))?
                    else {
                        return Ok(AdmissionProgress::Waiting);
                    };
                    route.bind(channel)?;
                    Ok(AdmissionProgress::Bound(AdmissionRoute::Entry(route)))
                }
                EntryStep::Observe { door, channel } => {
                    let peer = door.peer();
                    let tunnel = self
                        .tunnels
                        .iter()
                        .flatten()
                        .find(|t| t.channel == channel && t.room == room && t.peer == peer)
                        .ok_or(Fault::Closed)?;
                    if tunnel.closing || tunnel.remote_closed {
                        return Err(Fault::Closed.into());
                    }
                    Ok(if tunnel.handshake.is_ready() {
                        AdmissionProgress::Ready(peer)
                    } else {
                        AdmissionProgress::Waiting
                    })
                }
            },
        }
    }

    pub(super) fn entry_steps(&mut self, observe: &mut impl FnMut(Event)) -> Result<bool, Error> {
        for n in 0..self.apps.len() {
            let row = (self.app_cursor + n) % self.apps.len();
            let (count, cursor) = self.apps[row]
                .as_ref()
                .map_or((0, 0), |app| (app.rooms.len(), app.entry_cursor));
            for n in 0..count {
                let index = (cursor + n) % count;
                if self.open_step(row, index, observe)? || self.entry_step(row, index, observe)? {
                    self.apps[row].as_mut().ok_or(Fault::Stale)?.entry_cursor = (index + 1) % count;
                    self.app_cursor = (row + 1) % self.apps.len();
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
    pub(super) fn leases(&mut self, observe: &mut impl FnMut(Event)) -> Result<bool, Error> {
        for row in 0..self.apps.len() {
            let count = self.apps[row].as_ref().map_or(0, |app| app.rooms.len());
            for index in 0..count {
                let lease = &self.apps[row].as_ref().ok_or(Fault::Stale)?.rooms[index];
                let LeasePhase::Admitting(mut initial) = lease.phase else {
                    continue;
                };
                let (room, source) = (lease.room, lease.source);
                let door = match self.step_room_route(room, source, initial.route, initial.until) {
                    Ok(AdmissionProgress::Waiting) => continue,
                    Ok(AdmissionProgress::Bound(route)) => {
                        initial.route = route;
                        self.apps[row].as_mut().ok_or(Fault::Stale)?.rooms[index].phase =
                            LeasePhase::Admitting(initial);
                        return Ok(true);
                    }
                    Ok(AdmissionProgress::Ready(door)) => door,
                    Err(error) if busy(&error) => continue,
                    Err(Error::Protocol(fault)) => {
                        let cause = if fault == Fault::Deadline {
                            CloseCause::Deadline
                        } else {
                            CloseCause::Fault(fault)
                        };
                        self.close_app(row, cause, observe);
                        return Ok(true);
                    }
                    Err(Error::Core(error)) => {
                        self.close_app(row, CloseCause::Core(error), observe);
                        return Ok(true);
                    }
                    Err(error) => return Err(error),
                };
                if matches!(initial.next, InitialNotice::MemberId) {
                    let (_, id) = self.core.service_client(source)?;
                    let key = *self.core.room_key(room)?;
                    self.notice_before(
                        row,
                        Response::MemberId {
                            key: &key,
                            id: &id,
                            reset: 0,
                        },
                        WrittenAction::None,
                        Some(initial.until),
                    )?;
                    initial.next = InitialNotice::Room;
                    self.apps[row].as_mut().ok_or(Fault::Stale)?.rooms[index].phase =
                        LeasePhase::Admitting(initial);
                    return Ok(true);
                }
                let (reply, enter) = match initial.route {
                    AdmissionRoute::Open(_) => (RoomReply::Open, false),
                    AdmissionRoute::Entry(_) => (RoomReply::Entry, true),
                };
                self.room_reply_at(row, source, room, door, reply, Some(initial.until))?;
                let lease = &mut self.apps[row].as_mut().ok_or(Fault::Stale)?.rooms[index];
                lease.phase = LeasePhase::Active;
                lease.counted = true;
                self.statistics.opened(enter);
                return Ok(true);
            }
        }
        Ok(false)
    }
}
