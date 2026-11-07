use super::*;
impl<'c, 'slots, 'p, E: Entropy, const O: usize> Server<'c, 'slots, 'p, E, O> {
    /// Apply actual SERVICE ACL/Unix credentials before adopting original app IO.
    pub fn admit(
        &mut self,
        accepted: AcceptedConnection,
        observe: &mut impl FnMut(Event),
    ) -> Result<Option<Client>, Error> {
        let (connection, address, diagnostics) = accepted.into_parts();
        for d in diagnostics {
            observe(Event::Socket(SocketEvent::Diagnostic(d)))
        }
        let allowed = match address {
            PeerAddress::Tcp(a) => self.ports.options.access.allows(a.ip()),
            PeerAddress::Unix => self.ports.unix.allows(&connection)?,
        };
        if !allowed {
            drop(connection);
            observe(Event::Rejected(address));
            return Ok(None);
        }
        if self.shutdown.is_some() {
            drop(connection);
            return Err(Fault::Closed.into());
        }
        let row = self
            .apps
            .iter()
            .position(Option::is_none)
            .ok_or(Fault::Capacity)?;
        let serial = self.next_client.checked_add(1).ok_or(Fault::Overflow)?;
        let io = Framed::new(connection, self.limits.framing())?;
        let mut rooms = Vec::new();
        rooms
            .try_reserve_exact(self.limits.client_rooms)
            .map_err(|_| Fault::Capacity)?;
        let mut controls = VecDeque::new();
        controls
            .try_reserve_exact(self.limits.controls)
            .map_err(|_| Fault::Capacity)?;
        let client = Client {
            domain: self.domain.clone(),
            serial,
        };
        self.apps[row] = Some(App {
            client: client.clone(),
            io,
            has_request: false,
            public: None,
            rooms,
            controls,
            output: None,
            until: Instant::now() + self.limits.input_lifetime,
            input_until: None,
            entry_input: None,
            open_input: None,
            entry_cursor: 0,
            read_first: true,
        });
        self.next_client = serial;
        self.report.accepted = self.report.accepted.saturating_add(1);
        observe(Event::Accepted(client.clone()));
        Ok(Some(client))
    }
    pub(super) fn ensure_room(&mut self, key: Hash) -> Result<usize, Error> {
        if let Some(row) = self
            .rooms
            .iter()
            .position(|r| r.as_ref().is_some_and(|r| r.key == key))
        {
            if self.rooms[row].as_ref().is_some_and(|r| r.closing) {
                return Err(Fault::NotReady.into());
            }
            return Ok(row);
        }
        if !self.identity_ready() {
            return Err(Fault::WouldBlock.into());
        }
        let local = self.current_peer().ok_or(Fault::NotReady)?;
        let row = self
            .rooms
            .iter()
            .position(Option::is_none)
            .ok_or(Fault::Capacity)?;
        let prior = self
            .core
            .retained_rooms()
            .find(|room| self.core.room_key(*room).is_ok_and(|k| *k == key));
        let room = match prior {
            Some(room) => room,
            None => self
                .core
                .room_profiled(key, None, self.layouts.room(&key))?,
        };
        let count = self.core.retained_messages(room)?.count();
        if count > self.messages.iter().filter(|m| m.is_none()).count() {
            return Err(Fault::Capacity.into());
        }
        let signer = match self.core.attach_source(
            room,
            SourceRole::ServiceSigner(local),
            padding::Decode::Absent,
            None,
        ) {
            Ok(s) => s,
            Err(e) => {
                if prior.is_none()
                    && let Err(error) = self.core.forget_room(room)
                {
                    self.remember(error.into());
                }
                return Err(e.into());
            }
        };
        let mut historical = Vec::new();
        historical
            .try_reserve_exact(count)
            .map_err(|_| Fault::Capacity)?;
        historical.extend(self.core.retained_messages(room)?.map(|m| *m.hash()));
        for hash in historical {
            let i = self
                .messages
                .iter()
                .position(Option::is_none)
                .ok_or(Fault::Capacity)?;
            self.messages[i] = Some(MessageWork {
                room,
                hash,
                exclude: None,
                recent: false,
                fanned: true,
            });
        }
        self.rooms[row] = Some(RoomEntry {
            room,
            key,
            signer,
            port: None,
            hosting: false,
            closing: false,
            connections: None,
            announcement: None,
        });
        Ok(row)
    }
    pub(super) fn bind_app(
        &mut self,
        row: usize,
        key: Hash,
        public: Option<wire::PublicKey<'_>>,
        door: [u8; 32],
        enter: bool,
    ) -> Result<(), Error> {
        let (r, prior_public) = {
            let a = self.apps[row].as_ref().ok_or(Fault::Stale)?;
            (
                a.rooms.iter().position(|l| {
                    self.rooms
                        .iter()
                        .flatten()
                        .any(|r| r.room == l.room && r.key == key)
                }),
                a.public,
            )
        };
        if r.is_some() {
            return Err(Fault::WouldBlock.into());
        }
        {
            let a = self.apps[row].as_ref().ok_or(Fault::Stale)?;
            if a.rooms.len() == self.limits.client_rooms
                || a.controls.len() + 2 > self.limits.controls
            {
                return Err(Fault::Capacity.into());
            }
        }
        let public = match (prior_public, public) {
            (Some(p), Some(other)) if p != *other.as_bytes() => return Err(Fault::Conflict.into()),
            (Some(p), _) => p,
            (None, Some(p)) => *p.as_bytes(),
            (None, None) => *self.core.service_anonymous_public()?,
        };
        let target = if enter {
            let request = self.apps[row]
                .as_ref()
                .and_then(|app| app.entry_input)
                .ok_or(Fault::Conflict)?;
            let target = match request.target {
                Some(target) => target,
                None => {
                    let target = self.resolve_entry(door)?;
                    self.apps[row]
                        .as_mut()
                        .ok_or(Fault::Stale)?
                        .entry_input
                        .as_mut()
                        .ok_or(Fault::Conflict)?
                        .target = Some(target);
                    target
                }
            };
            Some(target)
        } else {
            None
        };
        let local = self.current_peer().ok_or(Fault::NotReady)?;
        let resolved_door = match target {
            Some(target) => target.door(local),
            None => local,
        };
        let room_index = self.ensure_room(key)?;
        let room = self.rooms[room_index].as_ref().ok_or(Fault::Stale)?.room;
        let (_, group, feed) = self.core.room_flags(room)?;
        // Personal private feeds may be joined with ENTRY. Only an OPEN
        // attempts to host a listening port and is forbidden for this room kind.
        if !enter && feed && !group {
            return Err(Fault::Unsupported.into());
        }
        let source = self.core.attach_source(
            room,
            SourceRole::Client,
            padding::Decode::Absent,
            Some(public),
        )?;
        let mut selected = self.core.historical_member_id(room, &public)?;
        if public != *self.core.service_anonymous_public()? {
            for (member, _, id, phase) in self.core.members(room)? {
                if phase == core::SessionPhase::Active
                    && self.core.member_public(member)? == &public
                {
                    selected = Some(id);
                    break;
                }
            }
        }
        let result = (|| -> Result<(), Error> {
            if let Some(id) = selected {
                self.core.bind_service_client(source, public, id)?;
            } else {
                let mut bound = false;
                for _ in 0..32 {
                    let mut id = [0; 32];
                    self.entropy.fill(&mut id)?;
                    match self.core.bind_service_client(source, public, id) {
                        Ok(()) => {
                            bound = true;
                            break;
                        }
                        Err(core::Error::Protocol(Fault::Conflict)) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                if !bound {
                    return Err(Fault::Capacity.into());
                }
            }
            let until = if enter {
                self.apps[row]
                    .as_ref()
                    .and_then(|app| app.entry_input)
                    .ok_or(Fault::Conflict)?
                    .until
            } else {
                self.apps[row]
                    .as_ref()
                    .and_then(|app| app.open_input)
                    .ok_or(Fault::Conflict)?
                    .until
            };
            if Instant::now() >= until {
                return Err(Fault::Deadline.into());
            }
            let app = self.apps[row].as_mut().ok_or(Fault::Stale)?;
            app.public = Some(public);
            app.rooms.push(Lease {
                room,
                source,
                phase: if enter {
                    LeasePhase::Entering
                } else {
                    LeasePhase::Opening
                },
                door: resolved_door,
                entry_local: matches!(target, Some(EntryTarget::Local)),
                entry: None,
                pending_entry: None,
                pending_open: None,
                id_written: false,
                counted: false,
                bootstrap: 0,
                proposed_id: None,
                proposal_until: None,
                sync_until: None,
                until,
            });
            if !enter {
                self.rooms[room_index].as_mut().ok_or(Fault::Stale)?.hosting = true;
            }
            Ok(())
        })();
        if result.is_err()
            && let Err(error) = self.core.release_service_client(source)
        {
            self.remember(error.into());
        }
        result
    }
    pub(super) fn room_reply(&mut self, row: usize, index: usize, kind: u8) -> Result<(), Error> {
        let (room, source, door, entry_local) = {
            let l = self.apps[row]
                .as_ref()
                .ok_or(Fault::Stale)?
                .rooms
                .get(index)
                .ok_or(Fault::Stale)?;
            (l.room, l.source, l.door, l.entry_local)
        };
        // Only ENTRY reports its selected door. OPEN/CLOSE/SYNC identify this
        // service, independently of the remote door used to enter the room.
        let door = if kind == 2 && !entry_local {
            door
        } else {
            if !self.identity_ready() {
                return Err(Fault::WouldBlock.into());
            }
            self.current_peer().ok_or(Fault::NotReady)?
        };
        self.room_reply_at(row, source, room, door, kind, None)
    }
    fn room_reply_at(
        &mut self,
        row: usize,
        source: Source<'c>,
        room: Room<'c>,
        door: [u8; 32],
        kind: u8,
        until: Option<Instant>,
    ) -> Result<(), Error> {
        let (key, previous, epoch, door) = self.room_fields(room, &door)?;
        let fields = wire::Room {
            door: &door,
            key: &key,
            previous: &previous,
            epoch: &epoch,
        };
        let response = match kind {
            1 => Response::Open(fields),
            2 => Response::Entry(fields),
            3 => Response::Close(fields),
            _ => Response::Sync(fields),
        };
        self.notice_before(
            row,
            response,
            if kind == 3 {
                WrittenAction::Detach(source)
            } else {
                WrittenAction::None
            },
            until,
        )?;
        Ok(())
    }
    pub(super) fn app_room(&self, row: usize, key: &Hash) -> Result<usize, Fault> {
        self.apps[row]
            .as_ref()
            .ok_or(Fault::Stale)?
            .rooms
            .iter()
            .position(|l| {
                self.rooms
                    .iter()
                    .flatten()
                    .any(|r| r.room == l.room && r.key == *key)
            })
            .ok_or(Fault::NotFound)
    }
    pub(super) fn get(&mut self, row: usize, lease: usize, hash: Hash) -> Result<(), Error> {
        let l = &self.apps[row].as_ref().ok_or(Fault::Stale)?.rooms[lease];
        let (room, source, client) = (
            l.room,
            l.source,
            self.apps[row].as_ref().ok_or(Fault::Stale)?.client.serial,
        );
        let (public, id) = self.core.service_client(source)?;
        let member = self.core.members(room)?.any(|(member, _, other, phase)| {
            other == id
                && phase != core::SessionPhase::Completed
                && self.core.member_public(member).is_ok_and(|p| *p == public)
        });
        if !member {
            return Ok(());
        }
        if self.core.message(room, &hash).is_err() {
            let key = *self.core.room_key(room)?;
            return self.notice(
                row,
                Response::Missing {
                    key: &key,
                    hash: &hash,
                },
                WrittenAction::None,
            );
        }
        let mut stack = Vec::new();
        let mut seen = Vec::new();
        let mut hashes = Vec::new();
        for v in [&mut stack, &mut seen, &mut hashes] {
            v.try_reserve(self.limits.deliveries.min(16))
                .map_err(|_| Fault::Capacity)?;
        }
        stack.push(hash);
        while let Some(hash) = stack.pop() {
            if seen.contains(&hash) {
                continue;
            }
            if seen.len() == self.limits.deliveries {
                return Err(Fault::Capacity.into());
            }
            seen.try_reserve(1).map_err(|_| Fault::Capacity)?;
            seen.push(hash);
            let msg = self.core.message(room, &hash)?;
            if msg.phase() == core::MessagePhase::Deleted {
                for parent in msg.parents() {
                    if *parent != [0; 64] && !seen.contains(parent) && !stack.contains(parent) {
                        if stack.len() == self.limits.deliveries {
                            return Err(Fault::Capacity.into());
                        }
                        stack.try_reserve(1).map_err(|_| Fault::Capacity)?;
                        stack.push(*parent)
                    }
                }
                continue;
            }
            self.core.service_attribution(room, &hash)?;
            if !self.core.service_may_read(source, &hash)? {
                continue;
            }
            if msg.original().is_some() {
                hashes.try_reserve(1).map_err(|_| Fault::Capacity)?;
                hashes.push(hash);
            }
        }
        let mut recipients = Vec::new();
        recipients
            .try_reserve_exact(self.limits.clients)
            .map_err(|_| Fault::Capacity)?;
        if self.limits.local_request {
            for app in self.apps.iter().flatten() {
                for lease in &app.rooms {
                    if lease.room == room && lease.phase != LeasePhase::Closing {
                        recipients.push(Destination::App {
                            client: app.client.serial,
                            source: lease.source,
                        })
                    }
                }
            }
        } else {
            recipients.push(Destination::App { client, source })
        }
        let maximum = hashes
            .len()
            .checked_mul(recipients.len())
            .ok_or(Fault::Overflow)?;
        if maximum > self.tasks.iter().filter(|t| t.is_none()).count() {
            return Err(Fault::Capacity.into());
        }
        for hash in hashes {
            for destination in &recipients {
                self.add_task(room, hash, *destination, false, true)?;
            }
        }
        Ok(())
    }
    pub(super) fn process_app(
        &mut self,
        row: usize,
        observe: &mut impl FnMut(Event),
    ) -> Result<bool, Error> {
        // Copy a complete immutable input before mutating ownership. It is bounded
        // to one original app frame; cancellation never loses its native read cursor.
        let input = OwnedBytes::copy_from(
            self.apps[row]
                .as_ref()
                .ok_or(Fault::Stale)?
                .io
                .frame()
                .ok_or(Fault::NotReady)?,
        )?;
        let request = Request::decode(input.expose())?;
        // The socket already passed SERVICE admission. Official reconnects
        // may start directly with OPEN/ENTRY; CREATE is only an idempotent
        // control message. All request-specific checks below still apply.
        self.apps[row].as_mut().ok_or(Fault::Stale)?.has_request = true;
        match request {
            Request::Create => {}
            Request::Destroy => {
                self.close_app(row, CloseCause::Shutdown, observe);
                return Ok(true);
            }
            Request::Open { room, public_key } | Request::Entry { room, public_key } => {
                let enter = matches!(request, Request::Entry { .. });
                if enter
                    && self.apps[row]
                        .as_ref()
                        .ok_or(Fault::Stale)?
                        .entry_input
                        .is_none()
                {
                    let until = self.apps[row]
                        .as_ref()
                        .and_then(|app| app.input_until)
                        .ok_or(Fault::Conflict)?;
                    let target = self.current_peer().map(|local| {
                        if *room.door == [0; 32] || *room.door == local {
                            EntryTarget::Local
                        } else {
                            EntryTarget::Remote(*room.door)
                        }
                    });
                    self.apps[row].as_mut().ok_or(Fault::Stale)?.entry_input = Some(EntryInput {
                        key: *room.key,
                        door: *room.door,
                        target,
                        until,
                    });
                }
                if !enter
                    && self.apps[row]
                        .as_ref()
                        .ok_or(Fault::Stale)?
                        .open_input
                        .is_none()
                {
                    let until = self.apps[row]
                        .as_ref()
                        .and_then(|app| app.input_until)
                        .ok_or(Fault::Conflict)?;
                    self.apps[row].as_mut().ok_or(Fault::Stale)?.open_input = Some(OpenInput {
                        key: *room.key,
                        until,
                    });
                }
                if self.shutdown.is_some() {
                    return Err(Fault::Closed.into());
                }
                if !self.identity_ready() {
                    return Ok(false);
                }
                let active = self.app_room(row, room.key).ok().filter(|index| {
                    self.apps[row]
                        .as_ref()
                        .is_some_and(|app| app.rooms[*index].phase == LeasePhase::Active)
                });
                if let Some(index) = active {
                    let admitted = if enter {
                        self.admit_entry(row, index, public_key, observe)?
                    } else {
                        self.admit_open(row, index, public_key, observe)?
                    };
                    if !admitted {
                        return Ok(false);
                    }
                } else {
                    self.bind_app(row, *room.key, public_key, *room.door, enter)?;
                }
            }
            Request::Close { room } => {
                let index = self.app_room(row, room.key)?;
                if self.apps[row].as_ref().ok_or(Fault::Stale)?.rooms[index].phase
                    == LeasePhase::Closing
                {
                    return Err(Fault::Replay.into());
                }
                self.room_reply(row, index, 3)?;
                self.apps[row].as_mut().ok_or(Fault::Stale)?.rooms[index].phase =
                    LeasePhase::Closing;
            }
            Request::Sync { room } => {
                let index = self.app_room(row, room.key)?;
                let until = self.until()?;
                let l = &mut self.apps[row].as_mut().ok_or(Fault::Stale)?.rooms[index];
                if l.sync_until.is_some() {
                    return Err(Fault::WouldBlock.into());
                }
                l.sync_until = Some(until);
            }
            Request::Get { key, hash } => {
                let index = self.app_room(row, key)?;
                self.get(row, index, *hash)?;
            }
            Request::Send { key, message } => {
                let index = self.app_room(row, key)?;
                let app = self.apps[row].as_ref().ok_or(Fault::Stale)?;
                let l = &app.rooms[index];
                if l.phase != LeasePhase::Active {
                    return Err(Fault::NotReady.into());
                }
                let (room, source) = (l.room, l.source);
                let layout = self
                    .layouts
                    .application(&self.core, source, message.expose())?;
                let header = wire::envelope::Envelope::decode(message.expose())?.header()?;
                let parsed = wire::message::Message::decode_with_profiles(
                    message.expose(),
                    layout.body_profile(header.kind)?,
                    layout.padding,
                    padding::Decode::Absent,
                )?;
                let kind = parsed.header().kind;
                if !kind.is_known()
                    || matches!(
                        kind,
                        Kind::INFO | Kind::PEER | Kind::MISS | Kind::MERGE | Kind::CONNECTION
                    )
                {
                    return Err(Fault::PermissionDenied.into());
                }
                if kind == Kind::GROUP && !self.limits.group_keys {
                    self.apps[row]
                        .as_mut()
                        .ok_or(Fault::Stale)?
                        .io
                        .release_frame();
                    return Ok(true);
                }
                if parsed.hash_input().len() + 68 + 3 > carrier::MAX_RAW {
                    return Err(Fault::TooLarge.into());
                }
                let hash = core::crypto::signature::message_hash(parsed);
                let known = self.core.service_attribution(room, &hash).is_ok();
                if !known && self.messages.iter().all(Option::is_some) {
                    return Err(Fault::Capacity.into());
                }
                let data = OwnedBytes::copy_from(message.expose())?;
                self.core
                    .receive_profiled(
                        source,
                        ReceiveMeta {
                            epoch: self.core.service_state(room)?.epoch,
                            flags: 0,
                            requested: false,
                            sender_hash: None,
                            context: None,
                        },
                        layout,
                        data,
                    )
                    .map_err(|r| Error::Core(r.error))?;
                self.core.advance(room, self.last_now)?;
                if matches!(parsed.body(), Body::Key { .. }) {
                    let (updated, _) = self.core.service_client(source)?;
                    self.apps[row].as_mut().ok_or(Fault::Stale)?.public = Some(updated);
                }
                if !known {
                    self.track(room, hash, None, true)?;
                }
                self.report.received = self.report.received.saturating_add(1);
                observe(Event::Received {
                    peer: false,
                    authenticated: self.core.service_attribution(room, &hash).is_ok(),
                });
            }
        }
        if let Some(app) = self.apps[row].as_mut() {
            app.io.release_frame();
            app.input_until = None;
            app.entry_input = None;
            app.open_input = None;
        }
        Ok(true)
    }
    fn resolve_entry(&self, raw: [u8; 32]) -> Result<EntryTarget, Error> {
        let local = self.current_peer().ok_or(Fault::NotReady)?;
        Ok(if raw == [0; 32] || raw == local {
            EntryTarget::Local
        } else {
            EntryTarget::Remote(raw)
        })
    }
    fn admit_open(
        &mut self,
        row: usize,
        index: usize,
        public: Option<wire::PublicKey<'_>>,
        observe: &mut impl FnMut(Event),
    ) -> Result<bool, Error> {
        let app = self.apps[row].as_ref().ok_or(Fault::Stale)?;
        let request = app.open_input.ok_or(Fault::Conflict)?;
        let (_, group, feed) = self.core.room_flags(app.rooms[index].room)?;
        let refusal = if Instant::now() >= request.until {
            Some(Fault::Deadline)
        } else if public.is_some_and(|p| app.public != Some(*p.as_bytes())) {
            Some(Fault::Conflict)
        } else if feed && !group {
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
            if phase != LeasePhase::Active {
                return Err(Fault::Closed.into());
            }
            if Instant::now() >= pending.request.until {
                return Err(Fault::Deadline.into());
            }
            if !self.identity_ready() {
                return Ok(false);
            }
            let door = self.current_peer().ok_or(Fault::NotReady)?;
            let Some(port) = self.hosting_port(room, pending.request.until)? else {
                return Ok(false);
            };
            if let Some(original) = pending.port {
                if port != original {
                    return Err(Fault::StaleGeneration.into());
                }
            } else {
                self.apps[row].as_mut().ok_or(Fault::Stale)?.rooms[index]
                    .pending_open
                    .as_mut()
                    .ok_or(Fault::Conflict)?
                    .port = Some(port);
                return Ok(true);
            }
            if !self.cadet.port_announced(port)? {
                return Ok(false);
            }
            self.room_reply_at(row, source, room, door, 1, Some(pending.request.until))?;
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
    fn admit_entry(
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
        let target = match request.target {
            Some(target) => target,
            None => {
                let target = self.resolve_entry(request.door)?;
                self.apps[row]
                    .as_mut()
                    .ok_or(Fault::Stale)?
                    .entry_input
                    .as_mut()
                    .ok_or(Fault::Conflict)?
                    .target = Some(target);
                target
            }
        };
        self.apps[row].as_mut().ok_or(Fault::Stale)?.rooms[index].pending_entry =
            Some(PendingEntry {
                request,
                target,
                source: None,
            });
        Ok(true)
    }
    // A real existing room+door route is shared. A new route is owned in the
    // original bounded tunnel table before any later work or error can return.
    fn start_entry(
        &mut self,
        room: Room<'c>,
        door: [u8; 32],
        until: Instant,
    ) -> Result<Option<Source<'c>>, Error> {
        if Instant::now() >= until {
            return Err(Fault::Deadline.into());
        }
        if let Some(tunnel) = self
            .tunnels
            .iter()
            .flatten()
            .find(|t| t.room == room && t.peer == door && !t.closing && !t.remote_closed)
        {
            return Ok(Some(tunnel.source));
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
            compatible: false,
            info_queued: false,
            closing: false,
            remote_closed: false,
            bootstrap: 0,
            until,
        });
        // room_step queues the original INFO using this same retained tunnel.
        Ok(Some(source))
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
            if phase != LeasePhase::Active {
                return Err(Fault::Closed.into());
            }
            if Instant::now() >= pending.request.until {
                return Err(Fault::Deadline.into());
            }
            if let EntryTarget::Local = pending.target {
                if !self.identity_ready() {
                    return Ok(false);
                }
                let peer = self.current_peer().ok_or(Fault::NotReady)?;
                let _assignment = self.core.service_client(source)?;
                self.room_reply_at(row, source, room, peer, 2, Some(pending.request.until))?;
                self.apps[row].as_mut().ok_or(Fault::Stale)?.rooms[index].pending_entry = None;
                self.statistics.opened(true);
                return Ok(true);
            }
            let EntryTarget::Remote(resolved) = pending.target else {
                return Err(Fault::Conflict.into());
            };
            let Some(target) = pending.source else {
                let Some(target) = self.start_entry(room, resolved, pending.request.until)? else {
                    return Ok(false);
                };
                self.apps[row].as_mut().ok_or(Fault::Stale)?.rooms[index]
                    .pending_entry
                    .as_mut()
                    .ok_or(Fault::Conflict)?
                    .source = Some(target);
                return Ok(true);
            };
            let tunnel = self
                .tunnels
                .iter()
                .flatten()
                .find(|t| t.source == target && t.room == room && t.peer == resolved)
                .ok_or(Fault::Closed)?;
            if tunnel.closing || tunnel.remote_closed {
                return Err(Fault::Closed.into());
            }
            if !tunnel.compatible {
                return Ok(false);
            }
            self.room_reply_at(row, source, room, resolved, 2, Some(pending.request.until))?;
            self.apps[row].as_mut().ok_or(Fault::Stale)?.rooms[index].pending_entry = None;
            self.statistics.opened(true);
            Ok(true)
        })();
        match result {
            // Backpressure keeps the exact request and original deadline.
            Err(error) if busy(&error) => Ok(false),
            Err(error) => {
                self.fail_entry(row, index, error, observe);
                Ok(true)
            }
            result => result,
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
    pub(super) fn leases(&mut self) -> Result<bool, Error> {
        for row in 0..self.apps.len() {
            let n = self.apps[row].as_ref().map_or(0, |a| a.rooms.len());
            for index in 0..n {
                let (room, phase, door, local_entry, entry, id_written, until) = {
                    let l = &self.apps[row].as_ref().ok_or(Fault::Stale)?.rooms[index];
                    (
                        l.room,
                        l.phase,
                        l.door,
                        l.entry_local,
                        l.entry,
                        l.id_written,
                        l.until,
                    )
                };
                if !matches!(phase, LeasePhase::Opening | LeasePhase::Entering) {
                    continue;
                }
                let door = if phase == LeasePhase::Opening || local_entry {
                    if !self.identity_ready() {
                        continue;
                    }
                    self.current_peer().ok_or(Fault::NotReady)?
                } else {
                    door
                };
                let ready = if phase == LeasePhase::Opening {
                    match self.hosting_port(room, until)? {
                        Some(port) => self.cadet.port_announced(port)?,
                        None => false,
                    }
                } else if local_entry {
                    let source = self.apps[row].as_ref().ok_or(Fault::Stale)?.rooms[index].source;
                    let _assignment = self.core.service_client(source)?;
                    true
                } else {
                    if let Some(source) = entry {
                        self.tunnels.iter().flatten().any(|t| {
                            t.source == source
                                && t.room == room
                                && t.peer == door
                                && t.compatible
                                && !t.closing
                                && !t.remote_closed
                        })
                    } else {
                        let until = self.apps[row].as_ref().ok_or(Fault::Stale)?.rooms[index].until;
                        if let Some(source) = self.start_entry(room, door, until)? {
                            self.apps[row].as_mut().ok_or(Fault::Stale)?.rooms[index].entry =
                                Some(source);
                            return Ok(true);
                        }
                        false
                    }
                };
                if !ready {
                    continue;
                }
                if !id_written {
                    let source = self.apps[row].as_ref().ok_or(Fault::Stale)?.rooms[index].source;
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
                        Some(until),
                    )?;
                    self.apps[row].as_mut().ok_or(Fault::Stale)?.rooms[index].id_written = true;
                    return Ok(true);
                }
                let source = self.apps[row].as_ref().ok_or(Fault::Stale)?.rooms[index].source;
                self.room_reply_at(
                    row,
                    source,
                    room,
                    door,
                    if phase == LeasePhase::Opening { 1 } else { 2 },
                    Some(until),
                )?;
                self.apps[row].as_mut().ok_or(Fault::Stale)?.rooms[index].phase =
                    LeasePhase::Active;
                self.apps[row].as_mut().ok_or(Fault::Stale)?.rooms[index].counted = true;
                self.statistics.opened(phase == LeasePhase::Entering);
                return Ok(true);
            }
        }
        Ok(false)
    }
    pub(super) fn app_output(
        &mut self,
        row: usize,
        observe: &mut impl FnMut(Event),
    ) -> Result<bool, Error> {
        if !self.history_ready() {
            return Ok(false);
        }
        let app = self.apps[row].as_ref().ok_or(Fault::Stale)?;
        if app.output.is_some() {
            return Ok(false);
        }
        if let Some(notice) = self.apps[row]
            .as_mut()
            .ok_or(Fault::Stale)?
            .controls
            .pop_front()
        {
            let sequence = self.sequence()?;
            let until = self.until()?;
            let total = notice.frame.len();
            let app = self.apps[row].as_mut().ok_or(Fault::Stale)?;
            app.io.reserve(total, Class::Ordinary)?;
            app.io
                .enqueue_owned(
                    notice.frame,
                    Origin {
                        client: app.client.serial,
                        sequence,
                    },
                    Class::Ordinary,
                )
                .map_err(|r| r.reason)?;
            app.output = Some(Output {
                sequence,
                total,
                sent: 0,
                until,
                action: notice.action,
                task: None,
            });
            observe(Event::Queued {
                sequence,
                peer: false,
            });
            return Ok(true);
        }
        self.queue_app_task(row, observe)
    }
    pub(super) fn app_write(
        &mut self,
        cx: &mut Context<'_>,
        row: usize,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        let p = match self.apps[row]
            .as_mut()
            .ok_or(Fault::Stale)?
            .io
            .poll_write(cx)
        {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => {
                self.close_app(row, CloseCause::Io(e), observe);
                return Poll::Ready(Ok(Progress::Activity));
            }
            Poll::Ready(Ok(p)) => p,
        };
        let app = self.apps[row].as_mut().ok_or(Fault::Stale)?;
        let out = app.output.as_mut().ok_or(Fault::Conflict)?;
        if p.origin.client != app.client.serial || p.origin.sequence != out.sequence {
            return Poll::Ready(Err(Fault::StaleGeneration.into()));
        }
        out.sent = out
            .sent
            .checked_add(p.bytes)
            .filter(|n| *n <= out.total)
            .ok_or(Fault::Overflow)?;
        if p.complete != (out.sent == out.total) {
            return Poll::Ready(Err(Fault::Conflict.into()));
        }
        if p.complete {
            let out = app.output.take().ok_or(Fault::Conflict)?;
            if let Some(task) = out.task {
                self.finish_task(task)
            }
            if let WrittenAction::Detach(source) = out.action {
                self.core.release_service_client(source)?;
                if self.apps[row]
                    .as_ref()
                    .ok_or(Fault::Stale)?
                    .rooms
                    .iter()
                    .any(|l| l.source == source && l.counted)
                {
                    self.statistics.closed_room();
                }
                self.apps[row]
                    .as_mut()
                    .ok_or(Fault::Stale)?
                    .rooms
                    .retain(|l| l.source != source);
            }
            self.report.written = self.report.written.saturating_add(1);
            observe(Event::Written {
                sequence: out.sequence,
                peer: false,
            });
        }
        Poll::Ready(Ok(Progress::Activity))
    }
    pub(super) fn app_poll(
        &mut self,
        cx: &mut Context<'_>,
        row: usize,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        if self.history_frozen() {
            if self.apps[row].as_ref().is_some_and(|a| a.output.is_some()) {
                return self.app_write(cx, row, observe);
            }
            if self.apps[row]
                .as_ref()
                .is_some_and(|a| a.io.frame().is_some())
            {
                return Poll::Pending;
            }
            return match self.apps[row]
                .as_mut()
                .ok_or(Fault::Stale)?
                .io
                .poll_read(cx)
            {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(e)) => {
                    self.close_app(row, CloseCause::Io(e), observe);
                    Poll::Ready(Ok(Progress::Activity))
                }
                Poll::Ready(Ok(ReadStep::Eof)) => {
                    self.close_app(row, CloseCause::Eof, observe);
                    Poll::Ready(Ok(Progress::Activity))
                }
                Poll::Ready(Ok(ReadStep::Progress { .. })) => {
                    let app = self.apps[row].as_mut().ok_or(Fault::Stale)?;
                    if app.input_until.is_none() {
                        app.input_until = Some(Instant::now() + self.limits.input_lifetime)
                    }
                    Poll::Ready(Ok(Progress::Activity))
                }
            };
        }
        if self.app_output(row, observe)? {
            return Poll::Ready(Ok(Progress::Activity));
        }
        let read_first = self.apps[row].as_ref().ok_or(Fault::Stale)?.read_first;
        for first in 0..2 {
            let read = (first == 0) == read_first;
            if !read {
                if self.apps[row]
                    .as_ref()
                    .ok_or(Fault::Stale)?
                    .output
                    .is_some()
                {
                    let p = self.app_write(cx, row, observe);
                    if p.is_ready() {
                        if let Some(a) = self.apps[row].as_mut() {
                            a.read_first = true
                        }
                        return p;
                    }
                }
                continue;
            }
            if self.apps[row]
                .as_ref()
                .ok_or(Fault::Stale)?
                .io
                .frame()
                .is_some()
            {
                match self.process_app(row, observe) {
                    Ok(true) => return Poll::Ready(Ok(Progress::Activity)),
                    Ok(false) => {}
                    Err(e) if busy(&e) => {}
                    Err(Error::Protocol(f)) => {
                        self.close_app(row, CloseCause::Fault(f), observe);
                        return Poll::Ready(Ok(Progress::Activity));
                    }
                    Err(Error::Core(e)) => {
                        self.close_app(row, CloseCause::Core(e), observe);
                        return Poll::Ready(Ok(Progress::Activity));
                    }
                    Err(e) => return Poll::Ready(Err(e)),
                }
                continue;
            }
            match self.apps[row]
                .as_mut()
                .ok_or(Fault::Stale)?
                .io
                .poll_read(cx)
            {
                Poll::Pending => {}
                Poll::Ready(Err(e)) => {
                    self.close_app(row, CloseCause::Io(e), observe);
                    return Poll::Ready(Ok(Progress::Activity));
                }
                Poll::Ready(Ok(ReadStep::Eof)) => {
                    self.close_app(row, CloseCause::Eof, observe);
                    return Poll::Ready(Ok(Progress::Activity));
                }
                Poll::Ready(Ok(ReadStep::Progress { .. })) => {
                    let a = self.apps[row].as_mut().ok_or(Fault::Stale)?;
                    if a.input_until.is_none() {
                        a.input_until = Some(Instant::now() + self.limits.input_lifetime)
                    }
                    a.read_first = false;
                    return Poll::Ready(Ok(Progress::Activity));
                }
            }
        }
        Poll::Pending
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use gnunet_service_runtime::{clock::SystemClock, connection::Connection};

    // Public member IDs only. No key, signature or authenticated peer fixture.
    struct MemberIds(u8);
    impl Entropy for MemberIds {
        fn fill(&mut self, output: &mut [u8]) -> Result<(), Fault> {
            output.fill(self.0);
            self.0 = self.0.wrapping_add(1);
            Ok(())
        }
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Actual host entry/lease/hosting transitions assert the official private-feed contract with fallible setup"
    )]
    fn private_feed_entry_preserves_membership_without_hosting()
    -> Result<(), Box<dyn std::error::Error>> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let mut core_instance = core::Instance::new();
                let mut cadet_instance = cadet::Instance::new();
                let mut pils_instance = pc::Instance::new();
                let mut observed_instance = pc::Instance::new();
                let mut ports = [cadet::PortSlot::new(), cadet::PortSlot::new()];
                let mut channels = [cadet::ChannelSlot::new(), cadet::ChannelSlot::new()];
                let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
                let limits = Limits {
                    clients: 3,
                    rooms: 2,
                    client_rooms: 2,
                    tunnels: 2,
                    deliveries: 8,
                    signatures: 1,
                    min_routers: 0,
                    profile: wire::profile::Profile::LITTLE_255,
                    peer_profile: wire::profile::Profile::LITTLE_255,
                    ..Limits::default()
                };
                let mut server = Server::<_, 1>::new(
                    &mut core_instance,
                    &mut cadet_instance,
                    &mut pils_instance,
                    &mut ports,
                    &mut channels,
                    core::Limits::default(),
                    limits,
                    Ports {
                        options: ServiceOptions::default(),
                        unix: UnixAccess::default(),
                        clock: clock.clone(),
                        cadet: EndpointSource::unix_with_clock(
                            "/unused-messenger-cadet".into(),
                            clock.clone(),
                        ),
                        pils: EndpointSource::unix_with_clock(
                            "/unused-messenger-pils".into(),
                            clock,
                        ),
                    },
                    MemberIds(1),
                )?;
                // The public identity is generated/signed by the real pure PILS
                // service and verified by its typed client. This models the
                // observation boundary only; neither native provider is polled.
                let now = SystemClock.sample()?.now;
                let hello = gnunet_pils::HelloLimits {
                    maximum_input_bytes: 4096,
                    maximum_address_bytes: 2048,
                    maximum_addresses: 16,
                };
                let producer = gnunet_pils::Service::<4096>::new(
                    gnunet_pils::MasterKey::from_seed([7; 32]),
                    gnunet_pils::Profile::Reference029,
                    now.as_micros(),
                    hello,
                )?;
                let mut observer = pc::Client::<1>::new(
                    &mut observed_instance,
                    gnunet_pils::Profile::Reference029,
                    hello,
                )?;
                let epoch = observer.begin_connection(now)?;
                let mut frame = producer.announcement().to_vec();
                let pc::Inbound::Identity { identity, .. } =
                    observer.receive(epoch, &mut frame, &mut [0; 2048], now)?
                else {
                    return Err("missing verified identity".into());
                };
                server.observe_identity(identity)?;
                assert!(server.identity_step(&mut |_| {})?);
                let peer = server.current_peer().ok_or(Fault::NotReady)?;
                let until = Instant::now() + Duration::from_secs(5);
                let mut peers = Vec::new();
                for row in 0..3 {
                    let (stream, peer) = tokio::net::UnixStream::pair()?;
                    peers.push(peer);
                    server.apps[row] = Some(App {
                        client: Client {
                            domain: server.domain.clone(),
                            serial: row as u64 + 1,
                        },
                        io: Framed::new(Connection::from_unix(stream), limits.framing())?,
                        has_request: true,
                        public: None,
                        rooms: Vec::new(),
                        controls: VecDeque::new(),
                        output: None,
                        until,
                        input_until: Some(until),
                        entry_input: None,
                        open_input: None,
                        entry_cursor: 0,
                        read_first: true,
                    });
                }
                // LITTLE bit0 clear=private, bit1 clear=personal, bit2 set=feed.
                let mut key = [0; 64];
                key[0] = 4;
                for (row, door) in [[0; 32], peer].into_iter().enumerate() {
                    server.apps[row].as_mut().ok_or(Fault::Stale)?.entry_input = Some(EntryInput {
                        key,
                        door,
                        target: Some(EntryTarget::Local),
                        until,
                    });
                    server.bind_app(row, key, None, door, true)?;
                    let source = server.apps[row].as_ref().ok_or(Fault::Stale)?.rooms[0].source;
                    assert_eq!(
                        server.core.service_client(source)?.0,
                        *server.core.service_anonymous_public()?
                    );
                    assert!(server.leases()?); // Actual MemberId notice.
                    assert!(server.leases()?); // Actual ENTRY reply admission.
                    let lease = &server.apps[row].as_ref().ok_or(Fault::Stale)?.rooms[0];
                    assert!(lease.phase == LeasePhase::Active);
                    assert!(lease.entry_local);
                    assert_eq!(lease.door, peer);
                    assert_eq!(lease.until, until);
                    assert_eq!(lease.source, source);
                }
                let room = server.apps[0].as_ref().ok_or(Fault::Stale)?.rooms[0].room;
                let room_index = server.room_index(room)?;
                assert!(
                    server.rooms[room_index]
                        .as_ref()
                        .is_some_and(|r| !r.hosting && r.port.is_none())
                );
                assert!(server.tunnels.iter().all(Option::is_none));
                assert!(server.cadet.pending_transmit().is_none());

                server.apps[2].as_mut().ok_or(Fault::Stale)?.open_input =
                    Some(OpenInput { key, until });
                assert!(matches!(
                    server.bind_app(2, key, None, peer, false),
                    Err(Error::Protocol(Fault::Unsupported))
                ));
                assert!(server.apps[2].as_ref().is_some_and(|a| a.rooms.is_empty()));

                let mut failed = false;
                server.apps[0].as_mut().ok_or(Fault::Stale)?.open_input =
                    Some(OpenInput { key, until });
                assert!(server.admit_open(0, 0, None, &mut |event| {
                    if matches!(
                        event,
                        Event::OpenFailed {
                            reason: Error::Protocol(Fault::Unsupported),
                            ..
                        }
                    ) {
                        failed = true;
                    }
                })?);
                assert!(failed);
                let lease = &server.apps[0].as_ref().ok_or(Fault::Stale)?.rooms[0];
                assert!(lease.phase == LeasePhase::Active && lease.pending_open.is_none());
                assert!(
                    server.apps[0]
                        .as_ref()
                        .is_some_and(|a| a.open_input.is_none())
                );
                // Even an internal hosting attempt must never allocate a Port.
                server.rooms[room_index]
                    .as_mut()
                    .ok_or(Fault::Stale)?
                    .hosting = true;
                assert!(matches!(
                    server.hosting_port(room, until),
                    Err(Error::Protocol(Fault::Unsupported))
                ));
                assert!(
                    server.rooms[room_index]
                        .as_ref()
                        .is_some_and(|r| r.port.is_none())
                );
                assert!(server.cadet.pending_transmit().is_none());
                // An ENTRY already classified as local remains a local room
                // choice across a new verified observation. Its raw old door
                // and original request target remain available for diagnostics.
                let original_notices: Vec<_> = server.apps[0]
                    .as_ref()
                    .ok_or(Fault::Stale)?
                    .controls
                    .iter()
                    .map(|notice| notice.frame.bytes().to_vec())
                    .collect();
                let source = server.apps[0].as_ref().ok_or(Fault::Stale)?.rooms[0].source;
                server.apps[0].as_mut().ok_or(Fault::Stale)?.rooms[0].pending_entry =
                    Some(PendingEntry {
                        request: EntryInput {
                            key,
                            door: peer,
                            target: Some(EntryTarget::Local),
                            until,
                        },
                        target: EntryTarget::Local,
                        source: None,
                    });
                let replacement = gnunet_pils::Service::<4096>::new(
                    gnunet_pils::MasterKey::from_seed([8; 32]),
                    gnunet_pils::Profile::Reference029,
                    now.as_micros(),
                    hello,
                )?;
                let mut frame = replacement.announcement().to_vec();
                let pc::Inbound::Identity { identity, .. } =
                    observer.receive(epoch, &mut frame, &mut [0; 2048], now)?
                else {
                    return Err("missing replacement observation".into());
                };
                server.observe_identity(identity)?;
                assert!(!server.identity_ready());
                assert!(!server.entry_steps(&mut |_| {})?);
                assert!(server.identity_step(&mut |_| {})?);
                let replacement_peer = server.current_peer().ok_or(Fault::NotReady)?;
                assert_ne!(peer, replacement_peer);
                assert!(server.entry_steps(&mut |_| {})?);
                let app = server.apps[0].as_ref().ok_or(Fault::Stale)?;
                assert_eq!(app.rooms[0].source, source);
                assert!(
                    app.rooms[0].phase == LeasePhase::Active
                        && app.rooms[0].pending_entry.is_none()
                );
                assert!(
                    app.controls
                        .iter()
                        .zip(&original_notices)
                        .all(|(notice, original)| notice.frame.bytes() == original)
                );
                let new_notice = app.controls.back().ok_or(Fault::NotFound)?;
                assert!(
                    matches!(Response::decode(new_notice.frame.bytes(), limits.profile)?,
                    Response::Entry(room) if *room.door == replacement_peer)
                );
                assert!(server.tunnels.iter().all(Option::is_none));
                drop(server);
                drop(peers);
                Ok(())
            })
    }
}
