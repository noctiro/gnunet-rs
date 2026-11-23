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
            PeerAddress::Unix => self
                .ports
                .unix
                .admits(&connection, |event| observe(Event::Socket(event))),
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
        let count = self
            .core
            .retained_messages(room)?
            .try_fold(0, |count, message| message.map(|_| count + 1))?;
        if count > self.messages.iter().filter(|m| m.is_none()).count() {
            return Err(Fault::Capacity.into());
        }
        let mut historical = Vec::new();
        historical
            .try_reserve_exact(count)
            .map_err(|_| Fault::Capacity)?;
        for message in self.core.retained_messages(room)? {
            historical.push(*message?.hash());
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
        input: AdmissionInput,
        public: Option<wire::PublicKey<'_>>,
    ) -> Result<(), Error> {
        let (key, until, route) = match input {
            AdmissionInput::Open(input) => (input.key, input.until, AdmissionRoute::Open(None)),
            AdmissionInput::Entry { key, target, until } => {
                (key, until, AdmissionRoute::Entry(EntryRoute::new(target)))
            }
        };
        if Instant::now() >= until {
            return Err(Fault::Deadline.into());
        }
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
        let room_index = self.ensure_room(key)?;
        let room = self.rooms[room_index].as_ref().ok_or(Fault::Stale)?.room;
        if matches!(route, AdmissionRoute::Open(_))
            && !self.core.room_capabilities(room)?.allows_open()
        {
            return Err(Fault::Unsupported.into());
        }
        let source = self.core.attach_source(
            room,
            SourceRole::Client,
            padding::Decode::Absent,
            Some(public),
        )?;
        let result = (|| -> Result<(), Error> {
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
            if Instant::now() >= until {
                return Err(Fault::Deadline.into());
            }
            let app = self.apps[row].as_mut().ok_or(Fault::Stale)?;
            app.public = Some(public);
            app.rooms.push(Lease {
                room,
                source,
                phase: LeasePhase::Admitting(InitialAdmission {
                    route,
                    next: InitialNotice::MemberId,
                    until,
                }),
                pending_entry: None,
                pending_open: None,
                counted: false,
                bootstrap: 0,
                proposed_id: None,
                proposal_until: None,
                sync_until: None,
            });
            if matches!(route, AdmissionRoute::Open(_)) {
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
    pub(super) fn room_reply(
        &mut self,
        row: usize,
        index: usize,
        kind: RoomReply,
    ) -> Result<(), Error> {
        let (room, source) = {
            let l = self.apps[row]
                .as_ref()
                .ok_or(Fault::Stale)?
                .rooms
                .get(index)
                .ok_or(Fault::Stale)?;
            (l.room, l.source)
        };
        if !self.identity_ready() {
            return Err(Fault::WouldBlock.into());
        }
        let door = self.current_peer().ok_or(Fault::NotReady)?;
        self.room_reply_at(row, source, room, door, kind, None)
    }
    pub(super) fn room_reply_at(
        &mut self,
        row: usize,
        source: Source<'c>,
        room: Room<'c>,
        door: [u8; 32],
        kind: RoomReply,
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
            RoomReply::Open => Response::Open(fields),
            RoomReply::Entry => Response::Entry(fields),
            RoomReply::Close => Response::Close(fields),
            RoomReply::Sync => Response::Sync(fields),
        };
        self.notice_before(
            row,
            response,
            if matches!(kind, RoomReply::Close) {
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
                    if lease.room == room && !lease.phase.is_closing() {
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
        let request = core::LocalRequest::decode(input.expose())?;
        // The socket already passed SERVICE admission. Official reconnects
        // may start directly with OPEN/ENTRY; CREATE is only an idempotent
        // control message. All request-specific checks below still apply.
        self.apps[row].as_mut().ok_or(Fault::Stale)?.has_request = true;
        match request {
            core::LocalRequest::Create => {}
            core::LocalRequest::Destroy => {
                self.close_app(row, CloseCause::Shutdown, observe);
                return Ok(true);
            }
            core::LocalRequest::AdmitRoom(request) => {
                if !self.process_app_join(row, request, observe)? {
                    return Ok(false);
                }
            }
            core::LocalRequest::Room(request) => {
                let (index, command) = request.scope(|key| self.app_room(row, key))?.into_parts();
                self.process_room_command(row, index, command, observe)?;
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
    fn process_app_join(
        &mut self,
        row: usize,
        request: core::LocalRoomAdmission<'_>,
        observe: &mut impl FnMut(Event),
    ) -> Result<bool, Error> {
        let (room, public_key, entry) = match request {
            core::LocalRoomAdmission::Open { room, public_key } => (room, public_key, None),
            core::LocalRoomAdmission::Entry(entry) => {
                (entry.room(), entry.public_key(), Some(entry))
            }
        };
        let enter = entry.is_some();
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
            let target = entry
                .zip(self.current_peer())
                .map(|(entry, local)| entry.target(local));
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
                .is_some_and(|app| app.rooms[*index].phase.is_active())
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
            let input = if enter {
                let (request, target) = self.resolve_entry(row)?;
                AdmissionInput::Entry {
                    key: request.key,
                    target,
                    until: request.until,
                }
            } else {
                AdmissionInput::Open(
                    self.apps[row]
                        .as_ref()
                        .and_then(|app| app.open_input)
                        .ok_or(Fault::Conflict)?,
                )
            };
            self.bind_app(row, input, public_key)?;
        }
        Ok(true)
    }
    fn process_room_command(
        &mut self,
        row: usize,
        index: usize,
        command: core::LocalRoomCommand<'_>,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Error> {
        match command {
            core::LocalRoomCommand::Close { .. } => {
                if self.apps[row].as_ref().ok_or(Fault::Stale)?.rooms[index]
                    .phase
                    .is_closing()
                {
                    return Err(Fault::Replay.into());
                }
                self.room_reply(row, index, RoomReply::Close)?;
                self.apps[row].as_mut().ok_or(Fault::Stale)?.rooms[index].phase =
                    LeasePhase::Closing;
            }
            core::LocalRoomCommand::Sync { .. } => {
                let until = self.until()?;
                let l = &mut self.apps[row].as_mut().ok_or(Fault::Stale)?.rooms[index];
                if l.sync_until.is_some() {
                    return Err(Fault::WouldBlock.into());
                }
                l.sync_until = Some(until);
            }
            core::LocalRoomCommand::Get { hash, .. } => {
                self.get(row, index, *hash)?;
            }
            core::LocalRoomCommand::Send(send) => {
                let app = self.apps[row].as_ref().ok_or(Fault::Stale)?;
                let l = &app.rooms[index];
                if !l.phase.is_active() {
                    return Err(Fault::NotReady.into());
                }
                let (room, source) = (l.room, l.source);
                let message = send.encoded();
                let layout = self
                    .layouts
                    .application(&self.core, source, message.expose())?;
                let send = send.decode(layout)?;
                if send.kind() == Kind::GROUP && !self.limits.group_keys {
                    return Ok(());
                }
                let parsed = send.for_carrier(core::carrier::MAX_FRAME_BYTES)?;
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
        Ok(())
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

#[cfg(test)]
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
                assert!(server.identity_step()?);
                let peer = server.current_peer().ok_or(Fault::NotReady)?;
                let until = Instant::now() + Duration::from_secs(5);
                let mut peers = Vec::new();
                for row in 0..3 {
                    let listener =
                        tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
                    let (peer, (stream, _)) = tokio::try_join!(
                        tokio::net::TcpStream::connect(listener.local_addr()?),
                        listener.accept()
                    )?;
                    peers.push(peer);
                    server.apps[row] = Some(App {
                        client: Client {
                            domain: server.domain.clone(),
                            serial: row as u64 + 1,
                        },
                        io: Framed::new(Connection::from_tcp(stream), limits.framing())?,
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
                    server.bind_app(
                        row,
                        AdmissionInput::Entry {
                            key,
                            target: EntryTarget::resolve(door, peer),
                            until,
                        },
                        None,
                    )?;
                    let source = server.apps[row].as_ref().ok_or(Fault::Stale)?.rooms[0].source;
                    assert_eq!(
                        server.core.service_client(source)?.0,
                        *server.core.service_anonymous_public()?
                    );
                    assert!(server.leases(&mut |_| {})?); // Actual MemberId notice.
                    assert!(server.leases(&mut |_| {})?); // Actual ENTRY reply admission.
                    let lease = &server.apps[row].as_ref().ok_or(Fault::Stale)?.rooms[0];
                    assert!(lease.phase.is_active());
                    let notice = lease.pending_entry;
                    assert!(notice.is_none());
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
                    server.bind_app(2, AdmissionInput::Open(OpenInput { key, until }), None),
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
                assert!(lease.phase.is_active() && lease.pending_open.is_none());
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
                        key,
                        requested_door: peer,
                        until,
                        route: EntryRoute::new(EntryTarget::resolve(peer, peer)),
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
                assert!(server.identity_step()?);
                let replacement_peer = server.current_peer().ok_or(Fault::NotReady)?;
                assert_ne!(peer, replacement_peer);
                assert!(server.entry_steps(&mut |_| {})?);
                let app = server.apps[0].as_ref().ok_or(Fault::Stale)?;
                assert_eq!(app.rooms[0].source, source);
                assert!(app.rooms[0].phase.is_active() && app.rooms[0].pending_entry.is_none());
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
