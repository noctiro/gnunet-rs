use super::*;
impl<'c, 'slots, 'p, E: Entropy, const O: usize> Server<'c, 'slots, 'p, E, O> {
    pub(super) fn add_task(
        &mut self,
        room: Room<'c>,
        hash: Hash,
        destination: Destination<'c>,
        recent: bool,
        requested: bool,
    ) -> Result<(), Error> {
        if self
            .tasks
            .iter()
            .flatten()
            .any(|t| t.room == room && t.hash == hash && t.destination == destination)
        {
            return Ok(());
        }
        let row = self
            .tasks
            .iter()
            .position(Option::is_none)
            .ok_or(Fault::Capacity)?;
        let sequence = self.sequence()?;
        let until = self.until()?;
        self.tasks[row] = Some(Task {
            sequence,
            room,
            hash,
            destination,
            recent,
            requested,
            queued: false,
            until,
        });
        Ok(())
    }
    pub(super) fn finish_task(&mut self, sequence: u64) {
        if let Some(row) = self
            .tasks
            .iter()
            .position(|t| t.as_ref().is_some_and(|t| t.sequence == sequence))
        {
            self.tasks[row] = None
        }
    }
    pub(super) fn queue_peer_control(
        &mut self,
        room: Room<'c>,
        body: Body<'_>,
    ) -> Result<core::Operation<'c>, Error> {
        self.queue_peer_control_at(room, body, self.deadline()?, self.until()?)
    }
    /// Admit one control under its original parent targets. Capacity pressure
    /// does not renew either target or create another retained payload queue.
    pub(super) fn queue_peer_control_at(
        &mut self,
        room: Room<'c>,
        body: Body<'_>,
        deadline: u64,
        until: Instant,
    ) -> Result<core::Operation<'c>, Error> {
        if !self.identity_ready() {
            return Err(Fault::WouldBlock.into());
        }
        if self.last_now >= deadline || Instant::now() >= until {
            return Err(Fault::Deadline.into());
        }
        let source = self.rooms[self.room_index(room)?]
            .as_ref()
            .ok_or(Fault::Stale)?
            .signer;
        let peer = self.current_peer().ok_or(Fault::NotReady)?;
        if self.control_budgets.iter().flatten().count() + self.signs.iter().flatten().count()
            >= self.limits.signatures
        {
            return Err(Fault::WouldBlock.into());
        }
        let i = self
            .control_budgets
            .iter()
            .position(Option::is_none)
            .ok_or(Fault::Capacity)?;
        let operation = self
            .core
            .prepare_peer(source, peer, body, self.last_now, deadline)?;
        self.control_budgets[i] = Some(ControlBudget {
            room,
            kind: body.kind(),
            operation,
            until,
        });
        Ok(operation)
    }
    fn note_request(&mut self, room: Room<'c>, hash: Hash) -> Result<(), Error> {
        if self
            .retrievals
            .iter()
            .flatten()
            .any(|r| r.room == room && r.hash == hash)
        {
            return Ok(());
        }
        let i = self
            .retrievals
            .iter()
            .position(Option::is_none)
            .ok_or(Fault::Capacity)?;
        self.retrievals[i] = Some(Retrieval {
            room,
            hash,
            until: self.until()?,
        });
        Ok(())
    }
    pub(super) fn deliver_messages(&mut self) -> Result<bool, Error> {
        for i in 0..self.messages.len() {
            let Some(m) = self.messages[i].as_ref() else {
                continue;
            };
            if m.fanned {
                continue;
            }
            let (room, hash, exclude, recent) = (m.room, m.hash, m.exclude, m.recent);
            if self.core.service_attribution(room, &hash).is_err() {
                continue;
            }
            let message = self.core.message(room, &hash)?;
            let body = message.body()?;
            let info = matches!(body, Body::Info { .. });
            let is_request = matches!(body, Body::Request { .. });
            let target = if let Body::Request { hash } = body {
                Some(*hash)
            } else {
                None
            };
            let mut destinations = Vec::new();
            destinations
                .try_reserve(self.limits.clients + self.limits.tunnels)
                .map_err(|_| Fault::Capacity)?;
            if !info {
                for app in self.apps.iter().flatten() {
                    for l in &app.rooms {
                        if l.room != room || l.phase != LeasePhase::Active {
                            continue;
                        }
                        if let Body::Talk { discourse, .. } = body {
                            let Some(member) = self.core.service_member(l.source)? else {
                                continue;
                            };
                            let original = message.original().ok_or(Fault::NotFound)?;
                            let timestamp = wire::message::Message::decode_with_profiles(
                                original,
                                message.layout().body_profile(
                                    wire::envelope::Envelope::decode(original)?.header()?.kind,
                                )?,
                                message.layout().padding,
                                message.padding(),
                            )?
                            .header()
                            .timestamp
                            .as_micros();
                            if !self.core.may_deliver_talk(member, discourse, timestamp)? {
                                continue;
                            }
                        }
                        destinations.push(Destination::App {
                            client: app.client.serial,
                            source: l.source,
                        });
                    }
                }
            }
            let mut answered = false;
            let mut denied = false;
            if let (Some(target), Some(channel)) = (target, exclude)
                && self.core.message(room, &target).is_ok()
            {
                destinations.clear();
                if self.core.service_request_may_read(room, &hash, &target)?
                    && self
                        .tunnels
                        .iter()
                        .flatten()
                        .any(|t| t.channel == channel && !t.closing && !t.remote_closed)
                {
                    destinations.push(Destination::Peer(channel));
                    answered = true
                } else {
                    denied = true
                }
            }
            if !denied && (!is_request || !answered) {
                for t in self.tunnels.iter().flatten() {
                    if t.room == room
                        && !t.closing
                        && !t.remote_closed
                        && Some(t.channel) != exclude
                        && (info || t.compatible)
                    {
                        destinations.push(Destination::Peer(t.channel));
                    }
                }
            }
            if let Some(target) = target
                && !answered
                && !denied
            {
                self.note_request(room, target)?;
            }
            if destinations.len() > self.tasks.iter().filter(|t| t.is_none()).count() {
                return Ok(false);
            }
            // REQUEST response is the actual requested signed original, never a forged
            // success envelope; an answered request itself is not flooded onward.
            for d in destinations {
                let response = answered && matches!(d,Destination::Peer(c) if Some(c)==exclude);
                self.add_task(
                    room,
                    if response {
                        target.ok_or(Fault::Conflict)?
                    } else {
                        hash
                    },
                    d,
                    recent,
                    response,
                )?;
            }
            self.messages[i].as_mut().ok_or(Fault::Stale)?.fanned = true;
            self.statistics.notified();
            return Ok(true);
        }
        Ok(false)
    }
    pub(super) fn queue_app_task(
        &mut self,
        row: usize,
        observe: &mut impl FnMut(Event),
    ) -> Result<bool, Error> {
        let serial = self.apps[row].as_ref().ok_or(Fault::Stale)?.client.serial;
        for n in 0..self.tasks.len() {
            let i = (self.task_cursor + n) % self.tasks.len();
            let Some(t) = self.tasks[i].as_ref() else {
                continue;
            };
            let Destination::App { client, source } = t.destination else {
                continue;
            };
            if client != serial || t.queued {
                continue;
            }
            if !self.apps[row]
                .as_ref()
                .ok_or(Fault::Stale)?
                .rooms
                .iter()
                .any(|l| l.source == source && l.phase != LeasePhase::Closing)
            {
                self.tasks[i] = None;
                return Ok(true);
            }
            let (sequence, room, hash, recent, requested, until) =
                (t.sequence, t.room, t.hash, t.recent, t.requested, t.until);
            let attribution = self.core.service_attribution(room, &hash)?;
            let message = self.core.message(room, &hash)?;
            let Some(raw) = message.original() else {
                self.tasks[i] = None;
                return Ok(true);
            };
            let decoded = wire::message::Message::decode_with_profiles(
                raw,
                message
                    .layout()
                    .body_profile(wire::envelope::Envelope::decode(raw)?.header()?.kind)?,
                message.layout().padding,
                message.padding(),
            )?;
            if let Body::Talk { discourse, .. } = decoded.body() {
                let allowed = if let Some(member) = self.core.service_member(source)? {
                    self.core.may_deliver_talk(
                        member,
                        discourse,
                        decoded.header().timestamp.as_micros(),
                    )?
                } else {
                    false
                };
                if !allowed {
                    self.tasks[i] = None;
                    return Ok(true);
                }
            }
            let unpadded = decoded
                .hash_input()
                .len()
                .checked_add(68)
                .ok_or(Fault::Overflow)?;
            let raw = &raw[..unpadded];
            let key = *self.core.room_key(room)?;
            let flags = (u32::from(self.core.service_is_sender(source, &hash)?))
                | if attribution.peer { 4 } else { 0 }
                | if recent { 8 } else { 0 };
            let frame = self.response(Response::Receive {
                key: &key,
                sender: &attribution.sender,
                context: &attribution.context,
                hash: &hash,
                epoch: &attribution.epoch,
                flags,
                message: wire::SensitiveBytes::new(raw),
            })?;
            let total = frame.len();
            let app = self.apps[row].as_mut().ok_or(Fault::Stale)?;
            app.io.reserve(total, Class::Ordinary)?;
            app.io
                .enqueue_owned(
                    frame,
                    Origin {
                        client: serial,
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
                action: WrittenAction::None,
                task: Some(sequence),
            });
            self.tasks[i].as_mut().ok_or(Fault::Stale)?.queued = true;
            self.task_cursor = (i + 1) % self.tasks.len();
            let _ = requested;
            observe(Event::Queued {
                sequence,
                peer: false,
            });
            return Ok(true);
        }
        Ok(false)
    }
    pub(super) fn peer_task(&mut self, observe: &mut impl FnMut(Event)) -> Result<bool, Error> {
        if self.cadet.pending_transmit().is_some() || !self.history_ready() {
            return Ok(false);
        }
        for n in 0..self.tasks.len() {
            let i = (self.task_cursor + n) % self.tasks.len();
            let Some(t) = self.tasks[i].as_ref() else {
                continue;
            };
            let Destination::Peer(channel) = t.destination else {
                continue;
            };
            if t.queued {
                continue;
            }
            let Some(tunnel) = self
                .tunnels
                .iter()
                .flatten()
                .find(|x| x.channel == channel && !x.closing && !x.remote_closed)
            else {
                self.tasks[i] = None;
                return Ok(true);
            };
            if self.cadet.channel_info(channel)?.send_credit == 0 {
                continue;
            }
            let (sequence, room, hash, until) = (t.sequence, t.room, t.hash, t.until);
            let msg = self.core.message(room, &hash)?;
            let Some(raw) = msg.original() else {
                self.tasks[i] = None;
                return Ok(true);
            };
            let kind = msg.body()?.kind();
            if !tunnel.compatible && kind != Kind::INFO {
                continue;
            }
            let bytes = carrier::encode(
                raw,
                msg.layout(),
                msg.padding(),
                self.layouts.transport(&tunnel.peer).outgoing_padding,
                &mut self.entropy,
            )?;
            let transmit = self.cadet.send(channel, 0, &bytes)?;
            self.tasks[i].as_mut().ok_or(Fault::Stale)?.queued = true;
            self.peer_output = Some(PeerOutput {
                transmit,
                sequence,
                task: Some(sequence),
                retire: None,
                until,
            });
            self.task_cursor = (i + 1) % self.tasks.len();
            observe(Event::Queued {
                sequence,
                peer: true,
            });
            return Ok(true);
        }
        Ok(false)
    }
    pub(super) fn bootstrap(&mut self) -> Result<bool, Error> {
        for i in 0..self.tunnels.len() {
            let Some(t) = self.tunnels[i].as_ref() else {
                continue;
            };
            if t.closing || t.remote_closed || !t.compatible || t.bootstrap >= self.messages.len() {
                continue;
            }
            let (room, channel, mut cursor) = (t.room, t.channel, t.bootstrap);
            while cursor < self.messages.len() {
                let index = cursor;
                cursor += 1;
                let Some(m) = self.messages[index].as_ref() else {
                    continue;
                };
                if m.room != room {
                    continue;
                }
                let hash = m.hash;
                let msg = self.core.message(room, &hash)?;
                if msg.original().is_none() {
                    continue;
                }
                let kind = msg.body()?.kind();
                // Same session/peer bootstrap data as the official forward_about_members,
                // not arbitrary historical chat/plaintext and not a new history permission.
                if !matches!(
                    kind,
                    Kind::JOIN
                        | Kind::LEAVE
                        | Kind::KEY
                        | Kind::ID
                        | Kind::NAME
                        | Kind::PEER
                        | Kind::MERGE
                        | Kind::CONNECTION
                ) {
                    continue;
                }
                if self.core.service_attribution(room, &hash).is_err() {
                    continue;
                }
                self.add_task(room, hash, Destination::Peer(channel), false, true)?;
                self.tunnels[i].as_mut().ok_or(Fault::Stale)?.bootstrap = cursor;
                return Ok(true);
            }
            self.tunnels[i].as_mut().ok_or(Fault::Stale)?.bootstrap = cursor;
            return Ok(true);
        }
        Ok(false)
    }
    pub(super) fn receive_packet(
        &mut self,
        observe: &mut impl FnMut(Event),
    ) -> Result<bool, Error> {
        let selected = (0..self.received.len())
            .map(|n| (self.receive_cursor + n) % self.received.len())
            .find(|i| self.received[*i].is_some());
        let Some(receive_index) = selected else {
            return Ok(false);
        };
        self.receive_cursor = (receive_index + 1) % self.received.len();
        let received = self.received[receive_index].as_ref().ok_or(Fault::Stale)?;
        let channel = received.input.channel();
        let Some(index) = self.tunnels.iter().position(|t| {
            t.as_ref().is_some_and(|t| {
                t.channel == channel
                    && t.room == received.room
                    && t.source == received.source
                    && !t.closing
            })
        }) else {
            // Local revocation/disappearing original source wins even while
            // another immutable history cut is frozen. Never retarget old bytes.
            self.received[receive_index] = None;
            return Ok(true);
        };
        if self.history_frozen() {
            return Ok(false);
        }
        if received.offset == received.input.messages().len() {
            if !self.history_ready() {
                return Ok(false);
            }
            if self.tunnels[index]
                .as_ref()
                .ok_or(Fault::Stale)?
                .remote_closed
            {
                // Raw processing and the original history cut actually completed.
                // Physical peer retirement permits local release, never a new ACK.
                self.received[receive_index] = None;
                return Ok(true);
            }
            if self.cadet.pending_transmit().is_some() {
                return Ok(false);
            }
            let delivery = received.input.delivery();
            let transmit = self.cadet.receive_done(delivery)?;
            let sequence = self.sequence()?;
            self.peer_output = Some(PeerOutput {
                transmit,
                sequence,
                task: None,
                retire: None,
                until: self.until()?,
            });
            self.received[receive_index] = None;
            return Ok(true);
        }
        let offset = received.offset;
        let bytes = &received.input.messages()[offset..];
        let (frame, _) = gnunet_wire::official::Frame::decode_prefix(bytes)?;
        let count = frame.encoded_len();
        let raw = carrier::decode(&bytes[..count])?;
        let (room, source, peer) = {
            let t = self.tunnels[index].as_ref().ok_or(Fault::Stale)?;
            (t.room, t.source, t.peer)
        };
        let layout =
            self.layouts
                .incoming(&self.core, room, raw, peer, padding::Decode::Required)?;
        let kind = wire::envelope::Envelope::decode(raw)?.header()?.kind;
        let parsed = wire::message::Message::decode_with_profiles(
            raw,
            layout.body_profile(kind)?,
            layout.padding,
            padding::Decode::Required,
        )?;
        let hash = core::crypto::signature::message_hash(parsed);
        if !kind.is_known() {
            return Err(Fault::Unsupported.into());
        }
        let known = self.core.service_attribution(room, &hash).is_ok();
        if !known && self.messages.iter().all(Option::is_some) {
            return Ok(false);
        }
        let requested = self
            .retrievals
            .iter()
            .flatten()
            .any(|r| r.room == room && r.hash == hash);
        let input = OwnedBytes::copy_from(raw)?;
        self.core
            .receive_profiled(
                source,
                ReceiveMeta {
                    epoch: self.core.service_state(room)?.epoch,
                    flags: 4,
                    requested,
                    sender_hash: None,
                    context: None,
                },
                layout,
                input,
            )
            .map_err(|r| Error::Core(r.error))?;
        self.core.advance(room, self.last_now)?;
        if kind == Kind::INFO {
            let authenticated = self.core.service_attribution(room, &hash)?;
            if authenticated.sender != gnunet_crypto::hash512(&peer) {
                return Err(Fault::Authentication.into());
            }
            let Body::Info { version } = parsed.body() else {
                return Err(Fault::Malformed.into());
            };
            if version != carrier::VERSION {
                return Err(Fault::Unsupported.into());
            }
            self.tunnels[index].as_mut().ok_or(Fault::Stale)?.compatible = true;
            // INFO is connection-local; no app notification or rebroadcast.
            self.track(room, hash, Some(channel), false)?;
            let m = self
                .messages
                .iter_mut()
                .flatten()
                .find(|m| m.room == room && m.hash == hash)
                .ok_or(Fault::Stale)?;
            m.fanned = true;
        } else if !known {
            self.track(room, hash, Some(channel), !requested)?
        }
        self.received[receive_index]
            .as_mut()
            .ok_or(Fault::Stale)?
            .offset = offset.checked_add(count).ok_or(Fault::Overflow)?;
        self.report.received = self.report.received.saturating_add(1);
        observe(Event::Received {
            peer: true,
            authenticated: self.core.service_attribution(room, &hash).is_ok(),
        });
        Ok(true)
    }
    /// Local abandonment for one actually revoked tunnel; no receive credit.
    pub(super) fn discard_tunnel_input(&mut self, channel: cadet::Channel<'c>) {
        for received in &mut self.received {
            if received
                .as_ref()
                .is_some_and(|r| r.input.channel() == channel)
            {
                *received = None;
            }
        }
    }
    /// Last room lease closure does not grant an old peer packet new authority.
    pub(super) fn discard_room_input(&mut self, room: Room<'c>) {
        for received in &mut self.received {
            if received.as_ref().is_some_and(|r| r.room == room) {
                *received = None;
            }
        }
    }
    fn retire_remote_tunnel(&mut self) -> Result<bool, Error> {
        for index in 0..self.tunnels.len() {
            let Some(tunnel) = &self.tunnels[index] else {
                continue;
            };
            if !tunnel.remote_closed {
                continue;
            }
            let channel = tunnel.channel;
            // Local cancellation wins independently of history. Otherwise retain
            // the same Source/room until held raw input and its actual durable
            // cut finish; receive_packet releases a processed packet only after
            // history_ready. Unrelated room cuts cannot prolong an empty source.
            if !tunnel.closing
                && self
                    .received
                    .iter()
                    .flatten()
                    .any(|r| r.input.channel() == channel)
            {
                continue;
            }
            self.retire_tunnel(channel)?;
            return Ok(true);
        }
        Ok(false)
    }
    pub(super) fn retire_tunnel(&mut self, channel: cadet::Channel<'c>) -> Result<(), Error> {
        if let Some(i) = self
            .tunnels
            .iter()
            .position(|t| t.as_ref().is_some_and(|t| t.channel == channel))
        {
            let t = self.tunnels[i].take().ok_or(Fault::Stale)?;
            self.core.source_stopped(t.source)?;
            if self.shutdown.is_none()
                && self
                    .apps
                    .iter()
                    .flatten()
                    .any(|a| a.rooms.iter().any(|l| l.room == t.room))
                && self
                    .core
                    .peers(t.room)?
                    .any(|(p, announced, _, _)| *p == t.peer && announced)
                && !self
                    .tunnels
                    .iter()
                    .flatten()
                    .any(|p| p.room == t.room && p.peer == t.peer)
                && !self
                    .misses
                    .iter()
                    .flatten()
                    .any(|m| m.room == t.room && m.peer == t.peer)
            {
                let i = self
                    .misses
                    .iter()
                    .position(Option::is_none)
                    .ok_or(Fault::Capacity)?;
                self.misses[i] = Some(MissingPeer {
                    room: t.room,
                    peer: t.peer,
                });
            }

            for task in &mut self.tasks {
                if task
                    .as_ref()
                    .is_some_and(|t| t.destination == Destination::Peer(channel))
                {
                    *task = None
                }
            }
            for app in self.apps.iter_mut().flatten() {
                for l in &mut app.rooms {
                    if l.entry == Some(t.source) {
                        l.entry = None;
                    }
                }
            }
        }
        for r in &mut self.received {
            if r.as_ref().is_some_and(|r| r.input.channel() == channel) {
                *r = None
            }
        }
        Ok(())
    }
    pub(super) fn cadet_lost(
        &mut self,
        report: Option<cadet::Loss<'c>>,
        cause: Option<cadet::LossCause>,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Error> {
        for r in &mut self.received {
            *r = None
        }
        self.cadet_pending = None;
        if let Some(out) = self.peer_output.take() {
            let exposed = report
                .and_then(|l| l.pending)
                .filter(|p| p.transmit == out.transmit)
                .map(|p| p.exposed);
            if exposed != Some(false) {
                self.report.unknown = self.report.unknown.saturating_add(1)
            }
            observe(Event::OutputLost {
                sequence: out.sequence,
                exposed,
            });
            if let Some(task) = out.task {
                self.finish_task(task)
            }
        }
        // No temporary channel vector is allocated after native loss.
        for i in 0..self.tunnels.len() {
            if let Some(t) = self.tunnels[i].as_ref() {
                let channel = t.channel;
                self.retire_tunnel(channel)?
            }
        }
        if let (Some(report), Some(cause)) = (report, cause) {
            observe(Event::CadetLost {
                epoch: report.epoch.value(),
                channels: report.channels,
                pending: report.pending.map(|p| (p.transmit.value(), p.exposed)),
                cause,
            })
        }
        observe(Event::DependencyLost { pils: false });
        Ok(())
    }
    pub(super) fn cadet_poll(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        match self.receive_packet(observe) {
            Ok(true) => return Poll::Ready(Ok(Progress::Activity)),
            Ok(false) => {}
            Err(e) if busy(&e) => {}
            Err(reason) => {
                // receive_packet rotated this exact original slot before any
                // fallible decoding. Refuse that input, never another channel's
                // earlier vector entry.
                let i = self
                    .receive_cursor
                    .checked_sub(1)
                    .unwrap_or(self.received.len() - 1);
                if self.received[i].is_some() {
                    let channel = self.received[i]
                        .as_ref()
                        .ok_or(Fault::Stale)?
                        .input
                        .channel();
                    self.received[i] = None;
                    if let Some(t) = self
                        .tunnels
                        .iter_mut()
                        .flatten()
                        .find(|t| t.channel == channel)
                    {
                        t.closing = true;
                    }
                    self.discard_tunnel_input(channel);
                    observe(Event::PeerRefused { reason });
                    return Poll::Ready(Ok(Progress::Activity));
                }
                return Poll::Ready(Err(reason));
            }
        }
        if self.retire_remote_tunnel()? {
            return Poll::Ready(Ok(Progress::Activity));
        }
        if self.cadet.pending_transmit().is_none() {
            for i in 0..self.tunnels.len() {
                if let Some(t) = self.tunnels[i].as_ref()
                    && t.closing
                    && !t.remote_closed
                {
                    let channel = t.channel;
                    let transmit = self.cadet.destroy(channel)?;
                    let sequence = self.sequence()?;
                    self.peer_output = Some(PeerOutput {
                        transmit,
                        sequence,
                        task: None,
                        retire: Some(channel),
                        until: self.until()?,
                    });
                    return Poll::Ready(Ok(Progress::Activity));
                }
            }
            if self.peer_task(observe)? {
                return Poll::Ready(Ok(Progress::Activity));
            }
        }
        let p = match self.cadet.poll(cx, None) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(p) => p?,
        };
        match p {
            cadet::Step::Incoming { channel, port } => {
                let room = self
                    .rooms
                    .iter()
                    .flatten()
                    .find(|r| r.port == Some(port))
                    .ok_or(Fault::NotFound)?
                    .room;
                let index = self
                    .tunnels
                    .iter()
                    .position(Option::is_none)
                    .ok_or(Fault::Capacity)?;
                let info = self.cadet.channel_info(channel)?;
                let source = self.core.attach_source(
                    room,
                    SourceRole::Peer(info.peer),
                    padding::Decode::Required,
                    None,
                )?;
                self.tunnels[index] = Some(Tunnel {
                    room,
                    source,
                    channel,
                    peer: info.peer,
                    compatible: false,
                    info_queued: false,
                    closing: false,
                    remote_closed: false,
                    bootstrap: 0,
                    until: self.until()?,
                });
            }
            cadet::Step::Written(w) => {
                if self
                    .peer_output
                    .as_ref()
                    .is_some_and(|p| p.transmit == w.transmit)
                {
                    let out = self.peer_output.take().ok_or(Fault::Stale)?;
                    if let Some(task) = out.task {
                        self.finish_task(task)
                    }
                    if let Some(channel) = out.retire {
                        self.retire_tunnel(channel)?
                    }
                    self.report.written = self.report.written.saturating_add(1);
                    observe(Event::Written {
                        sequence: out.sequence,
                        peer: true,
                    });
                }
            }
            cadet::Step::Data(input) => {
                let Some(tunnel) = self
                    .tunnels
                    .iter()
                    .flatten()
                    .find(|t| t.channel == input.channel() && !t.closing && !t.remote_closed)
                else {
                    // The original source no longer admits new DATA. No credit
                    // or replacement tunnel authority is manufactured by drop.
                    return Poll::Ready(Ok(Progress::Activity));
                };
                let (room, source) = (tunnel.room, tunnel.source);
                let i = self
                    .received
                    .iter()
                    .position(Option::is_none)
                    .ok_or(Fault::Capacity)?;
                self.received[i] = Some(Receive {
                    input,
                    room,
                    source,
                    offset: 0,
                    until: self.until()?,
                });
            }
            cadet::Step::Destroyed(channel) => {
                if let Some(tunnel) = self
                    .tunnels
                    .iter_mut()
                    .flatten()
                    .find(|t| t.channel == channel)
                {
                    // Physical close revokes new peer work immediately, but must
                    // not erase DATA already held across a history commit.
                    tunnel.remote_closed = true;
                }
            }
            cadet::Step::Lost { report, cause, .. } => {
                self.cadet_lost(Some(report), Some(cause), observe)?
            }
            cadet::Step::Blocked { reason, .. } => return Poll::Ready(Err(reason.into())),
            cadet::Step::Unavailable(e) => return Poll::Ready(Err(e.into())),
            cadet::Step::Closed => return Poll::Ready(Err(Fault::Closed.into())),
            _ => {}
        }
        Poll::Ready(Ok(Progress::Activity))
    }
    pub(super) fn relay_step(&mut self, observe: &mut impl FnMut(Event)) -> Result<bool, Error> {
        if self.history_frozen() {
            return Ok(false);
        }
        if self.entry_steps(observe)? || self.leases()? {
            return Ok(true);
        }
        if self.room_step()? {
            return Ok(true);
        }
        if self.history_frozen() {
            return Ok(false);
        }
        if self.deliver_messages()? {
            return Ok(true);
        }
        if self.bootstrap()? {
            return Ok(true);
        }
        Ok(false)
    }
}
