//! Actual room-port/channel control and bounded original signing admission.
use super::*;
#[derive(Clone, Copy)]
enum AnnouncementPhase<'c> {
    Peer,
    PeerPending(core::Operation<'c>),
    Miss,
    MissPending(core::Operation<'c>),
    Complete,
}
/// One room's bounded local announcement transaction. Native admission alone
/// never advances its PEER/MISS commit order or grants remote reachability.
pub(super) struct Announcement<'c> {
    peer: [u8; 32],
    deadline: u64,
    until: Instant,
    phase: AnnouncementPhase<'c>,
}
impl<'c, 'slots, 'p, E: Entropy, const O: usize> Server<'c, 'slots, 'p, E, O> {
    // Only an explicit OPEN invokes the original port factory. A port remains
    // owned by its shared room; local/remote ENTRY never implies hosting.
    pub(super) fn hosting_port(
        &mut self,
        room: Room<'c>,
        until: Instant,
    ) -> Result<Option<cadet::Port<'c>>, Error> {
        if Instant::now() >= until {
            return Err(Fault::Deadline.into());
        }
        if !self.identity_ready() {
            return Ok(None);
        }
        let index = self.room_index(room)?;
        let (_, group, feed) = self.core.room_flags(room)?;
        if feed && !group {
            return Err(Fault::Unsupported.into());
        }
        let r = self.rooms[index].as_ref().ok_or(Fault::Stale)?;
        if !r.hosting || r.closing {
            return Err(Fault::Closed.into());
        }
        if let Some(port) = r.port {
            // PortOpen carries only the room's port hash. This exact logical
            // registration survives healthy CADET identity replacement on the
            // same MQ. It is not a PID attestation or remote-reachability proof.
            return Ok(Some(port));
        }
        if self.cadet.pending_transmit().is_some() {
            return Ok(None);
        }
        let port = carrier::port(&r.key, self.limits.profile);
        if Instant::now() >= until {
            return Err(Fault::Deadline.into());
        }
        let original = self.cadet.listen(port)?;
        self.rooms[index].as_mut().ok_or(Fault::Stale)?.port = Some(original);
        Ok(Some(original))
    }
    pub(super) fn room_identity_changed(
        &mut self,
        _previous: [u8; 32],
        current: [u8; 32],
        deadline: u64,
        until: Instant,
    ) -> Result<(), Error> {
        // The identity owner must settle every original control operation before
        // changing its signer. Do not overwrite an outstanding branded receipt.
        if self.rooms.iter().flatten().any(|room| {
            room.announcement.as_ref().is_some_and(|announcement| {
                matches!(
                    announcement.phase,
                    AnnouncementPhase::PeerPending(_) | AnnouncementPhase::MissPending(_)
                )
            })
        }) {
            return Err(Fault::Conflict.into());
        }
        for room in self.rooms.iter_mut().flatten() {
            if room.hosting && room.port.is_some() && !room.closing {
                room.announcement = Some(Announcement {
                    peer: current,
                    deadline,
                    until,
                    phase: AnnouncementPhase::Peer,
                });
            }
        }
        Ok(())
    }
    /// Called only for an original local Core terminal fact, before retiring
    /// that same operation. A failure permits a distinct child under the same
    /// fixed parent; it never turns the failed original into a successful one.
    pub(super) fn room_control_finished(
        &mut self,
        operation: core::Operation<'c>,
        committed: bool,
    ) -> Result<(), Error> {
        for room in self.rooms.iter_mut().flatten() {
            let Some(announcement) = &mut room.announcement else {
                continue;
            };
            match announcement.phase {
                AnnouncementPhase::PeerPending(original) if original == operation => {
                    let actual = self.core.operation_phase(operation)?;
                    if !matches!(
                        (committed, actual),
                        (true, core::OperationPhase::Complete)
                            | (
                                false,
                                core::OperationPhase::Cancelled | core::OperationPhase::Failed
                            )
                    ) {
                        return Err(Fault::Conflict.into());
                    }
                    announcement.phase = if committed {
                        AnnouncementPhase::Miss
                    } else {
                        AnnouncementPhase::Peer
                    };
                    return Ok(());
                }
                AnnouncementPhase::MissPending(original) if original == operation => {
                    let actual = self.core.operation_phase(operation)?;
                    if !matches!(
                        (committed, actual),
                        (true, core::OperationPhase::Complete)
                            | (
                                false,
                                core::OperationPhase::Cancelled | core::OperationPhase::Failed
                            )
                    ) {
                        return Err(Fault::Conflict.into());
                    }
                    announcement.phase = AnnouncementPhase::Miss;
                    return Ok(());
                }
                _ => {}
            }
        }
        Ok(())
    }
    pub(super) fn room_announcement(&mut self, index: usize) -> Result<bool, Error> {
        if !self.identity_ready() {
            return Ok(false);
        }
        let room = self.rooms[index].as_ref().ok_or(Fault::Stale)?;
        let Some(announcement) = &room.announcement else {
            return Ok(false);
        };
        let (room, peer, deadline, until, phase) = (
            room.room,
            announcement.peer,
            announcement.deadline,
            announcement.until,
            announcement.phase,
        );
        if matches!(
            phase,
            AnnouncementPhase::Complete
                | AnnouncementPhase::PeerPending(_)
                | AnnouncementPhase::MissPending(_)
        ) {
            return Ok(false);
        }
        if self.last_now >= deadline || Instant::now() >= until {
            return Err(Fault::Deadline.into());
        }
        if self.current_peer() != Some(peer) {
            return Err(Fault::StaleGeneration.into());
        }
        let body = match phase {
            AnnouncementPhase::Peer => Body::Peer { peer: &peer },
            AnnouncementPhase::Miss => {
                let old = self
                    .core
                    .peers(room)?
                    .find_map(|(candidate, announced, _, _)| {
                        (announced && *candidate != peer && self.core.is_own_signer(candidate))
                            .then_some(*candidate)
                    });
                let Some(old) = old else {
                    self.rooms[index]
                        .as_mut()
                        .ok_or(Fault::Stale)?
                        .announcement
                        .as_mut()
                        .ok_or(Fault::Stale)?
                        .phase = AnnouncementPhase::Complete;
                    return Ok(true);
                };
                let operation = match self.queue_peer_control_at(
                    room,
                    Body::Miss { peer: &old },
                    deadline,
                    until,
                ) {
                    Ok(operation) => operation,
                    Err(error) if busy(&error) => return Ok(false),
                    Err(error) => return Err(error),
                };
                self.rooms[index]
                    .as_mut()
                    .ok_or(Fault::Stale)?
                    .announcement
                    .as_mut()
                    .ok_or(Fault::Stale)?
                    .phase = AnnouncementPhase::MissPending(operation);
                return Ok(true);
            }
            AnnouncementPhase::PeerPending(_)
            | AnnouncementPhase::MissPending(_)
            | AnnouncementPhase::Complete => return Ok(false),
        };
        let operation = match self.queue_peer_control_at(room, body, deadline, until) {
            Ok(operation) => operation,
            Err(error) if busy(&error) => return Ok(false),
            Err(error) => return Err(error),
        };
        self.rooms[index]
            .as_mut()
            .ok_or(Fault::Stale)?
            .announcement
            .as_mut()
            .ok_or(Fault::Stale)?
            .phase = AnnouncementPhase::PeerPending(operation);
        Ok(true)
    }
    pub(super) fn room_step(&mut self) -> Result<bool, Error> {
        if self.app_bootstrap()? {
            return Ok(true);
        }
        if !self.identity_ready() {
            return Ok(false);
        }
        if self.sync_step()? {
            return Ok(true);
        }
        if self.collision_step()? {
            return Ok(true);
        }
        for i in 0..self.tunnels.len() {
            let Some(t) = self.tunnels[i].as_ref() else {
                continue;
            };
            if t.closing || t.remote_closed || t.info_queued {
                continue;
            }
            let room = t.room;
            self.queue_peer_control(
                room,
                Body::Info {
                    version: carrier::VERSION,
                },
            )?;
            self.tunnels[i].as_mut().ok_or(Fault::Stale)?.info_queued = true;
            return Ok(true);
        }
        if let Some(i) = self.misses.iter().position(Option::is_some) {
            let m = self.misses[i].as_ref().ok_or(Fault::Stale)?;
            let (room, peer) = (m.room, m.peer);
            self.queue_peer_control(room, Body::Miss { peer: &peer })?;
            self.misses[i] = None;
            return Ok(true);
        }
        for i in 0..self.rooms.len() {
            let Some(r) = self.rooms[i].as_ref() else {
                continue;
            };
            let room = r.room;
            let live = self
                .apps
                .iter()
                .flatten()
                .any(|a| a.rooms.iter().any(|l| l.room == room));
            if !live {
                self.rooms[i].as_mut().ok_or(Fault::Stale)?.closing = true;
                for t in self.tunnels.iter_mut().flatten() {
                    if t.room == room {
                        t.closing = true
                    }
                }
                self.discard_room_input(room);
                if self.tunnels.iter().flatten().any(|t| t.room == room) {
                    continue;
                }
                if self.signs.iter().flatten().any(|s| s.room == room)
                    || self
                        .control_budgets
                        .iter()
                        .flatten()
                        .any(|b| b.room == room)
                {
                    continue;
                }
                if let Some(port) = self.rooms[i].as_ref().ok_or(Fault::Stale)?.port {
                    if self.cadet.pending_transmit().is_some() {
                        continue;
                    }
                    if let Some(transmit) = self.cadet.close_port(port)? {
                        let sequence = self.sequence()?;
                        self.peer_output = Some(PeerOutput {
                            transmit,
                            sequence,
                            task: None,
                            retire: None,
                            until: self.until()?,
                        });
                        // Logical port retirement is admitted here; no second close is issued.
                        // Original partial frame remains owned by the actual CADET client.
                        self.rooms[i].as_mut().ok_or(Fault::Stale)?.port = None;
                        return Ok(true);
                    }
                    self.rooms[i].as_mut().ok_or(Fault::Stale)?.port = None;
                    return Ok(true);
                }
                if self.cadet.pending_transmit().is_some() {
                    continue;
                }
                let r = self.rooms[i].take().ok_or(Fault::Stale)?;
                self.core.release_service_signer(r.signer)?;
                if self.history.is_none() {
                    self.core.forget_room(room)?;
                }
                for r in &mut self.retrievals {
                    if r.as_ref().is_some_and(|r| r.room == room) {
                        *r = None
                    }
                }
                for m in &mut self.messages {
                    if m.as_ref().is_some_and(|m| m.room == room) {
                        *m = None
                    }
                }
                for t in &mut self.tasks {
                    if t.as_ref().is_some_and(|t| t.room == room) {
                        *t = None
                    }
                }
                return Ok(true);
            }
            if r.closing {
                continue;
            }
            let published = r.hosting
                && r.port
                    .is_some_and(|p| self.cadet.port_announced(p).unwrap_or(false));
            if published {
                if r.announcement.is_none() && self.identity_ready() {
                    let peer = self.current_peer().ok_or(Fault::NotReady)?;
                    let deadline = self.deadline()?;
                    let until = self.until()?;
                    self.rooms[i].as_mut().ok_or(Fault::Stale)?.announcement = Some(Announcement {
                        peer,
                        deadline,
                        until,
                        phase: AnnouncementPhase::Peer,
                    });
                    return Ok(true);
                }
                if self.room_announcement(i)? {
                    return Ok(true);
                }
            }
            let count = u32::try_from(
                self.tunnels
                    .iter()
                    .flatten()
                    .filter(|t| t.room == room && t.compatible && !t.closing && !t.remote_closed)
                    .count(),
            )
            .map_err(|_| Fault::Overflow)?;
            if self.rooms[i].as_ref().ok_or(Fault::Stale)?.connections != Some(count) {
                self.queue_peer_control(
                    room,
                    Body::Connection {
                        amount: count,
                        flags: u32::from(self.limits.auto_routing),
                    },
                )?;
                self.rooms[i].as_mut().ok_or(Fault::Stale)?.connections = Some(count);
                return Ok(true);
            }
            let merge_pending = self
                .control_budgets
                .iter()
                .flatten()
                .any(|b| b.room == room && b.kind == Kind::MERGE)
                || self.signs.iter().flatten().any(|s| {
                    s.room == room
                        && wire::message::Message::decode(
                            s.frame.expose(),
                            self.limits.profile,
                            padding::Decode::Absent,
                        )
                        .is_ok_and(|m| m.header().kind == Kind::MERGE)
                });
            if !merge_pending && let Some(m) = self.core.service_merge(room)? {
                self.queue_peer_control(
                    room,
                    Body::Merge {
                        first_epoch: &m.first_epoch,
                        second_epoch: &m.second_epoch,
                        previous: &m.previous,
                    },
                )?;
                return Ok(true);
            }
            let reserved = self
                .tunnels
                .iter()
                .flatten()
                .filter(|t| t.room == room && !t.closing && !t.remote_closed)
                .count();
            let desired = if self.limits.auto_routing {
                self.limits.min_routers
            } else if self.limits.auto_connecting {
                1
            } else {
                0
            };
            if reserved < desired && self.cadet.pending_transmit().is_none() {
                let candidate = self.core.service_peer_candidates(room)?.find_map(|peer| {
                    (!self.core.is_own_signer(peer)
                        && !self
                            .tunnels
                            .iter()
                            .flatten()
                            .any(|t| t.room == room && t.peer == *peer))
                    .then_some(*peer)
                });
                if let Some(peer) = candidate
                    && let Some(slot) = self.tunnels.iter().position(Option::is_none)
                {
                    let key = *self.core.room_key(room)?;
                    let channel = self
                        .cadet
                        .open(peer, carrier::port(&key, self.layouts.relay(&peer)))?;
                    let source = self.core.attach_source(
                        room,
                        SourceRole::Peer(peer),
                        padding::Decode::Required,
                        None,
                    )?;
                    self.tunnels[slot] = Some(Tunnel {
                        room,
                        source,
                        channel,
                        peer,
                        compatible: false,
                        info_queued: false,
                        closing: false,
                        remote_closed: false,
                        bootstrap: 0,
                        until: self.until()?,
                    });
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
    fn collision_step(&mut self) -> Result<bool, Error> {
        for a in 0..self.apps.len() {
            let count = self.apps[a].as_ref().map_or(0, |a| a.rooms.len());
            for l in 0..count {
                let (room, source, proposal) = {
                    let lease = &self.apps[a].as_ref().ok_or(Fault::Stale)?.rooms[l];
                    (lease.room, lease.source, lease.proposed_id)
                };
                let (public, id) = self.core.service_client(source)?;
                if let Some(proposed) = proposal {
                    if proposed == id {
                        let lease = &mut self.apps[a].as_mut().ok_or(Fault::Stale)?.rooms[l];
                        lease.proposed_id = None;
                        lease.proposal_until = None;
                        return Ok(true);
                    }
                    continue;
                }
                let collision = self.core.members(room)?.any(|(member, _, other, phase)| {
                    other == id
                        && phase != core::SessionPhase::Completed
                        && self.core.member_public(member).is_ok_and(|p| *p != public)
                });
                if !collision {
                    continue;
                }
                if self.apps[a].as_ref().ok_or(Fault::Stale)?.controls.len() == self.limits.controls
                {
                    continue;
                }
                let mut proposed = None;
                for _ in 0..32 {
                    let mut candidate = [0; 32];
                    self.entropy.fill(&mut candidate)?;
                    match self.core.propose_service_client_id(source, candidate) {
                        Ok(()) => {
                            proposed = Some(candidate);
                            break;
                        }
                        Err(core::Error::Protocol(Fault::Conflict | Fault::Replay)) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                let proposed = proposed.ok_or(Fault::Capacity)?;
                let key = *self.core.room_key(room)?;
                self.notice(
                    a,
                    Response::MemberId {
                        key: &key,
                        id: &proposed,
                        reset: 1,
                    },
                    WrittenAction::None,
                )?;
                let until = self.until()?;
                let lease = &mut self.apps[a].as_mut().ok_or(Fault::Stale)?.rooms[l];
                lease.proposed_id = Some(proposed);
                lease.proposal_until = Some(until);
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn sync_step(&mut self) -> Result<bool, Error> {
        for a in 0..self.apps.len() {
            let count = self.apps[a].as_ref().map_or(0, |a| a.rooms.len());
            for l in 0..count {
                let lease = &self.apps[a].as_ref().ok_or(Fault::Stale)?.rooms[l];
                if lease.sync_until.is_none() {
                    continue;
                }
                let room = lease.room;
                let pending = self
                    .control_budgets
                    .iter()
                    .flatten()
                    .any(|b| b.room == room && b.kind == Kind::MERGE)
                    || self.signs.iter().flatten().any(|s| {
                        s.room == room
                            && wire::message::Message::decode(
                                s.frame.expose(),
                                self.limits.profile,
                                padding::Decode::Absent,
                            )
                            .is_ok_and(|m| m.header().kind == Kind::MERGE)
                    });
                if pending || self.core.service_merge(room)?.is_some() {
                    continue;
                }
                self.room_reply(a, l, 4)?;
                self.apps[a].as_mut().ok_or(Fault::Stale)?.rooms[l].sync_until = None;
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn app_bootstrap(&mut self) -> Result<bool, Error> {
        for a in 0..self.apps.len() {
            let n = self.apps[a].as_ref().map_or(0, |a| a.rooms.len());
            for l in 0..n {
                let lease = &self.apps[a].as_ref().ok_or(Fault::Stale)?.rooms[l];
                if lease.phase != LeasePhase::Active
                    || lease.bootstrap >= self.messages.len()
                    || self.core.service_member(lease.source)?.is_none()
                {
                    continue;
                }
                let (room, source, mut cursor) = (lease.room, lease.source, lease.bootstrap);
                let client = self.apps[a].as_ref().ok_or(Fault::Stale)?.client.serial;
                while cursor < self.messages.len() {
                    let i = cursor;
                    cursor += 1;
                    let Some(m) = self.messages[i].as_ref() else {
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
                            | Kind::ANNOUNCEMENT
                            | Kind::GROUP
                    ) {
                        continue;
                    }
                    if self.core.service_attribution(room, &hash).is_err() {
                        continue;
                    }
                    self.add_task(room, hash, Destination::App { client, source }, false, true)?;
                    self.apps[a].as_mut().ok_or(Fault::Stale)?.rooms[l].bootstrap = cursor;
                    return Ok(true);
                }
                self.apps[a].as_mut().ok_or(Fault::Stale)?.rooms[l].bootstrap = cursor;
                return Ok(true);
            }
        }
        Ok(false)
    }
}
