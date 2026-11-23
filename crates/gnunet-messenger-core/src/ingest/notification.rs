//! Borrowed notifications from the original client IPC source.

use super::*;

impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    /// Borrowed original client IPC notification. A new RECEIVE copies its original
    /// bytes directly into retained history after admission; an already retained
    /// duplicate needs no new frame storage.
    pub fn on_notification(
        &mut self,
        source: Source<'id>,
        response: wire::Response<'_>,
        now: u64,
    ) -> Result<(), Error> {
        self.notification_profiled(source, response, ClientLayout::same(self.profile), now)
    }
    /// Apply the actual original notification with explicit original body,
    /// plaintext and identifier facts. This is a CLIENT port, not daemon ingress;
    /// original key/hash/source/signature checks and pending-job binding remain.
    pub fn on_notification_profiled(
        &mut self,
        source: Source<'id>,
        response: wire::Response<'_>,
        layout: ClientLayout,
        now: u64,
    ) -> Result<(), Error> {
        self.notification_profiled(source, response, layout, now)
    }
    fn notification_profiled(
        &mut self,
        source: Source<'id>,
        response: wire::Response<'_>,
        layout: ClientLayout,
        now: u64,
    ) -> Result<(), Error> {
        if self.mode != Mode::Client {
            return Err(Error::Permission);
        }
        layout.validate()?;
        self.check_source(source)?;
        if self
            .rooms
            .get(source.room)?
            .operations
            .iter()
            .any(|(_, o)| {
                o.binding.source == source.slot
                    && !matches!(
                        o.phase,
                        OperationPhase::Complete
                            | OperationPhase::Failed
                            | OperationPhase::Cancelled
                    )
                    && o.deadline <= now
            })
        {
            return Err(Fault::Timeout.into());
        }
        let key = self.rooms.get(source.room)?.key;
        match response {
            wire::Response::Receive {
                key: k,
                sender,
                context,
                hash,
                epoch,
                flags,
                message,
            } => {
                if *k != key {
                    return Err(Error::AttributionConflict);
                }
                let bytes = message.expose();
                let original = OriginalFrame::decode(
                    bytes,
                    self.rooms
                        .get(source.room)?
                        .sources
                        .get(source.slot)?
                        .padding,
                    layout.original,
                )?;
                if original.hash != *hash {
                    return Err(Fault::Authentication.into());
                }
                self.check_receive_capacity(bytes.len())?;
                let get = self.pending_wire(source, NativePurpose::Get, Some(hash));
                let meta = ReceiveMeta {
                    epoch: *epoch,
                    flags,
                    requested: get.is_some(),
                    sender_hash: Some(*sender),
                    context: Some(*context),
                };
                let sender_id = *original.message.header().sender_id;
                let mut admission = self.check_decoded(source, meta, original)?;
                let join_echo = if admission.kind == Kind::JOIN {
                    admission.auth.map(|auth| (auth.public, sender_id))
                } else {
                    None
                };
                admission.cipher_layout = Some(layout.plaintext);
                admission.transcript_layout = Some(layout.transcript);
                admission.identifier_order = layout.identifier_order;
                self.frame_commit()
                    .0
                    .commit(source, meta, bytes, admission, 0)
                    .map_err(|(error, _)| error)?;

                if let Some(op) = get {
                    self.finish_wire(source, op)?;
                }
                let owned_join = if let Some((public, sender)) = join_echo {
                    self.observe_bootstrap_echo(source, *hash, public, sender)?
                } else {
                    false
                };
                if !owned_join
                    && let Some(op) = self.pending_wire(source, NativePurpose::Send, Some(hash))
                {
                    self.finish_wire(source, op)?;
                }
            }
            wire::Response::Missing { key: k, hash } => {
                if *k != key {
                    return Err(Error::AttributionConflict);
                }
                let op = self
                    .pending_wire(source, NativePurpose::Get, Some(hash))
                    .ok_or(Fault::StaleGeneration)?;
                let deadline = self.rooms.get(source.room)?.operations.get(op)?.deadline;
                self.reserve_events(2)?;
                self.finish_wire(source, op)?;
                let room = self.rooms.get_mut(source.room)?;
                if let Some((_, missing)) = room
                    .missing
                    .iter_mut()
                    .find(|(_, m)| m.hash == *hash && m.source == source.slot)
                {
                    missing.absent = true;
                    missing.operation = None;
                    if missing.retry_at == 0 {
                        missing.retry_at = deadline;
                    }
                }
                self.event(Event::Missing(self.event_room(source.room), *hash))?;
            }
            wire::Response::MemberId { key: k, id, reset } => {
                if *k != key {
                    return Err(Error::AttributionConflict);
                }
                // Response::decode uses the explicit original producer profile
                // for this single native-endian C field; no second swap here.
                self.reserve_events(1)?;
                let room = self.rooms.get_mut(source.room)?;
                let src = room.sources.get_mut(source.slot)?;
                if src.member_id.is_none() || reset == 1 {
                    src.member_id = Some(*id);
                    src.pending_member_id = None;
                    src.join_required = true;
                    src.join_operation = None;
                    room.local_id = Some(*id);
                    room.joined = false;
                } else {
                    // Keep the old sender ID until the signed ID(new) is really
                    // applied. Overwriting it here breaks original verification.
                    src.pending_member_id = Some(*id);
                }
                self.event(Event::RoomChanged(
                    self.event_room(source.room),
                    self.rooms.get(source.room)?.phase,
                ))?;
            }
            other => {
                let (r, purpose, phase) = match other {
                    wire::Response::Open(r) => (r, NativePurpose::Open, RoomPhase::Open),
                    wire::Response::Entry(r) => (r, NativePurpose::Enter, RoomPhase::Entered),
                    wire::Response::Close(r) => (r, NativePurpose::Close, RoomPhase::Detached),
                    wire::Response::Sync(r) => (
                        r,
                        NativePurpose::Sync,
                        if self.rooms.get(source.room)?.phase == RoomPhase::Closing {
                            RoomPhase::Closing
                        } else {
                            self.rooms
                                .get(source.room)?
                                .sync_phase
                                .ok_or(Fault::Conflict)?
                        },
                    ),
                    _ => return Err(Fault::Malformed.into()),
                };
                if *r.key != key {
                    return Err(Error::AttributionConflict);
                }
                let op = self
                    .pending_wire(source, purpose, None)
                    .ok_or(Fault::StaleGeneration)?;
                self.reserve_events(2)?;
                if purpose == NativePurpose::Sync
                    && self.frontier_sync_in_flight(self.event_room(source.room))?
                {
                    self.observe_frontier_sync(source, op, *r.previous, *r.epoch)?;
                    return Ok(());
                }
                self.finish_wire(source, op)?;
                let row = self.rooms.get_mut(source.room)?;
                row.phase = phase;
                if self.mode == Mode::Client
                    && row.frontier_reset
                    && matches!(purpose, NativePurpose::Open | NativePurpose::Enter)
                {
                    row.queues.frontier.clear();
                    row.frontier_base = Some(*r.previous);
                    row.frontier_control_hash = None;
                    row.frontier_reset = false;
                }
                if purpose == NativePurpose::Sync {
                    row.sync_phase = None;
                }
                if purpose == NativePurpose::Close {
                    row.joined = false;
                }
                // Actual synchronization metadata is a cursor, not proof that
                // an unknown message/epoch has arrived or passed authentication.
                row.last_message = *r.previous;
                row.current_epoch = *r.epoch;
                row.frontier_version =
                    row.frontier_version.checked_add(1).ok_or(Fault::Overflow)?;
                self.event(Event::RoomChanged(self.event_room(source.room), phase))?;
            }
        }
        Ok(())
    }
}
