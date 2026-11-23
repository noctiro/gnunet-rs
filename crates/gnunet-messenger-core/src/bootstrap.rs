//! A fresh signed JOIN may introduce this source before its inherited history
//! is available. Its echo grants no epoch/key or ordinary-message authority.
use crate::{engine::Core, state::*, *};
use gnunet_types::Error as Fault;
use wire::{body::Body, envelope::Kind};

impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    /// Actual active membership for this exact initialized physical source.
    /// Another source with the same public/member ID cannot clear its JOIN debt.
    pub fn source_joined(&self, source: Source<'id>) -> Result<bool, Error> {
        self.check_source(source)?;
        let room = self.rooms.get(source.room)?;
        let native = room.sources.get(source.slot)?;
        Ok(native.role == SourceRole::Client
            && native.create_written
            && !native.join_required
            && room.sessions.iter().any(|(_, session)| {
                session.phase == SessionPhase::Active
                    && Some(session.public) == native.public
                    && Some(session.id) == native.member_id
            }))
    }
    /// Whether this exact source's original whole-written JOIN has an actual
    /// matching authenticated echo. Causal/epoch completeness is independent:
    /// the owner may now request the missing history needed to prove its cursor.
    /// This is no server-membership ACK and grants no key or ordinary send.
    pub fn bootstrap_join_observed(
        &self,
        source: Source<'id>,
        operation: Operation<'id>,
    ) -> Result<bool, Error> {
        self.check_source(source)?;
        if operation.core != self.instance || operation.room != source.room {
            return Err(Fault::StaleGeneration.into());
        }
        let room = self.rooms.get(source.room)?;
        let native = room.sources.get(source.slot)?;
        let original = room.operations.get(operation.slot)?;
        if original.binding.source != source.slot || original.signed_kind != Some(Kind::JOIN) {
            return Err(Error::AttributionConflict);
        }
        let Job::Wire {
            purpose: NativePurpose::Send,
            length,
            ..
        } = original.job
        else {
            return Ok(false);
        };
        if native.join_required
            || !original.join_echo
            || original.written != length
            || original.phase != OperationPhase::Complete
        {
            return Ok(false);
        }
        let Some(slot) = room.find_node(&original.binding.message) else {
            return Ok(false);
        };
        let node = room.nodes.get(slot)?;
        let Some(auth) = node.auth else {
            return Ok(false);
        };
        let message = node.message(&self.frames)?;
        let Body::Join { public_key, .. } = message.body() else {
            return Err(Error::AttributionConflict);
        };
        if !native.create_written
            || native.role != SourceRole::Client
            || native.public != Some(auth.public)
            || public_key.as_bytes() != &auth.public
            || native.member_id.as_ref() != Some(message.header().sender_id)
        {
            return Err(Error::AttributionConflict);
        }
        Ok(true)
    }
    /// Record only an authenticated echo matching this source's original
    /// taken JOIN. Observation alone cannot settle an unwritten effect.
    pub(crate) fn observe_bootstrap_echo(
        &mut self,
        source: Source<'id>,
        hash: Hash,
        public: PublicKey,
        sender: ShortHash,
    ) -> Result<bool, Error> {
        if self.mode != Mode::Client {
            return Ok(false);
        }
        self.check_source(source)?;
        let room = self.rooms.get(source.room)?;
        let native = room.sources.get(source.slot)?;
        let Some(slot) = native.join_operation else {
            return Ok(false);
        };
        let original = room.operations.get(slot)?;
        if original.binding.source != source.slot
            || original.binding.message != hash
            || original.signed_kind != Some(Kind::JOIN)
            || !matches!(
                original.phase,
                OperationPhase::Taken | OperationPhase::Written
            )
            || !matches!(
                original.job,
                Job::Wire {
                    purpose: NativePurpose::Send,
                    ..
                }
            )
        {
            return Ok(false);
        }
        if native.public != Some(public) || native.member_id != Some(sender) {
            return Err(Error::AttributionConflict);
        }
        self.rooms
            .get_mut(source.room)?
            .operations
            .get_mut(slot)?
            .join_echo = true;
        self.finish_bootstrap_join(source, slot)?;
        Ok(true)
    }
    /// Reconcile the two original facts in either callback order. The retained
    /// node keeps its historical source; only the exact current JOIN owner can
    /// settle this source's initialization debt.
    pub(crate) fn finish_bootstrap_join(
        &mut self,
        source: Source<'id>,
        slot: Slot,
    ) -> Result<(), Error> {
        self.check_source(source)?;
        let room = self.rooms.get(source.room)?;
        let original = room.operations.get(slot)?;
        let Job::Wire {
            purpose: NativePurpose::Send,
            length,
            ..
        } = original.job
        else {
            return Err(Fault::Conflict.into());
        };
        if original.binding.source != source.slot || original.signed_kind != Some(Kind::JOIN) {
            return Err(Error::AttributionConflict);
        }
        if !original.join_echo
            || original.written != length
            || original.phase != OperationPhase::Written
        {
            return Ok(());
        }
        let node = room.nodes.get(
            room.find_node(&original.binding.message)
                .ok_or(Fault::NotReady)?,
        )?;
        let auth = node.auth.ok_or(Fault::Authentication)?;
        let message = node.message(&self.frames)?;
        let Body::Join { public_key, .. } = message.body() else {
            return Err(Error::AttributionConflict);
        };
        if public_key.as_bytes() != &auth.public {
            return Err(Error::AttributionConflict);
        }
        let sender = *message.header().sender_id;
        let semantic = node.semantic_applied;
        self.finish_wire(source, slot)?;
        let room = self.rooms.get_mut(source.room)?;
        let native = room.sources.get_mut(source.slot)?;
        if native.join_operation == Some(slot)
            && native.role == SourceRole::Client
            && native.create_written
            && native.public == Some(auth.public)
            && native.member_id == Some(sender)
        {
            native.join_required = false;
            if semantic && room.local_public == Some(auth.public) && room.local_id == Some(sender) {
                room.joined = true;
            }
        }
        Ok(())
    }
    pub(crate) fn bootstrap_position(
        &self,
        source: Source<'id>,
        member: Option<MemberSession<'id>>,
        public: PublicKey,
        sender: ShortHash,
        body: Body<'_>,
        position: &crate::key_controls::SigningPosition,
    ) -> Result<bool, Error> {
        let Body::Join {
            public_key, epoch, ..
        } = body
        else {
            return Ok(false);
        };
        let room = self.rooms.get(source.room)?;
        let native = room.sources.get(source.slot)?;
        if self.mode != Mode::Client
            || member.is_some()
            || self.source_joined(source)?
            || !matches!(room.phase, RoomPhase::Open | RoomPhase::Entered)
            || native.role != SourceRole::Client
            || !native.create_written
            || native.public != Some(public)
            || native.member_id != Some(sender)
            || room.local_public != Some(public)
            || public_key.as_bytes() != &public
            || *epoch != room.current_epoch
            || position.epoch != room.current_epoch
            || position.previous != room.last_message
        {
            return Err(Error::Permission);
        }
        Ok(true)
    }
}
