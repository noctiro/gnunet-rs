//! Client room leases, session snapshots and matching CLOSE retirement.
#[cfg(feature = "alloc")]
use crate::state::*;
use crate::{engine::Core, *};
#[cfg(feature = "alloc")]
use gnunet_types::Error as Fault;
#[cfg(feature = "alloc")]
use wire::envelope::Kind;
impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    /// Exact current active local session in this original room generation.
    /// This uses its own session/public-ID snapshot, never a Contact.key changed
    /// by another room. Absence grants no membership or signing authorization.
    #[cfg(feature = "alloc")]
    pub fn local_member(&self, room: Room<'id>) -> Result<Option<MemberSession<'id>>, Error> {
        let r = self.check_room(room)?;
        Ok(self
            .rooms
            .get(r)?
            .local_session()
            .map(|s| self.member_id(r, s)))
    }
    /// Original public signing snapshot of this exact checked member session.
    /// Completed historical sessions remain readable; this getter grants no
    /// eligibility to sign or revive their original provider/native operations.
    pub fn member_public(&self, member: MemberSession<'id>) -> Result<&PublicKey, Error> {
        self.check_member(member)?;
        Ok(&self
            .rooms
            .get(member.room)?
            .sessions
            .get(member.slot)?
            .public)
    }
    /// Retire only the original client room lease after its actual matching
    /// CLOSE notification completed the original Written CLOSE operation. This
    /// is not physical MQ loss and emits no SourceLost event. Shared native MQ
    /// epochs and other rooms remain live. Old authenticated history/keys remain;
    /// unverified originals cannot be adopted by a later reopened room lease.
    /// Consumes the completed CLOSE and optional matching whole-written LEAVE.
    /// A LEAVE without an echo is retired without a Complete event: CLOSE proves
    /// local room detachment, never remote receipt of that message.
    #[cfg(feature = "alloc")]
    pub fn retire_room_lease(
        &mut self,
        source: Source<'id>,
        close: Operation<'id>,
        leave: Option<Operation<'id>>,
    ) -> Result<(), Error> {
        self.check_source(source)?;
        if self.mode != Mode::Client || close.core != self.instance || close.room != source.room {
            return Err(Error::Permission);
        }
        let room = self.rooms.get(source.room)?;
        let source_row = room.sources.get(source.slot)?;
        if source_row.role != SourceRole::Client || room.phase != RoomPhase::Detached {
            return Err(Fault::NotReady.into());
        }
        let operation = room.operations.get(close.slot)?;
        if operation.binding.source != source.slot
            || operation.phase != OperationPhase::Complete
            || !matches!(
                &operation.job,
                Job::Wire {
                    purpose: NativePurpose::Close,
                    encoding: Encoding::Ipc,
                    ..
                }
            )
        {
            return Err(Fault::StaleGeneration.into());
        }
        let mut released = operation.charged_bytes;
        if let Some(leave) = leave {
            if leave.core != self.instance || leave.room != source.room || leave == close {
                return Err(Fault::StaleGeneration.into());
            }
            let original = room.operations.get(leave.slot)?;
            if original.binding.source != source.slot
                || original.signed_kind != Some(Kind::LEAVE)
                || !matches!(
                    original.phase,
                    OperationPhase::Written | OperationPhase::Complete
                )
                || !matches!(&original.job, Job::Wire {
                    purpose: NativePurpose::Send, length, encoding: Encoding::Ipc, ..
                } if original.written == *length)
            {
                return Err(Fault::NotReady.into());
            }
            released = released
                .checked_add(original.charged_bytes)
                .ok_or(Fault::Overflow)?;
        }
        if room.operations.iter().any(|(slot, o)| {
            o.binding.source == source.slot
                && Some(slot) != leave.map(|operation| operation.slot)
                && !matches!(
                    o.phase,
                    OperationPhase::Complete | OperationPhase::Failed | OperationPhase::Cancelled
                )
        }) {
            return Err(Fault::NotReady.into());
        }
        // Accounting and every scope/debt preflight precede the first mutation.
        self.reclaim_source_inputs(source, released)?;
        let room = self.rooms.get_mut(source.room)?;
        room.operations.remove(close.slot)?;
        if let Some(leave) = leave {
            room.operations.remove(leave.slot)?;
        }
        room.sources.remove(source.slot)?;
        if room.frontier_control.is_some_and(|control| {
            room.operations
                .get(control)
                .is_ok_and(|operation| operation.binding.source == source.slot)
        }) {
            room.frontier_control = None;
        }
        if room.sources.len() == 0 {
            room.joined = false;
            room.local_id = None;
            room.sync_phase = None;
            for (_, s) in room.subscriptions.iter_mut() {
                s.keep_alive = false;
                s.renew_at = None;
                s.renew_operation = None;
            }
        }
        Ok(())
    }
    /// Configure a new local signing owner for a genuinely detached room with
    /// no live lease or unsettled original work. History retains its original
    /// author/session snapshots. This queues no OPEN/JOIN and proves no key
    /// possession; those require real original native and signature results.
    #[cfg(feature = "alloc")]
    pub fn configure_reopen(&mut self, room: Room<'id>, public: PublicKey) -> Result<(), Error> {
        let r = self.check_room(room)?;
        wire::PublicKey::new(&public)?;
        if self.mode != Mode::Client {
            return Err(Error::Permission);
        }
        let row = self.rooms.get(r)?;
        if row.phase != RoomPhase::Detached
            || row.sources.len() != 0
            || row.operations.iter().any(|(_, o)| {
                !matches!(
                    o.phase,
                    OperationPhase::Complete | OperationPhase::Failed | OperationPhase::Cancelled
                )
            })
        {
            return Err(Fault::NotReady.into());
        }
        let row = self.rooms.get_mut(r)?;
        row.local_public = Some(public);
        row.local_id = None;
        row.joined = false;
        row.sync_phase = None;
        // A known contact may have first appeared remotely in another room.
        // Local configuration records an owner selection, not verification;
        // exact source/member IDs and real signatures still grant all rights.
        for (_, contact) in self.contacts.iter_mut() {
            if contact.key == public {
                contact.local = true;
            }
        }
        Ok(())
    }
}
