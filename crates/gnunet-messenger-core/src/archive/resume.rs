//! Rebind an existing historical Active qualification only after a new original
//! actual source supplies a real verified signature in that old scope. This is
//! not a synthetic JOIN or an identity/source constructed by snapshot recovery.
use super::*;
impl<'id> Core<'id> {
    pub(crate) fn rebind_historical(&mut self, r: Slot, node: Slot) -> Result<bool, Error> {
        if self.mode != Mode::Service {
            return Err(Error::Permission);
        }
        let row = self.rooms.get(r)?;
        let n = row.nodes.get(node)?;
        if !n.resume_pending {
            return Ok(true);
        }
        let source = n.origin.require_live()?;
        self.check_source(source)?;
        let auth = n.auth.ok_or(Fault::Authentication)?;
        let slot = auth.session.ok_or(Fault::Authentication)?;
        let session = row.sessions.get(slot)?;
        if !session.archived {
            return Ok(true);
        }
        if session.historical_phase != SessionPhase::Active
            || session.successor.is_some()
            || session.public != auth.public
            || session.completed_at.is_some()
        {
            return Err(Error::Permission);
        }
        // The official protocol has no monotonically increasing timestamp
        // requirement. Preserve actual expiry/closing bounds elsewhere; valid
        // out-of-order or clock-rollback messages still get their real rebind
        // opportunity once this original in-scope parent is actually known.
        let Some(parent) = row
            .find_node(&n.parents[0])
            .and_then(|s| row.nodes.get(s).ok())
        else {
            return Ok(false);
        };
        if parent.auth.is_none()
            || !(crate::graph::epoch_kind(parent.kind) || crate::graph::known(session, parent))
        {
            return Ok(false);
        }
        self.reserve_events(1)?;
        let session = self.rooms.get_mut(r)?.sessions.get_mut(slot)?;
        session.archived = false;
        session.phase = SessionPhase::Active;
        session.historical_phase = SessionPhase::Active;
        self.rooms.get_mut(r)?.nodes.get_mut(node)?.resume_pending = false;
        self.event(Event::MemberChanged(
            self.member_id(r, slot),
            SessionPhase::Active,
        ))?;
        Ok(true)
    }
    /// Existing archived identity assignment for a real new local app OPEN.
    /// This only proposes an id. It neither activates membership nor bypasses a
    /// real signature on a fresh JOIN/continuation under the new physical source.
    pub fn historical_member_id(
        &self,
        room: Room<'id>,
        public: &PublicKey,
    ) -> Result<Option<ShortHash>, Error> {
        if self.mode != Mode::Service {
            return Err(Error::Permission);
        }
        let row = self.rooms.get(self.check_room(room)?)?;
        let mut selected = None;
        for (_, session) in row.sessions.iter() {
            if session.archived
                && session.historical_phase == SessionPhase::Active
                && session.successor.is_none()
                && session.public == *public
            {
                if selected.is_some_and(|old| old != session.id) {
                    return Err(Fault::Conflict.into());
                }
                selected = Some(session.id)
            }
        }
        Ok(selected)
    }
}
