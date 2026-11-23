//! Original epoch, wrapping-group and referenced-event authority for key transfers.
use super::*;

impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    fn authorization_target(
        &self,
        r: Slot,
        e: Slot,
        identifier: ShortHash,
        event: Slot,
        sender: Slot,
    ) -> Result<(Slot, Option<Slot>, u64), Error> {
        let row = self.rooms.get(r)?;
        let epoch = row.epochs.get(e)?;
        let original = row.nodes.get(event)?;
        if original.epoch != epoch.hash || original.phase == MessagePhase::Deleted {
            return Err(Error::AttributionConflict);
        }
        original.auth.ok_or(Fault::Authentication)?;
        let wrapper = epoch
            .groups
            .iter()
            .find_map(|(_, g)| (g.identifier == identifier && g.valid).then_some(g))
            .ok_or(Fault::NotReady)?;
        let (is_group, wrapping_level) = identifier_order(wrapper.identifier_order, &identifier);
        if !is_group {
            return Err(Error::Permission);
        }
        let (target_id, announcement) = match original.body(&self.frames)? {
            Body::Announcement {
                identifier: target, ..
            } => (*target, Some(event)),
            Body::Group {
                identifier: target,
                initiator,
                partner,
                ..
            } => {
                let selected =
                    if original.auth.and_then(|a| a.owner).map(|a| a.contact) == Some(sender) {
                        initiator
                    } else {
                        partner
                    };
                let reference = row
                    .nodes
                    .get(row.find_node(selected).ok_or(Fault::NotReady)?)?;
                if reference.epoch != epoch.hash || reference.phase == MessagePhase::Deleted {
                    return Err(Error::AttributionConflict);
                }
                reference.auth.ok_or(Fault::Authentication)?;
                let Body::Announcement {
                    identifier: parent, ..
                } = reference.body(&self.frames)?
                else {
                    return Err(Fault::Malformed.into());
                };
                if *parent != identifier {
                    return Err(Error::Permission);
                }
                (*target, None)
            }
            _ => return Err(Fault::InvalidInput.into()),
        };
        if target_id == identifier {
            return Err(Error::Permission);
        }
        let target = epoch
            .groups
            .iter()
            .find(|(_, g)| g.identifier == target_id && g.valid);
        if let Some((_, group)) = target {
            let (is_group, target_level) = identifier_order(group.identifier_order, &target_id);
            if is_group && wrapping_level.checked_add(1) != Some(target_level)
                || !is_group && announcement.is_none()
            {
                return Err(Error::Permission);
            }
        }
        let deadline = if announcement.is_none() {
            self.group_proposal_deadline(r, e, target_id, original.hash)?
        } else {
            u64::MAX
        };
        let (target, group) = target.ok_or(Fault::NotReady)?;
        if announcement.is_some()
            && !group
                .confirmations
                .iter()
                .any(|c| c.message == original.hash)
        {
            return Err(Error::Permission);
        }
        Ok((target, announcement, deadline))
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Original epoch, message and authenticated sender are explicit authority inputs"
    )]
    pub(super) fn apply_authorization(
        &mut self,
        r: Slot,
        e: Slot,
        node: Slot,
        message: Message<'_>,
        identifier: ShortHash,
        event: Hash,
        sender: Slot,
        now: u64,
    ) -> Result<(), Error> {
        let source = self
            .rooms
            .get(r)?
            .nodes
            .get(node)?
            .origin
            .require_live(self.instance)?;
        self.check_source(source)?;
        let referenced = self.reference(r, event, node)?;
        let (target, announcement, deadline) =
            self.authorization_target(r, e, identifier, referenced, sender)?;
        if now >= deadline {
            return Err(Fault::Timeout.into());
        }
        let row = self.rooms.get(r)?;
        let epoch = row.epochs.get(e)?;
        let (wrapping, group) = epoch
            .groups
            .iter()
            .find(|(_, g)| g.identifier == identifier && g.valid && g.phase == KeyPhase::Present)
            .ok_or(Fault::NotReady)?;
        let key =
            crypto::group::open_authorization(message, group.key.as_ref().ok_or(Fault::NotReady)?)?;
        self.retain_group_key(r, e, wrapping)?;
        if let Some(announcement) = announcement {
            let announced = self
                .rooms
                .get(r)?
                .nodes
                .get(announcement)?
                .message(&self.frames)?;
            crypto::group::verify_mac(announced, &key)?;
        }
        self.install_group_key(r, e, target, key)
    }

    pub(crate) fn authorization_fields(
        &self,
        source: Source<'id>,
        member: MemberSession<'id>,
        identifier: ShortHash,
        event: Hash,
    ) -> Result<(crypto::group::Authorization, u64), Error> {
        let row = self.rooms.get(source.room)?;
        let event = row.find_node(&event).ok_or(Fault::NotFound)?;
        let original = row.nodes.get(event)?;
        let e = row.find_epoch(&original.epoch).ok_or(Fault::NotReady)?;
        let epoch = row.epochs.get(e)?;
        let sender = row.sessions.get(member.slot)?.contact;
        if !epoch.complete
            || epoch.hash != row.current_epoch
            || !row.epoch_has_member(epoch, sender)
        {
            return Err(Fault::NotReady.into());
        }
        let (target, announcement, deadline) =
            self.authorization_target(source.room, e, identifier, event, sender)?;
        let wrapping = epoch
            .groups
            .iter()
            .find_map(|(_, g)| {
                (g.identifier == identifier && g.valid && g.phase == KeyPhase::Present).then_some(g)
            })
            .ok_or(Fault::NotReady)?;
        let target = epoch.groups.get(target)?;
        if target.phase != KeyPhase::Present {
            return Err(Fault::NotReady.into());
        }
        let key = target.key.as_ref().ok_or(Fault::NotReady)?;
        if let Some(announcement) = announcement {
            crypto::group::verify_mac(row.nodes.get(announcement)?.message(&self.frames)?, key)?;
        }
        Ok((
            crypto::group::Authorization::seal(
                &identifier,
                &original.hash,
                wrapping.key.as_ref().ok_or(Fault::NotReady)?,
                key,
            )?,
            deadline,
        ))
    }
}

#[cfg(test)]
mod tests;
