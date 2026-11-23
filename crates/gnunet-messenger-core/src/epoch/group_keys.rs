//! Original group-key uses carried from a signed draft through native writing.
use super::*;

impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    pub(in crate::epoch) fn retain_group_key(
        &mut self,
        room: Slot,
        epoch: Slot,
        group: Slot,
    ) -> Result<(), Error> {
        self.rooms
            .get_mut(room)?
            .epochs
            .get_mut(epoch)?
            .groups
            .get_mut(group)?
            .key_custody = GroupKeyCustody::Retained;
        Ok(())
    }

    pub(crate) fn group_keys_for_message(
        &self,
        room: &RoomRow<'id>,
        epoch: &Hash,
        body: Body<'_>,
    ) -> Result<[Option<Slot>; 2], Error> {
        if self.mode != Mode::Client {
            return Ok([None; 2]);
        }
        let original = |event: &Hash| {
            let node = room
                .nodes
                .get(room.find_node(event).ok_or(Fault::NotReady)?)?;
            if node.epoch != *epoch || node.phase == MessagePhase::Deleted {
                return Err(Error::AttributionConflict);
            }
            node.body(&self.frames)
        };
        let identifier = |body| match body {
            Body::Group { identifier, .. } | Body::Announcement { identifier, .. } => {
                Ok(identifier)
            }
            _ => Err(Error::Protocol(Fault::Malformed)),
        };
        let (first, second) = match body {
            Body::Announcement { identifier, .. } | Body::Revolution { identifier, .. } => {
                (identifier, None)
            }
            Body::Access { event, .. } => {
                let target = match original(event)? {
                    Body::Appeal { event, .. } => original(event)?,
                    other => other,
                };
                (identifier(target)?, None)
            }
            Body::Authorization {
                identifier: wrapper,
                event,
                ..
            } => (wrapper, Some(identifier(original(event)?)?)),
            _ => return Ok([None; 2]),
        };
        let epoch = room
            .epochs
            .get(room.find_epoch(epoch).ok_or(Fault::NotReady)?)?;
        let find = |id: &ShortHash| {
            epoch
                .groups
                .iter()
                .find_map(|(slot, group)| (group.identifier == *id).then_some(slot))
                .ok_or(Fault::NotReady)
        };
        Ok([Some(find(first)?), second.map(find).transpose()?])
    }

    pub(crate) fn retain_written_group_keys(
        &mut self,
        binding: Binding<'id>,
        keys: [Option<Slot>; 2],
    ) -> Result<(), Error> {
        if keys == [None; 2] {
            return Ok(());
        }
        let room = self.rooms.get_mut(binding.source.room)?;
        let e = room
            .find_epoch(&binding.epoch)
            .ok_or(Fault::StaleGeneration)?;
        let epoch = room.epochs.get_mut(e)?;
        for group in keys.into_iter().flatten() {
            epoch.groups.get_mut(group)?.key_custody = GroupKeyCustody::Retained;
        }
        Ok(())
    }
}
