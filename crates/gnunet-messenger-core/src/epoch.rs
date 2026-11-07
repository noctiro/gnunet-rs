//! Actual immutable membership epochs, tentative versus MAC-checked group
//! confirmations, bound key operations and safe successor-key invalidation.
use crate::{engine::Core, slots::Slots, state::*, *};
use alloc::vec::Vec;
use gnunet_types::Error as Fault;
use wire::{body::Body, message::Message, profile::Endian};
#[derive(Clone, Copy)]
pub(crate) enum EpochMutation<'id> {
    Join(Contact<'id>),
    Leave(Contact<'id>),
    Merge,
}
#[derive(Clone, Copy)]
pub(crate) struct Nonce {
    /// Original value value.
    pub value: ShortHash,
    /// Original message value.
    pub message: Hash,
}
#[cfg(test)]
pub(crate) fn identifier(profile: wire::profile::Profile, id: &ShortHash) -> (bool, u32) {
    identifier_order(profile.endian, id)
}
pub(crate) fn identifier_order(order: Endian, id: &ShortHash) -> (bool, u32) {
    match order {
        Endian::Little => (id[0] & 1 != 0, u32::from(id[0] >> 1)),
        Endian::Big => (id[0] & 0x80 != 0, u32::from(id[0] & 0x7f)),
    }
}
fn verified(group: &GroupRow<'_>) -> usize {
    group
        .confirmations
        .iter()
        .filter(|c| c.verified_mac)
        .count()
}
impl<'id> Core<'id> {
    pub(crate) fn epoch_message(
        &mut self,
        r: Slot,
        node: Slot,
        body: Body<'_>,
    ) -> Result<(), Error> {
        let n = self.rooms.get(r)?.nodes.get(node)?;
        let hash = n.hash;
        let source = n.origin.require_live()?;
        let (parents, mutation) = match body {
            Body::Join { epoch, .. } => (
                [*epoch, [0; 64]],
                EpochMutation::Join(
                    n.auth
                        .and_then(|a| a.owner)
                        .ok_or(Fault::Authentication)?
                        .contact,
                ),
            ),
            Body::Leave { epoch } => (
                [*epoch, [0; 64]],
                EpochMutation::Leave(
                    n.auth
                        .and_then(|a| a.owner)
                        .ok_or(Fault::Authentication)?
                        .contact,
                ),
            ),
            Body::Merge {
                first_epoch,
                second_epoch,
                ..
            } => ([*first_epoch, *second_epoch], EpochMutation::Merge),
            _ => return Err(Fault::InvalidInput.into()),
        };
        if parents.contains(&hash) {
            return Err(Fault::Malformed.into());
        }
        if self.rooms.get(r)?.find_epoch(&hash).is_none() {
            self.rooms.get(r)?.epochs.next_key()?;
            let lower = Slots::<GroupRow<'id>>::required_bytes(self.limits.groups_per_epoch)?
                .checked_add(
                    self.limits
                        .sessions_per_room
                        .checked_mul(core::mem::size_of::<Contact<'id>>())
                        .ok_or(Fault::Overflow)?,
                )
                .and_then(|n| {
                    self.limits
                        .nonce_per_epoch
                        .checked_mul(core::mem::size_of::<Nonce>())
                        .and_then(|b| n.checked_add(b))
                })
                .ok_or(Fault::Overflow)?;
            if lower > self.remaining_bytes() {
                return Err(Fault::Capacity.into());
            }
            let mut members = Vec::new();
            members
                .try_reserve_exact(self.limits.sessions_per_room)
                .map_err(|_| Fault::Capacity)?;
            let groups = Slots::new(self.limits.groups_per_epoch)?;
            let mut nonces = Vec::new();
            nonces
                .try_reserve_exact(self.limits.nonce_per_epoch)
                .map_err(|_| Fault::Capacity)?;
            let bytes = members
                .capacity()
                .checked_mul(core::mem::size_of::<Contact<'id>>())
                .and_then(|n| {
                    nonces
                        .capacity()
                        .checked_mul(core::mem::size_of::<Nonce>())
                        .and_then(|b| n.checked_add(b))
                })
                .and_then(|n| groups.bytes().ok().and_then(|b| n.checked_add(b)))
                .ok_or(Fault::Overflow)?;
            self.charge(bytes)?;
            let epoch = EpochRow {
                hash,
                parents,
                mutation,
                members,
                complete: false,
                groups,
                nonces,
                revision: 1,
                ephemeral: None,
                ephemeral_until: 0,
                best_announcement: None,
                best_group: None,
            };
            if let Err((e, _)) = self.rooms.get_mut(r)?.epochs.insert(epoch) {
                self.release(bytes)?;
                return Err(e);
            }
        }
        for p in parents {
            if p != [0; 64] && self.rooms.get(r)?.find_epoch(&p).is_none() {
                self.note_missing(r, p, source)?;
            }
        }
        self.refresh_epochs(r)?;
        Ok(())
    }
    pub(crate) fn refresh_epochs(&mut self, r: Slot) -> Result<(), Error> {
        // Every pass either completes an actual immutable snapshot or stops.
        // Iterative fixed slots avoid recursion on maliciously deep epoch DAGs.
        for _ in 0..self.limits.work_per_turn {
            if self.events.capacity().saturating_sub(self.events.len()) < 3 {
                break;
            }
            let next = self.rooms.get(r)?.epochs.iter().find_map(|(s, e)| {
                (!e.complete
                    && e.parents.iter().all(|h| {
                        *h == [0; 64]
                            || self
                                .rooms
                                .get(r)
                                .ok()
                                .and_then(|row| {
                                    row.find_epoch(h).and_then(|p| row.epochs.get(p).ok())
                                })
                                .is_some_and(|p| p.complete)
                    }))
                .then_some(s)
            });
            let Some(s) = next else {
                break;
            };
            self.reserve_events(1)?;
            let (parents, mutation, hash) = {
                let e = self.rooms.get(r)?.epochs.get(s)?;
                (e.parents, e.mutation, e.hash)
            };
            for p in parents {
                if p == [0; 64] {
                    continue;
                }
                let parent = self.rooms.get(r)?.find_epoch(&p).ok_or(Fault::NotReady)?;
                let count = self.rooms.get(r)?.epochs.get(parent)?.members.len();
                for i in 0..count {
                    let member = self.rooms.get(r)?.epochs.get(parent)?.members[i];
                    let e = self.rooms.get_mut(r)?.epochs.get_mut(s)?;
                    if !e.members.contains(&member) {
                        if e.members.len() == e.members.capacity() {
                            return Err(Fault::Capacity.into());
                        }
                        e.members.push(member);
                    }
                }
            }
            let e = self.rooms.get_mut(r)?.epochs.get_mut(s)?;
            match mutation {
                EpochMutation::Join(contact) => {
                    if !e.members.contains(&contact) {
                        if e.members.len() == e.members.capacity() {
                            return Err(Fault::Capacity.into());
                        }
                        e.members.push(contact);
                    }
                }
                EpochMutation::Leave(contact) => e.members.retain(|m| *m != contact),
                EpochMutation::Merge => {}
            }
            e.complete = true;
            let room = self.rooms.get_mut(r)?;
            if room.current_epoch == [0; 64] || parents.contains(&room.current_epoch) {
                room.current_epoch = hash;
            }
            room.queue_dependants(&hash)?;
            if let Some(node) = room.find_node(&hash) {
                room.queue_node(node)?;
            }
            self.event(Event::EpochChanged(self.event_room(r), hash))?;
        }
        Ok(())
    }
    fn available_epoch(&self, r: Slot, node: Slot) -> Result<Slot, Error> {
        let row = self.rooms.get(r)?;
        let n = row.nodes.get(node)?;
        let e = row.find_epoch(&n.epoch).ok_or(Fault::NotReady)?;
        let epoch = row.epochs.get(e)?;
        if !epoch.complete {
            return Err(Fault::NotReady.into());
        }
        let sender = n
            .auth
            .and_then(|a| a.owner)
            .ok_or(Fault::Authentication)?
            .contact;
        let local = row
            .local_session()
            .and_then(|s| row.sessions.get(s).ok())
            .map(|s| s.contact);
        if !epoch.members.contains(&sender) || !local.is_some_and(|c| epoch.members.contains(&c)) {
            return Err(Error::Permission);
        }
        Ok(e)
    }
    pub(crate) fn ensure_group(&mut self, r: Slot, e: Slot, id: ShortHash) -> Result<Slot, Error> {
        self.ensure_group_inner(r, e, id, true, Some(self.profile.endian))
    }
    pub(crate) fn ensure_record_group(
        &mut self,
        r: Slot,
        e: Slot,
        id: ShortHash,
        declared: Option<Endian>,
    ) -> Result<Slot, Error> {
        self.ensure_group_inner(r, e, id, false, declared)
    }
    fn ensure_group_inner(
        &mut self,
        r: Slot,
        e: Slot,
        id: ShortHash,
        derive: bool,
        declared: Option<Endian>,
    ) -> Result<Slot, Error> {
        if let Some((s, _)) = self
            .rooms
            .get(r)?
            .epochs
            .get(e)?
            .groups
            .iter()
            .find(|(_, g)| g.identifier == id)
        {
            return Ok(s);
        }
        let origin = self
            .known_identifier_order(r, &id)?
            .or(declared)
            .ok_or(Fault::NotReady)?;
        let (group, level) = identifier_order(origin, &id);
        let epoch = self.rooms.get(r)?.epochs.get(e)?;
        if !epoch.complete {
            return Err(Fault::NotReady.into());
        }
        let target = if group {
            1usize.checked_shl(level).ok_or(Fault::Overflow)?
        } else {
            epoch.members.len()
        };
        if target == 0 || target > self.limits.sessions_per_room || target > epoch.members.len() {
            return Err(Fault::InvalidInput.into());
        }
        epoch.groups.next_key()?;
        let (hash, parents) = (epoch.hash, epoch.parents);
        let mut derived = None;
        if derive {
            for p in parents {
                if let Some(parent) = self.rooms.get(r)?.find_epoch(&p) {
                    let old = self.rooms.get(r)?.epochs.get(parent)?;
                    if let Some((_, g)) = old.groups.iter().find(|(_, g)| {
                        g.identifier == id
                            && g.valid
                            && verified(g) == g.target
                            && g.key.is_some()
                            && g.confirmations
                                .iter()
                                .filter(|c| c.verified_mac)
                                .all(|c| epoch.members.contains(&c.contact))
                    }) {
                        derived = Some((
                            g.key
                                .as_ref()
                                .ok_or(Fault::NotReady)?
                                .derive_epoch(&hash, &id, group)?,
                            p,
                        ));
                        break;
                    }
                }
            }
        }
        let lower = target
            .checked_mul(core::mem::size_of::<Confirmation<'id>>())
            .ok_or(Fault::Overflow)?;
        if lower > self.remaining_bytes() {
            return Err(Fault::Capacity.into());
        }
        let mut confirmations = Vec::new();
        confirmations
            .try_reserve_exact(target)
            .map_err(|_| Fault::Capacity)?;
        let bytes = confirmations
            .capacity()
            .checked_mul(core::mem::size_of::<Confirmation<'id>>())
            .ok_or(Fault::Overflow)?;
        self.charge(bytes)?;
        let (key, derived_from) = match derived {
            Some((key, parent)) => (Some(key), Some((parent, id))),
            None => (None, None),
        };
        let phase = if key.is_some() {
            KeyPhase::Present
        } else {
            KeyPhase::Missing
        };
        let value = GroupRow {
            identifier: id,
            identifier_order: origin,
            target,
            valid: true,
            phase,
            key,
            confirmations,
            expires: u64::MAX,
            appeal: None,
            appeal_until: 0,
            proposal: None,
            generation: 1,
            derived_from,
        };
        let slot = match self
            .rooms
            .get_mut(r)?
            .epochs
            .get_mut(e)?
            .groups
            .insert(value)
        {
            Ok(s) => s,
            Err((error, _)) => {
                self.release(bytes)?;
                return Err(error);
            }
        };
        self.event(Event::KeyChanged(self.event_room(r), hash, id, phase))?;
        Ok(slot)
    }
    pub(crate) fn known_identifier_order(
        &self,
        r: Slot,
        id: &ShortHash,
    ) -> Result<Option<Endian>, Error> {
        let mut result = None;
        for (_, epoch) in self.rooms.get(r)?.epochs.iter() {
            for (_, group) in epoch.groups.iter() {
                if group.identifier == *id {
                    if result.is_some_and(|old| old != group.identifier_order) {
                        return Err(Error::AttributionConflict);
                    }
                    result = Some(group.identifier_order);
                }
            }
        }
        Ok(result)
    }
    pub(crate) fn identifier_bits(&self, r: Slot, id: &ShortHash) -> Result<(bool, u32), Error> {
        Ok(identifier_order(
            self.known_identifier_order(r, id)?.ok_or(Fault::NotReady)?,
            id,
        ))
    }
    fn message_identifier_order(
        &self,
        r: Slot,
        node: Slot,
        id: &ShortHash,
    ) -> Result<Endian, Error> {
        self.known_identifier_order(r, id)?
            .or(self.rooms.get(r)?.nodes.get(node)?.identifier_order)
            .ok_or_else(|| Fault::NotReady.into())
    }
    fn incoming_group(
        &mut self,
        r: Slot,
        e: Slot,
        node: Slot,
        id: ShortHash,
    ) -> Result<Slot, Error> {
        let order = self.message_identifier_order(r, node, &id)?;
        self.ensure_group_inner(r, e, id, true, Some(order))
    }
    pub(crate) fn epoch_control(
        &mut self,
        r: Slot,
        node: Slot,
        message: Message<'_>,
        now: u64,
    ) -> Result<(), Error> {
        if self.mode == Mode::Service {
            return Ok(());
        }
        if matches!(message.body(), Body::Authorization { .. }) {
            return Err(Error::AuthorizationMacOmitted);
        }
        let e = self.available_epoch(r, node)?;
        let (hash, auth, local, stamp, flags) = {
            let n = self.rooms.get(r)?.nodes.get(node)?;
            (
                n.hash,
                n.auth.ok_or(Fault::Authentication)?,
                n.local_sent,
                n.timestamp,
                n.meta.flags,
            )
        };
        let contact = auth.owner.ok_or(Fault::Authentication)?.contact;
        match message.body() {
            Body::Announcement {
                identifier: id,
                nonce,
                timeout,
                ..
            } => {
                let g = self.incoming_group(r, e, node, *id)?;
                let epoch = self.rooms.get(r)?.epochs.get(e)?;
                let group = epoch.groups.get(g)?;
                let mac = if let Some(key) = group.key.as_ref() {
                    crypto::group::verify_mac(message, key)?;
                    true
                } else {
                    false
                };
                if mac
                    && epoch
                        .nonces
                        .iter()
                        .any(|n| n.value == *nonce && n.message != hash)
                {
                    return Err(Fault::Replay.into());
                }
                if mac
                    && epoch.nonces.len() == epoch.nonces.capacity()
                    && !epoch.nonces.iter().any(|n| n.message == hash)
                {
                    return Err(Fault::Capacity.into());
                }
                if verified(group) == group.target
                    && !group.confirmations.iter().any(|c| c.contact == contact)
                {
                    return Err(Error::Permission);
                }
                if !group.confirmations.iter().any(|c| c.contact == contact)
                    && group.confirmations.len() == group.confirmations.capacity()
                {
                    return Err(Fault::Capacity.into());
                }
                let epoch = self.rooms.get_mut(r)?.epochs.get_mut(e)?;
                if mac && !epoch.nonces.iter().any(|n| n.message == hash) {
                    epoch.nonces.push(Nonce {
                        value: *nonce,
                        message: hash,
                    });
                }
                let group = epoch.groups.get_mut(g)?;
                let c = Confirmation {
                    contact,
                    message: hash,
                    verified_mac: mac,
                };
                if let Some(old) = group
                    .confirmations
                    .iter_mut()
                    .find(|c| c.contact == contact)
                {
                    *old = c;
                } else {
                    group.confirmations.push(c);
                }
                if local {
                    group.expires = stamp.saturating_add(timeout.as_micros());
                }
                self.select_groups(r, e)?;
            }
            Body::Appeal { event, timeout, .. } => {
                let original = self.reference(r, *event, node)?;
                let original = self.rooms.get(r)?.nodes.get(original)?;
                let Body::Announcement { identifier, .. } = original.body(self.profile)? else {
                    return Err(Fault::Malformed.into());
                };
                let id = *identifier;
                if self.identifier_bits(r, &id)?.0 {
                    return Err(Fault::InvalidInput.into());
                }
                let original_epoch = original.epoch;
                let g = self.incoming_group(r, e, node, id)?;
                if original_epoch != self.rooms.get(r)?.epochs.get(e)?.hash {
                    return Err(Error::AttributionConflict);
                }
                let group = self
                    .rooms
                    .get_mut(r)?
                    .epochs
                    .get_mut(e)?
                    .groups
                    .get_mut(g)?;
                if !group.confirmations.iter().any(|c| c.message == *event) {
                    return Err(Error::Permission);
                }
                if local {
                    group.appeal = Some(hash);
                    group.appeal_until = stamp.saturating_add(timeout.as_micros());
                }
            }
            Body::Access { event, .. } => {
                if flags & 8 == 0 {
                    return Err(Fault::NotReady.into());
                }
                let (id, recipient_event) = self.access_target(r, e, node, *event)?;
                let g = self.incoming_group(r, e, node, id)?;
                let epoch = self.rooms.get(r)?.epochs.get(e)?;
                let ephemeral = epoch.ephemeral.as_ref().ok_or(Fault::NotReady)?;
                if epoch.ephemeral_until <= now {
                    return Err(Fault::Timeout.into());
                }
                // The original appeal/partner must actually have advertised this
                // retained recipient public key, not just carried a local flag.
                let advertised = self
                    .rooms
                    .get(r)?
                    .nodes
                    .get(recipient_event)?
                    .body(self.profile)?;
                let expected = match advertised {
                    Body::Appeal { public_key, .. } | Body::Announcement { public_key, .. } => {
                        public_key
                    }
                    _ => return Err(Fault::Malformed.into()),
                };
                if ephemeral.public_key().as_bytes() != expected {
                    return Err(Error::Permission);
                }
                let key = crypto::group::open_access(message, ephemeral)?;
                self.install_group_key(r, e, g, key)?;
            }
            Body::Revolution {
                identifier: id,
                nonce,
                ..
            } => {
                let g = self.incoming_group(r, e, node, *id)?;
                let epoch = self.rooms.get(r)?.epochs.get(e)?;
                let group = epoch.groups.get(g)?;
                crypto::group::verify_mac(message, group.key.as_ref().ok_or(Fault::NotReady)?)?;
                if epoch.nonces.iter().any(|n| n.value == *nonce) {
                    return Err(Fault::Replay.into());
                }
                if epoch.nonces.len() == epoch.nonces.capacity() {
                    return Err(Fault::Capacity.into());
                }
                self.rooms
                    .get_mut(r)?
                    .epochs
                    .get_mut(e)?
                    .nonces
                    .push(Nonce {
                        value: *nonce,
                        message: hash,
                    });
                self.invalidate_group(r, e, g)?;
            }
            Body::Group {
                identifier: id,
                initiator,
                partner,
                timeout,
            } => {
                let (is_group, level) =
                    identifier_order(self.message_identifier_order(r, node, id)?, id);
                if !is_group || level == 0 {
                    return Err(Fault::InvalidInput.into());
                }
                let a = self.reference(r, *initiator, node)?;
                let b = self.reference(r, *partner, node)?;
                if a == b {
                    return Err(Fault::InvalidInput.into());
                }
                let row = self.rooms.get(r)?;
                let na = row.nodes.get(a)?;
                let nb = row.nodes.get(b)?;
                if na.auth.and_then(|a| a.owner).map(|a| a.contact) != Some(contact)
                    || na.epoch != row.epochs.get(e)?.hash
                    || nb.epoch != na.epoch
                {
                    return Err(Error::Permission);
                }
                let (ia, ib) = match (na.body(self.profile)?, nb.body(self.profile)?) {
                    (
                        Body::Announcement { identifier: a, .. },
                        Body::Announcement { identifier: b, .. },
                    ) => (*a, *b),
                    _ => return Err(Fault::Malformed.into()),
                };
                if ia == ib {
                    return Err(Fault::Conflict.into());
                }
                let ga = row
                    .epochs
                    .get(e)?
                    .groups
                    .iter()
                    .find_map(|(_, g)| (g.identifier == ia).then_some(g))
                    .ok_or(Fault::NotReady)?;
                let gb = row
                    .epochs
                    .get(e)?
                    .groups
                    .iter()
                    .find_map(|(_, g)| (g.identifier == ib).then_some(g))
                    .ok_or(Fault::NotReady)?;
                if !ga.valid
                    || !gb.valid
                    || ga.confirmations.len() != ga.target
                    || gb.confirmations.len() != gb.target
                    || ga.target != gb.target
                    || ga.target.checked_mul(2) != 1usize.checked_shl(level)
                    || ga
                        .confirmations
                        .iter()
                        .any(|a| gb.confirmations.iter().any(|b| a.contact == b.contact))
                {
                    return Err(Error::Permission);
                }
                let g = self.incoming_group(r, e, node, *id)?;
                let group = self
                    .rooms
                    .get_mut(r)?
                    .epochs
                    .get_mut(e)?
                    .groups
                    .get_mut(g)?;
                if group.proposal.is_some_and(|p| p != hash) {
                    return Err(Fault::Conflict.into());
                }
                group.proposal = Some(hash);
                group.expires = stamp.saturating_add(timeout.as_micros());
            }
            _ => return Err(Fault::InvalidInput.into()),
        }
        Ok(())
    }
    fn reference(&mut self, r: Slot, hash: Hash, from: Slot) -> Result<Slot, Error> {
        let row = self.rooms.get(r)?;
        if let Some(s) = row.find_node(&hash)
            && row.nodes.get(s)?.auth.is_some()
            && row.nodes.get(s)?.phase != MessagePhase::Deleted
        {
            return Ok(s);
        }
        let source = row.nodes.get(from)?.origin.require_live()?;
        self.note_missing(r, hash, source)?;
        Err(Fault::NotReady.into())
    }
    fn access_target(
        &mut self,
        r: Slot,
        e: Slot,
        node: Slot,
        event: Hash,
    ) -> Result<(ShortHash, Slot), Error> {
        let event = self.reference(r, event, node)?;
        let row = self.rooms.get(r)?;
        let ev = row.nodes.get(event)?;
        if ev.epoch != row.epochs.get(e)?.hash {
            return Err(Error::AttributionConflict);
        }
        match ev.body(self.profile)? {
            Body::Appeal {
                event: announcement,
                ..
            } => {
                if !ev.local_sent {
                    return Err(Error::Permission);
                }
                let announcement = *announcement;
                let a = self.reference(r, announcement, node)?;
                let row = self.rooms.get(r)?;
                let an = row.nodes.get(a)?;
                let Body::Announcement { identifier, .. } = an.body(self.profile)? else {
                    return Err(Fault::Malformed.into());
                };
                if self.identifier_bits(r, identifier)?.0 {
                    return Err(Fault::InvalidInput.into());
                }
                // The reply signer must actually be a known signed announcer;
                // recovered ACCESS plus announcement MACs prove key possession.
                let sender = row
                    .nodes
                    .get(node)?
                    .auth
                    .and_then(|a| a.owner)
                    .ok_or(Fault::Authentication)?
                    .contact;
                let group = row
                    .epochs
                    .get(e)?
                    .groups
                    .iter()
                    .find_map(|(_, g)| (g.identifier == *identifier).then_some(g))
                    .ok_or(Fault::NotReady)?;
                if !group.confirmations.iter().any(|c| c.contact == sender) {
                    return Err(Error::Permission);
                }
                Ok((*identifier, event))
            }
            Body::Group {
                identifier,
                initiator,
                partner,
                ..
            } => {
                let (id, init, part) = (*identifier, *initiator, *partner);
                let init = self.reference(r, init, node)?;
                let part = self.reference(r, part, node)?;
                let row = self.rooms.get(r)?;
                let proposal = row.nodes.get(event)?;
                let initial = row.nodes.get(init)?;
                let partner = row.nodes.get(part)?;
                let access = row.nodes.get(node)?;
                if proposal.auth.and_then(|a| a.owner).map(|a| a.contact)
                    != initial.auth.and_then(|a| a.owner).map(|a| a.contact)
                    || access.auth.and_then(|a| a.owner).map(|a| a.contact)
                        != proposal.auth.and_then(|a| a.owner).map(|a| a.contact)
                    || !partner.local_sent
                {
                    return Err(Error::Permission);
                }
                let Body::Announcement { .. } = partner.body(self.profile)? else {
                    return Err(Fault::Malformed.into());
                };
                Ok((id, part))
            }
            _ => Err(Fault::Malformed.into()),
        }
    }
    pub(crate) fn install_group_key(
        &mut self,
        r: Slot,
        e: Slot,
        g: Slot,
        key: crypto::AeadKey,
    ) -> Result<(), Error> {
        let group = self.rooms.get(r)?.epochs.get(e)?.groups.get(g)?;
        if !group.valid {
            return Err(Error::Permission);
        }
        if let Some(old) = group.key.as_ref() {
            if !old.constant_time_eq(&key) {
                return Err(Fault::Conflict.into());
            }
            return Ok(());
        }
        // Verify every tentative real announcement before counting it as a key
        // holder. Bad HMACs cannot consume nonce slots or confer membership.
        let count = group.confirmations.len();
        let mut i = 0;
        while i < count.min(
            self.rooms
                .get(r)?
                .epochs
                .get(e)?
                .groups
                .get(g)?
                .confirmations
                .len(),
        ) {
            let hash = self
                .rooms
                .get(r)?
                .epochs
                .get(e)?
                .groups
                .get(g)?
                .confirmations[i]
                .message;
            let node = self.rooms.get(r)?.find_node(&hash).ok_or(Fault::NotReady)?;
            let m = self.rooms.get(r)?.nodes.get(node)?.message(self.profile)?;
            let (nonce, passed) = match m.body() {
                Body::Announcement { nonce, .. } => {
                    (*nonce, crypto::group::verify_mac(m, &key).is_ok())
                }
                _ => return Err(Fault::Conflict.into()),
            };
            let epoch = self.rooms.get(r)?.epochs.get(e)?;
            let collision = epoch
                .nonces
                .iter()
                .any(|n| n.value == nonce && n.message != hash);
            if !passed || collision {
                self.rooms
                    .get_mut(r)?
                    .epochs
                    .get_mut(e)?
                    .groups
                    .get_mut(g)?
                    .confirmations
                    .remove(i);
                continue;
            }
            if !epoch.nonces.iter().any(|n| n.message == hash) {
                if epoch.nonces.len() == epoch.nonces.capacity() {
                    return Err(Fault::Capacity.into());
                }
                self.rooms
                    .get_mut(r)?
                    .epochs
                    .get_mut(e)?
                    .nonces
                    .push(Nonce {
                        value: nonce,
                        message: hash,
                    });
            }
            self.rooms
                .get_mut(r)?
                .epochs
                .get_mut(e)?
                .groups
                .get_mut(g)?
                .confirmations[i]
                .verified_mac = true;
            i += 1;
        }
        let epoch = self.rooms.get_mut(r)?.epochs.get_mut(e)?;
        let hash = epoch.hash;
        let group = epoch.groups.get_mut(g)?;
        group.key = Some(key);
        group.phase = KeyPhase::Present;
        group.generation = group.generation.checked_add(1).ok_or(Fault::Overflow)?;
        let id = group.identifier;
        epoch.revision = epoch.revision.checked_add(1).ok_or(Fault::Overflow)?;
        self.select_groups(r, e)?;
        self.rooms.get_mut(r)?.queue_dependants(&hash)?;
        self.event(Event::KeyChanged(
            self.event_room(r),
            hash,
            id,
            KeyPhase::Present,
        ))?;
        Ok(())
    }
    pub(crate) fn install_historical_key(
        &mut self,
        r: Slot,
        e: Slot,
        g: Slot,
        key: crypto::AeadKey,
    ) -> Result<(), Error> {
        self.reserve_events(2)?;
        let epoch = self.rooms.get(r)?.epochs.get(e)?;
        let group = epoch.groups.get(g)?;
        if let Some(old) = group.key.as_ref() {
            if !old.constant_time_eq(&key) {
                return Err(Fault::Conflict.into());
            }
            if !group.valid && group.phase == KeyPhase::Revoked {
                return Ok(());
            }
        }
        group.generation.checked_add(1).ok_or(Fault::Overflow)?;
        epoch.revision.checked_add(1).ok_or(Fault::Overflow)?;
        self.limits
            .epochs_per_room
            .checked_mul(self.limits.groups_per_epoch)
            .ok_or(Fault::Overflow)?;
        let hash = epoch.hash;
        // The actual AEAD-authenticated capability remains opaque and bounded
        // by existing fixed group storage. No Present/generation/send authority
        // is published before the direct invalid/historical transition.
        self.rooms
            .get_mut(r)?
            .epochs
            .get_mut(e)?
            .groups
            .get_mut(g)?
            .key = Some(key);
        self.invalidate_group(r, e, g)?;
        self.rooms.get_mut(r)?.queue_dependants(&hash)?;
        Ok(())
    }
    fn select_groups(&mut self, r: Slot, e: Slot) -> Result<(), Error> {
        let epoch = self.rooms.get(r)?.epochs.get(e)?;
        let mut announcement = None;
        let mut group = None;
        for (slot, g) in epoch.groups.iter() {
            if !g.valid || g.phase != KeyPhase::Present || g.key.is_none() {
                continue;
            }
            let target = if identifier_order(g.identifier_order, &g.identifier).0 {
                &mut group
            } else {
                &mut announcement
            };
            let better = target.is_none_or(|s| {
                epoch
                    .groups
                    .get(s)
                    .is_ok_and(|old| (verified(g), g.identifier) > (verified(old), old.identifier))
            });
            if better {
                *target = Some(slot);
            }
        }
        let e = self.rooms.get_mut(r)?.epochs.get_mut(e)?;
        e.best_announcement = announcement;
        e.best_group = group;
        Ok(())
    }
    fn invalidate_group(&mut self, r: Slot, e: Slot, g: Slot) -> Result<(), Error> {
        let epoch = self.rooms.get_mut(r)?.epochs.get_mut(e)?;
        let group = epoch.groups.get_mut(g)?;
        group.valid = false;
        // Keep the opaque capability for original historical ciphertext only;
        // valid=false forbids selection, new send and all successor derivation.
        group.phase = KeyPhase::Revoked;
        group.generation = group.generation.checked_add(1).ok_or(Fault::Overflow)?;
        epoch.revision = epoch.revision.checked_add(1).ok_or(Fault::Overflow)?;
        // Invalidate actual dependent ratchets transitively. No key bytes or
        // private hash identifiers are exported to implement this relationship.
        let maximum = self
            .limits
            .epochs_per_room
            .checked_mul(self.limits.groups_per_epoch)
            .ok_or(Fault::Overflow)?;
        for _ in 0..maximum {
            let next = self.rooms.get(r)?.epochs.iter().find_map(|(es, ep)| {
                ep.groups.iter().find_map(|(gs, gr)| {
                    let (parent, id) = gr.derived_from?;
                    if !gr.valid {
                        return None;
                    }
                    let old = self.rooms.get(r).ok()?.find_epoch(&parent)?;
                    let prior = self.rooms.get(r).ok()?.epochs.get(old).ok()?;
                    prior
                        .groups
                        .iter()
                        .find(|(_, p)| p.identifier == id)
                        .is_some_and(|(_, p)| !p.valid)
                        .then_some((es, gs))
                })
            });
            let Some((es, gs)) = next else {
                break;
            };
            let ep = self.rooms.get_mut(r)?.epochs.get_mut(es)?;
            let gr = ep.groups.get_mut(gs)?;
            gr.valid = false;
            gr.phase = KeyPhase::Revoked;
            ep.revision = ep.revision.checked_add(1).ok_or(Fault::Overflow)?;
        }
        self.select_groups(r, e)?;
        let epoch = self.rooms.get(r)?.epochs.get(e)?;
        self.event(Event::KeyChanged(
            self.event_room(r),
            epoch.hash,
            epoch.groups.get(g)?.identifier,
            KeyPhase::Revoked,
        ))?;
        Ok(())
    }
    pub(crate) fn revoke_confirmation(&mut self, r: Slot, hash: &Hash) -> Result<(), Error> {
        let target = self.rooms.get(r)?.epochs.iter().find_map(|(es, e)| {
            e.groups.iter().find_map(|(gs, g)| {
                g.confirmations
                    .iter()
                    .any(|c| c.message == *hash)
                    .then_some((es, gs))
            })
        });
        if let Some((e, g)) = target {
            let epoch = self.rooms.get_mut(r)?.epochs.get_mut(e)?;
            epoch
                .groups
                .get_mut(g)?
                .confirmations
                .retain(|c| c.message != *hash);
            epoch.revision = epoch.revision.checked_add(1).ok_or(Fault::Overflow)?;
            // Actual C deletion removes this announcement confirmation. A new
            // signed announcement may confirm the same identifier/key again;
            // only a real key-authenticated REVOLUTION revokes future use.
            self.select_groups(r, e)?;
        }
        Ok(())
    }
    pub(crate) fn expire_epochs(&mut self, r: Slot, now: u64) -> Result<(), Error> {
        for (_, e) in self.rooms.get_mut(r)?.epochs.iter_mut() {
            if e.ephemeral_until <= now {
                e.ephemeral = None;
            }
        }
        // Expiry stops proposals/access attempts; it does not erase an already
        // possessed shared key or claim a remote rotation was transmitted.
        for (_, e) in self.rooms.get_mut(r)?.epochs.iter_mut() {
            for (_, g) in e.groups.iter_mut() {
                if g.appeal_until <= now {
                    g.appeal = None;
                }
                if g.expires <= now {
                    g.proposal = None;
                }
            }
        }
        Ok(())
    }
    /// Actual epoch snapshot, without treating a carried unknown epoch as ready.
    pub fn epoch_members(&self, room: Room<'id>, hash: &Hash) -> Result<&[Contact<'id>], Error> {
        let row = self.rooms.get(self.check_room(room)?)?;
        let e = row
            .epochs
            .get(row.find_epoch(hash).ok_or(Fault::NotFound)?)?;
        if !e.complete {
            return Err(Fault::NotReady.into());
        }
        Ok(&e.members)
    }
    /// Observed group state. Tentative signatures are separately counted from
    /// real HMAC-checked holders; no private/shared key is returned.
    pub fn group_state(
        &self,
        room: Room<'id>,
        epoch: &Hash,
        id: &ShortHash,
    ) -> Result<(KeyPhase, usize, usize, usize, bool), Error> {
        let row = self.rooms.get(self.check_room(room)?)?;
        let e = row
            .epochs
            .get(row.find_epoch(epoch).ok_or(Fault::NotFound)?)?;
        let (_, g) = e
            .groups
            .iter()
            .find(|(_, g)| g.identifier == *id)
            .ok_or(Fault::NotFound)?;
        Ok((
            g.phase,
            g.confirmations.len(),
            verified(g),
            g.target,
            g.valid,
        ))
    }
}
