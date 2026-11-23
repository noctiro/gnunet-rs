//! Client-only epoch key processing. Hosted rooms retain the membership graph.
use super::*;

impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    pub(super) fn prepare_epoch_keys(
        &self,
        budget: usize,
    ) -> Result<(Slots<GroupRow>, Vec<Nonce>, usize), Error> {
        if !self.mode.is_client() {
            return Ok((Slots::empty(), Vec::new(), budget));
        }
        let group_limit = self.limits.groups_per_epoch;
        let nonce_limit = self.limits.nonce_per_epoch;
        let key_bytes = nonce_limit
            .checked_mul(core::mem::size_of::<Nonce>())
            .and_then(|n| n.checked_add(Slots::<GroupRow>::required_bytes(group_limit).ok()?))
            .ok_or(Fault::Overflow)?;
        if key_bytes > budget {
            return Err(Fault::Capacity.into());
        }
        let mut nonces = Vec::new();
        nonces
            .try_reserve_exact(nonce_limit)
            .map_err(|_| Fault::Capacity)?;
        let groups = Slots::new(group_limit)?;
        let used = nonces
            .capacity()
            .checked_mul(core::mem::size_of::<Nonce>())
            .and_then(|n| n.checked_add(groups.bytes().ok()?))
            .ok_or(Fault::Overflow)?;
        Ok((
            groups,
            nonces,
            budget.checked_sub(used).ok_or(Fault::Capacity)?,
        ))
    }

    /// Retained actual raw identifier creator order, independent from any new
    /// sender's profile. Absence is not a claim of a default host order.
    pub fn group_identifier_order(
        &self,
        room: Room<'id>,
        id: &ShortHash,
    ) -> Result<Option<Endian>, Error> {
        self.known_identifier_order(self.check_room(room)?, id)
    }

    /// Add one already MAC-checked nonce. Its immutable epoch obtains replay
    /// storage only when it first has something to retain.
    fn remember_nonce(&mut self, room: Slot, epoch: Slot, nonce: Nonce) -> Result<(), Error> {
        let limit = self.limits.nonce_per_epoch;
        let nonces = &self.rooms.get(room)?.epochs.get(epoch)?.nonces;
        if nonces.len() >= limit || nonces.capacity() != 0 && nonces.len() == nonces.capacity() {
            return Err(Fault::Capacity.into());
        }
        if nonces.capacity() == 0 {
            let bytes_for = |count: usize| {
                count
                    .checked_mul(core::mem::size_of::<Nonce>())
                    .ok_or(Fault::Overflow)
            };
            if bytes_for(limit)? > self.remaining_bytes() {
                return Err(Fault::Capacity.into());
            }
            let mut storage = Vec::new();
            storage
                .try_reserve_exact(limit)
                .map_err(|_| Fault::Capacity)?;
            self.charge(bytes_for(storage.capacity())?)?;
            self.rooms.get_mut(room)?.epochs.get_mut(epoch)?.nonces = storage;
        }
        self.rooms
            .get_mut(room)?
            .epochs
            .get_mut(epoch)?
            .nonces
            .push(nonce);
        Ok(())
    }
    pub(crate) fn available_epoch(&self, r: Slot, node: Slot) -> Result<Slot, Error> {
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
        if !row.epoch_has_member(epoch, sender)
            || !local.is_some_and(|c| row.epoch_has_member(epoch, c))
        {
            return Err(Error::Permission);
        }
        Ok(e)
    }
    pub(crate) fn ensure_group(&mut self, r: Slot, e: Slot, id: ShortHash) -> Result<Slot, Error> {
        self.ensure_group_inner(r, e, id, true, Some(self.profile.endian), false)
    }
    pub(crate) fn ensure_record_group(
        &mut self,
        r: Slot,
        e: Slot,
        id: ShortHash,
        order: Endian,
        revoked: bool,
    ) -> Result<Slot, Error> {
        self.ensure_group_inner(r, e, id, false, Some(order), revoked)
    }
    fn ensure_group_inner(
        &mut self,
        r: Slot,
        e: Slot,
        id: ShortHash,
        derive: bool,
        declared: Option<Endian>,
        revoked: bool,
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
        let room = self.rooms.get(r)?;
        let proposal = match room.group_proposal_position(e, &id) {
            Ok(index) => Some(room.nodes.get(room.group_proposals[index].node)?.hash),
            Err(_) => None,
        };
        // A reconstructed cohort may authenticate later announcements. Its
        // already retired GROUP exchange remains bound to the original event.
        let historical = revoked || proposal.is_some();
        let epoch = room.epochs.get(e)?;
        if !epoch.complete {
            return Err(Fault::NotReady.into());
        }
        let target = if group {
            1usize.checked_shl(level).ok_or(Fault::Overflow)?
        } else {
            room.epoch_member_count(epoch)
        };
        if target == 0
            || target > self.limits.sessions_per_room
            || target > room.epoch_member_count(epoch)
        {
            return Err(Fault::InvalidInput.into());
        }
        if !historical && epoch.active_group_count() >= self.limits.groups_per_epoch {
            return Err(Fault::Capacity.into());
        }
        let hash = epoch.hash;
        let derived = if derive {
            self.inherited_group_key(r, e, &id, origin)?
        } else {
            None
        };
        let lower = target
            .checked_mul(core::mem::size_of::<Confirmation>())
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
            .checked_mul(core::mem::size_of::<Confirmation>())
            .ok_or(Fault::Overflow)?;
        self.ensure_group_capacity(r, e, bytes)?;
        self.charge(bytes)?;
        let (key, derived_from) = match derived {
            Some((key, parent)) => (Some(key), Some((parent, id))),
            None => (None, None),
        };
        let phase = if revoked {
            KeyPhase::Revoked
        } else if key.is_some() {
            KeyPhase::Present
        } else {
            KeyPhase::Missing
        };
        let key_custody = if revoked || key.is_some() {
            GroupKeyCustody::Retained
        } else {
            GroupKeyCustody::Provisional
        };
        let value = GroupRow {
            identifier: id,
            identifier_order: origin,
            target,
            valid: !revoked,
            phase,
            key,
            key_custody,
            confirmations,
            expires: u64::MAX,
            appeal: None,
            appeal_until: 0,
            proposal,
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
        if historical {
            self.rooms.get_mut(r)?.epochs.get_mut(e)?.historical_groups += 1;
        }
        if !revoked {
            self.rooms.get_mut(r)?.derivation.arm();
            self.event(Event::KeyChanged(self.event_room(r), hash, id, phase))?;
        }
        Ok(slot)
    }
    pub(crate) fn known_identifier_order(
        &self,
        r: Slot,
        id: &ShortHash,
    ) -> Result<Option<Endian>, Error> {
        let room = self.rooms.get(r)?;
        let start = room
            .group_proposals
            .partition_point(|binding| binding.identifier < *id);
        let mut result = room
            .group_proposals
            .get(start)
            .filter(|binding| binding.identifier == *id)
            .map(|binding| binding.order);
        for (_, epoch) in room.epochs.iter() {
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
        self.ensure_group_inner(r, e, id, true, Some(order), false)
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
        let e = self.available_epoch(r, node)?;
        let (hash, auth, local, stamp, recent) = {
            let n = self.rooms.get(r)?.nodes.get(node)?;
            (
                n.hash,
                n.auth.ok_or(Fault::Authentication)?,
                n.local_sent,
                n.timestamp,
                n.frontier_recent,
            )
        };
        let contact = auth.owner.ok_or(Fault::Authentication)?.contact;
        match message.body() {
            Body::Announcement {
                identifier: id,
                nonce,
                ..
            } => {
                let g = self.incoming_group(r, e, node, *id)?;
                let key = self
                    .rooms
                    .get(r)?
                    .epochs
                    .get(e)?
                    .groups
                    .get(g)?
                    .key
                    .as_ref();
                let mac = if let Some(key) = key {
                    crypto::group::verify_mac(message, key)?;
                    self.retain_group_key(r, e, g)?;
                    true
                } else {
                    false
                };
                let epoch = self.rooms.get(r)?.epochs.get(e)?;
                let group = epoch.groups.get(g)?;
                if mac
                    && epoch
                        .nonces
                        .iter()
                        .any(|n| n.value == *nonce && n.message != hash)
                {
                    return Err(Fault::Replay.into());
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
                if mac && !epoch.nonces.iter().any(|n| n.message == hash) {
                    self.remember_nonce(
                        r,
                        e,
                        Nonce {
                            value: *nonce,
                            message: hash,
                        },
                    )?;
                }
                let epoch = self.rooms.get_mut(r)?.epochs.get_mut(e)?;
                let group = epoch.groups.get_mut(g)?;
                let was_incomplete = group.confirmations.len() < group.target;
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
                let completed = was_incomplete && group.confirmations.len() == group.target;
                let epoch_hash = epoch.hash;
                self.select_groups(r, e)?;
                self.rooms.get_mut(r)?.derivation.arm();
                if completed {
                    self.rooms.get_mut(r)?.queue_dependants(&epoch_hash)?;
                }
            }
            Body::Appeal { event, timeout, .. } => {
                let original = self.reference(r, *event, node)?;
                let original = self.rooms.get(r)?.nodes.get(original)?;
                let Body::Announcement { identifier, .. } = original.body(&self.frames)? else {
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
                if !recent {
                    return Err(Fault::NotReady.into());
                }
                let (id, recipient_event) = self.access_target(r, e, node, *event, now)?;
                let g = self.incoming_group(r, e, node, id)?;
                let epoch = self.rooms.get(r)?.epochs.get(e)?;
                let ephemeral = epoch.ephemeral.as_ref().ok_or(Fault::NotReady)?;
                if ephemeral.valid_until <= now {
                    return Err(Fault::Timeout.into());
                }
                // The original appeal/partner must actually have advertised this
                // retained recipient public key, not just carried a local flag.
                let advertised = self
                    .rooms
                    .get(r)?
                    .nodes
                    .get(recipient_event)?
                    .body(&self.frames)?;
                let expected = match advertised {
                    Body::Appeal { public_key, .. } | Body::Announcement { public_key, .. } => {
                        public_key
                    }
                    _ => return Err(Fault::Malformed.into()),
                };
                if ephemeral.public.as_bytes() != expected {
                    return Err(Error::Permission);
                }
                let key = crypto::group::open_access(message, &ephemeral.secret)?;
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
                self.retain_group_key(r, e, g)?;
                let epoch = self.rooms.get(r)?.epochs.get(e)?;
                if epoch.nonces.iter().any(|n| n.value == *nonce) {
                    return Err(Fault::Replay.into());
                }
                self.remember_nonce(
                    r,
                    e,
                    Nonce {
                        value: *nonce,
                        message: hash,
                    },
                )?;
                self.invalidate_group(r, e, g)?;
            }
            Body::Authorization {
                identifier, event, ..
            } => {
                self.apply_authorization(r, e, node, message, *identifier, *event, contact, now)?
            }
            Body::Group {
                identifier: id,
                initiator,
                partner,
                timeout,
            } => {
                let order = self.message_identifier_order(r, node, id)?;
                let (is_group, level) = identifier_order(order, id);
                if !is_group || level == 0 {
                    return Err(Fault::InvalidInput.into());
                }
                let expires = stamp
                    .checked_add(timeout.as_micros())
                    .filter(|expires| *expires != u64::MAX)
                    .ok_or(Fault::Overflow)?;
                if now >= expires {
                    return Err(Fault::Timeout.into());
                }
                let room = self.rooms.get(r)?;
                let position = match room.group_proposal_position(e, id) {
                    Ok(position) if room.group_proposals[position].node != node => {
                        return Err(Fault::Conflict.into());
                    }
                    Ok(_) => {
                        let still_active = room.epochs.get(e)?.groups.iter().any(|(_, group)| {
                            group.identifier == *id
                                && group.valid
                                && group.proposal == Some(hash)
                                && group.expires == expires
                        });
                        return if still_active {
                            Ok(())
                        } else {
                            Err(Fault::Timeout.into())
                        };
                    }
                    Err(position) => position,
                };
                let a = self.reference(r, *initiator, node)?;
                let b = self.reference(r, *partner, node)?;
                if a == b {
                    return Err(Fault::InvalidInput.into());
                }
                self.check_group_parents(r, e, level, [a, b], contact)?;
                self.reserve_group_proposal(r)?;
                let g = self.incoming_group(r, e, node, *id)?;
                let room = self.rooms.get_mut(r)?;
                let group = room.epochs.get_mut(e)?.groups.get_mut(g)?;
                if !group.valid {
                    return Err(Error::Permission);
                }
                group.proposal = Some(hash);
                group.expires = expires;
                room.group_proposals.insert(
                    position,
                    GroupProposalBinding {
                        identifier: *id,
                        epoch: e,
                        node,
                        order,
                    },
                );
                if local
                    && let Some(attempt) = room
                        .automatic_proposal
                        .as_mut()
                        .filter(|attempt| attempt.event == hash)
                {
                    attempt.expires = attempt
                        .expires
                        .min(now.saturating_add(GROUP_PROPOSAL_RETRY_MICROS));
                }
            }
            _ => return Err(Fault::InvalidInput.into()),
        }
        Ok(())
    }
    pub(super) fn reference(&mut self, r: Slot, hash: Hash, from: Slot) -> Result<Slot, Error> {
        let row = self.rooms.get(r)?;
        if let Some(s) = row.find_node(&hash) {
            let node = row.nodes.get(s)?;
            if node.kind == Kind::GROUP && node.phase == MessagePhase::Deleted {
                return Err(Error::Permission);
            }
            if node.auth.is_some() && node.phase != MessagePhase::Deleted {
                return Ok(s);
            }
        }
        let source = row.nodes.get(from)?.origin.require_live(self.instance)?;
        self.note_dependency(r, hash, source)?;
        Err(Fault::NotReady.into())
    }
    fn access_target(
        &mut self,
        r: Slot,
        e: Slot,
        node: Slot,
        event: Hash,
        now: u64,
    ) -> Result<(ShortHash, Slot), Error> {
        let event = self.reference(r, event, node)?;
        let row = self.rooms.get(r)?;
        let ev = row.nodes.get(event)?;
        if ev.epoch != row.epochs.get(e)?.hash {
            return Err(Error::AttributionConflict);
        }
        match ev.body(&self.frames)? {
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
                let Body::Announcement { identifier, .. } = an.body(&self.frames)? else {
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
                if now >= self.group_proposal_deadline(r, e, id, ev.hash)? {
                    return Err(Fault::Timeout.into());
                }
                let epoch = row.epochs.get(e)?;
                let group = epoch
                    .groups
                    .iter()
                    .find_map(|(_, group)| (group.identifier == id && group.valid).then_some(group))
                    .ok_or(Fault::NotReady)?;
                let (is_group, level) = identifier_order(group.identifier_order, &id);
                if !is_group {
                    return Err(Error::Permission);
                }
                let init = self.reference(r, init, node)?;
                let part = self.reference(r, part, node)?;
                let row = self.rooms.get(r)?;
                let proposal = row.nodes.get(event)?;
                let partner = row.nodes.get(part)?;
                let access = row.nodes.get(node)?;
                let proposer = proposal
                    .auth
                    .and_then(|a| a.owner)
                    .ok_or(Fault::Authentication)?;
                if access.auth.and_then(|a| a.owner).map(|a| a.contact) != Some(proposer.contact)
                    || !partner.local_sent
                    || partner.auth.and_then(|a| a.owner).map(|a| a.contact)
                        != row.local_session().and_then(|session| {
                            row.sessions
                                .get(session)
                                .ok()
                                .map(|session| session.contact)
                        })
                {
                    return Err(Error::Permission);
                }
                self.check_group_parents(r, e, level, [init, part], proposer.contact)?;
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
        self.install_group_key_from(r, e, g, key, None)
    }
    pub(super) fn install_group_key_from(
        &mut self,
        r: Slot,
        e: Slot,
        g: Slot,
        key: crypto::AeadKey,
        parent: Option<Hash>,
    ) -> Result<(), Error> {
        let group = self.rooms.get(r)?.epochs.get(e)?.groups.get(g)?;
        if !group.valid {
            return Err(Error::Permission);
        }
        if let Some(old) = group.key.as_ref() {
            if !old.constant_time_eq(&key) {
                return Err(Fault::Conflict.into());
            }
            return self.retain_group_key(r, e, g);
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
            let m = self.rooms.get(r)?.nodes.get(node)?.message(&self.frames)?;
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
                self.remember_nonce(
                    r,
                    e,
                    Nonce {
                        value: nonce,
                        message: hash,
                    },
                )?;
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
        let generation = group.generation.checked_add(1).ok_or(Fault::Overflow)?;
        let revision = epoch.revision.checked_add(1).ok_or(Fault::Overflow)?;
        let id = group.identifier;
        group.derived_from = parent.map(|hash| (hash, id));
        group.key = Some(key);
        group.key_custody = GroupKeyCustody::Retained;
        group.phase = KeyPhase::Present;
        group.generation = generation;
        epoch.revision = revision;
        self.rooms.get_mut(r)?.derivation.arm();
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
        self.group_rows_in_room(r)?;
        let hash = epoch.hash;
        // The actual AEAD-authenticated capability stays under the original
        // storage budget. No live key authority precedes historical installation.
        let group = self
            .rooms
            .get_mut(r)?
            .epochs
            .get_mut(e)?
            .groups
            .get_mut(g)?;
        group.key = Some(key);
        group.key_custody = GroupKeyCustody::Retained;
        self.invalidate_group(r, e, g)?;
        self.rooms.get_mut(r)?.queue_dependants(&hash)?;
        Ok(())
    }
    fn select_groups(&mut self, r: Slot, e: Slot) -> Result<(), Error> {
        Self::select_epoch_groups(self.rooms.get_mut(r)?.epochs.get_mut(e)?);
        Ok(())
    }

    fn select_epoch_groups(epoch: &mut EpochRow) {
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
        epoch.best_announcement = announcement;
        epoch.best_group = group;
    }
    fn invalidate_group(&mut self, r: Slot, e: Slot, g: Slot) -> Result<(), Error> {
        let maximum = self.group_rows_in_room(r)?;
        let epoch = self.rooms.get_mut(r)?.epochs.get_mut(e)?;
        let group = epoch.groups.get_mut(g)?;
        if !group.historical() {
            epoch.historical_groups += 1;
        }
        group.valid = false;
        // Keep the opaque capability for original historical ciphertext only;
        // valid=false forbids selection, new send and all successor derivation.
        group.phase = KeyPhase::Revoked;
        group.generation = group.generation.checked_add(1).ok_or(Fault::Overflow)?;
        epoch.revision = epoch.revision.checked_add(1).ok_or(Fault::Overflow)?;
        // Invalidate actual dependent ratchets transitively. No key bytes or
        // private hash identifiers are exported to implement this relationship.
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
            if !gr.historical() {
                ep.historical_groups += 1;
            }
            gr.valid = false;
            gr.phase = KeyPhase::Revoked;
            ep.revision = ep.revision.checked_add(1).ok_or(Fault::Overflow)?;
            if ep.best_group == Some(gs) || ep.best_announcement == Some(gs) {
                Self::select_epoch_groups(ep);
            }
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
    fn group_rows_in_room(&self, r: Slot) -> Result<usize, Error> {
        self.rooms
            .get(r)?
            .epochs
            .iter()
            .try_fold(0usize, |count, (_, epoch)| {
                count
                    .checked_add(epoch.groups.len())
                    .ok_or_else(|| Fault::Overflow.into())
            })
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
        let client = self.mode.is_client();
        let room = self.rooms.get_mut(r)?;
        if room
            .automatic_proposal
            .is_some_and(|proposal| proposal.epoch != room.current_epoch || proposal.expires <= now)
        {
            room.automatic_proposal = None;
        }
        // Expiry stops proposals/access attempts; it does not erase an already
        // possessed shared key or claim a remote rotation was transmitted.
        let mut released = 0usize;
        let operations = &room.operations;
        for (_, epoch) in room.epochs.iter_mut() {
            if epoch.ephemeral_at(now).is_none() {
                epoch.ephemeral = None;
            }
            let mut reselection = false;
            for index in 0..epoch.groups.limit() {
                let Some(slot) = epoch.groups.slot_at(index) else {
                    continue;
                };
                let group = epoch.groups.get_mut(slot)?;
                if group.appeal_until <= now {
                    group.appeal = None;
                }
                if group.expires != u64::MAX && group.expires <= now {
                    if group.proposal.is_some() && !group.historical() {
                        epoch.historical_groups += 1;
                    }
                    group.expires = u64::MAX;
                }
                let disposable = match group.phase {
                    KeyPhase::Missing => group.key.is_none(),
                    KeyPhase::Present => group.key_custody == GroupKeyCustody::Provisional,
                    _ => false,
                };
                if client
                    && group.proposal.is_some()
                    && group.expires == u64::MAX
                    && group.valid
                    && disposable
                    && group.confirmations.is_empty()
                    && group.appeal.is_none()
                    && group.derived_from.is_none()
                    && !operations.iter().any(|(_, operation)| {
                        operation.binding.epoch == epoch.hash
                            && operation.group_keys.contains(&Some(slot))
                            && !matches!(
                                operation.phase,
                                OperationPhase::Complete
                                    | OperationPhase::Cancelled
                                    | OperationPhase::Failed
                            )
                    })
                {
                    // The identifier stays bound to the original GROUP. Any
                    // discarded key remained private to this local proposal.
                    let bytes = group
                        .confirmations
                        .capacity()
                        .checked_mul(core::mem::size_of::<Confirmation>())
                        .ok_or(Fault::Overflow)?;
                    released = released.checked_add(bytes).ok_or(Fault::Overflow)?;
                    reselection |= epoch.best_group == Some(slot);
                    epoch.groups.remove(slot)?;
                    epoch.historical_groups -= 1;
                }
            }
            if reselection {
                Self::select_epoch_groups(epoch);
            }
        }
        self.release(released)
    }
    /// Group state counts tentative signatures separately from HMAC-checked
    /// holders. The key stays with its owner.
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
