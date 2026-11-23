//! One actual bounded protocol action per owner turn. This uses official full
//! epoch ANNOUNCEMENT/APPEAL/ACCESS profile for full-room distribution.
use crate::{engine::Core, state::*, *};
use gnunet_types::Error as Fault;
use wire::{body::Body, envelope::Kind};
mod groups;
impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    fn announcement_deadline(
        &self,
        room: &RoomRow<'id>,
        epoch: &EpochRow,
        confirmation: &Confirmation,
        now: u64,
        own: bool,
    ) -> Option<u64> {
        let node = room
            .find_node(&confirmation.message)
            .and_then(|slot| room.nodes.get(slot).ok())?;
        if !node.complete
            || !node.semantic_applied
            || node.epoch != epoch.hash
            || node.auth.and_then(|a| a.owner).map(|owner| owner.contact)
                != Some(confirmation.contact)
            || matches!(node.phase, MessagePhase::Deleted | MessagePhase::Rejected)
        {
            return None;
        }
        let Ok(Body::Announcement {
            public_key,
            timeout,
            ..
        }) = node.body(&self.frames)
        else {
            return None;
        };
        let deadline = node.timestamp.saturating_add(timeout.as_micros());
        let deadline = if own {
            let key = epoch.ephemeral_at(now)?;
            if !confirmation.verified_mac || !node.local_sent || key.public.as_bytes() != public_key
            {
                return None;
            }
            deadline.min(key.valid_until)
        } else {
            deadline
        };
        (deadline > now).then_some(deadline)
    }

    /// Advance current full-room key distribution by at most one actual job.
    /// The caller first applies notifications with advance(), feeds real signer/
    /// key results, and writes only take_work() ownership on its original source.
    /// None means waiting/no action; it does not declare a published key/session.
    ///
    /// The reference consumer accepts a direct non-group epoch announcement:
    /// unknown members request it through APPEAL and receive real HPKE ACCESS.
    /// This driver also advances admitted GROUP proposals for their original
    /// participants through key generation, distribution and confirmation.
    pub fn drive_epoch(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        entropy: &mut impl crypto::Entropy,
        now: u64,
        deadline: u64,
    ) -> Result<Option<Operation<'id>>, Error> {
        self.drive_epoch_with_group_keys(source, member, entropy, now, deadline, false)
    }

    /// Advance epoch distribution and optionally originate GROUP proposals in
    /// private rooms using the current epoch's original announcements.
    /// Disabling origination still permits an admitted proposal to finish.
    pub fn drive_epoch_with_group_keys(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        entropy: &mut impl crypto::Entropy,
        now: u64,
        deadline: u64,
        group_keys: bool,
    ) -> Result<Option<Operation<'id>>, Error> {
        self.check_source(source)?;
        self.check_member(member)?;
        if !self.source_joined(source)? {
            return Err(Fault::NotReady.into());
        }
        let r = source.room;
        if r != member.room || self.mode != Mode::Client {
            return Err(Error::Permission);
        }
        let row = self.rooms.get(r)?;
        let session = row.sessions.get(member.slot)?;
        if row.local_session() != Some(member.slot) || !row.joined {
            return Err(Fault::NotReady.into());
        }
        let contact = session.contact;
        if row.frontier_control.is_some() {
            return Ok(None);
        }
        if let Some(operation) =
            self.drive_historical_keys(source, member, entropy, now, deadline)?
        {
            return Ok(Some(operation));
        }
        let row = self.rooms.get(r)?;
        let epoch_hash = row.current_epoch;
        let e = row.find_epoch(&epoch_hash).ok_or(Fault::NotReady)?;
        let epoch = row.epochs.get(e)?;
        if !epoch.complete || !row.epoch_has_member(epoch, contact) {
            return Err(Error::Permission);
        }
        // A real outstanding provider/signature/whole-write echo remains the
        // original operation. The driver does not enqueue duplicates every poll.
        if row.operations.iter().any(|(_, o)| {
            o.binding.source == source.slot
                && o.binding.epoch == epoch_hash
                && !matches!(
                    o.phase,
                    OperationPhase::Complete | OperationPhase::Cancelled | OperationPhase::Failed
                )
        }) {
            return Ok(None);
        }
        if epoch.ephemeral_at(now).is_none() {
            let until = now.checked_add(60_000_000).ok_or(Fault::Overflow)?;
            return self
                .request_ephemeral_key(source, member, epoch_hash, until, now, deadline)
                .map(Some);
        }
        // Respond only to a real applied original appeal for an actual local
        // key. Replies are suppressed by retained actual sent ACCESS vertices,
        // so retiring a local operation cannot make its response disappear.
        let appeal = row.nodes.iter().find_map(|(_, n)| {
            if !n.semantic_applied
                || n.semantic_kind != Kind::APPEAL
                || n.epoch != epoch_hash
                || n.phase == MessagePhase::Deleted
                || n.local_sent
            {
                return None;
            }
            if row.nodes.iter().any(|(_, reply)| {
                reply.local_sent
                    && reply.semantic_kind == Kind::ACCESS
                    && reply.references[0] == n.hash
            }) {
                return None;
            }
            let Body::Appeal { event, .. } = n.body(&self.frames).ok()? else {
                return None;
            };
            let original = row.nodes.get(row.find_node(event)?).ok()?;
            let Body::Announcement { identifier: id, .. } = original.body(&self.frames).ok()?
            else {
                return None;
            };
            if self.identifier_bits(r, id).ok()?.0 {
                return None;
            }
            epoch
                .groups
                .iter()
                .any(|(_, g)| {
                    g.identifier == *id
                        && g.valid
                        && g.phase == KeyPhase::Present
                        && g.confirmations
                            .iter()
                            .any(|c| c.contact == contact && c.verified_mac)
                })
                .then_some(n.hash)
        });
        if let Some(event) = appeal {
            return self
                .prepare_access(source, member, event, entropy, now, deadline)
                .map(Some);
        }
        if let Some(operation) = self.drive_groups(source, member, entropy, now, deadline)? {
            return Ok(Some(operation));
        }
        let row = self.rooms.get(r)?;
        let epoch = row.epochs.get(e)?;
        // First recover keys required by actual current-epoch authenticated
        // ciphertext. Candidate selection alone never confers key authority.
        let needed = row.nodes.iter().find_map(|(_, n)| {
            if n.epoch != epoch_hash
                || n.auth.is_none()
                || n.plaintext.is_some()
                || matches!(n.phase, MessagePhase::Deleted | MessagePhase::Rejected)
            {
                return None;
            }
            let Body::Secret { identifier: id, .. } = n.message(&self.frames).ok()?.body() else {
                return None;
            };
            let (_, g) = epoch.groups.iter().find(|(_, g)| {
                g.identifier == *id
                    && g.key.is_none()
                    && g.valid
                    && g.appeal.is_none()
                    && !crate::epoch::identifier_order(g.identifier_order, id).0
            })?;
            g.confirmations.first().map(|c| c.message)
        });
        if let Some(event) = needed {
            return self
                .prepare_appeal(source, member, event, 60_000_000, now, deadline)
                .map(Some);
        }
        if group_keys
            && let Some(operation) =
                self.propose_next_group(source, member, entropy, now, deadline)?
        {
            return Ok(Some(operation));
        }
        let row = self.rooms.get(r)?;
        let epoch = row.epochs.get(e)?;
        // All actual signed candidates participate in deterministic convergence;
        // counting only keys already possessed would leave simultaneous local
        // initial announcements permanently isolated. Tentative signatures rank
        // a request candidate only; real ACCESS/announcement MACs grant the key.
        let candidate = epoch
            .groups
            .iter()
            .filter(|(_, g)| {
                !crate::epoch::identifier_order(g.identifier_order, &g.identifier).0
                    && g.valid
                    && (!g.confirmations.is_empty() || g.key.is_some())
            })
            .max_by_key(|(_, g)| (g.confirmations.len(), g.identifier))
            .map(|(_, g)| {
                (
                    g.identifier,
                    g.key.is_some(),
                    g.confirmations.iter().any(|c| {
                        c.contact == contact
                            && self
                                .announcement_deadline(row, epoch, c, now, true)
                                .is_some()
                    }),
                    g.appeal,
                    g.confirmations.first().map(|c| c.message),
                )
            });
        if let Some((id, possessed, announced, appeal, reference)) = candidate {
            if possessed {
                if !announced {
                    return self
                        .prepare_announcement(
                            source, member, id, 60_000_000, entropy, now, deadline,
                        )
                        .map(Some);
                }
                return Ok(None);
            }
            if appeal.is_some() {
                return Ok(None);
            }
            if let Some(event) = reference {
                return self
                    .prepare_appeal(source, member, event, 60_000_000, now, deadline)
                    .map(Some);
            }
        }
        // Reuse an original failed/not-yet-provided local key slot first.
        let empty = epoch.groups.iter().find_map(|(_, g)| {
            (!crate::epoch::identifier_order(g.identifier_order, &g.identifier).0
                && g.valid
                && g.phase == KeyPhase::Missing
                && g.confirmations.is_empty())
            .then_some(g.identifier)
        });
        if let Some(id) = empty {
            return self
                .request_shared_key(source, member, epoch_hash, id, now, deadline)
                .map(Some);
        }
        // A compatible previous full cohort can ratchet. In particular this
        // does not derive a future key known by someone removed from the epoch.
        let previous = epoch.parents.iter().find_map(|p| {
            let old = row.epochs.get(row.find_epoch(p)?).ok()?;
            old.groups
                .iter()
                .filter(|(_, g)| {
                    !crate::epoch::identifier_order(g.identifier_order, &g.identifier).0
                        && g.valid
                        && g.key.is_some()
                        && g.confirmations.iter().filter(|c| c.verified_mac).count() == g.target
                        && g.confirmations
                            .iter()
                            .all(|c| row.epoch_has_member(epoch, c.contact))
                })
                .max_by_key(|(_, g)| (g.target, g.identifier))
                .map(|(_, g)| g.identifier)
        });
        if let Some(id) = previous {
            let group = self.ensure_group(r, e, id)?;
            if self
                .rooms
                .get(r)?
                .epochs
                .get(e)?
                .groups
                .get(group)?
                .key
                .is_some()
            {
                return self
                    .prepare_announcement(source, member, id, 60_000_000, entropy, now, deadline)
                    .map(Some);
            }
        }
        let id = self.fresh_identifier(None, entropy)?;
        self.request_shared_key(source, member, epoch_hash, id, now, deadline)
            .map(Some)
    }
}
