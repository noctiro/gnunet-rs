//! Synthetic trusted-checkpoint metadata cases, not signature/crypto admission.
//! All bytes are constructed in source; no native store, fixture or peer is used.
use super::*;
use crate::epoch::EpochMutation;
use wire::envelope::Kind;

const EPOCH: Hash = [17; 64];
const TALK: Hash = [18; 64];
const SUBSCRIPTION: Hash = [19; 64];
const CHILD: Hash = [20; 64];
const DISCOURSE: ShortHash = [117; 32];
const OLD_CONTEXT: Hash = [118; 64];
const OLD_EPOCH: Hash = [119; 64];
const PAYLOAD: &[u8] = b"synthetic transient content must never enter the durable projection";

fn limits() -> Limits {
    Limits {
        rooms: 1,
        contacts: 2,
        sources_per_room: 2,
        sessions_per_room: 2,
        messages_per_room: 8,
        epochs_per_room: 4,
        groups_per_epoch: 1,
        operations_per_room: 2,
        subscriptions_per_room: 2,
        missing_per_room: 2,
        nonce_per_epoch: 1,
        ..Limits::default()
    }
}
fn node<'id>(room: Slot, kind: Kind, hash: Hash, parent: Hash, sequence: u64) -> Node<'id> {
    let peer = [3; 32];
    let mut public = [0; 36];
    public[..4].copy_from_slice(&wire::KeyType::Eddsa.value().to_be_bytes());
    public[4..].copy_from_slice(&peer);
    Node {
        hash,
        origin: MessageOrigin::Archived(ArchivedFact {
            generation: 1,
            sequence,
        }),
        provenance: SourceObservation {
            room,
            source: Slot {
                index: 0,
                generation: 1,
            },
            role: SourceRole::Peer(peer),
        },
        resume_pending: false,
        meta: ReceiveMeta {
            epoch: EPOCH,
            flags: 0,
            requested: false,
            sender_hash: None,
            context: None,
        },
        phase: MessagePhase::Deleted,
        frame: None,
        plaintext: None,
        auth: Some(Authentication {
            owner: None,
            session: None,
            public,
            peer: Some(peer),
        }),
        padding: wire::padding::Decode::Absent,
        layout: OriginalLayout::same(wire::profile::Profile::LITTLE_255),
        cipher_layout: None,
        plain_layout: None,
        transcript_layout: None,
        identifier_order: None,
        plain_padding: wire::padding::Decode::Required,
        semantic_applied: true,
        complete: true,
        parents: [parent, [0; 64]],
        references: [[0; 64]; 3],
        frontier_applied: true,
        epoch: EPOCH,
        epoch_indexed: true,
        kind,
        semantic_kind: kind,
        timestamp: sequence,
        sequence,
        queued: false,
        requested: false,
        delete_at: None,
        deleted_by: None,
        discourse: None,
        local_sent: false,
        transcript: None,
        private_recipient: None,
        recipient: None,
        visit: 0,
    }
}
fn install_mock<'id>(core: &mut Core<'id>) -> Result<Room<'id>, Error> {
    core.configure_local_peer([9; 32])?;
    let id = core.room([10; 64], None)?;
    let row = core.rooms.get_mut(id.slot)?;
    row.sequence = 4;
    row.current_epoch = EPOCH;
    row.last_message = CHILD;
    row.frontier.push(CHILD);
    row.epoch_aliases
        .try_reserve_exact(32)
        .map_err(|_| Fault::Capacity)?;
    row.epoch_aliases.resize_with(32, || None);
    let mut payload_bytes = 0;
    for (kind, hash, parent, seq) in [
        (Kind::MERGE, EPOCH, [0; 64], 1),
        (Kind::TALK, TALK, EPOCH, 2),
        (Kind::SUBSCRIPTION, SUBSCRIPTION, TALK, 3),
        (Kind::TEXT, CHILD, SUBSCRIPTION, 4),
    ] {
        let mut n = node(id.slot, kind, hash, parent, seq);
        if crate::graph::discourse_kind(kind) {
            n.phase = MessagePhase::Applied;
            n.frame = Some(OwnedBytes::copy_from(PAYLOAD)?);
            n.discourse = Some(DISCOURSE);
            n.meta.context = Some(OLD_CONTEXT);
            n.meta.epoch = OLD_EPOCH;
            n.epoch = EPOCH;
            payload_bytes += n.payload_bytes();
        }
        if hash == CHILD {
            n.complete = false;
        }
        let slot = row.nodes.insert(n).map_err(|(e, _)| e)?;
        row.index.push(slot);
        row.put_alias(hash, EPOCH)?;
    }
    // Public synthetic hashes were inserted in their canonical sorted order.
    row.epochs
        .insert(EpochRow {
            hash: EPOCH,
            parents: [[0; 64]; 2],
            mutation: EpochMutation::Merge,
            members: Vec::new(),
            complete: true,
            groups: Slots::new(0)?,
            nonces: Vec::new(),
            revision: 1,
            ephemeral: None,
            ephemeral_until: 0,
            best_announcement: None,
            best_group: None,
        })
        .map_err(|(e, _)| e)?;
    let bytes =
        row.epoch_aliases.capacity() * core::mem::size_of::<Option<EpochAlias>>() + payload_bytes;
    core.charge(bytes)?;
    Ok(id)
}
struct Trusted(Zeroizing<Vec<u8>>);
impl CommittedArchive for Trusted {
    fn generation(&self) -> u64 {
        1
    }
    fn expose_committed(&self) -> &[u8] {
        self.0.as_slice()
    }
}
#[test]
fn transient_projection_preserves_durable_child_and_real_epoch() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut original = Core::new(
        &mut instance,
        Mode::Service,
        limits(),
        wire::profile::Profile::LITTLE_255,
    )?;
    let id = install_mock(&mut original)?;
    let image = original.prepare_archive(1 << 20)?;
    let body = image.into_body();
    for excluded in [
        PAYLOAD,
        DISCOURSE.as_slice(),
        OLD_CONTEXT.as_slice(),
        OLD_EPOCH.as_slice(),
    ] {
        assert!(!body.windows(excluded.len()).any(|v| v == excluded));
    }
    // Preparation itself must not erase/mutate the live original input owner.
    let row = original.rooms.get(id.slot)?;
    assert!(
        row.nodes
            .get(row.find_node(&TALK).ok_or(Fault::NotFound)?)?
            .frame
            .is_some()
    );
    let mut rejected = original.prepare_archive(1 << 20)?.into_body();
    rejected[..8].copy_from_slice(b"GMSHIS04");
    let mut old_domain = Instance::new();
    assert!(matches!(
        Core::recover_archive(
            &mut old_domain,
            &Trusted(rejected),
            limits(),
            wire::profile::Profile::LITTLE_255,
            1 << 20
        ),
        Err(Error::Protocol(Fault::Authentication))
    ));
    let mut next = Instance::new();
    let mut restored = Core::recover_archive(
        &mut next,
        &Trusted(body),
        limits(),
        wire::profile::Profile::LITTLE_255,
        1 << 20,
    )?
    .into_parts()
    .0;
    let room = restored.retained_rooms().next().ok_or(Fault::NotFound)?;
    for hash in [TALK, SUBSCRIPTION] {
        let row = restored.rooms.get(room.slot)?;
        let n = row
            .nodes
            .get(row.find_node(&hash).ok_or(Fault::NotFound)?)?;
        assert!(n.phase == MessagePhase::Deleted && n.frame.is_none() && n.discourse.is_none());
        assert!(n.epoch == [0; 64] && n.meta.context.is_none() && n.origin.live().is_none());
        assert!(
            row.alias(&hash).is_none() && row.sources.len() == 0 && row.subscriptions.len() == 0
        );
        assert!(restored.service_message_epoch(room, &hash)? == EPOCH);
    }
    let talk = restored
        .rooms
        .get(room.slot)?
        .find_node(&TALK)
        .ok_or(Fault::NotFound)?;
    restored
        .rooms
        .get_mut(room.slot)?
        .nodes
        .get_mut(talk)?
        .meta
        .context = Some(OLD_CONTEXT);
    assert!(matches!(
        restored.validate_archive(Some([9; 32])),
        Err(Error::Protocol(Fault::Malformed))
    ));
    restored
        .rooms
        .get_mut(room.slot)?
        .nodes
        .get_mut(talk)?
        .meta
        .context = None;
    assert!(restored.service_message_epoch(room, &CHILD)? == EPOCH);
    assert!(restored.epoch_members(room, &EPOCH)?.is_empty());
    let row = restored.rooms.get_mut(room.slot)?;
    let child = row.find_node(&CHILD).ok_or(Fault::NotFound)?;
    assert!(row.nodes.get(child)?.parents == [SUBSCRIPTION, [0; 64]]);
    assert!(row.nodes.get(child)?.sequence == 4 && row.nodes.get(child)?.auth.is_some());
    row.put_alias(TALK, [88; 64])?;
    assert!(row.alias(&TALK).is_none());
    row.queue_node(child)?;
    restored.advance(room, 100)?;
    let n = restored.rooms.get(room.slot)?.nodes.get(child)?;
    assert!(n.complete && n.origin.live().is_none());
    Ok(())
}
#[test]
fn cleanup_erases_both_discourse_kinds_and_cannot_refill_alias() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut core = Core::new(
        &mut instance,
        Mode::Service,
        limits(),
        wire::profile::Profile::LITTLE_255,
    )?;
    let room = install_mock(&mut core)?;
    for hash in [TALK, SUBSCRIPTION] {
        let row = core.rooms.get_mut(room.slot)?;
        let slot = row.find_node(&hash).ok_or(Fault::NotFound)?;
        let released = row.erase_message(slot, None)?;
        core.release(released)?;
        let row = core.rooms.get_mut(room.slot)?;
        row.put_alias(hash, [89; 64])?;
        assert!(row.alias(&hash).is_none());
        let n = row.nodes.get(slot)?;
        assert!(n.frame.is_none() && n.discourse.is_none() && n.meta.context.is_none());
        assert!(n.epoch == [0; 64] && n.phase == MessagePhase::Deleted);
    }
    assert!(core.service_message_epoch(room, &CHILD)? == EPOCH);
    Ok(())
}
#[test]
fn backshift_preserves_wrapped_full_cluster_values_and_count() -> Result<(), Error> {
    let mut room = RoomRow::new([1; 64], None, limits(), wire::profile::Profile::LITTLE_255)?;
    room.epoch_aliases
        .try_reserve_exact(4)
        .map_err(|_| Fault::Capacity)?;
    room.epoch_aliases.resize_with(4, || None);
    let mut keys = [[0; 64]; 4];
    for (i, key) in keys.iter_mut().enumerate() {
        key[0] = 3;
        key[63] = u8::try_from(i).map_err(|_| Fault::Overflow)?;
        room.put_alias(
            *key,
            [u8::try_from(i + 40).map_err(|_| Fault::Overflow)?; 64],
        )?;
    }
    assert!(room.remove_alias(&keys[0])? && room.epoch_alias_count == 3);
    for (i, key) in keys.iter().enumerate().skip(1) {
        assert!(room.alias(key) == Some([u8::try_from(i + 40).map_err(|_| Fault::Overflow)?; 64]));
    }
    assert!(room.remove_alias(&keys[2])? && room.epoch_alias_count == 2);
    assert!(room.alias(&keys[1]) == Some([41; 64]) && room.alias(&keys[3]) == Some([43; 64]));
    assert!(!room.remove_alias(&keys[0])? && room.epoch_alias_count == 2);
    Ok(())
}
