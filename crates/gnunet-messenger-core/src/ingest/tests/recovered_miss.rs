use super::*;
use crate::{CommittedArchive, model::structural_core};

const LIVE: ReceiveMeta = ReceiveMeta {
    epoch: ZERO,
    flags: 0,
    requested: false,
    sender_hash: None,
    context: None,
};
const REPLY: ReceiveMeta = ReceiveMeta {
    requested: true,
    ..LIVE
};
const LAYOUT: OriginalLayout = OriginalLayout::same(PROFILE);

struct SignedControl {
    frame: [u8; FRAME_BYTES],
    len: usize,
    hash: Hash,
}

impl SignedControl {
    fn new(
        key: &EddsaPrivateKey,
        timestamp: u64,
        previous: &Hash,
        body: Body<'_>,
    ) -> Result<Self, Error> {
        let mut encoded = [0; 32];
        let size = body.encode(PROFILE, &mut encoded)?;
        let mut frame = [0; FRAME_BYTES];
        let len = encode_signed_peer(
            key,
            SigningHeader {
                timestamp: AbsoluteTime::from_micros(timestamp),
                sender_id: key.public_key().as_bytes(),
                previous,
            },
            body.kind(),
            SensitiveBytes::new(&encoded[..size]),
            PROFILE,
            padding::Encode::Absent,
            &mut frame,
        )?;
        let message = Message::decode(&frame[..len], PROFILE, padding::Decode::Absent)?;
        let hash = message_hash(message);
        Ok(Self { frame, len, hash })
    }

    fn bytes(&self) -> &[u8] {
        &self.frame[..self.len]
    }
}

fn service_room(instance: &mut Instance) -> Result<(Core<'_>, Room<'_>), Error> {
    let mut core = structural_core(instance)?;
    core.mode = Mode::Service;
    core.configure_local_peer(*EddsaPrivateKey::from_seed([15; 32]).public_key().as_bytes())?;
    let room = core.room([9; 64], None)?;
    Ok((core, room))
}

#[test]
fn recovered_miss_waits_for_signed_parent_without_starting_hosting() -> Result<(), Error> {
    let reporter_announcement = SignedPeer::new(11, 1)?;
    let announcement = SignedPeer::with_parent(42, 2, &reporter_announcement.hash)?;
    let peer = *EddsaPrivateKey::from_seed([42; 32]).public_key().as_bytes();
    let reporter = EddsaPrivateKey::from_seed([11; 32]);
    let relay = *EddsaPrivateKey::from_seed([16; 32]).public_key().as_bytes();
    let mut instance = Instance::new();
    let (mut core, room) = service_room(&mut instance)?;
    let source = core.attach_source(room, SourceRole::Peer(peer), padding::Decode::Absent, None)?;
    let relay = core.attach_source(room, SourceRole::Peer(relay), padding::Decode::Absent, None)?;
    core.receive_borrowed(relay, LIVE, LAYOUT, reporter_announcement.bytes())?;
    core.advance(room, 1)?;
    core.receive_borrowed(source, LIVE, LAYOUT, announcement.bytes())?;
    core.advance(room, 2)?;

    let parent = SignedControl::new(
        &reporter,
        3,
        &announcement.hash,
        Body::Connection {
            amount: 1,
            flags: 0,
        },
    )?;
    let miss = SignedControl::new(&reporter, 4, &parent.hash, Body::Miss { peer: &peer })?;
    assert_eq!(
        core.receive_borrowed(relay, REPLY, LAYOUT, miss.bytes())?,
        miss.hash
    );
    core.advance(room, 4)?;
    assert_eq!(
        core.service_peer_announcement(room, &peer)?,
        Some(announcement.hash)
    );
    let waiting = core.message(room, &miss.hash)?;
    assert_eq!(waiting.phase(), MessagePhase::AwaitingParents);
    assert!(!waiting.semantic_applied() && !waiting.history_complete());
    assert!(core.is_required_dependency(relay, &parent.hash)?);

    core.receive_borrowed(relay, REPLY, LAYOUT, parent.bytes())?;
    core.advance(room, 5)?;
    assert_eq!(core.service_peer_announcement(room, &peer)?, None);
    assert_eq!(core.service_state(room)?.previous, announcement.hash);
    let recovered = core.message(room, &miss.hash)?;
    assert_eq!(recovered.phase(), MessagePhase::Applied);
    assert!(recovered.history_complete() && recovered.requested());
    assert_eq!(recovered.original(), Some(miss.bytes()));
    assert_eq!(
        recovered.original_signer(),
        Some(OriginalSigner::Peer(*reporter.public_key().as_bytes()))
    );
    assert!(
        !core::iter::from_fn(|| core.pop_event())
            .any(|event| matches!(event, Event::ServicePeerMiss { .. }))
    );
    Ok(())
}

#[test]
fn recovered_miss_on_old_branch_cannot_withdraw_new_announcement() -> Result<(), Error> {
    let reporter_announcement = SignedPeer::new(11, 1)?;
    let first = SignedPeer::with_parent(42, 2, &reporter_announcement.hash)?;
    let replacement = SignedPeer::with_parent(42, 3, &first.hash)?;
    let peer = *EddsaPrivateKey::from_seed([42; 32]).public_key().as_bytes();
    let reporter = EddsaPrivateKey::from_seed([11; 32]);
    let relay = *EddsaPrivateKey::from_seed([16; 32]).public_key().as_bytes();
    let mut instance = Instance::new();
    let (mut core, room) = service_room(&mut instance)?;
    let source = core.attach_source(room, SourceRole::Peer(peer), padding::Decode::Absent, None)?;
    let relay = core.attach_source(room, SourceRole::Peer(relay), padding::Decode::Absent, None)?;
    core.receive_borrowed(relay, LIVE, LAYOUT, reporter_announcement.bytes())?;
    core.advance(room, 1)?;
    for (announcement, now) in [(&first, 2), (&replacement, 3)] {
        core.receive_borrowed(source, LIVE, LAYOUT, announcement.bytes())?;
        core.advance(room, now)?;
    }

    // This concurrent announcement was first seen as a history response, so
    // it cannot replace the live one despite arriving after it.
    let fork = SignedPeer::with_parent(42, 4, &first.hash)?;
    core.receive_borrowed(relay, REPLY, LAYOUT, fork.bytes())?;
    core.advance(room, 4)?;
    assert_eq!(
        core.service_peer_announcement(room, &peer)?,
        Some(replacement.hash)
    );

    // The timestamp follows the replacement, but the signed parent does not.
    let stale = SignedControl::new(&reporter, 5, &fork.hash, Body::Miss { peer: &peer })?;
    core.receive_borrowed(relay, REPLY, LAYOUT, stale.bytes())?;
    core.advance(room, 5)?;
    assert_eq!(
        core.service_peer_announcement(room, &peer)?,
        Some(replacement.hash)
    );
    assert_eq!(core.service_state(room)?.previous, replacement.hash);
    let recovered = core.message(room, &stale.hash)?;
    assert_eq!(recovered.phase(), MessagePhase::Applied);
    assert!(recovered.history_complete() && recovered.requested());
    assert_eq!(recovered.original(), Some(stale.bytes()));
    assert!(
        !core::iter::from_fn(|| core.pop_event())
            .any(|event| matches!(event, Event::ServicePeerMiss { .. }))
    );
    Ok(())
}

#[test]
fn recovered_miss_relay_does_not_authorize_an_unannounced_signer() -> Result<(), Error> {
    let target = SignedPeer::new(42, 1)?;
    let peer = *EddsaPrivateKey::from_seed([42; 32]).public_key().as_bytes();
    let outsider = EddsaPrivateKey::from_seed([11; 32]);
    let relay = *EddsaPrivateKey::from_seed([16; 32]).public_key().as_bytes();
    let mut instance = Instance::new();
    let (mut core, room) = service_room(&mut instance)?;
    let source = core.attach_source(room, SourceRole::Peer(peer), padding::Decode::Absent, None)?;
    let relay = core.attach_source(room, SourceRole::Peer(relay), padding::Decode::Absent, None)?;
    core.receive_borrowed(source, LIVE, LAYOUT, target.bytes())?;
    core.advance(room, 1)?;

    let miss = SignedControl::new(&outsider, 2, &target.hash, Body::Miss { peer: &peer })?;
    core.receive_borrowed(relay, REPLY, LAYOUT, miss.bytes())?;
    core.advance(room, 2)?;
    let recorded = core.message(room, &miss.hash)?;
    assert!(recorded.history_complete());
    assert_eq!(
        recorded.original_signer(),
        Some(OriginalSigner::Peer(*outsider.public_key().as_bytes()))
    );
    assert_eq!(
        core.service_peer_announcement(room, &peer)?,
        Some(target.hash)
    );
    Ok(())
}

struct Checkpoint<'a>(&'a [u8]);

impl CommittedArchive for Checkpoint<'_> {
    fn generation(&self) -> u64 {
        1
    }

    fn expose_committed(&self) -> &[u8] {
        self.0
    }
}

#[test]
fn unsolicited_replay_of_a_checkpointed_miss_does_not_withdraw_a_live_route() -> Result<(), Error> {
    const MAXIMUM: usize = 8192;
    let initial = SignedPeer::new(42, 1)?;
    let fresh = SignedPeer::with_parent(42, 2, &initial.hash)?;
    let peer = *EddsaPrivateKey::from_seed([42; 32]).public_key().as_bytes();
    let reporter = EddsaPrivateKey::from_seed([11; 32]);
    let remote = *reporter.public_key().as_bytes();
    let local = *EddsaPrivateKey::from_seed([15; 32]).public_key().as_bytes();
    let miss = SignedControl::new(&reporter, 3, &fresh.hash, Body::Miss { peer: &peer })?;
    let mut instance = Instance::new();
    let (mut core, room) = service_room(&mut instance)?;
    let source = core.attach_source(room, SourceRole::Peer(peer), padding::Decode::Absent, None)?;
    let relay = core.attach_source(
        room,
        SourceRole::Peer(remote),
        padding::Decode::Absent,
        None,
    )?;
    core.receive_borrowed(source, LIVE, LAYOUT, initial.bytes())?;
    core.advance(room, 1)?;
    core.receive_borrowed(relay, REPLY, LAYOUT, miss.bytes())?;
    core.advance(room, 3)?;
    assert_eq!(
        core.message(room, &miss.hash)?.phase(),
        MessagePhase::AwaitingParents
    );

    let bytes = core.prepare_archive(MAXIMUM)?.into_body();
    let mut restored = Instance::new();
    let (mut core, _, _) = Core::recover_archive(
        &mut restored,
        &Checkpoint(&bytes),
        core.limits,
        PROFILE,
        MAXIMUM,
    )?
    .into_parts();
    core.configure_local_peer(local)?;
    let room = core.retained_rooms().next().ok_or(Fault::NotFound)?;
    let source = core.attach_source(room, SourceRole::Peer(peer), padding::Decode::Absent, None)?;
    let relay = core.attach_source(
        room,
        SourceRole::Peer(remote),
        padding::Decode::Absent,
        None,
    )?;
    core.receive_borrowed(source, LIVE, LAYOUT, fresh.bytes())?;
    core.advance(room, 4)?;
    core.receive_borrowed(relay, LIVE, LAYOUT, miss.bytes())?;
    core.advance(room, 5)?;
    assert_eq!(
        core.service_peer_announcement(room, &peer)?,
        Some(fresh.hash)
    );
    assert!(core.message(room, &miss.hash)?.requested());
    assert_eq!(core.service_state(room)?.previous, fresh.hash);
    Ok(())
}
