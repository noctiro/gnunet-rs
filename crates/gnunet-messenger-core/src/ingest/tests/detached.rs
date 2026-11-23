use super::*;
use crate::{
    archive::{
        ArchiveHistoryCell, ArchiveOriginalCell, ArchiveOriginals, CommittedGraphPage,
        CommittedGraphPageBytes, GraphPageIdentity,
    },
    model::{node, structural_core},
};
use core::num::NonZeroU64;
use gnunet_identity::SecretKey;
use wire::{body::Text, envelope::SIGNATURE_LEN};
use zeroize::Zeroizing;

const META: ReceiveMeta = ReceiveMeta {
    epoch: ZERO,
    flags: 0,
    requested: false,
    sender_hash: None,
    context: None,
};
const LAYOUT: OriginalLayout = OriginalLayout::same(PROFILE);

struct Committed<'a>(&'a [u8]);

impl CommittedArchive for Committed<'_> {
    fn generation(&self) -> u64 {
        2
    }

    fn expose_committed(&self) -> &[u8] {
        self.0
    }
}

impl CommittedGraphPageBytes for Committed<'_> {
    fn expose_committed_page(&self) -> &[u8] {
        self.0
    }
}

#[test]
fn detached_original_and_tombstone_verify_replays_without_retaining_them() -> Result<(), Error> {
    let local = EddsaPrivateKey::from_seed([15; 32]).public_key();
    let room_key = [9; 64];
    let namespace = [17; 16];
    let mut key = Zeroizing::new([42; 36]);
    key[..4].copy_from_slice(&wire::KeyType::Eddsa.value().to_be_bytes());
    let key = SecretKey::from_serialized(&key[..])?;
    let public = key.public_key()?;
    let mut instance = Instance::new();
    let mut core = structural_core(&mut instance)?;
    core.mode = Mode::Service;
    core.configure_local_peer(*local.as_bytes())?;
    let room = core.room(room_key, None)?;
    let role = SourceRole::Peer([11; 32]);
    let source = core.attach_source(room, role, padding::Decode::Absent, None)?;

    let mut originals: [SensitiveBuffer<FRAME_BYTES>; 2] =
        core::array::from_fn(|_| SensitiveBuffer::new());
    let mut hashes = [ZERO; 2];
    let mut slots = [Slot::empty(); 2];
    for sequence in [1, 2] {
        let index = sequence as usize - 1;
        let frame = &mut originals[index];
        frame.encode_signed(
            &key,
            SigningHeader {
                timestamp: AbsoluteTime::from_micros(sequence),
                sender_id: &[7; 32],
                previous: &ZERO,
            },
            Body::Text {
                text: Text::new(b"detached original")?,
            },
            PROFILE,
            padding::Encode::Absent,
        )?;
        let hash = OriginalFrame::decode(frame.expose(), padding::Decode::Absent, LAYOUT)?.hash;
        let mut original = node(core.instance, 0, 0, 1, 1, sequence)?;
        original.hash = hash;
        original.timestamp = sequence;
        original.origin = NodeOrigin::from_source(source, role);
        original.complete = true;
        original.auth = Some(Authentication {
            owner: None,
            session: None,
            public,
            peer: None,
        });
        if sequence == 1 {
            original.frame = Some(OwnedBytes::copy_from(frame.expose())?.into());
        } else {
            original.phase = MessagePhase::Deleted;
            original.frame = None;
        }
        slots[index] = core.rooms.get_mut(room.slot)?.insert_node(original)?;
        hashes[index] = hash;
    }
    core.rooms.get_mut(room.slot)?.sequence = 2;
    let identity = GraphPageIdentity::new(namespace, local, room_key, NonZeroU64::MIN, 0);
    let mut ordered = hashes;
    ordered.sort_unstable();
    let mut bytes = [0; 4096];
    let page = core.prepare_graph_page_into(room, identity, &ordered, &mut bytes, |_, _| {
        Err(Fault::Conflict.into())
    })?;
    let page = Committed(page.expose());
    let mut indexes = [ArchiveHistoryCell::EMPTY; 2];
    let page = CommittedGraphPage::open(&page, identity, core.limits, &mut indexes)?;
    assert!(
        page.get(&hashes[0])?
            .ok_or(Fault::NotFound)?
            .original()
            .is_some()
    );
    assert!(
        page.get(&hashes[1])?
            .ok_or(Fault::NotFound)?
            .original()
            .is_none()
    );

    let working = core.rooms.get_mut(room.slot)?;
    working.index.retain(|_| false);
    for slot in slots {
        working.nodes.remove(slot)?;
    }
    let checkpoint = core.prepare_archive(8192)?.into_body();
    let checkpoint = Committed(&checkpoint);
    let pages = [page];
    let history =
        CommittedRoomHistory::from_committed(&checkpoint, core.limits, 8192, &room_key, &mut [])?
            .ok_or(Fault::NotFound)?
            .with_detached_pages(&namespace, identity.emission(), &pages)?;
    core.rooms.get_mut(room.slot)?.sequence = 3;
    while core.pop_event().is_some() {}

    let charged = core.charged_bytes();
    for (frame, hash) in originals.iter().zip(hashes) {
        assert_eq!(
            core.receive_borrowed_with_history(source, META, LAYOUT, frame.expose(), history)?,
            hash
        );
        let mut bad = [0; FRAME_BYTES];
        let bad = &mut bad[..frame.expose().len()];
        bad.copy_from_slice(frame.expose());
        bad[SIGNATURE_LEN - 1] ^= 1;
        assert_eq!(
            OriginalFrame::decode(bad, padding::Decode::Absent, LAYOUT)?.hash,
            hash
        );
        assert!(
            core.receive_borrowed_with_history(source, META, LAYOUT, bad, history)
                .is_err()
        );
        let meta = ReceiveMeta {
            sender_hash: Some([1; 64]),
            ..META
        };
        assert!(matches!(
            core.receive_borrowed_with_history(source, meta, LAYOUT, frame.expose(), history),
            Err(Error::AttributionConflict)
        ));
        assert!(matches!(
            core.message(room, &hash),
            Err(Error::Protocol(Fault::NotFound))
        ));
    }
    assert_eq!(core.rooms.get(room.slot)?.sequence, 3);
    assert_eq!(core.charged_bytes(), charged);
    assert!(core.pop_event().is_none());
    Ok(())
}

#[test]
fn detached_peer_controls_keep_the_original_signer_without_reapplying_routes() -> Result<(), Error>
{
    const ROOM: Hash = [9; 64];
    const NAMESPACE: [u8; 16] = [17; 16];
    const KINDS: [Kind; 3] = [Kind::PEER, Kind::CONNECTION, Kind::MISS];
    let local = EddsaPrivateKey::from_seed([15; 32]).public_key();
    let signer = EddsaPrivateKey::from_seed([42; 32]);
    let peer = *signer.public_key().as_bytes();
    let relay_signer = EddsaPrivateKey::from_seed([11; 32]);
    let relay = *relay_signer.public_key().as_bytes();
    let mut instance = Instance::new();
    let mut core = structural_core(&mut instance)?;
    core.mode = Mode::Service;
    core.configure_local_peer(*local.as_bytes())?;
    let room = core.room(ROOM, None)?;
    let source = core.attach_source(room, SourceRole::Peer(peer), padding::Decode::Absent, None)?;
    let relay_source =
        core.attach_source(room, SourceRole::Peer(relay), padding::Decode::Absent, None)?;
    let mut frames = [[0; FRAME_BYTES]; 4];
    let mut lengths = [0; 4];
    let mut hashes = [ZERO; 4];
    let controls = [
        Body::Peer { peer: &peer },
        Body::Connection {
            amount: 1,
            flags: 0,
        },
        Body::Miss { peer: &peer },
        Body::Peer { peer: &relay },
    ];
    let mut previous = ZERO;
    for (index, body) in controls.into_iter().enumerate() {
        let (key, sender, ingress) = if index < KINDS.len() {
            (&signer, &peer, source)
        } else {
            (&relay_signer, &relay, relay_source)
        };
        let mut encoded = [0; 32];
        let n = body.encode(PROFILE, &mut encoded)?;
        lengths[index] = encode_signed_peer(
            key,
            SigningHeader {
                timestamp: AbsoluteTime::from_micros(index as u64 + 1),
                sender_id: sender,
                previous: &previous,
            },
            body.kind(),
            SensitiveBytes::new(&encoded[..n]),
            PROFILE,
            padding::Encode::Absent,
            &mut frames[index],
        )?;
        previous =
            core.receive_borrowed(ingress, META, LAYOUT, &frames[index][..lengths[index]])?;
        hashes[index] = previous;
        core.advance(room, 10)?;
        let row = core.rooms.get(room.slot)?;
        assert_eq!(
            row.current_peer_announcement(&peer, &hashes[0]),
            (index < 2).then_some(NonZeroU64::MIN)
        );
        let mut before = None;
        while let Some(event) = core.pop_event() {
            if let Event::ServicePeerMiss {
                room: found,
                members_before,
            } = event
            {
                assert_eq!(found, room);
                assert!(before.replace(members_before).is_none());
            }
        }
        assert_eq!(before, (body.kind() == Kind::MISS).then_some(1));
    }
    assert!(core.service_peer_candidates(room)?.eq([&relay]));

    let limits = core.limits;
    let identity = GraphPageIdentity::new(NAMESPACE, local, ROOM, NonZeroU64::MIN, 0);
    let mut ordered = [hashes[0], hashes[1], hashes[2]];
    ordered.sort_unstable();
    let mut page_bytes = [0; 4096];
    let mut image = [0; 8192];
    let mut cells = [const { ArchiveOriginalCell::EMPTY }; 4];
    let mut originals = ArchiveOriginals::new(&mut cells);
    let plan = core.begin_graph_detachment(room, &ordered)?;
    let page =
        plan.prepare_page_into(
            identity,
            &mut page_bytes,
            |_, _| Err(Fault::Conflict.into()),
        )?;
    let checkpoint = plan.prepare_checkpoint_into(&mut image, &mut originals, |_, _| {
        Err(Fault::Conflict.into())
    })?;
    plan.settle(&originals)?;
    let page = Committed(page.expose());
    let mut page_index = [ArchiveHistoryCell::EMPTY; 3];
    let pages = [CommittedGraphPage::open(
        &page,
        identity,
        limits,
        &mut page_index,
    )?];
    let checkpoint = Committed(checkpoint.expose());
    let mut working_index = [ArchiveHistoryCell::EMPTY; 1];
    let history =
        CommittedRoomHistory::from_committed(&checkpoint, limits, 8192, &ROOM, &mut working_index)?
            .ok_or(Fault::NotFound)?
            .with_detached_pages(&NAMESPACE, identity.emission(), &pages)?;
    let meta = ReceiveMeta {
        sender_hash: Some(hash512(&peer)),
        ..META
    };
    let mut after = 0;
    let charged = core.charged_bytes();
    for (index, kind) in KINDS.into_iter().enumerate() {
        let original = history
            .next_applied_original(after, 3, |original| Ok(!original.requested))?
            .ok_or(Fault::NotFound)?;
        assert_eq!(original.original.kind(), kind);
        assert_eq!(*original.original.hash(), hashes[index]);
        let raw = &mut frames[index][..lengths[index]];
        assert_eq!(original.original.bytes(), &*raw);
        after = original.sequence.get();
        assert_eq!(
            core.receive_borrowed_with_history(relay_source, meta, LAYOUT, raw, history)?,
            hashes[index]
        );
        let wrong = OriginalLayout {
            signer: Some(OriginalSigner::Peer(relay)),
            ..LAYOUT
        };
        assert!(matches!(
            core.receive_borrowed_with_history(relay_source, meta, wrong, raw, history),
            Err(Error::Protocol(Fault::Authentication))
        ));
        raw[SIGNATURE_LEN - 1] ^= 1;
        assert_eq!(
            OriginalFrame::decode(raw, padding::Decode::Absent, LAYOUT)?.hash,
            hashes[index]
        );
        assert!(
            core.receive_borrowed_with_history(relay_source, meta, LAYOUT, raw, history)
                .is_err()
        );
        assert!(matches!(
            core.message(room, &hashes[index]),
            Err(Error::Protocol(Fault::NotFound))
        ));
    }
    assert!(
        history
            .next_applied_original(after, 3, |original| Ok(!original.requested))?
            .is_none()
    );
    assert_eq!(
        *history
            .next_applied_original(after, 4, |original| Ok(!original.requested))?
            .ok_or(Fault::NotFound)?
            .original
            .hash(),
        hashes[3]
    );
    assert!(core.service_peer_candidates(room)?.eq([&relay]));
    let row = core.rooms.get(room.slot)?;
    assert_eq!(row.current_peer_announcement(&peer, &hashes[0]), None);
    assert_eq!(
        row.current_peer_announcement(&relay, &hashes[3]),
        NonZeroU64::new(4)
    );
    assert_eq!(core.charged_bytes(), charged);
    assert!(core.pop_event().is_none());
    Ok(())
}

#[test]
fn requested_miss_and_reflected_local_miss_cannot_start_hosting() -> Result<(), Error> {
    let signer = EddsaPrivateKey::from_seed([42; 32]);
    let reporter = *signer.public_key().as_bytes();
    let local_key = EddsaPrivateKey::from_seed([15; 32]);
    let local = *local_key.public_key().as_bytes();
    let mut instance = Instance::new();
    let mut core = structural_core(&mut instance)?;
    core.mode = Mode::Service;
    core.configure_local_peer(local)?;
    let room = core.room([9; 64], None)?;
    let relay = core.attach_source(
        room,
        SourceRole::Peer(reporter),
        padding::Decode::Absent,
        None,
    )?;
    let cases = [
        (&signer, &reporter, true, None),
        (&local_key, &local, false, None),
        (&signer, &reporter, false, Some(0)),
    ];
    let mut previous = ZERO;
    for (index, (key, sender, requested, expected)) in cases.into_iter().enumerate() {
        let mut frame = [0; FRAME_BYTES];
        let bytes = encode_signed_peer(
            key,
            SigningHeader {
                timestamp: AbsoluteTime::from_micros(index as u64 + 1),
                sender_id: sender,
                previous: &previous,
            },
            Kind::MISS,
            SensitiveBytes::new(&local),
            PROFILE,
            padding::Encode::Absent,
            &mut frame,
        )?;
        let frame = &frame[..bytes];
        let meta = ReceiveMeta { requested, ..META };
        previous = core.receive_borrowed(relay, meta, LAYOUT, frame)?;
        core.advance(room, 10)?;
        let mut before = None;
        while let Some(event) = core.pop_event() {
            if let Event::ServicePeerMiss {
                room: found,
                members_before,
            } = event
            {
                assert_eq!(found, room);
                assert!(before.replace(members_before).is_none());
            }
        }
        assert_eq!(before, expected);
        assert_eq!(core.receive_borrowed(relay, meta, LAYOUT, frame)?, previous);
        core.advance(room, 10)?;
        assert!(
            !core::iter::from_fn(|| core.pop_event())
                .any(|event| matches!(event, Event::ServicePeerMiss { .. }))
        );
    }
    Ok(())
}
