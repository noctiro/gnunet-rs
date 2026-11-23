use super::*;
use gnunet_identity::SecretKey;
use zeroize::Zeroizing;

const META: ReceiveMeta = ReceiveMeta {
    epoch: ZERO,
    flags: 0,
    requested: false,
    sender_hash: None,
    context: None,
};
const LAYOUT: OriginalLayout = OriginalLayout::same(PROFILE);

fn signer() -> Result<SecretKey, Error> {
    let mut key = Zeroizing::new([42; 36]);
    key[..4].copy_from_slice(&wire::KeyType::Eddsa.value().to_be_bytes());
    Ok(SecretKey::from_serialized(&key[..])?)
}

fn talk(key: &SecretKey, timestamp: u64) -> Result<SensitiveBuffer<FRAME_BYTES>, Error> {
    let mut frame = SensitiveBuffer::new();
    frame.encode_signed(
        key,
        SigningHeader {
            timestamp: AbsoluteTime::from_micros(timestamp),
            sender_id: &[1; 32],
            previous: &ZERO,
        },
        Body::Talk {
            discourse: &[2; 32],
            data: SensitiveBytes::new(b"deferred talk"),
        },
        PROFILE,
        padding::Encode::Absent,
    )?;
    Ok(frame)
}

#[test]
fn source_retirement_reclaims_only_unverified_history_generations() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut pool_instance = OriginalPoolInstance::new();
    let mut pool_slots = [OriginalSlot::EMPTY; 6];
    let mut bytes = [0; 6 * FRAME_BYTES];
    let mut workspace = [0; FRAME_BYTES];
    let mut nodes = [const { HistoryNodeCell::empty() }; 6];
    let mut index = [HistorySlotCell::empty(); 6];
    let mut ready = [HistorySlotCell::empty(); 6];
    let limits = Limits {
        rooms: 1,
        sources_per_room: 2,
        messages_per_room: 6,
        frame_bytes: FRAME_BYTES,
        name_bytes: FRAME_BYTES,
        work_per_turn: 3,
        ..Limits::default()
    };
    let pool = OriginalPool::new(&mut pool_instance, &mut pool_slots, &mut bytes);
    let mut core = Core::with_fixed_history(
        &mut instance,
        limits,
        PROFILE,
        pool,
        &mut workspace,
        RoomHistoryStorage::new(&mut nodes, &mut index, &mut ready),
    )?;
    let room = core.room([1; 64], None)?;
    let old_role = SourceRole::Peer([3; 32]);
    let old = core.attach_source(room, old_role, padding::Decode::Absent, None)?;
    let other = core.attach_source(
        room,
        SourceRole::Peer([4; 32]),
        padding::Decode::Absent,
        None,
    )?;
    let root = SignedPeer::new(7, 10)?;
    let child = SignedPeer::with_parent(8, 11, &root.hash)?;
    let key = signer()?;
    let first = talk(&key, 12)?;
    let second = talk(&key, 13)?;
    let survivor = talk(&key, 14)?;
    let third = talk(&key, 15)?;
    let extra = talk(&key, 16)?;
    core.receive_borrowed(old, META, LAYOUT, root.bytes())?;
    let removed = core.receive_borrowed(old, META, LAYOUT, first.expose())?;
    core.receive_borrowed(old, META, LAYOUT, second.expose())?;
    core.receive_borrowed(old, META, LAYOUT, child.bytes())?;
    let unaffected = core.receive_borrowed(other, META, LAYOUT, survivor.expose())?;
    core.receive_borrowed(old, META, LAYOUT, third.expose())?;
    assert_eq!(
        core.receive_borrowed(other, META, LAYOUT, extra.expose()),
        Err(Fault::Capacity.into())
    );

    core.advance(room, 16)?;
    // A pending TALK must not be published as a tombstone by retention timers.
    assert_eq!(
        core.message(room, &removed)?.phase(),
        MessagePhase::AwaitingSender
    );
    assert!(core.message(room, &removed)?.original() == Some(first.expose()));
    let row = core.rooms.get_mut(room.slot)?;
    let removed_slot = row.find_node(&removed).ok_or(Fault::NotFound)?;
    let root_slot = row.find_node(&root.hash).ok_or(Fault::NotFound)?;
    let child_slot = row.find_node(&child.hash).ok_or(Fault::NotFound)?;
    let unaffected_slot = row.find_node(&unaffected).ok_or(Fault::NotFound)?;
    let released = row.erase_message(&mut core.frames, root_slot, Some(child.hash))?;
    core.release(released)?;
    let before = core.charged_bytes();

    core.source_stopped(old)?;
    assert_eq!(
        core.charged_bytes(),
        before - first.expose().len() - second.expose().len() - third.expose().len()
    );
    assert!(matches!(
        core.message(room, &removed),
        Err(Error::Protocol(Fault::NotFound))
    ));
    assert_eq!(
        core.message(room, &root.hash)?.phase(),
        MessagePhase::Deleted
    );
    assert!(core.message(room, &child.hash)?.original() == Some(child.bytes()));
    let row = core.rooms.get(room.slot)?;
    assert!(row.ready.get(0) == Some(child_slot));
    assert!(row.ready.get(1) == Some(unaffected_slot));
    assert!(row.ready.get(2).is_none());
    assert!(row.graph_complete(child_slot, None)?);

    let replacement = core.attach_source(room, old_role, padding::Decode::Absent, None)?;
    for frame in [&first, &second, &third] {
        core.receive_borrowed(replacement, META, LAYOUT, frame.expose())?;
    }
    let row = core.rooms.get(room.slot)?;
    let new_slot = row.find_node(&removed).ok_or(Fault::NotFound)?;
    assert!(row.nodes.slot_at(removed_slot.index).is_some());
    assert!(matches!(
        row.nodes.get(removed_slot),
        Err(Error::Protocol(Fault::StaleGeneration))
    ));
    assert!(new_slot != removed_slot);
    let events = core::iter::from_fn(|| core.pop_event());
    assert_eq!(
        events
            .filter(|event| matches!(event, Event::MessageChanged(_, hash, _) if *hash == removed))
            .count(),
        1,
        "the same hash may be readmitted, but its earlier queued observation must be gone"
    );
    Ok(())
}

#[test]
fn released_service_lease_returns_unverified_history_capacity() -> Result<(), Error> {
    let mut instance = Instance::new();
    let limits = Limits {
        rooms: 1,
        messages_per_room: 1,
        ..Limits::default()
    };
    let mut core = Core::new(&mut instance, Mode::Service, limits, PROFILE)?;
    let room = core.room([1; 64], None)?;
    let key = signer()?;
    let frame = talk(&key, 10)?;
    let baseline = core.charged_bytes();
    let source = core.attach_source(room, SourceRole::Client, padding::Decode::Absent, None)?;
    core.bind_service_client(source, key.public_key()?, [1; 32])?;
    let hash = core.receive_borrowed(source, META, LAYOUT, frame.expose())?;
    core.release_service_client(source)?;
    assert!(core.charged_bytes() == baseline);
    assert!(matches!(
        core.message(room, &hash),
        Err(Error::Protocol(Fault::NotFound))
    ));
    let replacement =
        core.attach_source(room, SourceRole::Client, padding::Decode::Absent, None)?;
    core.bind_service_client(replacement, key.public_key()?, [1; 32])?;
    assert_eq!(
        core.receive_borrowed(replacement, META, LAYOUT, frame.expose())?,
        hash
    );
    while let Some(event) = core.pop_event() {
        assert!(!matches!(event, Event::SourceLost(_)));
    }
    Ok(())
}
