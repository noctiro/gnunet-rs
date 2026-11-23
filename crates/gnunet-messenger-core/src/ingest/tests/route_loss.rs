use super::*;

fn prepare_loss<'id>(
    core: &mut Core<'id>,
    room: Room<'id>,
    source: Source<'id>,
    signer: &EddsaPrivateKey,
    target: &ShortHash,
    now: u64,
) -> Result<(Binding<'id>, Hash), Error> {
    let local = *signer.public_key().as_bytes();
    let operation = core.prepare_peer(source, local, Body::Miss { peer: target }, now, 100)?;
    let work = core
        .take_service_signing_work(room)?
        .ok_or(Fault::NotReady)?;
    let binding = work.binding;
    assert_eq!(binding.operation(), operation);
    let mut bytes = [0; FRAME_BYTES];
    let len = encode_signed_peer(
        signer,
        SigningHeader {
            timestamp: AbsoluteTime::from_micros(work.timestamp),
            sender_id: &work.sender,
            previous: &work.previous,
        },
        work.kind,
        SensitiveBytes::new(work.body.expose()),
        PROFILE,
        padding::Encode::Absent,
        &mut bytes,
    )?;
    let bytes = &bytes[..len];
    let hash = message_hash(Message::decode(bytes, PROFILE, padding::Decode::Absent)?);
    core.complete_signature_from(binding, bytes, padding::Decode::Absent, now)?;
    Ok((binding, hash))
}

#[test]
fn route_loss_refuses_a_queued_replacement_and_withdraws_only_the_current_peer() -> Result<(), Error>
{
    let signer = EddsaPrivateKey::from_seed([15; 32]);
    let local = *signer.public_key().as_bytes();
    let peer = *EddsaPrivateKey::from_seed([42; 32]).public_key().as_bytes();
    let mut instance = Instance::new();
    let mut core = crate::model::structural_core(&mut instance)?;
    core.mode = Mode::Service;
    core.configure_local_peer(local)?;
    let room = core.room([9; 64], None)?;
    let source = core.attach_source(room, SourceRole::Peer(peer), padding::Decode::Absent, None)?;
    let local_source = core.attach_source(
        room,
        SourceRole::ServiceSigner(local),
        padding::Decode::Absent,
        None,
    )?;
    let meta = ReceiveMeta {
        epoch: ZERO,
        flags: 4,
        requested: false,
        sender_hash: None,
        context: None,
    };
    let layout = OriginalLayout::same(PROFILE);
    let first = SignedPeer::new(42, 1)?;
    assert_eq!(
        core.receive_borrowed(source, meta, layout, first.bytes())?,
        first.hash
    );
    core.advance(room, 1)?;
    let (stale, stale_hash) = prepare_loss(&mut core, room, local_source, &signer, &peer, 2)?;
    let fresh = SignedPeer::with_parent(42, 3, &first.hash)?;
    assert_eq!(
        core.receive_borrowed(source, meta, layout, fresh.bytes())?,
        fresh.hash
    );
    assert!(matches!(
        core.service_commit_route_loss(stale, &first.hash, 3),
        Err(Error::Protocol(Fault::WouldBlock))
    ));
    assert_eq!(
        core.service_peer_announcement(room, &peer)?,
        Some(first.hash)
    );
    core.advance(room, 3)?;
    assert!(matches!(
        core.service_commit_route_loss(stale, &first.hash, 4),
        Err(Error::Protocol(Fault::StaleGeneration))
    ));
    assert_eq!(
        core.service_peer_announcement(room, &peer)?,
        Some(fresh.hash)
    );
    assert_eq!(core.service_state(room)?.previous, fresh.hash);
    assert!(matches!(
        core.message(room, &stale_hash),
        Err(Error::Protocol(Fault::NotFound))
    ));
    core.source_cancelled(local_source)?;
    core.retire_operation(stale.operation())?;
    while core.pop_event().is_some() {}

    let local_source = core.attach_source(
        room,
        SourceRole::ServiceSigner(local),
        padding::Decode::Absent,
        None,
    )?;
    let (current, hash) = prepare_loss(&mut core, room, local_source, &signer, &peer, 5)?;
    assert_eq!(core.service_peer_announcement(room, &local)?, None);
    assert_eq!(
        core.service_commit_route_loss(current, &fresh.hash, 5)?,
        hash
    );
    assert_eq!(core.service_peer_announcement(room, &peer)?, None);
    assert!(core.message(room, &hash)?.semantic_applied());
    assert_eq!(
        core.service_attribution(room, &hash)?.sender,
        hash512(&local)
    );
    core.retire_operation(current.operation())?;
    core.advance(room, 5)?;
    assert_eq!(core.service_state(room)?.previous, hash);
    assert_eq!(core.message(room, &hash)?.phase(), MessagePhase::Applied);
    Ok(())
}
