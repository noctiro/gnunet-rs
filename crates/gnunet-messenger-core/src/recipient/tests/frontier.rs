//! Authenticated outer graph observations precede optional body prerequisites.
use super::*;

fn draft<'id>(
    core: &mut Core<'id>,
    room: Room<'id>,
    source: Source<'id>,
    peer: &SecretKey,
    id: &ShortHash,
    body: Body<'_>,
) -> Result<(Binding<'id>, SensitiveBuffer<8192>), Error> {
    let operation = core.prepare_peer(source, *id, body, 100, 10_000)?;
    let work = core
        .take_service_signing_work(room)?
        .ok_or(Fault::NotReady)?;
    assert_eq!(work.binding.operation(), operation);
    let bytes = signed(
        peer,
        &work.sender,
        &work.previous,
        Body::decode(work.kind, work.body.expose(), PROFILE)?,
        work.timestamp,
    )?;
    Ok((work.binding, bytes))
}

fn commit<'id>(
    core: &mut Core<'id>,
    room: Room<'id>,
    binding: Binding<'id>,
    bytes: &[u8],
) -> Result<Hash, Error> {
    core.complete_signature(
        binding,
        OwnedBytes::copy_from(bytes)?,
        padding::Decode::Absent,
        100,
    )
    .map_err(|rejected| rejected.error)?;
    let hash = core.service_commit_signature(binding, 100)?;
    core.retire_operation(binding.operation())?;
    drain(core, room)?;
    Ok(hash)
}

#[test]
fn connection_before_peer_preserves_service_and_client_frontier_coverage() -> Result<(), Error> {
    let peer = identity(85)?;
    let peer_id: ShortHash = peer.public_key()?[4..]
        .try_into()
        .map_err(|_| Fault::Malformed)?;
    let local = identity(86)?;
    let mut service_instance = Instance::new();
    let mut service = Core::new(&mut service_instance, Mode::Service, limits(), PROFILE)?;
    service.configure_local_peer(peer_id)?;
    let room = service.room(ROOM, None)?;
    let signer = service.attach_source(
        room,
        SourceRole::ServiceSigner(peer_id),
        padding::Decode::Absent,
        None,
    )?;
    // Both original drafts precede either native signature result, so neither
    // signed predecessor can be retargeted to the other's eventual commit.
    let (connection_binding, connection_bytes) = draft(
        &mut service,
        room,
        signer,
        &peer,
        &peer_id,
        Body::Connection {
            amount: 3,
            flags: 1,
        },
    )?;
    let (peer_binding, peer_bytes) = draft(
        &mut service,
        room,
        signer,
        &peer,
        &peer_id,
        Body::Peer { peer: &peer_id },
    )?;
    let connection = commit(
        &mut service,
        room,
        connection_binding,
        connection_bytes.expose(),
    )?;
    let row = service.rooms.get(room.slot)?;
    let node = row
        .nodes
        .get(row.find_node(&connection).ok_or(Fault::NotFound)?)?;
    assert!(node.auth.is_some() && node.complete && node.frontier_applied);
    assert!(node.semantic_applied && row.queues.peers.is_empty());
    assert_eq!(row.queues.frontier.as_slice(), &[connection]);
    let announcement = commit(&mut service, room, peer_binding, peer_bytes.expose())?;
    assert_eq!(
        service.service_room_ring(room)?.local_connection(),
        Some(ServiceConnection::default())
    );
    let merge = service.service_merge(room)?.ok_or(Fault::NotReady)?;
    assert_eq!(merge.previous, connection);
    assert_eq!(service.service_state(room)?.previous, announcement);

    let mut client_instance = Instance::new();
    let mut client = Core::new(&mut client_instance, Mode::Client, limits(), PROFILE)?;
    let address = open(&mut client, &local)?;
    for bytes in [peer_bytes.expose(), connection_bytes.expose()] {
        client
            .receive_owned(
                address.1,
                ReceiveMeta {
                    epoch: [0; 64],
                    flags: 8,
                    requested: false,
                    sender_hash: Some(gnunet_crypto::hash512(&peer_id)),
                    context: None,
                },
                OwnedBytes::copy_from(bytes)?,
            )
            .map_err(|rejected| rejected.error)?;
        drain(&mut client, address.0)?;
    }
    let mut hpke = [0; 36];
    crypto::EcdheSecret::from_bytes([87; 32])
        .public_key()
        .encode_hpke(&mut hpke)?;
    let joined = owned_join(&mut client, address, &local, hpke)?;
    let client_source =
        service.attach_source(room, SourceRole::Client, padding::Decode::Absent, None)?;
    service.bind_service_client(client_source, local.public_key()?, LOCAL)?;
    let row = client.rooms.get(address.0.slot)?;
    let frame = row
        .nodes
        .get(row.find_node(&joined).ok_or(Fault::NotFound)?)?
        .frame
        .as_ref()
        .ok_or(Fault::NotReady)?;
    let bytes = client.frames.expose(frame)?;
    service
        .receive_owned(
            client_source,
            ReceiveMeta {
                epoch: [0; 64],
                flags: 0,
                requested: false,
                sender_hash: None,
                context: None,
            },
            OwnedBytes::copy_from(bytes)?,
        )
        .map_err(|rejected| rejected.error)?;
    drain(&mut service, room)?;
    let merge = service.service_merge(room)?.ok_or(Fault::NotReady)?;
    assert_eq!(merge.previous, announcement);
    let (binding, bytes) = draft(
        &mut service,
        room,
        signer,
        &peer,
        &peer_id,
        Body::Merge {
            first_epoch: &merge.first_epoch,
            second_epoch: &merge.second_epoch,
            previous: &merge.previous,
        },
    )?;
    let merged = commit(&mut service, room, binding, bytes.expose())?;
    assert!(service.service_merge(room)?.is_none());
    let state = service.service_state(room)?;
    assert_eq!((state.previous, state.epoch), (merged, merged));
    let operation = client.synchronize(address.1, 10_000)?;
    let Work::Wire { binding, frame, .. } = client.take_work(address.0)?.ok_or(Fault::NotReady)?
    else {
        return Err(Fault::Conflict.into());
    };
    assert_eq!(binding.operation(), operation);
    client.write_progress(binding, frame.expose().len(), true)?;
    client
        .receive_owned(
            address.1,
            ReceiveMeta {
                epoch: merged,
                flags: 8,
                requested: false,
                sender_hash: Some(gnunet_crypto::hash512(&peer_id)),
                context: None,
            },
            OwnedBytes::copy_from(bytes.expose())?,
        )
        .map_err(|rejected| rejected.error)?;
    client.on_notification(
        address.1,
        wire::Response::Sync(wire::Room {
            door: &[0; 32],
            key: &ROOM,
            previous: &state.previous,
            epoch: &state.epoch,
        }),
        100,
    )?;
    drain(&mut client, address.0)?;
    assert_eq!(client.operation_phase(operation)?, OperationPhase::Complete);
    assert!(!client.frontier_sync_required(address.0)?);
    Ok(())
}
