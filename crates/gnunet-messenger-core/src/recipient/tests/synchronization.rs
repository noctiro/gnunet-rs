//! Actual signatures and causal edges qualify an explicit SYNC port reply.
use super::derivation::join_epoch;
use super::*;

fn sync<'id>(
    core: &mut Core<'id>,
    room: Room<'id>,
    source: Source<'id>,
) -> Result<Operation<'id>, Error> {
    let operation = core.synchronize(source, 10_000)?;
    let Work::Wire { binding, frame, .. } = core.take_work(room)?.ok_or(Fault::NotReady)? else {
        return Err(Fault::Conflict.into());
    };
    assert_eq!(binding.operation, operation);
    core.write_progress(binding, frame.expose().len(), true)?;
    Ok(operation)
}

fn reply<'id>(
    core: &mut Core<'id>,
    source: Source<'id>,
    previous: &Hash,
    epoch: &Hash,
) -> Result<(), Error> {
    core.on_notification(
        source,
        wire::Response::Sync(wire::Room {
            door: &[0; 32],
            key: &ROOM,
            previous,
            epoch,
        }),
        100,
    )
}

fn settle<'id>(
    core: &mut Core<'id>,
    room: Room<'id>,
    operation: Operation<'id>,
) -> Result<(), Error> {
    core.limits.work_per_turn = 1;
    for _ in 0..1024 {
        assert!(core.advance(room, 100)? <= 1);
        while core.pop_event().is_some() {}
        if core.operation_phase(operation)? == OperationPhase::Complete {
            return Ok(());
        }
    }
    Err(Fault::NotReady.into())
}

#[test]
fn unknown_sync_candidate_waits_for_actual_signed_dependency_at_minimum_capacity()
-> Result<(), Error> {
    let local = identity(61)?;
    let mut instance = Instance::new();
    let mut bounds = limits();
    bounds.operations_per_room = 3;
    let mut core = Core::new(&mut instance, Mode::Client, bounds, PROFILE)?;
    let address = open(&mut core, &local)?;
    let (epoch, _) = join_epoch(&mut core, address, &local, &LOCAL, &[0; 64])?;
    let body = Body::Name {
        name: Text::new(b"actual dependency")?,
    };
    let encoded = signed(&local, &LOCAL, &epoch, body, 10)?;
    let candidate = gnunet_crypto::hash512(&encoded.expose()[68..]);
    let operation = sync(&mut core, address.0, address.1)?;
    reply(&mut core, address.1, &candidate, &epoch)?;
    assert_eq!(core.operation_phase(operation)?, OperationPhase::Written);
    core.advance(address.0, 100)?;
    assert!(
        core.pending_dependencies(address.0)?
            .any(|(hash, source)| hash == candidate && source == address.1)
    );
    let retrieval = core.request_missing(address.1, candidate, 100, 10_000)?;
    let Work::Wire { binding, frame, .. } = core.take_work(address.0)?.ok_or(Fault::NotReady)?
    else {
        return Err(Fault::Conflict.into());
    };
    assert_eq!(binding.operation, retrieval);
    core.write_progress(binding, frame.expose().len(), true)?;
    let sender = gnunet_crypto::hash512(&local.public_key()?);
    core.on_notification(
        address.1,
        wire::Response::Receive {
            key: &ROOM,
            sender: &sender,
            context: &[0; 64],
            hash: &candidate,
            epoch: &epoch,
            flags: 0,
            message: wire::SensitiveBytes::new(encoded.expose()),
        },
        100,
    )?;
    settle(&mut core, address.0, operation)?;
    assert_eq!(core.operation_phase(retrieval)?, OperationPhase::Complete);
    assert!(!core.frontier_sync_required(address.0)?);
    Ok(())
}

#[test]
fn only_the_exact_missing_dependency_can_sign_during_an_unresolved_sync() -> Result<(), Error> {
    let local = identity(74)?;
    let mut instance = Instance::new();
    let mut bounds = limits();
    bounds.operations_per_room = 3;
    let mut core = Core::new(&mut instance, Mode::Client, bounds, PROFILE)?;
    let (room, source) = open(&mut core, &local)?;
    let mut hpke = [0; 36];
    crypto::EcdheSecret::from_bytes([75; 32])
        .public_key()
        .encode_hpke(&mut hpke)?;
    let joined = owned_join(&mut core, (room, source), &local, hpke)?;
    let member = core.local_member(room)?.ok_or(Fault::NotReady)?;
    let name = Body::Name {
        name: Text::new(b"recovered signed frontier")?,
    };
    let original = signed(&local, &LOCAL, &joined, name, 110)?;
    let target = gnunet_crypto::hash512(&original.expose()[68..]);
    let sync_op = sync(&mut core, room, source)?;
    reply(&mut core, source, &target, &joined)?;
    core.advance(room, 120)?;
    let get = core.request_missing(source, target, 120, 9000)?;
    let Work::Wire { binding, frame, .. } = core.take_work(room)?.ok_or(Fault::NotReady)? else {
        return Err(Fault::Conflict.into());
    };
    assert_eq!(binding.operation, get);
    let absent = wire::Response::Missing {
        key: &ROOM,
        hash: &target,
    };
    assert!(matches!(
        core.on_notification(source, absent, 120),
        Err(Error::Protocol(Fault::StaleGeneration))
    ));
    assert!(matches!(
        core.prepare_history_request(source, member, target, 120, 9000),
        Err(Error::Protocol(Fault::NotReady))
    ));
    core.write_progress(binding, frame.expose().len(), true)?;
    core.on_notification(source, absent, 120)?;
    core.retire_operation(get)?;
    assert!(matches!(
        core.prepare_history_request(source, member, target, 120, 9001),
        Err(Error::Protocol(Fault::NotReady))
    ));
    assert!(matches!(
        core.prepare_send(source, member, name, 120, 9000),
        Err(Error::Protocol(Fault::NotReady))
    ));
    let request = core.prepare_history_request(source, member, target, 120, 9000)?;
    let Work::Sign {
        binding,
        kind,
        body,
        sender,
        previous,
        timestamp,
        ..
    } = core.take_work(room)?.ok_or(Fault::NotReady)?
    else {
        return Err(Fault::Conflict.into());
    };
    assert_eq!(binding.operation, request);
    assert_eq!(previous, joined);
    assert_eq!(kind, wire::envelope::Kind::REQUEST);
    let body = Body::decode(kind, body.expose(), PROFILE)?;
    assert!(matches!(body, Body::Request { hash } if *hash == target));
    let request = signed(&local, &sender, &previous, body, timestamp)?;
    core.complete_signature_from(binding, request.expose(), padding::Decode::Absent, 120)?;
    let Work::Wire { binding, frame, .. } = core.take_work(room)?.ok_or(Fault::NotReady)? else {
        return Err(Fault::Conflict.into());
    };
    core.write_progress(binding, frame.expose().len(), true)?;
    assert_eq!(core.operation_phase(sync_op)?, OperationPhase::Written);
    core.on_notification(
        source,
        wire::Response::Receive {
            key: &ROOM,
            sender: &gnunet_crypto::hash512(&local.public_key()?),
            context: &[0; 64],
            hash: &target,
            epoch: &joined,
            flags: 0,
            message: wire::SensitiveBytes::new(original.expose()),
        },
        121,
    )?;
    settle(&mut core, room, sync_op)?;
    assert!(!core.frontier_sync_required(room)?);
    Ok(())
}

#[test]
fn an_old_sync_proof_preserves_newer_paired_cursor_and_requires_a_new_view_read()
-> Result<(), Error> {
    let local = identity(62)?;
    let mut instance = Instance::new();
    let mut core = Core::new(&mut instance, Mode::Client, limits(), PROFILE)?;
    let address = open(&mut core, &local)?;
    let (epoch, _) = join_epoch(&mut core, address, &local, &LOCAL, &[0; 64])?;
    let original_version = core.frontier_version(address.0)?;
    let first = sync(&mut core, address.0, address.1)?;
    let newer = receive(
        &mut core,
        address,
        &local,
        &LOCAL,
        &epoch,
        epoch,
        Body::Name {
            name: Text::new(b"newer signed cursor")?,
        },
    )?;
    reply(&mut core, address.1, &epoch, &epoch)?;
    settle(&mut core, address.0, first)?;
    let row = core.rooms.get(address.0.slot)?;
    assert_eq!((row.last_message, row.current_epoch), (newer, epoch));
    assert!(core.frontier_version(address.0)? > original_version);
    assert!(core.frontier_sync_required(address.0)?);
    core.retire_operation(first)?;
    let second = sync(&mut core, address.0, address.1)?;
    reply(&mut core, address.1, &newer, &epoch)?;
    settle(&mut core, address.0, second)?;
    assert!(!core.frontier_sync_required(address.0)?);
    Ok(())
}

#[test]
fn matching_service_epoch_hints_cannot_replace_actual_signed_epoch_ancestry() -> Result<(), Error> {
    let local = identity(63)?;
    let remote = identity(64)?;
    let mut instance = Instance::new();
    let mut core = Core::new(&mut instance, Mode::Client, limits(), PROFILE)?;
    let address = open(&mut core, &local)?;
    let (original_epoch, _) = join_epoch(&mut core, address, &local, &LOCAL, &[0; 64])?;
    let operation = sync(&mut core, address.0, address.1)?;
    let (claimed_epoch, _) = join_epoch(&mut core, address, &remote, &REMOTE, &original_epoch)?;
    let candidate = receive(
        &mut core,
        address,
        &local,
        &LOCAL,
        &original_epoch,
        claimed_epoch,
        Body::Name {
            name: Text::new(b"signed old branch")?,
        },
    )?;
    reply(&mut core, address.1, &candidate, &claimed_epoch)?;
    let mut rejected = false;
    core.limits.work_per_turn = 1;
    for _ in 0..128 {
        match core.advance(address.0, 100) {
            Err(Error::FrontierProof {
                stage: FrontierProofStage::EpochAncestry,
                cause: FrontierProofCause::Protocol(Fault::Authentication),
            }) => {
                rejected = true;
                break;
            }
            Ok(_) => while core.pop_event().is_some() {},
            Err(error) => return Err(error),
        }
    }
    assert!(rejected);
    assert_eq!(core.operation_phase(operation)?, OperationPhase::Written);
    assert!(core.frontier_sync_required(address.0)?);
    Ok(())
}

fn startup_merge(same_epoch: bool) -> Result<(), Error> {
    let local = identity(71)?;
    let peer = identity(72)?;
    let mut peer_id = [0; 32];
    peer_id.copy_from_slice(&peer.public_key()?[4..]);
    let mut instance = Instance::new();
    let mut core = Core::new(&mut instance, Mode::Client, limits(), PROFILE)?;
    let address = open(&mut core, &local)?;
    receive(
        &mut core,
        address,
        &peer,
        &peer_id,
        &[0; 64],
        [0; 64],
        Body::Peer { peer: &peer_id },
    )?;
    let mut hpke = [0; 36];
    crypto::EcdheSecret::from_bytes([73; 32])
        .public_key()
        .encode_hpke(&mut hpke)?;
    let joined = owned_join(&mut core, address, &local, hpke)?;
    let connection_parent = if same_epoch { joined } else { [0; 64] };
    let connection = receive(
        &mut core,
        address,
        &peer,
        &peer_id,
        &connection_parent,
        connection_parent,
        Body::Connection {
            amount: 0,
            flags: 0,
        },
    )?;
    let operation = sync(&mut core, address.0, address.1)?;
    let second_epoch = if same_epoch { joined } else { [0; 64] };
    let previous = if same_epoch { connection } else { joined };
    let other = if same_epoch { joined } else { connection };
    let body = Body::Merge {
        first_epoch: &joined,
        second_epoch: &second_epoch,
        previous: &other,
    };
    let bytes = signed(&peer, &peer_id, &previous, body, 0)?;
    let merged = gnunet_crypto::hash512(&bytes.expose()[68..]);
    let epoch = if same_epoch { joined } else { merged };
    assert_eq!(
        receive(&mut core, address, &peer, &peer_id, &previous, epoch, body)?,
        merged
    );
    reply(&mut core, address.1, &merged, &epoch)?;
    settle(&mut core, address.0, operation)?;
    assert!(!core.frontier_sync_required(address.0)?);
    Ok(())
}

#[test]
fn startup_peer_join_connection_branches_converge_through_a_signed_merge() -> Result<(), Error> {
    startup_merge(false)
}

#[test]
fn signed_same_epoch_startup_merge_preserves_its_canonical_epoch_anchor() -> Result<(), Error> {
    startup_merge(true)
}
