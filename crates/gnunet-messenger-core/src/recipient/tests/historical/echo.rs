//! Exact original JOIN echo/write receipts, including duplicate canonical hashes
//! and callback order independent of actual native I/O completion order.
use super::*;

struct Taken<'id> {
    operation: Operation<'id>,
    binding: Binding<'id>,
    frame: OwnedBytes,
    signed: SensitiveBuffer<8192>,
}
fn take<'id>(
    core: &mut Core<'id>,
    room: Room<'id>,
    key: &SecretKey,
    operation: Operation<'id>,
) -> Result<Taken<'id>, Error> {
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
    assert_eq!(binding.operation(), operation);
    let signed = signed(
        key,
        &sender,
        &previous,
        Body::decode(kind, body.expose(), PROFILE)?,
        timestamp,
    )?;
    core.complete_signature(
        binding,
        OwnedBytes::copy_from(signed.expose())?,
        padding::Decode::Absent,
        100,
    )
    .map_err(|error| error.error)?;
    let Work::Wire { binding, frame, .. } = core.take_work(room)?.ok_or(Fault::NotReady)? else {
        return Err(Fault::Conflict.into());
    };
    Ok(Taken {
        operation,
        binding,
        frame,
        signed,
    })
}
fn hpke() -> Result<PublicKey, Error> {
    let mut public = [0; 36];
    crypto::EcdheSecret::from_bytes([72; 32])
        .public_key()
        .encode_hpke(&mut public)?;
    Ok(public)
}
fn write<'id>(core: &mut Core<'id>, original: &Taken<'id>) -> Result<(), Error> {
    core.write_progress(original.binding, original.frame.expose().len(), true)
}
fn reopen<'id>(
    core: &mut Core<'id>,
    room: Room<'id>,
    key: &SecretKey,
) -> Result<Source<'id>, Error> {
    let public = key.public_key()?;
    core.configure_reopen(room, public)?;
    let source = core.attach_source(
        room,
        SourceRole::Client,
        padding::Decode::Absent,
        Some(public),
    )?;
    core.create_submitted(source)?;
    core.on_notification(
        source,
        wire::Response::MemberId {
            key: &ROOM,
            id: &LOCAL,
            reset: 1,
        },
        100,
    )?;
    let operation = core.open(source, 10_000)?;
    assert_eq!(write_wire(core, room)?.operation(), operation);
    core.on_notification(
        source,
        wire::Response::Open(wire::Room {
            key: &ROOM,
            door: &[0; 32],
            previous: &[0; 64],
            epoch: &[0; 64],
        }),
        100,
    )?;
    core.retire_operation(operation)?;
    Ok(source)
}

#[test]
fn authenticated_join_echo_before_write_callback_waits_for_the_same_full_write() -> Result<(), Error>
{
    let local = identity(11)?;
    let mut instance = Instance::new();
    let mut core = Core::new(&mut instance, Mode::Client, limits(), PROFILE)?;
    let (room, source) = open(&mut core, &local)?;
    let operation = core.prepare_join(source, hpke()?, 100, 10_000)?;
    let original = take(&mut core, room, &local, operation)?;
    let hash = gnunet_crypto::hash512(&original.signed.expose()[68..]);
    notification(
        &mut core,
        source,
        &local,
        original.signed.expose(),
        &hash,
        8,
    )?;
    drain(&mut core, room)?; // Semantic application alone cannot settle the write.
    assert!(!core.source_joined(source)?);
    assert!(!core.joined(room)?);
    assert!(!core.bootstrap_join_observed(source, operation)?);
    assert_eq!(core.operation_phase(operation)?, OperationPhase::Taken);
    let prefix = original.frame.expose().len() / 2;
    core.write_progress(original.binding, prefix, false)?;
    assert!(!core.bootstrap_join_observed(source, operation)?);
    core.write_progress(
        original.binding,
        original.frame.expose().len() - prefix,
        true,
    )?;
    assert_eq!(core.operation_phase(operation)?, OperationPhase::Complete);
    assert!(core.bootstrap_join_observed(source, operation)?);
    assert!(core.source_joined(source)?);
    assert!(core.joined(room)?);
    let node = core.rooms.get(source.room)?.nodes.get(
        core.rooms
            .get(source.room)?
            .find_node(&hash)
            .ok_or(Fault::NotReady)?,
    )?;
    assert!(!node.local_sent); // No historical/node observation was rewritten.
    core.retire_operation(operation)?;
    assert!(
        core.rooms
            .get(source.room)?
            .sources
            .get(source.slot)?
            .join_operation
            .is_none()
    );
    Ok(())
}

fn same_hash(echo_first: bool) -> Result<(), Error> {
    let local = identity(11)?;
    let mut instance = Instance::new();
    let mut core = Core::new(&mut instance, Mode::Client, limits(), PROFILE)?;
    let (room, old_source) = open(&mut core, &local)?;
    let operation = core.prepare_join(old_source, hpke()?, 100, 10_000)?;
    let old = take(&mut core, room, &local, operation)?;
    write(&mut core, &old)?;
    let hash = gnunet_crypto::hash512(&old.signed.expose()[68..]);
    notification(&mut core, old_source, &local, old.signed.expose(), &hash, 8)?;
    drain(&mut core, room)?;
    assert!(core.source_joined(old_source)?);
    core.retire_operation(operation)?;
    core.source_cancelled(old_source)?;
    let source = reopen(&mut core, room, &local)?;
    assert_ne!(source, old_source);
    // An old signed notification has no new original JOIN owner to acknowledge.
    notification(&mut core, source, &local, old.signed.expose(), &hash, 8)?;
    assert!(!core.source_joined(source)?);
    let operation = core.prepare_join(source, hpke()?, 100, 10_000)?;
    // A replay before even taking the new wire owner is not its echo receipt.
    notification(&mut core, source, &local, old.signed.expose(), &hash, 8)?;
    let original = take(&mut core, room, &local, operation)?;
    assert_eq!(original.signed.expose(), old.signed.expose());
    assert_eq!(*original.binding.message(), hash);
    assert_ne!(original.operation, old.operation);
    if echo_first {
        notification(
            &mut core,
            source,
            &local,
            original.signed.expose(),
            &hash,
            8,
        )?;
        assert!(!core.bootstrap_join_observed(source, operation)?);
        assert!(!core.source_joined(source)?);
        write(&mut core, &original)?;
    } else {
        write(&mut core, &original)?;
        assert!(!core.bootstrap_join_observed(source, operation)?);
        assert!(!core.source_joined(source)?);
        notification(
            &mut core,
            source,
            &local,
            original.signed.expose(),
            &hash,
            8,
        )?;
    }
    assert!(core.bootstrap_join_observed(source, operation)?);
    assert!(core.source_joined(source)?);
    let node = core.rooms.get(source.room)?.nodes.get(
        core.rooms
            .get(source.room)?
            .find_node(&hash)
            .ok_or(Fault::NotReady)?,
    )?;
    assert_eq!(core.message(room, &hash)?.origin().live(), Some(old_source));
    assert!(node.local_sent);
    core.retire_operation(operation)?;
    core.source_cancelled(source)?;
    assert!(core.write_progress(original.binding, 0, true).is_err());
    assert!(core.bootstrap_join_observed(source, operation).is_err());
    Ok(())
}
#[test]
fn fresh_same_hash_join_needs_its_own_write_and_echo_without_provenance_rebind() -> Result<(), Error>
{
    same_hash(false)
}
#[test]
fn fresh_same_hash_join_also_handles_echo_before_its_write_callback() -> Result<(), Error> {
    same_hash(true)
}
