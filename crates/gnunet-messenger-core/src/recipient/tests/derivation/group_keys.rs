//! Actual group-key providers and signed outputs, with explicit native port observations.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Retirement {
    Unsent,
    Partial,
    StopPrefix,
    BlockedWholeWrite,
    ExportedRecord,
    WriteBeforeProvider,
}

#[test]
fn a_proposal_key_retires_only_after_all_local_output_retires_unexposed() -> Result<(), Error> {
    for scenario in [
        Retirement::Unsent,
        Retirement::Partial,
        Retirement::StopPrefix,
        Retirement::BlockedWholeWrite,
        Retirement::ExportedRecord,
        Retirement::WriteBeforeProvider,
    ] {
        let local = identity(11)?;
        let remote = identity(22)?;
        let mut instance = Instance::new();
        let mut core = Core::new(&mut instance, Mode::Client, limits(), PROFILE)?;
        let mut entropy = Entropy(9);
        let fixture = group_fixture(&mut core, &local, &remote, &mut entropy)?;
        let GroupFixture {
            room,
            source,
            member,
            epoch,
            ..
        } = fixture;
        let identifier = [3; 32];
        let proposal = core.prepare_send(
            source,
            member,
            fixture.proposal(&identifier, 50),
            100,
            1_000,
        )?;
        let event = submit(&mut core, room, source, &local, epoch)?;
        core.retire_operation(proposal)?;
        if scenario == Retirement::WriteBeforeProvider {
            let key = crypto::AeadKey::from_bytes([64; 32]);
            let public = crypto::EcdheSecret::from_bytes([65; 32]).public_key();
            let announcement = |hmac| Body::Announcement {
                identifier: &identifier,
                public_key: public.as_bytes(),
                nonce: &[66; 32],
                timeout: gnunet_wire::official::RelativeTime::from_micros(50),
                hmac,
            };
            let hmac = crypto::group::message_mac(announcement(&[0; 64]), &key)?;
            core.prepare_send(source, member, announcement(&hmac), 100, 1_000)?;
            observe_original_output(&mut core, room, &local, Retirement::Partial)?;
        }
        let key = core.request_shared_key(source, member, epoch, identifier, 100, 1_000)?;
        let Work::SharedKey { binding, .. } = core.take_work(room)?.ok_or(Fault::NotReady)? else {
            return Err(Fault::Conflict.into());
        };
        core.complete_shared_key(binding, crypto::AeadKey::from_bytes([64; 32]), 100)?;
        core.retire_operation(key)?;
        if scenario == Retirement::ExportedRecord {
            let secret = crypto::records::RecordSecret::from_bytes([19; 64]);
            let _record =
                core.seal_epoch_record(room, &epoch, &identifier, &secret, &mut entropy)?;
        } else if scenario != Retirement::WriteBeforeProvider {
            core.prepare_access(source, member, event, &mut entropy, 100, 1_000)?;
            observe_original_output(&mut core, room, &local, scenario)?;
        }
        core.advance(room, 150)?;
        let scope = core
            .rooms
            .get(room.slot)?
            .find_epoch(&epoch)
            .ok_or(Fault::NotReady)?;
        assert_eq!(
            core.rooms.get(room.slot)?.epochs.get(scope)?.groups.len(),
            2
        );
        core.source_cancelled(source)?;
        core.advance(room, 151)?;
        let epoch = core.rooms.get(room.slot)?.epochs.get(scope)?;
        let present = epoch
            .groups
            .iter()
            .any(|(_, group)| group.identifier == identifier && group.key.is_some());
        assert_eq!(present, scenario != Retirement::Unsent, "{scenario:?}");
        assert_eq!(epoch.best_group.is_some(), present, "{scenario:?}");
    }
    Ok(())
}

fn observe_original_output<'id>(
    core: &mut Core<'id>,
    room: Room<'id>,
    local: &SecretKey,
    scenario: Retirement,
) -> Result<(), Error> {
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
    let bytes = signed(
        local,
        &sender,
        &previous,
        Body::decode(kind, body.expose(), PROFILE)?,
        timestamp,
    )?;
    core.complete_signature(
        binding,
        OwnedBytes::copy_from(bytes.expose())?,
        padding::Decode::Absent,
        100,
    )
    .map_err(|error| error.error)?;
    let Work::Wire { binding, frame, .. } = core.take_work(room)?.ok_or(Fault::NotReady)? else {
        return Err(Fault::Conflict.into());
    };
    match scenario {
        Retirement::Unsent => assert!(matches!(
            core.provider_failed(binding, Fault::Unavailable.into()),
            Err(Error::Protocol(Fault::Conflict))
        )),
        Retirement::Partial => core.write_progress(binding, 1, false)?,
        Retirement::StopPrefix => core.observe_retired_write_prefix(binding, 1)?,
        Retirement::BlockedWholeWrite => {
            while core.events.len() < core.events.capacity() {
                core.event(Event::OperationChanged(
                    binding.operation,
                    OperationPhase::Prepared,
                ))?;
            }
            assert!(matches!(
                core.write_progress(binding, frame.expose().len(), true),
                Err(Error::Protocol(Fault::WouldBlock))
            ));
            drain_events(core);
        }
        Retirement::ExportedRecord | Retirement::WriteBeforeProvider => {
            return Err(Fault::InvalidInput.into());
        }
    }
    Ok(())
}

#[test]
fn historical_groups_keep_original_slots_without_using_the_active_quota() -> Result<(), Error> {
    let local = identity(11)?;
    let remote = identity(22)?;
    let mut instance = Instance::new();
    let mut core = Core::new(
        &mut instance,
        Mode::Client,
        Limits {
            groups_per_epoch: 2,
            ..limits()
        },
        PROFILE,
    )?;
    let mut entropy = Entropy(9);
    let fixture = group_fixture(&mut core, &local, &remote, &mut entropy)?;
    let GroupFixture {
        room,
        source,
        member,
        epoch,
        ..
    } = fixture;
    let identifier = [3; 32];
    let operation = core.prepare_send(
        source,
        member,
        fixture.proposal(&identifier, 50),
        100,
        1_000,
    )?;
    let event = submit(&mut core, room, source, &local, epoch)?;
    core.retire_operation(operation)?;
    let key = core.request_shared_key(source, member, epoch, identifier, 100, 1_000)?;
    let Work::SharedKey { binding, .. } = core.take_work(room)?.ok_or(Fault::NotReady)? else {
        return Err(Fault::Conflict.into());
    };
    core.complete_shared_key(binding, crypto::AeadKey::from_bytes([64; 32]), 100)?;
    core.retire_operation(key)?;
    let root = crypto::records::RecordSecret::from_bytes([19; 64]);
    core.seal_epoch_record(room, &epoch, &identifier, &root, &mut entropy)?;
    let row = core.rooms.get(room.slot)?;
    let scope = row.find_epoch(&epoch).ok_or(Fault::NotReady)?;
    let original = row
        .epochs
        .get(scope)?
        .groups
        .iter()
        .find_map(|(slot, group)| (group.identifier == identifier).then_some(slot))
        .ok_or(Fault::NotReady)?;

    core.advance(room, 150)?;
    let mut next = identifier;
    next[1] = 4;
    let bytes = signed(&local, &LOCAL, &event, fixture.proposal(&next, 500), 150)?;
    core.receive_owned(
        source,
        ReceiveMeta {
            epoch,
            flags: 8,
            requested: false,
            sender_hash: None,
            context: None,
        },
        OwnedBytes::copy_from(bytes.expose())?,
    )
    .map_err(|error| error.error)?;
    core.advance(room, 150)?;
    core.advance(room, 149)?;
    let state = core.rooms.get(room.slot)?.epochs.get(scope)?;
    assert_eq!(state.active_group_count(), 2);
    assert_eq!(state.groups.len(), 3);
    assert!(state.groups.get(original)?.historical());
    assert!(matches!(
        core.group_proposal_deadline(room.slot, scope, identifier, event),
        Err(Error::Protocol(Fault::Timeout))
    ));
    let record = core.seal_epoch_record(room, &epoch, &identifier, &root, &mut entropy)?;
    let recovered = crypto::records::open_epoch_record(&root, record.record())?;
    assert!(recovered.constant_time_eq(&crypto::AeadKey::from_bytes([64; 32])));

    let mut archived = identifier;
    archived[1] = 5;
    let operation = core.request_epoch_record(source, member, epoch, archived, 150, 1_000)?;
    assert_eq!(
        core.rooms.get(room.slot)?.epochs.get(scope)?.groups.len(),
        3
    );
    let Work::EpochRecord { binding, .. } = core.take_work(room)?.ok_or(Fault::NotReady)? else {
        return Err(Fault::Conflict.into());
    };
    let capability = *core.room_key(room)?;
    let record = crypto::records::EpochRecord::seal(
        &root,
        &capability,
        &epoch,
        &archived,
        0,
        &crypto::AeadKey::from_bytes([65; 32]),
        &mut entropy,
    )?;
    core.complete_epoch_record(binding, &root, record.record(), 150)?;
    core.retire_operation(operation)?;
    let state = core.rooms.get(room.slot)?.epochs.get(scope)?;
    assert_eq!(state.active_group_count(), 2);
    assert_eq!(state.groups.len(), 4);
    assert!(state.groups.iter().any(|(_, group)| {
        group.identifier == archived && group.phase == KeyPhase::Revoked && group.key.is_some()
    }));
    assert_eq!(state.groups.get(original)?.identifier, identifier);
    Ok(())
}
