//! Real signatures, announcement MACs and SECRET AEAD across late key arrival.
use super::*;

const IDENTIFIER: ShortHash = [0; 32];
mod group_keys;

pub(super) fn join_epoch<'id>(
    core: &mut Core<'id>,
    address: (Room<'id>, Source<'id>),
    signer: &SecretKey,
    id: &ShortHash,
    parent: &Hash,
) -> Result<(Hash, MemberSession<'id>), Error> {
    let hpke = crypto::EcdheSecret::from_bytes([id[0] + 50; 32]);
    let mut public = [0; 36];
    hpke.public_key().encode_hpke(&mut public)?;
    let signing = signer.public_key()?;
    let body = Body::Join {
        epoch: parent,
        public_key: wire::PublicKey::new(&signing)?,
        hpke_key: wire::keys::HpkePublicKey::new(&public)?,
    };
    let bytes = signed(signer, id, parent, body, 0)?;
    let expected = gnunet_crypto::hash512(&bytes.expose()[68..]);
    let source = core
        .rooms
        .get(address.1.room)?
        .sources
        .get(address.1.slot)?;
    let epoch = if source.public == Some(signing)
        && source.member_id == Some(*id)
        && !core.source_joined(address.1)?
    {
        owned_join(core, address, signer, public)?
    } else {
        receive(core, address, signer, id, parent, expected, body)?
    };
    assert_eq!(epoch, expected);
    let member = core
        .members(address.0)?
        .find_map(|(member, _, actual, phase)| {
            (actual == *id && phase == SessionPhase::Active).then_some(member)
        })
        .ok_or(Fault::NotReady)?;
    Ok((epoch, member))
}

fn announce<'id>(
    core: &mut Core<'id>,
    address: (Room<'id>, Source<'id>),
    signer: &SecretKey,
    id: &ShortHash,
    epoch: &Hash,
    key: &crypto::AeadKey,
    nonce: u8,
) -> Result<Hash, Error> {
    let value = [nonce; 32];
    let public = crypto::EcdheSecret::from_bytes([nonce; 32]).public_key();
    let body = Body::Announcement {
        identifier: &IDENTIFIER,
        public_key: public.as_bytes(),
        nonce: &value,
        timeout: gnunet_wire::official::RelativeTime::from_micros(10_000),
        hmac: &[0; 64],
    };
    let mac = crypto::group::message_mac(body, key)?;
    let body = Body::Announcement {
        identifier: &IDENTIFIER,
        public_key: public.as_bytes(),
        nonce: &value,
        timeout: gnunet_wire::official::RelativeTime::from_micros(10_000),
        hmac: &mac,
    };
    receive(core, address, signer, id, epoch, *epoch, body)
}

fn late_parent(depth: usize, bad_child_mac: bool) -> Result<(), Error> {
    let local = identity(11)?;
    let remote = identity(22)?;
    let third = identity(33)?;
    let signers = [&local, &remote, &third];
    let ids = [LOCAL, REMOTE, [3; 32]];
    let mut instance = Instance::new();
    let mut core = Core::new(&mut instance, Mode::Client, limits(), PROFILE)?;
    let address = open(&mut core, &local)?;
    let (root, local_member) = join_epoch(&mut core, address, &local, &LOCAL, &[0; 64])?;
    let root_key = crypto::AeadKey::from_bytes([74; 32]);
    announce(&mut core, address, &local, &LOCAL, &root, &root_key, 80)?;
    let mut epoch = root;
    let mut key = root_key.derive_epoch(&root, &IDENTIFIER, false)?;
    for generation in 1..=depth {
        let next = join_epoch(
            &mut core,
            address,
            signers[generation],
            &ids[generation],
            &epoch,
        )?
        .0;
        key = if generation == 1 {
            root_key.derive_epoch(&next, &IDENTIFIER, false)?
        } else {
            key.derive_epoch(&next, &IDENTIFIER, false)?
        };
        epoch = next;
        for member in 0..=generation {
            let wrong = crypto::AeadKey::from_bytes([75; 32]);
            let advertised = if bad_child_mac && generation == 1 && member == 1 {
                &wrong
            } else {
                &key
            };
            announce(
                &mut core,
                address,
                signers[member],
                &ids[member],
                &epoch,
                advertised,
                90 + (generation * 3 + member) as u8,
            )?;
        }
        assert_eq!(
            core.group_state(address.0, &epoch, &IDENTIFIER)?.0,
            KeyPhase::Missing
        );
    }
    let mut encrypted = SensitiveBuffer::<8192>::new();
    encrypted.seal_secret(
        &IDENTIFIER,
        &key,
        Body::Text {
            text: Text::new(b"late parent actual secret")?,
        },
        PROFILE,
        &mut SensitiveBuffer::<8192>::new(),
        &mut Entropy(7),
    )?;
    let body = wire::body::Body::decode(wire::envelope::Kind::SECRET, encrypted.expose(), PROFILE)?;
    let message = receive(
        &mut core,
        address,
        signers[depth],
        &ids[depth],
        &epoch,
        epoch,
        body,
    )?;
    assert!(
        core.pending_decryption(address.0)?
            .any(|hash| hash == &message)
    );
    assert!(matches!(
        core.decrypt_message(address.0, &message, &mut SensitiveBuffer::<8192>::new()),
        Err(Error::Protocol(Fault::NotReady))
    ));
    // Relocate the actually admitted epoch owners through their generational
    // table, without changing signed messages, membership or confirmations.
    // Descendants now precede parents, so one forward sweep cannot suffice.
    let row = core.rooms.get_mut(address.0.slot)?;
    let slots: alloc::vec::Vec<_> = row.epochs.iter().map(|(slot, _)| slot).collect();
    let mut epochs = alloc::vec::Vec::new();
    for slot in slots {
        epochs.push(row.epochs.remove(slot)?);
    }
    for epoch in epochs {
        row.epochs.insert(epoch).map_err(|(error, _)| error)?;
    }
    // Admit the original provider job only after the storage-layout fixture.
    // No already-issued capability is retargeted to a new slot generation.
    let original =
        core.request_shared_key(address.1, local_member, root, IDENTIFIER, 100, 10_000)?;
    let Work::SharedKey { binding, .. } = core.take_work(address.0)?.ok_or(Fault::NotReady)? else {
        return Err(Fault::Conflict.into());
    };
    assert_eq!(binding.operation, original);
    let charged = core.charged_bytes();
    core.complete_shared_key(binding, root_key, 100)?;
    // One unit per caller turn demonstrates persistent, fair graph/derivation
    // progress rather than a recursive transitive scan in one advance call.
    core.limits.work_per_turn = 1;
    assert_eq!(core.advance(address.0, 100)?, 1);
    assert!(core.has_work(address.0)?);
    while core.pop_event().is_some() {}
    for _ in 0..256 {
        assert!(core.advance(address.0, 100)? <= 1);
        while core.pop_event().is_some() {}
        if !core.has_work(address.0)? {
            break;
        }
    }
    assert!(!core.has_work(address.0)?);
    assert_eq!(core.charged_bytes(), charged);
    let state = core.group_state(address.0, &epoch, &IDENTIFIER)?;
    if bad_child_mac {
        assert_eq!(state.0, KeyPhase::Missing);
        assert!(matches!(
            core.decrypt_message(address.0, &message, &mut SensitiveBuffer::<8192>::new()),
            Err(Error::Protocol(Fault::NotReady))
        ));
    } else {
        assert_eq!(
            (state.0, state.2, state.3),
            (KeyPhase::Present, depth + 1, depth + 1)
        );
        core.decrypt_message(address.0, &message, &mut SensitiveBuffer::<8192>::new())?;
        drain(&mut core, address.0)?;
        assert!(
            !core
                .pending_decryption(address.0)?
                .any(|hash| hash == &message)
        );
        assert!(
            matches!(core.message(address.0, &message)?.body()?, Body::Text { text } if text.content().expose() == b"late parent actual secret")
        );
        let nonce = [200; 32];
        let revolution = Body::Revolution {
            identifier: &IDENTIFIER,
            nonce: &nonce,
            hmac: &[0; 64],
        };
        let mac = crypto::group::message_mac(revolution, &crypto::AeadKey::from_bytes([74; 32]))?;
        receive(
            &mut core,
            address,
            &local,
            &LOCAL,
            &root,
            root,
            Body::Revolution {
                identifier: &IDENTIFIER,
                nonce: &nonce,
                hmac: &mac,
            },
        )?;
        let revoked = core.group_state(address.0, &epoch, &IDENTIFIER)?;
        assert_eq!((revoked.0, revoked.4), (KeyPhase::Revoked, false));
    }
    Ok(())
}

#[test]
fn late_parent_key_materializes_an_existing_missing_child_and_decrypts() -> Result<(), Error> {
    late_parent(1, false)
}

#[test]
fn late_parent_key_propagates_through_verified_child_cohorts() -> Result<(), Error> {
    late_parent(2, false)
}

#[test]
fn invalid_child_announcement_cannot_authorize_the_next_epoch_key() -> Result<(), Error> {
    late_parent(2, true)
}

struct GroupFixture<'id> {
    room: Room<'id>,
    source: Source<'id>,
    member: MemberSession<'id>,
    epoch: Hash,
    parents: [Hash; 2],
}

impl GroupFixture<'_> {
    fn proposal<'a>(&'a self, identifier: &'a ShortHash, lifetime: u64) -> Body<'a> {
        Body::Group {
            identifier,
            initiator: &self.parents[0],
            partner: &self.parents[1],
            timeout: gnunet_wire::official::RelativeTime::from_micros(lifetime),
        }
    }
}

fn group_fixture<'id>(
    core: &mut Core<'id>,
    local: &SecretKey,
    remote: &SecretKey,
    entropy: &mut Entropy,
) -> Result<GroupFixture<'id>, Error> {
    let address = open(core, local)?;
    let (room, source) = address;
    let (root, member) = join_epoch(core, address, local, &LOCAL, &[0; 64])?;
    let (epoch, _) = join_epoch(core, address, remote, &REMOTE, &root)?;
    let key = crypto::AeadKey::from_bytes([61; 32]);
    let scope = core
        .rooms
        .get(room.slot)?
        .find_epoch(&epoch)
        .ok_or(Fault::NotReady)?;
    let group = core.ensure_group(room.slot, scope, IDENTIFIER)?;
    core.install_group_key(
        room.slot,
        scope,
        group,
        crypto::AeadKey::from_bytes([61; 32]),
    )?;
    let ephemeral = core.request_ephemeral_key(source, member, epoch, 10_000, 100, 1_000)?;
    let Work::EphemeralKey { binding, .. } = core.take_work(room)?.ok_or(Fault::NotReady)? else {
        return Err(Fault::Conflict.into());
    };
    core.complete_ephemeral_key(binding, crypto::EcdheSecret::from_bytes([62; 32]), 100)?;
    core.retire_operation(ephemeral)?;
    let partner = announce(core, address, remote, &REMOTE, &epoch, &key, 63)?;
    let own = core.prepare_announcement(source, member, IDENTIFIER, 9_000, entropy, 100, 1_000)?;
    let initiator = submit(core, room, source, local, epoch)?;
    core.retire_operation(own)?;
    Ok(GroupFixture {
        room,
        source,
        member,
        epoch,
        parents: [initiator, partner],
    })
}

#[test]
fn epoch_refreshes_the_original_announcement_after_recipient_rotation() -> Result<(), Error> {
    let local = identity(11)?;
    let remote = identity(22)?;
    let mut instance = Instance::new();
    let mut core = Core::new(&mut instance, Mode::Client, limits(), PROFILE)?;
    let mut entropy = Entropy(9);
    let GroupFixture {
        room,
        source,
        member,
        epoch,
        ..
    } = group_fixture(&mut core, &local, &remote, &mut entropy)?;
    core.rooms.get_mut(room.slot)?.capabilities =
        RoomCapabilities::decode(&[0; 64], PROFILE.endian);
    let now = 10_010;
    let hard = now + 120_000_000;
    core.advance(room, now)?;
    let rotation = core
        .drive_epoch_with_group_keys(source, member, &mut entropy, now, hard, true)?
        .ok_or(Fault::NotReady)?;
    let Work::EphemeralKey { binding, .. } = core.take_work(room)?.ok_or(Fault::NotReady)? else {
        return Err(Fault::Conflict.into());
    };
    assert_eq!(binding.operation, rotation);
    let key = crypto::EcdheSecret::from_bytes([65; 32]);
    let public = key.public_key();
    core.complete_ephemeral_key(binding, key, now)?;
    core.retire_operation(rotation)?;

    let refresh = core
        .drive_epoch_with_group_keys(source, member, &mut entropy, now, hard, true)?
        .ok_or(Fault::NotReady)?;
    let Work::Sign {
        binding,
        kind,
        body,
        ..
    } = core.take_work(room)?.ok_or(Fault::NotReady)?
    else {
        return Err(Fault::Conflict.into());
    };
    assert_eq!(binding.epoch, epoch);
    let announcement = Body::decode(kind, body.expose(), PROFILE)?;
    assert!(
        matches!(announcement, Body::Announcement { identifier, public_key, timeout, .. }
        if *identifier == IDENTIFIER && public_key == public.as_bytes() && timeout.as_micros() == 60_000_000)
    );
    assert_eq!(core.operation_deadline(refresh)?, now + 60_000_000);
    Ok(())
}

#[test]
fn automatic_private_group_uses_echoed_announcements_and_advances_its_original_proposal()
-> Result<(), Error> {
    let local = identity(11)?;
    let remote = identity(22)?;
    let mut instance = Instance::new();
    let mut core = Core::new(&mut instance, Mode::Client, limits(), PROFILE)?;
    let mut entropy = Entropy(9);
    let GroupFixture {
        room,
        source,
        member,
        epoch,
        ..
    } = group_fixture(&mut core, &local, &remote, &mut entropy)?;
    assert!(
        core.drive_epoch_with_group_keys(source, member, &mut entropy, 100, 1_000, true)?
            .is_none()
    );
    core.rooms.get_mut(room.slot)?.capabilities =
        RoomCapabilities::decode(&[0; 64], PROFILE.endian);
    assert!(
        core.drive_epoch_with_group_keys(source, member, &mut entropy, 100, 1_000, false)?
            .is_none()
    );
    let proposal = core
        .drive_epoch_with_group_keys(source, member, &mut entropy, 100, 1_000, true)?
        .ok_or(Fault::NotReady)?;
    assert!(
        core.drive_epoch_with_group_keys(source, member, &mut entropy, 100, 1_000, true)?
            .is_none()
    );
    let event = submit(&mut core, room, source, &local, epoch)?;
    core.retire_operation(proposal)?;
    let generated = core
        .drive_epoch_with_group_keys(source, member, &mut entropy, 100, 1_000, true)?
        .ok_or(Fault::NotReady)?;
    let Work::SharedKey { binding, .. } = core.take_work(room)?.ok_or(Fault::NotReady)? else {
        return Err(Fault::Conflict.into());
    };
    assert_eq!(binding.operation, generated);
    assert_eq!(binding.message, event);
    core.complete_shared_key(binding, crypto::AeadKey::from_bytes([64; 32]), 100)?;
    core.retire_operation(generated)?;
    core.drive_epoch_with_group_keys(source, member, &mut entropy, 100, 1_000, true)?
        .ok_or(Fault::NotReady)?;
    let Work::Sign { kind, body, .. } = core.take_work(room)?.ok_or(Fault::NotReady)? else {
        return Err(Fault::Conflict.into());
    };
    assert!(
        matches!(Body::decode(kind, body.expose(), PROFILE)?, Body::Access { event: reference, .. } if *reference == event)
    );
    Ok(())
}

#[test]
fn expired_group_slot_reopens_before_a_queued_proposal_without_releasing_its_identifier()
-> Result<(), Error> {
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
    let fixture = group_fixture(&mut core, &local, &remote, &mut Entropy(9))?;
    let GroupFixture {
        room,
        source,
        member,
        epoch,
        ..
    } = fixture;
    let old = [3; 32];
    let proposal = core.prepare_send(source, member, fixture.proposal(&old, 50), 100, 1_000)?;
    let original = submit(&mut core, room, source, &local, epoch)?;
    core.retire_operation(proposal)?;
    let row = core.rooms.get(room.slot)?;
    let epoch_slot = row.find_epoch(&epoch).ok_or(Fault::NotReady)?;
    let old_slot = row
        .epochs
        .get(epoch_slot)?
        .groups
        .iter()
        .find_map(|(slot, group)| (group.identifier == old).then_some(slot))
        .ok_or(Fault::NotReady)?;

    let mut next = [4; 32];
    next[0] = 3;
    let bytes = signed(&local, &LOCAL, &original, fixture.proposal(&next, 500), 110)?;
    let replacement = core
        .receive_owned(
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
    assert!(matches!(
        core.advance(room, 149),
        Err(Error::Protocol(Fault::Capacity))
    ));
    drain_events(&mut core);
    core.advance(room, 150)?;
    let row = core.rooms.get(room.slot)?;
    assert!(row.epochs.get(epoch_slot)?.groups.get(old_slot).is_err());
    assert!(
        row.nodes
            .get(row.find_node(&replacement).ok_or(Fault::NotReady)?)?
            .semantic_applied
    );
    assert!(matches!(
        core.group_proposal_deadline(room.slot, epoch_slot, old, original),
        Err(Error::Protocol(Fault::Timeout))
    ));

    let original_slot = row.find_node(&original).ok_or(Fault::NotReady)?;
    assert!(matches!(
        core.request_shared_key(source, member, epoch, old, 150, 900),
        Err(Error::Protocol(Fault::Timeout))
    ));
    let released =
        core.rooms
            .get_mut(room.slot)?
            .erase_message(&mut core.frames, original_slot, None)?;
    core.release(released)?;
    assert_eq!(
        core.known_identifier_order(room.slot, &old)?,
        Some(PROFILE.endian)
    );
    let replay = receive(
        &mut core,
        (room, source),
        &local,
        &LOCAL,
        &replacement,
        epoch,
        fixture.proposal(&old, 800),
    )?;
    let row = core.rooms.get(room.slot)?;
    assert_eq!(
        row.nodes
            .get(row.find_node(&replay).ok_or(Fault::NotReady)?)?
            .phase,
        MessagePhase::Rejected
    );
    assert!(
        row.epochs
            .get(epoch_slot)?
            .groups
            .iter()
            .all(|(_, group)| group.identifier != old)
    );

    // An authentic record can restore the old key even with all live slots
    // occupied. It cannot turn the deleted, elapsed GROUP back into a grant.
    let key = crypto::AeadKey::from_bytes([73; 32]);
    let record_secret = crypto::records::RecordSecret::from_bytes([74; 64]);
    let capability = *core.room_key(room)?;
    let sealed = crypto::records::EpochRecord::seal(
        &record_secret,
        &capability,
        &epoch,
        &old,
        1,
        &key,
        &mut Entropy(19),
    )?;
    let record = core.request_epoch_record(source, member, epoch, old, 150, 900)?;
    let Work::EpochRecord { binding, .. } = core.take_work(room)?.ok_or(Fault::NotReady)? else {
        return Err(Fault::Conflict.into());
    };
    core.complete_epoch_record(binding, &record_secret, sealed.record(), 150)?;
    core.retire_operation(record)?;
    let state = core.rooms.get(room.slot)?.epochs.get(epoch_slot)?;
    assert_eq!(state.active_group_count(), 2);
    assert!(state.groups.iter().any(|(_, group)| {
        group.identifier == old
            && group.historical()
            && group.proposal == Some(original)
            && group.valid
            && group
                .key
                .as_ref()
                .is_some_and(|restored| restored.constant_time_eq(&key))
    }));
    assert!(
        core.group_proposal_deadline(room.slot, epoch_slot, old, original)
            .is_err()
    );
    Ok(())
}

fn drain_events(core: &mut Core<'_>) {
    while core.pop_event().is_some() {}
}
