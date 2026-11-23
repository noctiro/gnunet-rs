//! Historical HPKE recovery and real causal frontier retirement.
use super::*;
#[test]
fn historical_key_arrival_waits_for_authenticated_echo_and_exact_sync() -> Result<(), Error> {
    let local = identity(11)?;
    let remote = identity(22)?;
    let third = identity(33)?;
    let peer = identity(44)?;
    let mut instance = Instance::new();
    let mut core = Core::new(&mut instance, Mode::Client, limits(), PROFILE)?;
    let address @ (room, source) = open(&mut core, &local)?;
    let root = join_after(&mut core, address, &local, &LOCAL, &[0; 64], &[0; 64])?;
    let old = join_after(&mut core, address, &remote, &REMOTE, &root, &root)?;
    let member = core.local_member(room)?.ok_or(Fault::NotReady)?;
    let key = crypto::AeadKey::from_bytes([74; 32]);
    let dh = crypto::EcdheSecret::from_bytes([65; 32]);
    let dh_public = dh.public_key();
    let announcement = Body::Announcement {
        identifier: &IDENTIFIER,
        public_key: dh_public.as_bytes(),
        nonce: &[81; 32],
        timeout: gnunet_wire::official::RelativeTime::from_micros(10_000),
        hmac: &[0; 64],
    };
    let mac = crypto::group::message_mac(announcement, &key)?;
    let announcement = receive(
        &mut core,
        address,
        &remote,
        &REMOTE,
        &old,
        old,
        Body::Announcement {
            identifier: &IDENTIFIER,
            public_key: dh_public.as_bytes(),
            nonce: &[81; 32],
            timeout: gnunet_wire::official::RelativeTime::from_micros(10_000),
            hmac: &mac,
        },
    )?;
    let ephemeral = core.request_ephemeral_key(source, member, old, 10_000, 100, 10_000)?;
    let Work::EphemeralKey { binding, .. } = core.take_work(room)?.ok_or(Fault::NotReady)? else {
        return Err(Fault::Conflict.into());
    };
    let recipient = crypto::EcdheSecret::from_bytes([66; 32]);
    let recipient_public = recipient.public_key();
    core.complete_ephemeral_key(binding, recipient, 100)?;
    core.retire_operation(ephemeral)?;
    let mut peer_public = [0; 32];
    peer_public.copy_from_slice(&peer.public_key()?[4..]);
    let introduction = receive(
        &mut core,
        address,
        &peer,
        &peer_public,
        &announcement,
        old,
        Body::Peer { peer: &peer_public },
    )?;
    let current = join_after(&mut core, address, &third, &[3; 32], &introduction, &old)?;
    let earlier_sync = core.synchronize(source, 10_000)?;
    assert!(matches!(
        core.prepare_appeal(source, member, announcement, 1_000, 100, 10_000),
        Err(Error::Protocol(Fault::WouldBlock))
    ));
    assert_eq!(core.frontier_control(room)?, None);
    assert_eq!(write_wire(&mut core, room)?.operation(), earlier_sync);
    core.on_notification(
        source,
        wire::Response::Sync(wire::Room {
            door: &[0; 32],
            key: &ROOM,
            previous: &current,
            epoch: &current,
        }),
        100,
    )?;
    drain(&mut core, room)?;
    core.retire_operation(earlier_sync)?;
    let mut encrypted = SensitiveBuffer::<8192>::new();
    encrypted.seal_secret(
        &IDENTIFIER,
        &key,
        Body::Text {
            text: Text::new(b"historical original")?,
        },
        PROFILE,
        &mut SensitiveBuffer::<8192>::new(),
        &mut Entropy(9),
    )?;
    let secret = signed(
        &remote,
        &REMOTE,
        &announcement,
        Body::decode(Kind::SECRET, encrypted.expose(), PROFILE)?,
        10,
    )?;
    let secret_hash = gnunet_crypto::hash512(&secret.expose()[68..]);
    let get = core.request_missing(source, secret_hash, 100, 10_000)?;
    write_wire(&mut core, room)?;
    notification(&mut core, source, &remote, secret.expose(), &old, 0)?;
    core.retire_operation(get)?;
    drain(&mut core, room)?;
    assert_eq!(core.rooms.get(source.room)?.current_epoch, current);
    let control = core
        .drive_epoch(source, member, &mut Entropy(31), 100, 10_000)?
        .ok_or(Fault::NotReady)?;
    assert_eq!(core.frontier_control(room)?, Some(control));
    let appeal = sign_and_write(&mut core, room, &local, &old)?;
    assert!(matches!(
        core.synchronize(source, 10_000),
        Err(Error::Protocol(Fault::NotReady))
    ));
    assert!(
        core.prepare_send(
            source,
            member,
            Body::Name {
                name: Text::new(b"ordinary")?
            },
            100,
            10_000
        )
        .is_err()
    );
    let appeal_hash = notification(&mut core, source, &local, appeal.expose(), &old, 8)?;
    drain(&mut core, room)?;
    assert_eq!(core.operation_phase(control)?, OperationPhase::Complete);
    assert!(core.retire_operation(control).is_err());
    // A genuine old-epoch ACCESS imports only through its original recipient
    // key, announcement MAC and member gates while the send fence stays closed.
    let access =
        crypto::group::Access::seal(&appeal_hash, recipient_public, &key, &mut Entropy(47))?;
    let access = signed(&remote, &REMOTE, &old, access.body(), 10)?;
    notification(&mut core, source, &remote, access.expose(), &old, 8)?;
    drain(&mut core, room)?;
    assert_eq!(
        core.group_state(room, &old, &IDENTIFIER)?.0,
        KeyPhase::Present
    );
    core.decrypt_message(room, &secret_hash, &mut SensitiveBuffer::<8192>::new())?;
    drain(&mut core, room)?;
    assert!(
        matches!(core.message(room, &secret_hash)?.body()?, Body::Text { text } if text.content().expose() == b"historical original")
    );
    assert!(
        core.prepare_send(
            source,
            member,
            Body::Name {
                name: Text::new(b"ordinary")?
            },
            100,
            10_000
        )
        .is_err()
    );
    let sync = core.synchronize(source, 10_000)?;
    assert_eq!(write_wire(&mut core, room)?.operation(), sync);
    let access_hash = gnunet_crypto::hash512(&access.expose()[68..]);
    let old_merge_body = Body::Merge {
        first_epoch: &old,
        second_epoch: &old,
        previous: &appeal_hash,
    };
    let old_merge = receive(
        &mut core,
        address,
        &peer,
        &peer_public,
        &access_hash,
        old,
        old_merge_body,
    )?;
    let merge_body = Body::Merge {
        first_epoch: &current,
        second_epoch: &old,
        previous: &old_merge,
    };
    let merge = signed(&peer, &peer_public, &current, merge_body, 0)?;
    let merge_hash = gnunet_crypto::hash512(&merge.expose()[68..]);
    assert_eq!(
        receive(
            &mut core,
            address,
            &peer,
            &peer_public,
            &current,
            merge_hash,
            merge_body
        )?,
        merge_hash
    );
    core.on_notification(
        source,
        wire::Response::Sync(wire::Room {
            door: &[0; 32],
            key: &ROOM,
            previous: &merge_hash,
            epoch: &merge_hash,
        }),
        100,
    )?;
    assert_eq!(core.operation_phase(sync)?, OperationPhase::Written);
    drain(&mut core, room)?;
    assert_eq!(core.frontier_control(room)?, None);
    core.retire_operation(control)?;
    core.retire_operation(sync)?;
    // The now-known historical key is never substituted for an absent current key.
    assert!(
        core.prepare_secret_profiled(
            source,
            member,
            Body::Text {
                text: Text::new(b"new cohort")?
            },
            ShortLayout::same(PROFILE),
            &mut SensitiveBuffer::<8192>::new(),
            &mut SensitiveBuffer::<8192>::new(),
            &mut Entropy(57),
            100,
            10_000
        )
        .is_err()
    );
    Ok(())
}
