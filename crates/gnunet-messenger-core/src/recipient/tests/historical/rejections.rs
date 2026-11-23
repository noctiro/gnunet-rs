//! Signed-control refusal without a complete original causal epoch.
use super::*;
fn announcement_bytes(
    signer: &SecretKey,
    id: &ShortHash,
    previous: &Hash,
    key: &crypto::AeadKey,
    nonce: u8,
) -> Result<SensitiveBuffer<8192>, Error> {
    let public = crypto::EcdheSecret::from_bytes([65; 32]).public_key();
    let value = [nonce; 32];
    let timeout = gnunet_wire::official::RelativeTime::from_micros(10_000);
    let body = Body::Announcement {
        identifier: &IDENTIFIER,
        public_key: public.as_bytes(),
        nonce: &value,
        timeout,
        hmac: &[0; 64],
    };
    let mac = crypto::group::message_mac(body, key)?;
    signed(
        signer,
        id,
        previous,
        Body::Announcement {
            identifier: &IDENTIFIER,
            public_key: public.as_bytes(),
            nonce: &value,
            timeout,
            hmac: &mac,
        },
        10,
    )
}
#[test]
fn historical_controls_refuse_missing_causality_wrong_body_member_and_epoch() -> Result<(), Error> {
    let local = identity(11)?;
    let remote = identity(22)?;
    let third = identity(33)?;
    let mut instance = Instance::new();
    let mut core = Core::new(&mut instance, Mode::Client, limits(), PROFILE)?;
    let address @ (room, source) = open(&mut core, &local)?;
    let root = join_after(&mut core, address, &local, &LOCAL, &[0; 64], &[0; 64])?;
    let old = join_after(&mut core, address, &remote, &REMOTE, &root, &root)?;
    let member = core.local_member(room)?.ok_or(Fault::NotReady)?;
    let key = crypto::AeadKey::from_bytes([74; 32]);
    let predecessor = signed(
        &remote,
        &REMOTE,
        &old,
        Body::Name {
            name: Text::new(b"real predecessor")?,
        },
        10,
    )?;
    let predecessor_hash = gnunet_crypto::hash512(&predecessor.expose()[68..]);
    let bytes = announcement_bytes(&remote, &REMOTE, &predecessor_hash, &key, 81)?;
    let announcement = direct(&mut core, address, bytes.expose(), old)?;
    assert!(!core.message(room, &announcement)?.history_complete());
    assert!(matches!(
        core.prepare_appeal(source, member, announcement, 1_000, 100, 10_000),
        Err(Error::Protocol(Fault::NotReady))
    ));
    assert_eq!(core.frontier_control(room)?, None);
    direct(&mut core, address, predecessor.expose(), old)?;
    assert!(core.message(room, &announcement)?.history_complete());
    let current = join_after(&mut core, address, &third, &[3; 32], &old, &old)?;
    let wrong_body = receive(
        &mut core,
        address,
        &remote,
        &REMOTE,
        &current,
        current,
        Body::Name {
            name: Text::new(b"not an announcement")?,
        },
    )?;
    assert!(matches!(
        core.prepare_appeal(source, member, wrong_body, 1_000, 100, 10_000),
        Err(Error::Permission)
    ));
    // Both contacts belong to current, but this signature points to old. Native
    // epoch metadata cannot transplant that announcement into current.
    let spoof = announcement_bytes(&remote, &REMOTE, &old, &key, 82)?;
    let spoof = direct(&mut core, address, spoof.expose(), current)?;
    assert!(core.message(room, &spoof)?.history_complete());
    assert!(matches!(
        core.prepare_appeal(source, member, spoof, 1_000, 100, 10_000),
        Err(Error::AttributionConflict)
    ));
    // Alice never belonged to Bob's root epoch; a valid signature grants no
    // historical membership in that earlier cohort.
    let outsider = announcement_bytes(&remote, &REMOTE, &root, &key, 83)?;
    let outsider = direct(&mut core, address, outsider.expose(), root)?;
    assert!(matches!(
        core.prepare_appeal(source, member, outsider, 1_000, 100, 10_000),
        Err(Error::Permission)
    ));
    assert_eq!(core.frontier_control(room)?, None);
    Ok(())
}
