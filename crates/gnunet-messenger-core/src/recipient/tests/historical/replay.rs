//! Historical self-signatures and another source's actual JOIN cannot settle a
//! fresh source's own initialization debt, even when public/member IDs match.
use super::*;

#[test]
fn replayed_own_join_cannot_initialize_a_fresh_or_sibling_source() -> Result<(), Error> {
    let local = identity(11)?;
    let mut instance = Instance::new();
    let mut core = Core::new(&mut instance, Mode::Client, limits(), PROFILE)?;
    let address @ (room, source) = open(&mut core, &local)?;
    let public = local.public_key()?;
    let hpke = crypto::EcdheSecret::from_bytes([72; 32]);
    let mut encoded = [0; 36];
    hpke.public_key().encode_hpke(&mut encoded)?;
    let old = signed(
        &local,
        &LOCAL,
        &[0; 64],
        Body::Join {
            epoch: &[0; 64],
            public_key: wire::PublicKey::new(&public)?,
            hpke_key: wire::keys::HpkePublicKey::new(&encoded)?,
        },
        0,
    )?;
    let hash = gnunet_crypto::hash512(&old.expose()[68..]);
    assert_eq!(direct(&mut core, address, old.expose(), hash)?, hash);
    assert!(!core.source_joined(source)?);
    assert!(!core.joined(room)?);
    let historical_member = core.local_member(room)?.ok_or(Fault::NotReady)?;
    assert!(matches!(
        core.prepare_send(
            source,
            historical_member,
            Body::Name {
                name: Text::new(b"not initialized")?
            },
            100,
            10_000
        ),
        Err(Error::Protocol(Fault::NotReady))
    ));
    assert!(matches!(
        core.request_ephemeral_key(source, historical_member, hash, 10_000, 100, 10_000),
        Err(Error::Protocol(Fault::NotReady))
    ));
    let other = core.attach_source(
        room,
        SourceRole::Client,
        padding::Decode::Absent,
        Some(public),
    )?;
    core.create_submitted(other)?;
    core.on_notification(
        other,
        wire::Response::MemberId {
            key: &ROOM,
            id: &LOCAL,
            reset: 1,
        },
        100,
    )?;
    let open = core.open(other, 10_000)?;
    assert_eq!(write_wire(&mut core, room)?.operation(), open);
    core.on_notification(
        other,
        wire::Response::Open(wire::Room {
            door: &[0; 32],
            key: &ROOM,
            previous: &[0; 64],
            epoch: &[0; 64],
        }),
        100,
    )?;
    core.retire_operation(open)?;
    let fresh = crypto::EcdheSecret::from_bytes([73; 32]);
    fresh.public_key().encode_hpke(&mut encoded)?;
    owned_join(&mut core, address, &local, encoded)?;
    assert!(core.source_joined(source)?);
    assert!(!core.source_joined(other)?);
    assert!(
        core.rooms
            .get(other.room)?
            .sources
            .get(other.slot)?
            .join_required
    );
    // The sibling independently signs and writes its own JOIN, under its own
    // source generation, before it obtains query/producer readiness.
    let fresh = crypto::EcdheSecret::from_bytes([74; 32]);
    fresh.public_key().encode_hpke(&mut encoded)?;
    owned_join(&mut core, (room, other), &local, encoded)?;
    assert!(core.source_joined(source)?);
    assert!(core.source_joined(other)?);
    Ok(())
}
