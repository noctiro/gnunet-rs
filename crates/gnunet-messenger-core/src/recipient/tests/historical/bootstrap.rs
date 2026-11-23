//! Fresh self-authenticating JOIN breaks the history-authorization cycle while
//! inherited epoch/key and ordinary-message authority remain unproven.
use super::*;

#[test]
fn fresh_join_echo_allows_history_progress_before_unknown_epoch_completes() -> Result<(), Error> {
    let local = identity(11)?;
    let remote = identity(22)?;
    let third = identity(33)?;
    let later = identity(44)?;
    let mut instance = Instance::new();
    let mut bound = limits();
    bound.operations_per_room = 3;
    let mut core = Core::new(&mut instance, Mode::Client, bound, PROFILE)?;
    let address @ (room, source) = open(&mut core, &local)?;
    join_after(&mut core, address, &remote, &REMOTE, &[0; 64], &[0; 64])?;
    join_after(&mut core, address, &third, &[3; 32], &[0; 64], &[0; 64])?;
    assert!(core.frontier_sync_required(room)?);
    let future_hpke = crypto::EcdheSecret::from_bytes([70; 32]);
    let mut encoded_hpke = [0; 36];
    future_hpke.public_key().encode_hpke(&mut encoded_hpke)?;
    let later_public = later.public_key()?;
    let future = signed(
        &later,
        &[4; 32],
        &[0; 64],
        Body::Join {
            epoch: &[0; 64],
            public_key: wire::PublicKey::new(&later_public)?,
            hpke_key: wire::keys::HpkePublicKey::new(&encoded_hpke)?,
        },
        0,
    )?;
    let unknown = gnunet_crypto::hash512(&future.expose()[68..]);
    let reopening = core.open(source, 10_000)?;
    assert_eq!(write_wire(&mut core, room)?.operation(), reopening);
    core.on_notification(
        source,
        wire::Response::Open(wire::Room {
            door: &[0; 32],
            key: &ROOM,
            previous: &unknown,
            epoch: &unknown,
        }),
        100,
    )?;
    core.retire_operation(reopening)?;
    let local_hpke = crypto::EcdheSecret::from_bytes([71; 32]);
    local_hpke.public_key().encode_hpke(&mut encoded_hpke)?;
    let join = core.prepare_join(source, encoded_hpke, 100, 10_000)?;
    assert!(!core.bootstrap_join_observed(source, join)?);
    let original = sign_and_write(&mut core, room, &local, &unknown)?;
    assert!(!core.bootstrap_join_observed(source, join)?);
    let joined_hash = gnunet_crypto::hash512(&original.expose()[68..]);
    notification(
        &mut core,
        source,
        &local,
        original.expose(),
        &joined_hash,
        8,
    )?;
    // Actual verified self-echo is available before causal/epoch application.
    assert!(core.bootstrap_join_observed(source, join)?);
    assert!(!core.message(room, &joined_hash)?.history_complete());
    drain(&mut core, room)?;
    assert!(core.local_member(room)?.is_none());
    assert!(!core.message(room, &joined_hash)?.history_complete());
    assert!(
        core.pending_dependencies(room)?
            .any(|(hash, original)| hash == unknown && original == source)
    );
    // The one held JOIN cannot consume the separately reserved GET/SYNC rows.
    let get = core.request_missing(source, unknown, 100, 10_000)?;
    let sync = core.synchronize(source, 10_000)?;
    assert_eq!(core.rooms.get(source.room)?.operations.len(), 3);
    assert_eq!(write_wire(&mut core, room)?.operation(), get);
    assert_eq!(write_wire(&mut core, room)?.operation(), sync);
    assert!(core.bootstrap_join_observed(source, join)?);
    assert_eq!(
        notification(&mut core, source, &later, future.expose(), &unknown, 0)?,
        unknown
    );
    drain(&mut core, room)?;
    assert!(core.message(room, &joined_hash)?.history_complete());
    assert!(core.local_member(room)?.is_some());
    assert!(core.frontier_sync_required(room)?); // No raw metadata ACK clears it.
    core.source_cancelled(source)?;
    assert!(core.bootstrap_join_observed(source, join).is_err());
    Ok(())
}
