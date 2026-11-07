//! Local typed staging and claim-order boundaries. These tests construct no
//! cryptographic grant, native write completion or remote acknowledgement.
use super::*;

fn check(value: bool) -> Result<(), Error> {
    if value { Ok(()) } else { Err(Error::Conflict) }
}
fn fixture() -> Result<(Engine, Source, ClientId, PathId), Error> {
    let local = PeerId([1; 32]);
    let mut engine = Engine::new(local, Limits::default())?;
    let origin = engine.accept()?;
    let source = engine.dv_attach_source(local)?;
    let path = engine.dv_install_path(
        &source,
        PeerId([2; 32]),
        1024,
        Duration(1_000),
        Times::shared_coordinate(0),
    )?;
    Ok((engine, source, origin, path))
}
fn stage(
    engine: &mut Engine,
    path: &PathId,
    peer: PeerId,
    origin: Option<ClientId>,
    control: bool,
    expires: u64,
) -> Result<VirtualId, Error> {
    let job = engine.job_serial.checked_add(1).ok_or(Error::Overflow)?;
    let prepared = engine.dv_bridge.prepare_virtual(VirtualPlan {
        path: path.clone(),
        job,
        peer,
        origin,
        mid: job.to_be_bytes(),
        remote: None,
        expires,
        control,
    })?;
    let id = prepared.id.clone();
    let body = message(64, 4)?;
    engine.buffered = engine
        .buffered
        .checked_add(body.len())
        .ok_or(Error::Overflow)?;
    engine.job_serial = job;
    engine.dv_bridge.commit_virtual(prepared, body);
    Ok(id)
}

#[test]
fn completed_slot_removal_cannot_promote_a_later_stream_packet() -> Result<(), Error> {
    let (mut engine, _, origin, path) = fixture()?;
    let peer = PeerId([2; 32]);
    let completed = stage(&mut engine, &path, peer, Some(origin.clone()), false, 100)?;
    let first = stage(&mut engine, &path, peer, Some(origin.clone()), false, 100)?;
    let later = stage(&mut engine, &path, peer, Some(origin), false, 100)?;
    let completed_claim = engine.dv_claim_virtual(&completed)?;
    engine.dv_virtual_queued(&completed)?;
    engine
        .dv_finish_virtual(completed_claim)
        .map_err(|refused| refused.reason)?;
    // Exercise the actual unordered storage removal rather than arranging an
    // already sorted table: the last row now occupies the removed first slot.
    check(
        engine
            .dv_bridge
            .tx
            .virtuals
            .first()
            .is_some_and(|row| row.id == later),
    )?;
    check(
        engine
            .dv_virtual_packet()
            .is_some_and(|packet| packet.id == first),
    )?;
    check(matches!(
        engine.dv_claim_virtual(&later),
        Err(Error::NotReady)
    ))?;
    let first_claim = engine.dv_claim_virtual(&first)?;
    engine.dv_virtual_queued(&first)?;
    // Admission of the first packet is enough. Its retained local outcome or
    // remote reliability debt must not hold the next original packet forever.
    check(
        engine
            .dv_virtual_packet()
            .is_some_and(|packet| packet.id == later),
    )?;
    let _later_claim = engine.dv_claim_virtual(&later)?;
    engine
        .dv_finish_virtual(first_claim)
        .map_err(|refused| refused.reason)?;
    Ok(())
}

#[test]
fn claims_preserve_one_stream_without_blocking_controls_other_peers_or_origins() -> Result<(), Error>
{
    let (mut engine, source, origin, path) = fixture()?;
    let peer = PeerId([2; 32]);
    let other_origin = engine.accept()?;
    let other_peer = PeerId([3; 32]);
    let other_path = engine.dv_install_path(
        &source,
        other_peer,
        1024,
        Duration(1_000),
        Times::shared_coordinate(0),
    )?;
    let first = stage(&mut engine, &path, peer, Some(origin.clone()), false, 100)?;
    let later = stage(&mut engine, &path, peer, Some(origin.clone()), false, 100)?;
    let independent = stage(
        &mut engine,
        &path,
        peer,
        Some(other_origin.clone()),
        false,
        100,
    )?;
    let elsewhere = stage(
        &mut engine,
        &other_path,
        other_peer,
        Some(origin),
        false,
        100,
    )?;
    let control = stage(&mut engine, &path, peer, None, true, 100)?;

    check(
        engine
            .dv_virtual_packet()
            .is_some_and(|packet| packet.id == control && packet.without_fc),
    )?;
    let first_claim = engine.dv_claim_virtual(&first)?;
    check(matches!(
        engine.dv_claim_virtual(&later),
        Err(Error::NotReady)
    ))?;
    check(
        engine
            .dv_virtual_packet_where(|packet| packet.id == later)
            .is_none(),
    )?;
    check(
        engine
            .dv_virtual_packet_where(|packet| packet.origin == Some(&other_origin))
            .is_some_and(|packet| packet.id == independent),
    )?;
    check(
        engine
            .dv_virtual_packet_where(|packet| packet.target != peer)
            .is_some_and(|packet| packet.id == elsewhere),
    )?;
    let _independent_claim = engine.dv_claim_virtual(&independent)?;
    let _elsewhere_claim = engine.dv_claim_virtual(&elsewhere)?;
    let _control_claim = engine.dv_claim_virtual(&control)?;

    let deadline = engine.dv_virtual_get(&first)?.until;
    engine
        .dv_reject_virtual(first_claim)
        .map_err(|refused| refused.reason)?;
    check(engine.dv_virtual_get(&first)?.until == deadline)?;
    check(
        engine
            .dv_virtual_packet()
            .is_some_and(|packet| packet.id == first),
    )?;
    let _first_claim = engine.dv_claim_virtual(&first)?;
    engine.dv_virtual_queued(&first)?;
    check(engine.dv_claim_virtual(&later).is_ok())
}

#[test]
fn expired_or_retired_rows_cannot_hold_or_reopen_a_stream() -> Result<(), Error> {
    let (mut engine, source, origin, path) = fixture()?;
    let peer = PeerId([2; 32]);
    let expired = stage(&mut engine, &path, peer, Some(origin.clone()), false, 5)?;
    let live = stage(&mut engine, &path, peer, Some(origin), false, 100)?;
    engine.time_at(Times::shared_coordinate(10))?;
    check(
        engine
            .dv_virtual_packet()
            .is_some_and(|packet| packet.id == live),
    )?;
    check(matches!(
        engine.dv_claim_virtual(&expired),
        Err(Error::NotReady)
    ))?;
    let live_claim = engine.dv_claim_virtual(&live)?;
    engine
        .dv_reject_virtual(live_claim)
        .map_err(|refused| refused.reason)?;
    engine.dv_withdraw_path(&path)?;
    check(engine.dv_virtual_packet().is_none())?;
    check(matches!(
        engine.dv_claim_virtual(&live),
        Err(Error::NotReady)
    ))?;
    engine.dv_begin_retire_source(&source)?;
    check(engine.dv_virtual_packet().is_none())?;
    check(matches!(engine.dv_claim_virtual(&live), Err(Error::Stale)))?;

    let (mut foreign, _, _, _) = fixture()?;
    check(matches!(foreign.dv_claim_virtual(&live), Err(Error::Stale)))
}
