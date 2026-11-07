//! Real common Job admission/pump boundaries with bounded local Flow fixtures.
//! Route setup is a trusted-host assumption here, not a network/authentication
//! receipt; no native write or remote acknowledgement is synthesized.
use super::*;

struct NoSigning;
impl Signer for NoSigning {
    fn identity(&self) -> PeerId {
        PeerId([1; 32])
    }
    fn sign_validation(&mut self, _: &[u8; 48]) -> Result<[u8; 64], Error> {
        Err(Error::Unsupported)
    }
}
struct FixedEntropy;
impl Entropy for FixedEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
        output.fill(19);
        Ok(())
    }
}
fn check(value: bool) -> Result<(), Error> {
    if value { Ok(()) } else { Err(Error::Conflict) }
}
fn fixture() -> Result<(Engine, ClientId, ClientId, PeerId, PeerId), Error> {
    let mut engine = Engine::new(NoSigning.identity(), Limits::default())?;
    let origin = engine.accept()?;
    let other_origin = engine.accept()?;
    let peer = PeerId([2; 32]);
    let other_peer = PeerId([3; 32]);
    let source = engine.dv_attach_source(NoSigning.identity())?;
    for target in [peer, other_peer] {
        engine.dv_install_path(
            &source,
            target,
            1024,
            gnunet_types::Duration(1_000),
            Times::shared_coordinate(0),
        )?;
    }
    let index = engine
        .peers
        .iter()
        .position(|p| p.id == peer)
        .ok_or(Error::NotFound)?;
    // One small reliable packet fits; the older large packet cannot yet be
    // admitted. This is retained Flow state, not an invented packet grant.
    engine.peers[index].outbound_window = 72;
    Ok((engine, origin, other_origin, peer, other_peer))
}

#[test]
fn default_first_pass_preserves_source_order_without_waiting_for_remote_ack() -> Result<(), Error> {
    let (mut engine, origin, other_origin, peer, other_peer) = fixture()?;
    let large = message(64, 200)?;
    let small = message(64, 40)?;
    engine.enqueue(None, peer, &large, Some(origin.clone()), false)?;
    let older = engine.job_serial;
    engine.enqueue(None, peer, &small, Some(origin.clone()), false)?;
    let later = engine.job_serial;
    let flow = Flow {
        sequence: 1,
        inbound_window: p2p::DEFAULT_WINDOW,
        outbound_sent: 0,
        outbound_window: p2p::DEFAULT_WINDOW,
        sender_time: 0,
        rtt: 0,
        sync_ready: false,
    }
    .encode();
    engine.enqueue(None, peer, &flow, None, true)?;
    engine.enqueue(None, peer, &small, Some(other_origin.clone()), false)?;
    engine.enqueue(None, other_peer, &small, Some(origin.clone()), false)?;
    engine.pump(0, &mut FixedEntropy, false)?;
    check(
        engine
            .dv_virtual_packet_where(|packet| {
                packet.target == peer && packet.origin == Some(&origin)
            })
            .is_none(),
    )?;
    check(
        engine
            .dv_virtual_packet_where(|packet| packet.without_fc)
            .is_some(),
    )?;
    check(
        engine
            .dv_virtual_packet_where(|packet| packet.origin == Some(&other_origin))
            .is_some(),
    )?;
    check(
        engine
            .dv_virtual_packet_where(|packet| packet.target == other_peer)
            .is_some(),
    )?;

    let index = engine
        .peers
        .iter()
        .position(|p| p.id == peer)
        .ok_or(Error::NotFound)?;
    engine.peers[index].outbound_window = 1024;
    engine.pump(0, &mut FixedEntropy, false)?;
    let old_job = engine
        .jobs
        .iter()
        .find(|job| job.id == older)
        .ok_or(Error::NotFound)?;
    let new_job = engine
        .jobs
        .iter()
        .find(|job| job.id == later)
        .ok_or(Error::NotFound)?;
    // Both first passes are now staged, while genuine remote coverage is still
    // absent. The old ACK debt must not hold the later original indefinitely.
    check(!old_job.fresh() && !old_job.complete() && !new_job.fresh())?;
    let first = engine
        .dv_virtual_packet_where(|packet| packet.target == peer && packet.origin == Some(&origin))
        .ok_or(Error::NotFound)?;
    check(p2p::Reliable::decode(first.bytes)?.message == large.as_slice())?;
    let first_id = first.id;
    let _first_claim = engine.dv_claim_virtual(&first_id)?;
    engine.dv_virtual_queued(&first_id)?;
    let next = engine
        .dv_virtual_packet_where(|packet| packet.target == peer && packet.origin == Some(&origin))
        .ok_or(Error::NotFound)?;
    check(p2p::Reliable::decode(next.bytes)?.message == small.as_slice())
}

#[test]
fn explicit_reordering_preferences_keep_their_existing_first_pass_admission() -> Result<(), Error> {
    for preference in [32, 256] {
        let (mut engine, origin, _, peer, _) = fixture()?;
        engine.enqueue(None, peer, &message(64, 200)?, Some(origin.clone()), false)?;
        engine.enqueue(None, peer, &message(64, 40)?, Some(origin.clone()), false)?;
        engine.jobs.back_mut().ok_or(Error::NotFound)?.preferences = preference;
        engine.pump(0, &mut FixedEntropy, false)?;
        check(
            engine
                .dv_virtual_packet_where(|packet| packet.origin == Some(&origin))
                .is_some_and(|packet| {
                    p2p::Reliable::decode(packet.bytes).is_ok_and(|body| body.message.len() == 40)
                }),
        )?;
    }
    Ok(())
}
