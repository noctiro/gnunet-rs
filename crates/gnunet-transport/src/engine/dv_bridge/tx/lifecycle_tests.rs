//! Actual Engine path/Job/reliability state with an explicit trusted-host link.
//! Installed routes and decoded inter-Engine bytes are pure fixture inputs,
//! not AEAD grants, physical writes, native callbacks or C interoperability.
use super::*;
use alloc::vec;

struct NoSigning(PeerId);
impl Signer for NoSigning {
    fn identity(&self) -> PeerId {
        self.0
    }
    fn sign_validation(&mut self, _: &[u8; 48]) -> Result<[u8; 64], Error> {
        Err(Error::Unsupported)
    }
}
struct Random(u8);
impl Entropy for Random {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        self.0 = self.0.wrapping_add(1);
        bytes.fill(self.0);
        Ok(())
    }
}
fn check(value: bool) -> Result<(), Error> {
    if value { Ok(()) } else { Err(Error::Conflict) }
}
fn core(engine: &mut Engine) -> Result<ClientId, Error> {
    let id = engine.accept()?;
    let mut start = [0; 40];
    CoreRequest::Start(gnunet_client::transport::Start::new(
        Some(engine.identity),
        true,
    ))
    .encode(&mut start)?;
    engine.receive(
        &id,
        &start,
        0,
        &mut NoSigning(engine.identity),
        &mut Random(0),
    )?;
    Ok(id)
}
fn fixture(
    local: PeerId,
    peer: PeerId,
    mtu: usize,
) -> Result<(Engine, Source, ClientId, PathId), Error> {
    let mut engine = Engine::new(local, Limits::default())?;
    let core = core(&mut engine)?;
    let source = engine.dv_attach_source(local)?;
    let path = engine.dv_install_path(
        &source,
        peer,
        mtu,
        Duration(1_000),
        Times::shared_coordinate(0),
    )?;
    Ok((engine, source, core, path))
}
fn announcements(
    engine: &mut Engine,
    core: &ClientId,
    peer: PeerId,
) -> Result<(usize, usize), Error> {
    let mut connected = 0;
    let mut disconnected = 0;
    while let Some(output) = engine.output() {
        if let Output::Frame { client, bytes } = output
            && &client == core
        {
            match CoreResponse::decode(&bytes)? {
                CoreResponse::Connected(actual) if actual == peer => connected += 1,
                CoreResponse::Disconnected(actual) if actual == peer => disconnected += 1,
                _ => {}
            }
        }
    }
    Ok((connected, disconnected))
}
fn send(engine: &mut Engine, core: &ClientId, peer: PeerId, payload: &[u8]) -> Result<u64, Error> {
    let mut bytes = vec![0; 40 + payload.len()];
    CoreRequest::Send {
        peer,
        priority: 0,
        message: payload,
    }
    .encode(&mut bytes)?;
    let now = engine.last_monotonic;
    engine.receive(
        core,
        &bytes,
        now,
        &mut NoSigning(engine.identity),
        &mut Random(1),
    )?;
    Ok(engine.job_serial)
}

#[test]
fn withdrawal_closes_visibility_but_original_admitted_claim_still_retires() -> Result<(), Error> {
    let local = PeerId([1; 32]);
    let peer = PeerId([2; 32]);
    let (mut engine, source, core, path) = fixture(local, peer, 64)?;
    check(announcements(&mut engine, &core, peer)? == (1, 0))?;
    let payload = message(64, 40)?;
    let job = send(&mut engine, &core, peer, &payload)?;
    let packet = engine.dv_virtual_packet().ok_or(Error::NotFound)?;
    let id = packet.id;
    let original_until = packet.until;
    let claim = engine.dv_claim_virtual(&id)?;
    engine.dv_virtual_queued(&id)?;
    let _credits = announcements(&mut engine, &core, peer)?;
    engine.dv_withdraw_path(&path)?;
    check(
        engine.dv_bridge.virtual_path(peer, 0).is_none()
            && !engine.dv_bridge.has_peer(peer, 0)
            && !engine.payload_route_live(peer, 0)
            && engine.snapshot().connected == 0,
    )?;
    check(announcements(&mut engine, &core, peer)? == (0, 1))?;
    check(
        engine.jobs.iter().all(|original| original.id != job)
            && engine.dv_source_debts(&source) == 1
            && engine.dv_virtual_canceled(&id)
            && engine
                .dv_bridge
                .tx
                .virtuals
                .iter()
                .find(|row| row.id == id)
                .is_some_and(|row| row.expires == original_until.0),
    )?;
    // This is the production final payload gate with trusted-host bytes. No
    // raw inbound packet can recreate the withdrawn reverse reachability.
    check(matches!(
        engine.network_peer(
            None,
            peer,
            &payload,
            0,
            Times::shared_coordinate(0),
            &mut NoSigning(local)
        ),
        Err(Error::NotReady)
    ))?;
    engine
        .dv_finish_virtual(claim)
        .map_err(|refused| refused.reason)?;
    check(engine.dv_source_debts(&source) == 0)
}

#[test]
fn replacement_preserves_connection_jobs_budgets_and_original_callback_debt() -> Result<(), Error> {
    let local = PeerId([1; 32]);
    let peer = PeerId([2; 32]);
    let (mut engine, source, core, old) = fixture(local, peer, 64)?;
    let _connected = announcements(&mut engine, &core, peer)?;
    let payload = message(64, 200)?;
    let job = send(&mut engine, &core, peer, &payload)?;
    let first_packet = engine.dv_virtual_packet().ok_or(Error::NotFound)?;
    let first = first_packet.id;
    let original_until = first_packet.until;
    let claim = engine.dv_claim_virtual(&first)?;
    engine.dv_virtual_queued(&first)?;
    engine.pump(0, &mut Random(2), false)?;
    let staged = engine.dv_virtual_packet().ok_or(Error::NotFound)?.id;
    let original_job_until = engine
        .jobs
        .iter()
        .find(|j| j.id == job)
        .ok_or(Error::NotFound)?
        .expires;
    let used = engine
        .peers
        .iter()
        .find(|p| p.id == peer)
        .ok_or(Error::NotFound)?
        .outbound_used;
    let _credits = announcements(&mut engine, &core, peer)?;
    let new = engine.dv_install_path(
        &source,
        peer,
        128,
        Duration(2_000),
        Times::shared_coordinate(10),
    )?;
    check(
        new != old
            && engine.dv_bridge.virtual_path(peer, 10) == Some((new.clone(), 128))
            && engine.dv_bridge.has_peer(peer, 10)
            && engine.payload_route_live(peer, 10)
            && engine.snapshot().connected == 1,
    )?;
    check(announcements(&mut engine, &core, peer)? == (0, 0))?;
    check(
        engine
            .jobs
            .iter()
            .find(|j| j.id == job)
            .is_some_and(|j| j.expires == original_job_until)
            && engine
                .peers
                .iter()
                .find(|p| p.id == peer)
                .is_some_and(|p| p.outbound_used == used)
            && engine.dv_source_debts(&source) == 2
            && engine.dv_virtual_canceled(&first)
            && engine.dv_virtual_canceled(&staged)
            && engine
                .dv_bridge
                .tx
                .virtuals
                .iter()
                .find(|row| row.id == first)
                .is_some_and(|row| row.expires == original_until.0),
    )?;
    check(
        matches!(engine.dv_withdraw_path(&old), Err(Error::Stale))
            && engine.payload_route_live(peer, 10),
    )?;
    engine
        .dv_finish_virtual(claim)
        .map_err(|refused| refused.reason)?;
    engine.dv_discard_unadmitted(&staged)?;
    check(engine.dv_source_debts(&source) == 0)?;
    engine.pump(10, &mut Random(3), false)?;
    let next = engine.dv_virtual_packet().ok_or(Error::NotFound)?;
    check(
        next.path == new
            && next.until.0 <= original_job_until
            && engine.jobs.iter().any(|j| j.id == job),
    )
}

#[test]
fn full_original_notification_capacity_refuses_before_path_withdrawal() -> Result<(), Error> {
    let local = PeerId([1; 32]);
    let peer = PeerId([2; 32]);
    let mut engine = Engine::new(
        local,
        Limits {
            clients: 9,
            peers: 2,
            messages: 8,
            control_messages: 1,
            ..Limits::default()
        },
    )?;
    let mut cores = Vec::new();
    for _ in 0..9 {
        cores.push(core(&mut engine)?);
    }
    let source = engine.dv_attach_source(local)?;
    let path = engine.dv_install_path(
        &source,
        peer,
        64,
        Duration(1_000),
        Times::shared_coordinate(0),
    )?;
    // Nine actual Connected notifications occupy the legal fixed output cap.
    check(engine.snapshot().outputs == 9)?;
    check(
        matches!(engine.dv_withdraw_path(&path), Err(Error::WouldBlock))
            && engine.snapshot().connected == 1
            && engine.dv_bridge.has_peer(peer, 0)
            && engine.dv_bridge.virtual_path(peer, 0).is_some(),
    )?;
    let mut announcements = 0;
    while let Some(Output::Frame { client, bytes }) = engine.output() {
        check(cores.contains(&client))?;
        check(
            matches!(CoreResponse::decode(&bytes)?, CoreResponse::Connected(actual) if actual == peer),
        )?;
        announcements += 1;
    }
    check(announcements == 9)?;
    engine.dv_withdraw_path(&path)?;
    check(
        engine.snapshot().connected == 0
            && engine.snapshot().outputs == 9
            && !engine.dv_bridge.has_peer(peer, 0),
    )
}

fn exchange_acknowledgements(payload_bytes: usize, mtu: usize) -> Result<(), Error> {
    let a = PeerId([1; 32]);
    let b = PeerId([2; 32]);
    let (mut sender, sender_source, sender_core, _) = fixture(a, b, mtu)?;
    let (mut receiver, receiver_source, receiver_core, _) = fixture(b, a, mtu)?;
    let _a = announcements(&mut sender, &sender_core, b)?;
    let _b = announcements(&mut receiver, &receiver_core, a)?;
    let payload = message(64, payload_bytes)?;
    let job = send(&mut sender, &sender_core, b, &payload)?;
    let mut claims = Vec::new();
    let mut acknowledgements = Vec::new();
    let mut complete = false;
    for turn in 0..16_u64 {
        let packet = sender.dv_virtual_packet().ok_or(Error::NotFound)?;
        let id = packet.id;
        let bytes = copy(packet.bytes)?;
        let uuid = if payload_bytes + 24 <= mtu {
            let reliable = p2p::Reliable::decode(&bytes)?;
            check(reliable.message == payload.as_slice())?;
            reliable.uuid
        } else {
            p2p::Fragment::decode(&bytes)?.ack
        };
        claims.push(sender.dv_claim_virtual(&id)?);
        sender.dv_virtual_queued(&id)?;
        let received_at = turn * 3 + 1;
        receiver.time_at(Times::shared_coordinate(received_at))?;
        let input = receiver.network_peer(
            None,
            a,
            &bytes,
            0,
            Times::shared_coordinate(received_at),
            &mut NoSigning(b),
        )?;
        if let NetworkStep::OwnedMessage(body, _) = input {
            check(body.as_slice() == payload.as_slice())?;
            complete = true;
        }
        check(receiver.snapshot().pending_fragment_acks == 1)?;
        receiver.pump(received_at, &mut Random(4), false)?;
        check(receiver.snapshot().pending_fragment_acks == 0)?;
        let ack = receiver
            .dv_virtual_packet_where(|packet| packet.without_fc)
            .ok_or(Error::NotFound)?;
        let ack_id = ack.id;
        let ack_bytes = copy(ack.bytes)?;
        check(ack_bytes.len() <= mtu && ack_bytes.len() == 32)?;
        let entries = p2p::acknowledgements(&ack_bytes)?.collect::<Vec<_>>();
        check(entries == vec![(0, uuid)])?;
        acknowledgements.push(receiver.dv_claim_virtual(&ack_id)?);
        receiver.dv_virtual_queued(&ack_id)?;
        let acknowledged_at = received_at + 1;
        sender.time_at(Times::shared_coordinate(acknowledged_at))?;
        sender.network_peer(
            None,
            b,
            &ack_bytes,
            0,
            Times::shared_coordinate(acknowledged_at),
            &mut NoSigning(a),
        )?;
        check(sender.snapshot().pending_remote_acks == 0)?;
        sender.pump(acknowledged_at, &mut Random(5), false)?;
        if sender.jobs.iter().all(|original| original.id != job) {
            break;
        }
    }
    check(
        complete
            && sender.jobs.iter().all(|original| original.id != job)
            && sender.snapshot().pending_remote_acks == 0
            && sender.snapshot().retry_bitmap_bytes == 0,
    )?;
    // Return only these original pure admission leases. This reports no native
    // write outcome; remote reliability was discharged by the actual1217 bytes.
    for claim in claims {
        sender
            .dv_finish_virtual(claim)
            .map_err(|refused| refused.reason)?;
    }
    for claim in acknowledgements {
        receiver
            .dv_finish_virtual(claim)
            .map_err(|refused| refused.reason)?;
    }
    check(
        sender.dv_source_debts(&sender_source) == 0
            && receiver.dv_source_debts(&receiver_source) == 0,
    )
}

#[test]
fn virtual_only_reliable_and_fragment_packets_emit_real_acknowledgements() -> Result<(), Error> {
    exchange_acknowledgements(40, 64)?;
    exchange_acknowledgements(200, 64)
}

#[test]
fn oversized_old_ack_batch_expires_without_canceling_another_original_claim() -> Result<(), Error> {
    let local = PeerId([1; 32]);
    let remote = PeerId([2; 32]);
    let other = PeerId([3; 32]);
    let (mut engine, source, core, _) = fixture(local, remote, 128)?;
    let _connected = announcements(&mut engine, &core, remote)?;
    engine.dv_install_path(
        &source,
        remote,
        128,
        Duration(crate::fragment::EXPIRY * 2),
        Times::shared_coordinate(0),
    )?;
    engine.dv_install_path(
        &source,
        other,
        64,
        Duration(crate::fragment::EXPIRY * 2),
        Times::shared_coordinate(0),
    )?;
    let body = message(64, 4)?;
    // Each ring entry comes from a standard1216 receive boundary; this is a
    // scripted trusted-host wire fixture, not a manufactured AEAD grant.
    for (at, uuid) in [(10, [1; 16]), (11, [2; 16]), (12, [3; 16]), (13, [4; 16])] {
        let mut wire = vec![0; body.len() + 24];
        p2p::Reliable {
            countdown: 0,
            uuid,
            message: &body,
        }
        .encode(&mut wire)?;
        engine.time_at(Times::shared_coordinate(at))?;
        engine.network_peer(
            None,
            remote,
            &wire,
            0,
            Times::shared_coordinate(at),
            &mut NoSigning(local),
        )?;
    }
    // Prepare while128 fits, before a new64-byte actual path replaces it.
    engine.flush_fragment_acks(13)?;
    let old = engine
        .jobs
        .iter()
        .find(|job| {
            job.peer == remote
                && Frame::decode(&job.message)
                    .is_ok_and(|f| f.header().message_type().value() == 1217)
        })
        .ok_or(Error::NotFound)?;
    let old_id = old.id;
    let original_expiry = old.expires;
    check(
        old.message.len() == 104 && original_expiry == 10 + crate::fragment::EXPIRY && old_id != 0,
    )?;
    engine.dv_install_path(
        &source,
        remote,
        64,
        Duration(crate::fragment::EXPIRY * 2),
        Times::shared_coordinate(13),
    )?;
    // A later independent real receipt produces another ACK under its own
    // still-live deadline. Expiring the older job must not cancel this claim.
    let mut wire = vec![0; body.len() + 24];
    p2p::Reliable {
        countdown: 0,
        uuid: [9; 16],
        message: &body,
    }
    .encode(&mut wire)?;
    engine.time_at(Times::shared_coordinate(100))?;
    engine.network_peer(
        None,
        other,
        &wire,
        0,
        Times::shared_coordinate(100),
        &mut NoSigning(local),
    )?;
    engine.pump(100, &mut Random(9), false)?;
    let other_id = engine
        .dv_virtual_packet_where(|packet| packet.target == other)
        .ok_or(Error::NotFound)?
        .id;
    let other_job = engine
        .dv_bridge
        .tx
        .virtuals
        .iter()
        .find(|row| row.id == other_id)
        .ok_or(Error::NotFound)?
        .job;
    check(other_job != 0 && other_job != old_id)?;
    let claim = engine.dv_claim_virtual(&other_id)?;
    engine.dv_virtual_queued(&other_id)?;
    check(
        engine
            .jobs
            .iter()
            .find(|job| job.id == old_id)
            .is_some_and(|job| job.expires == original_expiry)
            && !engine.dv_virtual_canceled(&other_id),
    )?;
    engine.tick(original_expiry, &mut Random(10))?;
    check(
        engine.jobs.iter().all(|job| job.id != old_id)
            && !engine.dv_virtual_canceled(&other_id)
            && engine.dv_source_debts(&source) == 1,
    )?;
    engine
        .dv_finish_virtual(claim)
        .map_err(|refused| refused.reason)?;
    check(engine.dv_source_debts(&source) == 0)
}
