//! Pure ownership/resource fixtures. Explicit route flags below are trusted
//! host assumptions, not network authentication or native write receipts.
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
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        bytes.fill(17);
        Ok(())
    }
}
fn check(value: bool) -> Result<(), Error> {
    if value { Ok(()) } else { Err(Error::Conflict) }
}
fn times(now: u64) -> Times {
    Times::new(MonoInstant(now), AbsoluteTime::from_micros(1_000_000 + now))
}
fn register() -> Result<Vec<u8>, Error> {
    let mut bytes = message(1211, 16)?;
    bytes[4..8].copy_from_slice(&1u32.to_be_bytes());
    bytes[12..].copy_from_slice(b"tcp\0");
    Ok(bytes)
}
fn registered() -> Result<(Engine, ClientId), Error> {
    let mut engine = Engine::new(NoSigning.identity(), Limits::default())?;
    let owner = engine.accept()?;
    engine.receive_at(
        &owner,
        &register()?,
        times(10),
        &mut NoSigning,
        &mut FixedEntropy,
    )?;
    Ok((engine, owner))
}
fn queue(peer: PeerId, id: u32, length: u64) -> Result<Vec<u8>, Error> {
    let mut bytes = message(1204, 74)?;
    bytes[4..8].copy_from_slice(&id.to_be_bytes());
    bytes[8..40].copy_from_slice(&peer.0);
    bytes[44..48].copy_from_slice(&1024u32.to_be_bytes());
    bytes[48..56].copy_from_slice(&length.to_be_bytes());
    bytes[64..].copy_from_slice(b"tcp-local\0");
    Ok(bytes)
}
fn callback(peer: PeerId, id: u32) -> Result<Vec<u8>, Error> {
    let mut bytes = message(1210, 52)?;
    bytes[4..8].copy_from_slice(&1u32.to_be_bytes());
    bytes[8..16].copy_from_slice(&[9; 8]);
    bytes[16..20].copy_from_slice(&id.to_be_bytes());
    bytes[20..].copy_from_slice(&peer.0);
    Ok(bytes)
}
fn incoming(peer: PeerId, body: &[u8]) -> Result<Vec<u8>, Error> {
    let mut bytes = message(1202, 88 + body.len())?;
    bytes[4..8].copy_from_slice(&1u32.to_be_bytes());
    bytes[8..16].copy_from_slice(&[7; 8]);
    bytes[16..24].copy_from_slice(&1_000_000u64.to_be_bytes());
    bytes[24..56].copy_from_slice(&peer.0);
    bytes[88..].copy_from_slice(body);
    Ok(bytes)
}
fn maintain(
    engine: &mut Engine,
    owner: &ClientId,
    bytes: &[u8],
    now: u64,
) -> Result<Option<ReceiveOutcome>, Error> {
    engine.receive_maintenance_at(owner, bytes, times(now), &mut NoSigning, &mut FixedEntropy)
}

#[test]
fn queue_setup_and_send_callback_do_not_pump_retained_transmission_jobs() -> Result<(), Error> {
    let (mut engine, owner) = registered()?;
    let peer = PeerId([2; 32]);
    check(
        maintain(&mut engine, &owner, &queue(peer, 1, 8)?, 11)? == Some(ReceiveOutcome::Accepted),
    )?;
    check(engine.jobs.len() == 1 && engine.output.is_empty() && engine.attempts.is_empty())?;
    engine.routes[0].valid_until = 1000;
    engine.peers[0].connected = true;
    engine.enqueue(None, peer, &message(64, 8)?, None, false)?;
    check(
        maintain(&mut engine, &owner, &callback(peer, 1)?, 12)? == Some(ReceiveOutcome::Accepted),
    )?;
    check(engine.jobs.len() == 2 && engine.jobs.iter().all(Job::fresh))?;
    check(
        engine.output.is_empty() && engine.attempts.is_empty() && engine.routes[0].available == 8,
    )?;
    check(engine.ignored_local_callbacks == 1)?;
    let mut update = message(1222, 64)?;
    update[4..8].copy_from_slice(&1u32.to_be_bytes());
    update[8..40].copy_from_slice(&peer.0);
    update[44..48].copy_from_slice(&1024u32.to_be_bytes());
    engine.receive_at(
        &owner,
        &update,
        times(13),
        &mut NoSigning,
        &mut FixedEntropy,
    )?;
    check(!engine.output.is_empty() && !engine.attempts.is_empty())
}

#[test]
fn unregistered_and_business_heads_remain_unchanged_behind_the_barrier() -> Result<(), Error> {
    let mut unregistered = Engine::new(NoSigning.identity(), Limits::default())?;
    let first = unregistered.accept()?;
    let before = unregistered.snapshot();
    check(maintain(&mut unregistered, &first, &register()?, 10)?.is_none())?;
    check(unregistered.snapshot() == before && unregistered.monotonic_now() == MonoInstant(0))?;
    let (mut engine, owner) = registered()?;
    let before = engine.snapshot();
    let mut start = [0; 40];
    CoreRequest::Start(gnunet_client::transport::Start::new(
        Some(NoSigning.identity()),
        true,
    ))
    .encode(&mut start)?;
    for bytes in [&start[..], &message(1212, 4)?[..], &register()?[..]] {
        check(maintain(&mut engine, &owner, bytes, 20)?.is_none())?;
        check(engine.snapshot() == before && engine.monotonic_now() == MonoInstant(10))?;
    }
    Ok(())
}

#[test]
fn full_output_fifo_defers_effects_without_blocking_a_zero_output_callback() -> Result<(), Error> {
    let (mut engine, owner) = registered()?;
    let peer = PeerId([2; 32]);
    let _setup = maintain(&mut engine, &owner, &queue(peer, 1, 0)?, 10)?;
    let core = engine.accept()?;
    let mut start = [0; 40];
    CoreRequest::Start(gnunet_client::transport::Start::new(
        Some(NoSigning.identity()),
        true,
    ))
    .encode(&mut start)?;
    engine.receive_at(&core, &start, times(10), &mut NoSigning, &mut FixedEntropy)?;
    engine.routes[0].valid_until = 1000;
    engine.peers[0].connected = true;
    let maximum = engine.limits.messages + engine.limits.control_messages;
    for _ in 0..maximum {
        engine.emit(owner.clone(), message(99, 4)?)?;
    }
    let before = engine.snapshot();
    let challenge = Challenge {
        nonce: [3; 32],
        origin: 10,
    }
    .encode();
    check(maintain(&mut engine, &owner, &incoming(peer, &challenge)?, 11)?.is_none())?;
    let mut down = message(1205, 40)?;
    down[4..8].copy_from_slice(&1u32.to_be_bytes());
    down[8..].copy_from_slice(&peer.0);
    check(maintain(&mut engine, &owner, &down, 11)?.is_none())?;
    check(engine.snapshot() == before && engine.monotonic_now() == MonoInstant(10))?;
    check(
        maintain(&mut engine, &owner, &callback(peer, 1)?, 11)? == Some(ReceiveOutcome::Accepted),
    )?;
    check(engine.output.len() == maximum && engine.ignored_local_callbacks == 1)?;
    drop(engine.output());
    check(maintain(&mut engine, &owner, &down, 12)? == Some(ReceiveOutcome::Accepted))?;
    check(engine.routes.is_empty() && !engine.peers[0].connected && engine.output.len() == maximum)
}

#[test]
fn raw_dv_maintenance_retains_original_source_targets_and_flow_debt() -> Result<(), Error> {
    let (mut engine, owner) = registered()?;
    let peer = PeerId([2; 32]);
    let _setup = maintain(&mut engine, &owner, &queue(peer, 1, 0)?, 10)?;
    // This pure fixture supplies the same validated-route assumption required
    // by Inbox admission. An unvalidated route correctly retains Held instead.
    engine.routes[0].valid_until = 1000;
    let source = engine.dv_attach_source(NoSigning.identity())?;
    let body = message(crate::dv::BOX_TYPE, 4)?;
    let bytes = incoming(peer, &body)?;
    check(maintain(&mut engine, &owner, &bytes, 11)?.is_none())?;
    let mut wrapped = message(1216, 24 + body.len())?;
    wrapped[24..].copy_from_slice(&body);
    check(maintain(&mut engine, &owner, &incoming(peer, &wrapped)?, 11)?.is_none())?;
    check(engine.monotonic_now() == MonoInstant(10) && engine.dv_source_debts(&source) == 0)?;
    let until = MonoInstant(100);
    let absolute_until = AbsoluteTime::from_micros(1_000_100);
    check(
        engine.receive_dv_maintenance_at(
            dv_bridge::NativeInput {
                source: &source,
                owner: &owner,
                bytes: &bytes,
                until,
                absolute_until,
            },
            times(11),
            &mut NoSigning,
            &mut FixedEntropy,
        )? == Some(ReceiveOutcome::Accepted),
    )?;
    let inbox = engine.dv_inbox().ok_or(Error::NotFound)?;
    check(
        inbox.bytes == body
            && inbox.until == until
            && inbox.absolute_until == Some(absolute_until)
            && inbox.id.source() == &source,
    )?;
    check(engine.output.is_empty() && engine.dv_source_debts(&source) == 1)?;
    check(matches!(
        engine.receive_dv_maintenance_at(
            dv_bridge::NativeInput {
                source: &source,
                owner: &owner,
                bytes: &bytes,
                until,
                absolute_until
            },
            times(12),
            &mut NoSigning,
            &mut FixedEntropy
        ),
        Err(Error::Conflict)
    ))?;
    for (until, absolute_until) in [
        (11, 1_000_100),
        (u64::MAX, 1_000_100),
        (100, 1_000_011),
        (100, u64::MAX),
    ] {
        check(matches!(
            engine.receive_dv_maintenance_at(
                dv_bridge::NativeInput {
                    source: &source,
                    owner: &owner,
                    bytes: &bytes,
                    until: MonoInstant(until),
                    absolute_until: AbsoluteTime::from_micros(absolute_until)
                },
                times(11),
                &mut NoSigning,
                &mut FixedEntropy
            ),
            Err(Error::Deadline)
        ))?;
    }
    check(engine.monotonic_now() == MonoInstant(11) && engine.dv_source_debts(&source) == 1)?;
    let id = engine.dv_inbox().ok_or(Error::NotFound)?.id;
    check(engine.dv_drop_inbox(&id)? == dv_bridge::IngressEnd::AckQueued)?;
    let Some(Output::Frame { client, bytes: ack }) = engine.output() else {
        return Err(Error::NotFound);
    };
    check(
        client == owner
            && Frame::decode(&ack)?.header().message_type().value() == 1203
            && ack[8..16] == [7; 8],
    )?;
    engine.dv_begin_retire_source(&source)?;
    engine.dv_retire_source(&source)?;
    let replacement = engine.dv_attach_source(NoSigning.identity())?;
    check(matches!(
        engine.receive_dv_maintenance_at(
            dv_bridge::NativeInput {
                source: &source,
                owner: &owner,
                bytes: &bytes,
                until,
                absolute_until
            },
            times(12),
            &mut NoSigning,
            &mut FixedEntropy
        ),
        Err(Error::Stale)
    ))?;
    check(engine.monotonic_now() == MonoInstant(11) && engine.dv_source_debts(&replacement) == 0)
}

fn malformed_remote(maintenance: bool, body: &[u8]) -> Result<(u64, Option<RemoteDrop>), Error> {
    let (mut engine, owner) = registered()?;
    let peer = PeerId([2; 32]);
    let _setup = maintain(&mut engine, &owner, &queue(peer, 1, 0)?, 10)?;
    let bytes = incoming(peer, body)?;
    let outcome = if maintenance {
        maintain(&mut engine, &owner, &bytes, 11)?.ok_or(Error::NotReady)?
    } else {
        engine.receive_at(&owner, &bytes, times(11), &mut NoSigning, &mut FixedEntropy)?
    };
    check(
        outcome == ReceiveOutcome::Accepted
            && engine.clients.len() == 1
            && engine.routes.len() == 1,
    )?;
    let Some(Output::Frame { client, bytes }) = engine.output() else {
        return Err(Error::NotFound);
    };
    check(
        client == owner
            && Frame::decode(&bytes)?.header().message_type().value() == 1203
            && bytes[8..16] == [7; 8],
    )?;
    check(engine.output.is_empty())?;
    Ok((engine.dropped, engine.last_remote_drop))
}

#[test]
fn malformed_remote_reliable_envelopes_keep_original_drop_and_fc_semantics() -> Result<(), Error> {
    let short = message(1216, 4)?;
    let mut nested = message(1216, 28)?;
    nested[24..].copy_from_slice(&message(1216, 4)?);
    let mut invalid_inner = message(1216, 28)?;
    invalid_inner[24..].copy_from_slice(&[0, 8, 0, 64]);
    for body in [short, nested, invalid_inner, message(1304, 4)?] {
        let normal = malformed_remote(false, &body)?;
        let maintenance = malformed_remote(true, &body)?;
        check(normal.0 == 1 && normal.1.is_some() && normal == maintenance)?;
    }
    Ok(())
}

#[test]
fn validation_cannot_use_control_slots_above_the_ordinary_output_limit() -> Result<(), Error> {
    let (mut engine, owner) = registered()?;
    let remote = gnunet_crypto::EddsaPrivateKey::from_seed([2; 32]);
    let peer = PeerId(*remote.public_key().as_bytes());
    let _setup = maintain(&mut engine, &owner, &queue(peer, 1, 1)?, 10)?;
    let validity = 1_000_000;
    let response = Validation {
        signature: *remote
            .sign(
                p2p::CHALLENGE_PURPOSE,
                &Validation::signed_region(&engine.routes[0].nonce, validity),
            )?
            .as_bytes(),
        nonce: engine.routes[0].nonce,
        origin: 10,
        validity,
    }
    .encode();
    let mut bytes = incoming(peer, &response)?;
    bytes[4..8].fill(0); // No FC output can conceal the validation limit.
    let occupied = engine.limits.messages + 1;
    for _ in 0..occupied {
        engine.emit(owner.clone(), message(99, 4)?)?;
    }
    let before = engine.snapshot();
    check(maintain(&mut engine, &owner, &bytes, 11)?.is_none())?;
    check(engine.snapshot() == before && engine.monotonic_now() == MonoInstant(10))?;
    check(matches!(
        engine.receive_at(&owner, &bytes, times(11), &mut NoSigning, &mut FixedEntropy),
        Err(Error::Capacity)
    ))?;
    check(
        engine.output.len() == occupied
            && engine.validations == 0
            && engine.routes[0].valid_until == 0
            && engine.routes[0].challenge_pending,
    )
}
