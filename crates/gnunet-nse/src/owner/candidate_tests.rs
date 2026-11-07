//! Pure candidate-state cases, not positive-WORKBITS authentication evidence.
//! The receive cases explicitly use zero-work framing with a mock pending-proof
//! local identity; no default signature/PoW correctness or native peer is proved.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Finite candidate-state cases assert original ownership and ranking"
)]
use super::*;

fn frame(timestamp: u64, bits: u32, origin: [u8; 32]) -> Fields {
    Fields {
        hops: 7,
        timestamp: AbsoluteTime::from_micros(timestamp),
        matching_bits: bits,
        origin,
        proof: [9; 8],
        signature: [0; 64],
    }
}
fn pending<'i>(instance: &'i mut Instance) -> Result<Service<'i, 2, 0>, Error> {
    let mut service = Service::new(
        instance,
        Config {
            interval_micros: 1000,
            work_bits: crypto::WorkBits::new(0)?,
            ..Config::default()
        },
    )?;
    let identity = Identity {
        key: [1; 32],
        epoch: service.fresh()?,
        proof: None,
        counter: 0,
        work_id: service.fresh()?,
        work_ready: false,
        exhausted: false,
    };
    service.current = 2000;
    service.next = 3000;
    service.identity = Some(identity);
    service.history[service.index] = Some(Entry {
        frame: frame(2000, 4, identity.key),
        local_unsigned: true,
    });
    Ok(service)
}
fn receive<'i>(
    service: &mut Service<'i, 2, 0>,
    peer: PeerId<'i>,
    fields: Fields,
) -> Result<Received, Error> {
    let mut bytes = [0; flood::MESSAGE_LEN];
    let length = fields.encode(&mut bytes)?;
    service.receive(peer, &bytes[..length], &mut [])
}

#[test]
fn unproven_local_rank_does_not_block_current_candidates_including_zero() -> Result<(), Error> {
    for bits in [0, 2, 4] {
        let mut instance = Instance::new();
        let mut service = pending(&mut instance)?;
        let peer = service.connect_peer([2; 32])?;
        assert_eq!(
            receive(&mut service, peer, frame(2000, bits, [3; 32]))?,
            Received::Better
        );
        let best = service.best().ok_or(Error::NotReady)?;
        assert_eq!(best.matching_bits, bits);
        assert_eq!(best.origin, [3; 32]);
        assert_eq!(best.hops, 8);
        // Existing qualified equal candidates still coalesce; an unknown local
        // proof does not disable ordinary remote-v-remote ranking.
        assert_eq!(
            receive(&mut service, peer, frame(2000, bits, [4; 32]))?,
            Received::Equal
        );
        assert_eq!(service.best().ok_or(Error::NotReady)?.origin, [3; 32]);
        assert_eq!(service.count, 0); // Count/summary policy is intentionally separate.
    }
    Ok(())
}

#[test]
fn zero_next_candidate_survives_round_rollover_without_a_local_proof() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut service = pending(&mut instance)?;
    let peer = service.connect_peer([2; 32])?;
    assert_eq!(
        receive(&mut service, peer, frame(3000, 0, [3; 32]))?,
        Received::Carryover
    );
    let alarm = Alarm {
        id: service.fresh()?,
        kind: AlarmKind::Round,
        at: 3000,
    };
    service.round_alarm = Some(alarm);
    assert_eq!(service.alarm_fired(&alarm, 3000)?, AlarmProgress::Round);
    let best = service.best().ok_or(Error::NotReady)?;
    assert_eq!(best.timestamp.as_micros(), 3000);
    assert_eq!(best.matching_bits, 0);
    assert_eq!(best.origin, [3; 32]);
    assert_eq!(best.hops, 8);
    Ok(())
}

#[test]
fn qualified_local_promotion_keeps_ties_and_original_issued_effects() -> Result<(), Error> {
    for remote_bits in [2, 4, 6] {
        let mut instance = Instance::new();
        let mut service = pending(&mut instance)?;
        let mut identity = service.identity.ok_or(Error::NotReady)?;
        // Structural post-proof state only; valid_proof/default authentication
        // are not exercised by this ranking/immutable-effect case.
        identity.proof = Some([7; 8]);
        service.identity = Some(identity);
        let mut local = Entry {
            frame: frame(2000, 4, identity.key),
            local_unsigned: true,
        };
        local.frame.proof = [7; 8];
        let remote = frame(2000, remote_bits, [3; 32]);
        service.history[service.index] = Some(Entry {
            frame: remote,
            local_unsigned: false,
        });
        let send_peer = service.connect_peer([2; 32])?;
        let sign_peer = service.connect_peer([4; 32])?;
        let send = Transmission {
            id: service.fresh()?,
            peer: send_peer,
            epoch: identity.epoch,
            frame: remote,
        };
        let sign = SignRequest {
            id: service.fresh()?,
            peer: sign_peer,
            epoch: identity.epoch,
            frame: local.frame,
        };
        let send_at = service.peer_index(send_peer)?;
        let sign_at = service.peer_index(sign_peer)?;
        service.peers[send_at].as_mut().ok_or(Error::Stale)?.pending = Some(Pending::Send {
            request: send,
            issued: true,
            admitted: true,
        });
        service.peers[sign_at].as_mut().ok_or(Error::Stale)?.pending = Some(Pending::Sign {
            request: sign,
            issued: true,
            cancelled: false,
        });
        let cursors = (
            service.peer_cursor,
            service.sign_cursor,
            service.send_cursor,
        );
        service.prefer_current_local(local, identity);
        let best = service.best().ok_or(Error::NotReady)?;
        assert_eq!(best.matching_bits, remote_bits.max(4));
        assert_eq!(
            best.origin,
            if remote_bits < 4 {
                identity.key
            } else {
                remote.origin
            }
        );
        let Some(Pending::Send {
            request,
            issued,
            admitted,
        }) = service.peers[send_at].ok_or(Error::Stale)?.pending
        else {
            return Err(Error::Conflict);
        };
        assert!(issued && admitted);
        assert_eq!(request.id, send.id);
        assert_eq!(request.epoch, send.epoch);
        assert_eq!(request.frame, send.frame);
        let Some(Pending::Sign {
            request,
            issued,
            cancelled,
        }) = service.peers[sign_at].ok_or(Error::Stale)?.pending
        else {
            return Err(Error::Conflict);
        };
        assert!(issued && !cancelled);
        assert_eq!(request.id, sign.id);
        assert_eq!(request.epoch, sign.epoch);
        assert_eq!(request.frame, sign.frame);
        assert_eq!(
            (
                service.peer_cursor,
                service.sign_cursor,
                service.send_cursor
            ),
            cursors
        );
    }
    Ok(())
}
