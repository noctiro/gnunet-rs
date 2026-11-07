//! Original-instance, round, work and resource transitions.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions exercise exact ownership/round/resource transitions."
)]
use gnunet_crypto::{EddsaPrivateKey, pow};
use gnunet_nse::{
    crypto::{self, WorkBits},
    owner::{AlarmProgress, Config, Instance, Random, Received, Service, WorkProgress},
};
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime,
    nse::{self, flood::Fields},
};
struct Zero;
impl Random for Zero {
    fn below(&mut self, upper: u32) -> Result<u32, Error> {
        if upper == 0 {
            Err(Error::Entropy)
        } else {
            Ok(0)
        }
    }
}
fn config() -> Result<Config, Error> {
    Ok(Config {
        interval_micros: 1000,
        work_delay_micros: 5,
        work_bits: WorkBits::new(0)?,
        ..Config::default()
    })
}
fn activate<const P: usize, const S: usize>(
    service: &mut Service<'_, P, S>,
    key: &EddsaPrivateKey,
    now: u64,
) -> Result<(), Error> {
    let barrier = service.begin_identity_change()?;
    service.finish_identity_change(&barrier, *key.public_key().as_bytes(), [0; 8], now, &mut [])
}
fn packet(key: &EddsaPrivateKey, time: u64, bits: u32, proof: [u8; 8]) -> Result<[u8; 132], Error> {
    let mut f = Fields {
        hops: 2,
        timestamp: AbsoluteTime::from_micros(time),
        matching_bits: bits,
        origin: *key.public_key().as_bytes(),
        proof,
        signature: [0; 64],
    };
    let mut signed = [0; 60];
    f.encode_signed(&mut signed)?;
    f.signature = *key.sign(14, &signed)?.as_bytes();
    let mut b = [0; 132];
    f.encode(&mut b)?;
    Ok(b)
}
#[test]
fn immediate_subscription_nan_and_original_notification_capacity() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut service = Service::<0, 1>::new(&mut instance, config()?)?;
    let sub = service.subscribe(&[0, 4, 1, 65])?;
    let first = service.next_notification(9)?.ok_or(Error::NotReady)?;
    assert_eq!(first.subscriber(), sub);
    assert_eq!(first.estimate().log2_size.value(), 0.0);
    assert_eq!(first.estimate().deviation.value(), 0.0);
    assert!(service.next_notification(10)?.is_none());
    let key = EddsaPrivateKey::from_seed([1; 32]);
    activate(&mut service, &key, 2500)?;
    assert_eq!(service.notified(&first), Err(Error::Stale));
    let updated = service.next_notification(11)?.ok_or(Error::NotReady)?;
    assert!(updated.estimate().deviation.value().is_nan());
    assert!(service.next_notification(12)?.is_none());
    service.notified(&updated)?;
    assert_eq!(service.notified(&updated), Err(Error::Stale));
    assert!(service.next_notification(13)?.is_none());
    assert_eq!(service.subscribe(&[0, 4, 1, 65]), Err(Error::Capacity));
    service.unsubscribe(sub)?;
    let replacement = service.subscribe(&[0, 4, 1, 65])?;
    assert_ne!(sub, replacement);
    assert_eq!(service.unsubscribe(sub), Err(Error::Stale));
    Ok(())
}
#[test]
fn original_sign_snapshot_actual_signer_cancel_and_reconnect() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut service = Service::<1, 0>::new(&mut instance, config()?)?;
    let key = EddsaPrivateKey::from_seed([2; 32]);
    let wrong = EddsaPrivateKey::from_seed([3; 32]);
    activate(&mut service, &key, 2500)?;
    let peer = service.connect_peer([9; 32])?;
    let alarm = service
        .next_alarm(2500, &mut Zero)?
        .ok_or(Error::NotReady)?;
    assert_eq!(service.alarm_fired(&alarm, 2499)?, AlarmProgress::Early);
    assert_eq!(service.alarm_fired(&alarm, 2500)?, AlarmProgress::Peer);
    assert_eq!(service.alarm_fired(&alarm, 2500), Err(Error::Stale));
    let sign = service.next_sign()?.ok_or(Error::NotReady)?;
    assert!(service.next_sign()?.is_none());
    let original = sign.payload()?;
    assert_eq!(
        service.signed(
            &sign,
            *wrong.public_key().as_bytes(),
            *wrong.sign(14, &original)?.as_bytes()
        ),
        Err(Error::Authentication)
    );
    service.signed(
        &sign,
        *key.public_key().as_bytes(),
        *key.sign(14, &original)?.as_bytes(),
    )?;
    let tx = service.next_transmission()?.ok_or(Error::NotReady)?;
    assert_eq!(tx.fields().timestamp.as_micros(), 1000);
    assert!(service.next_transmission()?.is_none());
    let mut b = [0; 132];
    tx.encode(&mut b)?;
    assert_eq!(&b[8..68], original);
    service.disconnect_peer(peer)?;
    let replacement = service.connect_peer([9; 32])?;
    assert_ne!(replacement, peer);
    assert_eq!(service.transmitted(&tx), Err(Error::Stale));
    assert_eq!(
        service.signed(
            &sign,
            *key.public_key().as_bytes(),
            *key.sign(14, &original)?.as_bytes()
        ),
        Err(Error::Stale)
    );
    let alarm = service
        .next_alarm(2500, &mut Zero)?
        .ok_or(Error::NotReady)?;
    service.alarm_fired(&alarm, 2500)?;
    let sign = service.next_sign()?.ok_or(Error::NotReady)?;
    service.cancel_sign(&sign)?;
    assert_eq!(
        service.signed(
            &sign,
            *key.public_key().as_bytes(),
            *key.sign(14, &sign.payload()?)?.as_bytes()
        ),
        Err(Error::Stale)
    );
    Ok(())
}
#[test]
fn higher_remote_forwarding_keeps_signature_and_carryover_changes_hops_only() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut service = Service::<2, 1>::new(&mut instance, config()?)?;
    let local = EddsaPrivateKey::from_seed([4; 32]);
    let remote = EddsaPrivateKey::from_seed([5; 32]);
    activate(&mut service, &local, 2500)?;
    let source = service.connect_peer(*remote.public_key().as_bytes())?;
    let destination = service.connect_peer([7; 32])?;
    let now = packet(&remote, 2000, 100, [0; 8])?;
    assert_eq!(service.receive(source, &now, &mut [])?, Received::Better);
    let best = service.best().ok_or(Error::NotReady)?;
    assert_eq!(best.signature, &now[68..]);
    assert_eq!(best.hops, 3);
    // Acknowledge destination's previous-round local signature first, then current remote data.
    let alarm = service
        .next_alarm(2500, &mut Zero)?
        .ok_or(Error::NotReady)?;
    service.alarm_fired(&alarm, 2500)?;
    if let Some(sign) = service.next_sign()? {
        service.signed(
            &sign,
            *local.public_key().as_bytes(),
            *local.sign(14, &sign.payload()?)?.as_bytes(),
        )?;
        let tx = service.next_transmission()?.ok_or(Error::NotReady)?;
        service.transmitted(&tx)?;
    }
    let mut forwarded = None;
    for _ in 0..5 {
        let alarm = service
            .next_alarm(3000, &mut Zero)?
            .ok_or(Error::NotReady)?;
        service.alarm_fired(&alarm, alarm.deadline().max(2500))?;
        if let Some(tx) = service.next_transmission()? {
            if tx.peer() == destination && tx.fields().timestamp.as_micros() == 2000 {
                forwarded = Some(tx);
                break;
            }
            service.transmitted(&tx)?;
        }
        if let Some(sign) = service.next_sign()? {
            service.cancel_sign(&sign)?;
        }
    }
    let tx = forwarded.ok_or(Error::NotFound)?;
    let mut bytes = [0; 132];
    tx.encode(&mut bytes)?;
    assert_eq!(&bytes[8..], &now[8..]);
    service.transmitted(&tx)?;
    let next = packet(&remote, 3000, 200, [0; 8])?;
    assert_eq!(
        service.receive(source, &next, &mut [])?,
        Received::Carryover
    );
    assert_eq!(service.receive(source, &now, &mut [])?, Received::Equal);
    for _ in 0..8 {
        let alarm = service
            .next_alarm(3000, &mut Zero)?
            .ok_or(Error::NotReady)?;
        let progress = service.alarm_fired(&alarm, 3000)?;
        if progress == AlarmProgress::Round {
            break;
        }
        if let Some(s) = service.next_sign()? {
            service.cancel_sign(&s)?;
        }
        if let Some(t) = service.next_transmission()? {
            service.transmitted(&t)?;
        }
    }
    assert_eq!(service.rounds(), Some((3000, 4000)));
    let best = service.best().ok_or(Error::NotReady)?;
    assert_eq!(best.timestamp.as_micros(), 3000);
    assert_eq!(best.signature, &next[68..]);
    assert_eq!(best.hops, 3);
    Ok(())
}
#[test]
fn previous_pushback_uses_semantic_round_at_ring_wrap() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut service = Service::<1, 0>::new(&mut instance, config()?)?;
    let local = EddsaPrivateKey::from_seed([6; 32]);
    let remote = EddsaPrivateKey::from_seed([7; 32]);
    activate(&mut service, &local, 2500)?;
    let round = service
        .next_alarm(3000, &mut Zero)?
        .ok_or(Error::NotReady)?;
    assert_eq!(service.alarm_fired(&round, 3000)?, AlarmProgress::Round);
    let peer = service.connect_peer([8; 32])?;
    assert_eq!(
        service.receive(peer, &packet(&remote, 2000, 100, [0; 8])?, &mut [])?,
        Received::Better
    );
    assert_eq!(
        service.receive(peer, &packet(&remote, 2000, 99, [0; 8])?, &mut [])?,
        Received::Pushback
    );
    let push = service
        .next_alarm(3000, &mut Zero)?
        .ok_or(Error::NotReady)?;
    service.alarm_fired(&push, 3000)?;
    assert!(service.next_sign()?.is_none());
    let tx = service.next_transmission()?.ok_or(Error::NotReady)?;
    assert_eq!(tx.fields().timestamp.as_micros(), 2000);
    assert_eq!(tx.fields().matching_bits, 100);
    Ok(())
}
#[test]
fn foreign_tokens_identity_barrier_old_callbacks_and_close_are_bounded() -> Result<(), Error> {
    let mut a = Instance::new();
    let mut b = Instance::new();
    let mut left = Service::<1, 1>::new(&mut a, config()?)?;
    let mut right = Service::<1, 1>::new(&mut b, config()?)?;
    let key = EddsaPrivateKey::from_seed([8; 32]);
    activate(&mut left, &key, 2500)?;
    activate(&mut right, &key, 2500)?;
    let p = left.connect_peer([1; 32])?;
    let q = right.connect_peer([1; 32])?;
    assert_ne!(p, q);
    assert_eq!(left.disconnect_peer(q), Err(Error::Stale));
    let alarm = left.next_alarm(2500, &mut Zero)?.ok_or(Error::NotReady)?;
    left.alarm_fired(&alarm, 2500)?;
    let sign = left.next_sign()?.ok_or(Error::NotReady)?;
    let barrier = left.begin_identity_change()?;
    let foreign = right.begin_identity_change()?;
    assert_eq!(
        left.finish_identity_change(
            &foreign,
            *key.public_key().as_bytes(),
            [0; 8],
            2500,
            &mut []
        ),
        Err(Error::Stale)
    );
    assert!(left.identity().is_none());
    left.finish_identity_change(
        &barrier,
        *key.public_key().as_bytes(),
        [0; 8],
        2500,
        &mut [],
    )?;
    assert_eq!(
        left.signed(
            &sign,
            *key.public_key().as_bytes(),
            *key.sign(14, &sign.payload()?)?.as_bytes()
        ),
        Err(Error::Stale)
    );
    left.close();
    assert_eq!(left.connect_peer([2; 32]), Err(Error::Closed));
    assert_eq!(left.summary().err(), Some(Error::Closed));
    Ok(())
}
#[test]
fn real_bounded_work_original_delay_and_unknown_persistence_retention() -> Result<(), Error> {
    let key = EddsaPrivateKey::from_seed([9; 32]);
    let public = *key.public_key().as_bytes();
    let mut memory = vec![pow::Block::new(); pow::MEMORY_BLOCKS];
    let workbits = WorkBits::new(1)?;
    let mut invalid = None;
    for n in 0_u64..32 {
        let raw = n.to_be_bytes();
        if !crypto::valid_proof(workbits, &public, &raw, &mut memory)? {
            invalid = Some(raw);
            break;
        }
    }
    let mut instance = Instance::new();
    let mut service = Service::<0, 0>::new(
        &mut instance,
        Config {
            work_bits: workbits,
            ..config()?
        },
    )?;
    let barrier = service.begin_identity_change()?;
    service.finish_identity_change(
        &barrier,
        public,
        invalid.ok_or(Error::NotFound)?,
        2000,
        &mut memory,
    )?;
    let alarm = service
        .next_alarm(2000, &mut Zero)?
        .ok_or(Error::NotReady)?;
    assert_eq!(service.alarm_fired(&alarm, 1999)?, AlarmProgress::Early);
    service.alarm_fired(&alarm, 2000)?;
    let job = service.work_request().ok_or(Error::NotReady)?;
    assert_eq!(
        service.work(&job, 1, 2000, &mut memory)?,
        WorkProgress::More
    );
    assert_eq!(service.work(&job, 1, 2000, &mut memory), Err(Error::Stale));
    let pending = service.next_persist()?.ok_or(Error::NotReady)?;
    assert_eq!(
        service.persisted(&pending, Err(Error::OutcomeUnknown)),
        Err(Error::OutcomeUnknown)
    );
    assert!(service.next_persist()?.is_none());
    let next = service
        .next_alarm(2000, &mut Zero)?
        .ok_or(Error::NotReady)?;
    assert_eq!(next.deadline(), 2005);
    assert_eq!(service.alarm_fired(&next, 2004)?, AlarmProgress::Early);
    service.alarm_fired(&next, 2005)?;
    let job = service.work_request().ok_or(Error::NotReady)?;
    let progress = service.work(&job, 32, 2005, &mut memory)?;
    let proof = match progress {
        WorkProgress::Found(p) => p,
        _ => return Err(Error::NotFound),
    };
    assert!(crypto::valid_proof(workbits, &public, &proof, &mut memory)?);
    assert!(service.next_persist()?.is_none());
    service.persisted(&pending, Ok(()))?;
    let latest = service.next_persist()?.ok_or(Error::NotReady)?;
    assert_eq!(latest.bytes(), &proof);
    assert_eq!(service.persisted(&pending, Ok(())), Err(Error::Stale));
    service.persisted(&latest, Ok(()))?;
    assert!(service.next_persist()?.is_none());
    Ok(())
}
#[test]
fn zero_capacity_and_unknown_or_out_of_round_data_do_not_forge_success() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut service = Service::<0, 0>::new(&mut instance, config()?)?;
    assert_eq!(service.connect_peer([0; 32]), Err(Error::Capacity));
    assert_eq!(service.subscribe(&[0, 4, 1, 65]), Err(Error::Capacity));
    assert!(service.next_notification(0)?.is_none());
    assert!(service.next_alarm(0, &mut Zero)?.is_none());
    assert!(service.next_sign()?.is_none());
    assert!(service.next_transmission()?.is_none());
    assert!(service.next_persist()?.is_none());
    let mut instance = Instance::new();
    let mut s = Service::<1, 0>::new(&mut instance, config()?)?;
    let p = s.connect_peer([1; 32])?;
    assert_eq!(s.receive(p, &[], &mut [])?, Received::NoIdentity);
    let k = EddsaPrivateKey::from_seed([10; 32]);
    activate(&mut s, &k, 2500)?;
    assert_eq!(
        s.receive(p, &packet(&k, 4000, 100, [0; 8])?, &mut [])?,
        Received::OutsideRounds
    );
    assert_eq!(
        s.receive(p, &[0, 4, 1, 65], &mut []).err(),
        Some(Error::InvalidInput)
    );
    let mut start = [0; 4];
    nse::encode_start(&mut start)?;
    assert_eq!(start, [0, 4, 1, 65]);
    Ok(())
}

#[test]
fn equal_current_cancels_original_sign_but_keeps_callback_tombstone() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut service = Service::<1, 0>::new(&mut instance, config()?)?;
    let key = EddsaPrivateKey::from_seed([11; 32]);
    let remote = EddsaPrivateKey::from_seed([12; 32]);
    activate(&mut service, &key, 2500)?;
    let peer = service.connect_peer([19; 32])?;
    let alarm = service
        .next_alarm(2500, &mut Zero)?
        .ok_or(Error::NotReady)?;
    service.alarm_fired(&alarm, 2500)?;
    let original = service.next_sign()?.ok_or(Error::NotReady)?;
    let equal = packet(
        &remote,
        2000,
        service.best().ok_or(Error::NotReady)?.matching_bits,
        [0; 8],
    )?;
    assert_eq!(service.receive(peer, &equal, &mut [])?, Received::Equal);
    assert!(service.next_sign()?.is_none());
    assert!(service.next_transmission()?.is_none());
    assert_eq!(
        service.signed(
            &original,
            *key.public_key().as_bytes(),
            *key.sign(14, &original.payload()?)?.as_bytes()
        ),
        Err(Error::Cancelled)
    );
    assert_eq!(
        service.signed(
            &original,
            *key.public_key().as_bytes(),
            *key.sign(14, &original.payload()?)?.as_bytes()
        ),
        Err(Error::Stale)
    );
    assert!(service.next_transmission()?.is_none());
    Ok(())
}
struct Refuse;
impl Random for Refuse {
    fn below(&mut self, _: u32) -> Result<u32, Error> {
        Err(Error::EntropyUnavailable)
    }
}
#[test]
fn active_normal_profile_uses_no_rng_and_custom_jitter_retains_refusal() -> Result<(), Error> {
    let key = EddsaPrivateKey::from_seed([13; 32]);
    let mut instance = Instance::new();
    let mut normal = Service::<1, 0>::new(&mut instance, config()?)?;
    activate(&mut normal, &key, 2500)?;
    normal.connect_peer([5; 32])?;
    let alarm = normal
        .next_alarm(2500, &mut Refuse)?
        .ok_or(Error::NotReady)?;
    assert_eq!(alarm.deadline(), 2500);
    let mut instance = Instance::new();
    let mut jitter = Service::<1, 0>::new(
        &mut instance,
        Config {
            randomize_delays: true,
            ..config()?
        },
    )?;
    activate(&mut jitter, &key, 2500)?;
    let peer = jitter.connect_peer([5; 32])?;
    assert_eq!(
        jitter.next_alarm(2500, &mut Refuse),
        Err(Error::EntropyUnavailable)
    );
    assert_eq!(jitter.peer_count(), 1);
    let alarm = jitter.next_alarm(2500, &mut Zero)?.ok_or(Error::NotReady)?;
    assert_eq!(alarm.deadline(), 2500);
    jitter.alarm_fired(&alarm, 2500)?;
    let sign = jitter.next_sign()?.ok_or(Error::NotReady)?;
    jitter.disconnect_peer(peer)?;
    assert_eq!(jitter.cancel_sign(&sign), Err(Error::Stale));
    Ok(())
}
#[test]
fn in_flight_notifications_coalesce_and_foreign_credit_never_matches() -> Result<(), Error> {
    let key = EddsaPrivateKey::from_seed([14; 32]);
    let mut a = Instance::new();
    let mut b = Instance::new();
    let mut left = Service::<1, 1>::new(&mut a, config()?)?;
    let mut right = Service::<1, 1>::new(&mut b, config()?)?;
    activate(&mut left, &key, 2500)?;
    activate(&mut right, &key, 2500)?;
    let p = left.connect_peer(*key.public_key().as_bytes())?;
    right.connect_peer(*key.public_key().as_bytes())?;
    left.subscribe(&[0, 4, 1, 65])?;
    right.subscribe(&[0, 4, 1, 65])?;
    let first = left.next_notification(1)?.ok_or(Error::NotReady)?;
    let foreign = right.next_notification(1)?.ok_or(Error::NotReady)?;
    assert_eq!(left.notified(&foreign), Err(Error::Stale));
    assert_eq!(
        left.receive(p, &packet(&key, 2000, 100, [0; 8])?, &mut [])?,
        Received::SelfUpdate
    );
    assert!(left.next_notification(2)?.is_none());
    left.notified(&first)?;
    let newer = left.next_notification(3)?.ok_or(Error::NotReady)?;
    assert_eq!(newer.estimate().timestamp.as_micros(), 3);
    assert_eq!(left.notified(&first), Err(Error::Stale));
    left.notified(&newer)?;
    assert!(left.next_notification(4)?.is_none());
    Ok(())
}

#[test]
fn found_proof_rebinds_unsigned_previous_history_before_signing() -> Result<(), Error> {
    let key = EddsaPrivateKey::from_seed([15; 32]);
    let public = *key.public_key().as_bytes();
    let bits = WorkBits::new(1)?;
    let mut memory = vec![pow::Block::new(); pow::MEMORY_BLOCKS];
    let mut invalid = None;
    for n in 0_u64..32 {
        let raw = n.to_be_bytes();
        if !crypto::valid_proof(bits, &public, &raw, &mut memory)? {
            invalid = Some(raw);
            break;
        }
    }
    let mut instance = Instance::new();
    let mut service = Service::<1, 0>::new(
        &mut instance,
        Config {
            work_bits: bits,
            ..config()?
        },
    )?;
    let barrier = service.begin_identity_change()?;
    service.finish_identity_change(
        &barrier,
        public,
        invalid.ok_or(Error::NotFound)?,
        500,
        &mut memory,
    )?;
    let alarm = service.next_alarm(500, &mut Zero)?.ok_or(Error::NotReady)?;
    service.alarm_fired(&alarm, 500)?;
    let job = service.work_request().ok_or(Error::NotReady)?;
    let round = service
        .next_alarm(1000, &mut Zero)?
        .ok_or(Error::NotReady)?;
    assert_eq!(service.alarm_fired(&round, 1000)?, AlarmProgress::Round);
    let proof = match service.work(&job, 32, 1000, &mut memory)? {
        WorkProgress::Found(proof) => proof,
        _ => return Err(Error::NotFound),
    };
    service.connect_peer([18; 32])?;
    let alarm = service
        .next_alarm(1000, &mut Zero)?
        .ok_or(Error::NotReady)?;
    service.alarm_fired(&alarm, 1000)?;
    let sign = service.next_sign()?.ok_or(Error::NotReady)?;
    assert_eq!(&sign.payload()?[52..60], &proof);
    service.signed(&sign, public, *key.sign(14, &sign.payload()?)?.as_bytes())?;
    let tx = service.next_transmission()?.ok_or(Error::NotReady)?;
    let mut bytes = [0; 132];
    tx.encode(&mut bytes)?;
    assert_eq!(tx.fields().timestamp.as_micros(), 0);
    assert!(crypto::admit(&bytes, bits, &mut memory).is_ok());
    Ok(())
}
