#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify authenticated routes and original receipt state."
)]

use super::*;

fn identity(key: &EddsaPrivateKey) -> PeerId {
    PeerId(*key.public_key().as_bytes())
}

fn append(
    packet: Learn<'_>,
    previous: PeerId,
    signer: &EddsaPrivateKey,
    next: PeerId,
    out: &mut [u8],
) -> Result<usize, Error> {
    let signature = signer.sign(
        dv::HOP_PURPOSE,
        &dv::hop_region(previous, next, &packet.challenge()?),
    )?;
    packet.forward(
        dv::Hop {
            peer: identity(signer),
            signature: *signature.as_bytes(),
        },
        true,
        0,
        out,
    )
}

#[test]
fn inverse_path_needs_durable_source_and_expires_with_its_original_carrier() -> Result<(), Error> {
    let origin = EddsaPrivateKey::from_seed([1; 32]);
    let relay = EddsaPrivateKey::from_seed([2; 32]);
    let local = EddsaPrivateKey::from_seed([3; 32]);
    let origin_peer = identity(&origin);
    let relay_peer = identity(&relay);
    let local_peer = identity(&local);
    let challenge = [10; 32];
    let stamp = 11;
    let signature = origin.sign(dv::INIT_PURPOSE, &dv::init_region(stamp, &challenge))?;
    let initial = dv::initiate(origin_peer, stamp, &challenge, signature.as_bytes());
    let mut wire = [0; dv::LEARN_PREFIX + dv::HOP_BYTES];
    let length = append(
        Learn::decode(&initial)?,
        origin_peer,
        &relay,
        local_peer,
        &mut wire,
    )?;

    let instance = Instance::new();
    let mut neighbours = [NeighbourSlot::empty(), NeighbourSlot::empty()];
    let mut slots = [routes::RouteSlot::empty()];
    let mut probe = routes::ProbeSlot::empty();
    let mut sources = [routes::SourceSlot::empty()];
    let mut router = Router::new(
        &instance,
        local_peer,
        Storage {
            neighbours: &mut neighbours,
            routes: &mut slots,
            probe: &mut probe,
            sources: &mut sources,
        },
        routes::Limits::default(),
    )?;
    let zero = MonoInstant(0);
    let until = MonoInstant(100);
    let input_carrier = router.attach(relay_peer, until, zero)?;
    let mut input = router.verify_learn(input_carrier, &wire[..length], zero)?;
    let routes::Admission::Source(routes::SourceWork::Load { source, peer }) =
        router.accept_learn(&mut input, zero)?
    else {
        return Err(Error::Conflict);
    };
    assert_eq!(peer, origin_peer);
    router.source_loaded(source, None)?;
    assert_eq!(
        router.accept_learn(&mut input, zero)?,
        routes::Admission::Source(routes::SourceWork::Store {
            source,
            peer: origin_peer,
            stamp
        })
    );
    assert!(
        router
            .select(origin_peer, routes::SendPolicy::Bidirectional, zero)?
            .is_none()
    );
    router.source_committed(source, stamp)?;
    assert_eq!(
        router.accept_learn(&mut input, zero)?,
        routes::Admission::Routes {
            changed: 1,
            freshness: routes::Freshness::Passive
        }
    );
    assert!(
        router
            .select(origin_peer, routes::SendPolicy::Confirmed, zero)?
            .is_none()
    );
    {
        let selected = router
            .select(origin_peer, routes::SendPolicy::Bidirectional, zero)?
            .ok_or(Error::NotFound)?;
        assert_eq!(selected.next, input_carrier);
        assert_eq!(selected.route.path, &[relay_peer, origin_peer]);
        assert_eq!(selected.route.rtt, None);
    }

    // The nontrivial probe may return to its initiator over another real link.
    let target_carrier = router.attach(origin_peer, until, zero)?;
    let mut outgoing = [0; dv::LEARN_PREFIX + 2 * dv::HOP_BYTES];
    let (staged, length) =
        router.stage_learn(&mut input, target_carrier, zero, &local, &mut outgoing)?;
    let _verified = Learn::decode(&outgoing[..length])?.verify(origin_peer, local_peer)?;
    router.check_staged_learn(&staged, zero)?;
    assert!(matches!(
        router.stage_learn(&mut input, target_carrier, zero, &local, &mut outgoing),
        Err(Error::Conflict)
    ));
    assert!(
        router
            .select(origin_peer, routes::SendPolicy::Bidirectional, until)?
            .is_none()
    );
    let replacement = router.attach(relay_peer, MonoInstant(200), until)?;
    assert_ne!(replacement, input_carrier);
    assert_eq!(
        router.peer(input_carrier, until),
        Err(Error::StaleGeneration)
    );
    Ok(())
}

struct FixedEntropy;

impl Entropy for FixedEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
        output.fill(4);
        Ok(())
    }
}

#[test]
fn confirmed_loop_requires_the_same_written_first_hop() -> Result<(), Error> {
    let local = EddsaPrivateKey::from_seed([5; 32]);
    let first = EddsaPrivateKey::from_seed([6; 32]);
    let last = EddsaPrivateKey::from_seed([7; 32]);
    let local_peer = identity(&local);
    let first_peer = identity(&first);
    let last_peer = identity(&last);
    let instance = Instance::new();
    let mut neighbours = [NeighbourSlot::empty(), NeighbourSlot::empty()];
    let mut slots = [routes::RouteSlot::empty()];
    let mut probe = routes::ProbeSlot::empty();
    let mut sources = [routes::SourceSlot::empty()];
    let mut router = Router::new(
        &instance,
        local_peer,
        Storage {
            neighbours: &mut neighbours,
            routes: &mut slots,
            probe: &mut probe,
            sources: &mut sources,
        },
        routes::Limits::default(),
    )?;
    let until = MonoInstant(100);
    let zero = MonoInstant(0);
    let first_link = router.attach(first_peer, until, zero)?;
    let return_link = router.attach(last_peer, until, zero)?;
    let stamp = NonZeroU64::new(2).ok_or(Error::InvalidInput)?;
    let (id, packet) = router.begin_probe(first_link, zero, stamp, &local, &mut FixedEntropy)?;
    let mut intermediate = [0; dv::LEARN_PREFIX + dv::HOP_BYTES];
    append(
        Learn::decode(&packet)?,
        local_peer,
        &first,
        last_peer,
        &mut intermediate,
    )?;
    let mut returned = [0; dv::LEARN_PREFIX + 2 * dv::HOP_BYTES];
    append(
        Learn::decode(&intermediate)?,
        first_peer,
        &last,
        local_peer,
        &mut returned,
    )?;
    let now = MonoInstant(10);
    let mut input = router.verify_learn(return_link, &returned, now)?;
    assert_eq!(
        router.probe_written(id, return_link, now),
        Err(Error::StaleGeneration)
    );
    assert_eq!(
        router.accept_learn(&mut input, now),
        Err(Error::StaleGeneration)
    );
    router.probe_written(id, first_link, now)?;
    assert_eq!(
        router.accept_learn(&mut input, now)?,
        routes::Admission::Routes {
            changed: 1,
            freshness: routes::Freshness::Confirmed
        }
    );
    let selected = router
        .select(last_peer, routes::SendPolicy::Confirmed, now)?
        .ok_or(Error::NotFound)?;
    assert_eq!(selected.next, first_link);
    assert_eq!(selected.route.path, &[first_peer, last_peer]);
    Ok(())
}

#[test]
fn box_forwarding_preserves_its_original_admission_and_egress() -> Result<(), Error> {
    let local = identity(&EddsaPrivateKey::from_seed([20; 32]));
    let ingress = identity(&EddsaPrivateKey::from_seed([21; 32]));
    let next = identity(&EddsaPrivateKey::from_seed([22; 32]));
    let unknown = identity(&EddsaPrivateKey::from_seed([23; 32]));
    let instance = Instance::new();
    let mut neighbours = [NeighbourSlot::empty(), NeighbourSlot::empty()];
    let mut slots = [routes::RouteSlot::empty()];
    let mut probe = routes::ProbeSlot::empty();
    let mut sources = [routes::SourceSlot::empty()];
    let mut router = Router::new(
        &instance,
        local,
        Storage {
            neighbours: &mut neighbours,
            routes: &mut slots,
            probe: &mut probe,
            sources: &mut sources,
        },
        routes::Limits::default(),
    )?;
    let now = MonoInstant(1);
    let until = MonoInstant(100);
    let source = router.attach(ingress, until, now)?;
    let destination = router.attach(next, until, now)?;
    let header = dv::BoxHeader {
        without_fc: false,
        encapsulation: [0; 32],
        nonce: [0; 24],
        mac: [0; 16],
    };
    // These tests inspect routing of opaque ciphertext, not payload authentication.
    let ciphertext = [9; dv::PAYLOAD_PREFIX + 4];
    let mut wire = [0; dv::BOX_PREFIX + 2 * 32 + dv::PAYLOAD_PREFIX + 4];
    let size = header.encode(&[unknown, next], &ciphertext, &mut wire)?;
    let BoxAction::Forward(pending) = router.box_action(source, &wire[..size], now)? else {
        return Err(Error::Conflict);
    };
    let BoxAction::Forward(competing) = router.box_action(source, &wire[..size], now)? else {
        return Err(Error::Conflict);
    };
    assert_eq!(pending.egress(), destination);
    assert_eq!(pending.deadline(), until);
    let mut scratch = [0; dv::BOX_PREFIX + dv::PAYLOAD_PREFIX + 4];
    let (staged, len) = router.stage_box(pending, now, &mut scratch)?;
    let packet = dv::BoxPacket::decode(&scratch[..len])?;
    assert_eq!(packet.traversed(), 2);
    assert_eq!(packet.hop_count(), 0);
    assert_eq!(packet.ciphertext(), ciphertext.as_slice());
    router.check_staged_box(&staged, now)?;
    assert!(matches!(
        router.stage_box(competing, now, &mut scratch),
        Err(Error::WouldBlock)
    ));

    let Err(wrong_owner) = router.settle_staged_box(staged, source, Ok(())) else {
        return Err(Error::Conflict);
    };
    assert_eq!(wrong_owner.reason, Error::StaleGeneration);
    router.check_staged_box(&wrong_owner.value, now)?;
    assert_eq!(
        router
            .settle_staged_box(wrong_owner.value, destination, Err(Error::Cancelled))
            .map_err(|rejected| rejected.reason)?,
        BoxCompletion {
            ingress: source,
            egress: destination,
            ordered: Err(Error::Cancelled)
        }
    );

    let BoxAction::Forward(stale) = router.box_action(source, &wire[..size], now)? else {
        return Err(Error::Conflict);
    };
    router.detach(destination)?;
    let replacement = router.attach(next, until, now)?;
    assert_ne!(replacement, destination);
    assert!(matches!(
        router.stage_box(stale, now, &mut scratch),
        Err(Error::StaleGeneration)
    ));
    router.detach(replacement)?;
    assert!(matches!(
        router.box_action(source, &wire[..size], now),
        Err(Error::NotReady)
    ));
    let size = header.encode(&[unknown, ingress], &ciphertext, &mut wire)?;
    assert!(matches!(
        router.box_action(source, &wire[..size], now),
        Err(Error::Malformed)
    ));
    Ok(())
}
