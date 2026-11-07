//! Signed inverse-route leases are independent of later LEARN admission work.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions check actual signed route admission and identity boundaries"
)]
use gnunet_crypto::EddsaPrivateKey;
use gnunet_transport::{
    PeerId,
    dv::{self, Learn, VerifiedLearn, routes::*},
};
use gnunet_types::{Duration, Error, MonoInstant};

struct Storage {
    routes: [RouteSlot; 4],
    probes: [ProbeSlot; 1],
    sources: [SourceSlot; 1],
}
impl Storage {
    fn new() -> Self {
        Self {
            routes: core::array::from_fn(|_| RouteSlot::empty()),
            probes: [ProbeSlot::empty()],
            sources: [SourceSlot::empty()],
        }
    }
    fn book<'id>(
        &mut self,
        instance: &'id Instance,
        local: PeerId,
    ) -> Result<Routes<'id, '_>, Error> {
        Routes::new(
            instance,
            local,
            &mut self.routes,
            &mut self.probes,
            &mut self.sources,
            Limits {
                probe_lifetime: Duration(100),
                route_lifetime: Duration(100),
                paths_per_target: 3,
            },
        )
    }
}
fn peer(key: &EddsaPrivateKey) -> PeerId {
    PeerId(*key.public_key().as_bytes())
}
fn signed_learn(
    local: PeerId,
    initiator: &EddsaPrivateKey,
    hops: &[&EddsaPrivateKey],
    stamp: u64,
    history: u16,
) -> Result<Vec<u8>, Error> {
    if hops.len() > dv::MAX_HOPS {
        return Err(Error::TooLarge);
    }
    let count = u16::try_from(hops.len()).map_err(|_| Error::TooLarge)?;
    let size = dv::LEARN_PREFIX + hops.len() * dv::HOP_BYTES;
    let wire_size = u16::try_from(size).map_err(|_| Error::TooLarge)?;
    let challenge = [0x5a; 32];
    let mut bytes = vec![0; size];
    bytes[..2].copy_from_slice(&wire_size.to_be_bytes());
    bytes[2..4].copy_from_slice(&dv::LEARN_TYPE.to_be_bytes());
    bytes[4..6].copy_from_slice(&count.to_be_bytes());
    bytes[6..8].copy_from_slice(&history.to_be_bytes());
    bytes[16..24].copy_from_slice(&stamp.to_be_bytes());
    bytes[24..88].copy_from_slice(
        initiator
            .sign(dv::INIT_PURPOSE, &dv::init_region(stamp, &challenge))?
            .as_bytes(),
    );
    bytes[88..120].copy_from_slice(&peer(initiator).0);
    bytes[120..152].copy_from_slice(&challenge);
    for (i, hop) in hops.iter().enumerate() {
        let previous = if i == 0 {
            peer(initiator)
        } else {
            peer(hops[i - 1])
        };
        let next = if i + 1 == hops.len() {
            local
        } else {
            peer(hops[i + 1])
        };
        let at = dv::LEARN_PREFIX + i * dv::HOP_BYTES;
        bytes[at..at + 32].copy_from_slice(&peer(hop).0);
        bytes[at + 32..at + dv::HOP_BYTES].copy_from_slice(
            hop.sign(dv::HOP_PURPOSE, &dv::hop_region(previous, next, &challenge))?
                .as_bytes(),
        );
    }
    Ok(bytes)
}
fn initial_route<'id>(
    routes: &mut Routes<'id, '_>,
    proof: VerifiedLearn<'_>,
    now: MonoInstant,
) -> Result<(SourceId<'id>, RouteId<'id>, MonoInstant), Error> {
    let target = proof.packet().initiator()?;
    let stamp = proof.packet().stamp()?;
    let Admission::Source(SourceWork::Load { source, peer }) = routes.accept(proof, true, now)?
    else {
        return Err(Error::Conflict);
    };
    assert_eq!(peer, target);
    routes.source_loaded(source, None)?;
    assert_eq!(
        routes.accept(proof, true, now)?,
        Admission::Source(SourceWork::Store {
            source,
            peer: target,
            stamp,
        })
    );
    routes.source_committed(source, stamp)?;
    assert_eq!(
        routes.accept(proof, true, now)?,
        Admission::Routes {
            changed: 1,
            freshness: Freshness::Passive,
        }
    );
    let route = routes
        .select(target, SendPolicy::Bidirectional, now, |_| true)?
        .ok_or(Error::NotFound)?;
    assert_eq!(route.freshness, Freshness::Passive);
    assert_eq!(route.rtt, None);
    Ok((source, route.id, route.until))
}

#[test]
fn pending_and_committed_refresh_preserve_the_original_route_until_new_accept() -> Result<(), Error>
{
    let local = peer(&EddsaPrivateKey::from_seed([1; 32]));
    let initiator = EddsaPrivateKey::from_seed([2; 32]);
    let hop = EddsaPrivateKey::from_seed([3; 32]);
    let target = peer(&initiator);
    let old = signed_learn(local, &initiator, &[&hop], 10, 1)?;
    let newer = signed_learn(local, &initiator, &[&hop], 11, 1)?;
    let old = Learn::decode(&old)?.verify(local, peer(&hop))?;
    let newer = Learn::decode(&newer)?.verify(local, peer(&hop))?;
    let instance = Instance::new();
    let mut storage = Storage::new();
    let mut routes = storage.book(&instance, local)?;
    let (source, original, until) = initial_route(&mut routes, old, MonoInstant(1))?;
    assert_eq!(until, MonoInstant(101));
    assert_eq!(
        routes.accept(newer, true, MonoInstant(20))?,
        Admission::Source(SourceWork::Store {
            source,
            peer: target,
            stamp: 11,
        })
    );
    for proof in [old, newer] {
        assert_eq!(
            routes.accept(proof, true, MonoInstant(21))?,
            Admission::Pending
        );
    }
    {
        let route = routes.select_id(
            original,
            target,
            SendPolicy::Bidirectional,
            MonoInstant(22),
            |_| true,
        )?;
        assert_eq!(route.id, original);
        assert_eq!(route.until, until);
        assert_eq!(route.path, &[peer(&hop), target]);
        assert_eq!(route.freshness, Freshness::Passive);
        assert_eq!(route.rtt, None);
    }
    assert!(
        routes
            .select(target, SendPolicy::Bidirectional, MonoInstant(22), |_| {
                false
            })?
            .is_none()
    );
    assert!(
        routes
            .select(target, SendPolicy::Confirmed, MonoInstant(22), |_| true)?
            .is_none()
    );
    routes.source_committed(source, 11)?;
    assert_eq!(routes.route(original, MonoInstant(23))?.until, until);
    assert_eq!(
        routes.accept(old, true, MonoInstant(24)),
        Err(Error::Replay)
    );
    assert_eq!(routes.route(original, MonoInstant(24))?.until, until);
    assert_eq!(
        routes.accept(newer, true, MonoInstant(25))?,
        Admission::Routes {
            changed: 1,
            freshness: Freshness::Passive,
        }
    );
    let current = routes
        .select(target, SendPolicy::Bidirectional, MonoInstant(25), |_| true)?
        .ok_or(Error::NotFound)?;
    assert_ne!(current.id, original);
    assert_eq!(current.until, MonoInstant(125));
    assert_eq!(current.freshness, Freshness::Passive);
    assert_eq!(current.rtt, None);
    assert!(matches!(
        routes.route(original, MonoInstant(26)),
        Err(Error::StaleGeneration)
    ));
    Ok(())
}

#[test]
fn a_failed_new_candidate_does_not_refresh_or_replace_the_old_lease() -> Result<(), Error> {
    let local = peer(&EddsaPrivateKey::from_seed([4; 32]));
    let initiator = EddsaPrivateKey::from_seed([5; 32]);
    let old_hop = EddsaPrivateKey::from_seed([6; 32]);
    let looping_hop = EddsaPrivateKey::from_seed([7; 32]);
    let old = signed_learn(local, &initiator, &[&old_hop], 10, 1)?;
    // Both hop signatures are real. Repeated path peers are a separate route
    // semantic failure, checked only after the actual admission floor barrier.
    let looping = signed_learn(local, &initiator, &[&looping_hop, &looping_hop], 11, 3)?;
    let old = Learn::decode(&old)?.verify(local, peer(&old_hop))?;
    let looping = Learn::decode(&looping)?.verify(local, peer(&looping_hop))?;
    let instance = Instance::new();
    let mut storage = Storage::new();
    let mut routes = storage.book(&instance, local)?;
    let (source, original, until) = initial_route(&mut routes, old, MonoInstant(1))?;
    assert!(matches!(
        routes.accept(looping, true, MonoInstant(20))?,
        Admission::Source(SourceWork::Store { stamp: 11, .. })
    ));
    assert_eq!(
        routes.source_committed(source, 12),
        Err(Error::StaleGeneration)
    );
    assert_eq!(routes.route(original, MonoInstant(21))?.until, until);
    routes.source_committed(source, 11)?;
    assert_eq!(
        routes.accept(looping, true, MonoInstant(22)),
        Err(Error::Malformed)
    );
    let current = routes
        .select(
            peer(&initiator),
            SendPolicy::Bidirectional,
            MonoInstant(23),
            |_| true,
        )?
        .ok_or(Error::NotFound)?;
    assert_eq!(current.id, original);
    assert_eq!(current.path, &[peer(&old_hop), peer(&initiator)]);
    assert_eq!(current.until, until);
    assert_eq!(current.freshness, Freshness::Passive);
    assert_eq!(current.rtt, None);
    assert_eq!(
        routes.accept(old, true, MonoInstant(24)),
        Err(Error::Replay)
    );
    Ok(())
}

#[test]
fn source_loss_and_slot_reuse_cannot_revive_old_routes_or_receipts() -> Result<(), Error> {
    let local = peer(&EddsaPrivateKey::from_seed([8; 32]));
    let initiator = EddsaPrivateKey::from_seed([9; 32]);
    let hop = EddsaPrivateKey::from_seed([10; 32]);
    let bytes = signed_learn(local, &initiator, &[&hop], 10, 1)?;
    let proof = Learn::decode(&bytes)?.verify(local, peer(&hop))?;
    let instance = Instance::new();
    let mut storage = Storage::new();
    let mut routes = storage.book(&instance, local)?;
    let (old_source, original, _) = initial_route(&mut routes, proof, MonoInstant(1))?;
    routes.source_lost(old_source)?;
    assert!(matches!(
        routes.route(original, MonoInstant(20)),
        Err(Error::StaleGeneration)
    ));
    let Admission::Source(SourceWork::Load { source, .. }) =
        routes.accept(proof, true, MonoInstant(21))?
    else {
        return Err(Error::Conflict);
    };
    assert_ne!(source, old_source);
    assert_eq!(
        routes.source_loaded(old_source, Some(10)),
        Err(Error::StaleGeneration)
    );
    assert_eq!(
        routes.source_committed(old_source, 10),
        Err(Error::StaleGeneration)
    );
    routes.source_loaded(source, Some(10))?;
    assert!(matches!(
        routes.accept(proof, true, MonoInstant(22))?,
        Admission::Routes { changed: 1, .. }
    ));
    let current = routes
        .select(
            peer(&initiator),
            SendPolicy::Bidirectional,
            MonoInstant(23),
            |_| true,
        )?
        .ok_or(Error::NotFound)?;
    assert_ne!(current.id, original);
    let current = current.id;
    assert_eq!(routes.source_lost(old_source), Err(Error::StaleGeneration));
    assert!(matches!(
        routes.route(original, MonoInstant(24)),
        Err(Error::StaleGeneration)
    ));
    assert_eq!(
        routes.route(current, MonoInstant(24))?.until,
        MonoInstant(122)
    );
    Ok(())
}

#[test]
fn pending_and_committed_watermarks_cannot_extend_an_installed_route_expiry() -> Result<(), Error> {
    let local = peer(&EddsaPrivateKey::from_seed([11; 32]));
    let initiator = EddsaPrivateKey::from_seed([12; 32]);
    let hop = EddsaPrivateKey::from_seed([13; 32]);
    let old = signed_learn(local, &initiator, &[&hop], 10, 1)?;
    let newer = signed_learn(local, &initiator, &[&hop], 11, 1)?;
    let newest = signed_learn(local, &initiator, &[&hop], 12, 1)?;
    let old = Learn::decode(&old)?.verify(local, peer(&hop))?;
    let newer = Learn::decode(&newer)?.verify(local, peer(&hop))?;
    let newest = Learn::decode(&newest)?.verify(local, peer(&hop))?;
    let target = peer(&initiator);
    let instance = Instance::new();
    let mut storage = Storage::new();
    let mut routes = storage.book(&instance, local)?;
    let (source, original, _) = initial_route(&mut routes, old, MonoInstant(1))?;
    assert!(matches!(
        routes.accept(newer, true, MonoInstant(20))?,
        Admission::Source(SourceWork::Store { stamp: 11, .. })
    ));
    assert_eq!(
        routes.route(original, MonoInstant(100))?.until,
        MonoInstant(101)
    );
    assert!(
        routes
            .select(target, SendPolicy::Bidirectional, MonoInstant(101), |_| {
                true
            })?
            .is_none()
    );
    routes.source_committed(source, 11)?;
    assert!(matches!(
        routes.route(original, MonoInstant(102)),
        Err(Error::StaleGeneration)
    ));
    assert!(matches!(
        routes.accept(newer, true, MonoInstant(103))?,
        Admission::Routes { changed: 1, .. }
    ));
    let current = routes
        .select(target, SendPolicy::Bidirectional, MonoInstant(104), |_| {
            true
        })?
        .ok_or(Error::NotFound)?
        .id;
    assert!(matches!(
        routes.accept(newest, true, MonoInstant(110))?,
        Admission::Source(SourceWork::Store { stamp: 12, .. })
    ));
    routes.source_committed(source, 12)?;
    assert_eq!(
        routes.route(current, MonoInstant(202))?.until,
        MonoInstant(203)
    );
    assert!(
        routes
            .select(target, SendPolicy::Bidirectional, MonoInstant(203), |_| {
                true
            })?
            .is_none()
    );
    Ok(())
}
