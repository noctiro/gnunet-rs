//! Bounded actual GAP local cover/permission models, not network anonymity proof.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible models assert actual original route/shape/write/cover and revoked-admission retirement"
)]
use gnunet_crypto::hash512;
use gnunet_fs::{
    content::encode_data,
    gap::{
        self, Entropy, Neighbor, NeighborSlot, PathSlot, Route, RouteSlot, Router, Selection,
        privacy,
    },
};
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime,
    fs::BlockType,
    fs_gap::{Get, Put},
};
struct Draw(u32);
impl Entropy for Draw {
    fn uniform(&mut self, upper: u32) -> Result<u32, Error> {
        if upper == 0 {
            return Err(Error::InvalidInput);
        }
        Ok(self.0 % upper)
    }
}
fn get<'id>(
    router: &mut Router<'id, '_, '_>,
    from: Neighbor<'id>,
    query: [u8; 64],
) -> Result<gap::Admission<'id>, Error> {
    let mut bytes = [0; 88];
    let n = Get {
        block_type: BlockType::DBLOCK,
        priority: 32,
        ttl_seconds: 60,
        reserved: 0,
        bitmap: 0,
        query: &query,
        identities: &[],
        bloom: &[],
    }
    .encode(&mut bytes)?;
    router.receive_get_from(from, &bytes[..n], 0, &mut Draw(0), false)
}
fn permit<'id>(
    policy: &mut privacy::Policy<'id, '_>,
    r: privacy::Requirement<'id>,
    now: u64,
) -> Result<privacy::Permit<'id>, Error> {
    match policy.admit(r, now, &mut Draw(0))? {
        privacy::Admission::Ready(p) => Ok(p),
        privacy::Admission::Wait(_) => Err(Error::NotReady),
    }
}
fn query_written<'id>(
    router: &mut Router<'id, '_, '_>,
    policy: &mut privacy::Policy<'id, '_>,
    route: Route<'id>,
    to: Neighbor<'id>,
    now: u64,
) -> Result<(), Error> {
    let requirement = router.query_requirement(route, to)?;
    let p = permit(policy, requirement, now)?;
    let tx = router.prepare_query_with_permit(route, to, now, &mut Draw(0), p)?;
    policy.bind(p, tx)?;
    router.admitted(tx)?;
    router.exposed(tx)?;
    policy.exposed(p)?;
    let fact = router.written(tx)?;
    policy.settle(p, fact, now, true, true)
}
fn reply_written<'id>(
    router: &mut Router<'id, '_, '_>,
    policy: &mut privacy::Policy<'id, '_>,
    path: gap::Path<'id>,
    p: privacy::Permit<'id>,
    now: u64,
) -> Result<(), Error> {
    let tx = router.prepare_reply_with_permit(path, p)?;
    policy.bind(p, tx)?;
    router.admitted(tx)?;
    router.exposed(tx)?;
    policy.exposed(p)?;
    policy.settle(p, router.written(tx)?, now, true, true)
}
fn balance(policy: &privacy::Policy<'_, '_>) -> u64 {
    policy.credits().map(|(_, _, n)| u64::from(n)).sum()
}

#[test]
fn higher_queries_wait_for_real_equivalent_relay_writes_and_never_self_cover() -> Result<(), Error>
{
    let mut identity = gap::Instance::new();
    let mut neighbors = [NeighborSlot::default(); 3];
    let mut bytes = [[0; 256]; 6];
    let mut routes = bytes.each_mut().map(|b| RouteSlot::new(b));
    let mut paths = [PathSlot::default(); 8];
    let mut output = [0; 256];
    let mut router = Router::new(
        &mut identity,
        &mut neighbors,
        &mut routes,
        &mut paths,
        &mut output,
        gap::Limits::default(),
    )?;
    let origin = router.attach([1; 32])?;
    let egress = router.attach([2; 32])?;
    let mut domain = privacy::Instance::new();
    let mut credits = [privacy::CreditSlot::new(); 4];
    let mut intents = [privacy::IntentSlot::new(); 2];
    let mut policy = privacy::Policy::new(
        &mut domain,
        &mut credits,
        &mut intents,
        privacy::Limits::default(),
    )?;
    let one = get(&mut router, origin, [1; 64])?;
    let two = get(&mut router, origin, [2; 64])?;
    let three = get(&mut router, origin, [3; 64])?;
    let four = get(&mut router, origin, [5; 64])?;
    let five = get(&mut router, origin, [6; 64])?;
    let own = router.start_with_seen(
        Selection {
            kind: BlockType::DBLOCK,
            query: [4; 64],
        },
        44,
        3,
        32,
        60,
        0,
        &[],
        &mut Draw(0),
    )?;
    for _ in 0..6 {
        let job = router.next_lookup().ok_or(Error::NotReady)?;
        router.source_finished(job.route, None)?;
    }
    let r = router.query_requirement(own.route, egress)?;
    assert_eq!(r.level(), Some(3));
    assert_eq!(r.needed(), 2);
    assert!(!r.relayed());
    assert_eq!(
        router.prepare_query(own.route, egress, 0, &mut Draw(0)),
        Err(Error::NotReady)
    );
    let privacy::Admission::Wait(wait) = policy.admit(r, 0, &mut Draw(0))? else {
        return Err(Error::Authentication);
    };
    assert_eq!(wait.reason, privacy::WaitReason::Cover);
    assert_eq!((wait.available, wait.needed), (0, 2));
    assert_eq!(
        policy.intents().count(),
        0,
        "waiting own cover must leave room for genuine relays"
    );
    query_written(&mut router, &mut policy, one.route, egress, 0)?;
    assert_eq!(balance(&policy), 1);
    assert!(
        matches!(policy.admit(r,0,&mut Draw(0))?,privacy::Admission::Wait(w) if w.available==1&&w.needed==2)
    );
    query_written(&mut router, &mut policy, two.route, egress, 0)?;
    assert_eq!(balance(&policy), 2);
    let p = permit(&mut policy, r, 0)?;
    assert_eq!(balance(&policy), 0);
    let tx = router.prepare_query_with_permit(own.route, egress, 0, &mut Draw(0), p)?;
    let wire = router.send_bytes(tx)?.1;
    assert_eq!(wire.len(), 88);
    let decoded = Get::decode(wire)?;
    assert_eq!(decoded.query, &[4; 64]);
    assert_eq!(decoded.bitmap, 0);
    assert!(decoded.identities.is_empty());
    policy.bind(p, tx)?;
    router.admitted(tx)?;
    router.exposed(tx)?;
    policy.exposed(p)?;
    policy.settle(p, router.written(tx)?, 0, true, true)?;
    assert_eq!(
        balance(&policy),
        0,
        "originated writes must never replenish their own cover"
    );
    assert_eq!(policy.report().spent, 2);
    assert_eq!(policy.report().other_written, 1);
    assert_eq!(policy.report().relayed_queries_written, 2);
    // A genuine foreign frame with an exposed failure still earns no credit.
    let foreign = router.query_requirement(three.route, egress)?;
    let p = permit(&mut policy, foreign, 0)?;
    let tx = router.prepare_query_with_permit(three.route, egress, 0, &mut Draw(0), p)?;
    policy.bind(p, tx)?;
    router.admitted(tx)?;
    router.exposed(tx)?;
    policy.exposed(p)?;
    let fact = router.send_failed(tx)?;
    assert!(fact.exposed && !fact.written);
    policy.settle(p, fact, 0, false, true)?;
    assert_eq!(balance(&policy), 0);
    query_written(&mut router, &mut policy, four.route, egress, 500_000)?;
    query_written(&mut router, &mut policy, five.route, egress, 1_000_000)?;
    assert_eq!(balance(&policy), 2);
    assert_eq!(policy.next_deadline(1_000_000), Some(1_500_000));
    policy.advance(1_500_000)?;
    assert_eq!(
        balance(&policy),
        0,
        "later cover cannot extend the original batch window"
    );
    policy.request_shutdown();
    assert!(policy.quiesced());
    router.request_shutdown();
    assert!(router.quiesced());
    Ok(())
}

#[test]
fn real_publisher_anonymity_delay_and_revoked_permission_keep_original_settlement()
-> Result<(), Error> {
    let mut encoded = [[0; 64]; 4];
    let mut ciphertexts = [[0; 64]; 4];
    let mut queries = [[0; 64]; 4];
    let mut lengths = [0; 4];
    for i in 0..4 {
        let value = [u8::try_from(i + 1).map_err(|_| Error::Overflow)?; 8];
        let content = encode_data(&value, &mut encoded[i])?;
        queries[i] = content.key().query;
        lengths[i] = content.bytes().len();
        ciphertexts[i][..lengths[i]].copy_from_slice(content.bytes());
    }
    let mut identity = gap::Instance::new();
    let mut neighbors = [NeighborSlot::default(); 3];
    let mut results = [[0; 256]; 4];
    let mut slots = results.each_mut().map(|b| RouteSlot::new(b));
    let mut paths = [PathSlot::default(); 4];
    let mut output = [0; 256];
    let mut router = Router::new(
        &mut identity,
        &mut neighbors,
        &mut slots,
        &mut paths,
        &mut output,
        gap::Limits::default(),
    )?;
    let requester = router.attach([3; 32])?;
    let provider = router.attach([4; 32])?;
    let a = get(&mut router, requester, queries[0])?;
    let b = get(&mut router, requester, queries[1])?;
    let c = get(&mut router, requester, queries[2])?;
    let d = get(&mut router, requester, queries[3])?;
    for _ in 0..4 {
        let job = router.next_lookup().ok_or(Error::NotReady)?;
        if job.route == a.route {
            let mut wire = [0; 256];
            let n = Put {
                block_type: BlockType::DBLOCK,
                expiration: AbsoluteTime::NEVER,
                block: &ciphertexts[0][..lengths[0]],
            }
            .encode(&mut wire)?;
            router.source_finished_local(job.route, Some(&wire[..n]), 3)?;
        } else {
            router.source_finished(job.route, None)?;
        }
    }
    for i in 1..4 {
        let mut wire = [0; 256];
        let n = Put {
            block_type: BlockType::DBLOCK,
            expiration: AbsoluteTime::NEVER,
            block: &ciphertexts[i][..lengths[i]],
        }
        .encode(&mut wire)?;
        router.receive_put_from(provider, &wire[..n], false)?;
    }
    assert!(matches!(
        router.result_info(a.path)?.source,
        gap::ResultSource::Local { anonymity: 3 }
    ));
    assert!(matches!(
        router.result_info(b.path)?.source,
        gap::ResultSource::Peer {
            is_local: false,
            ..
        }
    ));
    assert_eq!(hash512(&ciphertexts[0][..lengths[0]]), queries[0]);
    let mut domain = privacy::Instance::new();
    let mut credits = [privacy::CreditSlot::new(); 1];
    let mut queue = [privacy::IntentSlot::new(); 2];
    let mut policy = privacy::Policy::new(
        &mut domain,
        &mut credits,
        &mut queue,
        privacy::Limits {
            randomized_delays: true,
            maximum_delay_ms: 10_000,
            cover_window_us: 10_000_000,
        },
    )?;
    let own = router.reply_requirement(a.path)?;
    assert_eq!(own.level(), Some(3));
    assert_eq!(own.needed(), 2);
    assert_eq!(router.prepare_reply(a.path), Err(Error::NotReady));
    assert!(
        matches!(policy.admit(own,0,&mut Draw(5))?,privacy::Admission::Wait(w) if w.reason==privacy::WaitReason::Cover)
    );
    assert_eq!(policy.intents().count(), 0);
    let br = router.reply_requirement(b.path)?;
    let cr = router.reply_requirement(c.path)?;
    assert_eq!(
        br.level(),
        None,
        "peer138 carries no numeric source anonymity"
    );
    assert!(br.source_policy_supplied());
    assert_eq!(br.needed(), 0);
    assert!(br.relayed());
    assert_eq!(br.class(), own.class());
    assert!(
        matches!(policy.admit(br,0,&mut Draw(5))?,privacy::Admission::Wait(w) if w.reason==privacy::WaitReason::Delay&&w.ready_at==Some(5000))
    );
    assert!(
        matches!(policy.admit(cr,0,&mut Draw(5))?,privacy::Admission::Wait(w) if w.reason==privacy::WaitReason::Delay&&w.ready_at==Some(5000))
    );
    assert_eq!(policy.intents().count(), 2);
    // Clock evidence can revoke, but never redraw/clamp an original target.
    policy.advance(1000)?;
    policy.advance(999)?;
    assert!(
        matches!(policy.admit(br,999,&mut Draw(9))?,privacy::Admission::Wait(w) if w.ready_at==Some(5000))
    );
    assert_eq!(policy.report().delays_drawn, 2);
    let p = permit(&mut policy, br, 5000)?;
    reply_written(&mut router, &mut policy, b.path, p, 5000)?;
    assert_eq!(balance(&policy), 1);
    let p = permit(&mut policy, cr, 5000)?;
    reply_written(&mut router, &mut policy, c.path, p, 5000)?;
    assert_eq!(balance(&policy), 2);
    assert!(
        matches!(policy.admit(own,4_999_000,&mut Draw(5))?,privacy::Admission::Wait(w) if w.ready_at==Some(5_004_000))
    );
    policy.advance(5_001_000)?;
    assert!(
        matches!(policy.admit(own,5_001_000,&mut Draw(9))?,privacy::Admission::Wait(w) if w.reason==privacy::WaitReason::Cover&&w.ready_at==Some(5_004_000))
    );
    // The own intent keeps its original target even after credits age out.
    // Its occupied row cannot block the reserved genuine-relay row.
    let dr = router.reply_requirement(d.path)?;
    assert!(
        matches!(policy.admit(dr,5_001_000,&mut Draw(5))?,privacy::Admission::Wait(w) if w.reason==privacy::WaitReason::Delay&&w.ready_at==Some(5_006_000))
    );
    let p = permit(&mut policy, dr, 5_006_000)?;
    reply_written(&mut router, &mut policy, d.path, p, 5_006_000)?;
    assert_eq!(balance(&policy), 2);
    let p = permit(&mut policy, own, 5_006_000)?;
    assert_eq!(
        policy.report().delays_drawn,
        4,
        "old own release target was redrawn after cover recovery"
    );
    assert_eq!(balance(&policy), 0);
    assert_eq!(policy.next_deadline(5_006_000), Some(10_005_000));
    let tx = router.prepare_reply_with_permit(a.path, p)?;
    policy.bind(p, tx)?;
    router.admitted(tx)?;
    policy.advance(5_005_999)?;
    assert!(!p.is_live());
    assert!(!p.time_epoch_current());
    assert_eq!(
        router.prepare_reply_with_permit(a.path, p),
        Err(Error::StaleGeneration)
    );
    let original = router.send_failed(tx)?;
    assert!(original.admitted && !original.exposed && !original.written);
    // Original retirement does not need a still-live admission permission.
    policy.settle(p, original, 5_005_999, false, true)?;
    assert!(policy.pending().is_none());
    assert_eq!(balance(&policy), 0);
    assert_eq!(policy.report().refunded, 0);
    assert_eq!(policy.report().discarded, 3);
    policy.request_shutdown();
    assert!(policy.quiesced());
    router.request_shutdown();
    assert!(router.quiesced());
    Ok(())
}
