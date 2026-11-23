//! Signed FS result groups, independent consumer state and continuous replies.
//! These are pure ownership models, not native encrypted-peer acceptance.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Models assert official signed-envelope/type/key/group and original local ownership facts"
)]
use gnunet_crypto::{gns::EdkeySecret, hash512};
use gnunet_fs::{
    gap::{self, Entropy, NeighborSlot, PathSlot, ResultState, RouteSlot, Router, Selection},
    ublock,
};
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime,
    fs::BlockType,
    fs_gap::{GET_PREFIX, Get, Put, RETURN_TO, TRANSMIT_TO},
};
struct Zero;
impl Entropy for Zero {
    fn uniform(&mut self, upper: u32) -> Result<u32, Error> {
        if upper == 0 {
            Err(Error::InvalidInput)
        } else {
            Ok(0)
        }
    }
}
fn signed(payload: u8) -> Result<([u8; 64], Vec<u8>), Error> {
    let secret = EdkeySecret::from_seed([17; 32]);
    let signer = secret.derive_bytes(b"same query", b"fs-ublock")?;
    let public = signer.public_key();
    let mut bytes = vec![0; 105];
    bytes[64..68].copy_from_slice(&41_u32.to_be_bytes());
    bytes[68..72].copy_from_slice(&ublock::PURPOSE.to_be_bytes());
    bytes[72..104].copy_from_slice(&public);
    bytes[104] = payload;
    let signature = signer.sign(ublock::PURPOSE, &[&bytes[64..]])?;
    bytes[..64].copy_from_slice(&signature);
    let query = hash512(&public);
    ublock::verify_envelope(&bytes, &query)?;
    Ok((query, bytes))
}
fn frame(block: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    Put {
        block_type: BlockType::UBLOCK,
        expiration: AbsoluteTime::from_micros(777),
        block,
    }
    .encode(out)
}
#[test]
fn signed_multi_results_keep_independent_any_and_ublock_groups_and_exact_pending_input()
-> Result<(), Error> {
    multi_result_groups(1)
}
#[test]
fn nonanonymous_any_and_ublock_keep_seen_groups_and_verified_multi_results() -> Result<(), Error> {
    multi_result_groups(0)
}

#[test]
fn full_width_peer_filter_uses_its_supplied_slot_and_retires_without_heap() -> Result<(), Error> {
    use gnunet_block::{
        BlockType as RegisteredKind,
        bloom::{BloomGroup, NativeEndian},
    };

    let (query, known) = signed(1)?;
    let (_, novel) = signed(2)?;
    let mut raw = [0; 4 + gap::MAX_GROUP_FILTER_BYTES];
    let nonce = 0x0102_0304_u32;
    raw[..4].copy_from_slice(&nonce.to_ne_bytes());
    let mut seen = BloomGroup::borrow_existing(
        &mut raw[4..],
        RegisteredKind::FS_UBLOCK,
        16,
        nonce,
        NativeEndian::native(),
    )?;
    assert!(!seen.test_and_set(&hash512(&known)));

    let mut scope = gap::Instance::new();
    let mut neighbors = [NeighborSlot::default(); 3];
    let mut results = [[0; 256]; 3];
    let mut filter = [0; gap::MAX_GROUP_FILTER_BYTES];
    let [wide, first_narrow, second_narrow] = results.each_mut();
    let mut routes = [
        RouteSlot::with_group_filter(wide, &mut filter),
        RouteSlot::new(first_narrow),
        RouteSlot::new(second_narrow),
    ];
    let mut paths = [PathSlot::default(); 3];
    let mut output = [0; 256];
    let limits = gap::Limits {
        filter_heap_bytes: 0,
        ..gap::Limits::default()
    };
    let mut router = Router::new(
        &mut scope,
        &mut neighbors,
        &mut routes,
        &mut paths,
        &mut output,
        limits,
    )?;
    let first = router.attach([1; 32])?;
    let second = router.attach([2; 32])?;
    let supplier = router.attach([3; 32])?;
    let now = 1;
    router.start_with_seen(
        Selection::new(BlockType::UBLOCK, [9; 64])?,
        11,
        1,
        32,
        60,
        now,
        &[],
        &mut Zero,
    )?;
    let request = Get {
        block_type: BlockType::UBLOCK,
        priority: 32,
        ttl_seconds: 60,
        reserved: 0,
        bitmap: 0,
        query: &query,
        identities: &[],
        bloom: &[],
    };
    let mut wire = [0; GET_PREFIX + 4 + gap::MAX_GROUP_FILTER_BYTES];
    let size = Get {
        bloom: &raw,
        ..request
    }
    .encode(&mut wire)?;
    let original = router.receive_get(first, &wire[..size], now, &mut Zero)?;
    assert_eq!(router.snapshot().filter_heap_bytes, 0);
    assert!(matches!(
        router.receive_get(second, &wire[..size], now, &mut Zero),
        Err(Error::Capacity)
    ));
    let mut reply = [0; 256];
    let size = frame(&known, &mut reply)?;
    assert_eq!(
        router.receive_put(supplier, &reply[..size])?,
        ResultState::Duplicate
    );
    let size = frame(&novel, &mut reply)?;
    assert_eq!(
        router.receive_put(supplier, &reply[..size])?,
        ResultState::Retained
    );

    router.cancel(original.path)?;
    let later = now + limits.residence_us;
    router.collect(original.route, later)?;
    raw.fill(0);
    let length = Get {
        bloom: &raw,
        ..request
    }
    .encode(&mut wire)?;
    let replacement = router.receive_get(second, &wire[..length], later, &mut Zero)?;
    assert_ne!(replacement.route, original.route);
    assert_eq!(
        router.receive_put(supplier, &reply[..size])?,
        ResultState::Retained
    );
    Ok(())
}

#[test]
fn paid_get_earns_one_credit_for_its_original_verified_reply() -> Result<(), Error> {
    let (query, block) = signed(1)?;
    let mut instance = gap::Instance::new();
    let mut neighbors = [NeighborSlot::default(); 3];
    let mut storage = [0; 256];
    let mut routes = [RouteSlot::new(&mut storage)];
    let mut paths = [PathSlot::default(); 1];
    let mut output = [0; 256];
    let mut router = Router::new(
        &mut instance,
        &mut neighbors,
        &mut routes,
        &mut paths,
        &mut output,
        gap::Limits::default(),
    )?;
    let sender = router.attach([1; 32])?;
    let return_id = [2; 32];
    let destination = router.attach(return_id)?;
    let respondent = router.attach([3; 32])?;

    let now = 65_537;
    let mut load = gap::load::DatastoreLoad::new();
    load.record(0, now)?;
    let load = load.at(now)?;
    let mut get = [0; 128];
    let count = Get {
        block_type: BlockType::UBLOCK,
        priority: 500,
        ttl_seconds: 100,
        reserved: 0,
        bitmap: RETURN_TO,
        query: &query,
        identities: &return_id,
        bloom: &[],
    }
    .encode(&mut get)?;
    assert!(
        router
            .receive_get_accounted(
                sender,
                &get[..count],
                now,
                &mut Zero,
                gap::GetBudget::new(99, load)
            )?
            .is_none()
    );
    assert!(router.next_lookup().is_none());
    let accepted = router
        .receive_get_accounted(
            sender,
            &get[..count],
            now,
            &mut Zero,
            gap::GetBudget::new(100, load),
        )?
        .ok_or(Error::NotReady)?;
    assert_eq!(accepted.debit, 100);
    assert!(!router.continue_source(accepted.admission.route, load)?);
    let mut bytes = [0; 256];
    let count = frame(&block, &mut bytes)?;
    let result = gap::CheckedPut::decode(&bytes[..count])?;
    let received = router.receive_put_accounted(respondent, result, false, now)?;
    assert_eq!(
        (received.state, received.credit),
        (ResultState::Retained, 100)
    );
    let duplicate = router.receive_put_accounted(respondent, result, false, now)?;
    assert_eq!(
        (duplicate.state, duplicate.credit),
        (ResultState::Duplicate, 0)
    );
    let transmission = router.prepare_reply(accepted.admission.path)?;
    assert_eq!(router.send_bytes(transmission)?.0, destination);
    Ok(())
}

#[test]
fn congested_return_path_uses_original_ingress_in_relay_frame() -> Result<(), Error> {
    let (query, block) = signed(1)?;
    let mut instance = gap::Instance::new();
    let mut neighbors = [NeighborSlot::default(); 4];
    let mut storage = [0; 256];
    let mut routes = [RouteSlot::new(&mut storage)];
    let mut paths = [PathSlot::default()];
    let mut output = [0; 256];
    let mut router = Router::new(
        &mut instance,
        &mut neighbors,
        &mut routes,
        &mut paths,
        &mut output,
        gap::Limits::default(),
    )?;
    let sender_id = [1; 32];
    let return_id = [2; 32];
    let provider = [9; 32];
    let sender = router.attach(sender_id)?;
    let destination = router.attach(return_id)?;
    let onward = router.attach([3; 32])?;
    let spare = router.attach([4; 32])?;
    let now = 3_000_000;
    router.record_handoff(destination, now + 1, now)?;
    router.record_handoff(destination, 0, now)?;
    let mut load = gap::load::DatastoreLoad::new();
    load.record(0, now)?;
    let mut wire = [0; 256];
    let count = Get {
        block_type: BlockType::UBLOCK,
        priority: 100,
        ttl_seconds: 100,
        reserved: 0,
        bitmap: RETURN_TO | TRANSMIT_TO,
        query: &query,
        identities: [return_id, provider].as_flattened(),
        bloom: &[],
    }
    .encode(&mut wire)?;
    let accepted = router
        .receive_get_accounted(
            sender,
            &wire[..count],
            now,
            &mut Zero,
            gap::GetBudget::new(100, load.at(now)?),
        )?
        .ok_or(Error::NotReady)?;
    assert_eq!(accepted.debit, 100);
    let job = router.next_lookup().ok_or(Error::NotReady)?;
    assert_eq!(job.route, accepted.admission.route);
    router.source_finished(job.route, None)?;
    assert_eq!(
        router.query_requirement(job.route, onward)?.class().bytes(),
        GET_PREFIX + 64
    );
    let send = router.prepare_query(job.route, onward, now, &mut Zero)?;
    let outgoing = Get::decode(router.send_bytes(send)?.1)?;
    assert_eq!((outgoing.priority, outgoing.ttl_seconds), (0, -10_000));
    assert_eq!(outgoing.identity(RETURN_TO)?, Some(&sender_id));
    assert_eq!(outgoing.identity(TRANSMIT_TO)?, Some(&provider));
    router.admitted(send)?;
    router.exposed(send)?;
    router.written(send)?;

    let frozen = router.prepare_query(job.route, spare, now, &mut Zero)?;
    assert!(router.relay_origin_current(frozen)?);
    router.retire_neighbor_paths(sender)?;
    assert!(!router.relay_origin_current(frozen)?);
    router.send_failed(frozen)?;
    router.disconnect(sender)?;
    let replacement = router.attach(sender_id)?;
    assert_ne!(replacement, sender);
    assert_eq!(
        router.query_requirement(job.route, spare),
        Err(Error::Closed)
    );
    let size = frame(&block, &mut wire)?;
    let retained = router.receive_put_accounted(
        onward,
        gap::CheckedPut::decode(&wire[..size])?,
        false,
        now,
    )?;
    assert_eq!(
        (retained.state, retained.credit),
        (ResultState::Retained, 0)
    );
    let reply = router.prepare_reply(accepted.admission.path)?;
    assert_eq!(router.send_bytes(reply)?.0, destination);
    Ok(())
}

fn multi_result_groups(anonymity: u32) -> Result<(), Error> {
    let (query, first) = signed(1)?;
    let (_, second) = signed(2)?;
    let mut identity = gap::Instance::new();
    let mut neighbors = [NeighborSlot::default(); 3];
    let mut data = [[0; 256]; 3];
    let mut routes = data.each_mut().map(|bytes| RouteSlot::new(bytes));
    let mut paths = [PathSlot::default(); 3];
    let mut output = [0; 256];
    let mut router = Router::new(
        &mut identity,
        &mut neighbors,
        &mut routes,
        &mut paths,
        &mut output,
        gap::Limits::default(),
    )?;
    let ingress = router.attach([1; 32])?;
    let onward = router.attach([2; 32])?;
    let a = router.start_with_seen(
        Selection::new(BlockType::UBLOCK, query)?,
        101,
        anonymity,
        32,
        60,
        0,
        &[hash512(&first)],
        &mut Zero,
    )?;
    let b = router.start_with_seen(
        Selection::new(BlockType::ANY, query)?,
        102,
        anonymity,
        32,
        60,
        0,
        &[],
        &mut Zero,
    )?;
    let mut query_wire = [0; 128];
    let length = Get {
        block_type: BlockType::UBLOCK,
        priority: 32,
        ttl_seconds: 60,
        reserved: 0,
        bitmap: 0,
        query: &query,
        identities: &[],
        bloom: &[],
    }
    .encode(&mut query_wire)?;
    let c = router.receive_get(ingress, &query_wire[..length], 0, &mut Zero)?;
    let duplicate = router.receive_get(ingress, &query_wire[..length], 0, &mut Zero)?;
    assert_eq!(c.route, duplicate.route);
    for _ in 0..3 {
        let job = router.next_lookup().ok_or(Error::NotReady)?;
        router.source_finished(job.route, None)?;
    }
    assert_eq!(
        router.query_requirement(b.route, onward)?.level(),
        Some(anonymity)
    );
    let tx = router.prepare_query(b.route, onward, 0, &mut Zero)?;
    // Empty optional hints are accepted by the actual C GET check; we never
    // emit its contradictory nonce4+power2 serialized tail as a private format.
    let forwarded = Get::decode(router.send_bytes(tx)?.1)?;
    assert_eq!(forwarded.block_type, BlockType::ANY);
    assert_eq!(*forwarded.query, query);
    assert!(forwarded.bloom.is_empty());
    router.admitted(tx)?;
    router.exposed(tx)?;
    router.written(tx)?;
    let mut one = [0; 256];
    let n1 = frame(&first, &mut one)?;
    assert_eq!(
        router.receive_put(onward, &one[..n1])?,
        ResultState::Retained
    );
    assert!(router.local_result(a.path)?.is_none());
    assert_eq!(
        Put::decode(router.local_result(b.path)?.ok_or(Error::NotReady)?.1)?.block,
        first
    );
    let mut two = [0; 256];
    let n2 = frame(&second, &mut two)?;
    // B and C still own first: no group's seen-state can be partially advanced.
    assert_eq!(
        router.receive_put(onward, &two[..n2]),
        Err(Error::WouldBlock)
    );
    assert!(router.local_result(a.path)?.is_none());
    router.commit_local(b.path)?;
    let reply = router.prepare_reply(c.path)?;
    assert_eq!(router.send_bytes(reply)?.1, &one[..n1]);
    router.admitted(reply)?;
    router.exposed(reply)?;
    router.written(reply)?;
    assert_eq!(
        router.receive_put(onward, &two[..n2])?,
        ResultState::Retained
    );
    assert_eq!(
        Put::decode(router.local_result(a.path)?.ok_or(Error::NotReady)?.1)?.block,
        second
    );
    assert_eq!(
        Put::decode(router.local_result(b.path)?.ok_or(Error::NotReady)?.1)?.block,
        second
    );
    router.commit_local(a.path)?;
    router.commit_local(b.path)?;
    let reply = router.prepare_reply(c.path)?;
    router.admitted(reply)?;
    router.exposed(reply)?;
    router.written(reply)?;
    assert!(!router.retiring(a.route)? && !router.retiring(b.route)? && !router.retiring(c.route)?);
    assert_eq!(
        router.receive_put(onward, &one[..n1])?,
        ResultState::Duplicate
    );
    assert_eq!(
        router.receive_put(onward, &two[..n2])?,
        ResultState::Duplicate
    );
    let mut tampered = two;
    tampered[16] ^= 1;
    assert!(router.receive_put(onward, &tampered[..n2]).is_err());
    assert!(router.local_result(a.path)?.is_none());
    assert!(router.local_result(b.path)?.is_none());
    router.cancel(a.path)?;
    router.cancel(b.path)?;
    router.cancel(c.path)?;
    router.request_shutdown();
    assert!(router.quiesced());
    Ok(())
}
