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
    fs_gap::{Get, Put},
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
fn nonanonymous_ublock_keeps_original_seen_group_and_verified_multi_results() -> Result<(), Error> {
    multi_result_groups(0)
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
        Selection {
            kind: BlockType::UBLOCK,
            query,
        },
        101,
        anonymity,
        32,
        60,
        0,
        &[hash512(&first)],
        &mut Zero,
    )?;
    let b = router.start_with_seen(
        Selection {
            kind: BlockType::ANY,
            query,
        },
        102,
        1,
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
    let tx = router.prepare_query(b.route, onward, 0, &mut Zero)?;
    // Empty optional hints are accepted by the actual C GET check; we never
    // emit its contradictory nonce4+power2 serialized tail as a private format.
    assert!(Get::decode(router.send_bytes(tx)?.1)?.bloom.is_empty());
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
