//! Unexecuted owner source cases. The port controls validation outcomes;
//! these are not signature, crypto, native-PILS or C interoperability evidence.
#![cfg(feature = "alloc")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions inspect fallible original owner transitions"
)]
use gnunet_block::{
    BlockType, ReplyEvaluation,
    bloom::{BloomGroup, NativeEndian},
};
use gnunet_crypto::Entropy;
use gnunet_dht::{
    network::{Filter, JobKind, NetworkBlocks, NetworkOwner, Policy, Work},
    routing::{Estimate, peer_key},
    service::{Blocks, Instance, Limits, LocalOwner, TypeCapability, Validity},
};
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime,
    dht::{GetMessage, ResultMessage, RouteOptions, ipc},
};

struct Registry {
    valid: bool,
    known: Option<[u8; 64]>,
}
impl Blocks for Registry {
    fn type_capability(&self, kind: u32) -> Result<TypeCapability, Error> {
        Ok(if kind == 13 {
            TypeCapability::Installed
        } else {
            TypeCapability::Absent
        })
    }
    fn query(&mut self, kind: u32, _: &[u8; 64], xquery: &[u8]) -> Result<(), Error> {
        if kind == 13 && xquery.is_empty() {
            Ok(())
        } else {
            Err(Error::Unsupported)
        }
    }
    fn validate(
        &mut self,
        kind: u32,
        key: &[u8; 64],
        payload: &[u8],
        now: u64,
    ) -> Result<Validity, Error> {
        Ok(
            if self.valid
                && kind == 13
                && payload.len() == 104
                && *key == peer_key(payload[..32].try_into().map_err(|_| Error::Truncated)?)
                && AbsoluteTime::decode(&payload[96..])?.as_micros() >= now
            {
                Validity::Valid
            } else {
                Validity::Invalid
            },
        )
    }
    fn reply(
        &mut self,
        requested: u32,
        _: &[u8; 64],
        _: &[u8],
        kind: u32,
        _: &[u8],
        _: u64,
    ) -> Result<ReplyEvaluation, Error> {
        if matches!(requested, 0 | 13) && kind == 13 {
            Ok(ReplyEvaluation::More)
        } else {
            Err(Error::Unsupported)
        }
    }
}
impl NetworkBlocks for Registry {
    fn derive_key(&mut self, kind: u32, payload: &[u8], _: u64) -> Result<Option<[u8; 64]>, Error> {
        if kind != 13 {
            return Err(Error::Unsupported);
        }
        Ok(Some(peer_key(
            payload
                .get(..32)
                .ok_or(Error::Truncated)?
                .try_into()
                .map_err(|_| Error::Truncated)?,
        )))
    }
    fn filter(
        &mut self,
        kind: u32,
        raw: Option<&[u8]>,
        size: usize,
        nonce: u32,
        profile: NativeEndian,
    ) -> Result<Filter, Error> {
        let mut bytes = vec![0; size];
        let mut group = BloomGroup::new(&mut bytes, BlockType(kind), 16, raw, nonce, profile)?;
        // The selected port supplies this already-known state. This case does
        // not assert a native serialized-filter sizing profile.
        if let Some(key) = self.known {
            group.test_and_set(&key);
        }
        Filter::from_group(kind, profile, Some(group))
    }
    fn filtered_reply(
        &mut self,
        requested: u32,
        key: &[u8; 64],
        xquery: &[u8],
        kind: u32,
        payload: &[u8],
        now: u64,
        filter: &mut Filter,
    ) -> Result<ReplyEvaluation, Error> {
        let result = self.reply(requested, key, xquery, kind, payload, now)?;
        if let Some(mut group) = filter.bloom()?
            && group.test_and_set(key)
        {
            Ok(ReplyEvaluation::Duplicate)
        } else {
            Ok(result)
        }
    }
}
struct FixedEntropy;
impl Entropy for FixedEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
        output.fill(0);
        Ok(())
    }
}
fn hello(peer: [u8; 32], expiration: u64) -> [u8; 104] {
    let mut bytes = [0; 104];
    bytes[..32].copy_from_slice(&peer);
    bytes[96..].copy_from_slice(&expiration.to_be_bytes());
    bytes
}
fn owner(instance: &mut Instance) -> Result<NetworkOwner<'_>, Error> {
    NetworkOwner::new(
        LocalOwner::new(
            instance,
            Limits {
                cache_records: 1,
                cache_bytes: 104,
                approximate_keys: 1,
                block_bytes: 104,
                ..Limits::default()
            },
        )?,
        [1; 32],
        gnunet_dht::network::Limits::default(),
        Policy {
            estimate: Estimate::new(1.0)?,
        },
    )
}
fn get(kind: u32, key: &[u8; 64], filter: &[u8]) -> Result<Vec<u8>, Error> {
    let message = GetMessage {
        block_type: kind,
        options: RouteOptions::DEMULTIPLEX_EVERYWHERE | RouteOptions::FIND_APPROXIMATE,
        hop_count: 1,
        desired_replication_level: 1,
        peer_bloom: &[0; 128],
        key,
        result_filter: filter,
        extended_query: &[],
    };
    let mut wire = vec![0; message.encoded_len()?];
    message.encode(&mut wire)?;
    Ok(wire)
}
#[test]
fn full_cache_and_nearest_key_cannot_hide_newest_own_hello() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut owner = owner(&mut instance)?;
    let peer = owner.connect_peer([2; 32])?;
    let mut blocks = Registry {
        valid: true,
        known: None,
    };
    let foreign = hello([3; 32], 5_000);
    owner.observe_hello(&foreign, 10, &mut blocks)?;
    let old = hello([1; 32], 1_000);
    owner.observe_local_hello(&old, 10, &mut blocks)?;
    let latest = hello([1; 32], 2_000);
    owner.observe_local_hello(&latest, 20, &mut blocks)?;
    assert_eq!(owner.local_snapshot().cache_records, 1);
    assert_eq!(owner.local_snapshot().cache_bytes, 104);
    assert_eq!(owner.local_snapshot().own_hello_bytes, 104);
    let target = peer_key(&[3; 32]);
    owner.ingest_peer(
        peer,
        &get(13, &target, &[])?,
        20,
        &mut blocks,
        &mut FixedEntropy,
    )?;
    let mut own = 0;
    let mut other = 0;
    for work in owner.work() {
        if let Work::Send {
            kind: JobKind::Result,
            frame,
            until,
            ..
        } = work
        {
            let result = ResultMessage::decode(frame)?;
            assert_eq!(result.key, &target);
            if result.payload == latest {
                own += 1;
                assert_eq!(until, 2_000);
            }
            if result.payload == foreign {
                other += 1;
            }
        }
    }
    assert_eq!((own, other), (1, 1));
    // A false validation result cannot replace the retained genuine candidate.
    blocks.valid = false;
    assert_eq!(
        owner.observe_local_hello(&hello([1; 32], 3_000), 20, &mut blocks),
        Err(Error::Authentication)
    );
    blocks.valid = true;
    // An actual source may publish a changed announcement with a shorter
    // validity bound; that is still the latest local observation.
    let mut changed = hello([1; 32], 1_000);
    changed[32] = 9;
    owner.observe_local_hello(&changed, 20, &mut blocks)?;
    changed[32] = 10;
    owner.observe_local_hello(&changed, 20, &mut blocks)?;
    assert_eq!(
        owner.observe_local_hello(&foreign, 20, &mut blocks),
        Err(Error::Authentication)
    );
    // A later remote replay cannot overwrite it, even with longer expiration.
    assert_eq!(
        owner.observe_hello(&latest, 20, &mut blocks),
        Err(Error::Capacity)
    );
    let client = owner.connect_client()?;
    let key = peer_key(&[1; 32]);
    let message = ipc::Get {
        options: 0,
        replication: 1,
        block_type: 13,
        key: &key,
        id: ipc::RequestId([7; 8]),
        extended_query: &[],
    };
    let mut wire = [0; 88];
    message.encode(&mut wire)?;
    owner.ingest_client(client, &wire, 20, &mut blocks, &mut FixedEntropy)?;
    let output = owner.take_output().ok_or(Error::NotFound)?;
    assert_eq!(
        ipc::ResultMessage::decode(output.bytes())?.payload,
        &changed
    );
    owner.tick(1_001, &mut blocks, &mut FixedEntropy)?;
    assert_eq!(owner.local_snapshot().own_hello_bytes, 0);
    assert_eq!(owner.local_snapshot().cache_records, 1);
    owner.close();
    assert_eq!(owner.local_snapshot().own_hello_bytes, 0);
    Ok(())
}
#[test]
fn original_hello_group_filters_self_and_any_uses_same_response_path() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut owner = owner(&mut instance)?;
    let peer = owner.connect_peer([2; 32])?;
    let mut blocks = Registry {
        valid: true,
        known: None,
    };
    owner.observe_local_hello(&hello([1; 32], 2_000), 20, &mut blocks)?;
    let own_key = peer_key(&[1; 32]);
    let target = [0; 64];
    blocks.known = Some(own_key);
    owner.ingest_peer(
        peer,
        &get(13, &target, &[])?,
        20,
        &mut blocks,
        &mut FixedEntropy,
    )?;
    assert!(!owner.work().any(|w| matches!(
        w,
        Work::Send {
            kind: JobKind::Result,
            ..
        }
    )));
    owner.ingest_peer(
        peer,
        &get(0, &target, &[])?,
        20,
        &mut blocks,
        &mut FixedEntropy,
    )?;
    assert!(owner.work().any(|w| matches!(
        w,
        Work::Send {
            kind: JobKind::Result,
            ..
        }
    )));
    assert_eq!(owner.local_snapshot().cache_records, 0);
    owner.close();
    assert_eq!(owner.local_snapshot().own_hello_bytes, 0);
    Ok(())
}
