//! Pure-owner inputs and real path signatures, not native PILS/FIFO receipts.
#![cfg(feature = "alloc")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible cases inspect retained original capabilities and independently verified path bytes"
)]
use gnunet_block::{
    bloom::NativeEndian,
    plugins::{Context, Plugin, Work as BlockWork},
};
use gnunet_crypto::{EddsaPrivateKey, Entropy, hash512};
use gnunet_dht::{
    network::{JobKind, NetworkOwner, Policy, Signed, Work},
    path,
    routing::Estimate,
    service::{BuiltinBlocks, Instance, Limits, LocalOwner, Outcome},
};
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime,
    dht::{GetMessage, Path, PutMessage, ResultMessage, RouteOptions, ipc},
};

struct FixedEntropy;
impl Entropy for FixedEntropy {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        bytes.fill(0);
        Ok(())
    }
}
fn blocks<'a>(scratch: &'a mut [u8]) -> BuiltinBlocks<'static, 'a> {
    BuiltinBlocks {
        context: Context::new(&[Plugin::Test], NativeEndian::native()),
        work: BlockWork {
            hello: scratch,
            hello_limits: gnunet_hello::Limits {
                maximum_input_bytes: 65535,
                maximum_address_bytes: 65535,
                maximum_addresses: 1024,
            },
            hello_profile: gnunet_hello::SignatureProfile::Gnunet029,
            pow: &mut [],
        },
    }
}
fn owner(instance: &mut Instance, identity: [u8; 32]) -> Result<NetworkOwner<'_>, Error> {
    NetworkOwner::new(
        LocalOwner::new(instance, Limits::default())?,
        identity,
        gnunet_dht::network::Limits::default(),
        Policy {
            estimate: Estimate::new(1.0)?,
        },
    )
}
fn local_get(key: &[u8; 64]) -> Result<Vec<u8>, Error> {
    let mut bytes = vec![0; 88];
    ipc::Get {
        options: 0,
        replication: 1,
        block_type: 8,
        key,
        id: ipc::RequestId([1; 8]),
        extended_query: &[],
    }
    .encode(&mut bytes)?;
    Ok(bytes)
}
fn local_put(key: &[u8; 64], payload: &[u8], tracked: bool) -> Result<Vec<u8>, Error> {
    let mut bytes = vec![0; 88 + payload.len()];
    ipc::Put {
        block_type: 8,
        options: if tracked {
            u32::from(RouteOptions::RECORD_ROUTE.bits())
        } else {
            0
        },
        replication: 1,
        expiration: AbsoluteTime::from_micros(10_000),
        key,
        payload,
    }
    .encode(&mut bytes)?;
    Ok(bytes)
}

#[test]
fn rotation_preserves_clients_queries_put_bounds_and_original_signing_retirement()
-> Result<(), Error> {
    let old = EddsaPrivateKey::from_seed([1; 32]);
    let new = EddsaPrivateKey::from_seed([2; 32]);
    let mut instance = Instance::new();
    let mut owner = owner(&mut instance, *old.public_key().as_bytes())?;
    let client = owner.connect_client()?;
    let peer = owner.connect_peer(*EddsaPrivateKey::from_seed([3; 32]).public_key().as_bytes())?;
    let mut scratch = [];
    let mut registry = blocks(&mut scratch);
    let get = local_get(&[7; 64])?;
    let Outcome::Get(query) =
        owner.ingest_client(client, &get, 10, &mut registry, &mut FixedEntropy)?
    else {
        return Err(Error::NotFound);
    };
    owner.ingest_client(
        client,
        &local_put(&[8; 64], b"original tracked intent", true)?,
        10,
        &mut registry,
        &mut FixedEntropy,
    )?;
    let (signing, material, frame_bytes) = owner
        .work()
        .find_map(|work| match work {
            Work::Sign {
                job,
                material,
                frame_bytes,
                ..
            } => Some((job, *material, frame_bytes)),
            _ => None,
        })
        .ok_or(Error::NotFound)?;
    assert!(frame_bytes > material.len());
    let signature = old.sign(path::PURPOSE, &material)?;
    let original = owner.unrouted_puts().next().ok_or(Error::NotFound)?;
    owner.sign_started(signing)?;
    owner.ingest_client(
        client,
        &local_put(&[9; 64], b"already handed off", false)?,
        10,
        &mut registry,
        &mut FixedEntropy,
    )?;
    let submitted = owner
        .work()
        .find_map(|work| match work {
            Work::Send {
                job,
                peer: target,
                kind: JobKind::Put,
                ..
            } if target == peer => Some(job),
            _ => None,
        })
        .ok_or(Error::NotFound)?;
    // Explicit pure caller input: the actual native queue remains the host's
    // responsibility and is not recreated by any later identity observation.
    owner.admitted(submitted, peer)?;
    let before = owner.local_snapshot();
    assert_eq!(
        owner.update_identity(*EddsaPrivateKey::from_seed([3; 32]).public_key().as_bytes()),
        Err(Error::Conflict)
    );
    let refused = owner.job_info(signing).ok_or(Error::NotFound)?;
    assert!(refused.issued && !refused.retiring);
    assert!(!owner.update_identity(*old.public_key().as_bytes())?);
    let same = owner.job_info(signing).ok_or(Error::NotFound)?;
    assert!(same.issued && !same.retiring);
    assert!(owner.update_identity(*new.public_key().as_bytes())?);
    let after = owner.local_snapshot();
    assert_eq!(
        (
            after.clients,
            after.queries,
            after.cache_records,
            after.cache_bytes
        ),
        (
            before.clients,
            before.queries,
            before.cache_records,
            before.cache_bytes
        )
    );
    let retained = owner.unrouted_puts().next().ok_or(Error::NotFound)?;
    assert_eq!(
        (
            retained.put,
            retained.client,
            retained.accepted,
            retained.expiration,
            retained.until
        ),
        (
            original.put,
            original.client,
            original.accepted,
            original.expiration,
            original.until
        )
    );
    assert_eq!(owner.put_stats().retained, 1);
    assert_eq!(owner.put_stats().submitted, 1);
    assert!(!owner.owns_job(submitted));
    let tombstone = owner.job_info(signing).ok_or(Error::NotFound)?;
    assert!(tombstone.issued && tombstone.retiring);
    assert_eq!(tombstone.until, same.until);
    assert_eq!(
        owner.signed(signing, *signature.as_bytes())?,
        Signed::Retired
    );
    assert!(!owner.owns_job(signing));
    assert!(
        matches!(owner.ingest_client(client, &get, 20, &mut registry, &mut FixedEntropy)?,
        Outcome::Duplicate(actual) if actual == query)
    );
    owner.tick(30, &mut registry, &mut FixedEntropy)?;
    let retried = owner.unrouted_puts().next().ok_or(Error::NotFound)?;
    assert_eq!(
        (
            retried.put,
            retried.accepted,
            retried.expiration,
            retried.until
        ),
        (
            original.put,
            original.accepted,
            original.expiration,
            original.until
        )
    );
    assert_eq!(owner.put_stats().submitted, 1);
    assert!(!owner.owns_job(submitted));
    assert!(
        owner
            .work()
            .any(|work| matches!(work, Work::Sign { job, until, .. }
        if job != signing && until <= original.until))
    );
    Ok(())
}

#[test]
fn rotation_truncates_cached_old_recipient_chain_before_real_new_key_signature() -> Result<(), Error>
{
    let old = EddsaPrivateKey::from_seed([1; 32]);
    let new = EddsaPrivateKey::from_seed([2; 32]);
    let sender = EddsaPrivateKey::from_seed([3; 32]);
    let requester = EddsaPrivateKey::from_seed([4; 32]);
    let mut instance = Instance::new();
    let mut owner = owner(&mut instance, *old.public_key().as_bytes())?;
    let sender_peer = owner.connect_peer(*sender.public_key().as_bytes())?;
    let requester_peer = owner.connect_peer(*requester.public_key().as_bytes())?;
    let payload = b"cached across local identity rotation";
    let key = [5; 64];
    let expiration = 10_000;
    let original_signature = sender.sign(
        path::PURPOSE,
        &path::region(
            &hash512(payload),
            expiration,
            &[0; 32],
            old.public_key().as_bytes(),
        ),
    )?;
    let put = PutMessage {
        block_type: 8,
        options: RouteOptions::RECORD_ROUTE | RouteOptions::DEMULTIPLEX_EVERYWHERE,
        hop_count: 1,
        desired_replication_level: 1,
        expiration: AbsoluteTime::from_micros(expiration),
        peer_bloom: &[255; 128],
        key: &key,
        truncated_peer: None,
        put_path: Path::empty(),
        sender_signature: Some(original_signature.as_bytes()),
        payload,
    };
    let mut input = vec![0; put.encoded_len()?];
    put.encode(&mut input)?;
    let mut scratch = [];
    let mut registry = blocks(&mut scratch);
    owner.ingest_peer(sender_peer, &input, 10, &mut registry, &mut FixedEntropy)?;
    assert_eq!(owner.local_snapshot().cache_records, 1);
    let path_bytes = owner.snapshot().cache_path_bytes;
    assert!(path_bytes >= 96);
    assert!(!owner.update_identity(*old.public_key().as_bytes())?);
    assert_eq!(owner.snapshot().cache_path_bytes, path_bytes);
    assert!(owner.update_identity(*new.public_key().as_bytes())?);
    assert_eq!(owner.snapshot().cache_path_bytes, 0);
    assert_eq!(owner.local_snapshot().cache_records, 1);
    let get = GetMessage {
        block_type: 8,
        options: RouteOptions::RECORD_ROUTE,
        hop_count: 0,
        desired_replication_level: 1,
        peer_bloom: &[255; 128],
        key: &key,
        result_filter: &[],
        extended_query: &[],
    };
    let mut request = vec![0; get.encoded_len()?];
    get.encode(&mut request)?;
    owner.ingest_peer(
        requester_peer,
        &request,
        20,
        &mut registry,
        &mut FixedEntropy,
    )?;
    let (job, material, expected_bytes) = owner
        .work()
        .find_map(|work| match work {
            Work::Sign {
                job,
                peer,
                material,
                frame_bytes,
                ..
            } if peer == requester_peer => Some((job, *material, frame_bytes)),
            _ => None,
        })
        .ok_or(Error::NotFound)?;
    assert_eq!(
        material,
        path::region(
            &hash512(payload),
            expiration,
            sender.public_key().as_bytes(),
            requester.public_key().as_bytes()
        )
    );
    let signature = new.sign(path::PURPOSE, &material)?;
    owner.sign_started(job)?;
    assert_eq!(owner.signed(job, *signature.as_bytes())?, Signed::Ready);
    let frame = owner
        .work()
        .find_map(|work| match work {
            Work::Send {
                job: actual, frame, ..
            } if actual == job => Some(frame),
            _ => None,
        })
        .ok_or(Error::NotFound)?;
    assert_eq!(frame.len(), expected_bytes);
    let result = ResultMessage::decode(frame)?;
    assert_eq!(result.key, &key);
    assert_eq!(result.payload, payload);
    assert_eq!(result.expiration.as_micros(), expiration);
    assert!(result.options.contains(RouteOptions::TRUNCATED));
    assert!(result.put_path.is_empty() && result.get_path.is_empty());
    assert_eq!(result.truncated_peer, Some(sender.public_key().as_bytes()));
    path::verify_incoming(
        result.payload,
        expiration,
        20,
        result.truncated_peer,
        result.put_path,
        result.get_path,
        new.public_key().as_bytes(),
        requester.public_key().as_bytes(),
        result.sender_signature.ok_or(Error::NotFound)?,
    )?;
    Ok(())
}
