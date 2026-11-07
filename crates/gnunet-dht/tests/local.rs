//! Original local operations and real BLOCK/cache boundaries.
#![cfg(feature = "alloc")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify fallible protocol transitions"
)]
use gnunet_block::{
    bloom::NativeEndian,
    plugins::{Context, Plugin, Work},
};
use gnunet_crypto::EddsaPrivateKey;
use gnunet_dht::service::{BuiltinBlocks, Instance, Limits, LocalOwner};
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime,
    dht::ipc::{Get, Hashes, Known, Monitor, Put, RequestId},
};
fn blocks<'a>(hello: &'a mut [u8]) -> BuiltinBlocks<'static, 'a> {
    BuiltinBlocks {
        context: Context::new(&[Plugin::Test], NativeEndian::native()),
        work: Work {
            hello,
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
fn get(key: &[u8; 64], id: u8, kind: u32) -> Result<Vec<u8>, Error> {
    let mut out = vec![0; 88];
    Get {
        options: 0,
        replication: 1,
        block_type: kind,
        key,
        id: RequestId([id; 8]),
        extended_query: &[],
    }
    .encode(&mut out)?;
    Ok(out)
}
fn put(key: &[u8; 64], payload: &[u8], expiration: u64, kind: u32) -> Result<Vec<u8>, Error> {
    let mut out = vec![0; 88 + payload.len()];
    Put {
        block_type: kind,
        options: 0,
        replication: 1,
        expiration: AbsoluteTime::from_micros(expiration),
        key,
        payload,
    }
    .encode(&mut out)?;
    Ok(out)
}
#[test]
fn known_duplicate_hashes_use_one_original_seen_slot() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut owner = LocalOwner::new(
        &mut instance,
        Limits {
            seen_hashes: 1,
            ..Limits::default()
        },
    )?;
    let c = owner.connect()?;
    let key = [1; 64];
    let mut scratch = [];
    let mut b = blocks(&mut scratch);
    owner.ingest(c, &get(&key, 1, 8)?, 0, &mut b)?;
    let hash = gnunet_crypto::hash512(b"known");
    let mut hashes = [0; 128];
    hashes[..64].copy_from_slice(&hash);
    hashes[64..].copy_from_slice(&hash);
    let known = Known {
        key: &key,
        id: RequestId([1; 8]),
        hashes: Hashes::new(&hashes)?,
    };
    let mut wire = vec![0; known.encoded_len()?];
    known.encode(&mut wire)?;
    owner.ingest(c, &wire, 0, &mut b)?;
    owner.ingest(c, &put(&key, b"known", 100, 8)?, 0, &mut b)?;
    assert!(owner.take_output().is_none());
    Ok(())
}
#[test]
fn local_put_without_get_does_not_invent_a_get_result_event() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut owner = LocalOwner::new(&mut instance, Limits::default())?;
    let c = owner.connect()?;
    let monitor = owner.connect()?;
    let key = [2; 64];
    let mut scratch = [];
    let mut b = blocks(&mut scratch);
    let mut wire = [0; 80];
    Monitor {
        block_type: 8,
        get: 0,
        get_response: 1,
        put: 1,
        key: None,
    }
    .encode(false, &mut wire)?;
    owner.ingest(monitor, &wire, 0, &mut b)?;
    owner.ingest(c, &put(&key, b"data", 100, 8)?, 0, &mut b)?;
    let output = owner.take_output().ok_or(Error::NotFound)?;
    assert_eq!(output.client(), monitor);
    assert_eq!(&output.bytes()[2..4], &151u16.to_be_bytes());
    assert!(owner.take_output().is_none());
    Ok(())
}
#[test]
fn expired_intrinsic_block_is_filtered_without_rejecting_new_query() -> Result<(), Error> {
    let key = EddsaPrivateKey::from_seed([9; 32]);
    let mut dns = [0; 112];
    dns[64..68].copy_from_slice(&48u32.to_be_bytes());
    dns[68..72].copy_from_slice(&11u32.to_be_bytes());
    dns[72..80].copy_from_slice(&10u64.to_be_bytes());
    dns[80..].copy_from_slice(key.public_key().as_bytes());
    let sig = key.sign(11, &dns[64..])?;
    dns[..64].copy_from_slice(sig.as_bytes());
    let mut instance = Instance::new();
    let mut owner = LocalOwner::new(&mut instance, Limits::default())?;
    let c = owner.connect()?;
    let hash = [7; 64];
    let mut scratch = [];
    let mut b = blocks(&mut scratch);
    b.context = Context::new(&[Plugin::Dns], NativeEndian::native());
    owner.ingest(c, &put(&hash, &dns, 100, 10)?, 0, &mut b)?;
    owner.ingest(c, &get(&hash, 2, 10)?, 11, &mut b)?;
    assert_eq!(owner.snapshot().queries, 1);
    assert!(owner.take_output().is_none());
    Ok(())
}

#[test]
fn real_put_get_result_and_publisher_disconnect() -> Result<(), Error> {
    use gnunet_wire::official::dht::ipc::ResultMessage;
    let mut i = Instance::new();
    let mut o = LocalOwner::new(&mut i, Limits::default())?;
    let publisher = o.connect()?;
    let key = [3; 64];
    let mut scratch = [];
    let mut b = blocks(&mut scratch);
    o.ingest(publisher, &put(&key, b"value", 100, 8)?, 0, &mut b)?;
    assert!(o.take_output().is_none());
    o.disconnect(publisher)?;
    let c = o.connect()?;
    o.ingest(c, &get(&key, 9, 8)?, 1, &mut b)?;
    let frame = o.take_output().ok_or(Error::NotFound)?;
    let result = ResultMessage::decode(frame.bytes())?;
    assert_eq!(frame.client(), c);
    assert_eq!(result.id, RequestId([9; 8]));
    assert_eq!(result.key, &key);
    assert_eq!(result.payload, b"value");
    assert_eq!(o.snapshot().cache_records, 1);
    Ok(())
}
#[test]
fn stop_and_known_are_confined_to_original_client_and_key() -> Result<(), Error> {
    use gnunet_wire::official::dht::ipc::Stop;
    let mut i = Instance::new();
    let mut o = LocalOwner::new(&mut i, Limits::default())?;
    let a = o.connect()?;
    let c = o.connect()?;
    let key = [4; 64];
    let mut scratch = [];
    let mut b = blocks(&mut scratch);
    o.ingest(a, &get(&key, 1, 8)?, 0, &mut b)?;
    o.ingest(c, &get(&key, 1, 8)?, 0, &mut b)?;
    let h = gnunet_crypto::hash512(b"first");
    let known = Known {
        key: &key,
        id: RequestId([1; 8]),
        hashes: Hashes::new(&h)?,
    };
    let mut wire = vec![0; 144];
    known.encode(&mut wire)?;
    o.ingest(a, &wire, 0, &mut b)?;
    o.ingest(c, &put(&key, b"first", 100, 8)?, 0, &mut b)?;
    assert_eq!(o.take_output().ok_or(Error::NotFound)?.client(), c);
    assert!(o.take_output().is_none());
    let mut wire = [0; 80];
    Stop {
        id: RequestId([1; 8]),
        key: &key,
    }
    .encode(&mut wire)?;
    o.ingest(a, &wire, 0, &mut b)?;
    assert_eq!(o.snapshot().queries, 1);
    o.ingest(c, &put(&key, b"second", 100, 8)?, 0, &mut b)?;
    assert_eq!(o.take_output().ok_or(Error::NotFound)?.client(), c);
    assert!(o.take_output().is_none());
    Ok(())
}
#[test]
fn reconnect_and_transferred_output_do_not_acquire_new_mq_authority() -> Result<(), Error> {
    let mut i = Instance::new();
    let mut o = LocalOwner::new(&mut i, Limits::default())?;
    let old = o.connect()?;
    let key = [5; 64];
    let mut scratch = [];
    let mut b = blocks(&mut scratch);
    o.ingest(old, &put(&key, b"x", 100, 8)?, 0, &mut b)?;
    o.ingest(old, &get(&key, 1, 8)?, 0, &mut b)?;
    let output = o.take_output().ok_or(Error::NotFound)?;
    o.disconnect(old)?;
    let new = o.connect()?;
    assert_ne!(old, new);
    assert_eq!(output.client(), old);
    let before = o.snapshot();
    assert_eq!(
        o.ingest(old, &get(&key, 1, 8)?, 0, &mut b),
        Err(Error::Stale)
    );
    assert_eq!(o.snapshot(), before);
    o.ingest(new, &get(&key, 1, 8)?, 0, &mut b)?;
    assert_eq!(o.take_output().ok_or(Error::NotFound)?.client(), new);
    Ok(())
}
#[test]
fn foreign_brand_cannot_modify_an_owner() -> Result<(), Error> {
    let mut a = Instance::new();
    let mut c = Instance::new();
    let mut x = LocalOwner::new(&mut a, Limits::default())?;
    let mut y = LocalOwner::new(&mut c, Limits::default())?;
    let foreign = x.connect()?;
    let local = y.connect()?;
    assert_eq!(foreign.diagnostic(), local.diagnostic());
    let mut scratch = [];
    let mut b = blocks(&mut scratch);
    let before = y.snapshot();
    assert_eq!(
        y.ingest(foreign, &get(&[0; 64], 1, 8)?, 0, &mut b),
        Err(Error::InvalidInput)
    );
    assert_eq!(y.snapshot(), before);
    Ok(())
}
#[test]
fn atomic_fanout_capacity_does_not_partially_publish_or_mark_seen() -> Result<(), Error> {
    let mut i = Instance::new();
    let mut o = LocalOwner::new(
        &mut i,
        Limits {
            output_frames: 1,
            ..Limits::default()
        },
    )?;
    let a = o.connect()?;
    let c = o.connect()?;
    let key = [6; 64];
    let mut scratch = [];
    let mut b = blocks(&mut scratch);
    o.ingest(a, &get(&key, 1, 8)?, 0, &mut b)?;
    o.ingest(c, &get(&key, 2, 8)?, 0, &mut b)?;
    let before = o.snapshot();
    assert_eq!(
        o.ingest(a, &put(&key, b"payload", 100, 8)?, 0, &mut b),
        Err(Error::Capacity)
    );
    assert_eq!(o.snapshot(), before);
    assert!(o.take_output().is_none());
    o.disconnect(c)?;
    o.ingest(a, &put(&key, b"payload", 100, 8)?, 0, &mut b)?;
    assert_eq!(o.snapshot().cache_records, 1);
    assert_eq!(o.take_output().ok_or(Error::NotFound)?.client(), a);
    Ok(())
}
#[test]
fn duplicate_get_is_idempotent_but_conflicting_replacement_is_refused() -> Result<(), Error> {
    use gnunet_dht::service::Outcome;
    let mut i = Instance::new();
    let mut o = LocalOwner::new(&mut i, Limits::default())?;
    let c = o.connect()?;
    let key = [7; 64];
    let mut scratch = [];
    let mut b = blocks(&mut scratch);
    let wire = get(&key, 1, 8)?;
    let Outcome::Get(token) = o.ingest(c, &wire, 0, &mut b)? else {
        return Err(Error::InvalidInput);
    };
    assert_eq!(o.ingest(c, &wire, 0, &mut b)?, Outcome::Duplicate(token));
    let mut changed = wire;
    changed[11] = 2;
    assert_eq!(o.ingest(c, &changed, 0, &mut b), Err(Error::Conflict));
    assert_eq!(o.snapshot().queries, 1);
    Ok(())
}
#[test]
fn duplicate_cache_expiry_is_maximum_and_time_does_not_resurrect_evicted_data() -> Result<(), Error>
{
    use gnunet_wire::official::dht::ipc::ResultMessage;
    let mut i = Instance::new();
    let mut o = LocalOwner::new(&mut i, Limits::default())?;
    let c = o.connect()?;
    let key = [8; 64];
    let mut scratch = [];
    let mut b = blocks(&mut scratch);
    o.ingest(c, &put(&key, b"x", 100, 8)?, 0, &mut b)?;
    o.ingest(c, &put(&key, b"x", 50, 8)?, 0, &mut b)?;
    assert_eq!(o.snapshot().cache_records, 1);
    o.ingest(c, &get(&key, 1, 8)?, 100, &mut b)?;
    let f = o.take_output().ok_or(Error::NotFound)?;
    assert_eq!(
        ResultMessage::decode(f.bytes())?.expiration.as_micros(),
        100
    );
    o.tick(101)?;
    assert_eq!(o.snapshot().cache_records, 0);
    o.tick(99)?;
    o.ingest(c, &get(&key, 2, 8)?, 99, &mut b)?;
    assert!(o.take_output().is_none());
    Ok(())
}
#[test]
fn opaque_unknown_traffic_is_distinct_from_validated_cache_and_installed_invalid_data()
-> Result<(), Error> {
    let mut i = Instance::new();
    let mut o = LocalOwner::new(&mut i, Limits::default())?;
    let c = o.connect()?;
    let mut scratch = [];
    let mut b = blocks(&mut scratch);
    let before = o.snapshot();
    assert_eq!(
        o.ingest(c, &put(&[0; 64], b"x", 100, 9999)?, 0, &mut b),
        Ok(gnunet_dht::service::Outcome::OpaquePut)
    );
    // Missing validation support permits an opaque transport intent, never a
    // trusted cache entry or an invented local GET result.
    assert_eq!(o.snapshot(), before);
    assert!(o.take_output().is_none());
    assert_eq!(
        gnunet_dht::service::Blocks::query(&mut b, 9999, &[0; 64], &[]),
        Err(Error::Unsupported)
    );
    assert!(matches!(
        o.ingest(c, &get(&[0; 64], 71, 9999)?, 0, &mut b)?,
        gnunet_dht::service::Outcome::Get(_)
    ));
    assert_eq!(o.snapshot().queries, before.queries + 1);
    assert_eq!(o.snapshot().cache_records, before.cache_records);
    assert!(o.take_output().is_none());
    let before_invalid = o.snapshot();
    b.context = Context::new(&[Plugin::Fs], NativeEndian::native());
    assert_eq!(
        o.ingest(c, &put(&[0; 64], b"x", 100, 1)?, 0, &mut b),
        Err(Error::Authentication)
    );
    assert_eq!(o.snapshot(), before_invalid);
    Ok(())
}
#[test]
fn concrete_last_and_any_query_have_different_lifetimes() -> Result<(), Error> {
    use gnunet_wire::official::dht::ipc::ResultMessage;
    let mut i = Instance::new();
    let mut o = LocalOwner::new(&mut i, Limits::default())?;
    let c = o.connect()?;
    let mut scratch = [];
    let mut b = blocks(&mut scratch);
    b.context = Context::new(&[Plugin::Fs, Plugin::Test], NativeEndian::native());
    let key = gnunet_crypto::hash512(b"fs");
    o.ingest(c, &put(&key, b"fs", 100, 1)?, 0, &mut b)?;
    o.ingest(c, &put(&key, b"test", 100, 8)?, 0, &mut b)?;
    o.ingest(c, &get(&key, 1, 0)?, 0, &mut b)?;
    let mut types = Vec::new();
    while let Some(f) = o.take_output() {
        types.push(ResultMessage::decode(f.bytes())?.block_type);
    }
    types.sort_unstable();
    assert_eq!(types, vec![1, 8]);
    assert_eq!(o.snapshot().queries, 1);
    o.ingest(c, &get(&key, 2, 1)?, 0, &mut b)?;
    assert_eq!(o.snapshot().queries, 1);
    assert_eq!(
        ResultMessage::decode(o.take_output().ok_or(Error::NotFound)?.bytes())?.block_type,
        1
    );
    Ok(())
}
#[test]
fn approximate_lookup_considers_four_nearest_keys() -> Result<(), Error> {
    use gnunet_wire::official::dht::ipc::ResultMessage;
    let mut i = Instance::new();
    let mut o = LocalOwner::new(&mut i, Limits::default())?;
    let c = o.connect()?;
    let mut scratch = [];
    let mut b = blocks(&mut scratch);
    for n in 1..=6 {
        let mut key = [0; 64];
        key[63] = n;
        o.ingest(c, &put(&key, &[n], 100, 8)?, 0, &mut b)?;
    }
    let zero = [0; 64];
    let mut wire = get(&zero, 1, 8)?;
    wire[7] = 4;
    o.ingest(c, &wire, 0, &mut b)?;
    let mut values = Vec::new();
    while let Some(f) = o.take_output() {
        let r = ResultMessage::decode(f.bytes())?;
        assert_eq!(r.key, &zero);
        values.push(r.payload[0]);
    }
    values.sort_unstable();
    assert_eq!(values, vec![1, 2, 3, 4]);
    Ok(())
}
#[test]
fn duplicate_monitors_notify_once_and_stop_removes_one_exact_registration() -> Result<(), Error> {
    let mut i = Instance::new();
    let mut o = LocalOwner::new(&mut i, Limits::default())?;
    let c = o.connect()?;
    let m = o.connect()?;
    let key = [0; 64];
    let mut scratch = [];
    let mut b = blocks(&mut scratch);
    let monitor = Monitor {
        block_type: 8,
        get: 0,
        get_response: 0,
        put: 1,
        key: Some(&key),
    };
    let mut wire = [0; 80];
    monitor.encode(false, &mut wire)?;
    o.ingest(m, &wire, 0, &mut b)?;
    o.ingest(m, &wire, 0, &mut b)?;
    o.ingest(c, &put(&[1; 64], b"no", 100, 8)?, 0, &mut b)?;
    assert!(o.take_output().is_none());
    o.ingest(c, &put(&key, b"yes", 100, 8)?, 0, &mut b)?;
    assert_eq!(o.take_output().ok_or(Error::NotFound)?.client(), m);
    assert!(o.take_output().is_none());
    monitor.encode(true, &mut wire)?;
    o.ingest(m, &wire, 0, &mut b)?;
    assert_eq!(o.snapshot().monitors, 1);
    o.ingest(c, &put(&key, b"second", 100, 8)?, 0, &mut b)?;
    assert_eq!(o.take_output().ok_or(Error::NotFound)?.client(), m);
    assert!(o.take_output().is_none());
    Ok(())
}
#[test]
fn real_hello_scratch_resource_failure_is_not_invalid_data_or_success() -> Result<(), Error> {
    use gnunet_block::BlockType;
    let hello = include_bytes!("../../gnunet-hello/tests/fixtures/normal.block");
    let mut scratch = [0; 1024];
    let mut b = blocks(&mut scratch);
    b.context = Context::new(&[Plugin::Dht], NativeEndian::native());
    let mut clock = || 0;
    let key = b
        .context
        .get_key(BlockType::DHT_HELLO, hello, &mut b.work, &mut clock)?
        .key
        .ok_or(Error::InvalidInput)?;
    let mut i = Instance::new();
    let mut o = LocalOwner::new(&mut i, Limits::default())?;
    let c = o.connect()?;
    o.ingest(c, &put(&key, hello, 100, 13)?, 0, &mut b)?;
    b.work.hello = &mut [];
    let before = o.snapshot();
    assert_eq!(
        o.ingest(c, &get(&key, 1, 13)?, 0, &mut b),
        Err(Error::Capacity)
    );
    assert_eq!(o.snapshot(), before);
    assert!(o.take_output().is_none());
    Ok(())
}
#[test]
fn close_releases_only_memory_and_refuses_reused_capabilities() -> Result<(), Error> {
    let mut i = Instance::new();
    let mut o = LocalOwner::new(&mut i, Limits::default())?;
    let c = o.connect()?;
    let mut scratch = [];
    let mut b = blocks(&mut scratch);
    o.ingest(c, &put(&[0; 64], b"x", 100, 8)?, 0, &mut b)?;
    o.close();
    let s = o.snapshot();
    assert!(s.closed);
    assert_eq!(
        (
            s.clients,
            s.queries,
            s.cache_records,
            s.cache_bytes,
            s.output_frames,
            s.output_bytes
        ),
        (0, 0, 0, 0, 0, 0)
    );
    assert_eq!(o.connect(), Err(Error::Closed));
    assert_eq!(
        o.ingest(c, &get(&[0; 64], 1, 8)?, 0, &mut b),
        Err(Error::Closed)
    );
    Ok(())
}
#[test]
fn result_larger_than_wire_limit_cannot_partially_commit_query_or_other_frames() -> Result<(), Error>
{
    let mut i = Instance::new();
    let mut o = LocalOwner::new(&mut i, Limits::default())?;
    let c = o.connect()?;
    let key = [11; 64];
    let payload = vec![0; 65440];
    let mut scratch = [];
    let mut b = blocks(&mut scratch);
    o.ingest(c, &put(&key, &payload, 100, 8)?, 0, &mut b)?;
    let before = o.snapshot();
    assert_eq!(
        o.ingest(c, &get(&key, 1, 8)?, 0, &mut b),
        Err(Error::TooLarge)
    );
    assert_eq!(o.snapshot(), before);
    assert!(o.take_output().is_none());
    Ok(())
}

#[test]
fn local_put_cannot_invent_a_truncated_route_predecessor() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut o = LocalOwner::new(&mut instance, Limits::default())?;
    let c = o.connect()?;
    let mut work = [0; 1024];
    let mut b = blocks(&mut work);
    let mut frame = put(&[1; 64], b"payload", 100, 8)?;
    frame[8..12].copy_from_slice(&8u32.to_be_bytes());
    let before = o.snapshot();
    assert_eq!(o.ingest(c, &frame, 0, &mut b), Err(Error::Unsupported));
    assert_eq!(o.snapshot(), before);
    Ok(())
}

#[test]
fn approximate_filtering_does_not_expand_the_original_nearest_key_set() -> Result<(), Error> {
    use gnunet_block::ReplyEvaluation;
    use gnunet_dht::service::{Blocks, Validity};
    struct Filter<'a>(BuiltinBlocks<'static, 'a>);
    impl Blocks for Filter<'_> {
        fn type_capability(&self, kind: u32) -> Result<gnunet_dht::service::TypeCapability, Error> {
            Blocks::type_capability(&self.0, kind)
        }

        fn query(&mut self, k: u32, q: &[u8; 64], x: &[u8]) -> Result<(), Error> {
            self.0.query(k, q, x)
        }
        fn validate(&mut self, k: u32, q: &[u8; 64], p: &[u8], t: u64) -> Result<Validity, Error> {
            self.0.validate(k, q, p, t)
        }
        fn reply(
            &mut self,
            r: u32,
            q: &[u8; 64],
            x: &[u8],
            k: u32,
            p: &[u8],
            t: u64,
        ) -> Result<ReplyEvaluation, Error> {
            let actual = self.0.reply(r, q, x, k, p, t)?;
            Ok(if p[0] <= 4 {
                ReplyEvaluation::Irrelevant
            } else {
                actual
            })
        }
    }
    let mut i = Instance::new();
    let mut o = LocalOwner::new(&mut i, Limits::default())?;
    let c = o.connect()?;
    let mut scratch = [];
    let mut b = Filter(blocks(&mut scratch));
    for n in 1..=6 {
        let mut key = [0; 64];
        key[63] = n;
        o.ingest(c, &put(&key, &[n], 100, 8)?, 0, &mut b)?;
    }
    let mut frame = get(&[0; 64], 1, 8)?;
    frame[7] = 4;
    o.ingest(c, &frame, 0, &mut b)?;
    assert!(o.take_output().is_none());
    assert_eq!(o.snapshot().queries, 1);
    Ok(())
}

#[test]
fn zero_opaque_correlation_gets_original_cached_result() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut owner = LocalOwner::new(&mut instance, Limits::default())?;
    let publisher = owner.connect()?;
    let subscriber = owner.connect()?;
    let key = [0x41; 64];
    let mut scratch = [];
    let mut b = blocks(&mut scratch);
    owner.ingest(publisher, &put(&key, b"cached-zero-id", 100, 8)?, 0, &mut b)?;
    owner.ingest(subscriber, &get(&key, 0, 8)?, 0, &mut b)?;
    let output = owner.take_output();
    assert!(
        output.is_some(),
        "accepted zero opaque GET ID must receive its cached result"
    );
    let output = output.ok_or(Error::NotFound)?;
    assert_eq!(output.client(), subscriber);
    let result = gnunet_wire::official::dht::ipc::ResultMessage::decode(output.bytes())?;
    assert_eq!(result.id, RequestId([0; 8]));
    assert_eq!(result.key, &key);
    assert_eq!(result.payload, b"cached-zero-id");
    assert!(owner.take_output().is_none());
    Ok(())
}
#[test]
fn zero_opaque_correlation_later_result_and_stop_stay_on_original_mq() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut owner = LocalOwner::new(&mut instance, Limits::default())?;
    let a = owner.connect()?;
    let b_client = owner.connect()?;
    let publisher = owner.connect()?;
    let key = [0x42; 64];
    let mut scratch = [];
    let mut b = blocks(&mut scratch);
    owner.ingest(a, &get(&key, 0, 8)?, 0, &mut b)?;
    owner.ingest(b_client, &get(&key, 0, 8)?, 0, &mut b)?;
    owner.ingest(publisher, &put(&key, b"first-zero-id", 100, 8)?, 0, &mut b)?;
    let outputs: Vec<_> = std::iter::from_fn(|| owner.take_output()).collect();
    assert_eq!(
        outputs.len(),
        2,
        "both original zero-ID MQs must receive the actual result"
    );
    assert!(outputs.iter().any(|output| output.client() == a));
    assert!(outputs.iter().any(|output| output.client() == b_client));
    for output in outputs {
        let result = gnunet_wire::official::dht::ipc::ResultMessage::decode(output.bytes())?;
        assert_eq!(result.id, RequestId([0; 8]));
        assert_eq!(result.payload, b"first-zero-id");
    }
    let mut stop = [0; 80];
    gnunet_wire::official::dht::ipc::Stop {
        key: &key,
        id: RequestId([0; 8]),
    }
    .encode(&mut stop)?;
    owner.ingest(a, &stop, 0, &mut b)?;
    owner.ingest(publisher, &put(&key, b"second-zero-id", 100, 8)?, 0, &mut b)?;
    let output = owner.take_output().ok_or(Error::NotFound)?;
    assert_eq!(output.client(), b_client);
    let result = gnunet_wire::official::dht::ipc::ResultMessage::decode(output.bytes())?;
    assert_eq!(result.id, RequestId([0; 8]));
    assert_eq!(result.payload, b"second-zero-id");
    assert!(owner.take_output().is_none());
    Ok(())
}
