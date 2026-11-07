//! Original DHT logical intent, physical epochs and exact wire attempts.
#![cfg(feature = "alloc")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Behavioral protocol tests assert original owners and exact refused transitions."
)]
use gnunet_dht_client::{
    Action, Cancel, Client, Event, Get, Ignored, Instance, Limits, Monitor, Outcome, ipc,
};
use gnunet_types::Error;
use gnunet_wire::official::{AbsoluteTime, dht::Path};
fn query(key: &[u8; 64]) -> Get<'_> {
    Get {
        key,
        block_type: 8,
        options: 0,
        replication: 1,
        extended_query: &[],
    }
}
fn result(key: &[u8; 64], id: ipc::RequestId, kind: u32, payload: &[u8]) -> Result<Vec<u8>, Error> {
    let m = ipc::ResultMessage {
        block_type: kind,
        options: 0,
        put_path: Path::empty(),
        get_path: Path::empty(),
        id,
        expiration: AbsoluteTime::from_micros(99),
        key,
        truncated_peer: None,
        payload,
    };
    let mut b = vec![0; m.encoded_len()?];
    m.encode(&mut b)?;
    Ok(b)
}
fn put<'a>(key: &'a [u8; 64], payload: &'a [u8]) -> ipc::Put<'a> {
    ipc::Put {
        block_type: 8,
        options: 0,
        replication: 1,
        expiration: AbsoluteTime::from_micros(99),
        key,
        payload,
    }
}
fn written<'a>(c: &mut Client<'a>) -> Result<(Action<'a>, Vec<u8>), Error> {
    let out = c.outbound()?.ok_or(Error::NotReady)?;
    let attempt = out.attempt();
    let bytes = out.bytes().to_vec();
    let action = c.written(attempt)?;
    Ok((action, bytes))
}
#[test]
fn zero_wire_id_is_opaque_and_original_result_is_delivered() -> Result<(), Error> {
    let mut i = Instance::new();
    let mut c = Client::new(&mut i, Limits::default())?;
    let key = [1; 64];
    let q = c.get(query(&key))?;
    assert_eq!(c.request_id(q)?, ipc::RequestId([0; 8]));
    let e = c.connect()?;
    let (_, b) = written(&mut c)?;
    let ipc::Request::Get(g) = ipc::Request::decode(&b)? else {
        return Err(Error::Malformed);
    };
    assert_eq!(g.id, ipc::RequestId([0; 8]));
    let received = c.receive(e, &result(&key, g.id, 8, b"value")?)?;
    assert!(
        matches!(received.event(),Event::Result{get,remembered:true,duplicate:false}if *get==q)
    );
    assert_eq!(received.result()?.payload, b"value");
    Ok(())
}
#[test]
fn foreign_instance_and_retired_epoch_never_address_new_query() -> Result<(), Error> {
    let (mut i, mut j) = (Instance::new(), Instance::new());
    let mut a = Client::new(&mut i, Limits::default())?;
    let mut b = Client::new(&mut j, Limits::default())?;
    let key = [2; 64];
    let qa = a.get(query(&key))?;
    let qb = b.get(query(&key))?;
    let ea = a.connect()?;
    let eb = b.connect()?;
    written(&mut a)?;
    written(&mut b)?;
    let bytes = result(&key, a.request_id(qa)?, 8, b"x")?;
    assert!(matches!(a.receive(eb, &bytes), Err(Error::InvalidInput)));
    assert_eq!(a.stop(qb), Err(Error::InvalidInput));
    a.lost(ea)?;
    let next = a.connect()?;
    written(&mut a)?;
    assert!(matches!(a.receive(ea, &bytes), Err(Error::Stale)));
    assert!(matches!(a.receive(next,&bytes)?.event(),Event::Result{get,..}if *get==qa));
    Ok(())
}
#[test]
fn reconnect_restores_query_known_monitor_and_hello_but_never_put() -> Result<(), Error> {
    let mut i = Instance::new();
    let mut c = Client::new(&mut i, Limits::default())?;
    let key = [3; 64];
    let q = c.get(query(&key))?;
    c.known(q, &[[7; 64]])?;
    let m = c.monitor(Monitor {
        block_type: 8,
        get: 1,
        result: 0,
        put: 1,
        key: Some(key),
    })?;
    let h = c.hello()?;
    let old = c.connect()?;
    let op = c.put(put(&key, b"original"))?;
    let mut first_get = None;
    for _ in 0..5 {
        let (action, bytes) = written(&mut c)?;
        if action == Action::Get(q) {
            first_get = Some(bytes)
        }
    }
    assert!(c.completion().is_some());
    let uncertain = c.put(put(&key, b"uncertain"))?;
    let abandoned = c.outbound()?.ok_or(Error::NotReady)?;
    assert_eq!(abandoned.attempt().action(), Action::Put(uncertain));
    c.lost(old)?;
    let n = c.completion().ok_or(Error::NotFound)?;
    assert_eq!(n.operation, uncertain);
    assert_eq!(n.outcome, Outcome::Lost);
    assert!(c.completion().is_none());
    let fresh = c.connect()?;
    assert_ne!(old, fresh);
    let mut actions = Vec::new();
    while c.next_size().is_some() {
        let (a, b) = written(&mut c)?;
        if a == Action::Get(q) {
            assert_eq!(Some(b), first_get)
        }
        actions.push(a)
    }
    assert!(actions.contains(&Action::Get(q)));
    assert!(actions.contains(&Action::Known { get: q, count: 1 }));
    assert!(actions.contains(&Action::MonitorStart(m)));
    assert!(actions.contains(&Action::Hello(h)));
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, Action::Put(_) | Action::Offer(_)))
    );
    assert_ne!(op, uncertain);
    assert_eq!(c.written(abandoned.attempt()), Err(Error::Stale));
    Ok(())
}
#[test]
fn original_fifo_cancel_cannot_complete_stop_before_started_get() -> Result<(), Error> {
    let mut i = Instance::new();
    let mut c = Client::new(&mut i, Limits::default())?;
    let key = [4; 64];
    let q = c.get(query(&key))?;
    let e = c.connect()?;
    let get = c.outbound()?.ok_or(Error::NotFound)?;
    assert_eq!(c.stop(q)?, Cancel::Draining);
    let stop = c.outbound()?.ok_or(Error::NotFound)?;
    assert_eq!(stop.attempt().action(), Action::Stop(q));
    assert_eq!(c.written(stop.attempt()), Err(Error::Stale));
    assert!(matches!(
        c.receive(e, &result(&key, c.request_id(q)?, 8, b"late")?)?
            .event(),
        Event::Ignored(Ignored::Result)
    ));
    assert_eq!(c.written(get.attempt())?, Action::Get(q));
    assert_eq!(c.written(stop.attempt())?, Action::Stop(q));
    assert_eq!(c.snapshot().gets, 0);
    assert_eq!(c.request_id(q), Err(Error::Stale));
    Ok(())
}
#[test]
fn canceled_never_issued_get_does_not_create_stop_or_reuse_wire_id() -> Result<(), Error> {
    let mut i = Instance::new();
    let mut c = Client::new(&mut i, Limits::default())?;
    let key = [5; 64];
    let old = c.get(query(&key))?;
    assert_eq!(c.stop(old)?, Cancel::BeforeIssue);
    let new = c.get(query(&key))?;
    assert_eq!(c.request_id(new)?, ipc::RequestId(1u64.to_be_bytes()));
    c.connect()?;
    assert_eq!(written(&mut c)?.0, Action::Get(new));
    assert!(c.next_size().is_none());
    Ok(())
}
#[test]
fn explicit_known_duplicates_and_capacity_refusal_are_atomic_and_chunked() -> Result<(), Error> {
    let mut i = Instance::new();
    let mut c = Client::new(
        &mut i,
        Limits {
            known_per_get: 2,
            frame_bytes: 144,
            ..Limits::default()
        },
    )?;
    let key = [6; 64];
    let q = c.get(query(&key))?;
    c.known(q, &[[1; 64], [1; 64]])?;
    assert_eq!(c.known(q, &[[2; 64], [3; 64]]), Err(Error::Capacity));
    c.known(q, &[[2; 64]])?;
    c.connect()?;
    written(&mut c)?;
    let (a, b) = written(&mut c)?;
    assert_eq!(a, Action::Known { get: q, count: 1 });
    let ipc::Request::Known(k) = ipc::Request::decode(&b)? else {
        return Err(Error::Malformed);
    };
    assert_eq!(k.hashes.iter().copied().collect::<Vec<_>>(), vec![[1; 64]]);
    let (_, b) = written(&mut c)?;
    let ipc::Request::Known(k) = ipc::Request::decode(&b)? else {
        return Err(Error::Malformed);
    };
    assert_eq!(k.hashes.iter().copied().collect::<Vec<_>>(), vec![[2; 64]]);
    assert!(c.next_size().is_none());
    Ok(())
}
#[test]
fn full_optional_history_never_blocks_actual_results_or_fakes_retention() -> Result<(), Error> {
    let mut i = Instance::new();
    let mut c = Client::new(
        &mut i,
        Limits {
            known_per_get: 1,
            ..Limits::default()
        },
    )?;
    let key = [7; 64];
    let q = c.get(query(&key))?;
    let e = c.connect()?;
    written(&mut c)?;
    let id = c.request_id(q)?;
    assert!(matches!(
        c.receive(e, &result(&key, id, 8, b"first")?)?.event(),
        Event::Result {
            remembered: true,
            duplicate: false,
            ..
        }
    ));
    assert!(matches!(
        c.receive(e, &result(&key, id, 8, b"second")?)?.event(),
        Event::Result {
            remembered: false,
            duplicate: false,
            ..
        }
    ));
    assert!(matches!(
        c.receive(e, &result(&key, id, 8, b"first")?)?.event(),
        Event::Result {
            remembered: true,
            duplicate: true,
            ..
        }
    ));
    assert!(c.next_size().is_none());
    c.lost(e)?;
    c.connect()?;
    written(&mut c)?;
    let (_, b) = written(&mut c)?;
    let ipc::Request::Known(k) = ipc::Request::decode(&b)? else {
        return Err(Error::Malformed);
    };
    assert_eq!(
        k.hashes.iter().copied().collect::<Vec<_>>(),
        vec![gnunet_crypto::hash512(b"first")]
    );
    Ok(())
}
#[test]
fn full_width_type_key_and_id_are_all_matched_before_callback() -> Result<(), Error> {
    let mut i = Instance::new();
    let mut c = Client::new(&mut i, Limits::default())?;
    let key = [8; 64];
    let mut g = query(&key);
    g.block_type = 0x10008;
    let q = c.get(g)?;
    let e = c.connect()?;
    written(&mut c)?;
    let id = c.request_id(q)?;
    for bytes in [
        result(&key, id, 8, b"wrongtype")?,
        result(&[9; 64], id, 0x10008, b"wrongkey")?,
        result(&key, ipc::RequestId([9; 8]), 0x10008, b"wrongid")?,
    ] {
        assert!(matches!(
            c.receive(e, &bytes)?.event(),
            Event::Ignored(Ignored::Result)
        ))
    }
    assert!(
        matches!(c.receive(e,&result(&key,id,0x10008,b"right")?)?.event(),Event::Result{get,..}if *get==q)
    );
    Ok(())
}
#[test]
fn put_cancel_only_suppresses_original_notice_without_truncating_issued_frame() -> Result<(), Error>
{
    let mut i = Instance::new();
    let mut c = Client::new(&mut i, Limits::default())?;
    let key = [9; 64];
    assert_eq!(c.put(put(&key, b"offline")), Err(Error::NotReady));
    c.connect()?;
    let before = c.put(put(&key, b"never-issued"))?;
    assert_eq!(c.cancel(before)?, Cancel::BeforeIssue);
    let op = c.put(put(&key, b"original"))?;
    let frame = c.outbound()?.ok_or(Error::NotReady)?;
    assert_eq!(c.cancel(op)?, Cancel::Draining);
    let ipc::Request::Put(p) = ipc::Request::decode(frame.bytes())? else {
        return Err(Error::Malformed);
    };
    assert_eq!(p.payload, b"original");
    c.written(frame.attempt())?;
    let n = c.completion().ok_or(Error::NotFound)?;
    assert_eq!((n.operation, n.outcome), (op, Outcome::CanceledWritten));
    assert!(c.completion().is_none());
    Ok(())
}
#[test]
fn hello_absence_is_actual_snapshot_for_only_current_written_observations() -> Result<(), Error> {
    let mut i = Instance::new();
    let mut c = Client::new(&mut i, Limits::default())?;
    let h1 = c.hello()?;
    let h2 = c.hello()?;
    let e = c.connect()?;
    let mut wire = [0; 4];
    ipc::encode_hello(None, false, &mut wire)?;
    assert!(matches!(
        c.receive(e, &wire)?.event(),
        Event::Ignored(Ignored::Hello)
    ));
    written(&mut c)?;
    written(&mut c)?;
    let response = c.receive(e, &wire)?;
    let Event::Hello { requests } = response.event() else {
        return Err(Error::Malformed);
    };
    assert_eq!(requests, &vec![h1, h2]);
    assert_eq!(response.hello_url()?, None);
    assert_eq!(c.snapshot().hellos, 0);
    Ok(())
}
#[test]
fn monitor_delivery_keeps_each_original_matching_registration() -> Result<(), Error> {
    let mut i = Instance::new();
    let mut c = Client::new(&mut i, Limits::default())?;
    let key = [10; 64];
    let spec = Monitor {
        block_type: 8,
        get: 1,
        result: 0,
        put: 0,
        key: Some(key),
    };
    let a = c.monitor(spec)?;
    let b = c.monitor(spec)?;
    let e = c.connect()?;
    written(&mut c)?;
    written(&mut c)?;
    let mut wire = [0; 88];
    ipc::MonitorGet {
        options: 0,
        block_type: 8,
        hop_count: 0,
        replication: 1,
        key: &key,
    }
    .encode(&mut wire)?;
    let r = c.receive(e, &wire)?;
    assert!(matches!(r.event(),Event::Monitor{monitors,..}if monitors==&vec![a,b]));
    c.stop_monitor(a)?;
    let r = c.receive(e, &wire)?;
    assert!(matches!(r.event(),Event::Monitor{monitors,..}if monitors==&vec![b]));
    assert_eq!(written(&mut c)?.0, Action::MonitorStop(a));
    Ok(())
}
#[test]
fn domain_fairness_does_not_starve_subscriptions_behind_one_shots() -> Result<(), Error> {
    let mut i = Instance::new();
    let mut c = Client::new(&mut i, Limits::default())?;
    let key = [11; 64];
    let q = c.get(query(&key))?;
    let m = c.monitor(Monitor {
        block_type: 0,
        get: 1,
        result: 1,
        put: 1,
        key: None,
    })?;
    let h = c.hello()?;
    c.connect()?;
    let p = c.put(put(&key, b"a"))?;
    c.put(put(&key, b"b"))?;
    assert_eq!(written(&mut c)?.0, Action::Get(q));
    assert_eq!(written(&mut c)?.0, Action::MonitorStart(m));
    assert_eq!(written(&mut c)?.0, Action::Hello(h));
    assert_eq!(written(&mut c)?.0, Action::Put(p));
    Ok(())
}
#[test]
fn close_is_permanent_but_original_uncertain_notice_remains_drainable() -> Result<(), Error> {
    let mut i = Instance::new();
    let mut c = Client::new(&mut i, Limits::default())?;
    let key = [12; 64];
    c.connect()?;
    let op = c.put(put(&key, b"outstanding"))?;
    let old = c.outbound()?.ok_or(Error::NotReady)?;
    c.close();
    assert_eq!(c.connect(), Err(Error::Closed));
    assert_eq!(c.get(query(&key)), Err(Error::Closed));
    assert_eq!(c.written(old.attempt()), Err(Error::Closed));
    let notice = c.completion().ok_or(Error::NotFound)?;
    assert_eq!((notice.operation, notice.outcome), (op, Outcome::Lost));
    assert_eq!(c.snapshot().source_bytes, 0);
    Ok(())
}
#[test]
fn unsupported_todo152_never_completes_a_put() -> Result<(), Error> {
    let mut i = Instance::new();
    let mut c = Client::new(&mut i, Limits::default())?;
    c.connect()?;
    let key = [13; 64];
    c.put(put(&key, b"pending"))?;
    let epoch = c.epoch().ok_or(Error::NotReady)?;
    assert!(matches!(
        c.receive(epoch, &[0, 4, 0, 152]),
        Err(Error::Unsupported)
    ));
    assert!(c.completion().is_none());
    assert_eq!(c.snapshot().operations, 1);
    Ok(())
}
#[test]
fn hello_offer_requires_actual_signature_expiry_and_preserves_metadata_only_coverage()
-> Result<(), Error> {
    use gnunet_hello::{HelloBuilder, SignatureCoverage, SignatureProfile};
    let limits = gnunet_hello::Limits {
        maximum_input_bytes: 1024,
        maximum_address_bytes: 128,
        maximum_addresses: 4,
    };
    let mut storage = [0; 128];
    let mut builder = HelloBuilder::new(&mut storage, limits);
    builder.add_address(b"a://original")?;
    let key = gnunet_crypto::EddsaPrivateKey::from_seed([55; 32]);
    let hello = builder.sign(
        &key,
        AbsoluteTime::from_micros(5),
        SignatureProfile::Gnunet029,
    )?;
    let mut encoded = [0; 1024];
    let url = hello.write_url(&mut encoded)?.as_bytes();
    let mut scratch = [0; 128];
    let mut instance = Instance::new();
    let mut c = Client::new(&mut instance, Limits::default())?;
    assert!(matches!(
        c.offer_hello(url, &mut scratch, limits, AbsoluteTime::UNIX_EPOCH),
        Err(Error::NotReady)
    ));
    c.connect()?;
    assert!(
        c.offer_hello(url, &mut scratch, limits, AbsoluteTime::from_micros(6))
            .is_err()
    );
    assert_eq!(c.snapshot().operations, 0);
    let (op, coverage) = c.offer_hello(url, &mut scratch, limits, AbsoluteTime::from_micros(5))?;
    assert_eq!(coverage, SignatureCoverage::MetadataOnly);
    let (action, bytes) = written(&mut c)?;
    assert_eq!(action, Action::Offer(op));
    assert!(
        matches!(ipc::Request::decode(&bytes)?,ipc::Request::HelloUrl(Some(actual))if actual==url)
    );
    assert_eq!(
        c.completion().ok_or(Error::NotFound)?.outcome,
        Outcome::Written
    );
    let unsigned = builder.with_signature(
        gnunet_crypto::EddsaPublicKey::from_bytes([0; 32]),
        gnunet_crypto::EddsaSignature::from_bytes([0; 64]),
        AbsoluteTime::from_micros(5),
    );
    let mut bad = [0; 1024];
    assert!(
        c.offer_hello(
            unsigned.write_url(&mut bad)?.as_bytes(),
            &mut scratch,
            limits,
            AbsoluteTime::UNIX_EPOCH
        )
        .is_err()
    );
    assert_eq!(c.snapshot().operations, 0);
    Ok(())
}
#[test]
fn original_source_budget_is_refunded_only_after_its_exact_terminal_release() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut c = Client::new(
        &mut instance,
        Limits {
            known_per_get: 0,
            source_bytes: 176,
            ..Limits::default()
        },
    )?;
    let key = [14; 64];
    let q = c.get(query(&key))?;
    let charged = c.snapshot().source_bytes;
    assert_eq!(charged, 88);
    assert!(c.get(query(&key)).is_ok());
    assert_eq!(c.get(query(&key)), Err(Error::Capacity));
    c.stop(q)?;
    assert_eq!(c.snapshot().source_bytes, 88);
    let epoch = c.connect()?;
    let p = c.put(put(&key, b"x"));
    assert_eq!(p, Err(Error::Capacity));
    c.lost(epoch)?;
    assert_eq!(c.snapshot().source_bytes, 88);
    Ok(())
}
#[test]
fn closing_unissued_put_keeps_its_original_mq_admission_identity() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut c = Client::new(&mut instance, Limits::default())?;
    let epoch = c.connect()?;
    let operation = c.put(put(&[15; 64], b"admitted on this MQ"))?;
    assert_eq!(c.snapshot().attempts, 0);
    c.close();
    let terminal = c.completion().ok_or(Error::NotFound)?;
    assert_eq!(
        (terminal.operation, terminal.epoch, terminal.outcome),
        (operation, Some(epoch), Outcome::Lost)
    );
    assert_eq!(c.snapshot().source_bytes, 0);
    Ok(())
}
#[test]
fn full_attempt_budget_keeps_unissued_intent_until_original_fifo_settles() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut c = Client::new(
        &mut instance,
        Limits {
            attempts: 1,
            ..Limits::default()
        },
    )?;
    let a = c.get(query(&[16; 64]))?;
    let b = c.get(query(&[17; 64]))?;
    c.connect()?;
    let first = c.outbound()?.ok_or(Error::NotReady)?;
    assert_eq!(first.attempt().action(), Action::Get(a));
    assert!(c.outbound()?.is_none());
    assert!(c.next_size().is_none());
    assert_eq!(c.snapshot().gets, 2);
    assert_eq!(c.stop(a)?, Cancel::Draining);
    c.written(first.attempt())?;
    let next = c.outbound()?.ok_or(Error::NotReady)?;
    assert_eq!(next.attempt().action(), Action::Get(b));
    c.written(next.attempt())?;
    let stop = c.outbound()?.ok_or(Error::NotReady)?;
    assert_eq!(stop.attempt().action(), Action::Stop(a));
    c.written(stop.attempt())?;
    assert_eq!(c.snapshot().attempts, 0);
    Ok(())
}
