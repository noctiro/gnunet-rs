//! Independent pure resolver protocol and original-effect ownership tests.
#![cfg(feature = "alloc")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Independent protocol and ownership assertions"
)]
use gnunet_crypto::gns::{EdkeySecret, PkeySecret};
use gnunet_gns::*;
use gnunet_gnscrypto::{Label, ZoneSecret};
use gnunet_gnsrecord::{ZoneKeyType, serialize};
use std::net::{IpAddr, Ipv4Addr};

fn secret(seed: u8) -> ZoneSecret {
    ZoneSecret::Edkey(EdkeySecret::from_seed([seed; 32]))
}

#[test]
fn literal_convenience_and_ipc_enum_conversion_are_explicit() -> Result<(), Error> {
    let ip = address_literal("192.0.2.1")?.ok_or(Error::NotFound)?;
    assert_eq!(ip.data, [192, 0, 2, 1]);
    assert_eq!(ip.origin, Origin::Literal);
    assert_eq!(ip.expiration_time, u64::MAX);
    assert_eq!(
        address_literal("2001:db8::1")?
            .ok_or(Error::NotFound)?
            .record_type,
        RecordType::AAAA
    );
    assert!(address_literal("host.example")?.is_none());
    assert_eq!(Policy::from_local_options(0), Ok(Policy::CacheThenRemote));
    assert_eq!(Policy::from_local_options(1), Ok(Policy::LocalOnly));
    assert_eq!(Policy::from_local_options(2), Ok(Policy::LocalMaster));
    assert_eq!(Policy::from_local_options(0xfedc), Err(Error::Unsupported));
    Ok(())
}
fn rd(kind: RecordType, expiry: u64, flags: RecordFlags, data: &[u8]) -> RecordData<'_> {
    RecordData {
        expiration_time: expiry,
        record_type: kind,
        flags,
        data,
    }
}
fn request(zone: ZoneKey, name: &str, kind: RecordType) -> Lookup<'_> {
    Lookup {
        zone,
        name,
        record_type: kind,
        policy: Policy::CacheThenRemote,
        recursion_limit: 32,
    }
}
fn block(key: &ZoneSecret, name: &str, records: &[RecordData<'_>]) -> Result<Vec<u8>, Error> {
    let mut chars = vec!['\0'; 4096];
    let mut normalized = vec![0; 4096];
    let label = Label::normalize(name, &mut chars, &mut normalized)?;
    let mut plain = vec![0; 64512];
    let n = serialize(records, &mut plain)?;
    let mut bytes = vec![0; 64640];
    let n = key
        .seal(label, 1000, &plain[..n], &mut bytes)?
        .as_bytes()
        .len();
    bytes.truncate(n);
    Ok(bytes)
}
fn effect<'a>(r: &Resolver<'a>, q: QueryId<'_>) -> Result<EffectId<'a>, Error> {
    Ok(r.effect(q)?.ok_or(Error::NotReady)?.id)
}
fn cache(r: &mut Resolver<'_>, q: QueryId<'_>, bytes: &[u8], now: u64) -> Result<(), Error> {
    let id = effect(r, q)?;
    assert!(matches!(
        r.effect(q)?.map(|x| &x.kind),
        Some(EffectKind::Revocation { .. })
    ));
    r.revoked(id, false)?;
    let id = effect(r, q)?;
    r.cached(id, Some(bytes), now)
}
fn answer(r: &mut Resolver<'_>, q: QueryId<'_>) -> Result<Vec<Record>, Error> {
    r.take_result(q)?
        .ok_or(Error::NotReady)?
        .map_err(|_| Error::NotFound)
}

#[test]
fn pkey_to_edkey_nfc_delegation_and_apex_return_actual_records() -> Result<(), Error> {
    let root = ZoneSecret::Pkey(PkeySecret::from_bytes([3; 32])?);
    let child = secret(7);
    let zone = root.public_key();
    let target = child.public_key();
    let mut instance = Instance::new();
    let mut resolver = Resolver::new(&mut instance, Limits::default())?;
    let query = resolver.lookup(request(zone, "cafe\u{301}", RecordType::A))?;
    let delegation = block(
        &root,
        "café",
        &[rd(
            RecordType::EDKEY,
            200,
            RecordFlags::CRITICAL,
            target.key(),
        )],
    )?;
    cache(&mut resolver, query, &delegation, 100)?;
    assert!(
        matches!(&resolver.effect(query)?.ok_or(Error::NotReady)?.kind,EffectKind::Revocation{zone}if *zone==target)
    );
    let records = block(
        &child,
        "@",
        &[
            rd(
                RecordType::A,
                200,
                RecordFlags::from_bits_preserve(0x1000),
                &[192, 0, 2, 1],
            ),
            rd(
                RecordType::NICK,
                200,
                RecordFlags::SUPPLEMENTAL,
                b"zone-nick\0",
            ),
        ],
    )?;
    cache(&mut resolver, query, &records, 100)?;
    let result = answer(&mut resolver, query)?;
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].data, [192, 0, 2, 1]);
    assert_eq!(result[0].flags.bits(), 0x1000);
    assert_eq!(result[0].origin, Origin::Gns(target));
    assert_eq!(result[1].data, b"zone-nick\0");
    Ok(())
}
#[test]
fn remote_wrong_signature_zone_and_label_never_retire_original_get() -> Result<(), Error> {
    let root = secret(1);
    let other = secret(2);
    let mut i = Instance::new();
    let mut r = Resolver::new(&mut i, Limits::default())?;
    let q = r.lookup(request(root.public_key(), "host", RecordType::A))?;
    r.revoked(effect(&r, q)?, false)?;
    r.cached(effect(&r, q)?, None, 100)?;
    let original = effect(&r, q)?;
    let records = [rd(RecordType::A, 200, RecordFlags::NONE, &[1, 2, 3, 4])];
    let good = block(&root, "host", &records)?;
    let wrong_zone = block(&other, "host", &records)?;
    let wrong_label = block(&root, "other", &records)?;
    let mut corrupted = good.clone();
    corrupted[50] ^= 1;
    for bad in [&wrong_zone, &wrong_label, &corrupted] {
        assert!(r.remote_block(original, bad, 100).is_err());
        assert_eq!(effect(&r, q)?, original);
        assert!(r.take_result(q)?.is_none());
    }
    r.remote_block(original, &good, 100)?;
    let store = effect(&r, q)?;
    assert_ne!(store, original);
    assert!(
        matches!(&r.effect(q)?.ok_or(Error::NotReady)?.kind,EffectKind::CachePut{block,..}if block==&good)
    );
    assert_eq!(r.remote_block(original, &good, 100), Err(Error::Stale));
    r.cache_stored(store, 100)?;
    assert_eq!(answer(&mut r, q)?[0].data, [1, 2, 3, 4]);
    Ok(())
}
#[test]
fn local_only_never_emits_remote_for_invalid_cache_or_disabled_cache() -> Result<(), Error> {
    let root = secret(3);
    for enabled in [true, false] {
        let mut i = Instance::new();
        let mut r = Resolver::new(
            &mut i,
            Limits {
                cache: enabled,
                ..Limits::default()
            },
        )?;
        let mut lookup = request(root.public_key(), "host", RecordType::A);
        lookup.policy = Policy::LocalOnly;
        let q = r.lookup(lookup)?;
        r.revoked(effect(&r, q)?, false)?;
        if enabled {
            r.cached(effect(&r, q)?, Some(&[0; 128]), 100)?;
        }
        assert!(r.effect(q)?.is_none());
        assert_eq!(r.take_result(q)?, Some(Err(Failure::NotFound)));
    }
    Ok(())
}
#[test]
fn revocation_each_authority_and_same_zone_other_query_receipts_are_distinct() -> Result<(), Error>
{
    let root = secret(4);
    let mut i = Instance::new();
    let mut r = Resolver::new(&mut i, Limits::default())?;
    let a = r.lookup(request(root.public_key(), "same", RecordType::A))?;
    let b = r.lookup(request(root.public_key(), "same", RecordType::A))?;
    let ea = effect(&r, a)?;
    let eb = effect(&r, b)?;
    assert_ne!(ea, eb);
    r.revoked(eb, true)?;
    assert_eq!(r.take_result(b)?, Some(Err(Failure::Revoked)));
    assert_eq!(effect(&r, a)?, ea);
    let mut other_i = Instance::new();
    let mut other = Resolver::new(&mut other_i, Limits::default())?;
    let foreign = other.lookup(request(root.public_key(), "same", RecordType::A))?;
    assert_eq!(
        r.revoked(effect(&other, foreign)?, false),
        Err(Error::Stale)
    );
    r.cancel(a)?;
    assert_eq!(r.revoked(ea, false), Err(Error::Stale));
    assert_eq!(r.take_result(a)?, Some(Err(Failure::Cancelled)));
    other.close();
    assert_eq!(
        other.lookup(request(root.public_key(), "same", RecordType::A)),
        Err(Error::Closed)
    );
    Ok(())
}
#[test]
fn critical_unknown_and_apex_delegation_fail_but_expired_unknown_is_ignored() -> Result<(), Error> {
    let root = secret(5);
    let target = secret(6).public_key();
    let unknown = RecordType::new(0xfedc_abcd);
    for (name, records, expected) in [
        (
            "host",
            vec![rd(unknown, 200, RecordFlags::CRITICAL, b"x")],
            Failure::Critical(unknown),
        ),
        (
            "@",
            vec![rd(
                RecordType::EDKEY,
                200,
                RecordFlags::CRITICAL,
                target.key(),
            )],
            Failure::Apex,
        ),
        (
            "host",
            vec![
                rd(RecordType::EDKEY, 200, RecordFlags::CRITICAL, target.key()),
                rd(RecordType::A, 200, RecordFlags::NONE, &[1, 2, 3, 4]),
            ],
            Failure::Records,
        ),
    ] {
        let mut i = Instance::new();
        let mut r = Resolver::new(&mut i, Limits::default())?;
        let q = r.lookup(request(root.public_key(), name, RecordType::A))?;
        cache(&mut r, q, &block(&root, name, &records)?, 100)?;
        assert_eq!(r.take_result(q)?, Some(Err(expected)));
    }
    let mut i = Instance::new();
    let mut r = Resolver::new(&mut i, Limits::default())?;
    let q = r.lookup(request(root.public_key(), "host", RecordType::A))?;
    cache(
        &mut r,
        q,
        &block(
            &root,
            "host",
            &[
                rd(unknown, 99, RecordFlags::CRITICAL, b"x"),
                rd(RecordType::A, 200, RecordFlags::NONE, &[1, 2, 3, 4]),
            ],
        )?,
        100,
    )?;
    assert_eq!(answer(&mut r, q)?.len(), 1);
    Ok(())
}
#[test]
fn shadow_boundary_and_delayed_store_recompute_at_receipt_time() -> Result<(), Error> {
    let root = secret(8);
    let records = [
        rd(RecordType::A, 100, RecordFlags::NONE, &[1, 1, 1, 1]),
        rd(RecordType::A, 200, RecordFlags::SHADOW, &[2, 2, 2, 2]),
    ];
    let bytes = block(&root, "host", &records)?;
    for (now, address) in [(100, [1, 1, 1, 1]), (101, [2, 2, 2, 2])] {
        let mut i = Instance::new();
        let mut r = Resolver::new(&mut i, Limits::default())?;
        let q = r.lookup(request(root.public_key(), "host", RecordType::A))?;
        cache(&mut r, q, &bytes, now)?;
        let answer = answer(&mut r, q)?;
        assert_eq!(answer.len(), 1);
        assert_eq!(answer[0].data, address);
        assert!(!answer[0].flags.contains(RecordFlags::SHADOW));
    }
    let mut i = Instance::new();
    let mut r = Resolver::new(&mut i, Limits::default())?;
    let q = r.lookup(request(root.public_key(), "host", RecordType::A))?;
    r.revoked(effect(&r, q)?, false)?;
    r.cached(effect(&r, q)?, None, 100)?;
    r.remote_block(effect(&r, q)?, &bytes, 100)?;
    r.cache_stored(effect(&r, q)?, 101)?;
    assert_eq!(answer(&mut r, q)?[0].data, [2, 2, 2, 2]);
    let mut i = Instance::new();
    let mut r = Resolver::new(&mut i, Limits::default())?;
    let q = r.lookup(request(root.public_key(), "host", RecordType::A))?;
    cache(
        &mut r,
        q,
        &block(
            &root,
            "host",
            &[rd(RecordType::A, 99, RecordFlags::SHADOW, &[9; 4])],
        )?,
        100,
    )?;
    assert_eq!(r.take_result(q)?, Some(Err(Failure::NotFound)));
    Ok(())
}
#[test]
fn relative_redirect_preserves_remainder_and_cross_zone_target() -> Result<(), Error> {
    let root = secret(9);
    let child = secret(10);
    let mut i = Instance::new();
    let mut r = Resolver::new(&mut i, Limits::default())?;
    let q = r.lookup(request(root.public_key(), "a.alias", RecordType::A))?;
    cache(
        &mut r,
        q,
        &block(
            &root,
            "alias",
            &[rd(
                RecordType::REDIRECT,
                200,
                RecordFlags::CRITICAL,
                b"b.+\0",
            )],
        )?,
        100,
    )?;
    r.revoked(effect(&r, q)?, false)?;
    assert!(
        matches!(&r.effect(q)?.ok_or(Error::NotReady)?.kind,EffectKind::Cache{label,..}if label=="b")
    );
    r.cached(
        effect(&r, q)?,
        Some(&block(
            &root,
            "b",
            &[rd(
                RecordType::EDKEY,
                200,
                RecordFlags::CRITICAL,
                child.public_key().key(),
            )],
        )?),
        100,
    )?;
    cache(
        &mut r,
        q,
        &block(
            &child,
            "a",
            &[rd(RecordType::A, 200, RecordFlags::NONE, &[10, 0, 0, 1])],
        )?,
        100,
    )?;
    assert_eq!(answer(&mut r, q)?[0].data, [10, 0, 0, 1]);
    let mut i = Instance::new();
    let mut r = Resolver::new(&mut i, Limits::default())?;
    let q = r.lookup(request(root.public_key(), "left.alias", RecordType::A))?;
    cache(
        &mut r,
        q,
        &block(
            &root,
            "alias",
            &[rd(
                RecordType::REDIRECT,
                200,
                RecordFlags::CRITICAL,
                b"target.example\0",
            )],
        )?,
        100,
    )?;
    assert!(
        matches!(&r.effect(q)?.ok_or(Error::NotReady)?.kind,EffectKind::System{name,..}if name=="left.target.example")
    );
    r.failed(effect(&r, q)?, Error::NotFound, 100)?;
    assert_eq!(r.take_result(q)?, Some(Err(Failure::NotFound)));
    Ok(())
}
#[test]
fn cname_profile_and_returned_relative_embedded_dns_name() -> Result<(), Error> {
    let root = secret(11);
    let bytes = block(
        &root,
        "alias",
        &[rd(
            RecordType::CNAME,
            200,
            RecordFlags::NONE,
            b"\x04host\x01+\0",
        )],
    )?;
    for follow in [true, false] {
        let mut i = Instance::new();
        let mut r = Resolver::new(
            &mut i,
            Limits {
                follow_cname: follow,
                ..Limits::default()
            },
        )?;
        let q = r.lookup(request(root.public_key(), "alias", RecordType::A))?;
        cache(&mut r, q, &bytes, 100)?;
        if follow {
            assert!(matches!(
                &r.effect(q)?.ok_or(Error::NotReady)?.kind,
                EffectKind::System { .. }
            ));
        } else {
            let answer = answer(&mut r, q)?;
            let parsed = gnunet_dns::Name::from_wire(&answer[0].data)?;
            let mut dotted = [0; 255];
            let n = parsed.write_dotted(&mut dotted)?;
            assert!(dotted[..n].starts_with(b"host.000"));
        }
    }
    Ok(())
}
#[test]
fn cname_following_replaces_nonempty_remainder_exactly_like_pinned_c() -> Result<(), Error> {
    let root = secret(23);
    let signed = block(
        &root,
        "alias",
        &[rd(
            RecordType::CNAME,
            200,
            RecordFlags::NONE,
            b"\x07service\x07example\0",
        )],
    )?;
    for follow in [true, false] {
        let mut instance = Instance::new();
        let mut resolver = Resolver::new(
            &mut instance,
            Limits {
                follow_cname: follow,
                ..Limits::default()
            },
        )?;
        let query = resolver.lookup(request(root.public_key(), "left.alias", RecordType::A))?;
        cache(&mut resolver, query, &signed, 100)?;
        if follow {
            match &resolver.effect(query)?.ok_or(Error::NotReady)?.kind {
                EffectKind::System { name, .. } => assert_eq!(name, "service.example"),
                _ => return Err(Error::NotReady),
            }
            resolver.resolved(
                effect(&resolver, query)?,
                &[rd(RecordType::A, 200, RecordFlags::NONE, &[192, 0, 2, 1])],
                1,
                100,
            )?;
            assert_eq!(answer(&mut resolver, query)?[0].origin, Origin::System);
        } else {
            assert_eq!(resolver.take_result(query)?, Some(Err(Failure::NotFound)));
        }
    }
    Ok(())
}
#[test]
fn numeric_box_symbolic_registry_and_sbox_prefix_unbox_actual_payload() -> Result<(), Error> {
    let root = secret(12);
    let box_data = [0, 6, 1, 187, 0, 0, 0, 52, 1, 2, 3];
    for name in ["_443._tcp.host", "_https._tcp.host"] {
        let mut i = Instance::new();
        let mut r = Resolver::new(&mut i, Limits::default())?;
        let q = r.lookup(request(root.public_key(), name, RecordType::new(52)))?;
        cache(
            &mut r,
            q,
            &block(
                &root,
                "host",
                &[
                    rd(RecordType::BOX, 200, RecordFlags::NONE, &box_data),
                    rd(RecordType::A, 200, RecordFlags::NONE, &[1; 4]),
                ],
            )?,
            100,
        )?;
        if name.contains("https") {
            assert!(
                matches!(&r.effect(q)?.ok_or(Error::NotReady)?.kind,EffectKind::Service{service,protocol}if service=="https"&&protocol=="tcp")
            );
            r.service(effect(&r, q)?, Some((6, 443)))?;
        }
        let answer = answer(&mut r, q)?;
        assert_eq!(answer.len(), 1);
        assert_eq!(answer[0].record_type, RecordType::new(52));
        assert_eq!(answer[0].data, [1, 2, 3]);
    }
    let mut payload = vec![0, 0, 0, 16];
    payload.extend_from_slice(b"ABC._smimecert\0payload");
    let mut i = Instance::new();
    let mut r = Resolver::new(&mut i, Limits::default())?;
    let q = r.lookup(request(
        root.public_key(),
        "ABC._smimecert",
        RecordType::TXT,
    ))?;
    cache(
        &mut r,
        q,
        &block(
            &root,
            "@",
            &[rd(RecordType::SBOX, 200, RecordFlags::NONE, &payload)],
        )?,
        100,
    )?;
    assert_eq!(answer(&mut r, q)?[0].data, b"payload");
    Ok(())
}
#[test]
fn gns2dns_tries_every_server_security_and_never_reenters_gns() -> Result<(), Error> {
    let root = secret(13);
    let records = [
        rd(
            RecordType::GNS2DNS,
            200,
            RecordFlags::CRITICAL,
            b"example\x00192.0.2.1\0",
        ),
        rd(
            RecordType::GNS2DNS,
            200,
            RecordFlags::CRITICAL,
            b"example\x002001:db8::1\0",
        ),
        rd(RecordType::new(43), 200, RecordFlags::NONE, b"ds"),
        rd(RecordType::NICK, 200, RecordFlags::SUPPLEMENTAL, b"nick\0"),
    ];
    let mut i = Instance::new();
    let mut r = Resolver::new(&mut i, Limits::default())?;
    let q = r.lookup(request(root.public_key(), "www.bridge", RecordType::A))?;
    cache(&mut r, q, &block(&root, "bridge", &records)?, 100)?;
    assert!(
        matches!(&r.effect(q)?.ok_or(Error::NotReady)?.kind,EffectKind::Dns{name,security,server,..}if name=="www.example"&&security.len()==1&&*server==IpAddr::V4(Ipv4Addr::new(192,0,2,1)))
    );
    let first = effect(&r, q)?;
    r.failed(first, Error::Timeout, 100)?;
    let second = effect(&r, q)?;
    assert_ne!(first, second);
    assert_eq!(
        r.resolved(
            second,
            &[rd(
                RecordType::EDKEY,
                200,
                RecordFlags::CRITICAL,
                root.public_key().key()
            )],
            1,
            100
        ),
        Err(Error::Malformed)
    );
    assert_eq!(effect(&r, q)?, second);
    r.resolved(
        second,
        &[rd(RecordType::A, 200, RecordFlags::NONE, &[192, 0, 2, 9])],
        1,
        100,
    )?;
    let answer = answer(&mut r, q)?;
    assert_eq!(answer[0].data, [192, 0, 2, 9]);
    assert_eq!(answer[1].record_type, RecordType::LEHO);
    assert_eq!(answer[1].data, b"www.example");
    assert_eq!(answer[0].origin, answer[1].origin);
    assert!(matches!(answer[0].origin, Origin::Dns(_)));
    assert!(answer[1].flags.contains(RecordFlags::RELATIVE_EXPIRATION));
    assert_eq!(r.failed(first, Error::Timeout, 100), Err(Error::Stale));
    Ok(())
}

#[test]
fn nfc_start_zone_maps_and_opaque_dns_labels_are_lossless() -> Result<(), Error> {
    let root = secret(19);
    let zone = root.public_key();
    let mut i = Instance::new();
    let mut r = Resolver::new(&mut i, Limits::default())?;
    let q = r.lookup_name(
        "host.cafe\u{301}.alt",
        &[Mapping {
            suffix: "café.alt",
            zone,
        }],
        RecordType::CNAME,
        Policy::LocalOnly,
        10,
    )?;
    let original = b"\x03a.b\x01\xff\0";
    cache(
        &mut r,
        q,
        &block(
            &root,
            "host",
            &[rd(RecordType::CNAME, 200, RecordFlags::NONE, original)],
        )?,
        100,
    )?;
    assert_eq!(answer(&mut r, q)?[0].data, original);
    Ok(())
}

#[test]
fn optional_cache_write_cannot_exhaust_an_already_successful_final_lookup() -> Result<(), Error> {
    let root = secret(20);
    let mut i = Instance::new();
    let mut r = Resolver::new(
        &mut i,
        Limits {
            steps: 4,
            ..Limits::default()
        },
    )?;
    let q = r.lookup(request(root.public_key(), "host", RecordType::A))?;
    r.revoked(effect(&r, q)?, false)?;
    r.cached(effect(&r, q)?, None, 100)?;
    r.remote_block(
        effect(&r, q)?,
        &block(
            &root,
            "host",
            &[rd(RecordType::A, 200, RecordFlags::NONE, &[1, 2, 3, 4])],
        )?,
        100,
    )?;
    assert_eq!(answer(&mut r, q)?[0].data, [1, 2, 3, 4]);
    Ok(())
}

#[test]
fn invalid_remote_candidate_stream_spends_finite_original_query_work() -> Result<(), Error> {
    let root = secret(22);
    let mut i = Instance::new();
    let mut r = Resolver::new(
        &mut i,
        Limits {
            steps: 5,
            ..Limits::default()
        },
    )?;
    let q = r.lookup(request(root.public_key(), "host", RecordType::A))?;
    r.revoked(effect(&r, q)?, false)?;
    r.cached(effect(&r, q)?, None, 100)?;
    let original = effect(&r, q)?;
    assert!(r.remote_block(original, &[0; 128], 100).is_err());
    assert_eq!(effect(&r, q)?, original);
    assert!(r.remote_block(original, &[0; 128], 100).is_err());
    assert_eq!(r.take_result(q)?, Some(Err(Failure::Recursion)));
    assert_eq!(r.remote_block(original, &[0; 128], 100), Err(Error::Stale));
    Ok(())
}

#[test]
fn box_and_sbox_overlap_combines_payloads_and_unassigned_critical_fails() -> Result<(), Error> {
    let root = secret(21);
    let box_data = [0, 6, 1, 187, 0, 0, 0, 52, 1];
    let mut sbox = vec![0, 0, 0, 52];
    sbox.extend_from_slice(b"_443._tcp\0second");
    let mut i = Instance::new();
    let mut r = Resolver::new(&mut i, Limits::default())?;
    let q = r.lookup(request(
        root.public_key(),
        "_443._tcp.host",
        RecordType::new(52),
    ))?;
    cache(
        &mut r,
        q,
        &block(
            &root,
            "host",
            &[
                rd(RecordType::BOX, 200, RecordFlags::NONE, &box_data),
                rd(RecordType::SBOX, 200, RecordFlags::NONE, &sbox),
            ],
        )?,
        100,
    )?;
    let result = answer(&mut r, q)?;
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].data, [1]);
    assert_eq!(result[1].data, b"second");
    let q = r.lookup(request(root.public_key(), "host", RecordType::A))?;
    cache(
        &mut r,
        q,
        &block(
            &root,
            "host",
            &[rd(RecordType::new(65546), 200, RecordFlags::CRITICAL, b"x")],
        )?,
        100,
    )?;
    assert_eq!(
        r.take_result(q)?,
        Some(Err(Failure::Critical(RecordType::new(65546))))
    );
    Ok(())
}
#[test]
fn relative_gns_nameserver_is_owned_child_and_cancellation_retires_child_attempt()
-> Result<(), Error> {
    let root = secret(14);
    let mut i = Instance::new();
    let mut r = Resolver::new(&mut i, Limits::default())?;
    let q = r.lookup(request(root.public_key(), "www.bridge", RecordType::A))?;
    cache(
        &mut r,
        q,
        &block(
            &root,
            "bridge",
            &[rd(
                RecordType::GNS2DNS,
                200,
                RecordFlags::CRITICAL,
                b"example\0ns.+\0",
            )],
        )?,
        100,
    )?;
    assert!(
        matches!(&r.effect(q)?.ok_or(Error::NotReady)?.kind,EffectKind::Revocation{zone}if *zone==root.public_key())
    );
    cache(
        &mut r,
        q,
        &block(
            &root,
            "ns",
            &[rd(RecordType::A, 200, RecordFlags::NONE, &[192, 0, 2, 53])],
        )?,
        100,
    )?;
    assert!(
        matches!(&r.effect(q)?.ok_or(Error::NotReady)?.kind,EffectKind::Dns{server,..}if *server==IpAddr::V4(Ipv4Addr::new(192,0,2,53)))
    );
    let dns = effect(&r, q)?;
    r.cancel(q)?;
    assert_eq!(r.failed(dns, Error::Timeout, 100), Err(Error::Stale));
    assert_eq!(r.take_result(q)?, Some(Err(Failure::Cancelled)));
    Ok(())
}
#[test]
fn nameserver_dns_idna_and_all_addresses_are_tried() -> Result<(), Error> {
    let root = secret(15);
    let mut i = Instance::new();
    let mut r = Resolver::new(&mut i, Limits::default())?;
    let q = r.lookup(request(root.public_key(), "bridge", RecordType::A))?;
    cache(
        &mut r,
        q,
        &block(
            &root,
            "bridge",
            &[rd(
                RecordType::GNS2DNS,
                200,
                RecordFlags::CRITICAL,
                "faß.example\0dns.faß.example\0".as_bytes(),
            )],
        )?,
        100,
    )?;
    assert!(
        matches!(&r.effect(q)?.ok_or(Error::NotReady)?.kind,EffectKind::Nameserver{name,..}if name=="dns.xn--fa-hia.example")
    );
    r.addresses(
        effect(&r, q)?,
        &[
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
        ],
        1,
    )?;
    assert!(
        matches!(&r.effect(q)?.ok_or(Error::NotReady)?.kind,EffectKind::Dns{name,..}if name=="xn--fa-hia.example")
    );
    r.failed(effect(&r, q)?, Error::Timeout, 100)?;
    r.failed(effect(&r, q)?, Error::Timeout, 100)?;
    assert_eq!(r.take_result(q)?, Some(Err(Failure::NotFound)));
    Ok(())
}
#[test]
fn namespace_mismatch_and_dns_disabled_have_explicit_failures() -> Result<(), Error> {
    let root = secret(16);
    let bytes = block(
        &root,
        "bridge",
        &[
            rd(
                RecordType::GNS2DNS,
                200,
                RecordFlags::CRITICAL,
                b"one\x00192.0.2.1\0",
            ),
            rd(
                RecordType::GNS2DNS,
                200,
                RecordFlags::CRITICAL,
                b"two\x00192.0.2.2\0",
            ),
        ],
    )?;
    let mut i = Instance::new();
    let mut r = Resolver::new(&mut i, Limits::default())?;
    let q = r.lookup(request(root.public_key(), "bridge", RecordType::A))?;
    cache(&mut r, q, &bytes, 100)?;
    assert_eq!(r.take_result(q)?, Some(Err(Failure::Records)));
    for kind in [RecordType::A, RecordType::GNS2DNS] {
        let mut i = Instance::new();
        let mut r = Resolver::new(
            &mut i,
            Limits {
                dns: false,
                ..Limits::default()
            },
        )?;
        let q = r.lookup(request(root.public_key(), "bridge", kind))?;
        let data = block(
            &root,
            "bridge",
            &[rd(
                RecordType::GNS2DNS,
                200,
                RecordFlags::CRITICAL,
                b"one\x00192.0.2.1\0",
            )],
        )?;
        cache(&mut r, q, &data, 100)?;
        if kind == RecordType::A {
            assert_eq!(r.take_result(q)?, Some(Err(Failure::DnsDisabled)));
        } else {
            assert_eq!(answer(&mut r, q)?[0].record_type, RecordType::GNS2DNS);
        }
    }
    Ok(())
}
#[test]
fn recursion_query_capacity_and_record_capacity_are_finite_and_recoverable() -> Result<(), Error> {
    let root = secret(17);
    let mut i = Instance::new();
    let mut r = Resolver::new(
        &mut i,
        Limits {
            queries: 1,
            ..Limits::default()
        },
    )?;
    let mut req = request(root.public_key(), "host", RecordType::A);
    req.recursion_limit = 0;
    let q = r.lookup(req)?;
    assert_eq!(r.lookup(req), Err(Error::WouldBlock));
    cache(
        &mut r,
        q,
        &block(
            &root,
            "host",
            &[rd(
                RecordType::EDKEY,
                200,
                RecordFlags::CRITICAL,
                root.public_key().key(),
            )],
        )?,
        100,
    )?;
    assert_eq!(r.take_result(q)?, Some(Err(Failure::Recursion)));
    assert!(r.lookup(req).is_ok());
    let mut i = Instance::new();
    let mut r = Resolver::new(
        &mut i,
        Limits {
            steps: 1,
            ..Limits::default()
        },
    )?;
    let q = r.lookup(req)?;
    r.revoked(effect(&r, q)?, false)?;
    assert_eq!(r.take_result(q)?, Some(Err(Failure::Recursion)));
    let mut i = Instance::new();
    let mut r = Resolver::new(
        &mut i,
        Limits {
            records: 1,
            cache: false,
            ..Limits::default()
        },
    )?;
    let q = r.lookup(req)?;
    r.revoked(effect(&r, q)?, false)?;
    let id = effect(&r, q)?;
    let records = block(
        &root,
        "host",
        &[
            rd(RecordType::A, 200, RecordFlags::NONE, &[1; 4]),
            rd(RecordType::TXT, 200, RecordFlags::NONE, b"x"),
        ],
    )?;
    assert_eq!(r.remote_block(id, &records, 100), Err(Error::Capacity));
    assert_eq!(effect(&r, q)?, id);
    Ok(())
}
#[test]
fn nick_supplemental_gate_and_vpn_opaque_record_keep_application_boundary() -> Result<(), Error> {
    let root = secret(18);
    let records = block(
        &root,
        "host",
        &[
            rd(
                RecordType::VPN,
                200,
                RecordFlags::NONE,
                b"vpn application payload",
            ),
            rd(
                RecordType::NICK,
                200,
                RecordFlags::SUPPLEMENTAL,
                b"nickname\0",
            ),
        ],
    )?;
    for kind in [RecordType::A, RecordType::VPN] {
        let mut i = Instance::new();
        let mut r = Resolver::new(&mut i, Limits::default())?;
        let q = r.lookup(request(root.public_key(), "host", kind))?;
        cache(&mut r, q, &records, 100)?;
        if kind == RecordType::A {
            assert_eq!(r.take_result(q)?, Some(Err(Failure::NotFound)));
        } else {
            let a = answer(&mut r, q)?;
            assert_eq!(a[0].record_type, RecordType::VPN);
            assert_eq!(a[0].data, b"vpn application payload");
        }
    }
    Ok(())
}
#[test]
fn start_zone_longest_suffix_ztld_priority_and_ambiguous_mappings() -> Result<(), Error> {
    let a = ZoneKey::new(ZoneKeyType::Edkey, [1; 32]);
    let b = ZoneKey::new(ZoneKeyType::Pkey, [2; 32]);
    let mappings = [
        Mapping {
            suffix: "gns.alt",
            zone: a,
        },
        Mapping {
            suffix: "example.gns.alt",
            zone: b,
        },
    ];
    let selected = select_start_zone("www.example.gns.alt", &mappings)?;
    assert_eq!(selected.zone, b);
    assert_eq!(selected.name, "www");
    assert_eq!(select_start_zone("gns.alt", &mappings)?.name, "");
    assert_eq!(
        select_start_zone("x.fakegns.alt", &mappings),
        Err(Error::NotFound)
    );
    assert_eq!(
        select_start_zone("x.gns.alt", &[mappings[0], mappings[0]]),
        Err(Error::Conflict)
    );
    let mut out = [0; 58];
    let name = format!("www.{}", a.write_ztld(&mut out)?);
    assert_eq!(select_start_zone(&name, &mappings)?.zone, a);
    let bad = "www.000G050invalid";
    assert!(
        select_start_zone(
            bad,
            &[Mapping {
                suffix: "000G050invalid",
                zone: b
            }]
        )
        .is_err()
    );
    Ok(())
}
