//! Exercise the actual public Business Job and its original provider tokens.
//! The ordered in-memory NAMESTORE/GNS replies below are explicit provider
//! models containing public mock values, not native/C/network evidence.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions compare actual public Job plans, provider acknowledgements and subsequent modeled GNS lookups; fallible setup remains returned."
)]
use super::*;
use gnunet_gnsrecord::{RecordData, RecordType};
use std::collections::{BTreeMap, BTreeSet};

fn label(id: Identifier) -> Result<Vec<u8>, Error> {
    let mut bytes = vec![0; business::IDENTIFIER_LABEL_BYTES];
    business::identifier_label(id, &mut bytes)?;
    Ok(bytes)
}
fn capability(id: Identifier, issuer: ZoneKey) -> Result<Vec<u8>, Error> {
    let mut bytes = label(id)?;
    bytes.push(b'.');
    let mut zone = [0; gnunet_gnsrecord::ZONE_TEXT_LEN];
    bytes.extend_from_slice(issuer.write_ztld(&mut zone)?.as_bytes());
    Ok(bytes)
}
fn row(name: &[u8], records: &[RecordData<'_>]) -> Result<Row, Error> {
    let mut data = vec![0; gnunet_gnsrecord::serialized_len(records)?];
    gnunet_gnsrecord::serialize(records, &mut data)?;
    Ok(Row {
        label: name.to_vec(),
        data,
        count: u16::try_from(records.len()).map_err(|_| Error::Capacity)?,
    })
}
fn record(kind: RecordType, data: &[u8], expiration: u64) -> RecordData<'_> {
    RecordData {
        record_type: kind,
        data,
        expiration_time: expiration,
        flags: RecordFlags::from_bits_preserve(0x4010),
    }
}
fn attribute(id: Identifier, credential: Identifier, name: &[u8]) -> Result<Vec<u8>, Error> {
    let mut value = Attribute::new(
        id,
        credential,
        AttributeType::STRING,
        Name::new(name)?,
        Sensitive::new(b"public mock value\0"),
    );
    value.flags = 0x1234;
    value.reserved = [17, 29];
    let mut bytes = vec![0; value.encoded_len()?];
    value.encode(&mut bytes)?;
    Ok(bytes)
}
fn credential(id: Identifier) -> Result<Vec<u8>, Error> {
    let mut value = Credential::new(
        id,
        CredentialType::JWT,
        Name::new(b"public credential")?,
        Sensitive::new(b"h.e30.s\0"),
    );
    value.flags = 0x3456;
    value.reserved = [19, 31];
    let mut bytes = vec![0; value.encoded_len()?];
    value.encode(&mut bytes)?;
    Ok(bytes)
}
fn presentation(id: Identifier) -> Result<Vec<u8>, Error> {
    let mut value = Presentation::new(id, CredentialType::JWT, Sensitive::new(b"h.e30.s\0"));
    value.ignored_flags = 0x5678;
    value.ignored_words = [7, 11, 13];
    let mut bytes = vec![0; value.encoded_len()?];
    value.encode(&mut bytes)?;
    Ok(bytes)
}
fn copy(row: &Row) -> Row {
    Row {
        label: row.label.clone(),
        data: row.data.clone(),
        count: row.count,
    }
}
fn scan_store(job: &mut Job, source: &Source, store: &BTreeMap<Vec<u8>, Row>) -> Result<(), Error> {
    let rows = store.values().collect::<Vec<_>>();
    scan(job, source, &rows)
}
fn apply(store: &mut BTreeMap<Vec<u8>, Row>, row: &Row) {
    if row.count == 0 {
        store.remove(&row.label);
    } else {
        store.insert(row.label.clone(), copy(row));
    }
}
fn consume(
    factory: &Factory,
    source: &Source,
    capability: &[u8],
    store: &BTreeMap<Vec<u8>, Row>,
) -> Result<Job, Error> {
    let mut job = factory.start(
        Request::ConsumeTicket {
            rid: 81,
            ticket: Ticket::new(capability)?,
            uri: Uri::new(b"https://public.example")?,
        },
        10,
        1000,
    )?;
    for _ in 0..16 {
        if job.response().is_some() {
            return Ok(job);
        }
        let name = match job.prepared()?.ok_or(Error::NotReady)?.action {
            Action::Lookup { label, .. } => label.to_vec(),
            _ => return Err(Error::Conflict),
        };
        let public = if let Some(row) = store.get(&name) {
            let records = row
                .view()?
                .records()
                .iter()
                .collect::<Result<Vec<_>, _>>()?;
            let records = records
                .into_iter()
                .filter(|r| !r.flags.contains(RecordFlags::PRIVATE))
                .collect::<Vec<_>>();
            self::row(&name, &records)?
        } else {
            self::row(&name, &[])?
        };
        complete(&mut job, source, Completion::Records(public.view()?))?;
    }
    Err(Error::Capacity)
}

#[test]
fn planning_work_exhaustion_precedes_mutation_and_releases_partial_index() -> Result<(), Error> {
    let factory = Factory::new(Limits {
        work_units: 80,
        ..Limits::default()
    })?;
    let ns = factory.bind(Provider::Namestore)?;
    let baseline = factory.retained_bytes();
    let (a, b) = (Identifier::new([10; 32]), Identifier::new([11; 32]));
    let own = attribute(a, Identifier::ZERO, b"a")?;
    let dependent = attribute(b, a, b"b")?;
    let credential = credential(a)?;
    let first = row(
        &label(a)?,
        &[
            record(RecordType::RECLAIM_ATTRIBUTE, &own, 100),
            record(RecordType::RECLAIM_CREDENTIAL, &credential, 101),
        ],
    )?;
    let mut records = vec![record(RecordType::RECLAIM_ATTRIBUTE, &dependent, 200)];
    records.extend(
        (0..39).map(|ordinal| record(RecordType::new(65125), b"public extension", 201 + ordinal)),
    );
    let second = row(&label(b)?, &records)?;
    let mut job = factory.start(
        Request::DeleteCredential {
            rid: 83,
            key: key()?,
            credential: Credential::decode(&credential)?,
        },
        10,
        1000,
    )?;
    scan(&mut job, &ns, &[&first, &second])?;
    assert_eq!(job.status().end, Some(End::Failed(Error::Capacity)));
    assert_eq!(job.status().committed_stores, 0);
    assert!(!job.status().provider_debt);
    assert!(job.prepared()?.is_none());
    output_written(&mut job)?;
    assert!(job.quiescent());
    drop(job);
    assert_eq!(factory.retained_bytes(), baseline);
    Ok(())
}

#[test]
fn mixed_rotation_rewrites_cycles_once_and_old_capabilities_no_longer_resolve() -> Result<(), Error>
{
    let factory = Factory::new(Limits::default())?;
    let ns = factory.bind(Provider::Namestore)?;
    let gns = factory.bind(Provider::Gns)?;
    let identity = factory.bind(Provider::Identity)?;
    let entropy = factory.bind(Provider::Entropy)?;
    let issuer = ZoneKey::new(ZoneKeyType::Edkey, [0x11; 32]);
    let (a, b, c) = (
        Identifier::new([2; 32]),
        Identifier::new([3; 32]),
        Identifier::new([4; 32]),
    );
    let (na, nb) = (Identifier::new([30; 32]), Identifier::new([31; 32]));
    let (t, e, f) = (
        Identifier::new([20; 32]),
        Identifier::new([6; 32]),
        Identifier::new([7; 32]),
    );
    let (ticket, other) = (
        capability(Identifier::new([20; 32]), issuer)?,
        capability(Identifier::new([21; 32]), issuer)?,
    );
    let ticket_name = business::capability(Ticket::new(&ticket)?)?.0.to_vec();
    let other_name = business::capability(Ticket::new(&other)?)?.0.to_vec();
    let (aa, ab, ac, ca, cb, pa, pb) = (
        attribute(a, b, b"a")?,
        attribute(b, a, b"b")?,
        attribute(c, a, b"c")?,
        credential(a)?,
        credential(b)?,
        presentation(a)?,
        presentation(b)?,
    );
    let (at, ae, af, ct, ce, pt, pe) = (
        attribute(t, Identifier::ZERO, b"ticket object")?,
        attribute(e, t, b"e")?,
        attribute(f, e, b"f")?,
        credential(t)?,
        credential(e)?,
        presentation(t)?,
        presentation(e)?,
    );
    let original_a = row(
        &label(a)?,
        &[
            record(RecordType::RECLAIM_ATTRIBUTE, &aa, 101),
            record(RecordType::RECLAIM_ATTRIBUTE, &aa, 102),
            record(RecordType::RECLAIM_CREDENTIAL, &ca, 103),
            record(RecordType::RECLAIM_ATTRIBUTE_REF, b.bytes(), 104),
            record(RecordType::RECLAIM_ATTRIBUTE_REF, b.bytes(), 105),
            record(RecordType::new(65123), b"opaque\0extension", 106),
            record(RecordType::new(65123), b"opaque\0extension", 106),
        ],
    )?;
    let original_b = row(
        &label(b)?,
        &[
            record(RecordType::RECLAIM_ATTRIBUTE, &ab, 201),
            record(RecordType::RECLAIM_CREDENTIAL, &cb, 202),
            record(RecordType::RECLAIM_ATTRIBUTE_REF, a.bytes(), 203),
            record(RecordType::RECLAIM_PRESENTATION, &pa, 204),
        ],
    )?;
    let original_c = row(
        &label(c)?,
        &[
            record(RecordType::RECLAIM_ATTRIBUTE, &ac, 301),
            record(RecordType::RECLAIM_ATTRIBUTE_REF, b.bytes(), 302),
            record(RecordType::RECLAIM_PRESENTATION, &pb, 303),
            record(RecordType::RECLAIM_ATTRIBUTE_REF, t.bytes(), 304),
            record(RecordType::RECLAIM_PRESENTATION, &pt, 305),
        ],
    )?;
    let original_e = row(
        &label(e)?,
        &[
            record(RecordType::RECLAIM_ATTRIBUTE, &ae, 601),
            record(RecordType::RECLAIM_CREDENTIAL, &ce, 602),
            record(RecordType::RECLAIM_ATTRIBUTE_REF, a.bytes(), 603),
        ],
    )?;
    let original_f = row(
        &label(f)?,
        &[record(RecordType::RECLAIM_ATTRIBUTE, &af, 701)],
    )?;
    let mut store = BTreeMap::new();
    for source in [
        &original_a,
        &original_b,
        &original_c,
        &original_e,
        &original_f,
    ] {
        store.insert(source.label.clone(), copy(source));
    }
    let selected = row(
        &ticket_name,
        &[
            record(RecordType::RECLAIM_ATTRIBUTE_REF, a.bytes(), 401),
            record(RecordType::RECLAIM_ATTRIBUTE_REF, b.bytes(), 402),
            record(RecordType::RECLAIM_ATTRIBUTE_REF, a.bytes(), 403),
            record(RecordType::TXT, b"https://public.example", 404),
            record(RecordType::RECLAIM_ATTRIBUTE, &at, 405),
            record(RecordType::RECLAIM_CREDENTIAL, &ct, 406),
            record(RecordType::RECLAIM_ATTRIBUTE_REF, e.bytes(), 407),
            record(RecordType::RECLAIM_ATTRIBUTE_REF, t.bytes(), 408),
        ],
    )?;
    store.insert(selected.label.clone(), selected);
    let remaining = row(
        &other_name,
        &[
            record(RecordType::RECLAIM_ATTRIBUTE_REF, a.bytes(), 501),
            record(RecordType::RECLAIM_ATTRIBUTE_REF, b.bytes(), 502),
            record(RecordType::RECLAIM_ATTRIBUTE_REF, c.bytes(), 503),
            record(RecordType::RECLAIM_PRESENTATION, &pa, 504),
            record(RecordType::RECLAIM_PRESENTATION, &pb, 505),
            record(RecordType::TXT, b"https://public.example", 506),
            record(RecordType::RECLAIM_ATTRIBUTE_REF, e.bytes(), 507),
            record(RecordType::RECLAIM_ATTRIBUTE_REF, f.bytes(), 508),
            record(RecordType::RECLAIM_PRESENTATION, &pt, 509),
            record(RecordType::RECLAIM_PRESENTATION, &pe, 510),
        ],
    )?;
    store.insert(remaining.label.clone(), remaining);
    // The normal snapshot contains over two thousand records, within the same
    // default rows/records/bytes/work limits. Unrelated extension groups must
    // neither require quadratic planning work nor be normalized or rewritten.
    let mut extensions = Vec::new();
    for index in 0..9 {
        let name = format!("public-extension-{index}");
        let records = (0..240)
            .map(|ordinal| {
                record(
                    RecordType::new(65124),
                    b"public opaque\0bytes",
                    1000 + ordinal,
                )
            })
            .collect::<Vec<_>>();
        let extension = row(name.as_bytes(), &records)?;
        store.insert(extension.label.clone(), copy(&extension));
        extensions.push(extension);
    }
    assert!(
        store
            .values()
            .map(|row| usize::from(row.count))
            .sum::<usize>()
            > 2000
    );
    let mut revoke = factory.start(
        Request::RevokeTicket {
            rid: 80,
            key: key()?,
            ticket: Ticket::new(&ticket)?,
        },
        10,
        1000,
    )?;
    complete(&mut revoke, &identity, Completion::PublicKey(issuer))?;
    scan_store(&mut revoke, &ns, &store)?;
    complete(&mut revoke, &entropy, Completion::Identifier(na))?;
    complete(&mut revoke, &entropy, Completion::Identifier(nb))?;
    let mut labels = BTreeSet::new();
    let mut writes = 0;
    while revoke.response().is_none() {
        let change = prepared_row(&revoke)?;
        assert!(labels.insert(change.label.clone()));
        if change.count == 0 && change.label == label(a)? {
            assert!(store.contains_key(&label(na)?));
        }
        if change.count == 0 && change.label == label(b)? {
            assert!(store.contains_key(&label(nb)?));
        }
        apply(&mut store, &change);
        complete(&mut revoke, &ns, Completion::Stored(0))?;
        writes += 1;
        if writes > 16 {
            return Err(Error::Capacity);
        }
    }
    assert_eq!(writes, 9);
    for original in &extensions {
        let retained = store.get(&original.label).ok_or(Error::NotFound)?;
        assert_eq!(retained.count, original.count);
        assert_eq!(retained.data, original.data);
    }
    assert!(matches!(
        revoke.response().ok_or(Error::NotReady)?.response()?,
        Response::Revoked { result: 1, .. }
    ));
    assert!(!store.contains_key(&ticket_name));
    for id in [a, b, t, e, f] {
        assert!(!store.contains_key(&label(id)?));
    }
    for (old, new_id, parent_id, original) in [(a, na, nb, &original_a), (b, nb, na, &original_b)] {
        let moved = store.get(&label(new_id)?).ok_or(Error::NotFound)?;
        assert_eq!(moved.count, original.count);
        for (before, after) in original
            .view()?
            .records()
            .iter()
            .zip(moved.view()?.records().iter())
        {
            let (before, after) = (before?, after?);
            assert_eq!(
                (after.record_type, after.flags, after.expiration_time),
                (before.record_type, before.flags, before.expiration_time)
            );
            match after.record_type {
                RecordType::RECLAIM_ATTRIBUTE => {
                    let value = Attribute::decode(after.data)?;
                    assert_eq!(value.id, new_id);
                    assert_eq!(value.credential, parent_id);
                    assert_eq!((value.flags, value.reserved), (0x1234, [17, 29]));
                }
                RecordType::RECLAIM_CREDENTIAL => {
                    let value = Credential::decode(after.data)?;
                    assert_eq!(value.id, new_id);
                    assert_eq!((value.flags, value.reserved), (0x3456, [19, 31]));
                }
                RecordType::RECLAIM_ATTRIBUTE_REF => {
                    assert_eq!(Identifier::decode(after.data)?, parent_id)
                }
                RecordType::RECLAIM_PRESENTATION => {
                    let value = Presentation::decode(after.data)?;
                    assert_eq!(value.credential, parent_id);
                    assert_eq!(
                        (value.ignored_flags, value.ignored_words),
                        (0x5678, [7, 11, 13])
                    );
                }
                _ => assert_eq!(after.data, before.data),
            }
        }
        assert!(!store.contains_key(&label(old)?));
    }
    let current_c = store.get(&label(c)?).ok_or(Error::NotFound)?;
    let c_record = current_c
        .view()?
        .records()
        .iter()
        .next()
        .ok_or(Error::NotFound)??;
    assert_eq!(Attribute::decode(c_record.data)?.credential, na);
    assert_eq!(current_c.count, 3);
    for record in current_c.view()?.records().iter() {
        let record = record?;
        if record.record_type == RecordType::RECLAIM_ATTRIBUTE_REF {
            assert_eq!(Identifier::decode(record.data)?, nb);
        }
        if record.record_type == RecordType::RECLAIM_PRESENTATION {
            assert_eq!(Presentation::decode(record.data)?.credential, nb);
        }
    }
    output_written(&mut revoke)?;
    drop(revoke);
    let mut denied = consume(&factory, &gns, &ticket, &store)?;
    assert!(matches!(
        denied.response().ok_or(Error::NotReady)?.response()?,
        Response::Consumed { result: 0, .. }
    ));
    output_written(&mut denied)?;
    drop(denied);
    let mut allowed = consume(&factory, &gns, &other, &store)?;
    let Response::Consumed {
        result: 1,
        attributes,
        presentations,
        ..
    } = allowed.response().ok_or(Error::NotReady)?.response()?
    else {
        return Err(Error::Authentication);
    };
    assert_eq!(
        attributes.iter().map(|a| a.id).collect::<Vec<_>>(),
        [na, na, nb, c]
    );
    assert_eq!(
        presentations
            .iter()
            .map(|p| p.credential)
            .collect::<Vec<_>>(),
        [na, nb]
    );
    output_written(&mut allowed)?;
    Ok(())
}

#[test]
fn original_new_store_refusal_or_unknown_never_admits_old_delete_or_replays() -> Result<(), Error> {
    for unknown in [false, true] {
        let factory = Factory::new(Limits::default())?;
        let ns = factory.bind(Provider::Namestore)?;
        let identity = factory.bind(Provider::Identity)?;
        let entropy = factory.bind(Provider::Entropy)?;
        let issuer = ZoneKey::new(ZoneKeyType::Edkey, [0x11; 32]);
        let old = Identifier::new([2; 32]);
        let new = Identifier::new([30; 32]);
        let ticket = capability(Identifier::new([20; 32]), issuer)?;
        let ticket_name = business::capability(Ticket::new(&ticket)?)?.0.to_vec();
        let bytes = attribute(old, Identifier::ZERO, b"public")?;
        let original = row(
            &label(old)?,
            &[
                record(RecordType::RECLAIM_ATTRIBUTE, &bytes, 101),
                record(RecordType::RECLAIM_ATTRIBUTE_REF, old.bytes(), 102),
            ],
        )?;
        let authorization = row(
            &ticket_name,
            &[record(RecordType::RECLAIM_ATTRIBUTE_REF, old.bytes(), 201)],
        )?;
        let mut store = BTreeMap::new();
        store.insert(original.label.clone(), original);
        store.insert(authorization.label.clone(), authorization);
        let mut job = factory.start(
            Request::RevokeTicket {
                rid: 82,
                key: key()?,
                ticket: Ticket::new(&ticket)?,
            },
            10,
            1000,
        )?;
        complete(&mut job, &identity, Completion::PublicKey(issuer))?;
        scan_store(&mut job, &ns, &store)?;
        complete(&mut job, &entropy, Completion::Identifier(new))?;
        let first = prepared_row(&job)?;
        assert_eq!(first.count, 0);
        assert_eq!(first.label, ticket_name);
        apply(&mut store, &first);
        complete(&mut job, &ns, Completion::Stored(0))?;
        let pending = prepared_row(&job)?;
        assert_eq!(pending.label, label(new)?);
        assert!(pending.count != 0);
        let original_effect = admitted(&mut job, &ns)?;
        if unknown {
            apply(&mut store, &pending);
        }
        job.complete(
            &original_effect,
            &ns,
            if unknown {
                Completion::Unknown
            } else {
                Completion::Stored(7)
            },
            10,
        )?;
        assert_eq!(job.status().committed_stores, 1);
        assert!(job.prepared()?.is_none());
        assert!(!job.status().provider_debt);
        assert!(store.contains_key(&label(old)?));
        if unknown {
            assert_eq!(job.status().end, Some(End::Unknown));
            assert!(job.status().outcome_unknown);
            assert!(job.response().is_none());
        } else {
            assert_eq!(job.status().provider_code, Some(7));
            assert!(matches!(
                job.response().ok_or(Error::NotReady)?.response()?,
                Response::Revoked {
                    result: u32::MAX,
                    ..
                }
            ));
            output_written(&mut job)?;
        }
        assert!(job.prepared()?.is_none());
        assert!(job.quiescent());
    }
    Ok(())
}

#[test]
fn deleting_mixed_group_closes_credential_dependencies_without_restoring_ticket_rows()
-> Result<(), Error> {
    for delete_credential in [false, true] {
        let factory = Factory::new(Limits::default())?;
        let ns = factory.bind(Provider::Namestore)?;
        let gns = factory.bind(Provider::Gns)?;
        let baseline = factory.retained_bytes();
        let issuer = ZoneKey::new(ZoneKeyType::Edkey, [0x11; 32]);
        let (a, b, c, d) = (
            Identifier::new([2; 32]),
            Identifier::new([3; 32]),
            Identifier::new([4; 32]),
            Identifier::new([5; 32]),
        );
        let dangling = Identifier::new([22; 32]);
        let (aa, ab, independent_b, ac, ad) = (
            attribute(a, Identifier::ZERO, b"a")?,
            attribute(b, a, b"b")?,
            attribute(b, Identifier::ZERO, b"independent b")?,
            attribute(c, b, b"c")?,
            attribute(d, Identifier::ZERO, b"d")?,
        );
        let (ca, cb, cd) = (credential(a)?, credential(b)?, credential(d)?);
        let (pa, pb, pd) = (presentation(a)?, presentation(b)?, presentation(d)?);
        let (cap_a, cap_b, cap_d) = (
            capability(a, issuer)?,
            capability(b, issuer)?,
            capability(d, issuer)?,
        );
        let mut ticket_a = cap_a.clone();
        ticket_a.push(0);
        let mut ticket_b = cap_b;
        ticket_b.push(0);
        let mut ticket_d = cap_d.clone();
        ticket_d.push(0);
        let original_a = row(
            &label(a)?,
            &[
                record(RecordType::RECLAIM_ATTRIBUTE, &aa, 101),
                record(RecordType::RECLAIM_CREDENTIAL, &ca, 102),
                record(RecordType::RECLAIM_TICKET, &ticket_a, 103),
                record(RecordType::RECLAIM_ATTRIBUTE_REF, b.bytes(), 104),
            ],
        )?;
        let original_b = row(
            &label(b)?,
            &[
                record(RecordType::RECLAIM_ATTRIBUTE, &ab, 201),
                record(RecordType::RECLAIM_ATTRIBUTE, &independent_b, 202),
                record(RecordType::RECLAIM_CREDENTIAL, &cb, 203),
                record(RecordType::RECLAIM_TICKET, &ticket_b, 204),
                record(RecordType::RECLAIM_ATTRIBUTE_REF, a.bytes(), 205),
                record(RecordType::RECLAIM_PRESENTATION, &pa, 206),
            ],
        )?;
        let original_c = row(
            &label(c)?,
            &[
                record(RecordType::RECLAIM_ATTRIBUTE, &ac, 301),
                record(RecordType::RECLAIM_ATTRIBUTE_REF, b.bytes(), 302),
                record(RecordType::new(65123), b"public extension", 303),
            ],
        )?;
        let survivor = row(
            &label(d)?,
            &[
                record(RecordType::RECLAIM_ATTRIBUTE, &ad, 401),
                record(RecordType::RECLAIM_CREDENTIAL, &cd, 402),
                record(RecordType::RECLAIM_ATTRIBUTE_REF, a.bytes(), 403),
                record(RecordType::RECLAIM_ATTRIBUTE_REF, a.bytes(), 404),
                record(RecordType::RECLAIM_ATTRIBUTE_REF, b.bytes(), 405),
                record(RecordType::RECLAIM_ATTRIBUTE_REF, c.bytes(), 406),
                record(RecordType::RECLAIM_ATTRIBUTE_REF, dangling.bytes(), 407),
                record(RecordType::RECLAIM_ATTRIBUTE_REF, d.bytes(), 408),
                record(RecordType::RECLAIM_PRESENTATION, &pa, 409),
                record(RecordType::RECLAIM_PRESENTATION, &pb, 410),
                record(RecordType::RECLAIM_PRESENTATION, &pd, 411),
                record(RecordType::RECLAIM_TICKET, &ticket_d, 412),
                record(RecordType::TXT, b"https://public.example", 413),
                record(RecordType::new(65123), b"public extension", 414),
                record(RecordType::new(65123), b"public extension", 415),
            ],
        )?;
        let mut store = BTreeMap::new();
        for source in [&original_a, &original_b, &original_c, &survivor] {
            store.insert(source.label.clone(), copy(source));
        }
        let request = if delete_credential {
            Request::DeleteCredential {
                rid: 83,
                key: key()?,
                credential: Credential::decode(&ca)?,
            }
        } else {
            Request::DeleteAttribute {
                rid: 83,
                key: key()?,
                attribute: Attribute::decode(&aa)?,
            }
        };
        let mut job = factory.start(request, 10, 1000)?;
        scan_store(&mut job, &ns, &store)?;
        let mut labels = BTreeSet::new();
        while job.response().is_none() {
            let change = prepared_row(&job)?;
            assert!(labels.insert(change.label.clone()));
            if change.label != label(d)? {
                assert_eq!(change.count, 0);
            }
            apply(&mut store, &change);
            complete(&mut job, &ns, Completion::Stored(0))?;
            if labels.len() > 4 {
                return Err(Error::Capacity);
            }
        }
        assert_eq!(labels.len(), 4);
        assert!(matches!(
            job.response().ok_or(Error::NotReady)?.response()?,
            Response::Success { result: 1, .. }
        ));
        for id in [a, b, c] {
            assert!(!store.contains_key(&label(id)?));
        }
        assert_eq!(store.len(), 1);
        let updated = store.get(&label(d)?).ok_or(Error::NotFound)?;
        let mut expected = Vec::new();
        for item in survivor.view()?.records().iter() {
            let item = item?;
            let keep = match item.record_type {
                RecordType::RECLAIM_ATTRIBUTE_REF => Identifier::decode(item.data)? == d,
                RecordType::RECLAIM_PRESENTATION => {
                    Presentation::decode(item.data)?.credential == d
                }
                _ => true,
            };
            if keep {
                expected.push(item);
            }
        }
        assert_eq!(usize::from(updated.count), expected.len());
        for (before, after) in expected.iter().zip(updated.view()?.records().iter()) {
            let after = after?;
            assert_eq!(
                (
                    after.record_type,
                    after.flags,
                    after.expiration_time,
                    after.data
                ),
                (
                    before.record_type,
                    before.flags,
                    before.expiration_time,
                    before.data
                )
            );
        }
        output_written(&mut job)?;
        drop(job);
        let mut denied = consume(&factory, &gns, &cap_a, &store)?;
        assert!(matches!(
            denied.response().ok_or(Error::NotReady)?.response()?,
            Response::Consumed { result: 0, .. }
        ));
        output_written(&mut denied)?;
        drop(denied);
        let mut allowed = consume(&factory, &gns, &cap_d, &store)?;
        let Response::Consumed {
            result: 1,
            attributes,
            presentations,
            ..
        } = allowed.response().ok_or(Error::NotReady)?.response()?
        else {
            return Err(Error::Authentication);
        };
        assert_eq!(
            attributes
                .iter()
                .map(|attribute| attribute.id)
                .collect::<Vec<_>>(),
            [d]
        );
        assert_eq!(
            presentations
                .iter()
                .map(|presentation| presentation.credential)
                .collect::<Vec<_>>(),
            [d]
        );
        output_written(&mut allowed)?;
        drop(allowed);
        assert_eq!(factory.retained_bytes(), baseline);
    }
    Ok(())
}
