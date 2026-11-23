use super::*;
use crate::{
    DnsPolicy, Failure, Lookup, Policy,
    fixed::{Effect, EffectKind, Instance, Resolver},
};
use gnunet_crypto::gns::EdkeySecret;
use gnunet_gnscrypto::{Label, ZoneSecret};

fn record(record_type: RecordType, data: &[u8]) -> RecordData<'_> {
    RecordData {
        record_type,
        data,
        expiration_time: 200,
        flags: RecordFlags::NONE,
    }
}

fn encrypted<'a>(
    secret: &ZoneSecret,
    label: &str,
    records: &[RecordData<'_>],
    output: &'a mut [u8],
) -> Result<&'a [u8], Error> {
    let mut scalar = ['\0'; 40];
    let mut normalized = [0; 40];
    let label = Label::normalize(label, &mut scalar, &mut normalized)?;
    let mut clear = [0; 512];
    let len = gnunet_gnsrecord::serialize(records, &mut clear)?;
    Ok(secret.seal(label, 500, &clear[..len], output)?.as_bytes())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assert the exact candidate sequence and local capacity outcome"
)]
fn signed_bridge_tries_all_servers_within_its_byte_capacity() -> Result<(), Error> {
    let secret = ZoneSecret::Edkey(EdkeySecret::from_seed([39; 32]));
    let request = Lookup {
        zone: secret.public_key(),
        name: "www.bridge",
        record_type: RecordType::A,
        policy: Policy::LocalOnly,
        recursion_limit: 2,
    };
    let records = [
        record(RecordType::GNS2DNS, b"example\x00192.0.2.1\0"),
        record(RecordType::GNS2DNS, b"example\x00192.0.2.2\0"),
        record(RecordType::GNS2DNS, b"example\x00192.0.2.3\0"),
        record(RecordType::GNS2DNS, b"example\x00192.0.2.4\0"),
        record(RecordType::GNS2DNS, b"example\x00192.0.2.5\0"),
    ];
    let mut cipher = [0; 768];
    let block = encrypted(&secret, "bridge", &records, &mut cipher)?;
    let mut plain = [0; 512];
    let mut output = [0; 256];
    let mut memory = Instance::new();
    let mut resolver = Resolver::<1, 1>::new(&mut memory);
    let query = resolver.lookup(request)?;
    resolver.revoked(resolver.effect(query)?.ok_or(Error::NotReady)?.id, false)?;
    let id = resolver.effect(query)?.ok_or(Error::NotReady)?.id;
    resolver.cached(id, Some(block), 100, &mut plain, &mut output)?;
    for last in 1..=5 {
        let Effect { id, kind, .. } = resolver.effect(query)?.ok_or(Error::NotReady)?;
        assert!(matches!(
            kind,
            EffectKind::Dns { name: "www.example", server, .. }
                if server.address() == IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
        ));
        if last < 5 {
            resolver.failed(id, Error::Timeout)?;
        } else {
            resolver.resolved(
                id,
                &[record(RecordType::A, &[192, 0, 2, 55])],
                1,
                101,
                &mut output,
            )?;
        }
    }
    assert!(matches!(
        resolver.outcome(query)?,
        Some(Ok(Answer {
            origin: Origin::Dns(_),
            ..
        }))
    ));

    let mut memory = Instance::new();
    let mut resolver = Resolver::<1, 1, 32>::new(&mut memory);
    let query = resolver.lookup(request)?;
    resolver.revoked(resolver.effect(query)?.ok_or(Error::NotReady)?.id, false)?;
    let id = resolver.effect(query)?.ok_or(Error::NotReady)?.id;
    resolver.cached(id, Some(block), 100, &mut plain, &mut output)?;
    assert!(resolver.effect(query)?.is_none());
    assert_eq!(
        resolver.outcome(query)?,
        Some(Err(Failure::Fault(Error::Capacity)))
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assert that denial blocks all external effects and preserves explicit reads"
)]
fn signed_external_targets_obey_the_resolver_policy() -> Result<(), Error> {
    let secret = ZoneSecret::Edkey(EdkeySecret::from_seed([40; 32]));
    let zone = secret.public_key();
    let mut memory = Instance::new();
    let mut resolver = Resolver::<1, 1, 0>::with_dns_policy(&mut memory, DnsPolicy::Deny);
    let mut cipher = [0; 512];
    let mut plain = [0; 256];
    let mut output = [0; 256];
    for source in [
        record(RecordType::GNS2DNS, b"example\x00192.0.2.53\0"),
        record(RecordType::REDIRECT, b"other.example\0"),
        record(RecordType::CNAME, b"\x05other\x07example\0"),
    ] {
        let block = encrypted(&secret, "alias", &[source], &mut cipher)?;
        for desired in [RecordType::A, source.record_type] {
            let query = resolver.lookup(Lookup {
                zone,
                name: "alias",
                record_type: desired,
                policy: Policy::LocalOnly,
                recursion_limit: 2,
            })?;
            resolver.revoked(resolver.effect(query)?.ok_or(Error::NotReady)?.id, false)?;
            let id = resolver.effect(query)?.ok_or(Error::NotReady)?.id;
            resolver.cached(id, Some(block), 100, &mut plain, &mut output)?;
            assert!(resolver.effect(query)?.is_none());
            if desired == RecordType::A {
                assert_eq!(resolver.outcome(query)?, Some(Err(Failure::DnsDisabled)));
            } else {
                assert!(matches!(
                    resolver.outcome(query)?,
                    Some(Ok(Answer { origin: Origin::Gns(source_zone), records: 1, .. }))
                        if source_zone == zone
                ));
            }
            resolver.cancel(query)?;
        }
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assert that nested exhaustion keeps its local capacity failure"
)]
fn nested_target_capacity_is_preserved_when_the_parent_has_no_fallback() -> Result<(), Error> {
    let secret = ZoneSecret::Edkey(EdkeySecret::from_seed([42; 32]));
    let mut memory = Instance::new();
    let mut resolver = Resolver::<1, 2, 32>::new(&mut memory);
    let query = resolver.lookup(Lookup {
        zone: secret.public_key(),
        name: "outer",
        record_type: RecordType::A,
        policy: Policy::LocalOnly,
        recursion_limit: 2,
    })?;
    let mut cipher = [0; 512];
    let mut plain = [0; 256];
    let mut output = [0; 256];
    let outer = [record(RecordType::GNS2DNS, b"example\0inner.+\0")];
    let inner = [
        record(RecordType::GNS2DNS, b"inner.test\x00192.0.2.1\0"),
        record(RecordType::GNS2DNS, b"inner.test\x00192.0.2.2\0"),
        record(RecordType::GNS2DNS, b"inner.test\x00192.0.2.3\0"),
    ];
    for (label, records) in [("outer", outer.as_slice()), ("inner", inner.as_slice())] {
        resolver.revoked(resolver.effect(query)?.ok_or(Error::NotReady)?.id, false)?;
        let Effect { id, kind, .. } = resolver.effect(query)?.ok_or(Error::NotReady)?;
        assert!(matches!(kind, EffectKind::Cache { label: actual, .. } if actual == label));
        let block = encrypted(&secret, label, records, &mut cipher)?;
        resolver.cached(id, Some(block), 100, &mut plain, &mut output)?;
    }
    assert!(resolver.effect(query)?.is_none());
    assert_eq!(
        resolver.outcome(query)?,
        Some(Err(Failure::Fault(Error::Capacity)))
    );
    assert!(resolver.bridges.iter().all(Option::is_none));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assert distinct live address order and retention of the longest lease"
)]
fn hostname_addresses_are_filtered_and_deduplicated_before_budgeting() -> Result<(), Error> {
    let secret = ZoneSecret::Edkey(EdkeySecret::from_seed([43; 32]));
    let mut memory = Instance::new();
    let mut resolver = Resolver::<1, 1, 64, 5>::new(&mut memory);
    let query = resolver.lookup(Lookup {
        zone: secret.public_key(),
        name: "bridge",
        record_type: RecordType::A,
        policy: Policy::LocalOnly,
        recursion_limit: 2,
    })?;
    resolver.revoked(resolver.effect(query)?.ok_or(Error::NotReady)?.id, false)?;
    let mut cipher = [0; 512];
    let block = encrypted(
        &secret,
        "bridge",
        &[record(RecordType::GNS2DNS, b"example\0ns.example\0")],
        &mut cipher,
    )?;
    let id = resolver.effect(query)?.ok_or(Error::NotReady)?.id;
    resolver.cached(id, Some(block), 100, &mut [0; 256], &mut [0; 256])?;
    let Effect { id, kind, .. } = resolver.effect(query)?.ok_or(Error::NotReady)?;
    assert!(matches!(
        kind,
        EffectKind::Nameserver {
            name: "ns.example",
            ..
        }
    ));

    let address = |last, valid_through| DnsAddress {
        address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)),
        valid_through,
    };
    let supplied = [
        address(0, 99),
        address(1, 160),
        address(2, 190),
        address(3, 190),
        address(4, 190),
        address(5, 190),
        address(1, 190),
    ];
    resolver.nameserver(id, &supplied, 1)?;
    for last in 1..=5 {
        let Effect {
            id,
            kind,
            valid_through,
            ..
        } = resolver.effect(query)?.ok_or(Error::NotReady)?;
        assert_eq!(valid_through, Some(190));
        assert!(matches!(
            kind,
            EffectKind::Dns { server, .. }
                if server.address() == address(last, 190).address
                    && server.identity() == DnsServerIdentity::Hostname("ns.example")
        ));
        resolver.failed(id, Error::Timeout)?;
    }
    assert_eq!(resolver.outcome(query)?, Some(Err(Failure::NotFound)));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assert that combined address overflow falls back without partial use"
)]
fn nested_dns_address_overflow_skips_the_partial_address_set() -> Result<(), Error> {
    let secret = ZoneSecret::Edkey(EdkeySecret::from_seed([44; 32]));
    let mut memory = Instance::new();
    let mut resolver = Resolver::<1, 2, 64, 2>::new(&mut memory);
    let query = resolver.lookup(Lookup {
        zone: secret.public_key(),
        name: "outer",
        record_type: RecordType::A,
        policy: Policy::LocalOnly,
        recursion_limit: 2,
    })?;
    let mut cipher = [0; 512];
    let mut plain = [0; 256];
    let mut output = [0; 256];
    let outer = [
        record(RecordType::GNS2DNS, b"example\0inner.+\0"),
        record(RecordType::GNS2DNS, b"example\x00198.51.100.53\0"),
    ];
    let inner = [record(RecordType::GNS2DNS, b"inner.test\x00192.0.2.53\0")];
    for (label, records) in [("outer", outer.as_slice()), ("inner", inner.as_slice())] {
        resolver.revoked(resolver.effect(query)?.ok_or(Error::NotReady)?.id, false)?;
        let id = resolver.effect(query)?.ok_or(Error::NotReady)?.id;
        let block = encrypted(&secret, label, records, &mut cipher)?;
        resolver.cached(id, Some(block), 100, &mut plain, &mut output)?;
    }
    let Effect { id, kind, .. } = resolver.effect(query)?.ok_or(Error::NotReady)?;
    assert!(matches!(
        kind,
        EffectKind::Dns {
            name: "inner.test",
            record_type: RecordType::A,
            ..
        }
    ));
    resolver.resolved(
        id,
        &[
            record(RecordType::A, &[192, 0, 2, 1]),
            record(RecordType::A, &[192, 0, 2, 2]),
        ],
        1,
        100,
        &mut output,
    )?;
    let Effect { id, kind, .. } = resolver.effect(query)?.ok_or(Error::NotReady)?;
    assert!(matches!(
        kind,
        EffectKind::Dns {
            name: "inner.test",
            record_type: RecordType::AAAA,
            ..
        }
    ));
    resolver.resolved(
        id,
        &[record(RecordType::AAAA, &Ipv6Addr::LOCALHOST.octets())],
        1,
        100,
        &mut output,
    )?;
    let Effect { id, kind, .. } = resolver.effect(query)?.ok_or(Error::NotReady)?;
    assert!(matches!(
        kind,
        EffectKind::Dns { name: "example", server, .. }
            if server.address() == IpAddr::V4(Ipv4Addr::new(198, 51, 100, 53))
    ));
    resolver.failed(id, Error::Timeout)?;
    assert_eq!(
        resolver.outcome(query)?,
        Some(Err(Failure::Fault(Error::Capacity)))
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assert deep bridge nesting and cancellation of every retained slot"
)]
fn deep_dns_nesting_uses_the_original_query_and_shared_arena_budgets() -> Result<(), Error> {
    let secret = ZoneSecret::Edkey(EdkeySecret::from_seed([45; 32]));
    let mut memory = Instance::new();
    let mut resolver = Resolver::<1, 6, 64>::new(&mut memory);
    let query = resolver.lookup(Lookup {
        zone: secret.public_key(),
        name: "n0",
        record_type: RecordType::A,
        policy: Policy::LocalOnly,
        recursion_limit: 5,
    })?;
    let mut cipher = [0; 512];
    let mut plain = [0; 256];
    let mut output = [0; 256];
    let chain: [(&str, &[u8]); 6] = [
        ("n0", b"example\0n1.+\0"),
        ("n1", b"example\0n2.+\0"),
        ("n2", b"example\0n3.+\0"),
        ("n3", b"example\0n4.+\0"),
        ("n4", b"example\0n5.+\0"),
        ("n5", b"example\x00192.0.2.53\0"),
    ];
    for (label, target) in chain {
        resolver.revoked(resolver.effect(query)?.ok_or(Error::NotReady)?.id, false)?;
        let Effect { id, kind, .. } = resolver.effect(query)?.ok_or(Error::NotReady)?;
        assert!(matches!(kind, EffectKind::Cache { label: actual, .. } if actual == label));
        let block = encrypted(
            &secret,
            label,
            &[record(RecordType::GNS2DNS, target)],
            &mut cipher,
        )?;
        resolver.cached(id, Some(block), 100, &mut plain, &mut output)?;
    }
    let Effect { id, kind, .. } = resolver.effect(query)?.ok_or(Error::NotReady)?;
    assert!(matches!(
        kind,
        EffectKind::Dns { name: "example", server, .. }
            if server.address() == IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))
    ));
    assert!(resolver.bridges.iter().all(Option::is_some));
    resolver.cancel(query)?;
    assert_eq!(resolver.failed(id, Error::Timeout), Err(Error::Stale));
    assert!(resolver.bridges.iter().all(Option::is_none));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assert original DNS lease, security record and budget"
)]
fn signed_bridge_preserves_security_and_consumes_actual_attempts() -> Result<(), Error> {
    let secret = ZoneSecret::Edkey(EdkeySecret::from_seed([37; 32]));
    let zone = secret.public_key();
    let mut scope = Instance::new();
    let mut resolver = Resolver::<1>::new(&mut scope);
    let query = resolver.lookup(Lookup {
        zone,
        name: "www.bridge",
        record_type: RecordType::A,
        policy: Policy::LocalOnly,
        recursion_limit: 2,
    })?;
    let first = resolver.effect(query)?.ok_or(Error::NotReady)?.id;
    resolver.revoked(first, false)?;
    let bridge = resolver.effect(query)?.ok_or(Error::NotReady)?.id;
    let ds = record(RecordType::new(43), b"\0\x01\x0c\x02digest");
    let mut cipher = [0; 512];
    let block = encrypted(
        &secret,
        "bridge",
        &[
            record(RecordType::GNS2DNS, b"example\0ns.+\0"),
            record(RecordType::GNS2DNS, b"example\0secondary.example\0"),
            ds,
        ],
        &mut cipher,
    )?;
    let mut plain = [0; 256];
    let mut output = [0; 256];
    resolver.cached(bridge, Some(block), 100, &mut plain, &mut output)?;

    let Effect { id, kind, .. } = resolver.effect(query)?.ok_or(Error::NotReady)?;
    assert!(matches!(kind, EffectKind::Revocation { zone: child } if child == zone));
    resolver.revoked(id, false)?;
    let Effect { id, kind, .. } = resolver.effect(query)?.ok_or(Error::NotReady)?;
    assert!(matches!(kind, EffectKind::Cache { label: "ns", .. }));
    let block = encrypted(
        &secret,
        "ns",
        &[record(RecordType::A, &[192, 0, 2, 53])],
        &mut cipher,
    )?;
    resolver.cached(id, Some(block), 100, &mut plain, &mut output)?;
    let Effect { id, kind, .. } = resolver.effect(query)?.ok_or(Error::NotReady)?;
    let EffectKind::Dns {
        name,
        authority,
        record_type,
        server: address,
        security,
        remaining_steps,
    } = kind
    else {
        return Err(Error::Conflict);
    };
    assert_eq!(
        (name, authority, record_type),
        ("www.example", "example", RecordType::A)
    );
    assert_eq!(address.address(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)));
    assert_eq!(address.identity(), DnsServerIdentity::GnsResolved);
    assert_eq!(security.iter().next().ok_or(Error::NotFound)??, ds);
    resolver.failed_counted(id, Error::Timeout, 3)?;
    assert_eq!(resolver.failed(id, Error::Timeout), Err(Error::Stale));

    let Effect { id, kind, .. } = resolver.effect(query)?.ok_or(Error::NotReady)?;
    assert!(
        matches!(kind, EffectKind::Nameserver { name: "secondary.example", remaining_steps: left } if left + 4 == remaining_steps)
    );
    resolver.nameserver(
        id,
        &[
            DnsAddress {
                address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 54)),
                valid_through: 99,
            },
            DnsAddress {
                address: "2001:db8::53".parse().map_err(|_| Error::Malformed)?,
                valid_through: 151,
            },
            DnsAddress {
                address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 55)),
                valid_through: 190,
            },
        ],
        1,
    )?;
    let Effect {
        id,
        kind,
        valid_through,
        ..
    } = resolver.effect(query)?.ok_or(Error::NotReady)?;
    let EffectKind::Dns {
        server,
        remaining_steps: first_budget,
        ..
    } = kind
    else {
        return Err(Error::Conflict);
    };
    assert!(server.address().is_ipv6());
    assert_eq!(
        server.identity(),
        DnsServerIdentity::Hostname("secondary.example")
    );
    assert_eq!(server.valid_through(), 151);
    assert_eq!(valid_through, Some(151));
    assert_eq!(
        resolver.resolved(
            id,
            &[record(RecordType::EDKEY, zone.key())],
            1,
            100,
            &mut output
        ),
        Err(Error::Malformed)
    );
    assert_eq!(resolver.effect(query)?.ok_or(Error::NotReady)?.id, id);
    assert!(resolver.expire_at(query, 152, || Ok(1))?);
    assert_eq!(resolver.failed(id, Error::Timeout), Err(Error::Stale));
    let retry = resolver.effect(query)?.ok_or(Error::NotReady)?;
    assert_eq!(retry.valid_through, Some(190));
    assert!(matches!(
        retry.kind,
        EffectKind::Dns { server, remaining_steps, .. }
            if server.address() == IpAddr::V4(Ipv4Addr::new(192, 0, 2, 55))
                && server.identity() == DnsServerIdentity::Hostname("secondary.example")
                && remaining_steps + 2 == first_budget
    ));
    resolver.resolved(
        retry.id,
        &[record(RecordType::A, &[192, 0, 2, 9])],
        1,
        152,
        &mut output,
    )?;
    let answer = resolver
        .outcome(query)?
        .ok_or(Error::NotReady)?
        .map_err(|_| Error::Conflict)?;
    assert_eq!(
        answer.origin,
        Origin::Dns(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 55)))
    );
    let records = RecordSet::parse(&output[..answer.bytes], 2, 2)?;
    let mut records = records.iter();
    let answer = records.next().ok_or(Error::NotFound)??;
    assert_eq!(answer.data, &[192, 0, 2, 9]);
    assert_eq!(answer.expiration_time, 190);
    let leho = records.next().ok_or(Error::NotFound)??;
    assert_eq!(
        (leho.record_type, leho.data),
        (RecordType::LEHO, b"www.example".as_slice())
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assert the separate system dependency and answer provenance"
)]
fn signed_redirect_does_not_authenticate_the_system_answer() -> Result<(), Error> {
    let secret = ZoneSecret::Edkey(EdkeySecret::from_seed([38; 32]));
    let mut scope = Instance::new();
    let mut resolver = Resolver::<1>::new(&mut scope);
    let query = resolver.lookup(Lookup {
        zone: secret.public_key(),
        name: "alias",
        record_type: RecordType::TXT,
        policy: Policy::LocalOnly,
        recursion_limit: 2,
    })?;
    let first = resolver.effect(query)?.ok_or(Error::NotReady)?.id;
    resolver.revoked(first, false)?;
    let cache = resolver.effect(query)?.ok_or(Error::NotReady)?.id;
    let mut cipher = [0; 512];
    let block = encrypted(
        &secret,
        "alias",
        &[record(RecordType::REDIRECT, b"other.example\0")],
        &mut cipher,
    )?;
    let mut plain = [0; 256];
    let mut output = [0; 256];
    resolver.cached(cache, Some(block), 100, &mut plain, &mut output)?;
    let Effect { id, kind, .. } = resolver.effect(query)?.ok_or(Error::NotReady)?;
    assert!(matches!(
        kind,
        EffectKind::System {
            name: "other.example",
            record_type: RecordType::TXT,
            ..
        }
    ));
    let txt = record(RecordType::TXT, b"\x01x");
    resolver.resolved(id, &[txt], 1, 100, &mut output)?;
    let answer = resolver
        .outcome(query)?
        .ok_or(Error::NotReady)?
        .map_err(|_| Error::Conflict)?;
    assert_eq!(answer.origin, Origin::System);
    assert_eq!(answer.records, 1);
    let records = RecordSet::parse(&output[..answer.bytes], 1, 1)?;
    assert_eq!(records.iter().next().ok_or(Error::NotFound)??, txt);
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assert exact nested continuation and family leases"
)]
fn nested_signed_bridge_uses_both_families_and_resumes_original_question() -> Result<(), Error> {
    let secret = ZoneSecret::Edkey(EdkeySecret::from_seed([41; 32]));
    let mut memory = Instance::new();
    let mut resolver = Resolver::<1, 2>::new(&mut memory);
    let request = Lookup {
        zone: secret.public_key(),
        name: "www.outer",
        record_type: RecordType::TXT,
        policy: Policy::LocalOnly,
        recursion_limit: 3,
    };
    let mut plaintext = [0; 256];
    let mut output = [0; 256];
    let mut cipher = [0; 512];
    for (first_target_until, expire_at) in [(200, None), (200, Some(151)), (120, Some(121))] {
        let query = resolver.lookup(request)?;
        let id = resolver.effect(query)?.ok_or(Error::NotReady)?.id;
        resolver.revoked(id, false)?;
        let id = resolver.effect(query)?.ok_or(Error::NotReady)?.id;
        let block = encrypted(
            &secret,
            "outer",
            &[
                RecordData {
                    expiration_time: first_target_until,
                    ..record(RecordType::GNS2DNS, b"outer.test\0inner.+\0")
                },
                record(RecordType::GNS2DNS, b"outer.test\x00198.51.100.53\0"),
            ],
            &mut cipher,
        )?;
        resolver.cached(id, Some(block), 100, &mut plaintext, &mut output)?;
        let id = resolver.effect(query)?.ok_or(Error::NotReady)?.id;
        resolver.revoked(id, false)?;
        let Effect { id, kind, .. } = resolver.effect(query)?.ok_or(Error::NotReady)?;
        assert!(matches!(kind, EffectKind::Cache { label: "inner", .. }));
        let block = encrypted(
            &secret,
            "inner",
            &[RecordData {
                expiration_time: 150,
                ..record(RecordType::GNS2DNS, b"inner.test\x00192.0.2.53\0")
            }],
            &mut cipher,
        )?;
        resolver.cached(id, Some(block), 100, &mut plaintext, &mut output)?;

        let Effect {
            id,
            kind,
            valid_through,
            ..
        } = resolver.effect(query)?.ok_or(Error::NotReady)?;
        assert!(
            matches!(kind, EffectKind::Dns { name: "inner.test", record_type: RecordType::A, server, .. }
            if server.address() == IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))
                && server.identity() == DnsServerIdentity::LiteralIp
                && server.valid_through() == first_target_until.min(150))
        );
        assert_eq!(valid_through, Some(first_target_until.min(150)));
        resolver.resolved(
            id,
            &[record(RecordType::A, &[192, 0, 2, 10])],
            1,
            101,
            &mut output,
        )?;
        let Effect { id: v6, kind, .. } = resolver.effect(query)?.ok_or(Error::NotReady)?;
        assert_ne!(id, v6);
        assert!(matches!(
            kind,
            EffectKind::Dns {
                name: "inner.test",
                record_type: RecordType::AAAA,
                server,
                ..
            } if server.identity() == DnsServerIdentity::LiteralIp
                && server.valid_through() == first_target_until.min(150)
        ));

        if let Some(now) = expire_at {
            assert!(resolver.expire_at(query, now, || Ok(0))?);
            assert_eq!(resolver.failed(v6, Error::Timeout), Err(Error::Stale));
        } else {
            let address = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 10);
            resolver.resolved(
                v6,
                &[record(RecordType::AAAA, &address.octets())],
                1,
                102,
                &mut output,
            )?;
            let Effect {
                id,
                kind,
                valid_through,
                ..
            } = resolver.effect(query)?.ok_or(Error::NotReady)?;
            assert!(
                matches!(kind, EffectKind::Dns { name: "www.outer.test", record_type: RecordType::TXT, server, .. }
                if server.address() == IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))
                    && server.identity() == DnsServerIdentity::GnsResolved
                    && server.valid_through() == 150)
            );
            assert_eq!(valid_through, Some(150));
            resolver.failed_counted(id, Error::Timeout, 2)?;
            let Effect { id, kind, .. } = resolver.effect(query)?.ok_or(Error::NotReady)?;
            assert!(
                matches!(kind, EffectKind::Dns { name: "www.outer.test", record_type: RecordType::TXT, server, .. }
                if server.address() == IpAddr::V6(address)
                    && server.identity() == DnsServerIdentity::GnsResolved)
            );
            resolver.failed_counted(id, Error::Timeout, 2)?;
        }

        let Effect {
            id,
            kind,
            valid_through,
            ..
        } = resolver.effect(query)?.ok_or(Error::NotReady)?;
        assert!(
            matches!(kind, EffectKind::Dns { name: "www.outer.test", record_type: RecordType::TXT, server, .. }
            if server.address() == IpAddr::V4(Ipv4Addr::new(198, 51, 100, 53))
                && server.identity() == DnsServerIdentity::LiteralIp
                && server.valid_through() == 200)
        );
        assert_eq!(valid_through, Some(200));
        if expire_at.is_some() {
            resolver.cancel(query)?;
            assert_eq!(resolver.failed(id, Error::Timeout), Err(Error::Stale));
        } else {
            resolver.resolved(
                id,
                &[record(RecordType::TXT, b"\x01x")],
                1,
                103,
                &mut output,
            )?;
            assert!(matches!(
                resolver.outcome(query)?,
                Some(Ok(Answer { records: 2, .. }))
            ));
            resolver.cancel(query)?;
        }
        assert!(resolver.bridges.iter().all(Option::is_none));
    }
    Ok(())
}
