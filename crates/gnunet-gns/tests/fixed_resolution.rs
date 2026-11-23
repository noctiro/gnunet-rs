//! Official signed block integration through the allocation-free owner.

#![expect(clippy::panic_in_result_fn, reason = "Protocol boundary assertions")]

use gnunet_crypto::gns::{EdkeySecret, PkeySecret};
use gnunet_gns::fixed::{Effect, EffectKind, Instance, Resolver};
use gnunet_gns::{BoxRegistry, Error, Lookup, Origin, Policy, RecordData, RecordFlags, RecordType};
use gnunet_gnscrypto::{Label, ZoneSecret};
use gnunet_gnsrecord::{RecordSet, serialize};
use std::num::NonZeroU16;

fn record(
    kind: RecordType,
    expiration_time: u64,
    flags: RecordFlags,
    data: &[u8],
) -> RecordData<'_> {
    RecordData {
        expiration_time,
        record_type: kind,
        flags,
        data,
    }
}

fn block<'a>(
    secret: &ZoneSecret,
    label: &str,
    records: &[RecordData<'_>],
    output: &'a mut [u8],
) -> Result<&'a [u8], Error> {
    let mut scalars = ['\0'; 32];
    let mut normalized = [0; 32];
    let label = Label::normalize(label, &mut scalars, &mut normalized)?;
    let mut plain = [0; 256];
    let len = serialize(records, &mut plain)?;
    Ok(secret.seal(label, 1_000, &plain[..len], output)?.as_bytes())
}

#[test]
fn signed_pkey_delegation_and_edkey_shadow_keep_exact_get_and_reply_owner() -> Result<(), Error> {
    let root = ZoneSecret::Pkey(PkeySecret::from_bytes([3; 32])?);
    let child = ZoneSecret::Edkey(EdkeySecret::from_seed([7; 32]));
    let zone = root.public_key();
    let target = child.public_key();
    let mut scope = Instance::new();
    let mut resolver = Resolver::<1>::new(&mut scope);
    let lookup = Lookup {
        zone,
        name: "www.cafe\u{301}",
        record_type: RecordType::A,
        policy: Policy::LocalMaster,
        recursion_limit: 2,
    };
    let query = resolver.lookup(lookup)?;
    assert_eq!(resolver.lookup(lookup), Err(Error::WouldBlock));
    let Effect { id, kind, .. } = resolver.effect(query)?.ok_or(Error::NotReady)?;
    assert!(matches!(kind, EffectKind::Revocation { zone: actual } if actual == zone));
    resolver.revoked(id, false)?;
    let Effect { id, kind, .. } = resolver.effect(query)?.ok_or(Error::NotReady)?;
    assert!(matches!(kind, EffectKind::Cache { label: "café", .. }));
    let mut block_wire = [0; 512];
    let delegation = block(
        &root,
        "café",
        &[record(
            RecordType::EDKEY,
            200,
            RecordFlags::CRITICAL,
            target.key(),
        )],
        &mut block_wire,
    )?;
    let mut plaintext = [0; 256];
    let mut reply = [0; 256];
    resolver.cached(id, Some(delegation), 100, &mut plaintext, &mut reply)?;
    assert_eq!(
        resolver.cached(id, None, 100, &mut plaintext, &mut reply),
        Err(Error::Stale)
    );
    let Effect { id, kind, .. } = resolver.effect(query)?.ok_or(Error::NotReady)?;
    assert!(matches!(kind, EffectKind::Revocation { zone } if zone == target));
    resolver.revoked(id, false)?;
    let cache = resolver.effect(query)?.ok_or(Error::NotReady)?.id;
    resolver.cached(cache, None, 100, &mut plaintext, &mut reply)?;
    let Effect { id, kind, .. } = resolver.effect(query)?.ok_or(Error::NotReady)?;
    assert!(matches!(kind, EffectKind::Remote { zone, label: "www", .. } if zone == target));

    let malformed = block(
        &child,
        "www",
        &[record(RecordType::A, 200, RecordFlags::NONE, &[0, 1, 2])],
        &mut block_wire,
    )?;
    assert!(!resolver.remote_block(id, malformed, 100, &mut plaintext, &mut reply)?);
    assert_eq!(resolver.effect(query)?.ok_or(Error::NotReady)?.id, id);
    let shadow = record(RecordType::A, 200, RecordFlags::SHADOW, &[192, 0, 2, 1]);
    let expired = record(RecordType::A, 50, RecordFlags::NONE, &[192, 0, 2, 2]);
    let answer = block(&child, "www", &[expired, shadow], &mut block_wire)?;
    assert!(resolver.remote_block(id, answer, 100, &mut plaintext, &mut reply)?);
    assert!(plaintext.iter().all(|byte| *byte == 0));
    assert!(resolver.effect(query)?.is_none());
    let outcome = resolver
        .outcome(query)?
        .ok_or(Error::NotReady)?
        .map_err(|_| Error::NotFound)?;
    assert_eq!(outcome.records, 1);
    assert_eq!(outcome.origin, Origin::Gns(target));
    let rrset = RecordSet::parse(&reply[..outcome.bytes], 1, 1)?;
    let selected = rrset.iter().next().ok_or(Error::NotFound)??;
    assert_eq!(
        selected,
        RecordData {
            flags: RecordFlags::NONE,
            ..shadow
        }
    );
    resolver.cancel(query)?;
    assert_eq!(resolver.outcome(query), Err(Error::Stale));
    assert_ne!(resolver.lookup(lookup)?, query);
    Ok(())
}

struct ServiceNames;

impl BoxRegistry for ServiceNames {
    fn protocol(&self, name: &str) -> Option<NonZeroU16> {
        name.eq_ignore_ascii_case("tcp")
            .then_some(NonZeroU16::new(6))
            .flatten()
    }

    fn service(&self, name: &str, protocol: &str) -> Option<NonZeroU16> {
        (name.eq_ignore_ascii_case("https") && protocol.eq_ignore_ascii_case("tcp"))
            .then_some(NonZeroU16::new(443))
            .flatten()
    }
}

#[test]
fn signed_box_and_sbox_use_named_numeric_and_literal_selection() -> Result<(), Error> {
    let zone = ZoneSecret::Edkey(EdkeySecret::from_seed([28; 32]));
    let tlsa = RecordType::new(52);
    let numeric = [3, 1, 1, 0x11];
    let literal = [3, 1, 1, 0x22];
    let assigned = [3, 1, 1, 0x33];
    let box_https = [
        0, 6, 1, 187, 0, 0, 0, 52, numeric[0], numeric[1], numeric[2], numeric[3],
    ];
    let box_trust = [
        192,
        0,
        192,
        0,
        0,
        0,
        0,
        52,
        assigned[0],
        assigned[1],
        assigned[2],
        assigned[3],
    ];
    let mut sbox_https = Vec::from(tlsa.value().to_be_bytes());
    sbox_https.extend_from_slice(b"_https._tcp\0");
    sbox_https.extend_from_slice(&literal);
    let mut ciphertext = [0; 512];
    let ciphertext = block(
        &zone,
        "site",
        &[
            record(RecordType::BOX, 200, RecordFlags::NONE, &box_https),
            record(RecordType::SBOX, 200, RecordFlags::NONE, &sbox_https),
            record(RecordType::BOX, 200, RecordFlags::NONE, &box_trust),
            record(RecordType::A, 200, RecordFlags::NONE, &[192, 0, 2, 1]),
        ],
        &mut ciphertext,
    )?;
    let mut scope = Instance::new();
    let service_names = ServiceNames;
    let mut resolver = Resolver::<1>::new(&mut scope).with_box_registry(&service_names);
    let mut plaintext = [0; 256];
    let mut reply = [0; 256];
    for (name, expected) in [
        ("_https._tcp.site", [Some(numeric), Some(literal)]),
        ("_443._tcp.site", [Some(numeric), None]),
        ("_https._TCP.site", [Some(numeric), None]),
        ("_scheme._trust.site", [Some(assigned), None]),
        ("_49152._trust.site", [Some(assigned), None]),
    ] {
        let query = resolver.lookup(Lookup {
            zone: zone.public_key(),
            name,
            record_type: tlsa,
            policy: Policy::LocalOnly,
            recursion_limit: 1,
        })?;
        let mut selected = expected.into_iter().flatten();
        let id = resolver.effect(query)?.ok_or(Error::NotReady)?.id;
        resolver.revoked(id, false)?;
        let Effect { id, kind, .. } = resolver.effect(query)?.ok_or(Error::NotReady)?;
        assert!(matches!(kind, EffectKind::Cache { label: "site", .. }));
        resolver.cached(id, Some(ciphertext), 100, &mut plaintext, &mut reply)?;
        let outcome = resolver
            .outcome(query)?
            .ok_or(Error::NotReady)?
            .map_err(|_| Error::NotFound)?;
        let count = usize::try_from(outcome.records).map_err(|_| Error::Capacity)?;
        let rrset = RecordSet::parse(&reply[..outcome.bytes], count, 2)?;
        for record in rrset.iter() {
            let record = record?;
            let expected = selected.next().ok_or(Error::Conflict)?;
            assert_eq!(record.record_type, tlsa);
            assert_eq!(record.data, expected);
        }
        assert!(selected.next().is_none());
        resolver.cancel(query)?;
    }
    Ok(())
}
