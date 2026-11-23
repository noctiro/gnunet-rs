//! Original signed outputs, private record isolation and durable nonce assignment.

#![expect(
    clippy::panic_in_result_fn,
    reason = "exact block and projection assertions"
)]

use gnunet_gnscrypto::{Block, Label};
use gnunet_gnsrecord::{RecordData, RecordFlags as Flags, RecordSet, RecordType, serialize};
use gnunet_identity::{KEY_LEN, KeyType, SecretKey};
use gnunet_zonemaster::{
    Error,
    fixed::{Destinations, Input, Limits, Output, Preparation, prepare},
};

fn key() -> Result<SecretKey, Error> {
    let mut raw = [0x23; KEY_LEN];
    raw[..4].copy_from_slice(&KeyType::Eddsa.value().to_be_bytes());
    SecretKey::new(raw)
}

fn workspace<'a>(
    scalars: &'a mut [char],
    label: &'a mut [u8],
    public_rdata: &'a mut [u8],
    local_rdata: &'a mut [u8],
) -> Preparation<'a> {
    Preparation {
        scalars,
        label,
        public_rdata,
        local_rdata,
    }
}

#[test]
fn scoped_reservation_seals_distinct_public_and_private_projections() -> Result<(), Error> {
    let key = key()?;
    let records = [
        RecordData {
            record_type: RecordType::A,
            flags: Flags::RELATIVE_EXPIRATION,
            expiration_time: 500,
            data: &[192, 0, 2, 1],
        },
        RecordData {
            record_type: RecordType::TXT,
            flags: Flags::PRIVATE.union(Flags::RELATIVE_EXPIRATION),
            expiration_time: 250,
            data: b"private",
        },
    ];
    let mut original = [0; 256];
    let width = serialize(&records, &mut original)?;
    let original = RecordSet::parse(&original[..width], records.len(), 8)?;
    let mut scalars = ['\0'; 32];
    let mut label = [0; 32];
    let mut public_rdata = [0; 256];
    let mut local_rdata = [0; 256];
    let prepared = prepare::<8>(
        Input {
            zone: key.view()?,
            label: b"host",
            records: original,
            source_expiry: 350,
        },
        100,
        Limits::default(),
        |_| false,
        Destinations::PublicAndLocal,
        workspace(
            &mut scalars,
            &mut label,
            &mut public_rdata,
            &mut local_rdata,
        ),
    )?
    .ok_or(Error::NotFound)?;
    assert_eq!(prepared.minimum_relative(), Some(250));
    let mut public = [0; 512];
    let mut local = [0; 512];
    let sealed = prepared.seal(
        Output {
            public: &mut public,
            local: &mut local,
        },
        |request| {
            let assigned = request.after(Some(700))?;
            assert_eq!(assigned.allocations(), 2);
            assert_eq!(assigned.maximum(), 702);
            Ok(assigned)
        },
    )?;
    assert!(sealed.requires_private_cache());
    assert_eq!(sealed.minimum_relative(), Some(250));
    assert_eq!(sealed.public_minimum_relative(), Some(500));
    let public = sealed.public().ok_or(Error::NotFound)?;
    let local = sealed.local().ok_or(Error::NotFound)?;
    let retained = public.retain();
    assert_eq!(retained.lend(public.bytes())?.bytes(), public.bytes());
    assert!(matches!(
        retained.lend(local.bytes()),
        Err(Error::Authentication)
    ));
    assert_eq!(public.query(), local.query());
    assert_eq!(public.expires(), 701);
    assert_eq!(local.expires(), 702);
    assert!(
        public_rdata
            .iter()
            .chain(&local_rdata)
            .all(|byte| *byte == 0)
    );

    let label = Label::normalize("host", &mut scalars, &mut label)?;
    let mut plaintext = [0; 256];
    let opened = Block::decode(public.bytes())?
        .verify_for(public.zone(), label)?
        .open_at(100, &mut plaintext)?;
    let mut selected = opened.iter();
    let record = selected.next().ok_or(Error::NotFound)??;
    assert_eq!(record.expiration_time, 600);
    assert_eq!(record.flags, Flags::NONE);
    assert!(selected.next().is_none());
    let opened = Block::decode(local.bytes())?
        .verify_for(public.zone(), label)?
        .open_at(100, &mut plaintext)?;
    let mut selected = opened.iter();
    assert_eq!(
        selected.next().ok_or(Error::NotFound)??.record_type,
        RecordType::A
    );
    assert_eq!(
        selected.next().ok_or(Error::NotFound)??,
        RecordData {
            flags: Flags::PRIVATE,
            expiration_time: 350,
            ..records[1]
        }
    );
    assert!(selected.next().is_none());
    Ok(())
}

#[test]
fn tombstone_renews_local_only_and_never_uses_public_storage() -> Result<(), Error> {
    let key = key()?;
    let record = RecordData {
        record_type: RecordType::TOMBSTONE,
        flags: Flags::PRIVATE.union(Flags::MAINTENANCE),
        expiration_time: 500,
        data: &[],
    };
    let mut original = [0; 32];
    let width = serialize(&[record], &mut original)?;
    let original = RecordSet::parse(&original[..width], 1, 1)?;
    let mut scalars = ['\0'; 32];
    let mut label = [0; 32];
    let prepared = prepare::<1>(
        Input {
            zone: key.view()?,
            label: b"gone",
            records: original,
            source_expiry: 500,
        },
        100,
        Limits::default(),
        |_| false,
        Destinations::LocalOnly,
        workspace(&mut scalars, &mut label, &mut [], &mut []),
    )?
    .ok_or(Error::NotFound)?;
    let mut local = [0; 256];
    let sealed = prepared.seal(
        Output {
            public: &mut [],
            local: &mut local,
        },
        |request| {
            let assigned = request.after(Some(600))?;
            assert_eq!(assigned.allocations(), 1);
            assert_eq!(assigned.maximum(), 601);
            Ok(assigned)
        },
    )?;
    assert!(sealed.public().is_none());
    assert!(!sealed.requires_private_cache());
    let local = sealed.local().ok_or(Error::NotFound)?;
    assert_eq!(local.expires(), 601);
    let zone =
        gnunet_gnscrypto::ZoneSecret::Edkey(gnunet_crypto::gns::EdkeySecret::from_seed([0x23; 32]))
            .public_key();
    let label = Label::normalize("gone", &mut scalars, &mut label)?;
    let opened = Block::decode(local.bytes())?
        .verify_for(zone, label)?
        .open_at(100, &mut [])?;
    assert!(opened.iter().next().is_none());
    Ok(())
}
