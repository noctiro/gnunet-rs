use super::*;
use crate::{APEX, Code, Filter, RecordFlags, ZoneKey};
use gnunet_gnsrecord::ZoneKeyType;
use gnunet_wire::official::namestore::{CString, RecordSets, StoreSet};

const NOW: u64 = 100;
const D: usize = 512;
const N: usize = D / RECORD_HEADER_LEN;

fn record(kind: RecordType, bytes: &[u8], flags: RecordFlags) -> RecordData<'_> {
    RecordData {
        expiration_time: 200,
        record_type: kind,
        flags,
        data: bytes,
    }
}

fn encode<'a>(records: &[RecordData<'_>], out: &'a mut [u8]) -> Result<Records<'a>, Error> {
    let n = gnunet_gnsrecord::serialize(records, out)?;
    Records::new(
        &out[..n],
        u16::try_from(records.len()).map_err(|_| Error::Capacity)?,
    )
}

fn batch<'a>(sets: &[(&[u8], Records<'_>)], output: &'a mut [u8]) -> Result<RecordSets<'a>, Error> {
    let mut written = 0;
    for &(label, records) in sets {
        written += StoreSet {
            label: CString::new(label)?,
            records,
            reserved: 0,
        }
        .encode(&mut output[written..])?;
    }
    RecordSets::new(
        &output[..written],
        u16::try_from(sets.len()).map_err(|_| Error::Capacity)?,
    )
}

#[test]
fn editor_preserves_record_serials_and_requires_the_original_hint() -> Result<(), Error> {
    const OUTPUT: usize = 2 * D;
    let mut memory = Inventory::<4, D>::EMPTY;
    let mut owner = Owner::new(&mut memory, crate::critical_type)?;
    let mut stage = StoreScratch::<4, D, N>::EMPTY;
    let mut read = ReadScratch::<OUTPUT, N>::EMPTY;
    let key = SecretKey::anonymous();
    let zone = key.view()?;
    let mut records = [0; 64];
    let values = encode(
        &[record(
            RecordType::A,
            &[192, 0, 2, 7],
            RecordFlags::from_bits_preserve(0),
        )],
        &mut records,
    )?;
    let mut raw = [0; 256];
    let supplied = batch(&[(b"label", values)], &mut raw)?;
    let committed = owner.store(zone, supplied, true, NOW, &mut stage, |_| Ok(()))?;
    if committed.code != Code::NONE {
        return Err(Error::Conflict);
    }
    drop(committed);

    let first =
        owner.edit_begin::<OUTPUT, N>(zone, b"label", b"first", NOW, &mut read, |image| {
            let row = image
                .rows()
                .next()
                .ok_or(CommitError::Failed(Error::NotFound))?
                .map_err(CommitError::Failed)?;
            if row.serial == 1 && row.hint == Some(b"first") && image.next_serial() == 2 {
                Ok(())
            } else {
                Err(CommitError::Failed(Error::Conflict))
            }
        })?;
    if first.code != Code::NONE || first.hint.is_some() || first.records.bytes() != values.bytes() {
        return Err(Error::Conflict);
    }
    if owner.edit_cancel::<OUTPUT, N>(zone, b"label", b"wrong", b"", &mut read, |_| {
        Err(CommitError::Failed(Error::Conflict))
    })? != Code::NONE
    {
        return Err(Error::Conflict);
    }
    let second =
        owner.edit_begin::<OUTPUT, N>(zone, b"label", b"second", NOW, &mut read, |_| Ok(()))?;
    if second.hint != Some(b"first") || second.records.bytes() != values.bytes() {
        return Err(Error::Conflict);
    }
    if !matches!(
        owner.edit_cancel::<OUTPUT, N>(zone, b"label", b"second", b"", &mut read, |_| {
            Err(CommitError::OutcomeUnknown)
        }),
        Err(Error::OutcomeUnknown)
    ) || !matches!(owner.next_row(None, 0), Err(Error::OutcomeUnknown))
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

#[test]
fn physical_deletion_advances_only_the_confirmed_record_floor() -> Result<(), Error> {
    let mut memory = Inventory::<2, D>::EMPTY;
    let mut owner = Owner::new(&mut memory, crate::critical_type)?;
    let mut stage = StoreScratch::<1, D, N>::EMPTY;
    let key = SecretKey::anonymous();
    let zone = key.view()?;
    let mut record_bytes = [0; 64];
    let private = encode(
        &[record(RecordType::A, &[192, 0, 2, 7], RecordFlags::PRIVATE)],
        &mut record_bytes,
    )?;
    let mut create_bytes = [0; 128];
    let create = batch(&[(b"local", private)], &mut create_bytes)?;
    if owner
        .store(zone, create, true, NOW, &mut stage, |_| Ok(()))?
        .code
        != Code::NONE
    {
        return Err(Error::Conflict);
    }
    let mut delete_bytes = [0; 128];
    let delete = batch(&[(b"local", Records::empty()?)], &mut delete_bytes)?;
    if !matches!(
        owner.store(zone, delete, true, NOW, &mut stage, |_| Err(
            CommitError::Failed(Error::Io)
        )),
        Err(Error::Io)
    ) || owner.next_serial()? != 2
        || owner.row(1)?.is_none()
    {
        return Err(Error::Conflict);
    }
    let removed = owner
        .store(zone, delete, true, NOW, &mut stage, |image| {
            if image.next_serial() == 3 && image.rows().next().is_none() {
                Ok(())
            } else {
                Err(CommitError::Failed(Error::Conflict))
            }
        })?
        .code;
    if removed != Code::NONE
        || owner.next_serial()? != 3
        || owner.row(1)?.is_some()
        || owner.next_row(None, 0)?.is_some()
    {
        return Err(Error::Conflict);
    }
    let recreated = owner.store(zone, create, true, NOW, &mut stage, |_| Ok(()))?;
    if recreated.code != Code::NONE || owner.row(3)?.is_none() || owner.row(1)?.is_some() {
        return Err(Error::Conflict);
    }
    Ok(())
}

#[test]
fn transform_commits_exact_rows_once_and_keeps_the_publication_floor() -> Result<(), Error> {
    let mut memory = Inventory::<6, D>::EMPTY;
    let mut owner = Owner::new(&mut memory, crate::critical_type)?;
    let mut stage = StoreScratch::<6, D, N>::EMPTY;
    let mut read = ReadScratch::<D, N>::EMPTY;
    let key = SecretKey::anonymous();
    let zone = key.view()?;
    let mut values = [0; 128];
    let mut private = [0; 64];
    let short = record(RecordType::A, &[192, 0, 2, 1], RecordFlags::NONE);
    let long = RecordData {
        expiration_time: 300,
        data: &[192, 0, 2, 2],
        ..short
    };
    let public = encode(&[short, long], &mut values)?;
    let private = encode(
        &[record(RecordType::A, &[192, 0, 2, 3], RecordFlags::PRIVATE)],
        &mut private,
    )?;
    let mut wire = [0; 512];
    let supplied = batch(
        &[
            (b"first", private),
            (b"public", public),
            (b"second", private),
            (b"third", private),
            (b"fourth", private),
        ],
        &mut wire,
    )?;
    if owner
        .store(zone, supplied, true, NOW, &mut stage, |_| Ok(()))?
        .code
        != Code::NONE
    {
        return Err(Error::Conflict);
    }
    owner.edit_begin::<D, N>(zone, b"public", b"editor", NOW, &mut read, |_| Ok(()))?;
    let transform = |turn: ZoneTransform<'_, 6, D, N>| {
        if !turn
            .rows()
            .enumerate()
            .all(|(index, row)| row.is_ok_and(|row| row.serial == index as u64 + 1))
        {
            return Err(Error::Conflict);
        }
        turn.visit(|row, edit| {
            if row.label == b"public" {
                edit.retain_records(|record| Ok(record.data != long.data))?;
            } else {
                edit.delete();
            }
            Ok(())
        })
    };
    if !matches!(
        owner.transform_zone(zone, NOW, &mut stage, transform, |_| Err(
            CommitError::Failed(Error::Io)
        )),
        Err(Error::Io)
    ) || owner.next_serial()? != 6
        || owner.row(1)?.is_none()
    {
        return Err(Error::Conflict);
    }
    let committed = owner.transform_zone(zone, NOW, &mut stage, transform, |image| {
        let mut rows = image.rows();
        let row = rows
            .next()
            .ok_or(CommitError::Failed(Error::NotFound))?
            .map_err(CommitError::Failed)?;
        let mut records = row.records.records().iter();
        let kept = records
            .next()
            .ok_or(CommitError::Failed(Error::NotFound))?
            .map_err(CommitError::Failed)?;
        let floor = records
            .next()
            .ok_or(CommitError::Failed(Error::NotFound))?
            .map_err(CommitError::Failed)?;
        if rows.next().is_some()
            || row.serial != 7
            || row.hint != Some(b"editor")
            || image.next_serial() != 11
            || kept.data != short.data
            || kept.expiration_time != short.expiration_time
            || floor.record_type != RecordType::TOMBSTONE
            || floor.expiration_time != 300
            || !floor
                .flags
                .contains(RecordFlags::PRIVATE.union(RecordFlags::MAINTENANCE))
        {
            return Err(CommitError::Failed(Error::Conflict));
        }
        Ok(())
    })?;
    if !committed
        .changes()
        .map(|change| change.serial)
        .eq([None, Some(7), None, None, None])
    {
        return Err(Error::Conflict);
    }
    drop(committed);
    let retained = owner.row(7)?.ok_or(Error::NotFound)?;
    if retained.ordinary_records_at(250).count() != 0
        || !retained.has_ordinary_records()?
        || owner.row(1)?.is_some()
    {
        return Err(Error::Conflict);
    }
    if !matches!(
        owner.transform_zone(
            zone,
            NOW,
            &mut stage,
            |turn| turn.visit(|_, edit| {
                edit.delete();
                Ok(())
            }),
            |_| Err(CommitError::OutcomeUnknown)
        ),
        Err(Error::OutcomeUnknown)
    ) || !matches!(owner.next_serial(), Err(Error::OutcomeUnknown))
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

#[test]
fn atomic_refusal_keeps_inventory_and_non_atomic_prefix_is_real() -> Result<(), Error> {
    let mut memory = Inventory::<4, D>::EMPTY;
    let mut owner = Owner::new(&mut memory, |_| false)?;
    let mut stage = StoreScratch::<4, D, N>::EMPTY;
    let mut read = ReadScratch::<D, N>::EMPTY;
    let key = SecretKey::anonymous();
    let zone = key.view()?;
    let mut records = [0; 128];
    let values = encode(
        &[
            record(
                RecordType::A,
                &[203, 0, 113, 1],
                RecordFlags::from_bits_preserve(0),
            ),
            record(RecordType::A, &[203, 0, 113, 2], RecordFlags::PRIVATE),
        ],
        &mut records,
    )?;
    let mut raw = [0; 1024];
    let supplied = batch(
        &[("é".as_bytes(), values), (b"invalid.label", values)],
        &mut raw,
    )?;
    let result = owner.store(zone, supplied, true, NOW, &mut stage, |_| {
        Err(CommitError::Failed(Error::Conflict))
    })?;
    if result.code != Code::LABEL_INVALID
        || result.changes().count() != 0
        || owner.next_serial()? != 1
    {
        return Err(Error::Conflict);
    }
    drop(result);

    let result = owner.store(zone, supplied, false, NOW, &mut stage, |image| {
        let mut rows = image.rows();
        let row = rows
            .next()
            .ok_or(CommitError::Failed(Error::Conflict))?
            .map_err(CommitError::Failed)?;
        if row.serial == 1
            && row.label == "é".as_bytes()
            && rows.next().is_none()
            && image.next_serial() == 2
        {
            Ok(())
        } else {
            Err(CommitError::Failed(Error::Conflict))
        }
    })?;
    if result.code != Code::LABEL_INVALID
        || !result
            .changes()
            .map(|change| change.label)
            .eq(["é".as_bytes()])
    {
        return Err(Error::Conflict);
    }
    drop(result);
    let mut nick_data = [0; 128];
    let nick = encode(
        &[record(
            RecordType::NICK,
            b"our zone\0",
            RecordFlags::PRIVATE,
        )],
        &mut nick_data,
    )?;
    let supplied = batch(&[(APEX, nick)], &mut raw)?;
    let result = owner.store(zone, supplied, true, NOW, &mut stage, |_| Ok(()))?;
    if result.code != Code::NONE || owner.next_serial()? != 3 {
        return Err(Error::Conflict);
    }
    drop(result);
    let selected = owner.lookup(zone, "é".as_bytes(), Filter::OMIT_PRIVATE, NOW, &mut read)?;
    let mut records = selected.records.records().iter();
    let first = records.next().ok_or(Error::NotFound)??;
    let second = records.next().ok_or(Error::NotFound)??;
    if !selected.found
        || selected.expires != 200
        || first.data != [203, 0, 113, 1]
        || second.record_type != RecordType::NICK
        || second.flags.contains(RecordFlags::PRIVATE)
        || !second.flags.contains(RecordFlags::SUPPLEMENTAL)
        || records.next().is_some()
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

#[test]
fn known_failure_preserves_zone_and_unknown_requires_explicit_recovery() -> Result<(), Error> {
    let mut memory = Inventory::<4, D>::EMPTY;
    let mut owner = Owner::new(&mut memory, |_| false)?;
    let mut stage = StoreScratch::<4, D, N>::EMPTY;
    let key = SecretKey::anonymous();
    let zone = key.view()?;
    let target = ZoneKey::new(ZoneKeyType::Edkey, [7; 32]);
    let mut encoded = [0; 64];
    let rd = encode(
        &[record(
            RecordType::EDKEY,
            target.key(),
            RecordFlags::from_bits_preserve(0),
        )],
        &mut encoded,
    )?;
    let mut raw = [0; 256];
    let supplied = batch(&[(b"child", rd)], &mut raw)?;
    let result = owner.store(zone, supplied, true, NOW, &mut stage, |_| Ok(()))?;
    if result.code != Code::NONE
        || owner.zone_to_name(zone, target)?.map(|row| row.label) != Some(&b"child"[..])
    {
        return Err(Error::Conflict);
    }
    drop(result);
    let supplied = batch(&[(b"new", rd)], &mut raw)?;
    if !matches!(
        owner.store(zone, supplied, true, NOW, &mut stage, |_| Err(
            CommitError::Failed(Error::Storage)
        )),
        Err(Error::Storage)
    ) || owner.next_serial()? != 2
        || owner.next_row(None, 1)?.is_some()
    {
        return Err(Error::Conflict);
    }
    if !matches!(
        owner.store(zone, supplied, true, NOW, &mut stage, |_| Err(
            CommitError::OutcomeUnknown
        )),
        Err(Error::OutcomeUnknown)
    ) || !matches!(owner.next_row(None, 0), Err(Error::OutcomeUnknown))
    {
        return Err(Error::Conflict);
    }
    owner.clear();
    if !matches!(
        Owner::new(&mut memory, |_| false),
        Err(Error::OutcomeUnknown)
    ) {
        return Err(Error::Conflict);
    }
    Ok(())
}

#[test]
fn private_relocation_reuses_the_only_body_slot_and_has_two_changes() -> Result<(), Error> {
    let mut memory = Inventory::<1, D>::EMPTY;
    let mut owner = Owner::new(&mut memory, |_| false)?;
    let mut stage = StoreScratch::<1, D, N>::EMPTY;
    let key = SecretKey::anonymous();
    let zone = key.view()?;
    let mut body = [0; 64];
    let records = encode(
        &[record(
            RecordType::TXT,
            b"private value",
            RecordFlags::PRIVATE,
        )],
        &mut body,
    )?;
    let result = owner.store_one(
        zone,
        StoreSet {
            label: CString::new(b"old")?,
            records,
            reserved: 0,
        },
        NOW,
        &mut stage,
        |_| Ok(()),
    )?;
    if result.code != Code::NONE {
        return Err(Error::Conflict);
    }
    drop(result);
    let committed = owner.transform_zone(
        zone,
        NOW,
        &mut stage,
        |turn| turn.visit(|row, change| change.move_to(b"new", row.records)),
        |image| {
            let mut rows = image.rows();
            let row = rows
                .next()
                .ok_or(CommitError::Failed(Error::NotFound))?
                .map_err(CommitError::Failed)?;
            if row.label != b"new"
                || row.serial != 3
                || row.records.bytes() != records.bytes()
                || rows.next().is_some()
                || image.next_serial() != 4
            {
                return Err(CommitError::Failed(Error::Conflict));
            }
            Ok(())
        },
    )?;
    if !committed
        .changes()
        .map(|change| (change.label, change.serial))
        .eq([(&b"old"[..], None), (&b"new"[..], Some(3))])
    {
        return Err(Error::Conflict);
    }
    drop(committed);
    if owner.row(1)?.is_some() || owner.row(3)?.map(|row| row.label) != Some(b"new") {
        return Err(Error::Conflict);
    }
    Ok(())
}

#[test]
fn large_fixed_record_uses_caller_byte_and_sort_budgets() -> Result<(), Error> {
    const BYTES: usize = 8192;
    let mut memory = Inventory::<1, BYTES>::EMPTY;
    let mut stage = StoreScratch::<1, BYTES, 1>::EMPTY;
    let mut read = ReadScratch::<BYTES, 1>::EMPTY;
    let mut no_offsets = ReadScratch::<BYTES, 0>::EMPTY;
    let mut owner = Owner::new(&mut memory, crate::critical_type)?;
    let key = SecretKey::anonymous();
    let zone = key.view()?;
    let payload = [42; 5000];
    let mut raw = [0; BYTES];
    let records = encode(
        &[record(
            RecordType::TXT,
            &payload,
            RecordFlags::from_bits_preserve(0),
        )],
        &mut raw,
    )?;
    let request = StoreSet {
        label: CString::new(b"large")?,
        records,
        reserved: 0,
    };
    let committed = owner.store_one(zone, request, NOW, &mut stage, |image| {
        let result = image
            .rows()
            .next()
            .ok_or(CommitError::Failed(Error::NotFound))?
            .map_err(CommitError::Failed)?;
        if result.records.bytes() != records.bytes() {
            return Err(CommitError::Failed(Error::Conflict));
        }
        Ok(())
    })?;
    if committed.code != Code::NONE {
        return Err(Error::Conflict);
    }
    drop(committed);
    if !matches!(
        owner.lookup(zone, b"large", Filter::NONE, NOW, &mut no_offsets),
        Err(Error::Capacity)
    ) {
        return Err(Error::Conflict);
    }
    let found = owner.lookup(zone, b"large", Filter::NONE, NOW, &mut read)?;
    if !found.found || found.expires != 200 || found.records.bytes() != records.bytes() {
        return Err(Error::Conflict);
    }
    Ok(())
}
