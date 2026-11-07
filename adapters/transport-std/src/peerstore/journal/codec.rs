//! Bounded private snapshot codec and independent ordinary-artifact validation.
use super::super::{decode_record, encode_record};
use super::{HEADER, MAX_BYTES, MAX_RECORDS, ManagedQuota, Origin, Record, Snapshot, Stored};
use gnunet_crypto::EddsaPublicKey;
use gnunet_transport::{PeerId, own_wire};
use gnunet_types::Error;
pub(super) fn copy_bytes(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    out.try_reserve_exact(bytes.len())
        .map_err(|_| Error::Capacity)?;
    out.extend_from_slice(bytes);
    Ok(out)
}
pub(super) fn clone_rows<'a>(rows: impl Iterator<Item = &'a Stored>) -> Result<Vec<Stored>, Error> {
    let mut out = Vec::new();
    for s in rows {
        out.try_reserve(1).map_err(|_| Error::Capacity)?;
        out.push(Stored {
            origin: s.origin,
            record: Record {
                peer: s.record.peer,
                subsystem: copy_bytes(&s.record.subsystem)?,
                key: copy_bytes(&s.record.key)?,
                value: copy_bytes(&s.record.value)?,
                expiry: s.record.expiry,
            },
        });
    }
    Ok(out)
}
pub(super) fn input_record_bytes(
    value: usize,
    subsystem: usize,
    key: usize,
) -> Result<usize, Error> {
    let bytes = 66usize
        .checked_add(subsystem)
        .and_then(|n| n.checked_add(key))
        .and_then(|n| n.checked_add(value))
        .ok_or(Error::Capacity)?;
    if bytes - 4 > usize::from(u16::MAX) {
        return Err(Error::TooLarge);
    }
    Ok(bytes)
}
pub(super) fn record_bytes(row: &Stored) -> Result<usize, Error> {
    66usize
        .checked_add(row.record.subsystem.len())
        .and_then(|v| v.checked_add(row.record.key.len()))
        .and_then(|v| v.checked_add(row.record.value.len()))
        .ok_or(Error::Capacity)
}
pub(super) fn check_partitions(rows: &[Stored], quota: Option<ManagedQuota>) -> Result<(), Error> {
    if rows.len() > MAX_RECORDS {
        return Err(Error::Capacity);
    }
    let (mut public_count, mut public_bytes, mut managed_count, mut managed_bytes) =
        (0, 0usize, 0, 0usize);
    for row in rows {
        let size = record_bytes(row)?;
        if size - 4 > u16::MAX as usize {
            return Err(Error::TooLarge);
        }
        if row.origin == Origin::Public {
            public_count += 1;
            public_bytes = public_bytes.checked_add(size).ok_or(Error::Capacity)?;
        } else {
            managed_count += 1;
            managed_bytes = managed_bytes.checked_add(size).ok_or(Error::Capacity)?;
        }
    }
    if public_bytes
        .checked_add(managed_bytes)
        .and_then(|n| n.checked_add(HEADER))
        .is_none_or(|n| n > MAX_BYTES)
    {
        return Err(Error::Capacity);
    }
    if let Some(q) = quota
        && (managed_count > q.records
            || managed_bytes > q.bytes
            || public_count > MAX_RECORDS - q.records
            || public_bytes > MAX_BYTES - HEADER - q.bytes)
    {
        return Err(Error::Capacity);
    }
    Ok(())
}
pub(super) fn encode_snapshot(
    generation: u64,
    highwater: u64,
    rows: &[Stored],
) -> Result<Vec<u8>, Error> {
    check_partitions(rows, None)?;
    let length = rows.iter().try_fold(HEADER, |n, r| {
        n.checked_add(record_bytes(r)?).ok_or(Error::Capacity)
    })?;
    let mut out = Vec::new();
    out.try_reserve_exact(length).map_err(|_| Error::Capacity)?;
    out.extend_from_slice(b"GPS3");
    out.extend_from_slice(&generation.to_be_bytes());
    out.extend_from_slice(&highwater.to_be_bytes());
    out.extend_from_slice(&(rows.len() as u32).to_be_bytes());
    for row in rows {
        out.extend_from_slice(&[row.origin as u8, 0, 0, 0]);
        out.extend_from_slice(&encode_record(&row.record, 0, 820)?);
    }
    Ok(out)
}
pub(super) fn decode_snapshot(
    raw: Vec<u8>,
    hello_profile: gnunet_hello::SignatureProfile,
) -> Result<Snapshot, Error> {
    if raw.len() < HEADER || raw.get(..4) != Some(b"GPS3") {
        return Err(Error::Storage);
    }
    let generation = u64::from_be_bytes(raw[4..12].try_into().map_err(|_| Error::Storage)?);
    let highwater = u64::from_be_bytes(raw[12..20].try_into().map_err(|_| Error::Storage)?);
    let count = u32::from_be_bytes(raw[20..24].try_into().map_err(|_| Error::Storage)?) as usize;
    if generation == 0 || count > MAX_RECORDS {
        return Err(Error::Storage);
    }
    let mut rows = Vec::new();
    rows.try_reserve_exact(count).map_err(|_| Error::Capacity)?;
    let mut offset = HEADER;
    for _ in 0..count {
        let tag = raw.get(offset..offset + 4).ok_or(Error::Storage)?;
        if tag[1..] != [0, 0, 0] {
            return Err(Error::Storage);
        }
        let origin = match tag[0] {
            0 => Origin::Public,
            1 => Origin::Address,
            2 => Origin::Hello,
            _ => return Err(Error::Storage),
        };
        offset += 4;
        let length = usize::from(u16::from_be_bytes(
            raw.get(offset..offset + 2)
                .ok_or(Error::Storage)?
                .try_into()
                .map_err(|_| Error::Storage)?,
        ));
        let end = offset.checked_add(length).ok_or(Error::Storage)?;
        let record = decode_record(raw.get(offset..end).ok_or(Error::Storage)?)?;
        if origin == Origin::Address {
            if record.subsystem != own_wire::SUBSYSTEM || record.key != own_wire::KEY {
                return Err(Error::Storage);
            }
            let address = own_wire::AddressRecord::parse(&record.value)?;
            address.verify(EddsaPublicKey::from_bytes(record.peer.0))?;
            if address.generated > highwater {
                return Err(Error::Replay);
            }
        } else if origin == Origin::Hello
            && (record.subsystem != b"peerstore"
                || record.key != b"peerstore-peer-hello-uri"
                || validate_hello(record.peer, &record.value, 0, hello_profile)? != record.expiry)
        {
            return Err(Error::Storage);
        }
        rows.push(Stored { origin, record });
        offset = end;
    }
    if offset != raw.len() || encode_snapshot(generation, highwater, &rows)? != raw {
        return Err(Error::Storage);
    }
    Ok(Snapshot {
        generation,
        highwater,
        rows,
        raw,
    })
}
pub(super) fn validate_hello(
    peer: PeerId,
    value: &[u8],
    now: u64,
    hello_profile: gnunet_hello::SignatureProfile,
) -> Result<u64, Error> {
    if value.len() > usize::from(u16::MAX) {
        return Err(Error::TooLarge);
    }
    let bytes = value
        .len()
        .checked_sub(gnunet_hello::MESSAGE_FIXED_LEN)
        .ok_or(Error::Malformed)?;
    let mut scratch = Vec::new();
    scratch
        .try_reserve_exact(bytes)
        .map_err(|_| Error::Capacity)?;
    scratch.resize(bytes, 0);
    let hello = gnunet_hello::Hello::parse_message(
        value,
        None,
        &mut scratch,
        gnunet_hello::Limits {
            maximum_input_bytes: u16::MAX as usize,
            maximum_address_bytes: bytes,
            maximum_addresses: u16::MAX as usize,
        },
    )?;
    if hello.peer().as_bytes() != &peer.0 || hello.addresses().next().is_none() {
        return Err(Error::Authentication);
    }
    hello.verify_at(hello_profile, gnunet_hello::AbsoluteTime::from_micros(now))?;
    Ok(gnunet_hello::message_expiration(value)?.as_micros())
}
