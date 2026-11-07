//! Independent fixed public metadata image. This is not the T1 generation body.
use super::{Error, Kind, PeerId, Protocol, Record, fault, key};
use zeroize::Zeroizing;
const MAGIC: &[u8; 8] = b"GNDVM001";
const HEADER: usize = 16;
const RECORD: usize = 48;
pub(super) fn limit(records: usize) -> Result<usize, Error> {
    if records == 0 || records > u32::MAX as usize {
        return Err(fault("record-limits", Protocol::Capacity));
    }
    let n = records
        .checked_mul(RECORD)
        .and_then(|n| n.checked_add(HEADER))
        .filter(|n| *n <= 64 * 1024 * 1024)
        .ok_or_else(|| fault("record-limits", Protocol::Capacity))?;
    Ok(n)
}
/// Canonical real genesis image: zero records with the same qualified format
/// used by every later commit. Empty body is not a recovered inventory.
pub(super) fn empty_image() -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut body = Zeroizing::new(Vec::new());
    body.try_reserve_exact(HEADER)
        .map_err(|_| fault("genesis-allocation", Protocol::Capacity))?;
    body.resize(HEADER, 0);
    body[..8].copy_from_slice(MAGIC);
    Ok(body)
}
pub(super) fn decode(body: &[u8], generation: u64, capacity: usize) -> Result<Vec<Record>, Error> {
    let _maximum = limit(capacity)?;
    let mut records = Vec::new();
    records
        .try_reserve_exact(capacity)
        .map_err(|_| fault("record-allocation", Protocol::Capacity))?;
    if generation == 0 {
        if !body.is_empty() {
            return Err(fault("genesis-body", Protocol::Malformed));
        }
        return Ok(records);
    }
    if body.len() < HEADER || &body[..8] != MAGIC || body[12..16] != [0; 4] {
        return Err(fault("dv-image-profile", Protocol::Malformed));
    }
    let count = u32::from_be_bytes(
        body[8..12]
            .try_into()
            .map_err(|_| fault("image-count", Protocol::Truncated))?,
    ) as usize;
    if count > capacity || body.len() != HEADER + count * RECORD {
        return Err(fault("image-size", Protocol::Capacity));
    }
    for row in body[HEADER..].as_chunks::<RECORD>().0 {
        let kind = match row[0] {
            1 => Kind::Learn,
            2 => Kind::Box,
            _ => return Err(fault("image-kind", Protocol::Malformed)),
        };
        if row[1..8] != [0; 7] {
            return Err(fault("image-reserved", Protocol::Malformed));
        }
        let peer = PeerId(
            row[8..40]
                .try_into()
                .map_err(|_| fault("image-peer", Protocol::Truncated))?,
        );
        let stamp = u64::from_be_bytes(
            row[40..48]
                .try_into()
                .map_err(|_| fault("image-stamp", Protocol::Truncated))?,
        );
        let record = Record { kind, peer, stamp };
        if records
            .last()
            .is_some_and(|previous| key(previous) >= key(&record))
        {
            return Err(fault("image-duplicate-order", Protocol::Malformed));
        }
        records.push(record)
    }
    Ok(records)
}
fn write(record: Record, out: &mut [u8]) {
    out[0] = record.kind as u8;
    out[8..40].copy_from_slice(&record.peer.0);
    out[40..48].copy_from_slice(&record.stamp.to_be_bytes())
}
pub(super) fn encode(
    records: &[Record],
    record: Record,
    index: usize,
    insert: bool,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if index > records.len() || (!insert && index == records.len()) {
        return Err(fault("stage-index", Protocol::Stale));
    }
    let count = records
        .len()
        .checked_add(usize::from(insert))
        .ok_or_else(|| fault("image-count", Protocol::Overflow))?;
    let size = limit(count)?;
    let mut body = Zeroizing::new(Vec::new());
    body.try_reserve_exact(size)
        .map_err(|_| fault("image-allocation", Protocol::Capacity))?;
    body.resize(size, 0);
    body[..8].copy_from_slice(MAGIC);
    body[8..12].copy_from_slice(&(count as u32).to_be_bytes());
    for target in 0..count {
        let item = if target == index {
            record
        } else {
            records[if insert && target > index {
                target - 1
            } else {
                target
            }]
        };
        write(
            item,
            &mut body[HEADER + target * RECORD..HEADER + (target + 1) * RECORD],
        )
    }
    Ok(body)
}
