//! Private complete-catalog format; no C database migration or secret keys.
use super::{LedgerId, Record};
use gnunet_crypto::EddsaPublicKey;
use gnunet_tcp_communicator_core::session::ReplayKind;
use gnunet_types::Error;
use zeroize::Zeroizing;
pub(crate) const HEADER: usize = 80;
const ROW: usize = 48;
const MAGIC: &[u8; 8] = b"GNTCPL02";
pub(crate) fn maximum(records: usize) -> Result<usize, Error> {
    if records == 0 || records > 65535 {
        return Err(Error::Capacity);
    }
    records
        .checked_mul(ROW)
        .and_then(|n| n.checked_add(HEADER))
        .ok_or(Error::Overflow)
}
fn tag(kind: ReplayKind) -> u8 {
    match kind {
        ReplayKind::Handshake => 1,
        ReplayKind::Acknowledgement => 2,
        ReplayKind::Rekey => 3,
    }
}
pub(crate) fn compare(a: &Record, b: &Record) -> core::cmp::Ordering {
    a.peer
        .as_bytes()
        .cmp(b.peer.as_bytes())
        .then_with(|| tag(a.kind).cmp(&tag(b.kind)))
}
pub(crate) fn decode(
    bytes: &[u8],
    generation: u64,
    local: EddsaPublicKey,
    maximum: usize,
) -> Result<(LedgerId, Vec<Record>, bool), Error> {
    if generation == 0
        || bytes.len() < HEADER
        || &bytes[..8] != MAGIC
        || bytes[76] > 1
        || bytes[77..80] != [0; 3]
    {
        return Err(Error::Malformed);
    }
    let id = LedgerId(bytes[8..40].try_into().map_err(|_| Error::Malformed)?);
    if id.0 == [0; 32] || bytes[40..72] != local.as_bytes()[..] {
        return Err(Error::Authentication);
    }
    let count =
        u32::from_be_bytes(bytes[72..76].try_into().map_err(|_| Error::Malformed)?) as usize;
    if count > maximum
        || bytes.len()
            != count
                .checked_mul(ROW)
                .and_then(|n| n.checked_add(HEADER))
                .ok_or(Error::Overflow)?
    {
        return Err(Error::Capacity);
    }
    let mut records = Vec::new();
    records
        .try_reserve_exact(maximum)
        .map_err(|_| Error::Capacity)?;
    for row in bytes[HEADER..].as_chunks::<ROW>().0 {
        if row[33..40] != [0; 7] {
            return Err(Error::Malformed);
        }
        let record = Record {
            peer: EddsaPublicKey::from_bytes(row[..32].try_into().map_err(|_| Error::Malformed)?),
            kind: match row[32] {
                1 => ReplayKind::Handshake,
                2 => ReplayKind::Acknowledgement,
                3 => ReplayKind::Rekey,
                _ => return Err(Error::Malformed),
            },
            stamp: u64::from_be_bytes(row[40..48].try_into().map_err(|_| Error::Malformed)?),
        };
        if records
            .last()
            .is_some_and(|before| compare(before, &record) != core::cmp::Ordering::Less)
        {
            return Err(Error::Malformed);
        }
        records.push(record);
    }
    if bytes[76] == 0 && (generation != 1 || !records.is_empty()) {
        return Err(Error::Malformed);
    }
    if bytes[76] == 1 && generation < 2 {
        return Err(Error::Malformed);
    }
    Ok((id, records, bytes[76] == 1))
}
pub(crate) fn encode(
    id: LedgerId,
    local: EddsaPublicKey,
    records: &[Record],
    change: Option<Record>,
    bound: bool,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let position = change.map(|row| records.binary_search_by(|value| compare(value, &row)));
    let count = records
        .len()
        .checked_add(usize::from(matches!(position, Some(Err(_)))))
        .ok_or(Error::Overflow)?;
    let used = count
        .checked_mul(ROW)
        .and_then(|n| n.checked_add(HEADER))
        .ok_or(Error::Overflow)?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.try_reserve_exact(used).map_err(|_| Error::Capacity)?;
    bytes.resize(HEADER, 0);
    bytes[76] = u8::from(bound);
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..40].copy_from_slice(&id.0);
    bytes[40..72].copy_from_slice(local.as_bytes());
    bytes[72..76].copy_from_slice(
        &u32::try_from(count)
            .map_err(|_| Error::Capacity)?
            .to_be_bytes(),
    );
    fn row(bytes: &mut Vec<u8>, record: Record) {
        bytes.extend_from_slice(record.peer.as_bytes());
        bytes.push(tag(record.kind));
        bytes.extend_from_slice(&[0; 7]);
        bytes.extend_from_slice(&record.stamp.to_be_bytes());
    }
    for (i, record) in records.iter().enumerate() {
        if let (Some(change), Some(Err(index))) = (change, position)
            && index == i
        {
            row(&mut bytes, change);
        }
        if let (Some(change), Some(Ok(index))) = (change, position)
            && index == i
        {
            row(&mut bytes, change);
        } else {
            row(&mut bytes, *record);
        }
    }
    if let (Some(change), Some(Err(index))) = (change, position)
        && index == records.len()
    {
        row(&mut bytes, change);
    }
    Ok(bytes)
}
