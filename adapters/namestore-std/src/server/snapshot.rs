//! Private Rust raw-body codec under the independent Namestore disk namespace.
//! This is never a local/P2P protocol, C database format or migration layer.
use gnunet_namestore::{Limits, OwnedRecords, Row, SecretKey, Snapshot, Zone};
use gnunet_types::Error;
use gnunet_wire::official::namestore::Records;
use zeroize::Zeroizing;
const MAGIC: &[u8; 8] = b"GNMCORE1";
const ROW_PREFIX: usize = 56;
pub(crate) fn encode(snapshot: &Snapshot, maximum: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut length = 12usize;
    for row in snapshot.rows() {
        let records = row.records().view()?;
        u16::try_from(row.label().len()).map_err(|_| Error::Capacity)?;
        u32::try_from(records.bytes().len()).map_err(|_| Error::Capacity)?;
        if let Some(hint) = row.hint() {
            u32::try_from(hint.len()).map_err(|_| Error::Capacity)?;
        }
        length = length
            .checked_add(ROW_PREFIX)
            .and_then(|n| n.checked_add(row.label().len()))
            .and_then(|n| n.checked_add(records.bytes().len()))
            .and_then(|n| n.checked_add(row.hint().map_or(0, <[u8]>::len)))
            .ok_or(Error::Overflow)?;
    }
    if length > maximum {
        return Err(Error::Capacity);
    }
    let count = u32::try_from(snapshot.rows().len()).map_err(|_| Error::Capacity)?;
    let mut body = Zeroizing::new(Vec::new());
    body.try_reserve_exact(length)
        .map_err(|_| Error::Capacity)?;
    body.extend_from_slice(MAGIC);
    body.extend_from_slice(&count.to_be_bytes());
    for row in snapshot.rows() {
        let records = row.records().view()?;
        body.extend_from_slice(&row.serial().to_be_bytes());
        body.extend_from_slice(row.zone().secret().expose_serialized());
        body.extend_from_slice(&(row.label().len() as u16).to_be_bytes());
        body.extend_from_slice(&records.count().to_be_bytes());
        body.extend_from_slice(&(records.bytes().len() as u32).to_be_bytes());
        body.extend_from_slice(
            &row.hint()
                .map_or(u32::MAX, |h| h.len() as u32)
                .to_be_bytes(),
        );
        body.extend_from_slice(row.label());
        body.extend_from_slice(records.bytes());
        if let Some(hint) = row.hint() {
            body.extend_from_slice(hint);
        }
    }
    Ok(body)
}
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(length).ok_or(Error::Overflow)?;
        let value = self.bytes.get(self.at..end).ok_or(Error::Storage)?;
        self.at = end;
        Ok(value)
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| Error::Storage)?,
        ))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| Error::Storage)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| Error::Storage)?,
        ))
    }
}
fn copy(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    out.try_reserve_exact(bytes.len())
        .map_err(|_| Error::Capacity)?;
    out.extend_from_slice(bytes);
    Ok(out)
}
pub(crate) fn decode(body: Zeroizing<Vec<u8>>, limits: Limits) -> Result<Vec<Row>, Error> {
    let mut c = Cursor {
        bytes: &body,
        at: 0,
    };
    if c.take(8)? != MAGIC {
        return Err(Error::Storage);
    }
    let count = usize::try_from(c.u32()?).map_err(|_| Error::Capacity)?;
    if count > limits.rows {
        return Err(Error::Capacity);
    }
    let mut rows = Vec::new();
    rows.try_reserve_exact(count).map_err(|_| Error::Capacity)?;
    for _ in 0..count {
        let serial = c.u64()?;
        let zone = Zone::new(SecretKey::from_serialized(c.take(36)?)?);
        let label = usize::from(c.u16()?);
        let records = c.u16()?;
        let size = usize::try_from(c.u32()?).map_err(|_| Error::Capacity)?;
        let hint = c.u32()?;
        if label > limits.label_bytes
            || usize::from(records) > limits.records_per_set
            || size > limits.record_bytes
            || (hint != u32::MAX
                && usize::try_from(hint).map_err(|_| Error::Capacity)? > limits.hint_bytes)
        {
            return Err(Error::Capacity);
        }
        let label = copy(c.take(label)?)?;
        let records =
            OwnedRecords::copy(Records::new(c.take(size)?, records)?, limits.record_bytes)?;
        let hint = if hint == u32::MAX {
            None
        } else {
            Some(Zeroizing::new(copy(c.take(
                usize::try_from(hint).map_err(|_| Error::Capacity)?,
            )?)?))
        };
        rows.push(Row::new(zone, label, records, hint, serial)?);
    }
    if c.at != body.len() {
        return Err(Error::Storage);
    }
    Ok(rows)
}
