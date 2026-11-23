use crate::{Error, Origin, RecordData, RecordFlags, RecordType, ZoneKey};
use alloc::{string::String, vec::Vec};

/// Explicit application convenience corresponding to GNUnet's numeric input
/// shortcut. Core zone lookup does not silently reinterpret numeric GNS labels.
pub fn address_literal(input: &str) -> Result<Option<Record>, Error> {
    let Ok(ip) = input.parse::<core::net::IpAddr>() else {
        return Ok(None);
    };
    let (record_type, data) = match ip {
        core::net::IpAddr::V4(ip) => (RecordType::A, bytes(&ip.octets())?),
        core::net::IpAddr::V6(ip) => (RecordType::AAAA, bytes(&ip.octets())?),
    };
    Ok(Some(Record {
        origin: Origin::Literal,
        expiration_time: u64::MAX,
        record_type,
        flags: RecordFlags::NONE,
        data,
    }))
}
/// Owned actual record result; expiration is absolute UTC microseconds unless
/// RELATIVE_EXPIRATION is set (e.g. synthesized DNS LEHO).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    /// Original trust boundary of this record or derived unboxed payload.
    pub origin: Origin,
    /// Expiration value in the flag-selected time domain.
    pub expiration_time: u64,
    /// Original or explicitly unboxed record type.
    pub record_type: RecordType,
    /// Original flags, except selected SHADOW is cleared.
    pub flags: RecordFlags,
    /// Complete record payload.
    pub data: Vec<u8>,
}
impl Record {
    /// Borrow for canonical official record serialization.
    pub fn as_data(&self) -> RecordData<'_> {
        RecordData {
            expiration_time: self.expiration_time,
            record_type: self.record_type,
            flags: self.flags,
            data: &self.data,
        }
    }
    pub(crate) fn copy(rd: RecordData<'_>, origin: Origin) -> Result<Self, Error> {
        Ok(Self {
            origin,
            expiration_time: rd.expiration_time,
            record_type: rd.record_type,
            flags: rd.flags,
            data: bytes(rd.data)?,
        })
    }
}
pub(crate) fn bytes(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(input.len())
        .map_err(|_| Error::Capacity)?;
    v.extend_from_slice(input);
    Ok(v)
}
pub(crate) fn text(input: &str) -> Result<String, Error> {
    String::from_utf8(bytes(input.as_bytes())?).map_err(|_| Error::Malformed)
}
pub(crate) fn join(left: &str, right: &str, max: usize) -> Result<String, Error> {
    let len = left
        .len()
        .checked_add(right.len())
        .and_then(|n| n.checked_add(usize::from(!left.is_empty() && !right.is_empty())))
        .ok_or(Error::Overflow)?;
    if len > max {
        return Err(Error::TooLarge);
    }
    let mut result = String::new();
    result.try_reserve_exact(len).map_err(|_| Error::Capacity)?;
    result.push_str(left);
    if !left.is_empty() && !right.is_empty() {
        result.push('.');
    }
    result.push_str(right);
    Ok(result)
}
pub(crate) fn rewrite(record: &mut Record, zone: ZoneKey, max: usize) -> Result<(), Error> {
    let width = crate::rdata::rewrite_capacity(record.record_type, &record.data)?;
    if width == 0 {
        return Ok(());
    }
    let mut output = filled(width, 0_u8)?;
    let len =
        crate::rdata::rewrite_into(record.record_type, &record.data, zone, max, &mut output)?.len();
    output.truncate(len);
    record.data = output;
    Ok(())
}

pub(crate) fn filled<T: Clone>(len: usize, value: T) -> Result<Vec<T>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(len).map_err(|_| Error::Capacity)?;
    v.resize(len, value);
    Ok(v)
}
