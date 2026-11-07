use crate::{Error, RecordData, RecordFlags, RecordType, ZoneKey};
use alloc::{string::String, vec::Vec};
use gnunet_dns::Name;
/// Security provenance of a returned record. DNS/system results never acquire
/// GNS authentication merely because they use the same record payload format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Origin {
    /// Signature and requested zone/NFC label verified in the owning resolver.
    Gns(ZoneKey),
    /// Recursive DNS result from the explicitly selected server.
    Dns(core::net::IpAddr),
    /// Result of the explicit default-system redirection port.
    System,
    /// Optional numeric-address application convenience; no GNS lookup occurred.
    Literal,
}
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
pub(crate) fn cstring(data: &[u8]) -> Result<&str, Error> {
    let data = data.strip_suffix(&[0]).ok_or(Error::Malformed)?;
    if data.contains(&0) {
        return Err(Error::Malformed);
    }
    core::str::from_utf8(data).map_err(|_| Error::Malformed)
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
pub(crate) fn zone_text(zone: ZoneKey) -> Result<String, Error> {
    let mut out = [0; 58];
    text(zone.write_ztld(&mut out)?)
}
pub(crate) fn expand(input: &str, zone: ZoneKey, max: usize) -> Result<String, Error> {
    if input == "+" {
        return zone_text(zone);
    }
    if let Some(rest) = input.strip_suffix(".+") {
        join(rest, &zone_text(zone)?, max)
    } else {
        text(input)
    }
}
pub(crate) fn rewrite(record: &mut Record, zone: ZoneKey, max: usize) -> Result<(), Error> {
    if record.record_type == RecordType::REDIRECT {
        let name = expand(cstring(&record.data)?, zone, max)?;
        record.data = bytes(name.as_bytes())?;
        record
            .data
            .try_reserve_exact(1)
            .map_err(|_| Error::Capacity)?;
        record.data.push(0);
        return Ok(());
    }
    // Stored DNS RDATA names are uncompressed; no packet exists for pointers.
    let start = match record.record_type.value() {
        2 | 5 | 12 | 39 | 6 => 0,
        15 => 2,
        33 => 6,
        _ => return Ok(()),
    };
    if start > record.data.len() {
        return Err(Error::Truncated);
    }
    let mut output = Vec::new();
    output.try_reserve_exact(512).map_err(|_| Error::Capacity)?;
    output.extend_from_slice(&record.data[..start]);
    let mut offset = start;
    let count = if record.record_type == RecordType::SOA {
        2
    } else {
        1
    };
    for _ in 0..count {
        let start = offset;
        loop {
            let n = usize::from(*record.data.get(offset).ok_or(Error::Truncated)?);
            offset += 1;
            if n == 0 {
                break;
            }
            if n > 63 {
                return Err(Error::Malformed);
            }
            offset = offset.checked_add(n).ok_or(Error::Overflow)?;
            if offset > record.data.len() {
                return Err(Error::Truncated);
            }
        }
        let original = Name::from_wire(&record.data[start..offset])?;
        let wire = original.wire();
        if wire.ends_with(&[1, b'+', 0]) {
            let mut ztld = [0; 58];
            let label = zone.write_ztld(&mut ztld)?;
            let prefix = &wire[..wire.len() - 3];
            if prefix.len() + label.len() + 2 > 255 {
                return Err(Error::TooLarge);
            }
            output
                .try_reserve_exact(prefix.len() + label.len() + 2)
                .map_err(|_| Error::Capacity)?;
            output.extend_from_slice(prefix);
            output.push(58);
            output.extend_from_slice(label.as_bytes());
            output.push(0);
        } else {
            output
                .try_reserve_exact(wire.len())
                .map_err(|_| Error::Capacity)?;
            output.extend_from_slice(wire);
        }
    }
    if record.record_type == RecordType::SOA {
        if record.data.len() - offset != 20 {
            return Err(Error::Malformed);
        }
        output.try_reserve_exact(20).map_err(|_| Error::Capacity)?;
        output.extend_from_slice(&record.data[offset..]);
    } else if offset != record.data.len() {
        return Err(Error::Malformed);
    }
    record.data = output;
    Ok(())
}

pub(crate) fn filled<T: Clone>(len: usize, value: T) -> Result<Vec<T>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(len).map_err(|_| Error::Capacity)?;
    v.resize(len, value);
    Ok(v)
}
