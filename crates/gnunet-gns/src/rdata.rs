//! Shared parsing and same-zone expansion of GNS target names in record data.

use crate::{Error, RecordType, ZoneKey};
use gnunet_dns::Name;
use gnunet_gnsrecord::ZONE_TEXT_LEN;

const DNS_NAME_BYTES: usize = 255;
const SOA_TAIL_BYTES: usize = 20;
pub(crate) const DNS_REWRITE_BYTES: usize = 2 * DNS_NAME_BYTES + SOA_TAIL_BYTES;

pub(crate) fn cstring(data: &[u8]) -> Result<&str, Error> {
    let data = data.strip_suffix(&[0]).ok_or(Error::Malformed)?;
    if data.contains(&0) {
        return Err(Error::Malformed);
    }
    core::str::from_utf8(data).map_err(|_| Error::Malformed)
}

fn dns_shape(kind: RecordType) -> Option<(usize, usize, usize)> {
    match kind.value() {
        2 | 5 | 12 | 39 => Some((0, 1, 0)),
        6 => Some((0, 2, SOA_TAIL_BYTES)),
        15 => Some((2, 1, 0)),
        33 => Some((6, 1, 0)),
        _ => None,
    }
}

fn visit_names(
    data: &[u8],
    offset: usize,
    names: usize,
    tail: usize,
    mut visit: impl FnMut(Name<'_>) -> Result<(), Error>,
) -> Result<&[u8], Error> {
    let mut cursor = offset;
    for _ in 0..names {
        let start = cursor;
        loop {
            let length = usize::from(*data.get(cursor).ok_or(Error::Truncated)?);
            cursor += 1;
            if length == 0 {
                break;
            }
            if length > 63 {
                return Err(Error::Malformed);
            }
            cursor = cursor.checked_add(length).ok_or(Error::Overflow)?;
        }
        visit(Name::from_wire(&data[start..cursor])?)?;
    }
    let remaining = data.get(cursor..).ok_or(Error::Truncated)?;
    if remaining.len() != tail {
        return Err(Error::Malformed);
    }
    Ok(remaining)
}

pub(crate) fn validate_names(kind: RecordType, data: &[u8]) -> Result<(), Error> {
    if let Some((offset, names, tail)) = dns_shape(kind) {
        visit_names(data, offset, names, tail, |_| Ok(()))?;
    }
    Ok(())
}

#[cfg(feature = "alloc")]
pub(crate) fn rewrite_capacity(kind: RecordType, data: &[u8]) -> Result<usize, Error> {
    if kind == RecordType::REDIRECT {
        return match relative_redirect_prefix(cstring(data)?) {
            Some(prefix) => prefix
                .len()
                .checked_add(ZONE_TEXT_LEN + 1)
                .ok_or(Error::Overflow),
            None => Ok(0),
        };
    }
    Ok(if dns_shape(kind).is_some() {
        DNS_REWRITE_BYTES
    } else {
        0
    })
}

fn relative_redirect_prefix(target: &str) -> Option<&str> {
    if target == "+" {
        return Some("");
    }
    let prefix = target.strip_suffix(".+")?;
    Some(if prefix.is_empty() {
        ""
    } else {
        &target[..prefix.len() + 1]
    })
}

pub(crate) fn rewrite_into<'a>(
    kind: RecordType,
    data: &'a [u8],
    zone: ZoneKey,
    name_limit: usize,
    output: &'a mut [u8],
) -> Result<&'a [u8], Error> {
    if kind == RecordType::REDIRECT {
        let target = cstring(data)?;
        let Some(first) = relative_redirect_prefix(target) else {
            return Ok(data);
        };
        let name_bytes = first
            .len()
            .checked_add(ZONE_TEXT_LEN)
            .ok_or(Error::Overflow)?;
        if target != "+" && name_bytes > name_limit {
            return Err(Error::TooLarge);
        }
        let result = output.get_mut(..=name_bytes).ok_or(Error::Capacity)?;
        result[..first.len()].copy_from_slice(first.as_bytes());
        zone.write_ztld(&mut result[first.len()..name_bytes])?;
        result[name_bytes] = 0;
        return Ok(result);
    }
    let Some((offset, names, tail)) = dns_shape(kind) else {
        return Ok(data);
    };
    let fixed = data.get(..offset).ok_or(Error::Truncated)?;
    output
        .get_mut(..offset)
        .ok_or(Error::Capacity)?
        .copy_from_slice(fixed);
    let mut len = offset;
    let rest = visit_names(data, offset, names, tail, |name| {
        if let Some(prefix) = name.wire().strip_suffix(&[1, b'+', 0]) {
            if prefix.len() + ZONE_TEXT_LEN + 2 > DNS_NAME_BYTES {
                return Err(Error::TooLarge);
            }
            let end = len
                .checked_add(prefix.len() + ZONE_TEXT_LEN + 2)
                .ok_or(Error::Overflow)?;
            let target = output.get_mut(len..end).ok_or(Error::Capacity)?;
            let split = prefix.len();
            target[..split].copy_from_slice(prefix);
            target[split] = u8::try_from(ZONE_TEXT_LEN).map_err(|_| Error::Overflow)?;
            zone.write_ztld(&mut target[split + 1..split + 1 + ZONE_TEXT_LEN])?;
            target[split + 1 + ZONE_TEXT_LEN] = 0;
            len = end;
            Ok(())
        } else {
            name.encode_at(output, &mut len).map(|_| ())
        }
    })?;
    let end = len.checked_add(rest.len()).ok_or(Error::Overflow)?;
    output
        .get_mut(len..end)
        .ok_or(Error::Capacity)?
        .copy_from_slice(rest);
    Ok(&output[..end])
}
