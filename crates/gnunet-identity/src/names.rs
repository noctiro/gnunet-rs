//! Locale-neutral Unicode18 lowercase followed by canonical NFD, as used by
//! GNUNET_STRINGS_utf8_tolower through libunistring1.5 u8_tolower(NULL,NFD).
use crate::tables;
use alloc::vec::Vec;
use gnunet_idna::{NativeProfile, normalize_nfd_scalars};
use gnunet_types::Error;
fn property(cp: u32, table: &[(u32, u32)]) -> bool {
    let i = table.partition_point(|r| r.1 < cp);
    table.get(i).is_some_and(|r| r.0 <= cp)
}
fn scalars(len: usize) -> Result<Vec<u32>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(len).map_err(|_| Error::Capacity)?;
    v.resize(len, 0);
    Ok(v)
}
fn lower(cp: u32) -> &'static [u32] {
    match tables::LOWER.binary_search_by_key(&cp, |r| r.0) {
        Ok(i) => {
            let (_, offset, len) = tables::LOWER[i];
            &tables::LOWERED[usize::from(offset)..usize::from(offset) + usize::from(len)]
        }
        Err(_) => &[],
    }
}
pub(crate) fn normalize(input: &[u8], maximum: usize) -> Result<Vec<u8>, Error> {
    // The largest actual protocol string has a four-byte prefix and final NUL.
    if input.len() > 65530 {
        return Err(Error::TooLarge);
    }
    if input.contains(&0) {
        return Err(Error::InvalidInput);
    }
    let text = core::str::from_utf8(input).map_err(|_| Error::InvalidInput)?;
    let mut count = 0usize;
    for c in text.chars() {
        count = count
            .checked_add(lower(u32::from(c)).len().max(1))
            .ok_or(Error::Overflow)?;
        if count > maximum {
            return Err(Error::TooLarge);
        }
    }
    let mut lowered = Vec::new();
    lowered
        .try_reserve_exact(count)
        .map_err(|_| Error::Capacity)?;
    let mut before_cased = false;
    for (index, c) in text.char_indices() {
        let cp = u32::from(c);
        if cp == 0x03a3 {
            let after_cased = text[index + c.len_utf8()..]
                .chars()
                .find(|c| !property(u32::from(*c), tables::IGNORABLE))
                .is_some_and(|c| property(u32::from(c), tables::CASED));
            lowered.push(if before_cased && !after_cased {
                0x03c2
            } else {
                0x03c3
            });
        } else {
            let mapped = lower(cp);
            if mapped.is_empty() {
                lowered.push(cp);
            } else {
                lowered.extend_from_slice(mapped);
            }
        }
        // Case_Ignorable takes precedence even for a scalar also marked Cased.
        if !property(cp, tables::IGNORABLE) {
            before_cased = property(cp, tables::CASED);
        }
    }
    let capacity = lowered
        .len()
        .checked_mul(4)
        .ok_or(Error::Overflow)?
        .min(maximum);
    let mut normalized = scalars(capacity)?;
    let mut ordering = scalars(capacity)?;
    let n = normalize_nfd_scalars(
        &lowered,
        &mut normalized,
        &mut ordering,
        NativeProfile::Libunistring1_5Unicode18_0,
    )
    .map_err(|_| Error::TooLarge)?;
    let mut bytes = 0usize;
    for cp in &normalized[..n] {
        bytes = bytes
            .checked_add(char::from_u32(*cp).ok_or(Error::InvalidInput)?.len_utf8())
            .ok_or(Error::Overflow)?;
    }
    if bytes > maximum {
        return Err(Error::TooLarge);
    }
    let mut out = Vec::new();
    out.try_reserve_exact(bytes).map_err(|_| Error::Capacity)?;
    for cp in &normalized[..n] {
        let c = char::from_u32(*cp).ok_or(Error::InvalidInput)?;
        let mut buffer = [0; 4];
        out.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
    }
    Ok(out)
}

// Caller-buffer companion used by pure credential/attribute adapters. This
// shares the existing exact tables/profile and performs no allocation or I/O.
pub(crate) fn normalize_into(
    input: &[u8],
    output: &mut [u8],
    lowered: &mut [u32],
    normalized: &mut [u32],
    ordering: &mut [u32],
) -> Result<usize, Error> {
    if input.len() > 65530 {
        return Err(Error::TooLarge);
    }
    if input.contains(&0) {
        return Err(Error::InvalidInput);
    }
    let text = core::str::from_utf8(input).map_err(|_| Error::InvalidInput)?;
    let mut count = 0usize;
    let mut before_cased = false;
    for (index, c) in text.char_indices() {
        let cp = u32::from(c);
        let special = if cp == 0x03a3 {
            let after_cased = text[index + c.len_utf8()..]
                .chars()
                .find(|c| !property(u32::from(*c), tables::IGNORABLE))
                .is_some_and(|c| property(u32::from(c), tables::CASED));
            Some(if before_cased && !after_cased {
                0x03c2
            } else {
                0x03c3
            })
        } else {
            None
        };
        if let Some(cp) = special {
            *lowered.get_mut(count).ok_or(Error::Capacity)? = cp;
            count = count.checked_add(1).ok_or(Error::Overflow)?;
        } else {
            let mapped = lower(cp);
            if mapped.is_empty() {
                *lowered.get_mut(count).ok_or(Error::Capacity)? = cp;
                count = count.checked_add(1).ok_or(Error::Overflow)?;
            } else {
                let end = count.checked_add(mapped.len()).ok_or(Error::Overflow)?;
                lowered
                    .get_mut(count..end)
                    .ok_or(Error::Capacity)?
                    .copy_from_slice(mapped);
                count = end;
            }
        }
        if !property(cp, tables::IGNORABLE) {
            before_cased = property(cp, tables::CASED);
        }
    }
    let n = normalize_nfd_scalars(
        &lowered[..count],
        normalized,
        ordering,
        NativeProfile::Libunistring1_5Unicode18_0,
    )
    .map_err(|_| Error::Capacity)?;
    let mut bytes = 0usize;
    for cp in &normalized[..n] {
        bytes = bytes
            .checked_add(char::from_u32(*cp).ok_or(Error::InvalidInput)?.len_utf8())
            .ok_or(Error::Overflow)?;
    }
    if bytes > output.len() {
        return Err(Error::Capacity);
    }
    let mut at = 0;
    for cp in &normalized[..n] {
        let c = char::from_u32(*cp).ok_or(Error::InvalidInput)?;
        let mut b = [0; 4];
        let raw = c.encode_utf8(&mut b).as_bytes();
        output[at..at + raw.len()].copy_from_slice(raw);
        at += raw.len();
    }
    Ok(bytes)
}
