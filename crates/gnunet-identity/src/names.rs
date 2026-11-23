//! Locale-neutral Unicode18 lowercase followed by canonical NFD, as used by
//! GNUNET_STRINGS_utf8_tolower through libunistring1.5 u8_tolower(NULL,NFD).
use crate::tables;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use gnunet_idna::{NativeProfile, normalize_nfd_scalars};
use gnunet_types::Error;

const INPUT_BYTES: usize = 65530;

fn property(cp: u32, table: &[(u32, u32)]) -> bool {
    let i = table.partition_point(|r| r.1 < cp);
    table.get(i).is_some_and(|r| r.0 <= cp)
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

fn text(input: &[u8]) -> Result<&str, Error> {
    if input.len() > INPUT_BYTES {
        return Err(Error::TooLarge);
    }
    if input.contains(&0) {
        return Err(Error::InvalidInput);
    }
    core::str::from_utf8(input).map_err(|_| Error::InvalidInput)
}

fn lowercase(input: &str, output: &mut [u32]) -> Result<usize, Error> {
    let mut used = 0_usize;
    let mut before_cased = false;
    for (index, c) in input.char_indices() {
        let cp = u32::from(c);
        let single;
        let mapped = if cp == 0x03a3 {
            let after_cased = input[index + c.len_utf8()..]
                .chars()
                .find(|c| !property(u32::from(*c), tables::IGNORABLE))
                .is_some_and(|c| property(u32::from(c), tables::CASED));
            single = [if before_cased && !after_cased {
                0x03c2
            } else {
                0x03c3
            }];
            &single[..]
        } else {
            let mapped = lower(cp);
            if mapped.is_empty() {
                single = [cp];
                &single[..]
            } else {
                mapped
            }
        };
        let end = used.checked_add(mapped.len()).ok_or(Error::Overflow)?;
        output
            .get_mut(used..end)
            .ok_or(Error::Capacity)?
            .copy_from_slice(mapped);
        used = end;
        // Case_Ignorable takes precedence even for a scalar also marked Cased.
        if !property(cp, tables::IGNORABLE) {
            before_cased = property(cp, tables::CASED);
        }
    }
    Ok(used)
}

fn nfd<'a>(input: &[u32], output: &'a mut [u32], ordering: &mut [u32]) -> Result<&'a [u32], Error> {
    let len = normalize_nfd_scalars(
        input,
        output,
        ordering,
        NativeProfile::Libunistring1_5Unicode18_0,
    )
    .map_err(|_| Error::Capacity)?;
    Ok(&output[..len])
}

fn utf8_len(input: &[u32]) -> Result<usize, Error> {
    input.iter().try_fold(0_usize, |count, &cp| {
        let c = char::from_u32(cp).ok_or(Error::InvalidInput)?;
        count.checked_add(c.len_utf8()).ok_or(Error::Overflow)
    })
}

fn write_utf8(input: &[u32], output: &mut [u8]) -> Result<(), Error> {
    let mut at = 0;
    for &cp in input {
        let c = char::from_u32(cp).ok_or(Error::InvalidInput)?;
        let mut bytes = [0; 4];
        let raw = c.encode_utf8(&mut bytes).as_bytes();
        output[at..at + raw.len()].copy_from_slice(raw);
        at += raw.len();
    }
    Ok(())
}

#[cfg(feature = "alloc")]
fn scalars(len: usize) -> Result<Vec<u32>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(len).map_err(|_| Error::Capacity)?;
    v.resize(len, 0);
    Ok(v)
}

#[cfg(feature = "alloc")]
pub(crate) fn normalize(input: &[u8], maximum: usize) -> Result<Vec<u8>, Error> {
    let text = text(input)?;
    let mut count = 0_usize;
    for c in text.chars() {
        count = count
            .checked_add(lower(u32::from(c)).len().max(1))
            .ok_or(Error::Overflow)?;
        if count > maximum {
            return Err(Error::TooLarge);
        }
    }
    let mut lowered = scalars(count)?;
    let used = lowercase(text, &mut lowered)?;
    let capacity = used.checked_mul(4).ok_or(Error::Overflow)?.min(maximum);
    let mut normalized = scalars(capacity)?;
    let mut ordering = scalars(capacity)?;
    let scalars =
        nfd(&lowered[..used], &mut normalized, &mut ordering).map_err(|_| Error::TooLarge)?;
    let count = utf8_len(scalars)?;
    if count > maximum {
        return Err(Error::TooLarge);
    }
    let mut out = Vec::new();
    out.try_reserve_exact(count).map_err(|_| Error::Capacity)?;
    out.resize(count, 0);
    write_utf8(scalars, &mut out)?;
    Ok(out)
}

pub(crate) fn normalize_into(
    input: &[u8],
    output: &mut [u8],
    lowered: &mut [u32],
    normalized: &mut [u32],
    ordering: &mut [u32],
) -> Result<usize, Error> {
    let used = lowercase(text(input)?, lowered)?;
    let scalars = nfd(&lowered[..used], normalized, ordering)?;
    let count = utf8_len(scalars)?;
    let output = output.get_mut(..count).ok_or(Error::Capacity)?;
    write_utf8(scalars, output)?;
    Ok(count)
}

pub(crate) fn lookup<'a>(
    name: &[u8],
    suffix: bool,
    mut names: impl Iterator<Item = &'a [u8]>,
) -> Result<Option<usize>, Error> {
    if name.len() > INPUT_BYTES || name.contains(&0) {
        return Err(Error::InvalidInput);
    }
    if !suffix {
        return Ok(names.position(|ego| ego.eq_ignore_ascii_case(name)));
    }
    let mut best = None;
    for (index, ego) in names.enumerate() {
        let len = ego.len();
        if len <= name.len()
            && name.ends_with(ego)
            && (len == name.len() || name[name.len() - len - 1] == b'.')
            && best.is_none_or(|(_, longest)| len > longest)
        {
            best = Some((index, len));
        }
    }
    Ok(best.map(|(index, _)| index))
}
