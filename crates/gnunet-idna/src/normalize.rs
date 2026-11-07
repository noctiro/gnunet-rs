//! Canonical decomposition, stable ordering and composition from UAX15.
use crate::{Error, NativeProfile, ccc, tables};
fn decompose(cp: u32, out: &mut [u32], n: &mut usize, profile: NativeProfile) -> Result<(), Error> {
    if (0xac00..0xd7a4).contains(&cp) {
        let s = cp - 0xac00;
        let seq = [0x1100 + s / 588, 0x1161 + (s % 588) / 28, 0x11a7 + s % 28];
        let len = if s.is_multiple_of(28) { 2 } else { 3 };
        append(&seq[..len], out, n)
    } else {
        let table = if profile == NativeProfile::Unicode15_1 {
            tables::DECOMPOSITION
        } else {
            tables::DECOMPOSITION18
        };
        let decomposed = if profile == NativeProfile::Unicode15_1 {
            tables::DECOMPOSED
        } else {
            tables::DECOMPOSED18
        };
        match table.binary_search_by_key(&cp, |x| x.0) {
            Ok(i) => {
                let (_, s, l) = table[i];
                append(
                    &decomposed[usize::from(s)..usize::from(s) + usize::from(l)],
                    out,
                    n,
                )
            }
            Err(_) => append(core::slice::from_ref(&cp), out, n),
        }
    }
}
fn append(seq: &[u32], out: &mut [u32], n: &mut usize) -> Result<(), Error> {
    if *n + seq.len() > out.len() {
        return Err(Error::Resource);
    }
    out[*n..*n + seq.len()].copy_from_slice(seq);
    *n += seq.len();
    Ok(())
}
fn compose(a: u32, b: u32, profile: NativeProfile) -> Option<u32> {
    if (0x1100..0x1113).contains(&a) && (0x1161..0x1176).contains(&b) {
        return Some(0xac00 + (a - 0x1100) * 588 + (b - 0x1161) * 28);
    }
    if (0xac00..0xd7a4).contains(&a)
        && (a - 0xac00).is_multiple_of(28)
        && (0x11a8..0x11c3).contains(&b)
    {
        return Some(a + b - 0x11a7);
    }
    let table = if profile == NativeProfile::Unicode15_1 {
        tables::COMPOSITION
    } else {
        tables::COMPOSITION18
    };
    table
        .binary_search_by_key(&(a, b), |x| (x.0, x.1))
        .ok()
        .map(|i| table[i].2)
}
pub(crate) fn nfc(input: &[u32], out: &mut [u32], profile: NativeProfile) -> Result<usize, Error> {
    let mut n = 0;
    for cp in input {
        decompose(*cp, out, &mut n, profile)?;
    }
    for i in 1..n {
        let class = ccc(out[i], profile);
        if class == 0 {
            continue;
        }
        let mut p = i;
        while p > 0 && ccc(out[p - 1], profile) > class {
            out.swap(p, p - 1);
            p -= 1;
        }
    }
    if n == 0 {
        return Ok(0);
    }
    let mut starter = 0;
    let mut previous_class = ccc(out[0], profile);
    let mut used = 1;
    for i in 1..n {
        let cp = out[i];
        let class = ccc(cp, profile);
        if (previous_class == 0 || previous_class < class)
            && let Some(composed) = compose(out[starter], cp, profile)
        {
            out[starter] = composed;
            continue;
        }
        if class == 0 {
            starter = used;
        }
        previous_class = class;
        out[used] = cp;
        used += 1;
    }
    Ok(used)
}

/// Canonically decompose and stably order using caller scratch. A counting sort
/// handles unordered nonstarter runs in linear bounded work; equal combining
/// classes keep their original order. NFC/IDNA entry points remain unchanged.
pub(crate) fn nfd(
    input: &[u32],
    out: &mut [u32],
    scratch: &mut [u32],
    profile: NativeProfile,
) -> Result<usize, Error> {
    let mut n = 0;
    for cp in input {
        decompose(*cp, out, &mut n, profile)?;
    }
    if scratch.len() < n {
        return Err(Error::Resource);
    }
    let mut begin = 0;
    while begin < n {
        if ccc(out[begin], profile) == 0 {
            begin += 1;
            continue;
        }
        let mut end = begin + 1;
        let mut ordered = true;
        while end < n && ccc(out[end], profile) != 0 {
            ordered &= ccc(out[end - 1], profile) <= ccc(out[end], profile);
            end += 1;
        }
        if !ordered {
            let mut counts = [0usize; 256];
            for cp in &out[begin..end] {
                counts[usize::from(ccc(*cp, profile))] += 1;
            }
            let mut offset = begin;
            for count in &mut counts {
                let len = *count;
                *count = offset;
                offset += len;
            }
            for cp in &out[begin..end] {
                let slot = &mut counts[usize::from(ccc(*cp, profile))];
                scratch[*slot] = *cp;
                *slot += 1;
            }
            out[begin..end].copy_from_slice(&scratch[begin..end]);
        }
        begin = end;
    }
    Ok(n)
}

/// Generic bounded NFC shares the linear canonical-order pass and composes in
/// place. The caller's output/scratch are the only variable-sized resources.
pub(crate) fn nfc_bounded(
    input: &[u32],
    out: &mut [u32],
    scratch: &mut [u32],
    profile: NativeProfile,
) -> Result<usize, Error> {
    let n = nfd(input, out, scratch, profile)?;
    if n == 0 {
        return Ok(0);
    }
    let mut starter = 0;
    let mut previous_class = ccc(out[0], profile);
    let mut used = 1;
    for i in 1..n {
        let cp = out[i];
        let class = ccc(cp, profile);
        if (previous_class == 0 || previous_class < class)
            && let Some(composed) = compose(out[starter], cp, profile)
        {
            out[starter] = composed;
            continue;
        }
        if class == 0 {
            starter = used;
        }
        previous_class = class;
        out[used] = cp;
        used += 1;
    }
    Ok(used)
}
