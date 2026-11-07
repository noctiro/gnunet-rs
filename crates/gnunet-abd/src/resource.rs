use alloc::vec::Vec;
use core::mem::size_of;
use gnunet_types::Error;

pub(crate) fn bytes<T>(v: &Vec<T>) -> Result<usize, Error> {
    v.capacity()
        .checked_mul(size_of::<T>())
        .ok_or(Error::Overflow)
}
pub(crate) fn sum(parts: &[usize]) -> Result<usize, Error> {
    parts
        .iter()
        .try_fold(0usize, |n, p| n.checked_add(*p).ok_or(Error::Overflow))
}
// An unpublished allocation preserves the old table and actual byte accounting
// on allocator/budget failure. Retained capacity, rather than live length, is
// charged. Temporary allocator peaks are not an RSS measurement/guarantee.
pub(crate) fn reserve<T>(
    v: &mut Vec<T>,
    need: usize,
    limit: usize,
    available: usize,
) -> Result<(), Error> {
    if need > limit {
        return Err(Error::Capacity);
    }
    if need <= v.capacity() {
        return Ok(());
    }
    let old = bytes(v)?;
    let geometric = v
        .capacity()
        .checked_mul(2)
        .unwrap_or(limit)
        .max(4)
        .max(need)
        .min(limit);
    for proposed in [geometric, need] {
        let mut staged = Vec::new();
        if staged.try_reserve_exact(proposed).is_err() {
            continue;
        }
        let actual = bytes(&staged)?;
        if actual.saturating_sub(old) > available {
            continue;
        }
        staged.append(v);
        *v = staged;
        return Ok(());
    }
    Err(Error::Capacity)
}
pub(crate) fn copy(input: &[u8], available: usize) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    reserve(&mut out, input.len(), input.len(), available)?;
    out.extend_from_slice(input);
    Ok(out)
}
pub(crate) fn filled<T: Clone>(n: usize, value: T, available: usize) -> Result<Vec<T>, Error> {
    let mut out = Vec::new();
    reserve(&mut out, n, n, available)?;
    out.resize(n, value);
    Ok(out)
}
pub(crate) fn normalize(input: &[u8], maximum: usize, available: usize) -> Result<Vec<u8>, Error> {
    if input.is_empty() || input.len() > maximum || input.contains(&0) {
        return Err(Error::InvalidInput);
    }
    let mut output = filled(maximum, 0u8, available)?;
    let mut used = bytes(&output)?;
    let mut lowered = filled(
        maximum.checked_mul(3).ok_or(Error::Overflow)?,
        0u32,
        available.checked_sub(used).ok_or(Error::Capacity)?,
    )?;
    used = sum(&[used, bytes(&lowered)?])?;
    let mut normalized = filled(
        maximum,
        0u32,
        available.checked_sub(used).ok_or(Error::Capacity)?,
    )?;
    used = sum(&[used, bytes(&normalized)?])?;
    let mut ordering = filled(
        maximum,
        0u32,
        available.checked_sub(used).ok_or(Error::Capacity)?,
    )?;
    let n = gnunet_identity::normalize_name_into(
        input,
        &mut output,
        &mut lowered,
        &mut normalized,
        &mut ordering,
    )?;
    output.truncate(n);
    drop(ordering);
    drop(normalized);
    drop(lowered);
    if output.capacity() == n {
        return Ok(output);
    }
    // The Unicode scratch is temporary. Retained role storage follows actual
    // normalized length, rather than preallocating maximum bytes per short name.
    copy(
        &output,
        available
            .checked_sub(bytes(&output)?)
            .ok_or(Error::Capacity)?,
    )
}
