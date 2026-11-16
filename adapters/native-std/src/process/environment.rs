//! Explicit UTF-16 environment blocks with native ordinal name ordering.
use std::{
    cmp::Ordering,
    ffi::{OsStr, OsString},
    io,
    os::windows::ffi::OsStrExt,
};
use windows_sys::Win32::Globalization::{
    CSTR_EQUAL, CSTR_GREATER_THAN, CSTR_LESS_THAN, CompareStringOrdinal,
};

/// Immutable native child environment with cached ordinal lookup keys.
/// Duplicate names retain their last input value, matching process creation.
#[derive(Clone, Debug)]
pub struct Environment {
    values: Vec<(OsString, OsString)>,
    keys: Vec<Vec<u16>>,
    maximum_units: usize,
}
impl Environment {
    /// Validate complete input before retaining it. Bounds count input UTF-16
    /// units and entries before duplicate elimination, as native creation does.
    pub fn new(values: Vec<(OsString, OsString)>, limits: super::LaunchLimits) -> io::Result<Self> {
        if values.len() > limits.environment_entries {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut keys = Vec::new();
        keys.try_reserve_exact(values.len())
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        let mut units = if values.is_empty() { 2usize } else { 1usize };
        for (key, value) in &values {
            let key = wide(key, limits.environment_units.saturating_sub(units))?;
            if !key_valid(&key) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid native environment name",
                ));
            }
            units = units
                .checked_add(key.len() + 2)
                .filter(|units| *units <= limits.environment_units)
                .ok_or(io::ErrorKind::InvalidInput)?;
            for unit in value.encode_wide() {
                if unit == 0 || units == limits.environment_units {
                    return Err(io::ErrorKind::InvalidInput.into());
                }
                units += 1;
            }
            keys.push(key);
        }
        if units > limits.environment_units {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(Self {
            values,
            keys,
            maximum_units: limits.environment_units,
        })
    }
    /// Original owned entries in input order, including native drive entries.
    pub fn values(&self) -> &[(OsString, OsString)] {
        &self.values
    }
    /// Fallible native ordinal lookup; no ASCII folding or Unicode replacement.
    /// Lookup allocates one bounded key, independent of the number of entries.
    pub fn value(&self, name: &OsStr) -> io::Result<Option<&OsStr>> {
        let name = wide(name, self.maximum_units)?;
        if !key_valid(&name) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        for (key, (_, value)) in self.keys.iter().zip(&self.values).rev() {
            if compare(key, &name)? == Ordering::Equal {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }
}

pub(super) fn wide(value: &OsStr, maximum: usize) -> io::Result<Vec<u16>> {
    let length = value.encode_wide().take(maximum.saturating_add(1)).count();
    if length > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native process string exceeds its UTF-16 budget",
        ));
    }
    let mut units = Vec::new();
    units
        .try_reserve_exact(length)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    for unit in value.encode_wide() {
        if unit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "NUL in native process input",
            ));
        }
        units.push(unit);
    }
    Ok(units)
}
struct Entry {
    key: Vec<u16>,
    value: Vec<u16>,
    exported: bool,
}
#[expect(
    unsafe_code,
    reason = "CompareStringOrdinal borrows bounded initialized UTF-16 key slices with exact checked lengths and no retained pointers"
)]
fn compare(a: &[u16], b: &[u16]) -> io::Result<Ordering> {
    let a_len = i32::try_from(a.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
    let b_len = i32::try_from(b.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
    // SAFETY: live complete key extents, explicit lengths, valid ignore-case flag.
    match unsafe { CompareStringOrdinal(a.as_ptr(), a_len, b.as_ptr(), b_len, 1) } {
        CSTR_LESS_THAN => Ok(Ordering::Less),
        CSTR_EQUAL => Ok(Ordering::Equal),
        CSTR_GREATER_THAN => Ok(Ordering::Greater),
        _ => Err(io::Error::last_os_error()),
    }
}
fn key_valid(key: &[u16]) -> bool {
    if key.is_empty() {
        return false;
    }
    if !key.contains(&(b'=' as u16)) {
        return true;
    }
    // Native per-drive current-directory variables are the only special keys.
    key.len() == 3
        && key[0] == b'=' as u16
        && key[2] == b':' as u16
        && (key[1] >= b'A' as u16 && key[1] <= b'Z' as u16
            || key[1] >= b'a' as u16 && key[1] <= b'z' as u16)
}
fn indices(entries: &[Entry]) -> io::Result<Vec<usize>> {
    let mut source = Vec::new();
    source
        .try_reserve_exact(entries.len())
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    source.extend(0..entries.len());
    let mut target = Vec::new();
    target
        .try_reserve_exact(entries.len())
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    target.resize(entries.len(), 0);
    // Fallible stable merge ordering propagates a native comparison error;
    // no fallible comparator is hidden inside an infallible sorting callback.
    let mut width = 1;
    while width < source.len() {
        for start in (0..source.len()).step_by(width * 2) {
            let middle = (start + width).min(source.len());
            let end = (middle + width).min(source.len());
            let (mut left, mut right) = (start, middle);
            for slot in &mut target[start..end] {
                if left < middle
                    && (right == end
                        || compare(&entries[source[left]].key, &entries[source[right]].key)?
                            != Ordering::Greater)
                {
                    *slot = source[left];
                    left += 1;
                } else {
                    *slot = source[right];
                    right += 1;
                }
            }
        }
        std::mem::swap(&mut source, &mut target);
        width *= 2;
    }
    Ok(source)
}
pub(super) fn encode(
    values: &[(OsString, OsString)],
    exports: &[(OsString, OsString)],
    maximum: usize,
    maximum_entries: usize,
) -> io::Result<Vec<u16>> {
    let count = values
        .len()
        .checked_add(exports.len())
        .filter(|count| *count <= maximum_entries)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "native process environment entry capacity",
            )
        })?;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(count)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    let mut units = if count == 0 { 2usize } else { 1usize };
    for (index, (key, value)) in values.iter().chain(exports).enumerate() {
        let key = wide(key, maximum.saturating_sub(units))?;
        if !key_valid(&key) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid native environment name",
            ));
        }
        units = units
            .checked_add(key.len() + 2)
            .filter(|n| *n <= maximum)
            .ok_or(io::ErrorKind::InvalidInput)?;
        let value = wide(value, maximum - units)?;
        units += value.len();
        entries.push(Entry {
            key,
            value,
            exported: index >= values.len(),
        });
    }
    let order = indices(&entries)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(units)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    let mut cursor = 0;
    while cursor < order.len() {
        let start = cursor;
        while cursor + 1 < order.len()
            && compare(&entries[order[cursor]].key, &entries[order[cursor + 1]].key)?
                == Ordering::Equal
        {
            cursor += 1;
        }
        if order[start..=cursor]
            .iter()
            .filter(|index| entries[**index].exported)
            .count()
            > 1
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "duplicate inherited-handle environment name",
            ));
        }
        let entry = &entries[order[cursor]];
        output.extend_from_slice(&entry.key);
        output.push(b'=' as u16);
        output.extend_from_slice(&entry.value);
        output.push(0);
        cursor += 1;
    }
    if output.is_empty() {
        output.push(0);
    }
    output.push(0);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::ffi::OsStringExt;
    fn check(condition: bool, message: &'static str) -> io::Result<()> {
        if condition {
            Ok(())
        } else {
            Err(io::Error::other(message))
        }
    }
    #[test]
    fn lookup_uses_native_ordinal_names_and_retains_original_units() -> io::Result<()> {
        let value = OsString::from_wide(&[0xd800, b'x' as u16]);
        let environment = Environment::new(
            vec![
                ("PaTh".into(), "first".into()),
                ("path".into(), "last".into()),
                ("Ä".into(), value.clone()),
                ("=C:".into(), "C:\\private".into()),
            ],
            super::super::LaunchLimits::default(),
        )?;
        check(
            environment.value(OsStr::new("PATH"))? == Some(OsStr::new("last")),
            "duplicate native names lost last input",
        )?;
        check(
            environment.value(OsStr::new("ä"))? == Some(value.as_os_str()),
            "native non-ASCII name or surrogate value changed",
        )?;
        check(
            environment.value(OsStr::new("=c:"))? == Some(OsStr::new("C:\\private")),
            "per-drive snapshot variable changed",
        )?;
        check(
            environment.value(OsStr::new("absent"))?.is_none(),
            "snapshot manufactured a value",
        )?;
        check(
            environment.value(OsStr::new("bad=name")).is_err(),
            "invalid lookup name became absence",
        )
    }
    #[test]
    fn snapshot_refuses_complete_input_beyond_native_bounds() -> io::Result<()> {
        let limits = super::super::LaunchLimits::default();
        check(
            Environment::new(
                Vec::new(),
                super::super::LaunchLimits {
                    environment_units: 1,
                    ..limits
                },
            )
            .is_err(),
            "empty environment exceeded terminator budget",
        )?;
        check(
            Environment::new(
                vec![("name".into(), "value".into())],
                super::super::LaunchLimits {
                    environment_entries: 0,
                    ..limits
                },
            )
            .is_err(),
            "snapshot exceeded entry budget",
        )?;
        check(
            Environment::new(vec![("name".into(), OsString::from_wide(&[0]))], limits).is_err(),
            "snapshot retained a NUL value",
        )
    }
}
