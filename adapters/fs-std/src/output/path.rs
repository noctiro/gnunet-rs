//! Validate native spelling before Path::components can normalize unsafe names.
use super::invalid_name;
use crate::{Error, Result};
use std::{
    ffi::OsStr,
    path::{Component, Path},
};
const MAX_UNITS: usize = 4096;
const MAX_COMPONENTS: usize = 128;
fn spelling(units: impl Iterator<Item = u32>) -> Result<()> {
    let mut length = 0;
    let mut component = 0;
    let mut dots = 0;
    let mut first = 0;
    for unit in units {
        length += 1;
        if length > MAX_UNITS {
            return Err(Error::Limit);
        }
        if matches!(unit, 0 | 92) {
            return Err(invalid_name());
        }
        #[cfg(windows)]
        if unit == u32::from(b':') {
            return Err(invalid_name());
        }
        if unit == u32::from(b'/') {
            if component == 0 || component == dots && component <= 2 {
                return Err(invalid_name());
            }
            component = 0;
            dots = 0;
        } else {
            if component == 0 {
                first = unit;
            }
            if component == 1
                && first <= 127
                && (first as u8).is_ascii_alphabetic()
                && unit == u32::from(b':')
            {
                return Err(invalid_name());
            }
            component += 1;
            dots += usize::from(unit == u32::from(b'.'));
        }
    }
    if component == 0 || component == dots && component <= 2 {
        return Err(invalid_name());
    }
    Ok(())
}
pub(crate) fn components(path: &Path) -> Result<Vec<&OsStr>> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        spelling(
            path.as_os_str()
                .as_bytes()
                .iter()
                .map(|byte| u32::from(*byte)),
        )?;
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        spelling(path.as_os_str().encode_wide().map(u32::from))?;
    }
    let mut result = Vec::new();
    for part in path.components() {
        let Component::Normal(name) = part else {
            return Err(invalid_name());
        };
        #[cfg(windows)]
        windows_component(name)?;
        if result.len() == MAX_COMPONENTS {
            return Err(Error::Limit);
        }
        result.try_reserve(1).map_err(|_| Error::Limit)?;
        result.push(name);
    }
    Ok(result)
}

#[cfg(windows)]
fn windows_component(name: &OsStr) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    let mut prefix = [0; 8];
    let mut length = 0;
    let mut stem_length = 0;
    let mut trimmed_stem = 0;
    let mut extension = false;
    let mut last = 0;
    for unit in name.encode_wide() {
        length += 1;
        if length > 255 || unit < 32 || matches!(unit, 34 | 42 | 58 | 60 | 62 | 63 | 124) {
            return Err(invalid_name());
        }
        last = unit;
        if unit == u16::from(b'.') {
            extension = true;
        }
        if !extension {
            if stem_length < prefix.len() {
                prefix[stem_length] = if (97..=122).contains(&unit) {
                    unit - 32
                } else {
                    unit
                };
            }
            stem_length += 1;
            if unit != u16::from(b' ') {
                trimmed_stem = stem_length;
            }
        }
    }
    if matches!(last, 32 | 46) {
        return Err(invalid_name());
    }
    let stem = &prefix[..trimmed_stem.min(prefix.len())];
    let equals = |wide: &[u16], ascii: &[u8]| {
        wide.iter()
            .copied()
            .eq(ascii.iter().copied().map(u16::from))
    };
    let reserved = [
        b"CON".as_slice(),
        b"PRN",
        b"AUX",
        b"NUL",
        b"CONIN$",
        b"CONOUT$",
    ]
    .iter()
    .any(|device| equals(stem, device))
        || stem.len() == 4
            && (equals(&stem[..3], b"COM") || equals(&stem[..3], b"LPT"))
            && matches!(stem[3], 49..=57 | 0xb9 | 0xb2 | 0xb3);
    if trimmed_stem <= prefix.len() && reserved {
        return Err(invalid_name());
    }
    Ok(())
}

/// Interpret an already validated protocol basename for the native filesystem.
/// Windows accepts actual UTF-8; internal WTF-8/local encodings never decode
/// peer-supplied names. Unix preserves the protocol's original basename bytes.
#[cfg(feature = "service")]
pub(crate) fn from_protocol_name(bytes: &[u8]) -> Result<&OsStr> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(OsStr::from_bytes(bytes))
    }
    #[cfg(windows)]
    {
        std::str::from_utf8(bytes)
            .map(OsStr::new)
            .map_err(|_| Error::Protocol(gnunet_types::Error::InvalidInput))
    }
}
