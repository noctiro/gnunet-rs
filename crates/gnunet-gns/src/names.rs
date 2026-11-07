use crate::{Error, ZoneKey};
/// Local administrator's complete suffix-to-public-zone mapping.
#[derive(Clone, Copy, Debug)]
pub struct Mapping<'a> {
    /// Label-boundary suffix, without a leading dot.
    pub suffix: &'a str,
    /// Authoritative public zone.
    pub zone: ZoneKey,
}
/// A discovered zone and remaining name, without DNS fallback authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartZone<'a> {
    /// Selected public zone.
    pub zone: ZoneKey,
    /// Name relative to that zone; empty denotes apex.
    pub name: &'a str,
}
/// Validate GNS name structure without imposing DNS length or case rules.
pub fn validate_name(name: &str) -> Result<(), Error> {
    if name.as_bytes().contains(&0)
        || (!name.is_empty() && name.split('.').any(|s| s.is_empty() || s == "+"))
    {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
/// RFC9498§7.1 zTLD-first, then longest exact label-boundary local suffix.
/// Inputs are canonical NFC names; allocation-backed Resolver::lookup_name
/// performs normalization when accepting unnormalized application strings.
/// Equal-length matching mappings are a configuration error, even if keys agree.
/// Supported PKEY/EDKEY zTLDs fit one label; a recognized malformed ztype
/// prefix is an error and cannot fall back to a local mapping or DNS.
pub fn select_start_zone<'a>(
    name: &'a str,
    mappings: &[Mapping<'_>],
) -> Result<StartZone<'a>, Error> {
    validate_name(name)?;
    let (rest, last) = name.rsplit_once('.').unwrap_or(("", name));
    if supported_prefix(last) {
        return Ok(StartZone {
            zone: ZoneKey::from_ztld(last)?,
            name: rest,
        });
    }
    let mut best: Option<(usize, ZoneKey)> = None;
    for (index, mapping) in mappings.iter().enumerate() {
        validate_name(mapping.suffix)?;
        if mapping.suffix.is_empty() {
            return Err(Error::InvalidInput);
        }
        let matches = name == mapping.suffix
            || name
                .strip_suffix(mapping.suffix)
                .is_some_and(|prefix| prefix.ends_with('.'));
        if !matches {
            continue;
        }
        if mappings[..index]
            .iter()
            .any(|previous| previous.suffix == mapping.suffix)
        {
            return Err(Error::Conflict);
        }
        match best {
            Some((n, _)) if n == mapping.suffix.len() => return Err(Error::Conflict),
            Some((n, _)) if n > mapping.suffix.len() => {}
            _ => best = Some((mapping.suffix.len(), mapping.zone)),
        }
    }
    let (len, zone) = best.ok_or(Error::NotFound)?;
    let end = name.len().saturating_sub(len + 1);
    Ok(StartZone {
        zone,
        name: &name[..end],
    })
}
fn supported_prefix(text: &str) -> bool {
    let mut bits = 0_u64;
    let mut n = 0;
    for b in text.bytes().take(7) {
        let b = match b.to_ascii_uppercase() {
            b'O' => b'0',
            b'I' | b'L' => b'1',
            b'U' => b'V',
            b => b,
        };
        let Some(i) = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"
            .iter()
            .position(|&x| x == b)
        else {
            return false;
        };
        bits = (bits << 5) | i as u64;
        n += 5;
    }
    n >= 32 && matches!(bits >> (n - 32), 65536 | 65556)
}
