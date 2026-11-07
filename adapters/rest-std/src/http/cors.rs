//! Explicit bounded CORS configuration, separate from HTTP effect ownership.
use super::{Error, Fault, copy};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    ops::Range,
};
use zeroize::Zeroizing;

const CONFIG_BYTES: usize = 4096;
const ORIGINS: usize = 64;

/// One immutable CORS policy. Construct it before admitting HTTP connections.
/// Configuration is bounded to4096 bytes and64 comma-separated origin entries.
pub struct Cors {
    allowed: Zeroizing<Vec<u8>>,
    origins: Vec<Range<usize>>,
    wildcard: bool,
    echo_webext: bool,
    credentials: bool,
    allow_headers: Option<Zeroizing<Vec<u8>>>,
}
impl Cors {
    /// Select exact allowed origins, optional browser-extension origins and
    /// response fields. Absent origins do not authorize ordinary web origins.
    /// Credentialed wildcard, empty list entries and malformed origins fail.
    pub fn new(
        allowed: Option<&[u8]>,
        echo_webext: bool,
        credentials: bool,
        allow_headers: Option<&[u8]>,
    ) -> Result<Self, Error> {
        if allowed.is_some_and(|v| {
            v.is_empty()
                || v.len() > CONFIG_BYTES
                || v.iter().any(|b| matches!(b, 0..=8 | 10..=31 | 127..=255))
        }) || allow_headers
            .is_some_and(|v| v.len() > CONFIG_BYTES || v.iter().any(|b| matches!(b, 0..=31 | 127)))
        {
            return Err(Fault::InvalidInput.into());
        }
        let mut origins = Vec::new();
        let mut wildcard = false;
        if let Some(raw) = allowed {
            let count = raw.iter().filter(|b| **b == b',').count() + 1;
            if count > ORIGINS {
                return Err(Fault::Capacity.into());
            }
            origins
                .try_reserve_exact(count)
                .map_err(|_| Fault::Capacity)?;
            let mut offset = 0;
            for item in raw.split(|b| *b == b',') {
                let first = item
                    .iter()
                    .position(|b| !matches!(b, b' ' | b'\t'))
                    .ok_or(Fault::InvalidInput)?;
                let last = item
                    .iter()
                    .rposition(|b| !matches!(b, b' ' | b'\t'))
                    .ok_or(Fault::InvalidInput)?
                    + 1;
                let value = &item[first..last];
                if value == b"*" {
                    wildcard = true;
                } else {
                    Origin::parse(value)?;
                    origins.push(offset + first..offset + last);
                }
                offset += item.len() + 1;
            }
        }
        if wildcard && credentials {
            return Err(Fault::InvalidInput.into());
        }
        Ok(Self {
            allowed: copy(allowed.unwrap_or_default())?,
            origins,
            wildcard,
            echo_webext,
            credentials,
            allow_headers: allow_headers.map(copy).transpose()?,
        })
    }
    pub(super) const fn credentials(&self) -> bool {
        self.credentials
    }
    pub(super) fn allow_headers(&self) -> Option<&[u8]> {
        self.allow_headers.as_deref().map(Vec::as_slice)
    }
    pub(super) fn varies(&self) -> bool {
        self.wildcard || !self.origins.is_empty() || self.echo_webext
    }
    pub(super) fn matched(&self, value: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        let actual = Origin::parse(value)?;
        if self.wildcard {
            return Ok(Some(copy(b"*")?));
        }
        for range in &self.origins {
            if Origin::parse(&self.allowed[range.clone()])?.same(actual) {
                return Ok(Some(copy(value)?));
            }
        }
        if self.echo_webext && actual.webext() {
            return Ok(Some(copy(value)?));
        }
        Ok(None)
    }
}

#[derive(Clone, Copy)]
enum Host<'a> {
    Name(&'a [u8]),
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}
impl Host<'_> {
    fn same(self, other: Self) -> bool {
        match (self, other) {
            (Self::Name(a), Self::Name(b)) => a.eq_ignore_ascii_case(b),
            (Self::V4(a), Self::V4(b)) => a == b,
            (Self::V6(a), Self::V6(b)) => a == b,
            _ => false,
        }
    }
}
#[derive(Clone, Copy)]
enum Origin<'a> {
    Null,
    Tuple {
        scheme: &'a [u8],
        host: Host<'a>,
        port: Option<u16>,
    },
}
impl<'a> Origin<'a> {
    fn parse(value: &'a [u8]) -> Result<Self, Fault> {
        if value == b"null" {
            return Ok(Self::Null);
        }
        if value.len() > CONFIG_BYTES {
            return Err(Fault::TooLarge);
        }
        if value.iter().any(|b| matches!(b, 0..=32 | 127..=255)) {
            return Err(Fault::Malformed);
        }
        let colon = value
            .iter()
            .position(|b| *b == b':')
            .ok_or(Fault::Malformed)?;
        let scheme = &value[..colon];
        if !scheme.first().is_some_and(u8::is_ascii_alphabetic)
            || scheme
                .iter()
                .any(|b| !b.is_ascii_alphanumeric() && !matches!(b, b'+' | b'-' | b'.'))
        {
            return Err(Fault::Malformed);
        }
        let authority = value[colon + 1..]
            .strip_prefix(b"//")
            .filter(|v| !v.is_empty())
            .ok_or(Fault::Malformed)?;
        let (host, port) = if let Some(ip) = authority.strip_prefix(b"[") {
            let end = ip.iter().position(|b| *b == b']').ok_or(Fault::Malformed)?;
            let address = core::str::from_utf8(&ip[..end])
                .map_err(|_| Fault::Malformed)?
                .parse::<Ipv6Addr>()
                .map_err(|_| Fault::Malformed)?;
            (Host::V6(address), port_suffix(&ip[end + 1..])?)
        } else {
            let colon = authority.iter().position(|b| *b == b':');
            let (name, port) = match colon {
                Some(at) => (&authority[..at], port_suffix(&authority[at..])?),
                None => (authority, None),
            };
            if name.is_empty()
                || name
                    .iter()
                    .any(|b| !b.is_ascii_alphanumeric() && !matches!(b, b'-' | b'_' | b'.'))
                || name.starts_with(b".")
                || name.windows(2).any(|w| w == b"..")
            {
                return Err(Fault::Malformed);
            }
            let host = if name.iter().all(|b| b.is_ascii_digit() || *b == b'.') {
                Host::V4(
                    core::str::from_utf8(name)
                        .map_err(|_| Fault::Malformed)?
                        .parse::<Ipv4Addr>()
                        .map_err(|_| Fault::Malformed)?,
                )
            } else {
                Host::Name(name)
            };
            (host, port)
        };
        Ok(Self::Tuple { scheme, host, port })
    }
    fn same(self, other: Self) -> bool {
        match (self, other) {
            (Self::Null, Self::Null) => true,
            (
                Self::Tuple {
                    scheme: a,
                    host: ah,
                    port: ap,
                },
                Self::Tuple {
                    scheme: b,
                    host: bh,
                    port: bp,
                },
            ) => {
                a.eq_ignore_ascii_case(b)
                    && ah.same(bh)
                    && effective_port(a, ap) == effective_port(b, bp)
            }
            _ => false,
        }
    }
    fn webext(self) -> bool {
        matches!(self, Self::Tuple { scheme, host: Host::Name(name), port: None }
            if (scheme.eq_ignore_ascii_case(b"moz-extension")
                || scheme.eq_ignore_ascii_case(b"chrome-extension"))
                && name.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-'))
    }
}
fn effective_port(scheme: &[u8], port: Option<u16>) -> Option<u16> {
    port.or_else(|| {
        if scheme.eq_ignore_ascii_case(b"http") {
            Some(80)
        } else if scheme.eq_ignore_ascii_case(b"https") {
            Some(443)
        } else {
            None
        }
    })
}
fn port_suffix(bytes: &[u8]) -> Result<Option<u16>, Fault> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let digits = bytes.strip_prefix(b":").ok_or(Fault::Malformed)?;
    if digits.is_empty() {
        return Err(Fault::Malformed);
    }
    let mut port = 0u16;
    for digit in digits {
        if !digit.is_ascii_digit() {
            return Err(Fault::Malformed);
        }
        port = port
            .checked_mul(10)
            .and_then(|n| n.checked_add(u16::from(*digit - b'0')))
            .ok_or(Fault::Malformed)?;
    }
    Ok(Some(port))
}
