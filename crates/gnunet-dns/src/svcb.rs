//! Borrowed SVCB/HTTPS RDATA and RFC 9461 DNS-over-TLS endpoint selection.

#[cfg(test)]
mod tests;

use crate::{Error, Name};
use core::net::{Ipv4Addr, Ipv6Addr};
use core::num::NonZeroU16;

const MANDATORY: u16 = 0;
const ALPN: u16 = 1;
const NO_DEFAULT_ALPN: u16 = 2;
const PORT: u16 = 3;
const IPV4_HINT: u16 = 4;
const IPV6_HINT: u16 = 6;
const DOH_PATH: u16 = 7;
const INVALID_KEY: u16 = u16::MAX;
const DEFAULT_DOT_PORT: u16 = 853;

/// One complete original SvcParam, including unknown keys.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Parameter<'a> {
    /// Numeric IANA service parameter key.
    pub key: u16,
    /// Unmodified key-specific wire value.
    pub value: &'a [u8],
}

impl<'a> Parameter<'a> {
    fn split(input: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
        let (&[a, b, c, d], tail) = input.split_first_chunk::<4>().ok_or(Error::Truncated)?;
        let (value, remaining) = tail
            .split_at_checked(usize::from(u16::from_be_bytes([c, d])))
            .ok_or(Error::Truncated)?;
        Ok((
            Self {
                key: u16::from_be_bytes([a, b]),
                value,
            },
            remaining,
        ))
    }
}

/// The interpretation of SvcPriority and the AliasMode root sentinel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode<'a> {
    /// Continue SVCB resolution at this name. `None` denotes unavailable.
    Alias(Option<Name<'a>>),
    /// The record describes a connection endpoint.
    Service,
}

/// A validated uncompressed SVCB-compatible RDATA view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Record<'a> {
    priority: u16,
    target: Name<'a>,
    parameters: &'a [u8],
}

impl<'a> Record<'a> {
    /// Parse a complete SVCB or HTTPS record. AliasMode parameters are opaque.
    pub fn parse(input: &'a [u8]) -> Result<Self, Error> {
        let record = Self::parse_structure(input)?;
        if record.priority != 0 {
            record.validate_values()?;
        }
        Ok(record)
    }

    fn parse_structure(input: &'a [u8]) -> Result<Self, Error> {
        if input.len() > usize::from(u16::MAX) {
            return Err(Error::TooLarge);
        }
        let (&priority, tail) = input.split_first_chunk::<2>().ok_or(Error::Truncated)?;
        let (target, parameters) = Name::uncompressed_prefix(tail)?;
        let mut unread = parameters;
        let mut previous = None;
        while !unread.is_empty() {
            let (parameter, rest) = Parameter::split(unread)?;
            if parameter.key == INVALID_KEY || previous.is_some_and(|key| parameter.key <= key) {
                return Err(Error::Malformed);
            }
            previous = Some(parameter.key);
            unread = rest;
        }
        Ok(Self {
            priority: u16::from_be_bytes(priority),
            target,
            parameters,
        })
    }

    fn validate_values(self) -> Result<(), Error> {
        let mut mandatory = &[][..];
        let mut has_alpn = false;
        let mut no_default = false;
        for Parameter { key, value } in self.parameters() {
            match key {
                MANDATORY => {
                    if value.is_empty() || !value.len().is_multiple_of(2) {
                        return Err(Error::Malformed);
                    }
                    mandatory = value;
                }
                ALPN => {
                    validate_alpn(value)?;
                    has_alpn = true;
                }
                NO_DEFAULT_ALPN if value.is_empty() => no_default = true,
                NO_DEFAULT_ALPN => return Err(Error::Malformed),
                PORT if value.len() != 2 => return Err(Error::Malformed),
                IPV4_HINT if value.is_empty() || !value.len().is_multiple_of(4) => {
                    return Err(Error::Malformed);
                }
                IPV6_HINT if value.is_empty() || !value.len().is_multiple_of(16) => {
                    return Err(Error::Malformed);
                }
                _ => {}
            }
        }
        if no_default && !has_alpn {
            return Err(Error::Malformed);
        }
        let mut previous = MANDATORY;
        let mut parameters = self.parameters();
        for key in keys(mandatory) {
            if key <= previous || key == INVALID_KEY {
                return Err(Error::Malformed);
            }
            if parameters
                .find(|parameter| parameter.key >= key)
                .map(|item| item.key)
                != Some(key)
            {
                return Err(Error::Malformed);
            }
            previous = key;
        }
        Ok(())
    }

    /// Zero selects AliasMode. Smaller nonzero values are preferred.
    pub const fn priority(self) -> u16 {
        self.priority
    }

    /// Original TargetName as encoded, preserving case. ServiceMode `.` still
    /// requires the original RR owner before it identifies a routing target.
    pub const fn target(self) -> Name<'a> {
        self.target
    }

    /// Distinguish AliasMode from ServiceMode before applying any parameters.
    pub fn mode(self) -> Mode<'a> {
        if self.priority == 0 {
            Mode::Alias((self.target.wire() != [0]).then_some(self.target))
        } else {
            Mode::Service
        }
    }

    /// Borrow original parameters in strictly increasing key order.
    pub fn parameters(self) -> impl Iterator<Item = Parameter<'a>> {
        let mut remaining = self.parameters;
        core::iter::from_fn(move || {
            let (item, tail) = Parameter::split(remaining).ok()?;
            remaining = tail;
            Some(item)
        })
    }

    /// Apply the RFC 9461 DNS mapping for a client implementing only DoT.
    /// The caller supplies the actual SVCB RR owner, including after aliasing.
    pub fn dot(self, owner: Name<'a>) -> Result<Option<Dot<'a>>, Error> {
        if self.priority == 0 {
            return Ok(None);
        }
        let mut dot = false;
        let mut http = false;
        let mut doh_path = false;
        let mut compatible = true;
        let mut port = DEFAULT_DOT_PORT;
        let mut ipv4 = &[][..];
        let mut ipv6 = &[][..];
        for Parameter { key, value } in self.parameters() {
            match key {
                MANDATORY => {
                    compatible =
                        keys(value).all(|key| matches!(key, ALPN | PORT | IPV4_HINT | IPV6_HINT));
                }
                ALPN => {
                    for protocol in protocols(value) {
                        dot |= protocol == b"dot";
                        http |=
                            matches!(protocol, b"h2" | b"h2c" | b"h3" | b"http/1.0" | b"http/1.1");
                    }
                }
                PORT => port = u16::from_be_bytes(value.try_into().map_err(|_| Error::Malformed)?),
                IPV4_HINT => ipv4 = value,
                IPV6_HINT => ipv6 = value,
                DOH_PATH => doh_path = !value.is_empty(),
                _ => {}
            }
        }
        if http && !doh_path {
            return Err(Error::Malformed);
        }
        let Some(port) = NonZeroU16::new(port).filter(|_| dot && compatible) else {
            return Ok(None);
        };
        let target = if self.target.wire() == [0] {
            owner
        } else {
            self.target
        };
        Ok(Some(Dot {
            target,
            port,
            priority: self.priority,
            ipv4,
            ipv6,
        }))
    }
}

/// Validate SVCB structural framing for DNSSEC's opaque canonical bytes.
pub(crate) fn validate_structure(input: &[u8]) -> Result<(), Error> {
    Record::parse_structure(input).map(|_| ())
}

fn keys(data: &[u8]) -> impl Iterator<Item = u16> + '_ {
    data.as_chunks::<2>()
        .0
        .iter()
        .copied()
        .map(u16::from_be_bytes)
}

fn protocol(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&length, remaining) = input.split_first()?;
    if length == 0 {
        return None;
    }
    remaining.split_at_checked(usize::from(length))
}

fn validate_alpn(mut value: &[u8]) -> Result<(), Error> {
    if value.is_empty() {
        return Err(Error::Malformed);
    }
    while !value.is_empty() {
        let (_, rest) = protocol(value).ok_or(Error::Malformed)?;
        value = rest;
    }
    Ok(())
}

fn protocols(mut input: &[u8]) -> impl Iterator<Item = &[u8]> {
    core::iter::from_fn(move || {
        let (id, remaining) = protocol(input)?;
        input = remaining;
        Some(id)
    })
}

/// One compatible DoT routing endpoint. The authentication name remains the
/// original binding authority, regardless of this record's target or aliases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Dot<'a> {
    target: Name<'a>,
    port: NonZeroU16,
    priority: u16,
    ipv4: &'a [u8],
    ipv6: &'a [u8],
}

impl<'a> Dot<'a> {
    /// Effective endpoint address lookup name.
    pub const fn target(self) -> Name<'a> {
        self.target
    }

    /// Advertised destination port, or 853 if omitted.
    pub const fn port(self) -> u16 {
        self.port.get()
    }

    /// Nonzero SvcPriority from the original record.
    pub const fn priority(self) -> u16 {
        self.priority
    }

    /// Optional IPv4 routing hints. These do not establish identity or policy.
    pub fn ipv4_hints(self) -> impl Iterator<Item = Ipv4Addr> + 'a {
        self.ipv4
            .as_chunks::<4>()
            .0
            .iter()
            .copied()
            .map(Ipv4Addr::from)
    }

    /// Optional IPv6 routing hints. These do not establish identity or policy.
    pub fn ipv6_hints(self) -> impl Iterator<Item = Ipv6Addr> + 'a {
        self.ipv6
            .as_chunks::<16>()
            .0
            .iter()
            .copied()
            .map(Ipv6Addr::from)
    }
}

/// The next SVCB resolution action for a DoT-only client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Selection<'a> {
    /// The supplied RRset is empty.
    Absent,
    /// Look up SVCB at this exact alias target, within the caller's chain limit.
    Alias(Name<'a>),
    /// AliasMode advertises that the service is unavailable.
    Unavailable,
    /// At least one ServiceMode record qualifies for DoT.
    Service(Dot<'a>),
    /// A nonempty ServiceMode RRset offers no usable DoT endpoint.
    Incompatible,
}

/// Prefer AliasMode, otherwise select the least-priority compatible DoT record.
/// Within the same priority, the first item in the caller's order wins.
pub fn select_dot<'a>(
    owner: Name<'a>,
    records: impl IntoIterator<Item = &'a [u8]>,
) -> Result<Selection<'a>, Error> {
    select_dot_where(owner, records, |_| true)
}

/// Select DoT with a caller's routing policy applied before ranking endpoints.
/// The caller can omit previously attempted records to advance alternatives.
pub fn select_dot_where<'a>(
    owner: Name<'a>,
    records: impl IntoIterator<Item = &'a [u8]>,
    mut accept: impl FnMut(Dot<'a>) -> bool,
) -> Result<Selection<'a>, Error> {
    let mut alias = None;
    let mut chosen = None::<Dot<'a>>;
    let mut present = false;
    for original in records {
        let record = Record::parse(original)?;
        present = true;
        match record.mode() {
            Mode::Alias(target) => {
                if let Some(target) = target
                    && target.wire().eq_ignore_ascii_case(owner.wire())
                {
                    return Err(Error::Malformed);
                }
                if alias.is_none() {
                    alias = Some(target);
                }
            }
            Mode::Service => {
                if let Some(candidate) = record.dot(owner)?
                    && accept(candidate)
                    && chosen.is_none_or(|current| candidate.priority < current.priority)
                {
                    chosen = Some(candidate);
                }
            }
        }
    }
    Ok(match (alias, chosen, present) {
        (Some(Some(target)), _, _) => Selection::Alias(target),
        (Some(None), _, _) => Selection::Unavailable,
        (None, Some(endpoint), _) => Selection::Service(endpoint),
        (None, None, true) => Selection::Incompatible,
        (None, None, false) => Selection::Absent,
    })
}
