//! Compact private storage for validated server targets, in record order.

use super::{MAX_NAME_BYTES, Name};
use crate::{Error, ZoneKey, select_start_zone, validate_name};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use gnunet_gnsrecord::ZONE_WIRE_LEN;

const IPV4: u8 = 0;
const IPV6: u8 = 1;
const HOST: u8 = 2;
const RELATIVE_GNS: u8 = 3;
const EXPLICIT_GNS: u8 = 4;
// Absolute expiration, payload length and target kind.
const HEADER: usize = 11;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::fixed) struct Cursor(usize);

impl Cursor {
    pub(super) const START: Self = Self(0);
}

pub(super) enum Target<'a> {
    Address(IpAddr),
    Host(&'a str),
    Gns(Option<ZoneKey>, &'a str),
}

impl<'a> Target<'a> {
    pub(super) fn parse(input: &'a str, hostname: &'a mut Name) -> Result<Self, Error> {
        if input.is_empty() {
            return Err(Error::Malformed);
        }
        if let Ok(address) = input.parse() {
            return Ok(Self::Address(address));
        }
        let unrooted = input.strip_suffix('.').unwrap_or(input);
        let (name, last) = unrooted.rsplit_once('.').unwrap_or(("", unrooted));
        if last == "+" {
            validate_name(name)?;
            return Self::gns(None, name);
        }
        match select_start_zone(unrooted, &[]) {
            Ok(start) => Self::gns(Some(start.zone), start.name),
            Err(Error::NotFound) => {
                *hostname = Name::ascii(input)?;
                let name = hostname.as_str()?;
                if name == "." {
                    return Err(Error::Malformed);
                }
                Ok(Self::Host(name))
            }
            Err(error) => Err(error),
        }
    }

    fn gns(zone: Option<ZoneKey>, name: &'a str) -> Result<Self, Error> {
        if name.len() > MAX_NAME_BYTES {
            return Err(Error::TooLarge);
        }
        Ok(Self::Gns(zone, name))
    }
}

pub(super) struct Frame<'a> {
    pub(super) target: Target<'a>,
    pub(super) valid_through: u64,
    pub(super) next: Cursor,
}

pub(super) struct Targets<const C: usize> {
    bytes: [u8; C],
    len: usize,
}

impl<const C: usize> Targets<C> {
    pub(super) const fn new() -> Self {
        Self {
            bytes: [0; C],
            len: 0,
        }
    }

    pub(super) fn push(&mut self, target: Target<'_>, valid_through: u64) -> Result<(), Error> {
        match target {
            Target::Address(IpAddr::V4(ip)) => self.append(IPV4, valid_through, &[], &ip.octets()),
            Target::Address(IpAddr::V6(ip)) => self.append(IPV6, valid_through, &[], &ip.octets()),
            Target::Host(name) => self.append(HOST, valid_through, &[], name.as_bytes()),
            Target::Gns(None, name) => {
                self.append(RELATIVE_GNS, valid_through, &[], name.as_bytes())
            }
            Target::Gns(Some(zone), name) => self.append(
                EXPLICIT_GNS,
                valid_through,
                &zone.to_wire(),
                name.as_bytes(),
            ),
        }
    }

    fn append(
        &mut self,
        kind: u8,
        valid_through: u64,
        prefix: &[u8],
        data: &[u8],
    ) -> Result<(), Error> {
        let size = u16::try_from(prefix.len() + data.len()).map_err(|_| Error::TooLarge)?;
        let width = HEADER + usize::from(size);
        let (header, payload) = self.bytes[self.len..]
            .get_mut(..width)
            .ok_or(Error::Capacity)?
            .split_at_mut(HEADER);
        header[..8].copy_from_slice(&valid_through.to_be_bytes());
        header[8..10].copy_from_slice(&size.to_be_bytes());
        header[10] = kind;
        let (key, name) = payload.split_at_mut(prefix.len());
        key.copy_from_slice(prefix);
        name.copy_from_slice(data);
        self.len += width;
        Ok(())
    }

    pub(super) fn read(&self, cursor: Cursor) -> Result<Option<Frame<'_>>, Error> {
        let bytes = self.bytes.get(cursor.0..self.len).ok_or(Error::Conflict)?;
        if bytes.is_empty() {
            return Ok(None);
        }
        let (header, tail) = bytes.split_first_chunk::<HEADER>().ok_or(Error::Conflict)?;
        let valid_through =
            u64::from_be_bytes(header[..8].try_into().map_err(|_| Error::Conflict)?);
        let size = usize::from(u16::from_be_bytes([header[8], header[9]]));
        let payload = tail.get(..size).ok_or(Error::Conflict)?;
        let name = |data| core::str::from_utf8(data).map_err(|_| Error::Conflict);
        let target = match header[10] {
            IPV4 => Target::Address(
                Ipv4Addr::from(<[u8; 4]>::try_from(payload).map_err(|_| Error::Conflict)?).into(),
            ),
            IPV6 => Target::Address(
                Ipv6Addr::from(<[u8; 16]>::try_from(payload).map_err(|_| Error::Conflict)?).into(),
            ),
            HOST => Target::Host(name(payload)?),
            RELATIVE_GNS => Target::Gns(None, name(payload)?),
            EXPLICIT_GNS => {
                let (zone, label) = payload
                    .split_at_checked(ZONE_WIRE_LEN)
                    .ok_or(Error::Conflict)?;
                Target::Gns(Some(ZoneKey::from_wire(zone)?), name(label)?)
            }
            _ => return Err(Error::Conflict),
        };
        Ok(Some(Frame {
            target,
            valid_through,
            next: Cursor(cursor.0 + HEADER + size),
        }))
    }
}
