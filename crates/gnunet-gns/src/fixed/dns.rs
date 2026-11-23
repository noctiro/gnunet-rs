//! Exact bounded DNS dependency data retained from an authenticated GNS block.

mod targets;

use super::{
    Answer, DnsAddress, DnsServer, DnsServerIdentity, MAX_NAME_BYTES, Name as RelativeName,
    pad_records,
};
use crate::{Error, Origin, RecordData, RecordFlags, RecordType, ZoneKey, rdata};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use gnunet_dns::Idna;
use gnunet_gnscrypto::OpenedRecords;
use gnunet_gnsrecord::{RecordSet, is_gns2dns_security_type};
use targets::{Cursor, Target, Targets};

#[cfg(test)]
mod tests;

const SECURITY_BYTES: usize = 4096;
const MAX_NAME: usize = 255;

#[derive(Clone, Copy)]
pub(super) struct Name {
    bytes: [u8; MAX_NAME],
    len: u8,
}

impl Name {
    pub(super) fn ascii(input: &str) -> Result<Self, Error> {
        if input.is_empty() || input == "." {
            let mut bytes = [0; MAX_NAME];
            bytes[0] = b'.';
            return Ok(Self { bytes, len: 1 });
        }
        let mut workspace = gnunet_idna::Workspace::new();
        let backend = gnunet_idna::Backend::new(
            &mut workspace,
            gnunet_idna::Limits::GNUNET,
            gnunet_idna::NativeProfile::Libunistring1_5Unicode18_0,
        );
        let mut bytes = [0; MAX_NAME];
        let len = backend
            .to_ascii(input.as_bytes(), &mut bytes)
            .map_err(|error| match error {
                Error::Capacity => Error::TooLarge,
                other => other,
            })?;
        let mut wire = [0; MAX_NAME];
        gnunet_dns::Name::from_dotted(&bytes[..len], &mut gnunet_dns::Arena::new(&mut wire))?;
        Ok(Self {
            bytes,
            len: u8::try_from(len).map_err(|_| Error::TooLarge)?,
        })
    }

    fn question(remaining: &str, namespace: &str) -> Result<Self, Error> {
        if remaining.is_empty() {
            return Self::ascii(namespace);
        }
        if namespace.is_empty() || namespace == "." {
            return Self::ascii(remaining);
        }
        let bytes = remaining
            .len()
            .checked_add(1)
            .and_then(|n| n.checked_add(namespace.len()))
            .ok_or(Error::Overflow)?;
        let mut input = [0; 4 * MAX_NAME];
        let joined = input.get_mut(..bytes).ok_or(Error::TooLarge)?;
        let (left, rest) = joined.split_at_mut(remaining.len());
        left.copy_from_slice(remaining.as_bytes());
        rest[0] = b'.';
        rest[1..].copy_from_slice(namespace.as_bytes());
        Self::ascii(core::str::from_utf8(joined).map_err(|_| Error::Malformed)?)
    }

    pub(super) fn as_str(&self) -> Result<&str, Error> {
        core::str::from_utf8(&self.bytes[..usize::from(self.len)]).map_err(|_| Error::Malformed)
    }
}

#[derive(Clone, Copy)]
pub(super) enum Attempt {
    Nameserver(Cursor),
    Server(SelectedAddress, Option<Family>),
    System(Option<Family>),
}

#[derive(Clone, Copy)]
pub(super) struct SelectedAddress {
    candidate: Cursor,
    pub(super) resolved: DnsAddress,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Family {
    V4,
    V6,
}

impl Family {
    pub(super) const fn kind(self) -> RecordType {
        match self {
            Self::V4 => RecordType::A,
            Self::V6 => RecordType::AAAA,
        }
    }
}

struct SelectedTarget {
    cursor: Cursor,
    valid_through: u64,
}

#[expect(
    clippy::large_enum_variant,
    reason = "the next authenticated child owns its bounded name"
)]
pub(super) enum Step {
    Native(Attempt),
    Gns(ZoneKey, RelativeName),
}

pub(super) struct Addresses<const A: usize> {
    entries: [Option<DnsAddress>; A],
    len: usize,
    next: usize,
}

impl<const A: usize> Addresses<A> {
    pub(super) const EMPTY: Self = Self {
        entries: [None; A],
        len: 0,
        next: 0,
    };

    pub(super) fn supplied(items: &[DnsAddress], now: u64) -> Result<Self, Error> {
        let mut result = Self::EMPTY;
        for item in items
            .iter()
            .copied()
            .filter(|item| item.valid_through >= now)
        {
            result.add(item)?;
        }
        Ok(result)
    }

    pub(super) fn records<'a>(
        items: impl Iterator<Item = Result<RecordData<'a>, Error>>,
        now: u64,
        family: Option<Family>,
        valid_through: u64,
    ) -> Result<Self, Error> {
        let mut result = Self::EMPTY;
        for record in items {
            let record = record?;
            let expiration = if record.has_relative_expiration() {
                now.saturating_add(record.expiration_time)
            } else {
                record.expiration_time
            }
            .min(valid_through);
            if expiration < now || family.is_some_and(|family| family.kind() != record.record_type)
            {
                continue;
            }
            let item = match record.record_type {
                RecordType::A => IpAddr::V4(Ipv4Addr::from(
                    <[u8; 4]>::try_from(record.data).map_err(|_| Error::Malformed)?,
                )),
                RecordType::AAAA => IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(record.data).map_err(|_| Error::Malformed)?,
                )),
                _ => continue,
            };
            result.add(DnsAddress {
                address: item,
                valid_through: expiration,
            })?;
        }
        Ok(result)
    }

    fn add(&mut self, address: DnsAddress) -> Result<(), Error> {
        if let Some(duplicate) = self.entries[..self.len]
            .iter_mut()
            .flatten()
            .find(|entry| entry.address == address.address)
        {
            duplicate.valid_through = duplicate.valid_through.max(address.valid_through);
        } else {
            *self.entries.get_mut(self.len).ok_or(Error::Capacity)? = Some(address);
            self.len += 1;
        }
        Ok(())
    }

    pub(super) fn merge(&mut self, result: Self, now: u64) -> Result<(), Error> {
        // Only pending address answers are merged, before a queue is ever read.
        let mut live = 0;
        for index in 0..self.len {
            if let Some(address) = self.entries[index]
                && address.valid_through >= now
            {
                self.entries[live] = Some(address);
                live += 1;
            }
        }
        self.entries[live..self.len].fill(None);
        self.len = live;
        for address in result.entries.into_iter().take(result.len).flatten() {
            self.add(address)?;
        }
        Ok(())
    }

    pub(super) fn live(&self, now: u64) -> bool {
        self.entries[..self.len]
            .iter()
            .flatten()
            .any(|address| address.valid_through >= now)
    }

    fn next(&mut self, now: u64) -> Option<DnsAddress> {
        while let Some(address) = self.entries.get(self.next).copied().flatten() {
            self.next += 1;
            if address.valid_through >= now {
                return Some(address);
            }
        }
        None
    }
}

pub(super) struct Bridge<const C: usize, const A: usize> {
    question: Name,
    authority: Name,
    targets: Targets<C>,
    next: Cursor,
    selected: Option<SelectedTarget>,
    addresses: Addresses<A>,
    security: [u8; SECURITY_BYTES],
    security_len: usize,
    security_count: usize,
    pub(super) security_until: u64,
}

impl<const C: usize, const A: usize> Bridge<C, A> {
    pub(super) fn from_records(remaining: &str, records: OpenedRecords<'_>) -> Result<Self, Error> {
        let mut namespace = None;
        let mut targets = Targets::new();
        let mut full = false;
        let mut security = [0; SECURITY_BYTES];
        let mut security_len = 0;
        let mut security_count = 0;
        let mut security_until = u64::MAX;
        for record in records.iter() {
            let record = record?;
            if record.flags.contains(RecordFlags::SUPPLEMENTAL) {
                continue;
            }
            if record.record_type == RecordType::GNS2DNS {
                let split = record
                    .data
                    .iter()
                    .position(|octet| *octet == 0)
                    .ok_or(Error::Malformed)?;
                let value =
                    core::str::from_utf8(&record.data[..split]).map_err(|_| Error::Malformed)?;
                if namespace.is_some_and(|old: &str| !old.eq_ignore_ascii_case(value)) {
                    return Err(Error::Malformed);
                }
                namespace = Some(value);
                let mut hostname = Name {
                    bytes: [0; MAX_NAME],
                    len: 0,
                };
                let target =
                    Target::parse(rdata::cstring(&record.data[split + 1..])?, &mut hostname)?;
                if !full {
                    match targets.push(target, record.expiration_time) {
                        Err(Error::Capacity) => full = true,
                        result => result?,
                    }
                }
            } else if is_gns2dns_security_type(record.record_type) {
                security_until = security_until.min(record.expiration_time);
                if !full {
                    match record.encode(&mut security[security_len..]) {
                        Ok(written) => {
                            security_len += written;
                            security_count += 1;
                        }
                        Err(Error::Capacity) => full = true,
                        Err(error) => return Err(error),
                    }
                }
            } else {
                return Err(Error::Malformed);
            }
        }
        let namespace = namespace.ok_or(Error::Malformed)?;
        let question = Name::question(remaining, namespace)?;
        let authority = Name::ascii(namespace)?;
        // Malformed records still take precedence over the local storage limit.
        if full {
            return Err(Error::Capacity);
        }
        Ok(Self {
            question,
            authority,
            targets,
            next: Cursor::START,
            selected: None,
            addresses: Addresses::EMPTY,
            security,
            security_len,
            security_count,
            security_until,
        })
    }

    pub(super) fn question_name(&self) -> Result<&str, Error> {
        self.question.as_str()
    }

    pub(super) fn authority(&self) -> Result<&str, Error> {
        self.authority.as_str()
    }

    pub(super) fn security(&self) -> Result<RecordSet<'_>, Error> {
        RecordSet::parse(
            &self.security[..self.security_len],
            self.security_count,
            self.security_count,
        )
    }

    fn candidate(&self, cursor: Cursor) -> Result<Target<'_>, Error> {
        if self
            .selected
            .as_ref()
            .is_none_or(|target| target.cursor != cursor)
        {
            return Err(Error::Conflict);
        }
        self.targets
            .read(cursor)?
            .map(|frame| frame.target)
            .ok_or(Error::Conflict)
    }

    pub(super) fn hostname(&self, cursor: Cursor) -> Result<&str, Error> {
        match self.candidate(cursor)? {
            Target::Host(name) => Ok(name),
            _ => Err(Error::Conflict),
        }
    }

    pub(super) fn selected_until(&self) -> u64 {
        self.selected
            .as_ref()
            .map_or(u64::MAX, |candidate| candidate.valid_through)
    }

    pub(super) fn server(
        &self,
        selected: SelectedAddress,
        authority_until: u64,
    ) -> Result<DnsServer<'_>, Error> {
        let candidate = self.candidate(selected.candidate)?;
        let address = selected.resolved.address;
        let identity = match candidate {
            Target::Address(original) if original == address => DnsServerIdentity::LiteralIp,
            Target::Address(_) => return Err(Error::Conflict),
            Target::Host(name) => DnsServerIdentity::Hostname(name),
            Target::Gns(..) => DnsServerIdentity::GnsResolved,
        };
        Ok(DnsServer {
            address,
            identity,
            valid_through: authority_until
                .min(self.selected_until())
                .min(selected.resolved.valid_through),
        })
    }

    pub(super) fn supply(&mut self, addresses: Addresses<A>) {
        self.addresses = addresses;
    }

    pub(super) fn next(&mut self, zone: ZoneKey, now: u64) -> Result<Option<Step>, Error> {
        if let Some(selected) = &self.selected
            && selected.valid_through >= now
            && let Some(resolved) = self.addresses.next(now)
        {
            return Ok(Some(Step::Native(Attempt::Server(
                SelectedAddress {
                    candidate: selected.cursor,
                    resolved,
                },
                None,
            ))));
        }
        self.selected = None;
        self.addresses = Addresses::EMPTY;
        while let Some(candidate) = self.targets.read(self.next)? {
            let cursor = self.next;
            self.next = candidate.next;
            if candidate.valid_through < now {
                continue;
            }
            self.selected = Some(SelectedTarget {
                cursor,
                valid_through: candidate.valid_through,
            });
            return Ok(Some(match candidate.target {
                Target::Address(address) => Step::Native(Attempt::Server(
                    SelectedAddress {
                        candidate: cursor,
                        resolved: DnsAddress {
                            address,
                            valid_through: candidate.valid_through,
                        },
                    },
                    None,
                )),
                Target::Host(_) => Step::Native(Attempt::Nameserver(cursor)),
                Target::Gns(authority, name) => {
                    Step::Gns(authority.unwrap_or(zone), RelativeName::new(name)?)
                }
            }));
        }
        Ok(None)
    }
}

/// Check the record count, DNS type range, and supported RDATA schemas before
/// handing a native answer to the fixed GNS resolver.
pub fn validate_dns_reply(records: &[RecordData<'_>]) -> Result<(), Error> {
    if records.len() > gnunet_gnscrypto::MAX_RECORDS {
        return Err(Error::TooLarge);
    }
    for record in records {
        if u16::try_from(record.record_type.value()).is_err() {
            return Err(Error::Malformed);
        }
        record.validate_fixed_size()?;
        rdata::validate_names(record.record_type, record.data)?;
    }
    Ok(())
}

pub(super) fn answer(
    records: &[RecordData<'_>],
    hostname: Option<&str>,
    now: u64,
    valid_through: u64,
    origin: Origin,
    output: &mut [u8],
) -> Result<Option<Answer>, Error> {
    let mut len = 0;
    let mut count = 0u32;
    for mut record in records.iter().copied() {
        if record.has_relative_expiration() {
            if valid_through != u64::MAX {
                record.expiration_time = record
                    .expiration_time
                    .min(valid_through.saturating_sub(now));
            }
        } else {
            if record.expiration_time < now {
                continue;
            }
            record.expiration_time = record.expiration_time.min(valid_through);
        }
        len += record.encode(output.get_mut(len..).ok_or(Error::Capacity)?)?;
        count += 1;
    }
    if count == 0 {
        return Ok(None);
    }
    if let Some(hostname) = hostname {
        len += RecordData {
            record_type: RecordType::LEHO,
            data: hostname.as_bytes(),
            expiration_time: 3_600_000_000,
            flags: RecordFlags::SUPPLEMENTAL.union(RecordFlags::RELATIVE_EXPIRATION),
        }
        .encode(output.get_mut(len..).ok_or(Error::Capacity)?)?;
        count += 1;
    }
    pad_records(count, len, false, origin, output).map(Some)
}
