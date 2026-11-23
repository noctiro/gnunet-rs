use super::{Answer, Authority, MAX_NAME_BYTES, Name, dns, pad_records};
use crate::{
    BoxRegistry, DnsPolicy, Error, Failure, Origin, RecordData, RecordFlags, RecordType, ZoneKey,
};
use crate::{boxed, policy::supported, rdata, select_start_zone, validate_name};
use gnunet_dns::Name as DnsName;
use gnunet_gnscrypto::OpenedRecords;
use gnunet_gnsrecord::is_gns2dns_security_type;

#[expect(
    clippy::large_enum_variant,
    reason = "the bounded authority target stays owned without heap allocation"
)]
pub(super) enum Step<const C: usize, const A: usize> {
    Follow(ZoneKey, Name),
    Dns(dns::Bridge<C, A>),
    System(dns::Name),
    Answer(Answer),
}

#[derive(Default)]
struct Records<'a> {
    seen: bool,
    primary: usize,
    delegation: Option<RecordData<'a>>,
    redirect: Option<&'a str>,
    dns_namespace: Option<&'a str>,
    conflicting_dns: bool,
    other_than_dns_security: bool,
    cname: Option<DnsName<'a>>,
    critical: Option<RecordType>,
    box_records: bool,
}

impl<'a> Records<'a> {
    fn observe(&mut self, record: RecordData<'a>) -> Result<(), Error> {
        record.validate_fixed_size()?;
        let kind = record.record_type;
        if matches!(kind, RecordType::BOX | RecordType::SBOX) {
            boxed::validate(record)?;
            self.box_records |= kind == RecordType::BOX;
        }
        let target = if kind == RecordType::REDIRECT {
            let target = rdata::cstring(record.data)?;
            validate_target(target)?;
            Some(target)
        } else {
            rdata::validate_names(kind, record.data)?;
            None
        };
        let namespace = if kind == RecordType::GNS2DNS {
            let split = record
                .data
                .iter()
                .position(|b| *b == 0)
                .ok_or(Error::Malformed)?;
            let namespace =
                core::str::from_utf8(&record.data[..split]).map_err(|_| Error::Malformed)?;
            if rdata::cstring(&record.data[split + 1..])?.is_empty() {
                return Err(Error::Malformed);
            }
            Some(namespace)
        } else {
            None
        };
        self.seen = true;
        if self.critical.is_none()
            && record.flags.contains(RecordFlags::CRITICAL)
            && !supported(kind)
        {
            self.critical = Some(kind);
        }
        if record.flags.contains(RecordFlags::SUPPLEMENTAL) {
            return Ok(());
        }
        self.primary += 1;
        if kind.is_zone_delegation() {
            self.delegation = Some(record);
        }
        if let Some(target) = target {
            self.redirect = Some(target);
        }
        if let Some(namespace) = namespace {
            self.conflicting_dns |= self
                .dns_namespace
                .is_some_and(|old| !old.eq_ignore_ascii_case(namespace));
            self.dns_namespace = Some(namespace);
        } else if !is_gns2dns_security_type(kind) {
            self.other_than_dns_security = true;
        }
        if kind == RecordType::CNAME {
            self.cname = Some(DnsName::from_wire(record.data)?);
        }
        Ok(())
    }
}

/// A malformed candidate is rejected before the caller can cache it. Only
/// well-framed authenticated data produces an authoritative business result.
pub(super) fn process<const C: usize, const A: usize>(
    frame: &Authority,
    desired: RecordType,
    records: OpenedRecords<'_>,
    output: &mut [u8],
    registry: Option<&dyn BoxRegistry>,
    dns: DnsPolicy,
) -> Result<Result<Step<C, A>, Failure>, Error> {
    let mut observed = Records::default();
    for record in records.iter() {
        observed.observe(record?)?;
    }
    if let Some(kind) = observed.critical {
        return Ok(Err(Failure::Critical(kind)));
    }
    if !observed.seen {
        return Ok(Err(Failure::NotFound));
    }
    let remaining = frame.remaining.as_str()?;
    let apex = frame.label.as_str()? == "@";
    if let Some(delegation) = observed.delegation {
        if apex {
            return Ok(Err(Failure::Apex));
        }
        if observed.primary != 1 {
            return Ok(Err(Failure::Records));
        }
        if !remaining.is_empty() || desired != delegation.record_type {
            return Ok(Ok(Step::Follow(
                ZoneKey::from_record(&delegation)?,
                Name::new(remaining)?,
            )));
        }
    } else if let Some(target) = observed.redirect {
        if apex {
            return Ok(Err(Failure::Apex));
        }
        if observed.primary != 1 {
            return Ok(Err(Failure::Records));
        }
        if !remaining.is_empty() || desired != RecordType::REDIRECT {
            let name = Name::joined(remaining, target)?;
            return follow(frame.zone, name.as_str()?, dns);
        }
    } else if observed.dns_namespace.is_some() {
        if observed.conflicting_dns || observed.other_than_dns_security {
            return Ok(Err(Failure::Records));
        }
        if !remaining.is_empty() || desired != RecordType::GNS2DNS {
            if apex {
                return Ok(Err(Failure::Apex));
            }
            if let Err(failure) = dns.check() {
                return Ok(Err(failure));
            }
            return match dns::Bridge::from_records(remaining, records) {
                Ok(bridge) => Ok(Ok(Step::Dns(bridge))),
                Err(Error::Capacity) => Ok(Err(Failure::Fault(Error::Capacity))),
                Err(error) => Err(error),
            };
        }
    } else if observed.primary == 1
        && desired != RecordType::CNAME
        && let Some(target) = observed.cname
    {
        let mut dotted = [0; 255];
        let n = target.write_dotted(&mut dotted)?;
        let text = core::str::from_utf8(&dotted[..n]).map_err(|_| Error::Malformed)?;
        return follow(frame.zone, text, dns);
    } else if !remaining.is_empty() {
        let Some(prefix) = boxed::Prefix::new(remaining) else {
            return Ok(Err(Failure::NotFound));
        };
        let selector = observed
            .box_records
            .then(|| prefix.resolve(registry))
            .flatten();
        let matching = records.iter().filter_map(|record| {
            record
                .and_then(|record| prefix.select(selector, record))
                .transpose()
        });
        return answer(frame.zone, desired, matching, output);
    }
    answer(frame.zone, desired, records.iter(), output)
}

fn validate_target(target: &str) -> Result<(), Error> {
    match target {
        "+" => Ok(()),
        _ if target.is_empty() => Err(Error::Malformed),
        _ => validate_name(
            target
                .strip_suffix(".+")
                .or_else(|| target.strip_suffix('.'))
                .unwrap_or(target),
        ),
    }
}

fn follow<const C: usize, const A: usize>(
    zone: ZoneKey,
    target: &str,
    dns: DnsPolicy,
) -> Result<Result<Step<C, A>, Failure>, Error> {
    if target == "+" {
        return Ok(Ok(Step::Follow(zone, Name::EMPTY)));
    }
    if let Some(name) = target.strip_suffix(".+") {
        validate_name(name)?;
        return Ok(Ok(Step::Follow(zone, Name::new(name)?)));
    }
    match select_start_zone(target.strip_suffix('.').unwrap_or(target), &[]) {
        Ok(target) => Ok(Ok(Step::Follow(target.zone, Name::new(target.name)?))),
        Err(Error::NotFound) => match dns.check() {
            Ok(()) => Ok(Ok(Step::System(dns::Name::ascii(target)?))),
            Err(failure) => Ok(Err(failure)),
        },
        Err(error) => Err(error),
    }
}

fn answer<'data, const C: usize, const A: usize>(
    zone: ZoneKey,
    desired: RecordType,
    records: impl Iterator<Item = Result<RecordData<'data>, Error>>,
    output: &mut [u8],
) -> Result<Result<Step<C, A>, Failure>, Error> {
    // The maximum rewritten known RDATA is two DNS names plus the SOA tail.
    let mut scratch = [0; rdata::DNS_REWRITE_BYTES];
    let mut len = 0_usize;
    let mut first_type = None;
    let mut count = 0_u32;
    let mut supplemental_nick = false;
    let mut primary_match = false;
    for record in records {
        let record = record?;
        record.validate_fixed_size()?;
        if record.flags.contains(RecordFlags::CRITICAL) && !supported(record.record_type) {
            return Ok(Err(Failure::Critical(record.record_type)));
        }
        let supplemental = record.flags.contains(RecordFlags::SUPPLEMENTAL);
        supplemental_nick |= supplemental && record.record_type == RecordType::NICK;
        primary_match |= !supplemental && (desired.value() == 0 || desired == record.record_type);
        count = count.checked_add(1).ok_or(Error::Overflow)?;
        first_type.get_or_insert(record.record_type);
        let data = rdata::rewrite_into(
            record.record_type,
            record.data,
            zone,
            MAX_NAME_BYTES,
            &mut scratch,
        )?;
        let rewritten = RecordData { data, ..record };
        let written = rewritten.encode(output.get_mut(len..).ok_or(Error::Capacity)?)?;
        len = len.checked_add(written).ok_or(Error::Overflow)?;
    }
    if count == 0 || (supplemental_nick && !primary_match) {
        return Ok(Err(Failure::NotFound));
    }
    let answer = pad_records(
        count,
        len,
        first_type.is_some_and(RecordType::is_zone_delegation),
        Origin::Gns(zone),
        output,
    )?;
    Ok(Ok(Step::Answer(answer)))
}
