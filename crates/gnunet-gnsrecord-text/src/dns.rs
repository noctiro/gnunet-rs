use crate::helpers::{Fields, Writer, cstr, decode_b64, encode_b64, number, u16_at};
use crate::{Error, Idna, RecordType};
use core::{
    fmt::Write as _,
    net::{Ipv4Addr, Ipv6Addr},
};
use gnunet_dns::{Arena, Mx, Name, RData, Reader, Soa, Srv, Type};
pub(crate) fn supported(kind: RecordType) -> bool {
    matches!(
        kind,
        RecordType::A
            | RecordType::NS
            | RecordType::CNAME
            | RecordType::SOA
            | RecordType::PTR
            | RecordType::MX
            | RecordType::TXT
            | RecordType::AAAA
            | RecordType::SRV
            | RecordType::CERT
            | RecordType::URI
            | RecordType::TLSA
            | RecordType::SMIMEA
            | RecordType::CAA
    )
}
fn name<'a>(
    text: &str,
    idna: &impl Idna,
    work: &mut [u8],
    arena: &mut Arena<'a>,
) -> Result<Name<'a>, Error> {
    Name::from_native_text(text.as_bytes(), idna, work, arena, gnunet_dns::Limits::DNS)
}
fn named_number(text: &str, names: &[(&str, u64)], maximum: u64) -> Result<u64, Error> {
    names
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(text))
        .map_or_else(|| number(text, maximum), |(_, v)| Ok(*v))
}
pub(crate) fn parse(
    kind: RecordType,
    text: &str,
    out: &mut Writer<'_>,
    idna: &impl Idna,
    names: &mut [u8],
    work: &mut [u8],
) -> Result<(), Error> {
    let mut arena = Arena::new(names);
    let mut f = Fields::new(text);
    match kind {
        RecordType::A => out.bytes(
            &text
                .parse::<Ipv4Addr>()
                .map_err(|_| Error::Malformed)?
                .octets(),
        ),
        RecordType::AAAA => out.bytes(
            &text
                .parse::<Ipv6Addr>()
                .map_err(|_| Error::Malformed)?
                .octets(),
        ),
        RecordType::TXT => out.bytes(text.as_bytes()),
        RecordType::NS | RecordType::CNAME | RecordType::PTR => {
            let n = name(text, idna, work, &mut arena)?;
            out.bytes(n.wire())
        }
        RecordType::MX => {
            let preference = f.u16()?;
            let host = name(f.next()?, idna, work, &mut arena)?;
            f.end()?;
            let n = RData::Mx(Mx { preference, host }).encode(out.tail())?;
            out.advance(n)
        }
        RecordType::SRV => {
            let priority = f.u16()?;
            let weight = f.u16()?;
            let port = f.u16()?;
            let target = name(f.next()?, idna, work, &mut arena)?;
            f.end()?;
            let n = RData::Srv(Srv {
                priority,
                weight,
                port,
                target,
            })
            .encode(out.tail())?;
            out.advance(n)
        }
        RecordType::SOA => {
            // The actual GNUnet text plugin prints/parses RNAME before MNAME;
            // the existing DNS encoder still writes standard MNAME/RNAME wire.
            let rname = name(f.next()?, idna, work, &mut arena)?;
            let mname = name(f.next()?, idna, work, &mut arena)?;
            if f.next()? != "(" {
                return Err(Error::Malformed);
            }
            let serial = f.u32()?;
            let refresh = f.u32()?;
            let retry = f.u32()?;
            let expire = f.u32()?;
            let minimum_ttl = f.u32()?;
            if f.next()? != ")" {
                return Err(Error::Malformed);
            }
            f.end()?;
            let n = RData::Soa(Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum_ttl,
            })
            .encode(out.tail())?;
            out.advance(n)
        }
        RecordType::CERT => {
            let cert = named_number(
                f.next()?,
                &[
                    ("PKIX", 1),
                    ("SPKI", 2),
                    ("PGP", 3),
                    ("IPKIX", 4),
                    ("ISPKI", 5),
                    ("IPGP", 6),
                    ("ACPKIX", 7),
                    ("IACPKIX", 8),
                    ("URI", 253),
                    ("OID", 254),
                ],
                u16::MAX.into(),
            )? as u16;
            let tag = f.u16()?;
            let algorithm = named_number(
                f.next()?,
                &[
                    ("RSAMD5", 1),
                    ("DH", 2),
                    ("DSA", 3),
                    ("ECC", 4),
                    ("RSASHA1", 5),
                    ("INDIRECT", 252),
                    ("PRIVATEDNS", 253),
                    ("PRIVATEOID", 254),
                ],
                u8::MAX.into(),
            )? as u8;
            let payload = f.next()?;
            f.end()?;
            out.bytes(&cert.to_be_bytes())?;
            out.bytes(&tag.to_be_bytes())?;
            out.byte(algorithm)?;
            decode_b64(payload, out)
        }
        RecordType::URI => {
            let priority = f.u16()?;
            let weight = f.u16()?;
            let target = f
                .rest()
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .ok_or(Error::Malformed)?;
            if target.is_empty()
                || target.as_bytes().iter().any(u8::is_ascii_whitespace)
                || !target
                    .find(':')
                    .is_some_and(|n| n > 0 && n + 1 < target.len())
            {
                return Err(Error::Malformed);
            }
            out.bytes(&priority.to_be_bytes())?;
            out.bytes(&weight.to_be_bytes())?;
            out.bytes(target.as_bytes())
        }
        RecordType::TLSA | RecordType::SMIMEA => {
            let usage = f.u8()?;
            let selector = f.u8()?;
            let matching = f.u8()?;
            let hex = f.rest();
            if hex.as_bytes().iter().any(u8::is_ascii_whitespace) {
                return Err(Error::Malformed);
            }
            out.bytes(&[usage, selector, matching])?;
            let n = gnunet_dns::decode_hex_native(hex.as_bytes(), out.tail())?;
            if n != hex.len() / 2 {
                return Err(Error::Malformed);
            }
            out.advance(n)
        }
        RecordType::CAA => {
            let flags = f.u8()?;
            let tag = f.next()?;
            let value = f.rest();
            if tag.is_empty()
                || tag.len() > 15
                || !tag.as_bytes().iter().all(u8::is_ascii_alphanumeric)
                || value.contains('\n')
            {
                return Err(Error::Malformed);
            }
            out.bytes(&[flags, tag.len() as u8])?;
            out.bytes(tag.as_bytes())?;
            out.bytes(value.as_bytes())
        }
        _ => Err(Error::Unsupported),
    }
}
fn write_name(
    out: &mut Writer<'_>,
    name: Name<'_>,
    idna: &impl Idna,
    work: &mut [u8],
) -> Result<(), Error> {
    let n = name.write_native_text(idna, work, out.tail())?;
    out.advance(n)
}
pub(crate) fn format(
    kind: RecordType,
    data: &[u8],
    out: &mut Writer<'_>,
    idna: &impl Idna,
    names: &mut [u8],
    work: &mut [u8],
    budget: usize,
) -> Result<(), Error> {
    match kind {
        RecordType::A => {
            let b: [u8; 4] = data.try_into().map_err(|_| Error::Malformed)?;
            write!(out, "{}", Ipv4Addr::from(b)).map_err(|_| Error::Capacity)
        }
        RecordType::AAAA => {
            let b: [u8; 16] = data.try_into().map_err(|_| Error::Malformed)?;
            write!(out, "{}", Ipv6Addr::from(b)).map_err(|_| Error::Capacity)
        }
        RecordType::TXT => out.bytes(cstr(data)),
        RecordType::CERT => {
            let algorithm = *data.get(4).ok_or(Error::Truncated)?;
            out.number(u16_at(data, 0)?.into())?;
            out.byte(b' ')?;
            out.number(u16_at(data, 2)?.into())?;
            out.byte(b' ')?;
            out.number(algorithm.into())?;
            out.byte(b' ')?;
            encode_b64(&data[5..], out)
        }
        RecordType::URI => {
            let target = data
                .get(4..)
                .filter(|s| !s.is_empty())
                .ok_or(Error::Malformed)?;
            out.number(u16_at(data, 0)?.into())?;
            out.byte(b' ')?;
            out.number(u16_at(data, 2)?.into())?;
            out.bytes(b" \"")?;
            out.bytes(cstr(target))?;
            out.byte(b'"')
        }
        RecordType::TLSA | RecordType::SMIMEA => {
            let header = data.get(..3).ok_or(Error::Truncated)?;
            for n in header {
                out.number(u64::from(*n))?;
                out.byte(b' ')?;
            }
            out.hex(&data[3..])
        }
        RecordType::CAA => {
            let header = gnunet_dns::CaaHeader::parse(data)?;
            let tag = header.tag(data)?;
            let value = header.value(data)?;
            if !(1..=15).contains(&tag.len()) {
                return Err(Error::Malformed);
            }
            out.number(header.flags.into())?;
            out.byte(b' ')?;
            out.bytes(cstr(tag))?;
            out.byte(b' ')?;
            out.bytes(cstr(value))
        }
        RecordType::NS
        | RecordType::CNAME
        | RecordType::PTR
        | RecordType::MX
        | RecordType::SOA
        | RecordType::SRV => {
            let mut arena = Arena::new(names);
            let mut reader = Reader::new(
                data,
                gnunet_dns::Limits {
                    maximum_work: budget,
                    ..gnunet_dns::Limits::DNS
                },
            )?;
            let value = reader.data(
                Type(u16::try_from(kind.value()).map_err(|_| Error::Unsupported)?),
                &mut arena,
            )?;
            if reader.position() != data.len() {
                return Err(Error::Malformed);
            }
            match value {
                RData::Hostname(name) => write_name(out, name, idna, work),
                RData::Mx(mx) => {
                    out.number(mx.preference.into())?;
                    out.byte(b' ')?;
                    write_name(out, mx.host, idna, work)
                }
                RData::Srv(srv) => {
                    for n in [srv.priority, srv.weight, srv.port] {
                        out.number(n.into())?;
                        out.byte(b' ')?;
                    }
                    write_name(out, srv.target, idna, work)
                }
                RData::Soa(soa) => {
                    write_name(out, soa.rname, idna, work)?;
                    out.byte(b' ')?;
                    write_name(out, soa.mname, idna, work)?;
                    out.bytes(b" ( ")?;
                    for (i, n) in [
                        soa.serial,
                        soa.refresh,
                        soa.retry,
                        soa.expire,
                        soa.minimum_ttl,
                    ]
                    .iter()
                    .enumerate()
                    {
                        if i > 0 {
                            out.byte(b' ')?;
                        }
                        out.number((*n).into())?;
                    }
                    out.bytes(b" )")
                }
                _ => Err(Error::Malformed),
            }
        }
        _ => Err(Error::Unsupported),
    }
}
