//! Shared admitted DNSPARSER, bounded streaming display and equal-width A/AAAA
//! replacement. Original compression, TTL, flags and unrelated wire bytes remain.
use gnunet_dns::{AbsoluteTime, Arena, Error, Header, Limits, Name, RData, Reader, Record, Type};
use std::{
    io::{self, Write},
    net::{Ipv4Addr, Ipv6Addr},
};
/// Complete official interception payload bound (65535 minus the IPC16 prefix).
pub const MAX_PACKET: usize = 65519;
/// One reusable parse arena, including worst-case expanded owner and SOA names.
pub const ARENA_BYTES: usize = MAX_PACKET + 765;
/// Explicit parser/output work policy; no counted object array is allocated.
#[derive(Clone, Copy, Debug)]
pub struct Bounds {
    /// Aggregate counted query/resource records per original packet.
    pub entries: usize,
    /// Existing DNSPARSER byte/label work per pass.
    pub work: usize,
}
impl Default for Bounds {
    fn default() -> Self {
        Self {
            entries: 16384,
            work: Limits::DNS.maximum_work,
        }
    }
}
fn reader<'a>(bytes: &'a [u8], bounds: Bounds) -> Result<(Header, Reader<'a>), Error> {
    let h = Header::decode(bytes)?;
    let entries = usize::from(h.counts.queries)
        + usize::from(h.counts.answers)
        + usize::from(h.counts.authority)
        + usize::from(h.counts.additional);
    if entries > bounds.entries || bytes.len() > MAX_PACKET || bounds.work == 0 {
        return Err(Error::Capacity);
    }
    let limits = Limits {
        maximum_packet_bytes: MAX_PACKET,
        maximum_queries: bounds.entries,
        maximum_records: bounds.entries,
        maximum_work: bounds.work,
        ..Limits::DNS
    };
    Ok((h, Reader::at(bytes, 12, bytes.len(), limits)?))
}
/// Validate all original sections and trailing bytes with bounded shared parser
/// work. A malformed input is never partly rewritten or silently truncated.
pub fn validate(bytes: &[u8], arena: &mut [u8], bounds: Bounds) -> Result<Header, Error> {
    let (h, mut r) = reader(bytes, bounds)?;
    for _ in 0..h.counts.queries {
        r.query(&mut Arena::new(arena))?;
    }
    let count = u32::from(h.counts.answers)
        + u32::from(h.counts.authority)
        + u32::from(h.counts.additional);
    for _ in 0..count {
        r.record(AbsoluteTime::UNIX_EPOCH, &mut Arena::new(arena))?;
    }
    if r.position() != bytes.len() {
        return Err(Error::Malformed);
    }
    Ok(h)
}
/// Rewrite only answer-section A/AAAA RDATA of the official widths. The complete
/// input is first validated, then copied only into a sufficiently sized caller
/// slab. On error, callers must forward original bytes; no changed slice is used.
/// This corrects the C utility's unrelated1024-byte repacking ceiling without
/// changing the external DNS protocol or compression graph.
pub fn redirect<'a>(
    bytes: &[u8],
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
    arena: &mut [u8],
    output: &'a mut [u8],
    bounds: Bounds,
) -> Result<(&'a [u8], usize), Error> {
    let h = validate(bytes, arena, bounds)?;
    if output.len() < bytes.len() {
        return Err(Error::Capacity);
    }
    output[..bytes.len()].copy_from_slice(bytes);
    let (_, mut r) = reader(bytes, bounds)?;
    for _ in 0..h.counts.queries {
        r.query(&mut Arena::new(arena))?;
    }
    let mut changed = 0;
    for _ in 0..h.counts.answers {
        let record = r.record(AbsoluteTime::UNIX_EPOCH, &mut Arena::new(arena))?;
        if let RData::Raw(raw) = record.data {
            let mut replacement = [0; 16];
            let n = match (record.kind, raw.len(), ipv4, ipv6) {
                (Type::A, 4, Some(ip), _) => {
                    replacement[..4].copy_from_slice(&ip.octets());
                    4
                }
                (Type::AAAA, 16, _, Some(ip)) => {
                    replacement.copy_from_slice(&ip.octets());
                    16
                }
                _ => 0,
            };
            if n != 0 {
                let value = &replacement[..n];
                let end = r.position();
                let at = end.checked_sub(n).ok_or(Error::Malformed)?;
                if bytes.get(at..end) != Some(value) {
                    output
                        .get_mut(at..end)
                        .ok_or(Error::Malformed)?
                        .copy_from_slice(value);
                    changed += 1;
                }
            }
        }
    }
    Ok((&output[..bytes.len()], changed))
}
fn escaped(out: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    for &byte in bytes {
        if (b' '..=b'~').contains(&byte) && !b"\\\"".contains(&byte) {
            out.write_all(&[byte])?;
        } else {
            write!(out, "\\x{byte:02x}")?;
        }
    }
    Ok(())
}
fn name(out: &mut impl Write, value: Name<'_>) -> io::Result<()> {
    if value.wire() == [0] {
        return out.write_all(b".");
    }
    for (i, label) in value.labels().enumerate() {
        if i != 0 {
            out.write_all(b".")?;
        }
        for byte in label {
            if *byte == b'.' || *byte == b' ' {
                write!(out, "\\x{byte:02x}")?;
            } else {
                escaped(out, &[*byte])?;
            }
        }
    }
    Ok(())
}
fn record(out: &mut impl Write, r: Record<'_>) -> io::Result<()> {
    out.write_all(b"  ")?;
    name(out, r.name)?;
    write!(
        out,
        " class={} type={} ttl={} ",
        r.class,
        r.kind.0,
        r.expiration.as_micros() / 1_000_000
    )?;
    match r.data {
        RData::Raw(raw) if r.kind == Type::A && raw.len() == 4 => {
            write!(out, "{}", Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]))?;
        }
        RData::Raw(raw) if r.kind == Type::AAAA && raw.len() == 16 => {
            let a: [u8; 16] = raw.try_into().map_err(io::Error::other)?;
            write!(out, "{}", Ipv6Addr::from(a))?;
        }
        RData::Raw(raw) => escaped(out, raw)?,
        RData::Hostname(target) => name(out, target)?,
        RData::Mx(mx) => {
            write!(out, "preference={} host=", mx.preference)?;
            name(out, mx.host)?;
        }
        RData::Srv(srv) => {
            write!(
                out,
                "priority={} weight={} port={} target=",
                srv.priority, srv.weight, srv.port
            )?;
            name(out, srv.target)?;
        }
        RData::Soa(soa) => {
            out.write_all(b"origin=")?;
            name(out, soa.mname)?;
            out.write_all(b" mailbox=")?;
            name(out, soa.rname)?;
            write!(
                out,
                " serial={} refresh={} retry={} expire={} minimum={}",
                soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum_ttl
            )?;
        }
        RData::Uri(uri) => {
            write!(
                out,
                "priority={} weight={} target=",
                uri.priority, uri.weight
            )?;
            escaped(out, uri.target)?;
        }
        RData::Cert(cert) => {
            write!(
                out,
                "certificate-type={} key-tag={} algorithm={} bytes={}",
                cert.cert_type,
                cert.key_tag,
                cert.algorithm,
                cert.data.len()
            )?;
        }
    }
    writeln!(out)
}
/// Display original questions and answers after full packet validation. Binary
/// names/TXT/URI/raw data are escaped, never emitted as terminal control codes.
pub fn display(
    bytes: &[u8],
    arena: &mut [u8],
    bounds: Bounds,
    out: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let h = validate(bytes, arena, bounds)?;
    writeln!(
        out,
        "{} id={} flags=0x{:04x} opcode={} rcode={} questions={} answers={} authority={} additional={}",
        if h.flags.query_or_response() {
            "Response"
        } else {
            "Query"
        },
        u16::from_be_bytes(h.id),
        h.flags.bits(),
        h.flags.opcode(),
        h.flags.return_code(),
        h.counts.queries,
        h.counts.answers,
        h.counts.authority,
        h.counts.additional
    )?;
    let (_, mut r) = reader(bytes, bounds)?;
    for _ in 0..h.counts.queries {
        let q = r.query(&mut Arena::new(arena))?;
        out.write_all(b"  question ")?;
        name(out, q.name)?;
        writeln!(out, " class={} type={}", q.class, q.kind.0)?;
    }
    for _ in 0..h.counts.answers {
        record(
            out,
            r.record(AbsoluteTime::UNIX_EPOCH, &mut Arena::new(arena))?,
        )?;
    }
    writeln!(out)?;
    out.flush()?;
    Ok(())
}
