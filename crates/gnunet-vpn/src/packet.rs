//! Checked raw IP packet primitives shared by VPN and EXIT, without allocation.
//! A parsed packet is structurally bounded, never automatically authenticated or
//! checksum-verified. Fragment reassembly and IPsec are explicit unsupported work.
use gnunet_types::Error;
pub use gnunet_wire::official::vpn::{Address, Family};
/// ICMPv4 protocol number.
pub const ICMP: u8 = 1;
/// TCP protocol number.
pub const TCP: u8 = 6;
/// UDP protocol number.
pub const UDP: u8 = 17;
/// ICMPv6 next-header number.
pub const ICMPV6: u8 = 58;
/// Borrowed structurally validated complete raw IP packet.
#[derive(Clone, Copy, Debug)]
pub struct Packet<'a> {
    bytes: &'a [u8],
    source: Address,
    destination: Address,
    protocol: u8,
    offset: usize,
    end: usize,
    header: usize,
}
fn short(b: &[u8], at: usize) -> Result<u16, Error> {
    Ok(u16::from_be_bytes(
        b.get(at..at.checked_add(2).ok_or(Error::Overflow)?)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Truncated)?,
    ))
}
fn array<const N: usize>(b: &[u8], at: usize) -> Result<[u8; N], Error> {
    b.get(at..at.checked_add(N).ok_or(Error::Overflow)?)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)
}
fn segment_len(protocol: u8, b: &[u8], family: Family, building: bool) -> Result<usize, Error> {
    match protocol {
        TCP => {
            if b.len() < 20 {
                return Err(Error::Truncated);
            }
            let n = usize::from(b[12] >> 4) * 4;
            if n < 20 || n > b.len() {
                return Err(Error::Malformed);
            }
            Ok(b.len())
        }
        UDP => {
            if b.len() < 8 {
                return Err(Error::Truncated);
            }
            if building {
                return Ok(b.len());
            }
            let n = usize::from(short(b, 4)?);
            if n < 8 || n > b.len() {
                return Err(Error::Malformed);
            }
            Ok(n)
        }
        ICMP | ICMPV6 => {
            if (protocol == ICMP) != (family == Family::V4) {
                return Err(Error::Malformed);
            }
            if b.len() < 8 {
                return Err(Error::Truncated);
            }
            Ok(b.len())
        }
        _ => Ok(b.len()),
    }
}
impl<'a> Packet<'a> {
    /// Validate original complete IP lengths/header/transport bounds. Unsupported
    /// fragmented datagrams are refused before any rewrite or forwarding effect.
    pub fn parse(b: &'a [u8]) -> Result<Self, Error> {
        let version = *b.first().ok_or(Error::Truncated)? >> 4;
        let (source, destination, mut protocol, mut offset, header) = match version {
            4 => {
                if b.len() < 20 {
                    return Err(Error::Truncated);
                }
                let h = usize::from(b[0] & 15) * 4;
                if h < 20 || h > b.len() || usize::from(short(b, 2)?) != b.len() {
                    return Err(Error::Malformed);
                }
                if short(b, 6)? & 0x3fff != 0 {
                    return Err(Error::Unsupported);
                }
                (
                    Address::V4(array(b, 12)?),
                    Address::V4(array(b, 16)?),
                    b[9],
                    h,
                    h,
                )
            }
            6 => {
                if b.len() < 40 {
                    return Err(Error::Truncated);
                }
                if 40 + usize::from(short(b, 4)?) != b.len() {
                    return Err(Error::Malformed);
                }
                (
                    Address::V6(array(b, 8)?),
                    Address::V6(array(b, 24)?),
                    b[6],
                    40,
                    40,
                )
            }
            _ => return Err(Error::Malformed),
        };
        if source.family() == Family::V6 {
            let mut extensions = 0;
            while matches!(protocol, 0 | 43 | 60) {
                if extensions >= 8 {
                    return Err(Error::TooLarge);
                }
                let h = b.get(offset..).ok_or(Error::Truncated)?;
                if h.len() < 8 {
                    return Err(Error::Truncated);
                }
                if protocol == 43 && h[3] != 0 {
                    return Err(Error::Unsupported);
                }
                let size = (usize::from(h[1]) + 1) * 8;
                if size > h.len() {
                    return Err(Error::Truncated);
                }
                protocol = h[0];
                offset += size;
                extensions += 1;
            }
            if protocol == 44 {
                return Err(Error::Unsupported);
            }
        }
        let n = segment_len(protocol, &b[offset..], source.family(), false)?;
        Ok(Self {
            bytes: b,
            source,
            destination,
            protocol,
            offset,
            end: offset + n,
            header,
        })
    }
    /// Original complete IP bytes, including any IP-layer padding.
    #[must_use]
    pub const fn bytes(self) -> &'a [u8] {
        self.bytes
    }
    /// Original IP source.
    #[must_use]
    pub const fn source(self) -> Address {
        self.source
    }
    /// Original IP destination.
    #[must_use]
    pub const fn destination(self) -> Address {
        self.destination
    }
    /// Actual terminal transport protocol, after supported IPv6 extension headers.
    #[must_use]
    pub const fn protocol(self) -> u8 {
        self.protocol
    }
    /// Complete transport segment, including its fixed header and TCP options.
    #[must_use]
    pub fn segment(self) -> &'a [u8] {
        &self.bytes[self.offset..self.end]
    }
    /// Original base IPv4 header length or forty-byte IPv6 base header.
    #[must_use]
    pub const fn ip_header_len(self) -> usize {
        self.header
    }
    /// Actual transport segment offset, after validated IP options/extensions.
    #[must_use]
    pub const fn transport_offset(self) -> usize {
        self.offset
    }
    /// Transport tuple, with zero ports for ICMP. This grants no flow/source owner.
    pub fn ports(self) -> Result<(u16, u16), Error> {
        match self.protocol {
            TCP | UDP => Ok((short(self.segment(), 0)?, short(self.segment(), 2)?)),
            ICMP | ICMPV6 => Ok((0, 0)),
            _ => Err(Error::Unsupported),
        }
    }
    /// Validate real IPv4 header and transport checksums. IPv4 UDP checksum zero is
    /// the standard disabled checksum; IPv6 UDP zero is rejected. No auth is implied.
    pub fn validate_checksums(self) -> Result<(), Error> {
        if self.source.family() == Family::V4 && checksum(&self.bytes[..self.header]) != 0 {
            return Err(Error::Malformed);
        }
        let b = self.segment();
        let valid = match self.protocol {
            TCP => {
                fold(pseudo(self.source, self.destination, self.protocol, b.len())? + sum(b)) == 0
            }
            UDP => {
                if short(b, 6)? == 0 {
                    self.source.family() == Family::V4
                } else {
                    fold(pseudo(self.source, self.destination, self.protocol, b.len())? + sum(b))
                        == 0
                }
            }
            ICMP => checksum(b) == 0,
            ICMPV6 => {
                fold(pseudo(self.source, self.destination, self.protocol, b.len())? + sum(b)) == 0
            }
            _ => return Err(Error::Unsupported),
        };
        if valid { Ok(()) } else { Err(Error::Malformed) }
    }
}
fn sum(b: &[u8]) -> u64 {
    let mut n = 0u64;
    for x in b.chunks(2) {
        n += if x.len() == 2 {
            u64::from(u16::from_be_bytes([x[0], x[1]]))
        } else {
            u64::from(x[0]) << 8
        };
    }
    n
}
fn fold(mut n: u64) -> u16 {
    while n >> 16 != 0 {
        n = (n & 0xffff) + (n >> 16)
    }
    !(n as u16)
}
/// Internet one's-complement checksum; odd final bytes are padded on the right.
#[must_use]
pub fn checksum(b: &[u8]) -> u16 {
    fold(sum(b))
}
fn pseudo(source: Address, destination: Address, protocol: u8, len: usize) -> Result<u64, Error> {
    if source.family() != destination.family() {
        return Err(Error::InvalidInput);
    }
    let n = u32::try_from(len).map_err(|_| Error::TooLarge)?;
    Ok(sum(source.bytes())
        + sum(destination.bytes())
        + u64::from(protocol)
        + u64::from(n & 0xffff)
        + u64::from(n >> 16))
}
fn fix_transport(
    source: Address,
    destination: Address,
    protocol: u8,
    b: &mut [u8],
) -> Result<(), Error> {
    let at = match protocol {
        TCP => 16,
        UDP => 6,
        ICMP | ICMPV6 => 2,
        _ => return Err(Error::Unsupported),
    };
    b[at..at + 2].fill(0);
    let n = if protocol == ICMP {
        checksum(b)
    } else {
        fold(pseudo(source, destination, protocol, b.len())? + sum(b))
    };
    let n = if protocol == UDP && n == 0 {
        u16::MAX
    } else {
        n
    };
    b[at..at + 2].copy_from_slice(&n.to_be_bytes());
    Ok(())
}
fn ip_header(
    source: Address,
    destination: Address,
    protocol: u8,
    payload: usize,
    out: &mut [u8],
) -> Result<usize, Error> {
    let h = match source.family() {
        Family::V4 => 20,
        Family::V6 => 40,
    };
    if source.family() != destination.family() {
        return Err(Error::InvalidInput);
    }
    let n = payload.checked_add(h).ok_or(Error::Overflow)?;
    if out.len() < n {
        return Err(Error::Capacity);
    }
    if payload > 65535 || (h == 20 && n > 65535) {
        return Err(Error::TooLarge);
    }
    out[..h].fill(0);
    match (source, destination) {
        (Address::V4(a), Address::V4(b)) => {
            out[0] = 0x45;
            out[2..4].copy_from_slice(&(n as u16).to_be_bytes());
            out[8] = 64;
            out[9] = protocol;
            out[12..16].copy_from_slice(&a);
            out[16..20].copy_from_slice(&b);
            let c = checksum(&out[..20]);
            out[10..12].copy_from_slice(&c.to_be_bytes());
        }
        (Address::V6(a), Address::V6(b)) => {
            out[0] = 0x60;
            out[4..6].copy_from_slice(&(payload as u16).to_be_bytes());
            out[6] = protocol;
            out[7] = 64;
            out[8..24].copy_from_slice(&a);
            out[24..40].copy_from_slice(&b);
        }
        _ => return Err(Error::InvalidInput),
    }
    Ok(h)
}
/// Build a complete standards-valid raw IP packet with correct transport length
/// and checksums. The original TCP options/opaque transport payload are retained.
/// Every validation/capacity refusal precedes output mutation.
pub fn build(
    source: Address,
    destination: Address,
    protocol: u8,
    segment: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    if source.family() != destination.family() {
        return Err(Error::InvalidInput);
    }
    if !matches!(protocol, TCP | UDP | ICMP | ICMPV6) {
        return Err(Error::Unsupported);
    }
    segment_len(protocol, segment, source.family(), true)?;
    let h = match source.family() {
        Family::V4 => 20,
        Family::V6 => 40,
    };
    let n = h + segment.len();
    if out.len() < n {
        return Err(Error::Capacity);
    }
    if segment.len() > 65535 || (h == 20 && n > 65535) {
        return Err(Error::TooLarge);
    }
    let h = ip_header(source, destination, protocol, segment.len(), out)?;
    out[h..n].copy_from_slice(segment);
    if protocol == UDP {
        out[h + 4..h + 6].copy_from_slice(&(segment.len() as u16).to_be_bytes())
    }
    fix_transport(source, destination, protocol, &mut out[h..n])?;
    Ok(n)
}
/// Rewrite addresses and optional TCP/UDP ports in an existing same-family raw
/// packet, preserving IP/TCP options. Checksums are recomputed from actual bytes.
/// Cross-family translation must build another packet into independent storage.
pub fn rewrite(
    bytes: &mut [u8],
    source: Address,
    destination: Address,
    ports: Option<(u16, u16)>,
) -> Result<(), Error> {
    let p = Packet::parse(bytes)?;
    if source.family() != p.source.family() || destination.family() != p.source.family() {
        return Err(Error::InvalidInput);
    }
    if !matches!(p.protocol, TCP | UDP | ICMP | ICMPV6) {
        return Err(Error::Unsupported);
    }
    if ports.is_some() && !matches!(p.protocol, TCP | UDP) {
        return Err(Error::Unsupported);
    }
    let (protocol, offset, end, h) = (p.protocol, p.offset, p.end, p.header);
    match (source, destination) {
        (Address::V4(a), Address::V4(b)) => {
            bytes[12..16].copy_from_slice(&a);
            bytes[16..20].copy_from_slice(&b)
        }
        (Address::V6(a), Address::V6(b)) => {
            bytes[8..24].copy_from_slice(&a);
            bytes[24..40].copy_from_slice(&b)
        }
        _ => return Err(Error::InvalidInput),
    }
    if let Some((a, b)) = ports {
        bytes[offset..offset + 2].copy_from_slice(&a.to_be_bytes());
        bytes[offset + 2..offset + 4].copy_from_slice(&b.to_be_bytes())
    }
    fix_transport(source, destination, protocol, &mut bytes[offset..end])?;
    if source.family() == Family::V4 {
        bytes[10..12].fill(0);
        let c = checksum(&bytes[..h]);
        bytes[10..12].copy_from_slice(&c.to_be_bytes())
    }
    Ok(())
}
/// Pinned VPN/EXIT error classes whose wire quote is intentionally omitted.
#[must_use]
pub const fn icmp_error(family: Family, kind: u8) -> bool {
    match family {
        Family::V4 => matches!(kind, 3 | 4 | 11),
        Family::V6 => matches!(kind, 1..=4),
    }
}
/// Translate the exact supported C ICMP family/type contract. Header code/rest
/// remain opaque original fields, matching the wire behavior. Unsupported C
/// cross-family error types are refused, never presented as successful routing.
pub fn translate_icmp_header(from: Family, to: Family, mut h: [u8; 8]) -> Result<[u8; 8], Error> {
    let kind = match from {
        Family::V4 => match h[0] {
            0 | 8 | 3 | 4 | 11 => h[0],
            _ => return Err(Error::Unsupported),
        },
        Family::V6 => match h[0] {
            1 | 2 | 3 | 4 | 128 | 129 => h[0],
            _ => return Err(Error::Unsupported),
        },
    };
    if from != to {
        h[0] = match (from, kind) {
            (Family::V4, 0) => 129,
            (Family::V4, 8) => 128,
            (Family::V4, 3) => 1,
            (Family::V4, 11) => 3,
            (Family::V6, 129) => 0,
            (Family::V6, 128) => 8,
            (Family::V6, 1) => 3,
            (Family::V6, 3) => 11,
            _ => return Err(Error::Unsupported),
        }
    }
    h[2..4].fill(0);
    Ok(h)
}
/// Reconstructed original IP plus eight transport bytes required by the official
/// quote-omission contract. This is explicit ICMP error data, never an ACK/result.
pub fn quote(
    source: Address,
    destination: Address,
    protocol: u8,
    ports: Option<(u16, u16)>,
    out: &mut [u8],
) -> Result<usize, Error> {
    if source.family() != destination.family() {
        return Err(Error::InvalidInput);
    }
    if !matches!(protocol, TCP | UDP | ICMP | ICMPV6) {
        return Err(Error::Unsupported);
    }
    if ports.is_some() && !matches!(protocol, TCP | UDP) {
        return Err(Error::InvalidInput);
    }
    if (protocol == ICMP && source.family() != Family::V4)
        || (protocol == ICMPV6 && source.family() != Family::V6)
    {
        return Err(Error::InvalidInput);
    }
    let h = match source.family() {
        Family::V4 => 20,
        Family::V6 => 40,
    };
    if out.len() < h + 8 {
        return Err(Error::Capacity);
    }
    let h = ip_header(source, destination, protocol, 8, out)?;
    out[h..h + 8].fill(0);
    if let Some((a, b)) = ports {
        out[h..h + 2].copy_from_slice(&a.to_be_bytes());
        out[h + 2..h + 4].copy_from_slice(&b.to_be_bytes())
    }
    if protocol == UDP {
        out[h + 4..h + 6].copy_from_slice(&8u16.to_be_bytes())
    }
    Ok(h + 8)
}
/// Bounded tuple from a quoted IP header plus at least eight transport bytes.
/// Its IP total length may describe the longer original datagram, so it must not
/// use Packet::parse's whole-packet/complete-TCP requirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Quoted {
    /// Original quoted source.
    pub source: Address,
    /// Original quoted destination.
    pub destination: Address,
    /// Original transport protocol.
    pub protocol: u8,
    /// Original source port, zero for ICMP.
    pub source_port: u16,
    /// Original destination port, zero for ICMP.
    pub destination_port: u16,
}
impl Quoted {
    /// Extract a quoted tuple without requiring a full original packet/checksum.
    pub fn parse(b: &[u8]) -> Result<Self, Error> {
        let (source, destination, protocol, h) = match b.first().ok_or(Error::Truncated)? >> 4 {
            4 => {
                if b.len() < 20 {
                    return Err(Error::Truncated);
                }
                let h = usize::from(b[0] & 15) * 4;
                if h < 20 || short(b, 6)? & 0x3fff != 0 {
                    return Err(Error::Unsupported);
                }
                (
                    Address::V4(array(b, 12)?),
                    Address::V4(array(b, 16)?),
                    b[9],
                    h,
                )
            }
            6 => {
                if b.len() < 40 {
                    return Err(Error::Truncated);
                }
                (
                    Address::V6(array(b, 8)?),
                    Address::V6(array(b, 24)?),
                    b[6],
                    40,
                )
            }
            _ => return Err(Error::Malformed),
        };
        let mut h = h;
        let mut protocol = protocol;
        if source.family() == Family::V6 {
            let mut extensions = 0;
            while matches!(protocol, 0 | 43 | 60) {
                if extensions >= 8 {
                    return Err(Error::TooLarge);
                }
                let ext = b.get(h..).ok_or(Error::Truncated)?;
                if ext.len() < 8 {
                    return Err(Error::Truncated);
                }
                if protocol == 43 && ext[3] != 0 {
                    return Err(Error::Unsupported);
                }
                let n = (usize::from(ext[1]) + 1) * 8;
                if n > ext.len() {
                    return Err(Error::Truncated);
                }
                protocol = ext[0];
                h += n;
                extensions += 1;
            }
        }
        let declared = match source.family() {
            Family::V4 => usize::from(short(b, 2)?),
            Family::V6 => 40 + usize::from(short(b, 4)?),
        };
        if declared < h + 8 {
            return Err(Error::Malformed);
        }
        let payload = b.get(h..).ok_or(Error::Truncated)?;
        if payload.len() < 8 {
            return Err(Error::Truncated);
        }
        let (a, z) = match protocol {
            TCP | UDP => (short(payload, 0)?, short(payload, 2)?),
            ICMP if source.family() == Family::V4 => (0, 0),
            ICMPV6 if source.family() == Family::V6 => (0, 0),
            _ => return Err(Error::Unsupported),
        };
        Ok(Self {
            source,
            destination,
            protocol,
            source_port: a,
            destination_port: z,
        })
    }
}

/// Original quoted source, destination, IP protocol and optional transport ports.
pub type QuotedTuple = (Address, Address, u8, Option<(u16, u16)>);

/// Tuple from an actual bounded ICMP quote; IPv4/IPv6 original total length may
/// exceed retained quoted bytes. No checksum/authentication proof is fabricated.
pub fn quoted_tuple(bytes: &[u8]) -> Result<QuotedTuple, Error> {
    let q = Quoted::parse(bytes)?;
    let ports = matches!(q.protocol, TCP | UDP).then_some((q.source_port, q.destination_port));
    Ok((q.source, q.destination, q.protocol, ports))
}

/// Build from a complete fixed transport skeleton plus its original options/data
/// tail, without allocating an intermediate segment or borrowing output as input.
/// All validation/capacity errors precede mutation, matching build's contract.
pub fn build_parts(
    source: Address,
    destination: Address,
    protocol: u8,
    prefix: &[u8],
    tail: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    if source.family() != destination.family() {
        return Err(Error::InvalidInput);
    }
    let payload = prefix
        .len()
        .checked_add(tail.len())
        .ok_or(Error::Overflow)?;
    match protocol {
        TCP => {
            if prefix.len() < 20 {
                return Err(Error::Truncated);
            }
            let offset = usize::from(prefix[12] >> 4) * 4;
            if offset < 20 || offset > payload {
                return Err(Error::Malformed);
            }
        }
        UDP => {
            if prefix.len() < 8 {
                return Err(Error::Truncated);
            }
        }
        ICMP | ICMPV6 => {
            if prefix.len() < 8 {
                return Err(Error::Truncated);
            }
            if (protocol == ICMP) != (source.family() == Family::V4) {
                return Err(Error::Malformed);
            }
        }
        _ => return Err(Error::Unsupported),
    }
    let h = match source.family() {
        Family::V4 => 20,
        Family::V6 => 40,
    };
    let n = h + payload;
    if payload > 65535 || (h == 20 && n > 65535) {
        return Err(Error::TooLarge);
    }
    if out.len() < n {
        return Err(Error::Capacity);
    }
    ip_header(source, destination, protocol, payload, out)?;
    out[h..h + prefix.len()].copy_from_slice(prefix);
    out[h + prefix.len()..n].copy_from_slice(tail);
    if protocol == UDP {
        out[h + 4..h + 6].copy_from_slice(&(payload as u16).to_be_bytes())
    }
    fix_transport(source, destination, protocol, &mut out[h..n])?;
    Ok(n)
}
