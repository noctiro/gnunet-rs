//! Raw IPv4/ICMP format used by GNUnet's reversal technique. This is an
//! unauthenticated networking observation, never a remote authorization token.
use gnunet_types::Error;
use gnunet_wire::official::nat::Endian;
/// Official reserved dummy destination.
pub const DUMMY: [u8; 4] = [192, 0, 2, 86];
/// Official dummy UDP traversal port.
pub const TRAVERSAL_PORT: u16 = 22225;
/// Official echo/outer IP packet identifier.
pub const PACKET_ID: u16 = 256;
/// Outer raw-IP total-length representation expected by the actual kernel.
/// Embedded IP packets always use network order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpLengthProfile {
    /// Standard network-order raw IP length.
    Network,
    /// Explicit kernel ABI requiring native-order raw IP length.
    Native(Endian),
}
impl IpLengthProfile {
    fn length(self, n: u16) -> [u8; 2] {
        match self {
            Self::Network => n.to_be_bytes(),
            Self::Native(e) => e.put16(n),
        }
    }
    fn read(self, b: [u8; 2]) -> u16 {
        match self {
            Self::Network => u16::from_be_bytes(b),
            Self::Native(e) => e.u16(b),
        }
    }
}
/// Correct Internet ones-complement checksum, including odd byte counts.
pub fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for b in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([b[0], *b.get(1).unwrap_or(&0)]));
        sum = (sum & 65535) + (sum >> 16);
    }
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
struct IpHeader {
    source: [u8; 4],
    destination: [u8; 4],
    id: u16,
    ttl: u8,
    protocol: u8,
    total: u16,
    profile: IpLengthProfile,
}
fn ip(out: &mut [u8], header: IpHeader) {
    let IpHeader {
        source,
        destination,
        id,
        ttl,
        protocol,
        total,
        profile,
    } = header;
    out[..20].fill(0);
    out[0] = 0x45;
    out[2..4].copy_from_slice(&profile.length(total));
    out[4..6].copy_from_slice(&id.to_be_bytes());
    out[8] = ttl;
    out[9] = protocol;
    out[12..16].copy_from_slice(&source);
    out[16..20].copy_from_slice(&destination);
    let crc = checksum(&out[..20]);
    out[10..12].copy_from_slice(&crc.to_be_bytes());
}
fn icmp_crc(packet: &mut [u8]) {
    packet[2..4].fill(0);
    let crc = checksum(packet);
    packet[2..4].copy_from_slice(&crc.to_be_bytes());
}
/// Build the official28-byte periodic ICMP ECHO probe to DUMMY.
pub fn echo_probe(
    local: [u8; 4],
    ttl: u8,
    profile: IpLengthProfile,
    out: &mut [u8],
) -> Result<usize, Error> {
    if out.len() < 28 {
        return Err(Error::Capacity);
    }
    if ttl == 0 {
        return Err(Error::InvalidInput);
    }
    out[..28].fill(0);
    ip(
        out,
        IpHeader {
            source: local,
            destination: DUMMY,
            id: PACKET_ID,
            ttl,
            protocol: 1,
            total: 28,
            profile,
        },
    );
    out[20] = 8;
    icmp_crc(&mut out[20..28]);
    Ok(28)
}
/// Build the official56-byte TIME_EXCEEDED packet carrying an ECHO reversal
/// port. Source is the requester's reachable IP; target is the NAT external IP.
pub fn reversal_icmp(
    local: [u8; 4],
    remote: [u8; 4],
    advertised_port: u16,
    ttl: u8,
    profile: IpLengthProfile,
    out: &mut [u8],
) -> Result<usize, Error> {
    if out.len() < 56 {
        return Err(Error::Capacity);
    }
    if advertised_port == 0 || ttl == 0 {
        return Err(Error::InvalidInput);
    }
    out[..56].fill(0);
    ip(
        out,
        IpHeader {
            source: local,
            destination: remote,
            id: PACKET_ID,
            ttl,
            protocol: 1,
            total: 56,
            profile,
        },
    );
    out[20] = 11;
    ip(
        &mut out[28..48],
        IpHeader {
            source: remote,
            destination: DUMMY,
            id: PACKET_ID,
            ttl: 1,
            protocol: 1,
            total: 28,
            profile: IpLengthProfile::Network,
        },
    );
    out[48] = 8;
    out[52..56].copy_from_slice(&u32::from(advertised_port).to_be_bytes());
    icmp_crc(&mut out[48..56]);
    icmp_crc(&mut out[20..56]);
    Ok(56)
}
/// Build the second official56-byte TIME_EXCEEDED variant, which deliberately
/// carries the advertised port in UDP.length instead of a real UDP length.
pub fn reversal_udp(
    local: [u8; 4],
    remote: [u8; 4],
    advertised_port: u16,
    profile: IpLengthProfile,
    out: &mut [u8],
) -> Result<usize, Error> {
    if out.len() < 56 {
        return Err(Error::Capacity);
    }
    if advertised_port == 0 {
        return Err(Error::InvalidInput);
    }
    out[..56].fill(0);
    ip(
        out,
        IpHeader {
            source: local,
            destination: remote,
            id: PACKET_ID,
            ttl: 128,
            protocol: 1,
            total: 56,
            profile,
        },
    );
    out[20] = 11;
    ip(
        &mut out[28..48],
        IpHeader {
            source: remote,
            destination: DUMMY,
            id: 0,
            ttl: 128,
            protocol: 17,
            total: 28,
            profile: IpLengthProfile::Network,
        },
    );
    out[48..50].copy_from_slice(&TRAVERSAL_PORT.to_be_bytes());
    out[50..52].copy_from_slice(&TRAVERSAL_PORT.to_be_bytes());
    out[52..54].copy_from_slice(&advertised_port.to_be_bytes());
    icmp_crc(&mut out[20..56]);
    Ok(56)
}
/// Which official embedded packet supplied the observed port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Technique {
    /// Embedded ICMP ECHO reserved word.
    Echo,
    /// Embedded UDP length word.
    Udp,
}
/// Received unauthenticated reversal observation. A zero port is the ordinary
/// dummy-probe diagnostic; it is not a usable connect-back endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Observation {
    /// Original outer IPv4 source.
    pub remote: [u8; 4],
    /// Extracted port, including diagnostic zero.
    pub port: u16,
    /// Actual recognized embedded protocol.
    pub technique: Technique,
}
fn ipv4_header(
    packet: &[u8],
    profile: IpLengthProfile,
    quoted: bool,
) -> Result<Option<usize>, Error> {
    let h = packet.get(..20).ok_or(Error::Truncated)?;
    if h[0] >> 4 != 4 {
        return Ok(None);
    }
    let n = usize::from(h[0] & 15) * 4;
    if n < 20 || n > packet.len() {
        return Err(Error::Malformed);
    }
    let len = usize::from(profile.read([h[2], h[3]]));
    if len < n || !quoted && len != packet.len() {
        return Err(Error::Malformed);
    } // No fragments: parsing a noninitial fragment as an ICMP envelope is unsafe.
    if u16::from_be_bytes([h[6], h[7]]) & 0x3fff != 0 {
        return Ok(None);
    }
    let mut normalized = [0u8; 60];
    normalized[..n].copy_from_slice(&packet[..n]);
    normalized[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    if checksum(&normalized[..n]) != 0 {
        return Err(Error::Malformed);
    }
    Ok(Some(n))
}
/// Parse a received standard raw IPv4 packet with bounded IP options.
pub fn observe(packet: &[u8]) -> Result<Option<Observation>, Error> {
    observe_profiled(packet, IpLengthProfile::Network)
}
/// Parse for an explicit raw-kernel length profile. Only the actual
/// TIME_EXCEEDED/code0, quoted dummy destination, and ECHO/UDP payload shape
/// are recognized. Quoted IP checksum is not trusted: NATs may rewrite it.
pub fn observe_profiled(
    packet: &[u8],
    profile: IpLengthProfile,
) -> Result<Option<Observation>, Error> {
    let Some(outer) = ipv4_header(packet, profile, false)? else {
        return Ok(None);
    };
    if packet[9] != 1 {
        return Ok(None);
    }
    let icmp = packet.get(outer..).ok_or(Error::Truncated)?;
    if icmp.len() < 8 {
        return Err(Error::Truncated);
    }
    if icmp[0] != 11 || icmp[1] != 0 {
        return Ok(None);
    }
    if checksum(icmp) != 0 {
        return Err(Error::Malformed);
    }
    let inner = icmp.get(8..).ok_or(Error::Truncated)?;
    let h = inner.get(..20).ok_or(Error::Truncated)?;
    if h[0] >> 4 != 4 {
        return Ok(None);
    }
    let n = usize::from(h[0] & 15) * 4;
    if n < 20 || n.checked_add(8).ok_or(Error::Overflow)? != inner.len() {
        return Err(Error::Malformed);
    }
    if h[16..20] != DUMMY || u16::from_be_bytes([h[6], h[7]]) & 0x3fff != 0 {
        return Ok(None);
    }
    let data = &inner[n..];
    let (port, technique) = match h[9] {
        1 => {
            if data[0] != 8 || data[1] != 0 {
                return Ok(None);
            }
            let p = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            let p = u16::try_from(p).map_err(|_| Error::Malformed)?;
            (p, Technique::Echo)
        }
        17 => {
            if data[..2] != TRAVERSAL_PORT.to_be_bytes()
                || data[2..4] != TRAVERSAL_PORT.to_be_bytes()
            {
                return Ok(None);
            }
            (u16::from_be_bytes([data[4], data[5]]), Technique::Udp)
        }
        _ => return Ok(None),
    };
    Ok(Some(Observation {
        remote: [packet[12], packet[13], packet[14], packet[15]],
        port,
        technique,
    }))
}
