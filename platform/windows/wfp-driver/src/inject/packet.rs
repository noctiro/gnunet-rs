use core::fmt;
use gnunet_wfp_dns::{Addresses, Path};

const UDP_BYTES: usize = 8;
const DNS_BYTES: usize = 12;
const IPV4_BYTES: usize = 20;
const IPV6_BYTES: usize = 40;
const UDP_PROTOCOL: u8 = 17;
const HOP_LIMIT: u8 = 64;

/// Invalid reply input, without consuming its original reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketError {
    /// A complete DNS header with its response bit set was absent.
    Response,
    /// The original remote endpoint is not the DNS port.
    Port,
    /// The DNS body exceeds this family's non-jumbo IP/UDP maximum.
    Length {
        /// Supplied DNS body size.
        bytes: usize,
        /// Largest ordinary DNS UDP body for this address family.
        maximum: usize,
    },
    /// Destination storage is not exactly the prepared complete IP extent.
    Storage,
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Response => f.write_str("injected DNS body is not a complete response header"),
            Self::Port => f.write_str("original remote UDP port is not DNS"),
            Self::Length { bytes, maximum } => {
                write!(f, "DNS body length {bytes} exceeds UDP maximum {maximum}")
            }
            Self::Storage => f.write_str("packet storage does not match its prepared IP extent"),
        }
    }
}
impl core::error::Error for PacketError {}

pub(super) struct Plan {
    path: Path,
    header: usize,
    bytes: usize,
}

impl Plan {
    pub(super) fn new(path: Path, payload: &[u8]) -> Result<Self, PacketError> {
        if payload.len() < DNS_BYTES || payload[2] & 0x80 == 0 {
            return Err(PacketError::Response);
        }
        if path.ports()[1] != 53 {
            return Err(PacketError::Port);
        }
        let (header, maximum) = match path.addresses() {
            Addresses::V4 { .. } => (IPV4_BYTES, usize::from(u16::MAX) - IPV4_BYTES - UDP_BYTES),
            Addresses::V6 { .. } => (IPV6_BYTES, usize::from(u16::MAX) - UDP_BYTES),
        };
        if payload.len() > maximum {
            return Err(PacketError::Length {
                bytes: payload.len(),
                maximum,
            });
        }
        Ok(Self {
            path,
            header,
            bytes: header + UDP_BYTES + payload.len(),
        })
    }

    pub(super) fn bytes(&self) -> usize {
        self.bytes
    }

    pub(super) fn write(&self, payload: &[u8], output: &mut [u8]) -> Result<(), PacketError> {
        if output.len() != self.bytes || payload.len() != self.bytes - self.header - UDP_BYTES {
            return Err(PacketError::Storage);
        }
        output[..self.header + UDP_BYTES].fill(0);
        let udp_bytes = (UDP_BYTES + payload.len()) as u16;
        let ports = self.path.ports();
        let udp = &mut output[self.header..];
        udp[0..2].copy_from_slice(&ports[1].to_be_bytes());
        udp[2..4].copy_from_slice(&ports[0].to_be_bytes());
        udp[4..6].copy_from_slice(&udp_bytes.to_be_bytes());
        udp[UDP_BYTES..].copy_from_slice(payload);
        let mut sum = Sum::new();
        match self.path.addresses() {
            Addresses::V4 { local, remote } => {
                sum.add(&remote);
                sum.add(&local);
                sum.add(&[0, UDP_PROTOCOL]);
                sum.add(&udp_bytes.to_be_bytes());
            }
            Addresses::V6 { local, remote } => {
                sum.add(&remote);
                sum.add(&local);
                sum.add(&u32::from(udp_bytes).to_be_bytes());
                sum.add(&[0, 0, 0, UDP_PROTOCOL]);
            }
        }
        sum.add(udp);
        let checksum = match sum.finish() {
            0 => u16::MAX,
            checksum => checksum,
        };
        udp[6..8].copy_from_slice(&checksum.to_be_bytes());
        let bytes = output.len();
        match self.path.addresses() {
            Addresses::V4 { local, remote } => {
                output[0] = 0x45;
                output[2..4].copy_from_slice(&(bytes as u16).to_be_bytes());
                // This locally generated packet is atomic: DF set, MF/offset
                // clear. RFC 6864 permits identification zero for atomic IPv4.
                output[6] = 0x40;
                output[8] = HOP_LIMIT;
                output[9] = UDP_PROTOCOL;
                output[12..16].copy_from_slice(&remote);
                output[16..20].copy_from_slice(&local);
                let mut checksum = Sum::new();
                checksum.add(&output[..IPV4_BYTES]);
                output[10..12].copy_from_slice(&checksum.finish().to_be_bytes());
            }
            Addresses::V6 { local, remote } => {
                output[0] = 0x60;
                output[4..6].copy_from_slice(&udp_bytes.to_be_bytes());
                output[6] = UDP_PROTOCOL;
                output[7] = HOP_LIMIT;
                output[8..24].copy_from_slice(&remote);
                output[24..40].copy_from_slice(&local);
            }
        }
        Ok(())
    }
}

struct Sum(u32);
impl Sum {
    fn new() -> Self {
        Self(0)
    }
    // Each pseudo-header component before the body has even length. The only
    // possible odd final byte is padded on the right as required by RFC 768.
    fn add(&mut self, bytes: &[u8]) {
        let (pairs, remainder) = bytes.as_chunks::<2>();
        for pair in pairs {
            self.0 += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        }
        if let [last] = remainder {
            self.0 += u32::from(*last) << 8;
        }
    }
    fn finish(mut self) -> u16 {
        while self.0 > u32::from(u16::MAX) {
            self.0 = (self.0 & 0xffff) + (self.0 >> 16);
        }
        !(self.0 as u16)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use self::std::{vec, vec::Vec};
    use super::*;
    use gnunet_wfp_dns::LocalInterface;

    const RESPONSE: &[u8] = b"\x12\x34\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00\xaa";

    fn path(addresses: Addresses) -> Path {
        let interface = LocalInterface::new(0x0123_0000, 8, 9).expect("fixed interface identity");
        Path::new(addresses, [4242, 53], 7, interface, 0).expect("fixed complete unicast path")
    }

    fn assert_hex(actual: &[u8], fixture: &str) {
        let expected: Vec<_> = fixture
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let digits = core::str::from_utf8(pair).expect("ASCII fixture");
                u8::from_str_radix(digits, 16).expect("hexadecimal fixture")
            })
            .collect();
        assert_eq!(
            actual, expected,
            "complete IP/UDP packet differs from checksum fixture"
        );
    }

    #[test]
    fn ipv4_reply_has_reversed_tuple_and_odd_body_checksums() {
        let plan = Plan::new(
            path(Addresses::V4 {
                local: [192, 0, 2, 9],
                remote: [198, 51, 100, 53],
            }),
            RESPONSE,
        )
        .expect("valid reply");
        let mut output = vec![0xff; plan.bytes()];
        plan.write(RESPONSE, &mut output).expect("exact storage");
        assert_hex(
            &output,
            "450000290000400040114e52c6336435c0000209003510920015c4d4123481800001000000000000aa",
        );
    }

    #[test]
    fn ipv6_reply_has_reversed_addresses_and_mandatory_odd_body_checksum() {
        let addresses = Addresses::V6 {
            local: [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9],
            remote: [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53],
        };
        let plan = Plan::new(path(addresses), RESPONSE).expect("valid reply");
        let mut output = vec![0xff; plan.bytes()];
        plan.write(RESPONSE, &mut output).expect("exact storage");
        assert_hex(
            &output,
            "600000000015114020010db800000000000000000000005320010db80000000000000000000000090035109200155579123481800001000000000000aa",
        );
    }

    #[test]
    fn ordinary_ip_extents_are_family_specific_and_never_wrap() {
        let ipv4 = path(Addresses::V4 {
            local: [192, 0, 2, 9],
            remote: [198, 51, 100, 53],
        });
        let ipv6 = path(Addresses::V6 {
            local: [1; 16],
            remote: [2; 16],
        });
        for (path, maximum, header) in [(ipv4, 65_507, IPV4_BYTES), (ipv6, 65_527, IPV6_BYTES)] {
            let mut body = vec![0; maximum];
            body[2] = 0x80;
            let plan = Plan::new(path, &body).expect("maximum ordinary datagram");
            let mut packet = vec![0; plan.bytes()];
            plan.write(&body, &mut packet)
                .expect("maximum packet storage");
            assert_eq!(
                &packet[header + 4..header + 6],
                &((maximum + UDP_BYTES) as u16).to_be_bytes()
            );
            body.push(0);
            assert!(
                matches!(Plan::new(path, &body), Err(PacketError::Length { bytes, maximum: max }) if bytes == maximum+1 && max == maximum)
            );
        }
    }
}
