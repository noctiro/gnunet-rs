//! 64-bit Darwin PF layouts from Apple's bsd/net/pfvar.h.
//! Packed state records are decoded as bytes; no unaligned Rust references.
use std::{io, net::IpAddr};

pub(super) const STATE_BYTES: usize = 297;
pub(super) const GET_STATES: libc::c_ulong = 0xc010_4419;
pub(super) const KILL_STATES: libc::c_ulong = 0xc0d8_4429;
const IPV4: u8 = 2;
const IPV6: u8 = 30;
const UDP: u8 = 17;
const OUTBOUND: u8 = 2;

const _: () = assert!(libc::AF_INET == 2 && libc::AF_INET6 == 30);

#[repr(C)]
pub(super) struct States {
    pub bytes: i32,
    pub buffer: *mut u8,
}
const _: () = assert!(size_of::<States>() == 16 && align_of::<States>() == 8);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct Id([u8; 12]);

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct Key {
    family: u8,
    source: [u8; 16],
    destination: [u8; 16],
    source_port: [u8; 2],
    destination_port: [u8; 2],
    interface: [u8; 16],
}

pub(super) struct Record<'src>(&'src [u8]);
pub(super) fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid Darwin PF state snapshot",
    )
}

impl<'src> Record<'src> {
    pub fn parse(bytes: &'src [u8]) -> io::Result<Self> {
        if bytes.len() != STATE_BYTES
            || !matches!(bytes[282], IPV4 | IPV6)
            || !matches!(bytes[285], 1 | OUTBOUND)
        {
            return Err(invalid());
        }
        let name = &bytes[8..24];
        let end = name
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(invalid)?;
        if end == 0 || name[..end].iter().any(|byte| byte.is_ascii_control()) {
            return Err(invalid());
        }
        Ok(Self(bytes))
    }
    pub fn id(&self) -> Id {
        let mut id = [0; 12];
        id[..8].copy_from_slice(&self.0[..8]);
        id[8..].copy_from_slice(&self.0[276..280]);
        Id(id)
    }
    pub fn dns(&self, local: &[IpAddr]) -> Option<Key> {
        if self.0[284] != UDP {
            return None;
        }
        let outbound = self.0[285] == OUTBOUND;
        // DIOCKILLSTATES compares the original stack-side hosts, not NAT's
        // gateway/wire hosts. Match that exact predicate in both directions.
        let (source, destination) = if outbound { (24, 72) } else { (72, 24) };
        let family = self.0[282];
        let mut key = Key {
            family,
            source: [0; 16],
            destination: [0; 16],
            source_port: [self.0[source + 16], self.0[source + 17]],
            destination_port: [self.0[destination + 16], self.0[destination + 17]],
            interface: [0; 16],
        };
        if key.destination_port != 53_u16.to_be_bytes() {
            return None;
        }
        let bytes = if family == IPV4 { 4 } else { 16 };
        key.source[..bytes].copy_from_slice(&self.0[source..source + bytes]);
        key.destination[..bytes].copy_from_slice(&self.0[destination..destination + bytes]);
        let source = if family == IPV4 {
            IpAddr::from([key.source[0], key.source[1], key.source[2], key.source[3]])
        } else {
            IpAddr::from(key.source)
        };
        if !local.contains(&source)
            || matches!(source, IpAddr::V6(ip) if ip.is_unicast_link_local())
        {
            return None;
        }
        let name = &self.0[8..24];
        let end = name.iter().position(|byte| *byte == 0)?;
        key.interface[..end].copy_from_slice(&name[..end]);
        Some(key)
    }
}

#[repr(C, align(8))]
pub(super) struct Kill([u8; 216]);
const _: () = assert!(size_of::<Kill>() == 216 && align_of::<Kill>() == 8);

impl Key {
    pub fn command(self) -> Kill {
        let mut bytes = [0; 216];
        bytes[0] = self.family;
        bytes[1] = UDP;
        // pf_addr_wrap is 48 bytes; the reserved/neg fields put the port
        // comparator at 52. PF_OP_EQ=2, including an exact source-port zero.
        for (at, address, port) in [
            (8, self.source, self.source_port),
            (72, self.destination, self.destination_port),
        ] {
            let width = if self.family == IPV4 { 4 } else { 16 };
            bytes[at..at + width].copy_from_slice(&address[..width]);
            bytes[at + 16..at + 16 + width].fill(0xff);
            bytes[at + 52..at + 54].copy_from_slice(&port);
            bytes[at + 54..at + 56].copy_from_slice(&port);
            bytes[at + 56] = 2;
        }
        bytes[136..152].copy_from_slice(&self.interface);
        Kill(bytes)
    }
}

#[cfg(test)]
pub(super) fn command_bytes(command: &Kill) -> &[u8; 216] {
    &command.0
}
