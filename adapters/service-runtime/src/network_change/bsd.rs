//! Read-only PF_ROUTE hints for the macOS and FreeBSD scan owners.
#![forbid(unsafe_code)]

use crate::readiness::RegisteredIo;
use gnunet_native::pf_scope::{Event, MESSAGE_BYTES, Monitor};
use std::{
    io,
    mem::{offset_of, size_of},
    task::{Context, Poll},
};

pub(super) struct Source {
    socket: RegisteredIo<Monitor>,
    receive: Vec<u8>,
}

impl Source {
    pub(super) fn subscribe() -> io::Result<Self> {
        let mut receive = Vec::new();
        receive
            .try_reserve_exact(MESSAGE_BYTES)
            .map_err(io::Error::other)?;
        receive.resize(MESSAGE_BYTES, 0);
        let socket =
            RegisteredIo::from_descriptor(Monitor::subscribe()?).map_err(|(_, error)| error)?;
        Ok(Self { socket, receive })
    }

    pub(super) fn poll_receive(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        self.socket.poll_read_on(cx, |monitor| {
            // The native monitor validates the source, version and exact record
            // length before returning even for the additional message kinds.
            Ok(match monitor.read(&mut self.receive)? {
                Event::AddressAdded | Event::AddressRemoved(_) | Event::InterfaceDeparted(_) => {
                    true
                }
                Event::Other => extra_hint(&self.receive),
            })
        })
    }
}

fn extra_hint(buffer: &[u8]) -> bool {
    let [low, high, _, kind, ..] = buffer else {
        return false;
    };
    let length = usize::from(u16::from_ne_bytes([*low, *high]));
    let Some(packet) = buffer.get(..length) else {
        return false;
    };
    match i32::from(*kind) {
        libc::RTM_IFINFO => packet.len() >= size_of::<libc::if_msghdr>(),
        #[cfg(target_os = "macos")]
        libc::RTM_IFINFO2 => packet.len() >= size_of::<libc::if_msghdr2>(),
        #[cfg(target_os = "freebsd")]
        libc::RTM_IFANNOUNCE => packet.len() >= size_of::<libc::if_announcemsghdr>(),
        libc::RTM_ADD | libc::RTM_DELETE | libc::RTM_CHANGE | libc::RTM_REDIRECT => {
            default_route(packet).unwrap_or(false)
        }
        _ => false,
    }
}

const ROUTE_HEADER: usize = size_of::<libc::rt_msghdr>();
#[cfg(target_os = "macos")]
const ADDRESS_ALIGNMENT: usize = size_of::<u32>();
#[cfg(target_os = "freebsd")]
const ADDRESS_ALIGNMENT: usize = size_of::<libc::c_ulong>();
const ROUTE_WORDS: [usize; 3] = [
    offset_of!(libc::rt_msghdr, rtm_flags),
    offset_of!(libc::rt_msghdr, rtm_addrs),
    offset_of!(libc::rt_msghdr, rtm_errno),
];

fn default_route(packet: &[u8]) -> Option<bool> {
    let [flags_at, addresses_at, error_at] = ROUTE_WORDS;
    let word = |at| Some(i32::from_ne_bytes(packet.get(at..at + 4)?.try_into().ok()?));
    let flags = word(flags_at)?;
    let addresses = word(addresses_at)?;
    if word(error_at)? != 0
        || flags & (libc::RTF_HOST | libc::RTF_LLINFO) != 0
        || addresses & libc::RTA_DST == 0
    {
        return Some(false);
    }
    let (destination, mut rest) = take_address(packet.get(ROUTE_HEADER..)?)?;
    if !unspecified(destination) {
        return Some(false);
    }
    if addresses & libc::RTA_NETMASK == 0 {
        return Some(true);
    }
    if addresses & libc::RTA_GATEWAY != 0 {
        (_, rest) = take_address(rest)?;
    }
    let (mask, _) = take_address(rest)?;
    // Compact masks carry only their nonzero prefix bytes after the native
    // length and family, including a zero-length sockaddr for the /0 mask.
    Some(mask.iter().skip(2).all(|byte| *byte == 0))
}

fn unspecified(address: &[u8]) -> bool {
    let &[_, family, ..] = address else {
        return false;
    };
    let (offset, size) = match i32::from(family) {
        libc::AF_INET => (offset_of!(libc::sockaddr_in, sin_addr), 4),
        libc::AF_INET6 => (offset_of!(libc::sockaddr_in6, sin6_addr), 16),
        _ => return false,
    };
    address
        .get(offset..offset + size)
        .is_some_and(|bytes| bytes.iter().all(|byte| *byte == 0))
}

fn take_address(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let length = usize::from(*bytes.first()?);
    let address = bytes.get(..length)?;
    let tail = if length == bytes.len() {
        &[]
    } else {
        bytes.get(length.max(1).next_multiple_of(ADDRESS_ALIGNMENT)..)?
    };
    Some((address, tail))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(kind: i32, length: usize) -> Vec<u8> {
        let mut packet = vec![0; length];
        packet[..2].copy_from_slice(&(length as u16).to_ne_bytes());
        packet[2] = libc::RTM_VERSION as u8;
        packet[3] = kind as u8;
        packet
    }

    fn default_with_mask(family: i32, destination_size: usize) -> Vec<u8> {
        let size = destination_size.next_multiple_of(ADDRESS_ALIGNMENT);
        let mut bytes = packet(libc::RTM_CHANGE, ROUTE_HEADER + size + ADDRESS_ALIGNMENT);
        let addresses_at = ROUTE_WORDS[1];
        bytes[addresses_at..addresses_at + 4]
            .copy_from_slice(&(libc::RTA_DST | libc::RTA_NETMASK).to_ne_bytes());
        bytes[ROUTE_HEADER] = destination_size as u8;
        bytes[ROUTE_HEADER + 1] = family as u8;
        bytes
    }

    #[test]
    fn matches_link_change_and_only_default_ip_routes() {
        let link = packet(libc::RTM_IFINFO, size_of::<libc::if_msghdr>());
        assert!(extra_hint(&link));
        let mut v4 = default_with_mask(libc::AF_INET, size_of::<libc::sockaddr_in>());
        let v6 = default_with_mask(libc::AF_INET6, size_of::<libc::sockaddr_in6>());
        assert!(extra_hint(&v4));
        assert!(extra_hint(&v6));
        let mask =
            ROUTE_HEADER + size_of::<libc::sockaddr_in>().next_multiple_of(ADDRESS_ALIGNMENT);
        let mut gateway = vec![0; 10_usize.next_multiple_of(ADDRESS_ALIGNMENT)];
        gateway[0] = 10;
        gateway[1] = libc::AF_LINK as u8;
        let mut with_gateway = v4.clone();
        drop(with_gateway.splice(mask..mask, gateway));
        let length = with_gateway.len() as u16;
        with_gateway[..2].copy_from_slice(&length.to_ne_bytes());
        let addresses_at = ROUTE_WORDS[1];
        with_gateway[addresses_at..addresses_at + 4].copy_from_slice(
            &(libc::RTA_DST | libc::RTA_GATEWAY | libc::RTA_NETMASK).to_ne_bytes(),
        );
        assert!(extra_hint(&with_gateway));

        v4[mask] = 5;
        let padded_mask = 5_usize.next_multiple_of(ADDRESS_ALIGNMENT);
        let length = mask + padded_mask;
        v4.resize(length, 0);
        v4[..2].copy_from_slice(&(length as u16).to_ne_bytes());
        v4[mask + 4] = 0xff;
        assert!(!extra_hint(&v4));
        assert!(!extra_hint(&v6[..ROUTE_HEADER]));
    }
}
