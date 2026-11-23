//! Linux rtnetlink notifications for interface and default-route scan hints.
#![forbid(unsafe_code)]

use crate::readiness::RegisteredIo;
use nix::sys::socket::{
    AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, bind, recvmsg, socket,
};
use std::{
    io::{self, IoSliceMut},
    os::fd::{AsRawFd, BorrowedFd},
    task::{Context, Poll},
};

// UAPI RTMGRP_LINK, RTMGRP_IPV4_IFADDR, RTMGRP_IPV4_ROUTE,
// RTMGRP_IPV6_IFADDR and RTMGRP_IPV6_ROUTE. Bionic's libc bindings omit them.
const GROUPS: u32 = 0x0001 | 0x0010 | 0x0040 | 0x0100 | 0x0400;
const NETLINK_HEADER: usize = size_of::<libc::nlmsghdr>();
const ROUTE_HEADER: usize = 12;
const RECEIVE_BYTES: usize = 8 * 1024;
pub(super) struct Source {
    socket: RegisteredIo,
    receive: Vec<u8>,
}

impl Source {
    pub(super) fn subscribe() -> io::Result<Self> {
        let socket = socket(
            AddressFamily::Netlink,
            SockType::Raw,
            SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
            SockProtocol::NetlinkRoute,
        )?;
        bind(socket.as_raw_fd(), &NetlinkAddr::new(0, GROUPS))?;
        let mut receive = Vec::new();
        receive
            .try_reserve_exact(RECEIVE_BYTES)
            .map_err(io::Error::other)?;
        receive.resize(RECEIVE_BYTES, 0);
        let socket = RegisteredIo::new(socket).map_err(|failure| failure.error)?;
        Ok(Self { socket, receive })
    }

    pub(super) fn poll_receive(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        self.socket
            .poll_read_with(cx, |fd| receive_hint(fd, &mut self.receive))
    }
}

fn receive_hint(socket: BorrowedFd<'_>, bytes: &mut [u8]) -> io::Result<bool> {
    let mut buffers = [IoSliceMut::new(bytes)];
    let received = recvmsg::<NetlinkAddr>(
        socket.as_raw_fd(),
        &mut buffers,
        None,
        MsgFlags::MSG_DONTWAIT,
    )?;
    // A message header port need not be the sender. Only the kernel-supplied
    // address identifies the origin of a multicast notification.
    if !received.address.is_some_and(|sender| sender.pid() == 0) {
        return Ok(false);
    }
    if received
        .flags
        .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC)
    {
        return Ok(true);
    }
    let extent = received.bytes;
    Ok(bytes.get(..extent).is_none_or(datagram_hint))
}

fn datagram_hint(mut bytes: &[u8]) -> bool {
    const OVERRUN: u16 = libc::NLMSG_OVERRUN as u16;
    loop {
        let Some(&[l0, l1, l2, l3, k0, k1, ..]) = bytes.first_chunk::<NETLINK_HEADER>() else {
            return true;
        };
        let length = u32::from_ne_bytes([l0, l1, l2, l3]) as usize;
        let Some(body) = bytes.get(NETLINK_HEADER..length) else {
            return true;
        };
        match u16::from_ne_bytes([k0, k1]) {
            libc::RTM_NEWLINK
            | libc::RTM_DELLINK
            | libc::RTM_NEWADDR
            | libc::RTM_DELADDR
            | OVERRUN => return true,
            libc::RTM_NEWROUTE | libc::RTM_DELROUTE => {
                let Some(&[family, destination_bits, ..]) = body.first_chunk::<ROUTE_HEADER>()
                else {
                    return true;
                };
                if destination_bits == 0
                    && matches!(i32::from(family), libc::AF_INET | libc::AF_INET6)
                {
                    return true;
                }
            }
            _ => {}
        }
        if length == bytes.len() {
            return false;
        }
        let Some(remaining) = length
            .checked_next_multiple_of(4)
            .and_then(|next| bytes.get(next..))
        else {
            return true;
        };
        if remaining.is_empty() {
            return false;
        }
        bytes = remaining;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame<const N: usize>(kind: u16) -> [u8; N] {
        let mut frame = [0; N];
        frame[..4].copy_from_slice(&(N as u32).to_ne_bytes());
        frame[4..6].copy_from_slice(&kind.to_ne_bytes());
        frame
    }

    #[test]
    fn filters_ordinary_routes_and_coalesces_actual_changes_or_loss() {
        let mut route = frame::<{ NETLINK_HEADER + ROUTE_HEADER }>(libc::RTM_NEWROUTE);
        route[NETLINK_HEADER] = libc::AF_INET6 as u8;
        route[NETLINK_HEADER + 1] = 64;
        assert!(!datagram_hint(&route));
        let deleted_address = frame::<{ NETLINK_HEADER + 8 }>(libc::RTM_DELADDR);
        let mut batch = route.to_vec();
        batch.extend_from_slice(&deleted_address);
        assert!(datagram_hint(&batch));
        route[NETLINK_HEADER + 1] = 0;
        assert!(datagram_hint(&route));
        assert!(datagram_hint(&route[..NETLINK_HEADER + 1]));
        assert!(datagram_hint(&frame::<NETLINK_HEADER>(
            libc::NLMSG_OVERRUN as u16
        )));
    }
}
