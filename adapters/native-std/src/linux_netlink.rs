//! Kernel-addressed, deadline-bounded native Netlink datagrams.
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use std::{
    io,
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
    time::Instant,
};

const ADDRESS_SIZE: libc::socklen_t = size_of::<libc::sockaddr_nl>() as libc::socklen_t;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Header {
    pub length: u32,
    pub kind: u16,
    pub flags: u16,
    pub sequence: u32,
    pub port: u32,
}

impl Header {
    pub(super) const SIZE: usize = size_of::<libc::nlmsghdr>();

    pub(super) fn write(self, bytes: &mut [u8]) -> io::Result<()> {
        let bytes = bytes
            .get_mut(..Self::SIZE)
            .ok_or_else(|| invalid("short Netlink header destination"))?;
        bytes[..4].copy_from_slice(&self.length.to_ne_bytes());
        bytes[4..6].copy_from_slice(&self.kind.to_ne_bytes());
        bytes[6..8].copy_from_slice(&self.flags.to_ne_bytes());
        bytes[8..12].copy_from_slice(&self.sequence.to_ne_bytes());
        bytes[12..16].copy_from_slice(&self.port.to_ne_bytes());
        Ok(())
    }

    pub(super) fn read(bytes: &[u8]) -> io::Result<Self> {
        let Some(
            &[
                len0,
                len1,
                len2,
                len3,
                kind0,
                kind1,
                flags0,
                flags1,
                seq0,
                seq1,
                seq2,
                seq3,
                port0,
                port1,
                port2,
                port3,
            ],
        ) = bytes.first_chunk::<{ Self::SIZE }>()
        else {
            return Err(invalid("short native Netlink header"));
        };
        let length = u32::from_ne_bytes([len0, len1, len2, len3]);
        if length < Self::SIZE as u32 {
            return Err(invalid("invalid native Netlink message length"));
        }
        Ok(Self {
            length,
            kind: u16::from_ne_bytes([kind0, kind1]),
            flags: u16::from_ne_bytes([flags0, flags1]),
            sequence: u32::from_ne_bytes([seq0, seq1, seq2, seq3]),
            port: u32::from_ne_bytes([port0, port1, port2, port3]),
        })
    }

    pub(super) fn take<'a>(bytes: &mut &'a [u8]) -> io::Result<(Self, &'a [u8])> {
        let packet = *bytes;
        let header = Self::read(packet)?;
        let length = header.length as usize;
        let body = packet
            .get(Self::SIZE..length)
            .ok_or_else(|| invalid("truncated native Netlink body"))?;
        *bytes = if length == packet.len() {
            &[]
        } else {
            packet
                .get(aligned(length)?..)
                .ok_or_else(|| invalid("truncated native Netlink padding"))?
        };
        Ok((header, body))
    }
}

pub(super) fn aligned(length: usize) -> io::Result<usize> {
    length
        .checked_next_multiple_of(4)
        .ok_or_else(|| invalid("native Netlink alignment overflow"))
}

#[derive(Debug)]
pub(super) struct Socket {
    descriptor: OwnedFd,
    port: u32,
}

impl AsFd for Socket {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.descriptor.as_fd()
    }
}

impl Socket {
    #[cfg(test)]
    pub(super) const fn fixture(descriptor: OwnedFd) -> Self {
        Self {
            descriptor,
            port: 0,
        }
    }

    #[expect(
        unsafe_code,
        reason = "Create, bind, and connect a privately owned native Netlink descriptor"
    )]
    pub(super) fn open(protocol: libc::c_int) -> io::Result<Self> {
        // SAFETY: socket receives only scalar Linux UAPI values.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                protocol,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is a newly created descriptor with no other owners.
        let descriptor = unsafe { OwnedFd::from_raw_fd(fd) };
        let kernel = unicast_address();
        // SAFETY: the exact initialized network address is borrowed during the call.
        if unsafe { libc::bind(fd, (&raw const kernel).cast(), ADDRESS_SIZE) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the same initialized address now selects destination port 0, the kernel.
        if unsafe { libc::connect(fd, (&raw const kernel).cast(), ADDRESS_SIZE) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut local = unicast_address();
        let mut length = ADDRESS_SIZE;
        // SAFETY: local and length provide exact initialized, exclusive output extents.
        if unsafe { libc::getsockname(fd, (&raw mut local).cast(), &raw mut length) } < 0 {
            return Err(io::Error::last_os_error());
        }
        if length != ADDRESS_SIZE
            || i32::from(local.nl_family) != libc::AF_NETLINK
            || local.nl_pid == 0
            || local.nl_groups != 0
        {
            return Err(invalid("invalid local Netlink port"));
        }
        Ok(Self {
            descriptor,
            port: local.nl_pid,
        })
    }

    pub(super) const fn port(&self) -> u32 {
        self.port
    }

    #[expect(
        unsafe_code,
        reason = "Only one initialized native integer is borrowed by setsockopt"
    )]
    pub(super) fn strict_dump(&self) -> io::Result<bool> {
        let enabled: libc::c_int = 1;
        // SAFETY: the live descriptor and initialized scalar remain valid for the call.
        let result = unsafe {
            libc::setsockopt(
                self.descriptor.as_raw_fd(),
                libc::SOL_NETLINK,
                libc::NETLINK_GET_STRICT_CHK,
                (&raw const enabled).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if result == 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOPROTOOPT) {
            return Ok(false);
        }
        Err(error)
    }

    #[expect(
        unsafe_code,
        reason = "Send one initialized datagram through the connected native descriptor"
    )]
    pub(super) fn send(&self, bytes: &[u8], deadline: Instant) -> io::Result<()> {
        if bytes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty Netlink request",
            ));
        }
        loop {
            check_deadline(deadline)?;
            // SAFETY: the valid descriptor and all initialized input bytes are live for this call.
            let length = unsafe {
                libc::send(
                    self.descriptor.as_raw_fd(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if length >= 0 {
                return if usize::try_from(length).ok() == Some(bytes.len()) {
                    Ok(())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "short Netlink datagram send",
                    ))
                };
            }
            self.retry(PollFlags::POLLOUT, deadline)?;
        }
    }

    #[expect(
        unsafe_code,
        reason = "Receive one bounded datagram and its original kernel source address"
    )]
    pub(super) fn receive(&self, bytes: &mut [u8], deadline: Instant) -> io::Result<usize> {
        let mut peer = unicast_address();
        let mut vector = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        // SAFETY: zero is valid for all scalar fields and pointers in msghdr before setup.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_name = (&raw mut peer).cast();
        message.msg_iov = &raw mut vector;
        message.msg_iovlen = 1;
        loop {
            check_deadline(deadline)?;
            message.msg_namelen = ADDRESS_SIZE;
            message.msg_flags = 0;
            // SAFETY: all initialized records and the bounded output extent are live and exclusive.
            let length = unsafe {
                libc::recvmsg(
                    self.descriptor.as_raw_fd(),
                    &raw mut message,
                    libc::MSG_DONTWAIT,
                )
            };
            if let Ok(length) = usize::try_from(length) {
                if length == 0
                    || length > bytes.len()
                    || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
                {
                    return Err(invalid("empty or truncated Netlink datagram"));
                }
                if message.msg_namelen != ADDRESS_SIZE
                    || i32::from(peer.nl_family) != libc::AF_NETLINK
                    || peer.nl_pid != 0
                    || peer.nl_groups != 0
                {
                    return Err(invalid("Netlink sender differs from the unicast kernel"));
                }
                return Ok(length);
            }
            self.retry(PollFlags::POLLIN, deadline)?;
        }
    }

    fn retry(&self, interest: PollFlags, deadline: Instant) -> io::Result<()> {
        let error = io::Error::last_os_error();
        match error.kind() {
            io::ErrorKind::Interrupted => return Ok(()),
            io::ErrorKind::WouldBlock => {}
            _ => return Err(error),
        }
        loop {
            check_deadline(deadline)?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            // Poll takes whole milliseconds. Round up and retain the original absolute deadline.
            let milliseconds = remaining.as_millis().saturating_add(1);
            let timeout = PollTimeout::try_from(milliseconds).unwrap_or(PollTimeout::MAX);
            let mut watched = [PollFd::new(self.descriptor.as_fd(), interest)];
            match poll(&mut watched, timeout) {
                Ok(0) | Err(nix::errno::Errno::EINTR) => {}
                Ok(_) => return Ok(()),
                Err(error) => return Err(error.into()),
            }
        }
    }
}

fn check_deadline(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Netlink request deadline elapsed",
        ));
    }
    Ok(())
}

fn unicast_address() -> libc::sockaddr_nl {
    #[expect(
        unsafe_code,
        reason = "The native Netlink address has only scalar fields and padding"
    )]
    // SAFETY: all zero is valid for the fields and implicit padding of sockaddr_nl.
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    address
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
