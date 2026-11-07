//! Linux UAPI RTM_GETADDR multipart dumps; no mutation message is constructed.
use super::*;
use std::{
    os::fd::{AsRawFd, OwnedFd},
    sync::atomic::{AtomicU32, Ordering},
};
use tokio::io::unix::AsyncFd;
static NEXT_QUERY: AtomicU32 = AtomicU32::new(0);
pub(super) struct Backend {
    io: AsyncFd<OwnedFd>,
    frame: [u8; 24],
    sent: bool,
    sequence: u32,
    pid: u32,
    rx: Box<[u8; 32768]>,
    datagrams: usize,
    bytes: usize,
    options: Ipv6WatchOptions,
    found: Option<(u8, u32)>,
}
impl Backend {
    pub(super) fn new(_: &Ipv6Target, options: Ipv6WatchOptions) -> io::Result<Self> {
        let (fd, pid) = socket()?;
        #[expect(
            unsafe_code,
            reason = "Private observer retains one nonblocking OwnedFd unchanged until deregistration before close"
        )]
        // SAFETY: no mutable descriptor replacement or second registration is
        // exposed. This sole owner outlives registration and into_inner deregisters.
        let io = unsafe { AsyncFd::register(fd) }.map_err(io::Error::from)?;
        Ok(Self {
            io,
            frame: [0; 24],
            sent: false,
            sequence: 0,
            pid,
            rx: Box::new([0; 32768]),
            datagrams: 0,
            bytes: 0,
            options,
            found: None,
        })
    }
    pub(super) fn begin(&mut self) -> io::Result<()> {
        self.sequence = NEXT_QUERY
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map(|n| n + 1)
            .map_err(|_| io::Error::other("IPv6 address query sequence exhausted"))?;
        self.frame.fill(0);
        self.frame[0..4].copy_from_slice(&24u32.to_ne_bytes());
        self.frame[4..6].copy_from_slice(&libc::RTM_GETADDR.to_ne_bytes());
        self.frame[6..8]
            .copy_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
        self.frame[8..12].copy_from_slice(&self.sequence.to_ne_bytes());
        self.frame[12..16].copy_from_slice(&self.pid.to_ne_bytes());
        // UAPI ifaddrmsg: family,prefixlen,flags,scope,index (native u32).
        self.frame[16] = libc::AF_INET6 as u8;
        self.sent = false;
        self.datagrams = 0;
        self.bytes = 0;
        self.found = None;
        Ok(())
    }
    pub(super) fn close(self) -> io::Result<()> {
        nix::unistd::close(self.io.into_inner()).map_err(io::Error::from)
    }
    pub(super) fn poll(
        &mut self,
        cx: &mut Context<'_>,
        target: &Ipv6Target,
    ) -> Poll<io::Result<Step>> {
        if !self.sent {
            let mut ready = match self.io.poll_write_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(r)) => r,
            };
            let result = ready.try_io(|io| {
                nix::unistd::write(io.get_ref(), &self.frame).map_err(io::Error::from)
            });
            return match result {
                Err(_) => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Ok(Err(e)) => Poll::Ready(Err(e)),
                Ok(Ok(n)) if n != self.frame.len() => Poll::Ready(Err(io::Error::other(
                    "short read-only netlink query; no suffix replay",
                ))),
                Ok(Ok(n)) => {
                    self.sent = true;
                    Poll::Ready(Ok(Step::Activity(n)))
                }
            };
        }
        let mut ready = match self.io.poll_read_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(r)) => r,
        };
        let result = ready.try_io(|io| receive(io.get_ref(), self.rx.as_mut()));
        let n = match result {
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Ok(Err(e)) => return Poll::Ready(Err(e)),
            Ok(Ok(n)) => n,
        };
        self.datagrams += 1;
        self.bytes += n;
        if self.datagrams > self.options.dump_datagrams || self.bytes > self.options.dump_bytes {
            return Poll::Ready(Err(io::Error::other("bounded IPv6 address dump exhausted")));
        }
        let parsed = parse(&self.rx[..n], self.sequence, target, &mut self.found);
        match parsed {
            Err(e) => Poll::Ready(Err(e)),
            Ok(false) => Poll::Ready(Ok(Step::Activity(n))),
            Ok(true) => {
                let (state, flags) = match self.found {
                    None => (Ipv6State::Missing, None),
                    Some((prefix, flags)) if prefix != target.prefix => {
                        (Ipv6State::PrefixMismatch { observed: prefix }, Some(flags))
                    }
                    Some((_, flags)) => {
                        let state = if flags & libc::IFA_F_DADFAILED != 0 {
                            Ipv6State::DadFailed
                        } else if flags & (libc::IFA_F_TENTATIVE | libc::IFA_F_OPTIMISTIC) != 0 {
                            Ipv6State::Tentative
                        } else {
                            Ipv6State::Ready
                        };
                        (state, Some(flags))
                    }
                };
                Poll::Ready(Ok(Step::Sample(state, flags)))
            }
        }
    }
}
fn parse(
    bytes: &[u8],
    sequence: u32,
    target: &Ipv6Target,
    found: &mut Option<(u8, u32)>,
) -> io::Result<bool> {
    let mut at = 0;
    let mut done = false;
    while at < bytes.len() {
        let b = bytes.get(at..).ok_or_else(malformed)?;
        let n = word(b, 0)? as usize;
        if n < 16 || n > b.len() {
            return Err(malformed());
        }
        let b = &b[..n];
        let kind = short(b, 4)?;
        if kind == libc::NLMSG_OVERRUN as u16 {
            return Err(io::Error::other("kernel IPv6 address dump overrun"));
        }
        if word(b, 8)? == sequence {
            if done || short(b, 6)? & libc::NLM_F_DUMP_INTR as u16 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "interrupted IPv6 address dump; no absence inferred",
                ));
            }
            if kind == libc::NLMSG_ERROR as u16 {
                let error = i32::from_ne_bytes(range(b, 16)?);
                if error != 0 {
                    return Err(errno(error)?);
                }
            } else if kind == libc::NLMSG_DONE as u16 {
                if n != 16 && n < 20 {
                    return Err(malformed());
                }
                if n >= 20 {
                    let error = i32::from_ne_bytes(range(b, 16)?);
                    if error != 0 {
                        return Err(errno(error)?);
                    }
                }
                done = true;
            } else if kind == libc::RTM_NEWADDR {
                address(b, target, found)?;
            } else if kind != libc::NLMSG_NOOP as u16 {
                return Err(malformed());
            }
        }
        let padded = (n + 3) & !3;
        if padded > bytes.len() - at {
            if n == bytes.len() - at {
                at = bytes.len();
            } else {
                return Err(malformed());
            }
        } else {
            at += padded;
        }
    }
    Ok(done)
}
fn address(b: &[u8], target: &Ipv6Target, found: &mut Option<(u8, u32)>) -> io::Result<()> {
    if b.len() < 24 {
        return Err(malformed());
    }
    if b[16] != libc::AF_INET6 as u8 || word(b, 20)? != target.interface.index {
        return Ok(());
    }
    if b[17] > 128 {
        return Err(malformed());
    }
    let mut flags = u32::from(b[18]);
    let mut local = None;
    let mut address = None;
    let mut extended_flags = false;
    let mut at = 24;
    while at < b.len() {
        let n = usize::from(short(b, at)?);
        if n < 4 || n > b.len() - at {
            return Err(malformed());
        }
        let kind = short(b, at + 2)?;
        let value = &b[at + 4..at + n];
        if kind == libc::IFA_ADDRESS {
            if address.is_some() || value.len() != 16 {
                return Err(malformed());
            }
            address = Some(range::<16>(value, 0)?);
        } else if kind == libc::IFA_LOCAL {
            if local.is_some() || value.len() != 16 {
                return Err(malformed());
            }
            local = Some(range::<16>(value, 0)?);
        } else if kind == libc::IFA_FLAGS {
            if extended_flags || value.len() != 4 {
                return Err(malformed());
            }
            flags = word(value, 0)?;
            extended_flags = true;
        }
        let padded = (n + 3) & !3;
        if padded > b.len() - at {
            if n == b.len() - at {
                at = b.len();
            } else {
                return Err(malformed());
            }
        } else {
            at += padded;
        }
    }
    let Some(actual) = local.or(address) else {
        return Err(malformed());
    };
    if actual != target.address.octets() {
        return Ok(());
    }
    match *found {
        None => *found = Some((b[17], flags)),
        Some((prefix, old_flags)) if prefix == b[17] && old_flags != flags => {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "address changed within original dump",
            ));
        }
        Some((prefix, _)) if prefix != target.prefix && b[17] == target.prefix => {
            *found = Some((b[17], flags))
        }
        _ => {}
    }
    Ok(())
}
fn errno(negative: i32) -> io::Result<io::Error> {
    if negative >= 0 {
        return Err(malformed());
    }
    Ok(io::Error::from_raw_os_error(
        negative.checked_neg().ok_or_else(malformed)?,
    ))
}
fn range<const N: usize>(b: &[u8], at: usize) -> io::Result<[u8; N]> {
    b.get(at..at + N)
        .ok_or_else(malformed)?
        .try_into()
        .map_err(|_| malformed())
}
fn word(b: &[u8], at: usize) -> io::Result<u32> {
    Ok(u32::from_ne_bytes(range(b, at)?))
}
fn short(b: &[u8], at: usize) -> io::Result<u16> {
    Ok(u16::from_ne_bytes(range(b, at)?))
}
fn socket() -> io::Result<(OwnedFd, u32)> {
    let socket = socket2::Socket::new(
        socket2::Domain::from(libc::AF_NETLINK),
        socket2::Type::RAW,
        Some(socket2::Protocol::from(libc::NETLINK_ROUTE)),
    )?;
    socket.set_recv_buffer_size(65536)?;
    socket.set_send_buffer_size(4096)?;
    let fd: OwnedFd = socket.into();
    crate::platform::nonblocking(&fd)?;
    #[expect(
        unsafe_code,
        reason = "sockaddr_nl contains only scalar fields and padding; all-zero initialization is valid"
    )]
    // SAFETY: zero is valid for the scalar sockaddr_nl ABI, including private padding.
    let (mut local, mut kernel): (libc::sockaddr_nl, libc::sockaddr_nl) =
        unsafe { std::mem::zeroed() };
    local.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let size = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
    #[expect(
        unsafe_code,
        reason = "bind/connect use live initialized sockaddr_nl storage and its exact size; kernel destination pid/groups remain zero"
    )]
    // SAFETY: each address remains initialized/live for its synchronous syscall.
    let result = unsafe {
        let r = libc::bind(
            fd.as_raw_fd(),
            (&local as *const libc::sockaddr_nl).cast(),
            size,
        );
        if r < 0 {
            r
        } else {
            libc::connect(
                fd.as_raw_fd(),
                (&kernel as *const libc::sockaddr_nl).cast(),
                size,
            )
        }
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut n = size;
    #[expect(
        unsafe_code,
        reason = "getsockname writes only into live initialized exact sockaddr_nl capacity"
    )]
    // SAFETY: exclusive local object and length storage have the declared capacities.
    let result = unsafe {
        libc::getsockname(
            fd.as_raw_fd(),
            (&mut local as *mut libc::sockaddr_nl).cast(),
            &mut n,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if n != size || local.nl_family != libc::AF_NETLINK as libc::sa_family_t || local.nl_pid == 0 {
        return Err(malformed());
    }
    Ok((fd, local.nl_pid))
}
fn receive(fd: &OwnedFd, bytes: &mut [u8]) -> io::Result<usize> {
    #[expect(
        unsafe_code,
        reason = "sockaddr_nl/msghdr scalar and pointer storage permit zero initialization before recvmsg fills them"
    )]
    // SAFETY: no Rust references or invalid scalar representations in these C types.
    let (mut peer, mut message): (libc::sockaddr_nl, libc::msghdr) = unsafe { std::mem::zeroed() };
    let mut vector = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    message.msg_name = (&mut peer as *mut libc::sockaddr_nl).cast();
    message.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    #[expect(
        unsafe_code,
        reason = "recvmsg receives one bounded exclusive byte buffer, exact peer storage and one live iovec; no pointer escapes"
    )]
    // SAFETY: every pointer/capacity refers to the live objects above for this call.
    let n = unsafe { libc::recvmsg(fd.as_raw_fd(), &mut message, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n == 0 || message.msg_flags & libc::MSG_TRUNC != 0 || n as usize > bytes.len() {
        return Err(malformed());
    }
    if message.msg_namelen as usize != std::mem::size_of::<libc::sockaddr_nl>()
        || peer.nl_family != libc::AF_NETLINK as libc::sa_family_t
        || peer.nl_pid != 0
        || peer.nl_groups != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "IPv6 query sender is not the original unicast kernel source",
        ));
    }
    Ok(n as usize)
}
