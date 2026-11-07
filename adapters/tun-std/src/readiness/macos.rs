//! Read-only SDK IPv6 address-specific netmask and DAD-flag ioctls.
use super::*;
use std::os::fd::{AsRawFd, OwnedFd};
// SDK in6_var.h: _IOWR('i',37,struct in6_ifreq). Pinned libc exports the
// same _IOWR('i',73,in6_ifreq) flags command but not the netmask command.
// Both use identical direction/group/size; replace only the command byte.
const GET_NETMASK: libc::c_ulong = (libc::SIOCGIFAFLAG_IN6 & !0xff) | 37;
pub(super) struct Backend {
    socket: OwnedFd,
}
impl Backend {
    pub(super) fn new(_: &Ipv6Target, _: Ipv6WatchOptions) -> io::Result<Self> {
        let socket = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)?;
        let socket: OwnedFd = socket.into();
        crate::platform::nonblocking(&socket)?;
        Ok(Self { socket })
    }
    pub(super) fn begin(&mut self) -> io::Result<()> {
        Ok(())
    }
    pub(super) fn close(self) -> io::Result<()> {
        nix::unistd::close(self.socket).map_err(io::Error::from)
    }
    pub(super) fn poll(
        &mut self,
        _: &mut Context<'_>,
        target: &Ipv6Target,
    ) -> Poll<io::Result<Step>> {
        let sample = (|| {
            let before = self.netmask(target)?;
            let mut req = request(target)?;
            ioctl(&self.socket, libc::SIOCGIFAFLAG_IN6, &mut req)?;
            #[expect(
                unsafe_code,
                reason = "Successful SIOCGIFAFLAG_IN6 wrote the exact SDK in6_ifreq flags6 union member"
            )]
            // SAFETY: this exact initialized request was synchronously filled by
            // the flags ioctl; read only its documented integer output member.
            let flags = unsafe { req.ifr_ifru.ifru_flags6 } as u32;
            let after = self.netmask(target)?;
            if before != after {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "IPv6 prefix changed during readiness query",
                ));
            }
            let state = if before != target.prefix {
                Ipv6State::PrefixMismatch { observed: before }
            } else if flags & libc::IN6_IFF_DUPLICATED as u32 != 0 {
                Ipv6State::DadFailed
            } else if flags & (libc::IN6_IFF_TENTATIVE | libc::IN6_IFF_OPTIMISTIC) as u32 != 0 {
                Ipv6State::Tentative
            } else if flags & libc::IN6_IFF_DETACHED as u32 != 0 {
                Ipv6State::Detached
            } else {
                Ipv6State::Ready
            };
            Ok(Step::Sample(state, Some(flags)))
        })();
        // EADDRNOTAVAIL is actual address-specific absence. Other errors retain
        // their errno instead of being rewritten as missing/DAD completion.
        Poll::Ready(match sample {
            Err(e) if e.raw_os_error() == Some(libc::EADDRNOTAVAIL) => {
                Ok(Step::Sample(Ipv6State::Missing, None))
            }
            other => other,
        })
    }
    fn netmask(&self, target: &Ipv6Target) -> io::Result<u8> {
        let mut req = request(target)?;
        ioctl(&self.socket, GET_NETMASK, &mut req)?;
        #[expect(
            unsafe_code,
            reason = "Successful SIOCGIFNETMASK_IN6 wrote this exact SDK sockaddr_in6 union member"
        )]
        // SAFETY: preceding read-only ioctl initializes its documented address output.
        let mask = unsafe { req.ifr_ifru.ifru_addr };
        // XNU may leave family zero for masks; only the initialized 16 address
        // octets are interpreted as a contiguous prefix, never as an IP endpoint.
        prefix(mask.sin6_addr.s6_addr)
    }
}
fn request(target: &Ipv6Target) -> io::Result<libc::in6_ifreq> {
    let mut req = libc::in6_ifreq::default();
    let name = crate::platform::name(&target.interface.name)?;
    for (a, b) in req.ifr_name.iter_mut().zip(name.as_bytes_with_nul()) {
        *a = *b as libc::c_char;
    }
    req.ifr_ifru.ifru_addr = libc::sockaddr_in6 {
        sin6_len: std::mem::size_of::<libc::sockaddr_in6>() as u8,
        sin6_family: libc::AF_INET6 as u8,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: target.address.octets(),
        },
        sin6_scope_id: if target.address.is_unicast_link_local() {
            target.interface.index
        } else {
            0
        },
    };
    Ok(req)
}
fn ioctl(fd: &OwnedFd, command: libc::c_ulong, req: &mut libc::in6_ifreq) -> io::Result<()> {
    #[expect(
        unsafe_code,
        reason = "Only fixed read-only SDK IPv6 ioctls reach this helper, with exact initialized in6_ifreq storage and a bounded NUL-terminated name/address"
    )]
    // SAFETY: command's ABI/type/size match this writable live request. No
    // pointer escapes; neither supported command mutates network configuration.
    let result = unsafe { libc::ioctl(fd.as_raw_fd(), command, req as *mut libc::in6_ifreq) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn prefix(mask: [u8; 16]) -> io::Result<u8> {
    let mut count = 0;
    let mut zero = false;
    for byte in mask {
        for bit in (0..8).rev() {
            if byte & (1 << bit) == 0 {
                zero = true;
            } else if zero {
                return Err(malformed());
            } else {
                count += 1;
            }
        }
    }
    Ok(count)
}
