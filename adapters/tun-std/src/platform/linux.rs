//! Linux UAPI TUNSETIFF/TUNGETIFF; ifreq layout comes from the pinned libc.
use super::*;
use crate::Mode;
use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};
fn ioctl(fd: &impl AsRawFd, code: libc::c_ulong, req: &mut libc::ifreq) -> io::Result<()> {
    #[expect(
        unsafe_code,
        reason = "Exact Linux TUN/network ioctl request points to initialized writable libc::ifreq for this synchronous call"
    )]
    // SAFETY: code is selected only from the typed callers below; req has the
    // kernel ABI layout/size and remains exclusively borrowed for the ioctl.
    let r = unsafe { libc::ioctl(fd.as_raw_fd(), code as _, req as *mut libc::ifreq) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
pub(crate) fn open(name: Option<&str>, pi: bool) -> io::Result<OwnedFd> {
    open_with_exclusivity(name, pi, false)
}
pub(crate) fn open_exclusive(name: Option<&str>, pi: bool) -> io::Result<OwnedFd> {
    open_with_exclusivity(name, pi, true)
}
fn open_with_exclusivity(name: Option<&str>, pi: bool, exclusive: bool) -> io::Result<OwnedFd> {
    let mut req = request(name.unwrap_or("tun%d"))?;
    // This is the actual Linux UAPI flag, already supplied by the pinned libc.
    // The kernel checks exclusivity atomically in the same TUNSETIFF; a separate
    // userspace name-absence check could race and grant false Created provenance.
    req.ifr_ifru.ifru_flags = (libc::IFF_TUN
        | if pi { 0 } else { libc::IFF_NO_PI }
        | if exclusive { libc::IFF_TUN_EXCL } else { 0 })
        as libc::c_short;
    let fd: OwnedFd = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open("/dev/net/tun")?
        .into();
    ioctl(&fd, libc::TUNSETIFF as libc::c_ulong, &mut req)?;
    Ok(fd)
}
pub(crate) fn verify(fd: &OwnedFd) -> io::Result<Info> {
    let mut req = request("tun")?;
    ioctl(fd, libc::TUNGETIFF as libc::c_ulong, &mut req)?;
    #[expect(
        unsafe_code,
        reason = "Successful TUNGETIFF initialized ifru_flags as the documented union member"
    )]
    // SAFETY: the kernel just wrote the TUN flags member of this local ifreq.
    let flags = unsafe { req.ifr_ifru.ifru_flags } as i32;
    if flags & (libc::IFF_TUN | libc::IFF_TAP) != libc::IFF_TUN || flags & libc::IFF_VNET_HDR != 0 {
        return Err(invalid("not a supported IP-only TUN descriptor"));
    }
    let name = read_name(&req.ifr_name)?;
    let index = index(&name)?;
    Ok(Info {
        name,
        index,
        mode: if flags & libc::IFF_NO_PI == 0 {
            Mode::LinuxPi
        } else {
            Mode::RawIp
        },
    })
}
fn legacy_apply(info: &Info, action: &Action) -> io::Result<()> {
    let socket = control_socket()?;
    let mut req = request(&info.name)?;
    match action {
        Action::Mtu(n) => {
            req.ifr_ifru.ifru_mtu = i32::try_from(*n).map_err(|_| invalid("MTU overflow"))?;
            ioctl(&socket, libc::SIOCSIFMTU as libc::c_ulong, &mut req)
        }
        Action::LinkUp(up) => {
            ioctl(&socket, libc::SIOCGIFFLAGS as libc::c_ulong, &mut req)?;
            #[expect(
                unsafe_code,
                reason = "Successful SIOCGIFFLAGS initialized this exact ifreq flags union member"
            )]
            // SAFETY: the previous ioctl wrote ifru_flags in this local request.
            let old = unsafe { req.ifr_ifru.ifru_flags };
            req.ifr_ifru.ifru_flags = if *up {
                old | libc::IFF_UP as i16
            } else {
                old & !(libc::IFF_UP as i16)
            };
            ioctl(&socket, libc::SIOCSIFFLAGS as libc::c_ulong, &mut req)
        }
        Action::Ipv4Address(address) | Action::Ipv4Netmask(address) => {
            let mut bytes = [0u8; 14];
            bytes[2..6].copy_from_slice(&address.octets());
            req.ifr_ifru.ifru_addr = libc::sockaddr {
                sa_family: libc::AF_INET as libc::sa_family_t,
                sa_data: bytes.map(|b| b as libc::c_char),
            };
            let command = if matches!(action, Action::Ipv4Address(_)) {
                libc::SIOCSIFADDR
            } else {
                libc::SIOCSIFNETMASK
            };
            ioctl(&socket, command as libc::c_ulong, &mut req)
        }
        Action::Ipv6Address { address, prefix } => address6(info, *address, *prefix),
        Action::Route { .. } => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "use NativeRoute for correlated kernel route ACKs",
        )),
    }
}

/// Actual Linux IPv6 interface-address ioctl, matching the active helper ABI.
fn address6(info: &Info, address: std::net::Ipv6Addr, prefix: u8) -> io::Result<()> {
    if prefix > 128 {
        return Err(invalid("IPv6 prefix overflow"));
    }
    let socket = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)?;
    let req = libc::in6_ifreq {
        ifr6_addr: libc::in6_addr {
            s6_addr: address.octets(),
        },
        ifr6_prefixlen: u32::from(prefix),
        ifr6_ifindex: i32::try_from(info.index).map_err(|_| invalid("interface index overflow"))?,
    };
    #[expect(
        unsafe_code,
        reason = "Linux SIOCSIFADDR on an AF_INET6 control socket reads one exact initialized libc in6_ifreq; no pointer is retained"
    )]
    // SAFETY: native request layout is supplied by libc; prefix/index were checked,
    // and this immutable stack request remains live for the synchronous ioctl.
    let result = unsafe {
        libc::ioctl(
            socket.as_raw_fd(),
            libc::SIOCSIFADDR as _,
            &req as *const libc::in6_ifreq,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
pub(crate) fn apply(info: &Info, action: &Action) -> io::Result<()> {
    if let Action::Ipv6Address { address, prefix } = action {
        return address6(info, *address, *prefix);
    }
    legacy_apply(info, action)
}
