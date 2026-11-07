//! macOS SDK kernel-control/utun ABI; no hand-sized surrogate sockaddr structs.
use super::*;
use crate::Mode;
const CONTROL: &[u8] = b"com.apple.net.utun_control\0";
fn ioctl_info(fd: &OwnedFd) -> io::Result<libc::ctl_info> {
    let mut info = libc::ctl_info {
        ctl_id: 0,
        ctl_name: [0; libc::MAX_KCTL_NAME],
    };
    for (a, b) in info.ctl_name.iter_mut().zip(CONTROL) {
        *a = *b as libc::c_char
    }
    #[expect(
        unsafe_code,
        reason = "CTLIOCGINFO receives the exact initialized SDK/libc ctl_info buffer and retains no pointer"
    )]
    // SAFETY: ioctl code and buffer size/type agree with sys/kern_control.h.
    let r = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            libc::CTLIOCGINFO,
            &mut info as *mut libc::ctl_info,
        )
    };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(info)
    }
}
fn get_option<T>(fd: &OwnedFd, option: libc::c_int, value: &mut T) -> io::Result<usize> {
    let mut size = libc::socklen_t::try_from(std::mem::size_of::<T>())
        .map_err(|_| invalid("socket option size"))?;
    #[expect(
        unsafe_code,
        reason = "The internal caller supplies initialized writable storage of the documented utun option type; kernel receives its exact byte capacity"
    )]
    // SAFETY: the local storage is initialized, exclusive and live for this call.
    let r = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SYSPROTO_CONTROL,
            option,
            (value as *mut T).cast(),
            &mut size,
        )
    };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(size as usize)
    }
}
pub(crate) fn open(unit: Option<u32>) -> io::Result<OwnedFd> {
    let socket = socket2::Socket::new(
        socket2::Domain::from(libc::PF_SYSTEM),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::from(libc::SYSPROTO_CONTROL)),
    )?;
    let fd: OwnedFd = socket.into();
    let info = ioctl_info(&fd)?;
    let address = libc::sockaddr_ctl {
        sc_len: std::mem::size_of::<libc::sockaddr_ctl>() as u8,
        sc_family: libc::AF_SYSTEM as u8,
        ss_sysaddr: libc::AF_SYS_CONTROL as u16,
        sc_id: info.ctl_id,
        sc_unit: unit
            .map(|u| {
                u.checked_add(1)
                    .ok_or_else(|| invalid("utun unit overflow"))
            })
            .transpose()?
            .unwrap_or(0),
        sc_reserved: [0; 5],
    };
    #[expect(
        unsafe_code,
        reason = "Connect uses an initialized SDK sockaddr_ctl with correct length/family/controller id; borrowed stack storage remains live synchronously"
    )]
    // SAFETY: sockaddr_ctl pointer and exact size are passed only for AF_SYSTEM.
    let r = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&address as *const libc::sockaddr_ctl).cast(),
            std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}
pub(crate) fn verify(fd: &OwnedFd) -> io::Result<Info> {
    if socket2::SockRef::from(fd).r#type()? != socket2::Type::DGRAM {
        return Err(invalid("utun requires packet-preserving SOCK_DGRAM"));
    }
    let controller = ioctl_info(fd)?;
    let mut peer = libc::sockaddr_ctl {
        sc_len: 0,
        sc_family: 0,
        ss_sysaddr: 0,
        sc_id: 0,
        sc_unit: 0,
        sc_reserved: [0; 5],
    };
    let mut n = std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t;
    #[expect(
        unsafe_code,
        reason = "getpeername writes only into exact initialized sockaddr_ctl storage with its full capacity"
    )]
    // SAFETY: kernel receives an exclusive initialized buffer and length pointer.
    let r = unsafe {
        libc::getpeername(
            fd.as_raw_fd(),
            (&mut peer as *mut libc::sockaddr_ctl).cast(),
            &mut n,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    if n as usize != std::mem::size_of::<libc::sockaddr_ctl>()
        || peer.sc_family != libc::AF_SYSTEM as u8
        || peer.ss_sysaddr != libc::AF_SYS_CONTROL as u16
        || peer.sc_id != controller.ctl_id
    {
        return Err(invalid(
            "descriptor is not connected to the real utun controller",
        ));
    }
    let mut flags = 0u32;
    if get_option(fd, libc::UTUN_OPT_FLAGS, &mut flags)? != 4 || flags != 0 {
        return Err(invalid("unsupported utun flags/header extensions"));
    }
    let mut bytes = [0 as libc::c_char; libc::IFNAMSIZ];
    let n = get_option(fd, libc::UTUN_OPT_IFNAME, &mut bytes)?;
    if n == 0 || n > bytes.len() {
        return Err(invalid("invalid utun interface-name option length"));
    }
    let name = read_name(&bytes[..n])?;
    let index = index(&name)?;
    Ok(Info {
        name,
        index,
        mode: Mode::Utun,
    })
}
fn ioctl(fd: &impl AsRawFd, code: libc::c_ulong, req: &mut libc::ifreq) -> io::Result<()> {
    #[expect(
        unsafe_code,
        reason = "Exact SDK interface ioctl request points to initialized writable libc::ifreq with a selected compatible union member"
    )]
    // SAFETY: only the fixed private network ioctl callers below reach this helper.
    let r = unsafe { libc::ioctl(fd.as_raw_fd(), code, req as *mut libc::ifreq) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn legacy_apply(info: &Info, action: &Action) -> io::Result<()> {
    let socket = control_socket()?;
    let mut req = request(&info.name)?;
    match action {
        Action::Mtu(n) => {
            req.ifr_ifru.ifru_mtu = i32::try_from(*n).map_err(|_| invalid("MTU overflow"))?;
            ioctl(&socket, libc::SIOCSIFMTU, &mut req)
        }
        Action::LinkUp(up) => {
            ioctl(&socket, libc::SIOCGIFFLAGS, &mut req)?;
            #[expect(
                unsafe_code,
                reason = "Successful SIOCGIFFLAGS initialized this exact local ifreq flags member"
            )]
            // SAFETY: kernel wrote ifru_flags in the preceding synchronous call.
            let old = unsafe { req.ifr_ifru.ifru_flags };
            req.ifr_ifru.ifru_flags = if *up {
                old | libc::IFF_UP as i16
            } else {
                old & !(libc::IFF_UP as i16)
            };
            ioctl(&socket, libc::SIOCSIFFLAGS, &mut req)
        }
        Action::Ipv4Address(address) | Action::Ipv4Netmask(address) => {
            let mut bytes = [0u8; 14];
            bytes[2..6].copy_from_slice(&address.octets());
            req.ifr_ifru.ifru_addr = libc::sockaddr {
                sa_len: 16,
                sa_family: libc::AF_INET as u8,
                sa_data: bytes.map(|b| b as libc::c_char),
            };
            let command = if matches!(action, Action::Ipv4Address(_)) {
                libc::SIOCSIFADDR
            } else {
                libc::SIOCSIFNETMASK
            };
            ioctl(&socket, command, &mut req)
        }
        Action::Ipv6Address { address, prefix } => address6(info, *address, *prefix),
        Action::Route { .. } => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "use NativeRoute for correlated kernel route ACKs",
        )),
    }
}

fn address6(info: &Info, address: std::net::Ipv6Addr, prefix: u8) -> io::Result<()> {
    if prefix > 128 {
        return Err(invalid("IPv6 prefix overflow"));
    }
    let socket = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)?;
    let sockaddr = |bytes: [u8; 16], scope: u32| libc::sockaddr_in6 {
        sin6_len: std::mem::size_of::<libc::sockaddr_in6>() as u8,
        sin6_family: libc::AF_INET6 as u8,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr { s6_addr: bytes },
        sin6_scope_id: scope,
    };
    let mut mask = [0u8; 16];
    for (bit, byte) in mask.iter_mut().enumerate() {
        let bits = (usize::from(prefix).saturating_sub(bit * 8)).min(8);
        *byte = if bits == 0 { 0 } else { 0xffu8 << (8 - bits) }
    }
    let mut req = libc::in6_aliasreq::default();
    req.ifra_addr = sockaddr(
        address.octets(),
        if address.is_unicast_link_local() {
            info.index
        } else {
            0
        },
    );
    req.ifra_dstaddr = sockaddr([0; 16], 0);
    req.ifra_prefixmask = sockaddr(mask, 0);
    req.ifra_lifetime = libc::in6_addrlifetime {
        ia6t_expire: 0,
        ia6t_preferred: 0,
        ia6t_vltime: u32::MAX,
        ia6t_pltime: u32::MAX,
    };
    // No peer destination is configured by this address-assignment action.
    req.ifra_dstaddr.sin6_len = 0;
    req.ifra_dstaddr.sin6_family = 0;
    let name = super::name(&info.name)?;
    for (a, b) in req.ifra_name.iter_mut().zip(name.as_bytes_with_nul()) {
        *a = *b as libc::c_char
    }
    #[expect(
        unsafe_code,
        reason = "SIOCAIFADDR_IN6 reads the exact initialized SDK/libc in6_aliasreq with bounded name, sockaddr fields and explicit infinite lifetimes"
    )]
    // SAFETY: every field is initialized; the checked prefix mask is sixteen
    // bytes, and this immutable C ABI request remains live for the ioctl call.
    let result = unsafe {
        libc::ioctl(
            socket.as_raw_fd(),
            libc::SIOCAIFADDR_IN6,
            &req as *const libc::in6_aliasreq,
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
