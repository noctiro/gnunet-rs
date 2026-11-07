//! FreeBSD if_tun.h and in6_var.h ABI. No shell commands or device surrogates.
use super::*;
use crate::Mode;
use std::{mem::size_of, net::Ipv6Addr, os::unix::fs::OpenOptionsExt};

// FreeBSD sys/net/if_tun.h. Sizes come from the native ABI types, not Darwin.
const GET_NAME: libc::c_ulong = nix::request_code_read!(b't', 93, size_of::<libc::ifreq>());
const SET_HEADER: libc::c_ulong = nix::request_code_write!(b't', 96, size_of::<libc::c_int>());
const GET_HEADER: libc::c_ulong = nix::request_code_read!(b't', 97, size_of::<libc::c_int>());
pub(crate) const SIOCGIFMTU: libc::c_ulong =
    nix::request_code_readwrite!(b'i', 51, size_of::<libc::ifreq>());
pub(crate) const SIOCGIFFLAGS: libc::c_ulong =
    nix::request_code_readwrite!(b'i', 17, size_of::<libc::ifreq>());
pub(crate) const SIOCGIFNETMASK: libc::c_ulong =
    nix::request_code_readwrite!(b'i', 37, size_of::<libc::ifreq>());
const SIOCSIFMTU: libc::c_ulong = nix::request_code_write!(b'i', 52, size_of::<libc::ifreq>());
const SIOCSIFFLAGS: libc::c_ulong = nix::request_code_write!(b'i', 16, size_of::<libc::ifreq>());
const SIOCSIFADDR: libc::c_ulong = nix::request_code_write!(b'i', 12, size_of::<libc::ifreq>());
const SIOCSIFNETMASK: libc::c_ulong = nix::request_code_write!(b'i', 22, size_of::<libc::ifreq>());

fn header(fd: &OwnedFd) -> io::Result<libc::c_int> {
    let mut value = 0;
    #[expect(
        unsafe_code,
        reason = "TUNGIFHEAD writes exactly one live initialized c_int, as declared by FreeBSD if_tun.h"
    )]
    // SAFETY: the native request size and exclusive output buffer agree.
    let result = unsafe { libc::ioctl(fd.as_raw_fd(), GET_HEADER, &mut value) };
    result_code(result)?;
    Ok(value)
}

pub(crate) fn verify(fd: &OwnedFd) -> io::Result<Info> {
    let stat = nix::sys::stat::fstat(fd)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFCHR {
        return Err(invalid("FreeBSD TUN requires a character device"));
    }
    // TUNGIFHEAD is accepted only by the L3 TUN branch, not TAP. A zero header
    // cannot establish raw-IP framing: TUN_LMODE may carry a variable sockaddr.
    if header(fd)? != 1 {
        return Err(invalid("FreeBSD TUN requires TUN_IFHEAD framing"));
    }
    let mut req = request("tun")?;
    ioctl(fd, GET_NAME, &mut req)?;
    let name = read_name(&req.ifr_name)?;
    let index = index(&name)?;
    Ok(Info {
        name,
        index,
        mode: Mode::FreeBsd,
    })
}

pub(crate) fn open_existing(interface: &str) -> io::Result<OwnedFd> {
    let suffix = interface
        .strip_prefix("tun")
        .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        .ok_or_else(|| invalid("expected a named FreeBSD tunN interface"))?;
    let _checked_name = name(interface)?;
    // Refuse an absent unit before opening its named device. The caller must
    // serialize interface administration: concurrent destruction can invoke
    // named devfs cloning before the second identity check detects replacement.
    let expected = index(interface)?;
    let path = format!("/dev/tun{suffix}");
    let fd: OwnedFd = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)?
        .into();
    let mut enabled: libc::c_int = 1;
    #[expect(
        unsafe_code,
        reason = "TUNSIFHEAD reads one initialized native c_int and clears incompatible TUN_LMODE in the actual FreeBSD driver"
    )]
    // SAFETY: exact ioctl ABI; this owned descriptor remains live synchronously.
    let result = unsafe { libc::ioctl(fd.as_raw_fd(), SET_HEADER, &mut enabled) };
    result_code(result)?;
    let info = verify(&fd)?;
    if info.name != interface || info.index != expected {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "FreeBSD TUN identity changed during open",
        ));
    }
    Ok(fd)
}

fn result_code(result: libc::c_int) -> io::Result<()> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn ioctl(fd: &impl AsRawFd, command: libc::c_ulong, req: &mut libc::ifreq) -> io::Result<()> {
    #[expect(
        unsafe_code,
        reason = "Private callers supply exact initialized FreeBSD ifreq storage for fixed interface ioctls, with the documented active union member"
    )]
    // SAFETY: only the typed private operations in this module call this helper.
    let result = unsafe { libc::ioctl(fd.as_raw_fd(), command, req as *mut libc::ifreq) };
    result_code(result)
}

pub(crate) fn apply(info: &Info, action: &Action) -> io::Result<()> {
    if index(&info.name)? != info.index {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "TUN interface replaced",
        ));
    }
    let socket = control_socket()?;
    let mut req = request(&info.name)?;
    match action {
        Action::Mtu(mtu) => {
            req.ifr_ifru.ifru_mtu = i32::try_from(*mtu).map_err(|_| invalid("MTU overflow"))?;
            ioctl(&socket, SIOCSIFMTU, &mut req)
        }
        Action::LinkUp(up) => {
            ioctl(&socket, SIOCGIFFLAGS, &mut req)?;
            #[expect(
                unsafe_code,
                reason = "Successful SIOCGIFFLAGS initializes both native FreeBSD flags shorts in this exact local request"
            )]
            // SAFETY: read only the union member just written by the kernel.
            let mut flags = unsafe { req.ifr_ifru.ifru_flags };
            if *up {
                flags[0] |= libc::IFF_UP as i16;
            } else {
                flags[0] &= !(libc::IFF_UP as i16);
            }
            req.ifr_ifru.ifru_flags = flags;
            ioctl(&socket, SIOCSIFFLAGS, &mut req)
        }
        Action::Ipv4Address(address) | Action::Ipv4Netmask(address) => {
            let mut data = [0; 14];
            data[2..6].copy_from_slice(&address.octets());
            req.ifr_ifru.ifru_addr = libc::sockaddr {
                sa_len: size_of::<libc::sockaddr_in>() as u8,
                sa_family: libc::AF_INET as u8,
                sa_data: data.map(|b| b as libc::c_char),
            };
            ioctl(
                &socket,
                if matches!(action, Action::Ipv4Address(_)) {
                    SIOCSIFADDR
                } else {
                    SIOCSIFNETMASK
                },
                &mut req,
            )
        }
        Action::Ipv6Address { address, prefix } => address6(info, *address, *prefix),
        Action::Route { .. } => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "use NativeRoute for correlated kernel route ACKs",
        )),
    }
}

// libc does not export these FreeBSD structures. Field order/types follow
// sys/netinet6/in6_var.h; the native CI ABI probe checks sizes and ioctl values.
#[repr(C)]
struct AddressLifetime {
    expire: libc::time_t,
    preferred: libc::time_t,
    valid_seconds: u32,
    preferred_seconds: u32,
}
#[repr(C)]
struct AliasRequest {
    name: [libc::c_char; libc::IFNAMSIZ],
    address: libc::sockaddr_in6,
    destination: libc::sockaddr_in6,
    mask: libc::sockaddr_in6,
    flags: libc::c_int,
    lifetime: AddressLifetime,
    vhid: libc::c_int,
}
const ADD_ADDRESS6: libc::c_ulong = nix::request_code_write!(b'i', 27, size_of::<AliasRequest>());

fn address6(info: &Info, address: Ipv6Addr, prefix: u8) -> io::Result<()> {
    if prefix > 128 {
        return Err(invalid("IPv6 prefix overflow"));
    }
    let sockaddr = |octets, scope| libc::sockaddr_in6 {
        sin6_len: size_of::<libc::sockaddr_in6>() as u8,
        sin6_family: libc::AF_INET6 as u8,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr { s6_addr: octets },
        sin6_scope_id: scope,
    };
    let mut mask = [0; 16];
    for (at, byte) in mask.iter_mut().enumerate() {
        let bits = usize::from(prefix).saturating_sub(at * 8).min(8);
        *byte = if bits == 0 { 0 } else { 0xff << (8 - bits) };
    }
    let mut req = AliasRequest {
        name: [0; libc::IFNAMSIZ],
        address: sockaddr(
            address.octets(),
            if address.is_unicast_link_local() {
                info.index
            } else {
                0
            },
        ),
        destination: sockaddr([0; 16], 0),
        mask: sockaddr(mask, 0),
        flags: 0,
        lifetime: AddressLifetime {
            expire: 0,
            preferred: 0,
            valid_seconds: u32::MAX,
            preferred_seconds: u32::MAX,
        },
        vhid: 0,
    };
    // No point-to-point peer address is requested by this action.
    req.destination.sin6_len = 0;
    req.destination.sin6_family = 0;
    let interface = name(&info.name)?;
    for (a, b) in req.name.iter_mut().zip(interface.as_bytes_with_nul()) {
        *a = *b as libc::c_char;
    }
    let socket = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)?;
    #[expect(
        unsafe_code,
        reason = "SIOCAIFADDR_IN6 receives initialized repr(C) in6_aliasreq matching FreeBSD in6_var.h, including vhid and native time_t; no pointer retained"
    )]
    // SAFETY: exact request layout and native ioctl size, live exclusive storage.
    let result = unsafe { libc::ioctl(socket.as_raw_fd(), ADD_ADDRESS6, &mut req) };
    result_code(result)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Assert actual kernel descriptor refusal and independently compiled native ABI values"
    )]
    use super::*;

    #[test]
    fn ordinary_descriptors_cannot_be_adopted_as_tun() -> io::Result<()> {
        let null: OwnedFd = std::fs::File::open("/dev/null")?.into();
        let Err(error) = verify(&null) else {
            return Err(io::Error::other("non-TUN character device was admitted"));
        };
        assert_eq!(error.raw_os_error(), Some(libc::ENOTTY));
        let socket: OwnedFd = control_socket()?.into();
        let Err(error) = verify(&socket) else {
            return Err(io::Error::other("socket was admitted as TUN"));
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        Ok(())
    }

    #[test]
    fn ioctl_layout_matches_native_headers() -> io::Result<()> {
        let values = [
            size_of::<libc::ifreq>() as u64,
            size_of::<AliasRequest>() as u64,
            std::mem::offset_of!(AliasRequest, lifetime) as u64,
            GET_NAME,
            SET_HEADER,
            GET_HEADER,
            ADD_ADDRESS6,
            SIOCGIFMTU,
            SIOCGIFFLAGS,
            SIOCGIFNETMASK,
            SIOCSIFMTU,
            SIOCSIFFLAGS,
            SIOCSIFADDR,
            SIOCSIFNETMASK,
        ];
        crate::native_abi::check("freebsd_tun_abi.c", &values)
    }
}
