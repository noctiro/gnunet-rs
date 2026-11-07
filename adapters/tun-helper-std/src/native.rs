//! Narrow Linux UAPI and original-fd boundary; no libgnunet or hidden runtime.
use crate::{
    failure::Failure,
    options::{MAX_PACKET, Options},
};
use std::{
    fs::OpenOptions,
    io,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd, IntoRawFd, OwnedFd},
        unix::fs::OpenOptionsExt,
    },
};
pub(super) struct Streams {
    pub input: OwnedFd,
    pub output: OwnedFd,
}
impl Streams {
    #[expect(
        unsafe_code,
        reason = "The standalone single-threaded helper uniquely captures initial fd0/fd1 once; it never creates Rust stdin/stdout globals or competing owners"
    )]
    pub fn capture() -> io::Result<Self> {
        for fd in [0, 1] {
            // SAFETY: F_GETFD observes an initial standard descriptor; no variadic argument.
            if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        // SAFETY: both original inherited descriptors were verified before any open;
        // this dedicated process uses only these new owners for stdin/stdout.
        Ok(Self {
            // SAFETY: validated original fd0 is adopted only here, before any
            // other opens or Rust stdin owner exists in this helper process.
            input: unsafe { OwnedFd::from_raw_fd(0) },
            // SAFETY: validated original fd1 is distinct from fd0 and adopted
            // only here; this helper never constructs a competing stdout owner.
            output: unsafe { OwnedFd::from_raw_fd(1) },
        })
    }
}
pub(super) struct Tun {
    pub fd: OwnedFd,
    pub mtu: u32,
}
#[expect(
    unsafe_code,
    reason = "getppid only observes this current helper process"
)]
pub(super) fn parent() -> i32 {
    // SAFETY: no pointers or ownership effects.
    unsafe { libc::getppid() }
}
#[expect(
    unsafe_code,
    reason = "close consumes one unique OwnedFd exactly once and is never retried after EINTR or an ambiguous native close result"
)]
pub(super) fn close(fd: OwnedFd) -> io::Result<()> {
    let raw = fd.into_raw_fd();
    // SAFETY: this is the only owner; ownership was consumed before the call.
    if unsafe { libc::close(raw) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn close_into(error: &mut Failure, stage: &'static str, fd: OwnedFd) {
    if let Err(cause) = close(fd) {
        error.add(stage, cause);
    }
}
#[expect(
    unsafe_code,
    reason = "F_DUPFD_CLOEXEC returns one fresh descriptor above stdio; only that successful new fd is adopted once"
)]
fn lift(fd: OwnedFd) -> Result<OwnedFd, Failure> {
    if fd.as_raw_fd() >= 3 {
        return Ok(fd);
    }
    // SAFETY: the source is owned and F_DUPFD_CLOEXEC has an integer minimum argument.
    let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if raw < 0 {
        let mut error = Failure::new("descriptor lift", io::Error::last_os_error());
        close_into(&mut error, "unlifted descriptor close", fd);
        return Err(error);
    }
    // SAFETY: fcntl returned one new fd with no other Rust owner.
    let duplicate = unsafe { OwnedFd::from_raw_fd(raw) };
    if let Err(cause) = close(fd) {
        let mut error = Failure::new("unlifted descriptor close", cause);
        close_into(&mut error, "lifted descriptor close", duplicate);
        return Err(error);
    }
    Ok(duplicate)
}
#[expect(
    unsafe_code,
    reason = "libc::ifreq is a C scalar/union record for which zero is valid; all kernel inputs are explicitly initialized before use"
)]
fn request(name: &[u8]) -> Result<libc::ifreq, Failure> {
    if name.len() >= libc::IFNAMSIZ || name.contains(&0) {
        return Err(Failure::invalid("interface", "invalid interface name"));
    }
    // SAFETY: ifreq contains no Rust references/enums; zeroed scalar and pointer
    // representations are valid. The selected union member is written before ioctl.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (dst, src) in request.ifr_name.iter_mut().zip(name) {
        *dst = *src as libc::c_char;
    }
    Ok(request)
}
#[expect(
    unsafe_code,
    reason = "Only typed fixed Linux TUN/interface ioctl callers supply initialized exclusively borrowed libc::ifreq records"
)]
fn ioctl(
    fd: &impl AsRawFd,
    code: libc::c_ulong,
    request: &mut libc::ifreq,
    stage: &'static str,
) -> Result<(), Failure> {
    // SAFETY: selected code/ifreq ABI and writable lifetime are paired by callers below.
    if unsafe { libc::ioctl(fd.as_raw_fd(), code as _, request as *mut libc::ifreq) } < 0 {
        Err(Failure::new(stage, io::Error::last_os_error()))
    } else {
        Ok(())
    }
}
#[expect(
    unsafe_code,
    reason = "socket returns one fresh Linux datagram control descriptor, adopted once only on success"
)]
fn control<T>(
    family: i32,
    action: impl FnOnce(&OwnedFd) -> Result<T, Failure>,
) -> Result<T, Failure> {
    // SAFETY: constant AF_INET/AF_INET6 and datagram/CLOEXEC flags, no pointers.
    let raw = unsafe { libc::socket(family, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(Failure::new(
            "interface control socket",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: successful socket returned a unique unowned descriptor.
    let fd = lift(unsafe { OwnedFd::from_raw_fd(raw) })?;
    let result = action(&fd);
    let closed = close(fd);
    match (result, closed) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(cause)) => Err(Failure::new("control socket close", cause)),
        (Err(mut error), Err(cause)) => {
            error.add("control socket close", cause);
            Err(error)
        }
        (Err(error), Ok(())) => Err(error),
    }
}
#[expect(
    unsafe_code,
    reason = "Successful kernel getter calls initialize the corresponding documented ifreq union member before each scalar read"
)]
fn flags_mtu(fd: &OwnedFd, name: &[u8], up: bool) -> Result<u32, Failure> {
    if up {
        let mut req = request(name)?;
        ioctl(
            fd,
            libc::SIOCGIFFLAGS as _,
            &mut req,
            "read interface flags",
        )?;
        // SAFETY: SIOCGIFFLAGS wrote ifru_flags in this local record.
        let flags = unsafe { req.ifr_ifru.ifru_flags };
        req.ifr_ifru.ifru_flags = flags | (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        ioctl(fd, libc::SIOCSIFFLAGS as _, &mut req, "activate interface")?;
    }
    let mut req = request(name)?;
    ioctl(fd, libc::SIOCGIFMTU as _, &mut req, "read actual MTU")?;
    // SAFETY: SIOCGIFMTU wrote ifru_mtu in this local record.
    let mtu = u32::try_from(unsafe { req.ifr_ifru.ifru_mtu })
        .map_err(|_| Failure::invalid("MTU", "negative kernel MTU"))?;
    if mtu == 0 || mtu > MAX_PACKET as u32 {
        return Err(Failure::invalid(
            "MTU",
            "actual MTU cannot fit one official helper frame",
        ));
    }
    Ok(mtu)
}
#[expect(
    unsafe_code,
    reason = "SIOCGIFINDEX initializes ifru_ifindex; exact libc in6_ifreq address/prefix/index storage is borrowed for one synchronous IPv6 ioctl"
)]
fn ipv6(fd: &OwnedFd, name: &[u8], address: std::net::Ipv6Addr, prefix: u8) -> Result<(), Failure> {
    let mut req = request(name)?;
    ioctl(
        fd,
        libc::SIOCGIFINDEX as _,
        &mut req,
        "read IPv6 interface index",
    )?;
    // SAFETY: the matching successful getter wrote the native index member.
    let index = unsafe { req.ifr_ifru.ifru_ifindex };
    if index <= 0 {
        return Err(Failure::invalid(
            "IPv6",
            "kernel returned invalid interface index",
        ));
    }
    let req = libc::in6_ifreq {
        ifr6_addr: libc::in6_addr {
            s6_addr: address.octets(),
        },
        ifr6_prefixlen: u32::from(prefix),
        ifr6_ifindex: index,
    };
    // SAFETY: AF_INET6 SIOCSIFADDR consumes exactly this initialized Linux ABI
    // record, with valid prefix and positive current index; no pointer is retained.
    if unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            libc::SIOCSIFADDR as _,
            &req as *const libc::in6_ifreq,
        )
    } < 0
    {
        Err(Failure::new("set IPv6 address", io::Error::last_os_error()))
    } else {
        Ok(())
    }
}
fn ipv4(
    fd: &OwnedFd,
    name: &[u8],
    address: std::net::Ipv4Addr,
    mask: std::net::Ipv4Addr,
) -> Result<(), Failure> {
    for (value, code, stage) in [
        (address, libc::SIOCSIFADDR, "set IPv4 address"),
        (mask, libc::SIOCSIFNETMASK, "set IPv4 netmask"),
    ] {
        let mut req = request(name)?;
        let mut data = [0u8; 14];
        data[2..6].copy_from_slice(&value.octets());
        req.ifr_ifru.ifru_addr = libc::sockaddr {
            sa_family: libc::AF_INET as libc::sa_family_t,
            sa_data: data.map(|byte| byte as libc::c_char),
        };
        ioctl(fd, code as _, &mut req, stage)?;
    }
    Ok(())
}
pub(super) fn create(options: &Options) -> Result<Tun, Failure> {
    let fd: OwnedFd = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open("/dev/net/tun")
        .map_err(|error| Failure::new("open /dev/net/tun", error))?
        .into();
    let fd = lift(fd)?;
    let result = (|| {
        let mut req = request(&options.name)?;
        // Atomic fresh creation: never attach/mutate an existing foreign TUN.
        // Keep the actual four-byte PI; NO_PI and VNET_HDR are deliberately absent.
        req.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_TUN_EXCL) as libc::c_short;
        ioctl(&fd, libc::TUNSETIFF as _, &mut req, "create fresh PI TUN")?;
        let used = req
            .ifr_name
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| Failure::invalid("interface", "unterminated actual kernel name"))?;
        let name: Vec<u8> = req.ifr_name[..used]
            .iter()
            .map(|byte| *byte as u8)
            .collect();
        if name.is_empty() {
            return Err(Failure::invalid("interface", "kernel returned empty name"));
        }
        let family = if options.v4.is_some() || options.v6.is_none() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };
        if let Some(mtu) = options.mtu {
            control(family, |socket| {
                let mut req = request(&name)?;
                req.ifr_ifru.ifru_mtu = mtu as libc::c_int;
                ioctl(
                    socket,
                    libc::SIOCSIFMTU as _,
                    &mut req,
                    "set explicit Rust MTU",
                )
            })?;
        }
        if let Some((address, prefix)) = options.v6 {
            control(libc::AF_INET6, |socket| {
                ipv6(socket, &name, address, prefix)
            })?;
        }
        let mtu = control(family, |socket| {
            if let Some((address, mask)) = options.v4 {
                ipv4(socket, &name, address, mask)?;
            }
            flags_mtu(socket, &name, options.v4.is_some() || options.v6.is_some())
        })?;
        if options.v6.is_some() && mtu < 1280 {
            return Err(Failure::invalid("MTU", "actual IPv6 MTU below1280"));
        }
        Ok(mtu)
    })();
    match result {
        Ok(mtu) => Ok(Tun { fd, mtu }),
        Err(mut error) => {
            close_into(&mut error, "failed original TUN close", fd);
            Err(error)
        }
    }
}
#[expect(
    unsafe_code,
    reason = "poll borrows a fixed initialized array of fd/event values only; no pointer survives the synchronous call"
)]
pub(super) fn poll(entries: &mut [libc::pollfd], timeout: i32) -> io::Result<usize> {
    // SAFETY: contiguous initialized entries and exact count remain exclusive.
    let result =
        unsafe { libc::poll(entries.as_mut_ptr(), entries.len() as libc::nfds_t, timeout) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}
#[expect(
    unsafe_code,
    reason = "read writes only into the supplied exclusively borrowed bounded byte slice on an original live descriptor"
)]
pub(super) fn read(fd: &impl AsFd, output: &mut [u8]) -> io::Result<usize> {
    // SAFETY: output's pointer/length are valid for the synchronous read.
    let result = unsafe {
        libc::read(
            fd.as_fd().as_raw_fd(),
            output.as_mut_ptr().cast(),
            output.len(),
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}
#[expect(
    unsafe_code,
    reason = "write borrows only a live bounded immutable byte slice on the original supplied descriptor"
)]
pub(super) fn write(fd: &impl AsFd, input: &[u8]) -> io::Result<usize> {
    // SAFETY: this exact input slice remains live for the synchronous write.
    let result = unsafe { libc::write(fd.as_fd().as_raw_fd(), input.as_ptr().cast(), input.len()) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}
pub(super) fn diagnostic(error: &Failure) {
    use std::fmt::Write as _;
    let mut text = String::new();
    let _formatted = writeln!(text, "gnunet-tun-helper: {error}");
    let bytes = text.as_bytes();
    let bytes = &bytes[..bytes.len().min(512)];
    let mut events = [libc::pollfd {
        fd: 2,
        events: libc::POLLOUT,
        revents: 0,
    }];
    if poll(&mut events, 0).is_err() || events[0].revents & libc::POLLOUT == 0 {
        return;
    }
    #[expect(
        unsafe_code,
        reason = "One best-effort <=512-byte diagnostic uses only original fd2 after credential reduction; no packet or private data is formatted"
    )]
    // SAFETY: bytes is live for one bounded synchronous call; fd2 is never adopted,
    // closed or reconstructed as a capability. Native descriptors were lifted >=3.
    let _actual = unsafe { libc::write(2, bytes.as_ptr().cast(), bytes.len()) };
}
