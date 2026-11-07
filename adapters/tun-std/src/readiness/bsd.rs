//! Bounded BSD address-specific observations; native ABI stays in each backend.
use super::*;
use std::os::fd::OwnedFd;
#[cfg(target_os = "macos")]
#[path = "bsd/macos.rs"]
mod abi;
#[cfg(target_os = "freebsd")]
#[path = "bsd/freebsd.rs"]
mod abi;

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
        Poll::Ready(sample(
            &self.socket,
            &target.interface,
            target.address,
            target.prefix,
        ))
    }
}
fn sample(
    socket: &OwnedFd,
    interface: &Info,
    address: Ipv6Addr,
    requested: u8,
) -> io::Result<Step> {
    let observed = (|| {
        let before = prefix(abi::netmask(socket, interface, address)?)?;
        let flags = abi::flags(socket, interface, address)?;
        let after = prefix(abi::netmask(socket, interface, address)?)?;
        if before != after {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "IPv6 prefix changed during readiness query",
            ));
        }
        let state = if before != requested {
            Ipv6State::PrefixMismatch { observed: before }
        } else if flags & abi::DUPLICATED != 0 {
            Ipv6State::DadFailed
        } else if flags & abi::TENTATIVE != 0 {
            Ipv6State::Tentative
        } else if flags & abi::DETACHED != 0 {
            Ipv6State::Detached
        } else {
            Ipv6State::Ready
        };
        Ok(Step::Sample(state, Some(flags)))
    })();
    match observed {
        Err(error) if error.raw_os_error() == Some(libc::EADDRNOTAVAIL) => {
            Ok(Step::Sample(Ipv6State::Missing, None))
        }
        other => other,
    }
}
fn sockaddr(interface: &Info, address: Ipv6Addr) -> libc::sockaddr_in6 {
    libc::sockaddr_in6 {
        sin6_len: std::mem::size_of::<libc::sockaddr_in6>() as u8,
        sin6_family: libc::AF_INET6 as u8,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: address.octets(),
        },
        sin6_scope_id: if address.is_unicast_link_local() {
            interface.index
        } else {
            0
        },
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Check real read-only BSD loopback getters and native absence/error classification; this creates no TUN or address"
    )]
    fn loopback_ipv6_queries_keep_exact_prefix_flags_and_native_absence() -> io::Result<()> {
        let interface = Info {
            name: "lo0".to_owned(),
            index: crate::platform::index("lo0")?,
            #[cfg(target_os = "macos")]
            mode: crate::Mode::Utun,
            #[cfg(target_os = "freebsd")]
            mode: crate::Mode::FreeBsd,
        };
        let socket: OwnedFd =
            socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)?.into();
        crate::platform::nonblocking(&socket)?;
        // Only the primitive getters are exercised on lo0; no device owner or
        // source-bound Ipv6Observation receipt is manufactured by this test.
        assert!(matches!(
            sample(&socket, &interface, Ipv6Addr::LOCALHOST, 128)?,
            Step::Sample(Ipv6State::Ready, Some(_))
        ));
        assert!(matches!(
            sample(&socket, &interface, Ipv6Addr::LOCALHOST, 64)?,
            Step::Sample(Ipv6State::PrefixMismatch { observed: 128 }, Some(_))
        ));
        let absent: Ipv6Addr = "2001:db8::dead:beef".parse().map_err(io::Error::other)?;
        assert!(matches!(
            sample(&socket, &interface, absent, 128)?,
            Step::Sample(Ipv6State::Missing, None)
        ));
        nix::unistd::close(socket).map_err(io::Error::from)
    }
}
