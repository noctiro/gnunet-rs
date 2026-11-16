//! Unix read-only interface getters and original-source qualification.
use super::*;
use crate::platform;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
use std::os::fd::{AsRawFd, OwnedFd};
impl OwnedTun {
    /// Read original link state and the requested IP observations. Unrequested
    /// address getters do not run. No native write or restoration occurs.
    pub fn snapshot(
        &self,
        until: Instant,
        options: SnapshotOptions,
    ) -> Result<NativeSnapshot, AdminFailure> {
        snapshot(self.epoch(), self.info.clone(), until, options, || {
            self.admin_source(until)
        })
    }
    pub(crate) fn admin_source(&self, until: Instant) -> Result<(), AdminFailure> {
        if !self.epoch.current() || self.handle.is_none() {
            return Err(AdminFailure::SourceRetired);
        }
        if Instant::now() >= until {
            return Err(AdminFailure::Deadline);
        }
        let actual = platform::verify(self.native_fd()?)?;
        if actual.name != self.info.name || actual.index != self.info.index {
            return Err(AdminFailure::SourceRetired);
        }
        Ok(())
    }
}
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn get(fd: &OwnedFd, command: libc::c_ulong, request: &mut libc::ifreq) -> io::Result<()> {
    #[cfg(all(target_os = "linux", target_env = "musl"))]
    let request_code = libc::c_int::try_from(command)
        .map_err(|_| platform::invalid("read-only ioctl command overflow"))?;
    #[cfg(not(all(target_os = "linux", target_env = "musl")))]
    let request_code = command;
    #[expect(
        unsafe_code,
        reason = "Private callers select only four exact read-only ifreq getters with initialized exclusive ABI storage and a bounded interface name"
    )]
    // SAFETY: request layout/size agree with each selected getter; synchronous
    // ioctl retains no pointer and mutates no network configuration.
    let result = unsafe { libc::ioctl(fd.as_raw_fd(), request_code, request as *mut libc::ifreq) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn ipv4(fd: &OwnedFd, name: &str, command: libc::c_ulong) -> io::Result<Ipv4Observation> {
    let mut req = platform::request(name)?;
    match get(fd, command, &mut req) {
        Err(e) if e.raw_os_error() == Some(libc::EADDRNOTAVAIL) => Ok(Ipv4Observation::Absent {
            errno: libc::EADDRNOTAVAIL,
        }),
        Err(e) => Err(e),
        Ok(()) => {
            #[expect(
                unsafe_code,
                reason = "Successful SIOCGIFADDR/SIOCGIFNETMASK initialized the sockaddr storage in this exact ifreq union"
            )]
            // SAFETY: both documented outputs are the same sockaddr ABI storage.
            let a = unsafe { req.ifr_ifru.ifru_addr };
            if u32::from(a.sa_family) != libc::AF_INET as u32 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "native IPv4 getter family",
                ));
            }
            let octets = [a.sa_data[2], a.sa_data[3], a.sa_data[4], a.sa_data[5]]
                .map(|byte| u8::from_ne_bytes(byte.to_ne_bytes()));
            Ok(Ipv4Observation::Present(Ipv4Addr::from(octets)))
        }
    }
}

/// Shared real read-only getters. The supplied source check is run before and
/// between actual syscalls; neither pipe metadata nor a configuration claim can
/// construct NativeSnapshot.
pub(crate) fn snapshot(
    epoch: Epoch,
    info: Info,
    until: Instant,
    options: SnapshotOptions,
    check: impl Fn() -> Result<(), AdminFailure>,
) -> Result<NativeSnapshot, AdminFailure> {
    check()?;
    let started_at = Instant::now();
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    {
        let socket: OwnedFd = if options.ipv6 && !options.ipv4 {
            socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)?.into()
        } else {
            platform::control_socket()?.into()
        };
        platform::nonblocking(&socket)?;
        let result = (|| {
            let mut req = platform::request(&info.name)?;
            get(&socket, platform::SIOCGIFMTU, &mut req)?;
            #[expect(
                unsafe_code,
                reason = "Successful SIOCGIFMTU wrote this exact initialized ifreq MTU union member"
            )]
            // SAFETY: this request was synchronously filled by the matching getter.
            let mtu = u32::try_from(unsafe { req.ifr_ifru.ifru_mtu })
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative native MTU"))?;
            check()?;
            let mut req = platform::request(&info.name)?;
            get(&socket, platform::SIOCGIFFLAGS, &mut req)?;
            #[expect(
                unsafe_code,
                reason = "Successful SIOCGIFFLAGS wrote the documented initialized ifreq flags union member"
            )]
            // SAFETY: read only the scalar flags written by this exact getter.
            let native_flags = unsafe { req.ifr_ifru.ifru_flags };
            #[cfg(not(target_os = "freebsd"))]
            let flags = u32::from(native_flags as u16);
            #[cfg(target_os = "freebsd")]
            let flags =
                u32::from(native_flags[0] as u16) | (u32::from(native_flags[1] as u16) << 16);
            check()?;
            let address = if options.ipv4 {
                ipv4(&socket, &info.name, libc::SIOCGIFADDR)?
            } else {
                Ipv4Observation::NotRequested
            };
            check()?;
            let netmask = if options.ipv4 {
                ipv4(&socket, &info.name, platform::SIOCGIFNETMASK)?
            } else {
                Ipv4Observation::NotRequested
            };
            check()?;
            Ok::<_, AdminFailure>((mtu, flags, address, netmask))
        })();
        let close_error = nix::unistd::close(socket).err().map(io::Error::from);
        let completed = result.and_then(|fields| {
            check()?;
            let observed_at = Instant::now();
            if observed_at >= until {
                return Err(AdminFailure::Deadline);
            }
            Ok((fields, observed_at))
        });
        let ((mtu, flags, address, netmask), observed_at) = match completed {
            Ok(fields) => fields,
            Err(failure) => {
                return Err(match close_error {
                    Some(close_error) => AdminFailure::WithClose {
                        failure: Box::new(failure),
                        close_error,
                    },
                    None => failure,
                });
            }
        };
        Ok(NativeSnapshot {
            epoch,
            interface: info,
            deadline: until,
            started_at,
            observed_at,
            options,
            link_mtu: mtu,
            flags: Some(flags),
            up: flags & libc::IFF_UP as u32 != 0,
            windows_status: None,
            address,
            netmask,
            close_error,
        })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
    {
        let _inputs = (epoch, info, until, started_at, options);
        Err(AdminFailure::Kernel(io::ErrorKind::Unsupported.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Mode, Stamp, Version};
    use std::{cell::Cell, rc::Rc, time::Duration};

    // Actual unprivileged kernel getter ABI, not TUN qualification or mutation.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "The read-only kernel ABI test asserts actual observations while propagating native query errors to the test runner"
    )]
    fn ipv6_control_socket_preserves_link_getters_and_unrequested_ipv4() -> Result<(), AdminFailure>
    {
        #[cfg(target_os = "linux")]
        let name = "lo";
        #[cfg(not(target_os = "linux"))]
        let name = "lo0";
        let index = platform::index(name)?;
        let epoch = Epoch(Rc::new(Stamp {
            alive: Cell::new(true),
            route_table: None,
        }));
        let wanted = SnapshotOptions {
            ipv4: false,
            ipv6: true,
        };
        let observed = snapshot(
            epoch,
            Info {
                name: name.to_owned(),
                index,
                mode: Mode::RawIp,
            },
            Instant::now() + Duration::from_secs(5),
            wanted,
            || {
                if platform::index(name)? == index {
                    Ok(())
                } else {
                    Err(AdminFailure::SourceRetired)
                }
            },
        )?;
        assert_eq!(observed.options(), wanted);
        assert_eq!(observed.interface().index, index);
        assert!(observed.link_mtu() > 0);
        assert_eq!(observed.ip_mtu(Version::V6), Some(observed.link_mtu()));
        assert_eq!(observed.ip_mtu(Version::V4), None);
        assert_eq!(observed.ipv4_address(), Ipv4Observation::NotRequested);
        assert_eq!(observed.ipv4_netmask(), Ipv4Observation::NotRequested);
        assert!(observed.close_error().is_none());
        Ok(())
    }
}
