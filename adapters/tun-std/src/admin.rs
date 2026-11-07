//! Actual read-only per-interface observations, never restore/route ownership.
use crate::{Epoch, Info, OwnedTun, platform};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::fd::{AsRawFd, OwnedFd};
use std::{io, net::Ipv4Addr};
use tokio::time::Instant;
/// Address-specific native IPv4 observation; zero is never invented for absence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ipv4Observation {
    /// Actual address/netmask octets returned by the kernel, including real zero.
    Present(Ipv4Addr),
    /// Actual EADDRNOTAVAIL from this exact interface getter.
    Absent {
        /// Native absence errno, retained without normalization.
        errno: i32,
    },
}
/// Original source-bound query failure, never a replacement-interface snapshot.
#[derive(Debug)]
pub enum AdminFailure {
    /// Original descriptor epoch retired or name/index changed/disappeared.
    SourceRetired,
    /// Original absolute query deadline elapsed, including a late native call.
    Deadline,
    /// Actual native errno or explicit malformed/unsupported ABI result.
    Kernel(io::Error),
    /// Original failure plus independent actual query-socket close errno.
    WithClose {
        /// Original classification/errno, never replaced by cleanup failure.
        failure: Box<AdminFailure>,
        /// Actual close error; descriptor close is never retried.
        close_error: io::Error,
    },
}
impl std::fmt::Display for AdminFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SourceRetired => f.write_str("original TUN source retired"),
            Self::Deadline => f.write_str("original admin deadline"),
            Self::Kernel(e) => e.fmt(f),
            Self::WithClose {
                failure,
                close_error,
            } => write!(f, "{failure}; query socket close: {close_error}"),
        }
    }
}
impl std::error::Error for AdminFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Kernel(e) => Some(e),
            Self::WithClose { failure, .. } => Some(failure.as_ref()),
            _ => None,
        }
    }
}
impl From<io::Error> for AdminFailure {
    fn from(e: io::Error) -> Self {
        Self::Kernel(e)
    }
}
/// Actual finite group of read-only kernel interface getters. Fields are private
/// so a caller cannot manufacture a native receipt from configuration values.
/// This is a time-local observation, not a persistent or atomic restore image.
#[derive(Debug)]
pub struct NativeSnapshot {
    epoch: Epoch,
    interface: Info,
    deadline: Instant,
    started_at: Instant,
    observed_at: Instant,
    mtu: u32,
    flags: u32,
    address: Ipv4Observation,
    netmask: Ipv4Observation,
    close_error: Option<io::Error>,
}
impl NativeSnapshot {
    /// Original actual descriptor lifetime, never retained alive by this receipt.
    #[must_use]
    pub const fn epoch(&self) -> &Epoch {
        &self.epoch
    }
    /// Original verified interface name/index, not rebound on reuse.
    #[must_use]
    pub const fn interface(&self) -> &Info {
        &self.interface
    }
    /// Original finite caller deadline.
    #[must_use]
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }
    /// First query time; the getters are a bounded group, not one atomic read.
    #[must_use]
    pub const fn started_at(&self) -> Instant {
        self.started_at
    }
    /// Native group completed before the original deadline.
    #[must_use]
    pub const fn observed_at(&self) -> Instant {
        self.observed_at
    }
    /// Actual MTU from SIOCGIFMTU.
    #[must_use]
    pub const fn mtu(&self) -> u32 {
        self.mtu
    }
    /// Actual IFF_UP bit from the native flags getter.
    #[must_use]
    pub const fn up(&self) -> bool {
        self.flags & libc::IFF_UP as u32 != 0
    }
    /// Actual native lower16 interface flags.
    #[must_use]
    pub const fn flags(&self) -> u32 {
        self.flags
    }
    /// Actual primary IPv4 address or explicit native absence.
    #[must_use]
    pub const fn ipv4_address(&self) -> Ipv4Observation {
        self.address
    }
    /// Actual primary IPv4 netmask or explicit native absence.
    #[must_use]
    pub const fn ipv4_netmask(&self) -> Ipv4Observation {
        self.netmask
    }
    /// Independent actual control socket close errno; never retried.
    #[must_use]
    pub const fn close_error(&self) -> Option<&io::Error> {
        self.close_error.as_ref()
    }
    pub(crate) fn take_close_error(&mut self) -> Option<io::Error> {
        self.close_error.take()
    }
}
impl OwnedTun {
    /// Read current actual MTU/link/primary IPv4 configuration on the original
    /// verified device. No native write, adoption, restoration or rollback occurs.
    pub fn snapshot(&self, until: Instant) -> Result<NativeSnapshot, AdminFailure> {
        snapshot(self.epoch(), self.info.clone(), until, || {
            self.admin_source(until)
        })
    }
    pub(crate) fn admin_source(&self, until: Instant) -> Result<(), AdminFailure> {
        if !self.epoch.current() || self.fd.is_none() {
            return Err(AdminFailure::SourceRetired);
        }
        if Instant::now() >= until {
            return Err(AdminFailure::Deadline);
        }
        let actual = platform::verify(self.fd.as_ref().ok_or(AdminFailure::SourceRetired)?)?;
        if actual.name != self.info.name || actual.index != self.info.index {
            return Err(AdminFailure::SourceRetired);
        }
        Ok(())
    }
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
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
#[cfg(any(target_os = "linux", target_os = "macos"))]
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
            Ok(Ipv4Observation::Present(Ipv4Addr::from([
                a.sa_data[2] as u8,
                a.sa_data[3] as u8,
                a.sa_data[4] as u8,
                a.sa_data[5] as u8,
            ])))
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
    check: impl Fn() -> Result<(), AdminFailure>,
) -> Result<NativeSnapshot, AdminFailure> {
    check()?;
    let started_at = Instant::now();
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let socket: OwnedFd = platform::control_socket()?.into();
        platform::nonblocking(&socket)?;
        let result = (|| {
            let mut req = platform::request(&info.name)?;
            get(&socket, libc::SIOCGIFMTU, &mut req)?;
            #[expect(
                unsafe_code,
                reason = "Successful SIOCGIFMTU wrote this exact initialized ifreq MTU union member"
            )]
            // SAFETY: this request was synchronously filled by the matching getter.
            let mtu = u32::try_from(unsafe { req.ifr_ifru.ifru_mtu })
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative native MTU"))?;
            check()?;
            let mut req = platform::request(&info.name)?;
            get(&socket, libc::SIOCGIFFLAGS, &mut req)?;
            #[expect(
                unsafe_code,
                reason = "Successful SIOCGIFFLAGS wrote the documented initialized ifreq flags union member"
            )]
            // SAFETY: read only the scalar flags written by this exact getter.
            let flags = u32::from(unsafe { req.ifr_ifru.ifru_flags } as u16);
            check()?;
            let address = ipv4(&socket, &info.name, libc::SIOCGIFADDR)?;
            check()?;
            let netmask = ipv4(&socket, &info.name, libc::SIOCGIFNETMASK)?;
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
            mtu,
            flags,
            address,
            netmask,
            close_error,
        })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _inputs = (epoch, info, until, started_at);
        Err(AdminFailure::Kernel(io::ErrorKind::Unsupported.into()))
    }
}
