//! Exclusive clone creation and its native interface lifetime.
#[cfg(test)]
use super::GET_FIB;
use super::{SET_FIB, enable_header, get_fib, ioctl, process_fib, read_int, set_int, verify};
use crate::DeviceHandle;
use crate::platform::{control_socket, index, invalid, name, request};
use std::{io, mem::size_of, os::fd::OwnedFd, os::unix::fs::OpenOptionsExt};
const CREATE: libc::c_ulong = nix::request_code_readwrite!(b'i', 122, size_of::<libc::ifreq>());
const DESTROY: libc::c_ulong = nix::request_code_write!(b'i', 121, size_of::<libc::ifreq>());
const RENAME: libc::c_ulong = nix::request_code_write!(b'i', 40, size_of::<libc::ifreq>());
const SET_TRANSIENT: libc::c_ulong = nix::request_code_write!(b't', 98, size_of::<libc::c_int>());
pub(super) const GET_TRANSIENT: libc::c_ulong =
    nix::request_code_read!(b't', 99, size_of::<libc::c_int>());

#[derive(Clone, Copy, Debug)]
pub(crate) enum Lifetime {
    Manual,
    Transient,
}
#[derive(Clone, Copy, Debug)]
enum Retired {
    Destroyed,
    Absent,
}
#[derive(Debug)]
pub(crate) enum CreationFailure {
    Before(io::Error),
    Reclaimed(io::Error),
    Unknown(io::Error),
}
impl From<io::Error> for CreationFailure {
    fn from(error: io::Error) -> Self {
        Self::Before(error)
    }
}
impl CreationFailure {
    pub(crate) fn into_parts(self) -> (io::Error, bool) {
        match self {
            Self::Before(error) | Self::Reclaimed(error) => (error, true),
            Self::Unknown(error) => (error, false),
        }
    }
}
// No Drop implementation: failed explicit destruction retains this capability
// in InterfaceCleanupError, and retry is always a caller decision.
#[derive(Debug)]
pub(crate) struct InterfaceLease {
    pub(super) socket: OwnedFd,
    pub(super) name: [u8; libc::IFNAMSIZ],
    pub(super) index: Option<u32>,
    pub(crate) recovery: Option<Box<crate::recovery::Record>>,
    pub(crate) checkpoint: Option<Box<crate::recovery::Journal>>,
    pub(super) lifetime: Lifetime,
    retired: Option<Retired>,
}
impl InterfaceLease {
    pub(crate) fn deferred(self) -> InterfaceCleanupError {
        InterfaceCleanupError {
            error: io::Error::other(
                "persistent interface destruction was deferred without an ioctl",
            ),
            interface: self,
        }
    }
    pub(super) fn name(&self) -> io::Result<&str> {
        let end = self
            .name
            .iter()
            .position(|c| *c == 0)
            .ok_or_else(|| invalid("unterminated created interface name"))?;
        if end == 0 {
            return Err(invalid("empty created interface name"));
        }
        std::str::from_utf8(&self.name[..end])
            .map_err(|_| invalid("invalid created interface name"))
    }
    fn update(&mut self, bytes: &[libc::c_char; libc::IFNAMSIZ]) {
        self.name = bytes.map(|byte| u8::from_ne_bytes(byte.to_ne_bytes()));
    }
    pub(super) fn recovered(
        socket: OwnedFd,
        record: crate::recovery::Record,
        lifetime: Lifetime,
        actual_name: [u8; 16],
    ) -> Self {
        Self {
            socket,
            name: actual_name,
            index: Some(record.index),
            recovery: Some(Box::new(record)),
            checkpoint: None,
            lifetime,
            retired: None,
        }
    }
    pub(crate) fn destroy(self) -> Result<(), InterfaceCleanupError> {
        self.retire().map(drop)
    }
    pub(crate) fn retire(
        mut self,
    ) -> Result<Option<crate::recovery::Journal>, InterfaceCleanupError> {
        let result = (|| {
            if self.retired.is_none() {
                if let (Some(checkpoint), Some(record)) = (&mut self.checkpoint, &self.recovery) {
                    checkpoint.fence_active(record)?;
                }
                let absent = if let Some(record) = &self.recovery {
                    match super::recovery::locate(&self.socket, record)? {
                        Some(name) => {
                            self.name = name;
                            false
                        }
                        None => true,
                    }
                } else if let Some(expected) = self.index {
                    match index(self.name()?) {
                        Ok(current) if current == expected => false,
                        Ok(_) => {
                            return Err(invalid(
                                "created interface name changed its original index",
                            ));
                        }
                        Err(error)
                            if matches!(
                                error.raw_os_error(),
                                Some(libc::ENXIO | libc::ENODEV | libc::ENOENT)
                            ) =>
                        {
                            true
                        }
                        Err(error) => return Err(error),
                    }
                } else {
                    false
                };
                let name = self.name()?.to_owned();
                if absent {
                    self.retired = Some(Retired::Absent);
                } else {
                    if let Some(record) = &self.recovery {
                        super::recovery::check_marker_at(&self.socket, &name, record)?;
                    }
                    if matches!(self.lifetime, Lifetime::Transient) {
                        return Err(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "transient TUN still has independent device users",
                        ));
                    }
                    ioctl(&self.socket, DESTROY, &mut request(&name)?)?;
                    self.retired = Some(Retired::Destroyed);
                }
            }
            if let (Some(checkpoint), Some(record)) = (&mut self.checkpoint, &self.recovery) {
                checkpoint.finish_active(record)?;
            }
            Ok(())
        })();
        match result {
            Ok(()) => Ok(self.checkpoint.take().map(|checkpoint| *checkpoint)),
            Err(error) => Err(InterfaceCleanupError {
                error,
                interface: self,
            }),
        }
    }
}

/// Original persistent interface cleanup failed. It retains the exact original
/// name/index and control socket; retry never adopts a replacement interface.
/// Dropping this error abandons cleanup and closes only its control socket.
#[derive(Debug)]
#[must_use]
pub struct InterfaceCleanupError {
    error: io::Error,
    interface: InterfaceLease,
}
impl InterfaceCleanupError {
    /// Native error, detected identity mismatch, or explicitly deferred cleanup.
    #[must_use]
    pub const fn error(&self) -> &io::Error {
        &self.error
    }
    /// Last verified name of the original interface, including observed renames.
    ///
    /// # Errors
    /// Returns an error if the retained native name is unterminated or not UTF-8.
    pub fn interface_name(&self) -> io::Result<&str> {
        self.interface.name()
    }
    /// Original observed interface index, when creation reached that lookup.
    #[must_use]
    pub const fn interface_index(&self) -> Option<u32> {
        self.interface.index
    }
    /// Original persistent-interface selector, when marker installation reached
    /// successful readback. Retention/encoding alone does not checkpoint it.
    #[must_use]
    pub fn recovery_record(&self) -> Option<&crate::recovery::Record> {
        self.interface.recovery.as_deref()
    }
    /// Reconcile the same retained checkpoint after a failed write/sync. This
    /// performs no native interface operation and never repeats FD close.
    ///
    /// # Errors
    /// Preserves missing-checkpoint, file identity, format and I/O errors.
    pub fn reconcile_checkpoint(&mut self) -> io::Result<&crate::recovery::State> {
        self.interface
            .checkpoint
            .as_mut()
            .ok_or(io::ErrorKind::NotConnected)?
            .reconcile()
    }
    /// Retry only original interface cleanup, never a descriptor close. Native
    /// destruction may wait for independently duplicated descriptors to close.
    ///
    /// # Errors
    /// Returns the original interface owner with the new native error or detected
    /// identity mismatch. A replacement interface is never destroyed.
    pub fn retry(self) -> Result<(), Self> {
        self.interface.destroy()
    }
}
impl std::fmt::Display for InterfaceCleanupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.interface.name() {
            Ok(name) => write!(f, "created interface {name}"),
            Err(_) => write!(f, "created interface name {:?}", self.interface.name),
        }?;
        write!(f, " index {:?}: {}", self.interface.index, self.error)
    }
}
impl std::error::Error for InterfaceCleanupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

fn canonical_unit(name: &str) -> bool {
    crate::recovery::canonical_unit(name)
}

pub(crate) fn open_exclusive(desired: Option<&str>) -> io::Result<DeviceHandle> {
    attempt(desired, None).map_err(|cause| cause.into_parts().0)
}
pub(crate) fn open_recorded(
    desired: Option<&str>,
    birth: [u8; 32],
) -> Result<DeviceHandle, CreationFailure> {
    attempt(desired, Some(birth))
}
fn attempt(
    desired: Option<&str>,
    birth: Option<[u8; 32]>,
) -> Result<DeviceHandle, CreationFailure> {
    // Validate and reserve every caller-supplied native name before mutation.
    let desired_c = desired.map(name).transpose()?;
    let fib = process_fib()?;
    let clone = desired.filter(|name| canonical_unit(name)).unwrap_or("tun");
    let mut req = request(clone)?;
    let socket: OwnedFd = control_socket()?.into();
    ioctl(&socket, CREATE, &mut req).map_err(|error| {
        // A specific occupied unit fails alloc_unr_specific before cdev/ifnet
        // creation. Other creation errors retain their potentially unknown effect.
        if canonical_unit(clone) && error.raw_os_error() == Some(libc::EEXIST) {
            CreationFailure::Before(error)
        } else {
            CreationFailure::Unknown(error)
        }
    })?; // Native clone creation refuses existing units.
    let mut lease = InterfaceLease {
        socket,
        name: [0; libc::IFNAMSIZ],
        index: None,
        recovery: None,
        checkpoint: None,
        lifetime: Lifetime::Manual,
        retired: None,
    };
    lease.update(&req.ifr_name);
    let mut device = DeviceHandle::persistent(lease);
    let configured = (|| {
        let lease = device
            .interface
            .as_mut()
            .ok_or_else(|| invalid("missing created interface owner"))?;
        let created = lease.name()?.to_owned();
        lease.index = Some(index(&created)?);
        if let Some(birth) = birth {
            super::recovery::install_created(lease, &created, birth)?;
        }
        // Devfs keeps the original clone unit's device name across if_rename().
        let fd: OwnedFd = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW)
            .open(format!("/dev/{created}"))?
            .into();
        device.install_fd(fd);
        {
            let (fd, lease) = device.recovery_parts()?;
            super::recovery::check_created(fd, lease)?;
        }
        enable_header(device.fd()?)?;
        let info = verify(device.fd()?)?;
        let lease = device
            .interface
            .as_mut()
            .ok_or_else(|| invalid("missing created interface owner"))?;
        if info.name != created || Some(info.index) != lease.index {
            return Err(invalid("created TUN identity changed during open"));
        }
        if let Some(desired) = desired_c.as_ref()
            && desired.as_bytes() != created.as_bytes()
        {
            let mut rename = request(&created)?;
            rename.ifr_ifru.ifru_data = desired.as_ptr().cast_mut();
            ioctl(&lease.socket, RENAME, &mut rename)?;
            // A successful native rename is now part of this same owned identity.
            lease.name.fill(0);
            lease.name[..desired.as_bytes().len()].copy_from_slice(desired.as_bytes());
            if let Some(record) = &mut lease.recovery {
                record.name = lease.name;
            }
        }
        let info = verify(device.fd()?)?;
        let lease = device
            .interface
            .as_ref()
            .ok_or_else(|| invalid("missing created interface owner"))?;
        if info.name != lease.name()? || Some(info.index) != lease.index {
            return Err(invalid("created TUN identity changed after rename"));
        }
        // if_alloc() initializes if_fib=0, while tunwrite() uses that interface
        // FIB for injected packets. Set the freshly owned interface to the FIB
        // captured before creation; route qualification later reads it back.
        let mut req = request(&info.name)?;
        req.ifr_ifru.ifru_fib = fib;
        ioctl(&lease.socket, SET_FIB, &mut req)?;
        if get_fib(&lease.socket, &info.name)? != fib {
            return Err(invalid("created TUN FIB differs from the selected table"));
        }
        match set_int(device.fd()?, SET_TRANSIENT, 1) {
            Ok(()) => {
                if read_int(device.fd()?, GET_TRANSIENT)? != 1 {
                    return Err(invalid("kernel did not enable transient TUN lifetime"));
                }
                // The driver now owns deletion at final FD close. Keep that
                // responsibility with the FD, including any external duplicates.
                if birth.is_some() {
                    let (_, lease) = device.recovery_parts()?;
                    lease.lifetime = Lifetime::Transient;
                } else {
                    device.interface = None;
                }
            }
            Err(error) if error.raw_os_error() == Some(libc::ENOTTY) => {
                // FreeBSD 14 has no transient ioctl. This same fresh interface
                // remains owned by the explicit close-then-destroy lease.
                if birth.is_none() {
                    let (fd, lease) = device.recovery_parts()?;
                    super::recovery::install(fd, lease, &created, None)?;
                }
            }
            Err(error) => return Err(error),
        }
        Ok(())
    })();
    match configured {
        Ok(()) => Ok(device),
        Err(error) => match device.cleanup_after_setup(error) {
            Ok(error) => Err(CreationFailure::Reclaimed(error)),
            Err(cause) => Err(CreationFailure::Unknown(io::Error::new(
                cause.error().kind(),
                cause,
            ))),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clone_and_transient_abi_matches_native_headers() -> io::Result<()> {
        crate::native_abi::check(
            "freebsd_tun_lifetime_abi.c",
            &[
                CREATE,
                DESTROY,
                RENAME,
                SET_TRANSIENT,
                GET_TRANSIENT,
                std::mem::offset_of!(libc::ifreq, ifr_ifru) as u64,
                GET_FIB,
                SET_FIB,
            ],
        )
    }
    #[test]
    fn only_canonical_units_select_explicit_clone_creation() {
        assert!(canonical_unit("tun0"));
        assert!(canonical_unit("tun2147483647"));
        for name in [
            "tun",
            "tun01",
            "tun-1",
            "tun2147483648",
            "vpn-gnunet",
            "tap1",
        ] {
            assert!(!canonical_unit(name));
        }
    }
}
