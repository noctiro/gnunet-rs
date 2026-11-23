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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
                } else {
                    let expected = self.index.ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "created FreeBSD TUN has no verified interface index",
                        )
                    })?;
                    match super::recovery::name_at_index(expected)? {
                        None => true,
                        Some(current) => {
                            if crate::recovery::read_name(&current)? != self.name()? {
                                return Err(invalid(
                                    "unmarked FreeBSD TUN changed its original name",
                                ));
                            }
                            false
                        }
                    }
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
    attempt(desired, None, process_fib()?).map_err(|cause| cause.into_parts().0)
}
pub(crate) fn open_recorded(
    desired: Option<&str>,
    birth: [u8; 32],
    fib: Option<u32>,
) -> Result<DeviceHandle, CreationFailure> {
    let fib = match fib {
        Some(fib) => fib,
        None => process_fib()?,
    };
    attempt(desired, Some(birth), fib)
}

fn confirm_transient(device: &mut DeviceHandle) -> io::Result<()> {
    let (fd, lease) = device.recovery_parts()?;
    // TUNSTRANSIENT has already transferred removal to the driver's final
    // close. Preserve that authority even if verification refuses publication.
    lease.lifetime = Lifetime::Transient;
    if read_int(fd, GET_TRANSIENT)? != 1 {
        return Err(invalid("kernel did not enable transient TUN lifetime"));
    }
    if lease.recovery.is_none() {
        device.interface = None;
    }
    Ok(())
}

fn attempt(
    desired: Option<&str>,
    birth: Option<[u8; 32]>,
    fib: u32,
) -> Result<DeviceHandle, CreationFailure> {
    // Validate and reserve every caller-supplied native name before mutation.
    let desired_c = desired.map(name).transpose()?;
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
        if birth.is_some() {
            // The active checkpoint owns destruction. Keep the interface
            // across a packet descriptor close, including on FreeBSD 15.
            let (fd, lease) = device.recovery_parts()?;
            lease.lifetime = super::recovery::observed_lifetime(fd)?;
            return if lease.lifetime == Lifetime::Manual {
                Ok(())
            } else {
                Err(invalid("checkpointed TUN did not retain manual lifetime"))
            };
        }
        match set_int(device.fd()?, SET_TRANSIENT, 1) {
            Ok(()) => confirm_transient(&mut device)?,
            Err(error) if error.raw_os_error() == Some(libc::ENOTTY) => {
                // FreeBSD 14 has no transient ioctl. This same fresh interface
                // remains owned by the explicit close-then-destroy lease.
                let (fd, lease) = device.recovery_parts()?;
                super::recovery::install(fd, lease, &created, None)?;
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

    #[test]
    fn a_failed_transient_readback_keeps_kernel_owned_removal() -> io::Result<()> {
        // An ordinary descriptor rejects the verification ioctl. No TUN is
        // needed to exercise the Rust transition after an admitted setter.
        let fd = || std::fs::File::open("/dev/null").map(OwnedFd::from);
        let mut device = DeviceHandle::persistent(InterfaceLease {
            socket: fd()?,
            name: [0; libc::IFNAMSIZ],
            index: None,
            recovery: None,
            checkpoint: None,
            lifetime: Lifetime::Manual,
            retired: None,
        });
        device.install_fd(fd()?);
        let expected = read_int(device.fd()?, GET_TRANSIENT)
            .err()
            .ok_or_else(|| io::Error::other("non-TUN descriptor accepted TUNGTRANSIENT"))?;
        let error = confirm_transient(&mut device)
            .err()
            .ok_or_else(|| io::Error::other("failed transient readback permitted publication"))?;
        if !matches!(
            device.interface.as_ref().map(|lease| lease.lifetime),
            Some(Lifetime::Transient)
        ) || error.raw_os_error() != expected.raw_os_error()
        {
            return Err(io::Error::other(
                "failed readback lost the transient retirement owner or native error",
            ));
        }
        Ok(())
    }

    #[test]
    fn unqualified_creation_retains_cleanup_without_destroy_by_name() -> io::Result<()> {
        let mut name = [0; libc::IFNAMSIZ];
        name[..5].copy_from_slice(b"tun42");
        let lease = InterfaceLease {
            socket: std::fs::File::open("/dev/null")?.into(),
            name,
            index: None,
            recovery: None,
            checkpoint: None,
            lifetime: Lifetime::Manual,
            retired: None,
        };
        let error = lease
            .destroy()
            .err()
            .ok_or_else(|| io::Error::other("unqualified TUN was treated as destroyed"))?;
        if error.error().kind() != io::ErrorKind::InvalidData
            || error.error().raw_os_error().is_some()
            || error.interface_name()? != "tun42"
            || error.interface_index().is_some()
        {
            return Err(io::Error::other(
                "cleanup did not retain the unqualified interface without a destroy ioctl",
            ));
        }
        Ok(())
    }
}
