//! Unix native descriptor qualification and physical interface ownership.
#[cfg(target_os = "freebsd")]
use crate::recovery;
use crate::{DeviceHandle, Epoch, Info, Limits, Stamp, platform, routes};
use std::{
    cell::Cell,
    io,
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd},
    rc::Rc,
};
/// One exclusively owned verified TUN FD. Drop closes it and retires its epoch.
/// Existing duplicated descriptors remain the caller's responsibility.
/// Persistent FreeBSD interfaces require explicit close for destruction.
#[derive(Debug)]
pub struct OwnedTun {
    pub(crate) handle: Option<DeviceHandle>,
    pub(crate) info: Info,
    pub(crate) limits: Limits,
    pub(crate) epoch: Epoch,
    pub(crate) next_effect: u64,
}
impl OwnedTun {
    /// Verify a transferred device handle while retaining its interface cleanup
    /// responsibility. Refusal closes it and preserves any independent cleanup
    /// error in DeviceSetupError. No externally supplied metadata is trusted.
    ///
    /// # Errors
    /// Returns the validation or native qualification error. When cleanup also
    /// fails, [DeviceSetupError](crate::DeviceSetupError) retains both failures and the remaining owner.
    pub fn from_handle(handle: DeviceHandle, limits: Limits) -> io::Result<Self> {
        let prepared = (|| {
            limits.validate()?;
            let fd = handle.fd()?;
            let info = platform::verify(fd)?;
            platform::nonblocking(fd)?;
            let table = routes::table(&info)?;
            Ok((info, table))
        })();
        let (info, route_table) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => return Err(handle.setup_error(error)),
        };
        Ok(Self {
            handle: Some(handle),
            info,
            limits,
            epoch: Epoch(Rc::new(Stamp {
                alive: Cell::new(true),
                route_table,
            })),
            next_effect: 0,
        })
    }
    /// Consume and validate an existing real native TUN descriptor. This adopts
    /// packet ownership, never another owner's persistent interface cleanup.
    ///
    /// # Errors
    /// Returns invalid limits, unsupported device/framing, or the original native
    /// verification error. The consumed descriptor is closed on refusal.
    pub fn from_fd(fd: OwnedFd, limits: Limits) -> io::Result<Self> {
        Self::from_handle(DeviceHandle::from_fd(fd), limits)
    }
    pub(crate) fn native_fd(&self) -> io::Result<&OwnedFd> {
        self.handle
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?
            .fd()
    }
    pub(crate) fn defer_interface_cleanup(&mut self) {
        if let Some(handle) = self.handle.as_mut() {
            handle.defer_interface_cleanup();
        }
    }
    pub(crate) fn setup_error(mut self, error: io::Error) -> io::Error {
        self.epoch.0.alive.set(false);
        match self.handle.take() {
            Some(handle) => handle.setup_error(error),
            None => error,
        }
    }
    /// Linux: open /dev/net/tun and issue the actual TUNSETIFF, without configuring
    /// addresses/routes. Name None requests kernel allocation; errors retain errno.
    #[cfg(target_os = "linux")]
    pub fn open_linux(
        name: Option<&str>,
        packet_information: bool,
        limits: Limits,
    ) -> io::Result<Self> {
        limits.validate()?;
        let fd = platform::open(name, packet_information)?;
        Self::from_fd(fd, limits)
    }
    /// Linux: create a nonpersistent TUN using TUNSETIFF with IFF_TUN_EXCL.
    /// A requested existing name is refused by the kernel; no name lookup or
    /// nonexclusive fallback can adopt another owner's interface. None requests
    /// a fresh kernel-selected name. Actual ioctl/open errno is preserved.
    #[cfg(target_os = "linux")]
    pub fn open_linux_exclusive(
        name: Option<&str>,
        packet_information: bool,
        limits: Limits,
    ) -> io::Result<Self> {
        limits.validate()?;
        let fd = platform::open_exclusive(name, packet_information)?;
        Self::from_fd(fd, limits)
    }
    /// macOS: connect the real utun kernel control; None requests a free unit,
    /// Some(n) requests utunN. It does not install an address or route.
    #[cfg(target_os = "macos")]
    pub fn open_utun(unit: Option<u32>, limits: Limits) -> io::Result<Self> {
        limits.validate()?;
        let fd = platform::open(unit)?;
        Self::from_fd(fd, limits)
    }
    /// FreeBSD: exclusively create a new TUN, optionally with an exact name.
    /// An existing requested unit/name is refused. Other names use a fresh clone
    /// followed by native rename. No addresses or routes are configured here.
    /// Interface administration/device access must be serialized by the caller.
    ///
    /// # Errors
    /// Returns invalid limits/names or native creation, open, rename, FIB or
    /// framing errors. [DeviceSetupError](crate::DeviceSetupError) retains independent cleanup failure.
    #[cfg(target_os = "freebsd")]
    pub fn open_freebsd_exclusive(name: Option<&str>, limits: Limits) -> io::Result<Self> {
        limits.validate()?;
        Self::from_handle(platform::open_exclusive(name)?, limits)
    }
    /// FreeBSD: provision through an original private recovery checkpoint.
    /// Saved native ownership is retired before another allocation. Outstanding
    /// allocation intents fence recreation. The checkpoint parent must already
    /// be private and device/interface administration must be serialized.
    ///
    /// # Errors
    /// Retains startup stage, original errors and checkpoint/cleanup ownership.
    #[cfg(target_os = "freebsd")]
    pub fn open_freebsd_recoverable(
        name: Option<&str>,
        checkpoint: &std::path::Path,
        limits: Limits,
    ) -> Result<Self, recovery::OpenError> {
        recovery::managed::open(name, checkpoint, limits)
    }
    /// FreeBSD: open an existing named TUN and enable its native family header.
    /// The interface must already exist. The caller must serialize interface
    /// creation/destruction across this open; observed replacement is refused.
    /// Close retires packet ownership and lets the kernel clear link/address
    /// state, but does not destroy the persistent FreeBSD interface. Interface
    /// creation/destruction remains with the caller's administrative owner.
    #[cfg(target_os = "freebsd")]
    pub fn open_freebsd_existing(name: &str, limits: Limits) -> io::Result<Self> {
        limits.validate()?;
        let fd = platform::open_existing(name)?;
        Self::from_fd(fd, limits)
    }
    /// Immutable actual device metadata.
    #[must_use]
    pub const fn info(&self) -> &Info {
        &self.info
    }
    /// Original persistent FreeBSD selector. Encoding is not a durable
    /// checkpoint and does not grant cleanup authority.
    #[cfg(target_os = "freebsd")]
    #[must_use]
    pub fn recovery_record(&self) -> Option<&recovery::Record> {
        self.handle.as_ref().and_then(DeviceHandle::recovery_record)
    }
    /// Original physical lifetime token.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.epoch.clone()
    }
    /// Close packet ownership and any owned interface lifetime. Independent
    /// failures remain in DeviceCleanupError; descriptor closes are never retried.
    ///
    /// # Errors
    /// Returns [DeviceCleanupError](crate::DeviceCleanupError) inside [`io::Error`] when native close or
    /// interface cleanup fails, or interface cleanup was explicitly deferred.
    pub fn close(mut self) -> io::Result<()> {
        self.epoch.0.alive.set(false);
        self.handle
            .take()
            .ok_or(io::ErrorKind::NotConnected)?
            .close()
    }
    /// Borrow the actual FD. Independent duplicates must close before a manually
    /// managed FreeBSD interface owner: native destruction can wait for open users.
    ///
    /// # Errors
    /// Returns NotConnected if the original descriptor is no longer retained.
    pub fn descriptor(&self) -> io::Result<BorrowedFd<'_>> {
        Ok(self.native_fd()?.as_fd())
    }
    /// Transfer the entire raw device owner, retiring old epoch/effect authority.
    /// The interface cleanup responsibility moves with its original descriptor.
    ///
    /// # Errors
    /// Returns NotConnected if the original device owner was already removed.
    pub fn into_handle(mut self) -> io::Result<DeviceHandle> {
        self.epoch.0.alive.set(false);
        self.handle.take().ok_or(io::ErrorKind::NotConnected.into())
    }
}
impl AsRawFd for OwnedTun {
    fn as_raw_fd(&self) -> RawFd {
        self.handle.as_ref().map_or(-1, AsRawFd::as_raw_fd)
    }
}
impl Drop for OwnedTun {
    fn drop(&mut self) {
        self.epoch.0.alive.set(false);
    }
}
