//! Raw device ownership, including native interface lifetime responsibilities.
use std::{
    io,
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd},
};
#[cfg(target_os = "freebsd")]
#[derive(Clone, Copy, Debug)]
enum InterfaceClose {
    Destroy,
    Defer,
}

/// One native descriptor and its interface cleanup responsibility. Transferring
/// this owner never leaves a persistent interface's cleanup attached elsewhere.
/// Close all independently duplicated descriptors before closing a manually
/// managed FreeBSD device: native interface destruction can wait for open users.
/// Explicit close is required for persistent interface destruction; Drop only
/// releases native descriptors and never waits for other device users.
#[derive(Debug)]
#[must_use]
pub struct DeviceHandle {
    fd: Option<OwnedFd>,
    #[cfg(target_os = "freebsd")]
    pub(crate) interface: Option<crate::platform::InterfaceLease>,
    #[cfg(target_os = "freebsd")]
    interface_close: InterfaceClose,
}
impl DeviceHandle {
    #[cfg(target_os = "freebsd")]
    pub(crate) fn recovery_parts(
        &mut self,
    ) -> io::Result<(&OwnedFd, &mut crate::platform::InterfaceLease)> {
        Ok((
            self.fd.as_ref().ok_or(io::ErrorKind::NotConnected)?,
            self.interface.as_mut().ok_or(io::ErrorKind::NotConnected)?,
        ))
    }
    /// Original persistent FreeBSD selector. Persist it privately and durably
    /// before packet use when restart recovery is required. Transient and
    /// externally owned interfaces have no recovery selector.
    #[cfg(target_os = "freebsd")]
    #[must_use]
    pub fn recovery_record(&self) -> Option<&crate::recovery::Record> {
        self.interface
            .as_ref()
            .and_then(|lease| lease.recovery.as_deref())
    }

    #[cfg(target_os = "freebsd")]
    pub(crate) fn persistent(interface: crate::platform::InterfaceLease) -> Self {
        Self {
            fd: None,
            interface: Some(interface),
            interface_close: InterfaceClose::Destroy,
        }
    }
    #[cfg(target_os = "freebsd")]
    pub(crate) fn install_fd(&mut self, fd: OwnedFd) {
        self.fd = Some(fd);
    }
    pub(crate) fn from_fd(fd: OwnedFd) -> Self {
        Self {
            fd: Some(fd),
            #[cfg(target_os = "freebsd")]
            interface: None,
            #[cfg(target_os = "freebsd")]
            interface_close: InterfaceClose::Destroy,
        }
    }
    pub(crate) fn fd(&self) -> io::Result<&OwnedFd> {
        self.fd.as_ref().ok_or(io::ErrorKind::NotConnected.into())
    }
    #[cfg(target_os = "freebsd")]
    pub(crate) fn close_packet_fd(&mut self) -> io::Result<()> {
        self.fd
            .take()
            .map_or(Ok(()), |fd| nix::unistd::close(fd).map_err(Into::into))
    }
    pub(crate) fn defer_interface_cleanup(&mut self) {
        #[cfg(target_os = "freebsd")]
        {
            self.interface_close = InterfaceClose::Defer;
        }
    }
    /// Whether this owner retains interface cleanup after closing the descriptor.
    /// A tracked FreeBSD transient interface observes the driver's final-close
    /// removal. A manual interface requires explicit destruction.
    #[must_use]
    pub const fn requires_interface_cleanup(&self) -> bool {
        #[cfg(target_os = "freebsd")]
        {
            self.interface.is_some()
        }
        #[cfg(not(target_os = "freebsd"))]
        {
            false
        }
    }
    /// Extract the FD only when this owner has no separate interface cleanup.
    ///
    /// # Errors
    /// Returns the unchanged owner in [`IntoFdError`] when separate interface
    /// cleanup is required. No resource is closed on refusal.
    pub fn try_into_fd(mut self) -> Result<OwnedFd, IntoFdError> {
        if self.requires_interface_cleanup() {
            return Err(IntoFdError { handle: self });
        }
        match self.fd.take() {
            Some(fd) => Ok(fd),
            None => Err(IntoFdError { handle: self }),
        }
    }
    /// One FD close, then any required original interface destruction. Failure
    /// retains independent errors in DeviceCleanupError. No FD close is retried.
    ///
    /// # Errors
    /// Returns an [`io::Error`] containing [`DeviceCleanupError`] on descriptor
    /// or interface cleanup failure. Interface cleanup can be retried through
    /// its retained owner; a descriptor close is never retried.
    pub fn close(mut self) -> io::Result<()> {
        self.close_inner()
    }
    #[cfg(target_os = "freebsd")]
    pub(crate) fn retire(mut self) -> io::Result<Option<crate::recovery::Journal>> {
        self.retire_inner()
    }
    #[cfg(target_os = "freebsd")]
    fn close_inner(&mut self) -> io::Result<()> {
        self.retire_inner().map(drop)
    }
    #[cfg(not(target_os = "freebsd"))]
    fn close_inner(&mut self) -> io::Result<()> {
        self.fd.take().map_or(Ok(()), |fd| {
            nix::unistd::close(fd).map_err(|error| {
                let cause = DeviceCleanupError::Descriptor(error.into());
                io::Error::new(cause.primary().kind(), cause)
            })
        })
    }
    #[cfg(target_os = "freebsd")]
    fn retire_inner(&mut self) -> io::Result<Option<crate::recovery::Journal>> {
        let fd_error = self.close_packet_fd().err();
        let interface = match self.interface.take() {
            Some(owner) => match self.interface_close {
                InterfaceClose::Destroy => owner.retire(),
                InterfaceClose::Defer => Err(owner.deferred()),
            },
            None => Ok(None),
        };
        let error = match (fd_error, interface) {
            (None, Ok(checkpoint)) => return Ok(checkpoint),
            (Some(fd), Ok(_)) => DeviceCleanupError::Descriptor(fd),
            (None, Err(interface)) => DeviceCleanupError::Interface(interface),
            (Some(fd), Err(interface)) => DeviceCleanupError::Both { fd, interface },
        };
        Err(io::Error::new(error.primary().kind(), error))
    }
    pub(crate) fn setup_error(self, error: io::Error) -> io::Error {
        match self.cleanup_after_setup(error) {
            Ok(error) => error,
            Err(cause) => io::Error::new(cause.error().kind(), cause),
        }
    }
    pub(crate) fn cleanup_after_setup(
        self,
        error: io::Error,
    ) -> Result<io::Error, DeviceSetupError> {
        match self.close() {
            Ok(()) => Ok(error),
            Err(cleanup) => Err(DeviceSetupError { error, cleanup }),
        }
    }
}
impl AsFd for DeviceHandle {
    #[expect(
        clippy::expect_used,
        reason = "A live public handle always owns its FD; close/extraction consume it, and only private finalization can empty it"
    )]
    fn as_fd(&self) -> BorrowedFd<'_> {
        // A live public DeviceHandle always owns an FD. close/try_into_fd consume
        // it, and the empty state exists only during its private finalization.
        self.fd.as_ref().expect("live device handle").as_fd()
    }
}
impl AsRawFd for DeviceHandle {
    fn as_raw_fd(&self) -> RawFd {
        self.as_fd().as_raw_fd()
    }
}
impl Drop for DeviceHandle {
    fn drop(&mut self) {
        // SIOCIFDESTROY can wait for other open references. Only explicit close
        // may perform that operation; ordinary descriptor release follows here.
        // The remaining control socket is released with the fields, without an
        // implicit interface-destruction attempt or retry.
        drop(self.fd.take());
    }
}

/// FD extraction was refused; the original complete device owner remains live.
#[derive(Debug)]
#[must_use]
pub struct IntoFdError {
    handle: DeviceHandle,
}
impl IntoFdError {
    /// Recover the unchanged owner, including its interface cleanup obligation.
    pub fn into_handle(self) -> DeviceHandle {
        self.handle
    }
}
impl std::fmt::Display for IntoFdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("device descriptor cannot be separated from its interface cleanup")
    }
}
impl std::error::Error for IntoFdError {}

/// Independent failures or deferred cleanup from one device close. A retained interface error
/// also owns the remaining explicit cleanup capability; its retry is caller-led.
#[derive(Debug)]
#[non_exhaustive]
#[must_use]
pub enum DeviceCleanupError {
    /// Only the original descriptor close failed.
    Descriptor(io::Error),
    /// Only persistent interface destruction failed.
    #[cfg(target_os = "freebsd")]
    Interface(crate::InterfaceCleanupError),
    /// Both independent native operations failed.
    #[cfg(target_os = "freebsd")]
    Both {
        /// Original descriptor close error.
        fd: io::Error,
        /// Original interface cleanup error and its remaining owner.
        interface: crate::InterfaceCleanupError,
    },
}
impl DeviceCleanupError {
    /// Original FD close error, if the native close failed.
    #[must_use]
    pub const fn fd_error(&self) -> Option<&io::Error> {
        match self {
            Self::Descriptor(error) => Some(error),
            #[cfg(target_os = "freebsd")]
            Self::Both { fd, .. } => Some(fd),
            #[cfg(target_os = "freebsd")]
            Self::Interface(_) => None,
        }
    }
    /// Original interface destruction error and its retained cleanup capability.
    #[cfg(target_os = "freebsd")]
    #[must_use]
    pub const fn interface_error(&self) -> Option<&crate::InterfaceCleanupError> {
        match self {
            Self::Interface(error)
            | Self::Both {
                interface: error, ..
            } => Some(error),
            Self::Descriptor(_) => None,
        }
    }
    /// Recover both independent errors without retrying either operation.
    #[cfg(target_os = "freebsd")]
    #[must_use]
    pub fn into_parts(self) -> (Option<io::Error>, Option<crate::InterfaceCleanupError>) {
        match self {
            Self::Descriptor(error) => (Some(error), None),
            Self::Interface(error) => (None, Some(error)),
            Self::Both { fd, interface } => (Some(fd), Some(interface)),
        }
    }
    fn primary(&self) -> &io::Error {
        match self {
            Self::Descriptor(error) => error,
            #[cfg(target_os = "freebsd")]
            Self::Both { fd, .. } => fd,
            #[cfg(target_os = "freebsd")]
            Self::Interface(error) => error.error(),
        }
    }
}
impl std::fmt::Display for DeviceCleanupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Descriptor(error) => write!(f, "native descriptor close: {error}"),
            #[cfg(target_os = "freebsd")]
            Self::Interface(error) => write!(f, "native device cleanup: {error}"),
            #[cfg(target_os = "freebsd")]
            Self::Both { fd, interface } => write!(f, "native descriptor close: {fd}; {interface}"),
        }
    }
}
impl std::error::Error for DeviceCleanupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.primary())
    }
}

/// Setup failed and an independent cleanup also failed. The original error and
/// the remaining cleanup capability are retained rather than claiming rollback.
#[derive(Debug)]
#[must_use]
pub struct DeviceSetupError {
    error: io::Error,
    cleanup: io::Error,
}
impl DeviceSetupError {
    /// Original setup error.
    #[must_use]
    pub const fn error(&self) -> &io::Error {
        &self.error
    }
    /// Independent cleanup error, including DeviceCleanupError when applicable.
    #[must_use]
    pub const fn cleanup(&self) -> &io::Error {
        &self.cleanup
    }
    /// Recover setup and cleanup errors, including any explicit cleanup owner.
    #[must_use]
    pub fn into_parts(self) -> (io::Error, io::Error) {
        (self.error, self.cleanup)
    }
}
impl std::fmt::Display for DeviceSetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "device setup: {}", self.error)?;
        write!(f, "; cleanup: {}", self.cleanup)
    }
}
impl std::error::Error for DeviceSetupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

const _: () = {
    const fn error_contract<T: std::error::Error + Send + Sync + 'static>() {}
    error_contract::<IntoFdError>();
    error_contract::<DeviceCleanupError>();
    error_contract::<DeviceSetupError>();
};

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Check actual raw-owner transfer, peer EOF and refusal without manufacturing a qualified TUN"
    )]
    use super::*;
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
        time::Duration,
    };

    #[test]
    fn descriptor_transfer_keeps_the_original_endpoint_live() -> io::Result<()> {
        let (left, mut peer) = UnixStream::pair()?;
        peer.set_read_timeout(Some(Duration::from_secs(1)))?;
        // Private FD ownership model only; no native TUN qualification occurs.
        let epoch = crate::Epoch(std::rc::Rc::new(crate::Stamp {
            alive: std::cell::Cell::new(true),
            route_table: None,
        }));
        let owned = crate::OwnedTun {
            handle: Some(DeviceHandle::from_fd(left.into())),
            info: crate::Info {
                name: "controlled-transfer".into(),
                index: 0,
                mode: crate::Mode::RawIp,
            },
            limits: crate::Limits::default(),
            epoch: epoch.clone(),
            next_effect: 0,
        };
        let handle = owned.into_handle()?;
        assert!(!epoch.current());
        assert!(!handle.requires_interface_cleanup());
        let fd = handle
            .try_into_fd()
            .map_err(|_| io::Error::other("ordinary descriptor transfer refused"))?;
        let mut original = std::fs::File::from(fd);
        original.write_all(b"original")?;
        let mut bytes = [0; 8];
        peer.read_exact(&mut bytes)?;
        assert_eq!(&bytes, b"original");
        drop(original);
        assert_eq!(peer.read(&mut bytes)?, 0);
        Ok(())
    }
    #[test]
    fn failed_qualification_closes_only_its_consumed_endpoint() -> io::Result<()> {
        let (left, mut peer) = UnixStream::pair()?;
        peer.set_read_timeout(Some(Duration::from_secs(1)))?;
        let handle = DeviceHandle::from_fd(left.into());
        assert!(crate::OwnedTun::from_handle(handle, crate::Limits::default()).is_err());
        assert_eq!(peer.read(&mut [0])?, 0);
        Ok(())
    }
    #[test]
    fn no_runtime_failure_retires_and_closes_the_controlled_owner() -> io::Result<()> {
        let (left, mut peer) = UnixStream::pair()?;
        peer.set_read_timeout(Some(Duration::from_secs(1)))?;
        // Only a private ownership model, not a qualified native device.
        let epoch = crate::Epoch(std::rc::Rc::new(crate::Stamp {
            alive: std::cell::Cell::new(true),
            route_table: None,
        }));
        let owned = crate::OwnedTun {
            handle: Some(DeviceHandle::from_fd(left.into())),
            info: crate::Info {
                name: "controlled-owner".into(),
                index: 0,
                mode: crate::Mode::RawIp,
            },
            limits: crate::Limits::default(),
            epoch: epoch.clone(),
            next_effect: 0,
        };
        assert!(crate::AsyncTun::new(owned).is_err());
        assert!(!epoch.current());
        assert_eq!(peer.read(&mut [0])?, 0);
        Ok(())
    }
}
