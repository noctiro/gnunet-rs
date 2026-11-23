//! Kernel namespace identity on retained Linux sockets.
use std::{
    io,
    mem::size_of,
    num::NonZeroU64,
    os::fd::{AsRawFd, BorrowedFd},
};

/// Kernel network namespace cookie observed on an actual socket.
/// The original socket retains its namespace. This value identifies the
/// namespace and carries no device lifetime or socket delivery authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkNamespace(NonZeroU64);

impl NetworkNamespace {
    /// Read `SO_NETNS_COOKIE` from the original live socket.
    ///
    /// # Errors
    /// Preserves native errors, including kernels without the socket option,
    /// and refuses malformed or zero results.
    #[expect(
        unsafe_code,
        reason = "exact native u64 output and initialized length remain live during getsockopt"
    )]
    pub fn observe(socket: BorrowedFd<'_>) -> io::Result<Self> {
        let mut cookie = 0u64;
        let mut length = size_of::<u64>() as libc::socklen_t;
        // SAFETY: the borrowed socket and exact initialized output extents live through return.
        if unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NETNS_COOKIE,
                (&raw mut cookie).cast(),
                &raw mut length,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if length as usize != size_of::<u64>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Linux network namespace cookie length",
            ));
        }
        NonZeroU64::new(cookie).map(Self).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "zero Linux network namespace cookie",
            )
        })
    }

    /// Confirm that an actual observed socket namespace matches this one.
    ///
    /// # Errors
    /// Refuses a different network namespace.
    pub fn require(self, actual: Self) -> io::Result<()> {
        if self == actual {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "transparent DNS socket network namespace differs",
            ))
        }
    }

    #[cfg(test)]
    pub(super) const fn fixture(cookie: NonZeroU64) -> Self {
        Self(cookie)
    }
}
