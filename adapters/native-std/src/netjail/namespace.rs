//! Type-checked namespace descriptor ownership and joined worker entry.

use nix::{
    fcntl::{FcntlArg, FdFlag, fcntl},
    sched::{CloneFlags, setns, unshare},
    sys::statfs::{NSFS_MAGIC, fstatfs},
    unistd::{getegid, geteuid, getgid, getuid},
};
use std::{
    fs::{self, File},
    io,
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
    thread,
};

/// An original Linux network namespace pinned by a close-on-exec descriptor.
/// A lease keeps the namespace alive but grants no capabilities. Other live
/// descriptors, processes or sockets can independently retain the namespace.
#[derive(Debug)]
pub struct NetworkNamespace(OwnedFd);

impl NetworkNamespace {
    /// Hold the calling thread's current network namespace.
    ///
    /// # Errors
    /// Preserves procfs open and native namespace-type errors.
    pub fn current() -> io::Result<Self> {
        Self::try_from(OwnedFd::from(File::open("/proc/thread-self/ns/net")?))
    }
}

impl AsFd for NetworkNamespace {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl TryFrom<OwnedFd> for NetworkNamespace {
    type Error = io::Error;

    /// Consume an nsfs descriptor and check its namespace type in the kernel.
    /// Set close-on-exec if the transferred descriptor was inheritable.
    #[expect(
        unsafe_code,
        reason = "The namespace type ioctl borrows a live descriptor and takes no output buffer"
    )]
    fn try_from(fd: OwnedFd) -> io::Result<Self> {
        let flags = FdFlag::from_bits_retain(fcntl(&fd, FcntlArg::F_GETFD)?);
        if !flags.contains(FdFlag::FD_CLOEXEC) {
            fcntl(&fd, FcntlArg::F_SETFD(flags | FdFlag::FD_CLOEXEC))?;
        }
        if fstatfs(&fd)?.filesystem_type() != NSFS_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Linux nsfs descriptor required",
            ));
        }
        // SAFETY: NS_GET_NSTYPE takes no pointer and the descriptor stays live.
        let kind = unsafe { libc::ioctl(fd.as_raw_fd(), libc::NS_GET_NSTYPE) };
        if kind < 0 {
            return Err(io::Error::last_os_error());
        }
        if kind != libc::CLONE_NEWNET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Linux network namespace descriptor required",
            ));
        }
        Ok(Self(fd))
    }
}

/// An original, newly created network namespace for a TESTING fixture.
/// Only private namespace leases can authorize native topology mutations.
#[derive(Debug)]
pub struct PrivateNetworkNamespace(NetworkNamespace);

impl PrivateNetworkNamespace {
    /// Create a fresh namespace within the current user namespace on a joined
    /// worker. The caller keeps its own network namespace.
    ///
    /// # Errors
    /// Preserves worker start, capability, namespace creation and descriptor errors.
    pub fn create() -> io::Result<Self> {
        on_worker(|| {
            unshare(CloneFlags::CLONE_NEWNET)?;
            NetworkNamespace::current().map(Self)
        })
    }

    /// Run `work` in the original private namespace on a joined worker.
    /// New sockets and subprocesses inherit this network namespace.
    ///
    /// # Errors
    /// Preserves worker start and namespace-entry errors. `work` runs only
    /// after entry succeeds. A worker panic is returned as an I/O error.
    pub fn with_worker<T: Send>(
        &self,
        work: impl FnOnce() -> io::Result<T> + Send,
    ) -> io::Result<T> {
        on_worker(|| {
            setns(self, CloneFlags::CLONE_NEWNET)?;
            work()
        })
    }
}

impl AsFd for PrivateNetworkNamespace {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

/// Enter a fresh user namespace mapping only the launcher's current user and
/// primary group. Call in a dedicated launcher before starting any threads.
/// The kernel enforces the single-thread requirement for this transition.
///
/// # Errors
/// Preserves the kernel's namespace and mapping errors. A failure after the
/// namespace transition may leave mappings incomplete. The launcher should
/// report the failure and exit its original process.
pub fn enter_fixture_user_namespace() -> io::Result<()> {
    let user = getuid();
    let group = getgid();
    if user != geteuid() || group != getegid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "netjail user namespace requires matching real and effective identities",
        ));
    }
    unshare(CloneFlags::CLONE_NEWUSER)?;
    fs::write("/proc/self/setgroups", b"deny\n")?;
    fs::write("/proc/self/uid_map", format!("0 {user} 1\n"))?;
    fs::write("/proc/self/gid_map", format!("0 {group} 1\n"))?;
    Ok(())
}

fn on_worker<T: Send>(work: impl FnOnce() -> io::Result<T> + Send) -> io::Result<T> {
    thread::scope(|scope| {
        thread::Builder::new()
            .spawn_scoped(scope, work)?
            .join()
            .map_err(|_| io::Error::other("network namespace worker panicked"))?
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions check original procfs namespace identity and descriptor validation"
    )]
    fn captured_lease_tracks_the_calling_thread_and_refuses_other_namespace_types() -> io::Result<()>
    {
        let current = NetworkNamespace::current()?;
        let duplicate = File::from(current.as_fd().try_clone_to_owned()?);
        let expected = File::open("/proc/thread-self/ns/net")?.metadata()?;
        let actual = duplicate.metadata()?;
        assert_eq!(
            (actual.dev(), actual.ino()),
            (expected.dev(), expected.ino())
        );
        for path in ["/proc/thread-self/ns/mnt", "/dev/null"] {
            let other = OwnedFd::from(File::open(path)?);
            let refusal = NetworkNamespace::try_from(other).err();
            assert_eq!(
                refusal.as_ref().map(io::Error::kind),
                Some(io::ErrorKind::InvalidInput)
            );
        }
        Ok(())
    }
}
