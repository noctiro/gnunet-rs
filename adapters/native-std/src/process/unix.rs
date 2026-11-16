//! Retain original file-description leases in an explicitly selected child.
use std::{
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::process::CommandExt,
    },
    process::Command,
};

/// Effective user selected before a helper drops its parent's privileges.
/// This value grants no credentials: the kernel must still permit the child to
/// select that real or saved user. Group IDs and supplementary groups stay as
/// configured by the caller. The parent never changes identity during spawn.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
#[derive(Clone, Copy, Debug)]
pub struct EffectiveUser(libc::uid_t);

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
impl EffectiveUser {
    /// Capture the calling process's current effective user without name lookup.
    #[must_use]
    pub fn current() -> Self {
        Self(nix::unistd::geteuid().as_raw())
    }

    /// Select this effective user only in the forked child before exec.
    /// Use a fixed trusted executable and a cleared environment when retaining
    /// saved privilege. The helper's real user remains eligible to stop its
    /// original child; this does not perform a permanent `setuid` transition.
    ///
    /// # Errors
    /// Credential-selection failure is returned by the later command spawn.
    #[expect(
        unsafe_code,
        reason = "The selected BSD seteuid entry is a direct syscall; the child callback uses only a scalar ID and raw errno, without locks, allocation or parent identity changes"
    )]
    pub fn apply(self, command: &mut Command) {
        // SAFETY: these supported BSDs expose seteuid as a direct system call.
        // No allocation, formatting, lock, destructor or caller callback runs
        // between fork and exec. An errno-only error goes through spawn's
        // original error pipe; failure never executes the selected program.
        unsafe {
            command.pre_exec(move || {
                if libc::seteuid(self.0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
}

/// Inherit a duplicate sharing the original file description and its flock.
/// The child retains it across exec without changing parent descriptor flags.
/// No descriptor number or child-readiness receipt is returned. The selected
/// executable must retain the descriptor for the lifetime of guarded work.
/// Dropping command configuration closes only its parent-side duplicate.
///
/// # Errors
/// Returns failure to duplicate the original file. Child-side descriptor setup
/// failures are reported by the command's later `spawn` operation.
#[expect(
    unsafe_code,
    reason = "The owned fcntl duplicate stays live throughout spawn; the post-fork callback only uses async-signal-safe fcntl and raw errno capture"
)]
pub fn inherit_file(command: &mut Command, file: &File) -> io::Result<()> {
    let raw = nix::fcntl::fcntl(file, nix::fcntl::FcntlArg::F_DUPFD_CLOEXEC(3))?;
    // SAFETY: successful F_DUPFD_CLOEXEC returns one new owned descriptor above
    // stdio, with no other Rust owner. It shares the original open description.
    let inherited = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: the closure owns the duplicate throughout spawn. Only fcntl and
    // raw errno capture run after fork, without allocations, locks or borrowed
    // parent state. Clearing CLOEXEC in the child preserves its shared flock;
    // the original parent's CLOEXEC descriptor remains unchanged.
    unsafe {
        command.pre_exec(move || {
            let descriptor = inherited.as_raw_fd();
            let flags = libc::fcntl(descriptor, libc::F_GETFD);
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}
