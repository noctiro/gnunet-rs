//! Small checked POSIX spawn boundary; no GNUnet C code is linked.
use nix::unistd::Pid;
use std::{
    ffi::CStr,
    io,
    mem::MaybeUninit,
    os::fd::{AsRawFd, BorrowedFd},
};
fn status(code: libc::c_int) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else if code > 0 {
        Err(io::Error::from_raw_os_error(code))
    } else {
        Err(io::Error::last_os_error())
    }
}
struct Actions(libc::posix_spawn_file_actions_t);
impl Actions {
    #[expect(
        unsafe_code,
        reason = "POSIX initializes the opaque object only on return0; no uninitialized object is read or destroyed on an error"
    )]
    fn new() -> io::Result<Self> {
        let mut actions = MaybeUninit::uninit();
        // SAFETY: the out pointer names aligned writable uninitialized storage;
        // POSIX success0 initializes it. Positive errors must not assume_init.
        status(unsafe { libc::posix_spawn_file_actions_init(actions.as_mut_ptr()) })?;
        // SAFETY: the preceding initializer returned exactly0, establishing init.
        Ok(Self(unsafe { actions.assume_init() }))
    }
    #[expect(
        unsafe_code,
        reason = "A live borrowed source FD and a nonnegative child target are recorded in an initialized opaque action object, with positive POSIX errors checked"
    )]
    fn duplicate(&mut self, source: BorrowedFd<'_>, target: i32) -> io::Result<()> {
        if target < 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // SAFETY: self owns the initialized action list, source remains open
        // through spawn, and this records actions for the child only.
        status(unsafe {
            libc::posix_spawn_file_actions_adddup2(&mut self.0, source.as_raw_fd(), target)
        })
    }
}
impl Drop for Actions {
    #[expect(
        unsafe_code,
        reason = "Only a successfully initialized exclusively owned action list reaches Drop, and it is destroyed exactly once"
    )]
    fn drop(&mut self) {
        // SAFETY: self was constructed only after initializer success0; no
        // actions/spawn operation may still borrow it when Drop is invoked.
        let _ = unsafe { libc::posix_spawn_file_actions_destroy(&mut self.0) };
    }
}
#[expect(
    unsafe_code,
    reason = "Checked POSIX spawn consumes only live CString arrays and initialized RAII file actions; the kernel creates a separate child, with no raw FD owner construction"
)]
pub(crate) fn spawn(
    program: &CStr,
    argv: &[std::ffi::CString],
    env: &[std::ffi::CString],
    mappings: &[(BorrowedFd<'_>, i32)],
) -> io::Result<Pid> {
    if argv.is_empty() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut actions = Actions::new()?;
    for (source, target) in mappings {
        actions.duplicate(*source, *target)?;
    }
    let mut args: Vec<_> = argv.iter().map(|s| s.as_ptr().cast_mut()).collect();
    args.push(std::ptr::null_mut());
    let mut environment: Vec<_> = env.iter().map(|s| s.as_ptr().cast_mut()).collect();
    environment.push(std::ptr::null_mut());
    let mut pid = 0;
    // SAFETY: all CStr/CString allocations and their NULL-terminated pointer
    // arrays remain live and immutable for this call. POSIX does not modify
    // their bytes. actions is initialized/exclusively borrowed; NULL attributes
    // select inherited/default process attributes. Borrowed source FDs stay
    // owned by the caller throughout the call. No parent FD or env is mutated.
    status(unsafe {
        libc::posix_spawnp(
            &mut pid,
            program.as_ptr(),
            &actions.0,
            std::ptr::null(),
            args.as_ptr(),
            environment.as_ptr(),
        )
    })?;
    if pid <= 0 {
        return Err(io::Error::other(
            "POSIX spawn success returned invalid child PID",
        ));
    }
    Ok(Pid::from_raw(pid))
}
/// Read only the spawning thread/process's native SIGPIPE inheritance class.
/// C exec preserves IGN and resets caught handlers to default; no handler/mask
/// is changed in the parent. The caller serializes process-wide signal changes
/// with launch, as in the original single-threaded GNUnet scheduler profile.
#[expect(
    unsafe_code,
    reason = "A NULL new-action pointer makes sigaction read-only; initialized native output is inspected only after success0"
)]
pub(crate) fn inherited_pipe_ignore() -> io::Result<bool> {
    let mut action = MaybeUninit::<libc::sigaction>::uninit();
    // SAFETY: the output points at writable aligned storage; a NULL action
    // queries current disposition without installing/changing a parent handler.
    let result = unsafe { libc::sigaction(libc::SIGPIPE, std::ptr::null(), action.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful sigaction initialized the returned native structure.
    Ok(unsafe { action.assume_init() }.sa_sigaction == libc::SIG_IGN)
}
/// Replace only the fresh helper process with the original native argv, restoring
/// its sampled inherited SIGPIPE class after Rust's own entry initialization.
#[expect(
    unsafe_code,
    reason = "Only the explicit exec helper calls this boundary: it owns live CString argument storage, restores its own signal action, then uses the same execvp as upstream"
)]
pub(crate) unsafe fn exec_original(
    filename: &CStr,
    argv: &[std::ffi::CString],
    pipe_ignore: bool,
    closed_stdio: u8,
) -> io::Error {
    let mut pointers: Vec<_> = argv.iter().map(|arg| arg.as_ptr()).collect();
    pointers.push(std::ptr::null());
    // SAFETY: all fields of the native C sigaction are integer/pointer/sigset
    // storage admitting zero; sigemptyset initializes the platform signal mask.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: writable native sigset storage; this does not change signal mask.
    if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0 {
        return io::Error::last_os_error();
    }
    action.sa_sigaction = if pipe_ignore {
        libc::SIG_IGN
    } else {
        libc::SIG_DFL
    };
    // SAFETY: an initialized native action restores only this fresh helper's
    // SIGPIPE state. It never changes the original parent process or its mask.
    if unsafe { libc::sigaction(libc::SIGPIPE, &action, std::ptr::null_mut()) } != 0 {
        return io::Error::last_os_error();
    }
    for fd in 0..3 {
        if closed_stdio & (1 << fd) != 0 {
            // SAFETY: the explicit fresh-helper contract guarantees no Rust
            // owner for stdio slots; this restores only originally closed/CLO
            // inherited stdio after Rust entry may have filled it with null.
            let result = unsafe { libc::close(fd) };
            if result != 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::EBADF) {
                    return error;
                }
            }
        }
    }
    // SAFETY: each CString plus the trailing NULL array remains live/immutable
    // through execvp. Success replaces this process; failure returns errno. No
    // Rust Command layer may silently reset the deliberately preserved SIGPIPE.
    unsafe { libc::execvp(filename.as_ptr(), pointers.as_ptr()) };
    io::Error::last_os_error()
}

/// Duplicate one live owned resource to a fresh descriptor above stdio, without
/// clearing flags or stealing the original owner's FD.
#[expect(
    unsafe_code,
    reason = "F_DUPFD_CLOEXEC creates a fresh unique descriptor above the checked minimum; only that fresh successful return is adopted as OwnedFd"
)]
pub(crate) fn duplicate_at_least(
    source: BorrowedFd<'_>,
    minimum: i32,
) -> io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    // SAFETY: integer fcntl command consumes a live borrowed source and checked positive minimum;
    // success creates new exclusive ownership with CLOEXEC already set.
    let fresh = unsafe { libc::fcntl(source.as_raw_fd(), libc::F_DUPFD_CLOEXEC, minimum) };
    if fresh < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the OS returned a fresh valid uniquely owned descriptor.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fresh) })
}
pub(crate) fn lift(fd: std::os::fd::OwnedFd) -> io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::AsFd;
    if fd.as_raw_fd() >= 3 {
        Ok(fd)
    } else {
        let moved = duplicate_at_least(fd.as_fd(), 3)?;
        drop(fd);
        Ok(moved)
    }
}
/// Inherited stdio that native exec must leave closed, sampled before a new pipe
/// or null handle can occupy an originally closed standard slot.
#[expect(
    unsafe_code,
    reason = "F_GETFD is a read-only integer operation accepting EBADF; it never creates borrowed/owning Rust handles for closed stdio"
)]
pub(crate) fn inherited_closed_stdio(inherit: u32) -> io::Result<u8> {
    let mut mask = 0u8;
    for fd in 0..3 {
        if inherit & (1 << fd) == 0 {
            continue;
        }
        // SAFETY: integer-only query; invalid/closed descriptors report errno.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EBADF) {
                mask |= 1 << fd;
            } else {
                return Err(error);
            }
        } else if flags & libc::FD_CLOEXEC != 0 {
            mask |= 1 << fd;
        }
    }
    Ok(mask)
}
/// Issue the native integer signal only for a registry-validated original PID.
#[expect(
    unsafe_code,
    reason = "The caller retains exclusive original unreaped PID authority; kill consumes only the checked PID and raw signal integer, with errno preserved"
)]
pub(crate) fn signal_original(pid: Pid, signal: i32) -> io::Result<()> {
    // SAFETY: no pointers or owning descriptor transfers are involved; the
    // exclusive registry contract prevents numeric PID reuse before actual reap.
    if unsafe { libc::kill(pid.as_raw(), signal) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Consuming nonblocking wait for this registry's positive original PID.
#[expect(
    unsafe_code,
    reason = "A checked positive original PID selects one exclusively owned child; initialized status storage is read only after that exact PID returns"
)]
pub(crate) fn wait_original_status(pid: Pid) -> io::Result<Option<libc::c_int>> {
    if pid.as_raw() <= 0 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut status = 0;
    // SAFETY: status is aligned writable storage, and the positive PID names
    // only the caller's exclusively owned original unreaped child.
    let observed = unsafe { libc::waitpid(pid.as_raw(), &mut status, libc::WNOHANG) };
    if observed == -1 {
        Err(io::Error::last_os_error())
    } else if observed == 0 {
        Ok(None)
    } else if observed == pid.as_raw() {
        Ok(Some(status))
    } else {
        Err(io::Error::other("waitpid returned a foreign child"))
    }
}

pub(crate) struct WaitUsage {
    pub(crate) status: libc::c_int,
    pub(crate) resources: Option<libc::rusage>,
}
/// Consuming nonblocking wait for one registry-owned positive original PID.
#[expect(
    unsafe_code,
    reason = "Only an exclusive registry-owned original PID is waited; output storage is read solely after that positive PID's successful wait4 return"
)]
pub(crate) fn wait_original_usage(pid: Pid) -> io::Result<Option<WaitUsage>> {
    if pid.as_raw() <= 0 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut status = 0;
    let mut resources = MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: both output pointers name aligned writable storage for the call.
    // The positive PID selects only this registry's original child; the caller
    // retains exclusive wait authority and never requests process-group waits.
    let observed = unsafe {
        libc::wait4(
            pid.as_raw(),
            &mut status,
            libc::WNOHANG,
            resources.as_mut_ptr(),
        )
    };
    if observed == -1 {
        return Err(io::Error::last_os_error());
    }
    if observed == 0 {
        return Ok(None);
    }
    if observed != pid.as_raw() {
        return Err(io::Error::other("wait4 returned a foreign child"));
    }
    // Ignore any nonterminal status without reading resource storage. Resource
    // observations belong only to this original child's consuming terminal wait.
    let resources = if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
        // SAFETY: successful terminal wait4 for the requested positive PID
        // initialized its resource record. Other statuses never read the storage.
        Some(unsafe { resources.assume_init() })
    } else {
        None
    };
    Ok(Some(WaitUsage { status, resources }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn positive_posix_errno_is_never_success() {
        assert!(super::status(0).is_ok());
        assert_eq!(
            super::status(libc::EBADF)
                .err()
                .and_then(|e| e.raw_os_error()),
            Some(libc::EBADF)
        );
        assert_eq!(
            super::status(libc::ENOMEM)
                .err()
                .and_then(|e| e.raw_os_error()),
            Some(libc::ENOMEM)
        );
    }
}
