//! Spawn the existing exec helper on Android API 24–27 as well as newer Bionic.
use super::duplicate_at_least;
use nix::{
    errno::Errno,
    sys::wait::{WaitStatus, waitpid},
    unistd::Pid,
};
use std::{
    ffi::{CStr, CString, OsStr},
    io::{self, Read},
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd},
        unix::ffi::OsStrExt,
    },
    ptr,
};

fn candidates(program: &CStr) -> io::Result<Vec<CString>> {
    if program.to_bytes().contains(&b'/') {
        return Ok(vec![program.to_owned()]);
    }
    #[expect(
        unsafe_code,
        reason = "Bionic's default PATH is a static terminated C string"
    )]
    // SAFETY: the libc constant points to an immutable terminated string.
    let default_path = unsafe { CStr::from_ptr(libc::_PATH_DEFPATH) };
    let search = std::env::var_os("PATH")
        .unwrap_or_else(|| OsStr::from_bytes(default_path.to_bytes()).to_owned());
    let program = OsStr::from_bytes(program.to_bytes());
    std::env::split_paths(&search)
        .map(|part| {
            CString::new(part.join(program).as_os_str().as_bytes()).map_err(io::Error::other)
        })
        .collect()
}

fn pointers(strings: &[CString]) -> Vec<*const libc::c_char> {
    strings
        .iter()
        .map(|value| value.as_ptr())
        .chain(std::iter::once(ptr::null()))
        .collect()
}

pub(crate) fn spawn(
    program: &CStr,
    argv: &[CString],
    env: &[CString],
    mappings: &[(BorrowedFd<'_>, i32)],
) -> io::Result<Pid> {
    if program.to_bytes().is_empty()
        || argv.is_empty()
        || mappings.iter().any(|(_, target)| *target < 0)
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let minimum = mappings
        .iter()
        .map(|(_, target)| *target)
        .max()
        .unwrap_or(2)
        .max(2)
        .checked_add(1)
        .ok_or(io::ErrorKind::InvalidInput)?;
    let candidates = candidates(program)?;
    let argv = pointers(argv);
    let env = pointers(env);
    let (mut reader, writer) = io::pipe()?;
    // The private failure writer cannot be overwritten by any user mapping.
    let error_fd = duplicate_at_least(writer.as_fd(), minimum)?;
    drop(writer);
    #[expect(
        unsafe_code,
        reason = "the child uses only async-signal-safe native calls before exec or _exit"
    )]
    // SAFETY: the child does not allocate, lock, or run Rust destructors.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        #[expect(
            unsafe_code,
            reason = "only the fork child may run the prepared exec plan"
        )]
        // SAFETY: all arrays and staged descriptors were prepared before fork.
        // The child closes its read end before applying any mapping.
        unsafe {
            libc::close(reader.as_raw_fd());
            exec_child(&candidates, &argv, &env, mappings, error_fd.as_raw_fd());
        }
    }
    let pid = Pid::from_raw(pid);
    drop(error_fd);
    let mut code = [0; std::mem::size_of::<libc::c_int>()];
    let failure = match reader.read_exact(&mut code[..1]) {
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(pid),
        result => result.and_then(|()| reader.read_exact(&mut code[1..])),
    };
    if failure.is_err() {
        drop(super::signal_original(pid, libc::SIGKILL));
    }
    // No PID is handed to the registry on failure; consume our original child.
    loop {
        match waitpid(pid, None) {
            Ok(WaitStatus::Exited(..) | WaitStatus::Signaled(..)) => break,
            Ok(_) | Err(Errno::EINTR) => continue,
            Err(error) => return Err(error.into()),
        }
    }
    failure?;
    Err(io::Error::from_raw_os_error(libc::c_int::from_ne_bytes(
        code,
    )))
}

#[expect(
    unsafe_code,
    reason = "only Bionic dup2, execve, errno, write and _exit run in the fork child"
)]
unsafe fn exec_child(
    candidates: &[CString],
    argv: &[*const libc::c_char],
    env: &[*const libc::c_char],
    mappings: &[(BorrowedFd<'_>, i32)],
    error_fd: libc::c_int,
) -> ! {
    // SAFETY: the caller supplies live, non-overlapping source/target mappings,
    // terminated argv/env, and its own reserved child error-pipe descriptor.
    let errno = unsafe {
        let mut errno = libc::ENOENT;
        'launch: {
            for (source, target) in mappings {
                if libc::dup2(source.as_raw_fd(), *target) < 0 {
                    errno = *libc::__errno();
                    break 'launch;
                }
            }
            for path in candidates {
                libc::execve(path.as_ptr(), argv.as_ptr(), env.as_ptr());
                match *libc::__errno() {
                    libc::EACCES => errno = libc::EACCES,
                    libc::ENOENT | libc::ENOTDIR => {}
                    error => {
                        errno = error;
                        break;
                    }
                }
            }
        }
        errno
    };
    let bytes = errno.to_ne_bytes();
    // SAFETY: a single errno fits within PIPE_BUF. The parent retains the
    // read end until it receives the record or the exec closes this writer.
    unsafe {
        while libc::write(error_fd, bytes.as_ptr().cast(), bytes.len()) < 0
            && *libc::__errno() == libc::EINTR
        {}
        libc::_exit(127);
    }
}
