//! Source-shaped initialization of an already accepted uniquely owned stream.
//! This borrowed native boundary never accepts, closes or substitutes the fd.
//! The owning caller must close it on a fatal result. No libgnunet FFI is used.
use std::{
    fmt, io,
    os::fd::{AsRawFd, BorrowedFd},
};
/// Actual transport kind supplied by the accepting layer, not a wire flag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamKind {
    /// Non-Unix TCP stream; attempts TCP_NODELAY after other initialization.
    Tcp,
    /// Unix stream; source skips TCP_NODELAY, retaining other native policy.
    Unix,
}
/// A source-nonfatal diagnostic. No option success is inferred from this value.
#[derive(Debug)]
pub enum Diagnostic {
    /// `socket_set_inheritable` failure: source logs ERROR|BULK and continues.
    CloseOnExec(io::Error),
    /// TCP_NODELAY failure: source logs WARNING and continues.
    TcpNoDelay(io::Error),
}
/// Two fixed diagnostic slots, preserving source order without a growable queue.
#[derive(Debug, Default)]
pub struct Diagnostics {
    close_on_exec: Option<io::Error>,
    tcp_no_delay: Option<io::Error>,
}
impl Diagnostics {
    /// Actual close-on-exec diagnostic, if its native attempt failed.
    pub fn close_on_exec(&self) -> Option<&io::Error> {
        self.close_on_exec.as_ref()
    }
    /// Actual TCP_NODELAY diagnostic, if its native attempt failed.
    pub fn tcp_no_delay(&self) -> Option<&io::Error> {
        self.tcp_no_delay.as_ref()
    }
    /// Whether no native nonfatal failure was observed.
    pub fn is_empty(&self) -> bool {
        self.close_on_exec.is_none() && self.tcp_no_delay.is_none()
    }
}
impl IntoIterator for Diagnostics {
    type Item = Diagnostic;
    type IntoIter = std::iter::Flatten<std::array::IntoIter<Option<Diagnostic>, 2>>;
    fn into_iter(self) -> Self::IntoIter {
        [
            self.close_on_exec.map(Diagnostic::CloseOnExec),
            self.tcp_no_delay.map(Diagnostic::TcpNoDelay),
        ]
        .into_iter()
        .flatten()
    }
}
/// Fatal initialization failure plus earlier nonfatal diagnostics, if any.
/// The borrowed function has not closed the original socket; its owning accept
/// layer must drop/close it before returning this error to a peer consumer.
#[derive(Debug)]
pub struct InitializationError {
    /// Captured primary native error, unaffected by later owner cleanup.
    pub error: io::Error,
    /// Earlier real nonfatal attempts, retained even when a later step failed.
    pub diagnostics: Diagnostics,
}
impl fmt::Display for InitializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}
impl std::error::Error for InitializationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}
trait Operations {
    fn get_fd(&mut self, fd: i32) -> io::Result<i32>;
    fn set_fd(&mut self, fd: i32, flags: i32) -> io::Result<()>;
    fn get_fl(&mut self, fd: i32) -> io::Result<i32>;
    fn set_fl(&mut self, fd: i32, flags: i32) -> io::Result<()>;
    #[cfg(target_os = "macos")]
    fn get_no_sigpipe(&mut self, fd: i32) -> io::Result<bool>;
    #[cfg(target_os = "macos")]
    fn no_sigpipe(&mut self, fd: i32) -> io::Result<()>;
    fn no_delay(&mut self, fd: i32) -> io::Result<()>;
}
struct Native;
impl Operations for Native {
    #[expect(
        unsafe_code,
        reason = "fcntl reads descriptor flags of the caller's live borrowed original fd, with no pointers"
    )]
    fn get_fd(&mut self, fd: i32) -> io::Result<i32> {
        // SAFETY: the caller keeps this borrowed descriptor live for this call;
        // F_GETFD takes no optional argument or memory pointer.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(flags)
        }
    }
    #[expect(
        unsafe_code,
        reason = "fcntl changes flags of this live borrowed descriptor only, with a valid integer argument"
    )]
    fn set_fd(&mut self, fd: i32, flags: i32) -> io::Result<()> {
        // SAFETY: fd remains live and F_SETFD receives only native flag bits.
        let result = unsafe { libc::fcntl(fd, libc::F_SETFD, flags) };
        status(result)
    }
    #[expect(
        unsafe_code,
        reason = "fcntl reads status flags from the live borrowed descriptor without pointers"
    )]
    fn get_fl(&mut self, fd: i32) -> io::Result<i32> {
        // SAFETY: the borrowed fd remains live; F_GETFL has no pointer argument.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(flags)
        }
    }
    #[expect(
        unsafe_code,
        reason = "fcntl sets only the source O_NONBLOCK bit on the stable borrowed original stream"
    )]
    fn set_fl(&mut self, fd: i32, flags: i32) -> io::Result<()> {
        // SAFETY: fd remains live, and flags preserve all native bits obtained
        // from F_GETFL while adding the native O_NONBLOCK bit.
        status(unsafe { libc::fcntl(fd, libc::F_SETFL, flags) })
    }
    #[cfg(target_os = "macos")]
    #[expect(
        unsafe_code,
        reason = "getsockopt writes one initialized native integer and its checked length while the original fd stays borrowed"
    )]
    fn get_no_sigpipe(&mut self, fd: i32) -> io::Result<bool> {
        let mut value: libc::c_int = 0;
        let expected = core::mem::size_of_val(&value) as libc::socklen_t;
        let mut length = expected;
        // SAFETY: both outputs are initialized, live and writable for the call.
        // The supplied capacity is exactly one native integer. No descriptor
        // ownership moves, and an incomplete result is never treated as enabled.
        status(unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                (&mut value as *mut libc::c_int).cast(),
                &mut length,
            )
        })?;
        if length != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SO_NOSIGPIPE returned an unexpected native integer length",
            ));
        }
        // Darwin returns the socket's flag mask, not necessarily the integer 1.
        Ok(value != 0)
    }
    #[cfg(target_os = "macos")]
    fn no_sigpipe(&mut self, fd: i32) -> io::Result<()> {
        option(fd, libc::SOL_SOCKET, libc::SO_NOSIGPIPE)
    }
    fn no_delay(&mut self, fd: i32) -> io::Result<()> {
        option(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY)
    }
}
fn status(value: i32) -> io::Result<()> {
    if value == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
#[expect(
    unsafe_code,
    reason = "setsockopt reads one initialized native integer from a live local while the original fd stays borrowed"
)]
fn option(fd: i32, level: i32, name: i32) -> io::Result<()> {
    let value: libc::c_int = 1;
    // SAFETY: value is initialized and live for the call; the exact native int
    // length is passed. No socket/descriptor ownership moves or duplicates.
    status(unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (&value as *const libc::c_int).cast(),
            core::mem::size_of_val(&value) as libc::socklen_t,
        )
    })
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum InitializationPolicy {
    Select,
    Reactor,
}
fn initialize(
    fd: i32,
    kind: StreamKind,
    ops: &mut impl Operations,
) -> Result<Diagnostics, InitializationError> {
    initialize_policy(fd, kind, ops, InitializationPolicy::Select)
}
fn initialize_policy(
    fd: i32,
    kind: StreamKind,
    ops: &mut impl Operations,
    policy: InitializationPolicy,
) -> Result<Diagnostics, InitializationError> {
    let mut diagnostics = Diagnostics::default();
    let fatal = |error, diagnostics| InitializationError { error, diagnostics };
    if fd < 0 {
        return Err(fatal(
            io::Error::from_raw_os_error(libc::EBADF),
            diagnostics,
        ));
    }
    if policy == InitializationPolicy::Select && fd as usize >= libc::FD_SETSIZE {
        return Err(fatal(
            io::Error::from_raw_os_error(libc::EMFILE),
            diagnostics,
        ));
    }
    let close_on_exec = ops.get_fd(fd).and_then(|flags| {
        if flags & libc::FD_CLOEXEC != 0 {
            Ok(())
        } else {
            ops.set_fd(fd, flags | libc::FD_CLOEXEC)
        }
    });
    if let Err(error) = close_on_exec {
        diagnostics.close_on_exec = Some(error);
    }
    let nonblocking = ops.get_fl(fd).and_then(|flags| {
        if policy == InitializationPolicy::Reactor && flags & libc::O_NONBLOCK != 0 {
            Ok(())
        } else {
            ops.set_fl(fd, flags | libc::O_NONBLOCK)
        }
    });
    if let Err(error) = nonblocking {
        return Err(fatal(error, diagnostics));
    }
    #[cfg(target_os = "macos")]
    {
        // A std/mio listener already enables this option, and Darwin inherits
        // it on accept. A peer can close before initialization; Darwin then
        // rejects redundant setters even while received bytes remain readable.
        // Only an actual successful getter authorizes skipping this setter.
        let sigpipe = match policy {
            InitializationPolicy::Select => ops.no_sigpipe(fd),
            InitializationPolicy::Reactor => ops
                .get_no_sigpipe(fd)
                .and_then(|enabled| if enabled { Ok(()) } else { ops.no_sigpipe(fd) }),
        };
        if let Err(error) = sigpipe {
            return Err(fatal(error, diagnostics));
        }
    }
    if kind == StreamKind::Tcp
        && let Err(error) = ops.no_delay(fd)
    {
        diagnostics.tcp_no_delay = Some(error);
    }
    Ok(diagnostics)
}
/// Apply official v0.29.1 successful-accept initialization to a stable original
/// stream descriptor. The source FD_SETSIZE cap is explicit. CLOEXEC failure is
/// nonfatal; nonblocking and Darwin SO_NOSIGPIPE failures are fatal; non-Unix
/// TCP_NODELAY failure is nonfatal. Diagnostics are bounded and preserve order.
///
/// This function borrows and never closes the fd, including on error. Its owning
/// accepting caller must close it on fatal failure. It adds no peer/core
/// admission and makes no promise about earlier std/mio accept error behavior.
pub fn initialize_accepted_stream(
    fd: BorrowedFd<'_>,
    kind: StreamKind,
) -> Result<Diagnostics, InitializationError> {
    initialize(fd.as_raw_fd(), kind, &mut Native)
}
/// Configure a uniquely owned reactor socket without a C select descriptor cap.
/// Already-enabled nonblocking and, on Darwin, a successfully observed
/// SO_NOSIGPIPE flag avoid redundant setters. Getter failures and necessary
/// setter failures remain fatal; nonfatal diagnostics retain their order. This
/// borrows the original descriptor and never closes or duplicates it. Observed
/// options imply neither a live peer nor delivery of queued bytes.
pub fn initialize_reactor_stream(
    fd: BorrowedFd<'_>,
    kind: StreamKind,
) -> Result<Diagnostics, InitializationError> {
    initialize_policy(
        fd.as_raw_fd(),
        kind,
        &mut Native,
        InitializationPolicy::Reactor,
    )
}
#[cfg(test)]
mod tests {
    //! Finite source-policy return seams, not claimed actual C syscall failures.
    #![expect(
        clippy::expect_used,
        reason = "Finite named source-policy observations require exact results"
    )]
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Native fixture invariants assert observed source behavior"
    )]
    use super::*;
    #[derive(Default)]
    struct Trace {
        calls: Vec<&'static str>,
        fail: Option<&'static str>,
        flags: i32,
        cloexec: i32,
    }
    impl Trace {
        fn step(&mut self, name: &'static str) -> io::Result<()> {
            self.calls.push(name);
            if self.fail == Some(name) {
                Err(io::Error::from_raw_os_error(libc::EINTR))
            } else {
                Ok(())
            }
        }
    }
    impl Operations for Trace {
        fn get_fd(&mut self, _fd: i32) -> io::Result<i32> {
            self.step("getfd")?;
            Ok(self.cloexec)
        }
        fn set_fd(&mut self, _fd: i32, value: i32) -> io::Result<()> {
            self.step("setfd")?;
            self.cloexec = value;
            Ok(())
        }
        fn get_fl(&mut self, _fd: i32) -> io::Result<i32> {
            self.step("getfl")?;
            Ok(self.flags)
        }
        fn set_fl(&mut self, _fd: i32, value: i32) -> io::Result<()> {
            self.step("setfl")?;
            self.flags = value;
            Ok(())
        }
        #[cfg(target_os = "macos")]
        fn get_no_sigpipe(&mut self, _fd: i32) -> io::Result<bool> {
            self.step("getnosigpipe")?;
            Ok(false)
        }
        #[cfg(target_os = "macos")]
        fn no_sigpipe(&mut self, _fd: i32) -> io::Result<()> {
            self.step("nosigpipe")
        }
        fn no_delay(&mut self, _fd: i32) -> io::Result<()> {
            self.step("nodelay")
        }
    }
    #[test]
    fn exact_source_order_preserves_flags_and_skips_redundant_cloexec_set() {
        let mut t = Trace {
            flags: libc::O_APPEND,
            ..Trace::default()
        };
        assert!(
            initialize(7, StreamKind::Tcp, &mut t)
                .expect("policy")
                .is_empty()
        );
        let mut expected = vec!["getfd", "setfd", "getfl", "setfl"];
        #[cfg(target_os = "macos")]
        expected.push("nosigpipe");
        expected.push("nodelay");
        assert_eq!(t.calls, expected);
        assert_eq!(t.flags, libc::O_APPEND | libc::O_NONBLOCK);
        assert_eq!(t.cloexec, libc::FD_CLOEXEC);
        t.calls.clear();
        initialize(7, StreamKind::Unix, &mut t).expect("Unix policy");
        assert!(!t.calls.contains(&"setfd"));
        assert!(!t.calls.contains(&"nodelay"));
    }
    #[test]
    fn reactor_policy_accepts_high_fd_and_preserves_real_setter_failures() {
        for fd in [libc::FD_SETSIZE as i32, i32::MAX] {
            let mut trace = Trace::default();
            assert!(
                initialize_policy(
                    fd,
                    StreamKind::Tcp,
                    &mut trace,
                    InitializationPolicy::Reactor
                )
                .expect("reactor policy")
                .is_empty()
            );
            assert!(trace.calls.contains(&"getfl") && trace.calls.contains(&"nodelay"));
        }
        let mut trace = Trace {
            fail: Some("setfl"),
            ..Trace::default()
        };
        let error = initialize_policy(
            libc::FD_SETSIZE as i32,
            StreamKind::Tcp,
            &mut trace,
            InitializationPolicy::Reactor,
        )
        .expect_err("real setter failure");
        assert_eq!(error.error.raw_os_error(), Some(libc::EINTR));
        assert!(trace.calls.contains(&"setfl"));
    }
    #[test]
    fn invalid_or_fdsetsize_boundary_mints_no_native_attempt() {
        for (fd, errno) in [
            (-1, libc::EBADF),
            (libc::FD_SETSIZE as i32, libc::EMFILE),
            (i32::MAX, libc::EMFILE),
        ] {
            let mut t = Trace::default();
            let error = initialize(fd, StreamKind::Tcp, &mut t).expect_err("finite boundary");
            assert_eq!(error.error.raw_os_error(), Some(errno));
            assert!(error.diagnostics.is_empty());
            assert!(t.calls.is_empty());
        }
    }
    #[test]
    fn cloexec_and_nodelay_failure_are_nonfatal_with_bounded_ordered_diagnostics() {
        for step in ["getfd", "setfd", "nodelay"] {
            let mut t = Trace {
                fail: Some(step),
                ..Trace::default()
            };
            let diagnostics = initialize(7, StreamKind::Tcp, &mut t).expect("source nonfatal");
            assert_eq!(diagnostics.into_iter().count(), 1);
            assert!(t.calls.contains(&"nodelay"));
        }
        struct Two(Trace);
        impl Operations for Two {
            fn get_fd(&mut self, fd: i32) -> io::Result<i32> {
                self.0.get_fd(fd)
            }
            fn set_fd(&mut self, _fd: i32, _v: i32) -> io::Result<()> {
                Err(io::Error::from_raw_os_error(libc::EIO))
            }
            fn get_fl(&mut self, fd: i32) -> io::Result<i32> {
                self.0.get_fl(fd)
            }
            fn set_fl(&mut self, fd: i32, v: i32) -> io::Result<()> {
                self.0.set_fl(fd, v)
            }
            #[cfg(target_os = "macos")]
            fn get_no_sigpipe(&mut self, fd: i32) -> io::Result<bool> {
                self.0.get_no_sigpipe(fd)
            }
            #[cfg(target_os = "macos")]
            fn no_sigpipe(&mut self, fd: i32) -> io::Result<()> {
                self.0.no_sigpipe(fd)
            }
            fn no_delay(&mut self, _fd: i32) -> io::Result<()> {
                Err(io::Error::from_raw_os_error(libc::ENOPROTOOPT))
            }
        }
        let diagnostics =
            initialize(7, StreamKind::Tcp, &mut Two(Trace::default())).expect("two nonfatal slots");
        let mut it = diagnostics.into_iter();
        assert!(
            matches!(it.next(),Some(Diagnostic::CloseOnExec(e))if e.raw_os_error()==Some(libc::EIO))
        );
        assert!(
            matches!(it.next(),Some(Diagnostic::TcpNoDelay(e))if e.raw_os_error()==Some(libc::ENOPROTOOPT))
        );
        assert!(it.next().is_none());
    }
    #[test]
    fn nonblocking_failure_is_fatal_and_does_not_attempt_later_options() {
        for step in ["getfl", "setfl"] {
            let mut t = Trace {
                fail: Some(step),
                ..Trace::default()
            };
            let error = initialize(7, StreamKind::Tcp, &mut t).expect_err("source fatal");
            assert_eq!(error.error.raw_os_error(), Some(libc::EINTR));
            assert!(!t.calls.contains(&"nodelay"));
            assert!(!t.calls.contains(&"nosigpipe"));
        }
    }
    #[test]
    fn earlier_nonfatal_diagnostic_survives_later_fatal_error() {
        struct Both;
        impl Operations for Both {
            fn get_fd(&mut self, _fd: i32) -> io::Result<i32> {
                Err(io::Error::from_raw_os_error(libc::EIO))
            }
            fn set_fd(&mut self, _fd: i32, _v: i32) -> io::Result<()> {
                Ok(())
            }
            fn get_fl(&mut self, _fd: i32) -> io::Result<i32> {
                Err(io::Error::from_raw_os_error(libc::EBADF))
            }
            fn set_fl(&mut self, _fd: i32, _v: i32) -> io::Result<()> {
                Ok(())
            }
            #[cfg(target_os = "macos")]
            fn get_no_sigpipe(&mut self, _fd: i32) -> io::Result<bool> {
                Ok(false)
            }
            #[cfg(target_os = "macos")]
            fn no_sigpipe(&mut self, _fd: i32) -> io::Result<()> {
                Ok(())
            }
            fn no_delay(&mut self, _fd: i32) -> io::Result<()> {
                Ok(())
            }
        }
        let error = initialize(7, StreamKind::Tcp, &mut Both).expect_err("later fatal");
        assert_eq!(error.error.raw_os_error(), Some(libc::EBADF));
        assert_eq!(
            error
                .diagnostics
                .close_on_exec()
                .and_then(io::Error::raw_os_error),
            Some(libc::EIO)
        );
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_nosigpipe_failure_is_fatal_before_nodelay() {
        let mut t = Trace {
            fail: Some("nosigpipe"),
            ..Trace::default()
        };
        let error = initialize(7, StreamKind::Tcp, &mut t).expect_err("Darwin fatal");
        assert_eq!(error.error.raw_os_error(), Some(libc::EINTR));
        assert!(!t.calls.contains(&"nodelay"));
    }
    #[test]
    fn real_wrong_kind_setter_failure_keeps_owned_socket_usable() -> io::Result<()> {
        use std::io::{Read, Write};
        use std::os::fd::AsFd;
        let (mut stream, mut peer) = std::os::unix::net::UnixStream::pair()?;
        // Deliberately injected wrong-kind context forces a real defined native
        // option error. This is Rust component evidence, never a normal C case.
        let diagnostics =
            initialize_accepted_stream(stream.as_fd(), StreamKind::Tcp).map_err(|e| e.error)?;
        assert!(diagnostics.tcp_no_delay().is_some());
        peer.write_all(b"q")?;
        let mut got = [0];
        stream.read_exact(&mut got)?;
        assert_eq!(got, *b"q");
        Ok(())
    }
}
