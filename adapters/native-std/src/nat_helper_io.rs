//! Process-local output and signal ownership shared by explicit NAT helpers.
use std::{
    fs::File,
    io::{self, Write},
    mem::MaybeUninit,
    os::fd::{AsFd, AsRawFd, BorrowedFd},
    sync::atomic::{AtomicBool, Ordering},
};
/// Retained duplicate of the original stdout/stderr description. Nonblocking
/// writes retain the original cursor; restore explicitly reports fcntl failure.
/// Caller must own exclusive helper output use while this guard is live. No late
/// arbitrary fd number is reconstructed, and cleanup uses the same owned file.
pub struct Output {
    file: File,
    flags: libc::c_int,
    active: bool,
}
impl AsFd for Output {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}
impl Output {
    /// Capture the actual original stdout after credentials have dropped.
    pub fn stdout() -> io::Result<Self> {
        Self::capture(std::io::stdout().as_fd())
    }
    /// Capture actual original stderr for a single bounded best-effort diagnostic.
    pub fn stderr() -> io::Result<Self> {
        Self::capture(std::io::stderr().as_fd())
    }
    #[expect(
        unsafe_code,
        reason = "fcntl changes flags only on a retained duplicate of a caller-owned live stdio description; integer commands have the correct ABI"
    )]
    fn capture(fd: BorrowedFd<'_>) -> io::Result<Self> {
        let file = File::from(fd.try_clone_to_owned()?);
        // SAFETY: F_GETFL takes no variadic argument; this fd is owned for the call.
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: F_SETFL's variadic argument is the c_int flags returned by F_GETFL.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            file,
            flags,
            active: true,
        })
    }
    /// One real nonblocking original write; short writes retain cursor at caller.
    pub fn write(&self, bytes: &[u8]) -> io::Result<usize> {
        let mut file = &self.file;
        file.write(bytes)
    }
    /// Restore the original shared description's exact flags before returning.
    #[expect(
        unsafe_code,
        reason = "The owned duplicate keeps the original description alive; F_SETFL receives its original c_int flags"
    )]
    pub fn restore(&mut self) -> io::Result<()> {
        if self.active {
            // SAFETY: file remains live/exclusively controlled by this helper guard.
            if unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_SETFL, self.flags) } < 0 {
                return Err(io::Error::last_os_error());
            }
            self.active = false;
        }
        Ok(())
    }
}
impl Drop for Output {
    fn drop(&mut self) {
        let _restored = self.restore();
    }
}
static STOP: AtomicBool = AtomicBool::new(false);
static SIGNALS: AtomicBool = AtomicBool::new(false);
extern "C" fn stopped(_signal: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}
/// Single-threaded process-local SIGTERM/SIGINT/PIPE ownership. No handler does
/// allocation/I/O, and a controlled stop lets the original stdout flags restore.
pub struct Signals {
    saved: Vec<(libc::c_int, libc::sigaction)>,
    active: bool,
}
impl Signals {
    /// Install only after dropping credentials; a second owner is refused.
    #[expect(
        unsafe_code,
        reason = "sigaction operates on initialized target Unix ABI records; original handlers are retained and restored by the same single-threaded owner"
    )]
    pub fn install() -> io::Result<Self> {
        if SIGNALS.swap(true, Ordering::AcqRel) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "helper signal owner already installed",
            ));
        }
        STOP.store(false, Ordering::Relaxed);
        let mut guard = Self {
            saved: Vec::new(),
            active: true,
        };
        guard.saved.try_reserve_exact(3).map_err(io::Error::other)?;
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGPIPE] {
            // SAFETY: all-zero sigaction is initialized before passing it to libc; the
            // mask is explicitly initialized and all fields have libc's target Unix C layout.
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            // SAFETY: sa_mask is a live initialized sigset_t, uniquely borrowed here.
            if unsafe { libc::sigemptyset(&mut action.sa_mask) } < 0 {
                return Err(io::Error::last_os_error());
            }
            action.sa_sigaction = if signal == libc::SIGPIPE {
                libc::SIG_IGN
            } else {
                stopped as *const () as usize
            };
            action.sa_flags = 0;
            let mut original = MaybeUninit::<libc::sigaction>::uninit();
            // SAFETY: input/output pointers each designate one correctly aligned record;
            // successful sigaction initializes original before assume_init below.
            if unsafe { libc::sigaction(signal, &action, original.as_mut_ptr()) } < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: the preceding successful syscall fully initialized this record.
            guard
                .saved
                .push((signal, unsafe { original.assume_init() }));
        }
        Ok(guard)
    }
    /// Actual original stop signal has been received; no clock or syscall is needed.
    pub fn stopped(&self) -> bool {
        STOP.load(Ordering::Relaxed)
    }
    /// Restore each original handler and retain the first actual cleanup errno.
    #[expect(
        unsafe_code,
        reason = "Each saved sigaction came from a successful install in the same process and remains initialized until restoration"
    )]
    pub fn restore(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }
        let mut first = None;
        for (signal, action) in self.saved.iter().rev() {
            // SAFETY: initialized original action is borrowed for this synchronous call;
            // null old-action output is expressly permitted by sigaction.
            if unsafe { libc::sigaction(*signal, action, std::ptr::null_mut()) } < 0
                && first.is_none()
            {
                first = Some(io::Error::last_os_error())
            }
        }
        self.active = false;
        SIGNALS.store(false, Ordering::Release);
        match first {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        let _restored = self.restore();
    }
}
