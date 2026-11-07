//! Official GNUnet inherited-listener ownership and atomic private Unix binding.
//!
//! `service.c:setup_service` consumes a count plus numeric, colon-separated
//! LISTEN_FDNAMES; it does not consult LISTEN_PID. `os_process.c` can pass arbitrary
//! dup-assigned descriptors, so neither a systemd name nor fd3 is assumed.
//! Capture occurs exactly once at process startup, before a runtime, configuration
//! files or other Rust fd owners exist. All borrowed descriptors are validated
//! before any ownership transfer. Only this native host boundary contains unsafe
//! operations; protocol/state/storage crates retain their unsafe prohibition.
use socket2::{Domain, SockAddr, SockRef, Socket, Type};
use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fs::{File, OpenOptions},
    io,
    net::TcpListener,
    os::{
        fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
        unix::{ffi::OsStrExt, net::UnixListener},
    },
    path::Path,
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
};

static CAPTURED: AtomicBool = AtomicBool::new(false);
static PRIVATE_BIND: Mutex<()> = Mutex::new(());

/// Listeners actually inherited from the official process launcher.
/// Dropping sockets closes their unique descriptors. Original stdio slots are
/// restored to the null device; their listeners first move to owned fds >=3.
#[derive(Debug, Default)]
pub struct Activation {
    /// Complete validated set in LISTEN_FDNAMES order; empty means no activation.
    pub sockets: Vec<ActivatedSocket>,
}
/// An owned, nonblocking stream listener ready for safe runtime conversion.
#[derive(Debug)]
pub enum ActivatedSocket {
    /// Unix-domain listening socket; no path was created or may be unlinked by capture.
    Unix(UnixListener),
    /// IPv4 or IPv6 TCP listening socket.
    Tcp(TcpListener),
}
#[derive(Clone, Copy)]
enum Kind {
    Unix,
    Tcp,
}

/// Consume the official inherited descriptor declaration once, before other host initialization.
/// Invalid advertised counts are ignored as in the C service; a positive count
/// with malformed/incomplete/duplicate descriptors is an explicit startup error.
/// All validation precedes ownership transfer. Successful listeners are made
/// nonblocking and close-on-exec; LISTEN_FDS is then removed as in the C service.
///
/// # Safety
/// On the first call, the process must still be single-threaded, before opening
/// configuration/runtime/logging files or constructing Rust owners for any named
/// descriptor. Every named open descriptor must be foreign inherited ownership,
/// exclusively offered to this function: no concurrent close, reuse, `exec`,
/// environment mutation or other owner may race validation/adoption. Successful
/// capture transfers descriptors >=3 directly; low stdio listeners move to fresh
/// fds >=3 before their original stdio slots are restored to /dev/null. Repeated
/// calls are rejected before reading environment or touching any descriptor.
/// An OS failure after validation/adoption is a fatal startup failure: already
/// adopted handles may have closed, so the caller must exit rather than continue
/// or retry with the same declaration. The one-shot guard also covers errors and
/// empty declarations; it is not reset by dropping the returned listeners.
#[expect(
    unsafe_code,
    reason = "The single-threaded early-main caller transfers exclusive foreign inherited fd ownership after complete validation and removes its consumed activation hint"
)]
pub unsafe fn capture() -> io::Result<Activation> {
    if CAPTURED.swap(true, Ordering::AcqRel) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "listener activation was already captured",
        ));
    }
    let count = std::env::var_os("LISTEN_FDS");
    let names = std::env::var_os("LISTEN_FDNAMES");
    let descriptors = parse_declaration(count.as_deref(), names.as_deref())?;
    let mut validated = Vec::with_capacity(descriptors.len());
    for fd in descriptors {
        let flags = descriptor_flags(fd)?;
        if flags & libc::FD_CLOEXEC != 0 {
            return Err(invalid("inherited listener originally has FD_CLOEXEC set"));
        }
        // SAFETY: F_GETFD established an open fd; the caller guarantees its
        // exclusive inherited lifetime remains stable throughout capture.
        let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
        let socket = SockRef::from(&borrowed);
        if socket.r#type()? != Type::STREAM {
            return Err(invalid("inherited descriptor is not a stream socket"));
        }
        if !is_listener(fd)? {
            return Err(invalid("inherited stream socket is not listening"));
        }
        let address = socket.local_addr()?;
        let kind = if address.is_unix() {
            Kind::Unix
        } else if address.as_socket().is_some() {
            // Read-only TCP option query excludes unrelated IP stream protocols.
            socket.tcp_nodelay()?;
            Kind::Tcp
        } else {
            return Err(invalid("unsupported inherited listener address family"));
        };
        validated.push((fd, flags, kind));
    }
    // libstd and service diagnostics must retain usable stdin/stdout/stderr.
    // Reserve every moved listener before opening /dev/null, while all original
    // named fds are still live, so neither allocation can reuse another target.
    let mut relocated = Vec::new();
    relocated
        .try_reserve_exact(3)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    for (fd, _, _) in &validated {
        if *fd < 3 {
            relocated.push((*fd, duplicate_above_stdio(*fd)?));
        }
    }
    if !relocated.is_empty() {
        let null = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")?;
        for (fd, _) in &relocated {
            restore_stdio(&null, *fd)?;
        }
    }
    let mut sockets = Vec::with_capacity(validated.len());
    for (fd, flags, kind) in validated {
        let owned = if fd < 3 {
            let index = relocated
                .iter()
                .position(|(original, _)| *original == fd)
                .ok_or_else(|| invalid("missing relocated standard descriptor"))?;
            relocated.swap_remove(index).1
        } else {
            // SAFETY: the complete unique fd set was validated while no owners
            // or competing threads existed. This is its sole ownership transfer.
            unsafe { OwnedFd::from_raw_fd(fd) }
        };
        set_descriptor_flags(&owned, flags | libc::FD_CLOEXEC)?;
        let socket = Socket::from(owned);
        socket.set_nonblocking(true)?;
        let owned: OwnedFd = socket.into();
        sockets.push(match kind {
            Kind::Unix => ActivatedSocket::Unix(UnixListener::from(owned)),
            Kind::Tcp => ActivatedSocket::Tcp(TcpListener::from(owned)),
        });
    }
    if !sockets.is_empty() {
        // SAFETY: early-main contract excludes all other environment readers or
        // writers. C likewise removes only LISTEN_FDS, retaining names and PID.
        unsafe { std::env::remove_var("LISTEN_FDS") };
    }
    Ok(Activation { sockets })
}

fn parse_declaration(count: Option<&OsStr>, names: Option<&OsStr>) -> io::Result<Vec<RawFd>> {
    let (Some(count), Some(names)) = (count, names) else {
        return Ok(Vec::new());
    };
    // The outer C predicate ignores missing, nonnumeric, zero and out-of-select
    // range counts. Unlike libc scanf, arithmetic overflow is checked safely.
    let Some(count) = unsigned(count.as_bytes()).filter(|n| *n > 0 && *n < libc::FD_SETSIZE as u32)
    else {
        return Ok(Vec::new());
    };
    let mut descriptors = Vec::with_capacity(count as usize);
    let mut unique = BTreeSet::new();
    // C strtok skips empty components, including leading/repeated/trailing ':'.
    for token in names
        .as_bytes()
        .split(|b| *b == b':')
        .filter(|s| !s.is_empty())
    {
        if descriptors.len() == count as usize {
            return Err(invalid("more numeric listener names than LISTEN_FDS"));
        }
        let number = unsigned(token)
            .filter(|n| *n < libc::FD_SETSIZE as u32)
            .ok_or_else(|| invalid("malformed or out-of-range numeric inherited fd"))?;
        let fd = number as RawFd;
        if !unique.insert(fd) {
            return Err(invalid("duplicate inherited descriptor number"));
        }
        descriptors.push(fd);
    }
    if descriptors.len() != count as usize {
        return Err(invalid("fewer numeric listener names than LISTEN_FDS"));
    }
    Ok(descriptors)
}
fn unsigned(mut bytes: &[u8]) -> Option<u32> {
    while bytes
        .first()
        .is_some_and(|b| *b == b' ' || (9..=13).contains(b))
    {
        bytes = &bytes[1..];
    }
    let negative = bytes.first() == Some(&b'-');
    if negative || bytes.first() == Some(&b'+') {
        bytes = &bytes[1..];
    }
    if bytes.is_empty() {
        return None;
    }
    let mut value = 0_u32;
    for b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u32::from(*b - b'0'))?;
    }
    Some(if negative {
        0_u32.wrapping_sub(value)
    } else {
        value
    })
}
#[expect(
    unsafe_code,
    reason = "F_DUPFD_CLOEXEC allocates a fresh exclusively owned descriptor >=3 from a validated stable inherited socket, then OwnedFd owns only that new descriptor"
)]
fn duplicate_above_stdio(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: integer-only fcntl receives a validated live inherited descriptor;
    // the OS creates an unused descriptor atomically marked close-on-exec.
    let moved = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if moved < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful duplication returned a fresh live fd with no Rust owner.
    Ok(unsafe { OwnedFd::from_raw_fd(moved) })
}
#[expect(
    unsafe_code,
    reason = "Synchronous early-main dup2 atomically replaces a still-foreign low stdio listener with the already-open null device after its socket was safely duplicated"
)]
fn restore_stdio(null: &File, target: RawFd) -> io::Result<()> {
    // SAFETY: null is a live owned /dev/null fd, target is a validated low stdio
    // slot with no Rust owner, and the startup contract excludes reuse races.
    if unsafe { libc::dup2(null.as_raw_fd(), target) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[expect(
    unsafe_code,
    reason = "fcntl F_GETFD accepts any integer descriptor and returns an error for invalid values; it never accesses Rust memory"
)]
fn descriptor_flags(fd: RawFd) -> io::Result<libc::c_int> {
    // SAFETY: F_GETFD takes only an integer; no variadic or pointer arguments.
    let value = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if value < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value)
    }
}
#[expect(
    unsafe_code,
    reason = "fcntl F_SETFD changes flags on the still-live uniquely owned descriptor using only integer arguments"
)]
fn set_descriptor_flags(fd: &OwnedFd, flags: libc::c_int) -> io::Result<()> {
    // SAFETY: this owned fd stays open, and F_SETFD expects the supplied integer.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
#[cfg(not(target_os = "macos"))]
#[expect(
    unsafe_code,
    reason = "getsockopt SO_ACCEPTCONN writes exactly the provided initialized c_int buffer whose socklen is checked before use"
)]
fn is_listener(fd: RawFd) -> io::Result<bool> {
    let mut value: libc::c_int = 0;
    let mut length = size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: SOL_SOCKET/SO_ACCEPTCONN writes into value with the stated length;
    // length is a valid mutable socklen_t. Invalid/non-socket fds produce errno.
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ACCEPTCONN,
            (&raw mut value).cast(),
            &raw mut length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if length as usize != size_of::<libc::c_int>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected SO_ACCEPTCONN result size",
        ));
    }
    Ok(value != 0)
}

// macOS defines SO_ACCEPTCONN but does not expose it through getsockopt.
// Public libproc reports the same socket option bits without accepting a queued
// connection or modifying an unlistening socket. Prefix ABI matches the SDK's
// sys/proc_info.h; the subprocess C layout oracle checks its offset and capacity.
#[cfg(target_os = "macos")]
#[repr(C)]
struct DarwinProcFileInfo {
    open_flags: u32,
    status: u32,
    offset: libc::off_t,
    kind: i32,
    guard_flags: u32,
}
#[cfg(target_os = "macos")]
#[repr(C)]
struct DarwinSocketPrefix {
    file: DarwinProcFileInfo,
    stat: libc::vinfo_stat,
    socket: u64,
    pcb: u64,
    kind: libc::c_int,
    protocol: libc::c_int,
    family: libc::c_int,
    options: libc::c_short,
}
#[cfg(target_os = "macos")]
/// Byte offset checked against the macOS public SDK by the process fixture.
pub const DARWIN_SOCKET_OPTIONS_OFFSET: usize = std::mem::offset_of!(DarwinSocketPrefix, options);
#[cfg(target_os = "macos")]
/// Native socket-info result capacity checked against the macOS public SDK.
pub const DARWIN_SOCKET_INFO_BUFFER_BYTES: usize = 4096;
#[cfg(target_os = "macos")]
#[expect(
    unsafe_code,
    reason = "Self-process proc_pidfdinfo writes at most the supplied zero-initialized byte buffer; the public SDK prefix offset and result length are checked before reading option bytes"
)]
fn is_listener(fd: RawFd) -> io::Result<bool> {
    const PROC_PIDFDSOCKETINFO: libc::c_int = 3;
    let mut bytes = [0_u8; DARWIN_SOCKET_INFO_BUFFER_BYTES];
    // SAFETY: the self PID and validated open fd identify our inherited socket;
    // the byte buffer is writable for exactly its advertised length. The kernel
    // API never writes beyond that bound and returns bytes actually copied.
    let written = unsafe {
        libc::proc_pidfdinfo(
            std::process::id() as libc::c_int,
            fd,
            PROC_PIDFDSOCKETINFO,
            bytes.as_mut_ptr().cast(),
            bytes.len() as libc::c_int,
        )
    };
    if written <= 0 {
        return Err(io::Error::last_os_error());
    }
    if (written as usize) < size_of::<DarwinSocketPrefix>() || written as usize > bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported native socket-info layout",
        ));
    }
    let start = DARWIN_SOCKET_OPTIONS_OFFSET;
    let options = libc::c_short::from_ne_bytes([bytes[start], bytes[start + 1]]);
    Ok(libc::c_int::from(options) & libc::SO_ACCEPTCONN != 0)
}

/// Bind a Unix listener with atomic private creation and restore the prior umask.
///
/// The caller must serialize startup against unrelated process-wide umask users
/// and file creators. The internal mutex serializes this package's own binds;
/// it cannot exclude foreign file creation. There is no await or callback while
/// the mask is changed. This function does not create parents or remove paths.
pub fn bind_private(path: &Path) -> io::Result<UnixListener> {
    bind_unix_private(path)
}

/// Synchronously bind a Unix path with the official atomic 0700 creation mask.
/// The host must call this only in its startup bind section, without unrelated
/// threads opening files concurrently. This function contains no await/callback;
/// its private guard restores the previous process umask even on bind failure.
/// The mutex serializes this module's binds, not foreign process-wide mask users.
pub(crate) fn bind_unix_private(path: &Path) -> io::Result<UnixListener> {
    let _mask = PrivateUmaskGuard::new()?;
    UnixListener::bind(path)
}
struct PrivateUmaskGuard {
    previous: libc::mode_t,
    _serialized: MutexGuard<'static, ()>,
}
impl PrivateUmaskGuard {
    #[expect(
        unsafe_code,
        reason = "The synchronous startup-only guard sets the process umask to official 077 while holding the module's bind lock"
    )]
    fn new() -> io::Result<Self> {
        let serialized = PRIVATE_BIND
            .lock()
            .map_err(|_| io::Error::other("private Unix bind lock was poisoned"))?;
        // SAFETY: umask takes a mode value and has no pointer preconditions;
        // startup-only caller excludes unrelated concurrent file creation.
        let previous = unsafe { libc::umask(0o077) };
        Ok(Self {
            previous,
            _serialized: serialized,
        })
    }
}
impl Drop for PrivateUmaskGuard {
    #[expect(
        unsafe_code,
        reason = "The guard restores its exact saved process umask before releasing the serialized synchronous bind scope"
    )]
    fn drop(&mut self) {
        // SAFETY: previous was returned by this guard's paired umask call.
        unsafe { libc::umask(self.previous) };
    }
}

#[cfg(test)]
mod tests {
    use super::parse_declaration;
    use std::ffi::OsStr;
    #[test]
    fn official_numeric_names_are_not_systemd_names_or_sequential_guesses() {
        assert_eq!(
            parse_declaration(Some(OsStr::new(" +2")), Some(OsStr::new(":73::19:"))).ok(),
            Some(vec![73, 19])
        );
        assert_eq!(
            parse_declaration(Some(OsStr::new("1")), Some(OsStr::new("0"))).ok(),
            Some(vec![0])
        );
        assert!(
            parse_declaration(Some(OsStr::new("1")), Some(OsStr::new("statistics.socket")))
                .is_err()
        );
    }
    #[test]
    fn inactive_outer_predicate_matches_c_and_avoids_overflow() {
        for count in [
            None,
            Some(""),
            Some("0"),
            Some("-1"),
            Some("1024"),
            Some("1 "),
            Some("4294967296"),
            Some("wrong"),
        ] {
            assert_eq!(
                parse_declaration(count.map(OsStr::new), Some(OsStr::new("73"))).ok(),
                Some(Vec::new())
            );
        }
        assert_eq!(
            parse_declaration(Some(OsStr::new("1")), None).ok(),
            Some(Vec::new())
        );
    }
    #[test]
    fn no_prefix_success_duplicate_owner_or_invalid_descriptor_number() {
        for (count, names) in [
            ("2", "73"),
            ("1", "73:19"),
            ("2", "73:73"),
            ("2", "73:bad"),
            ("1", "1024"),
            ("1", "-1"),
            ("1", "19 "),
            ("1", ""),
        ] {
            assert!(parse_declaration(Some(OsStr::new(count)), Some(OsStr::new(names))).is_err());
        }
    }
}

/// Newly created private Unix listener plus its exact pathname ownership.
/// The listener field drops before the path guard on ordinary aggregate drop.
#[derive(Debug)]
pub struct PrivateListener {
    /// First actual listen used the supplied backlog, without an earlier std bind/listen.
    pub listener: UnixListener,
    /// Guard for this bind's newly created filesystem entry only.
    pub path: crate::CreatedPath,
    /// Nonfatal SO_REUSEADDR diagnostics, as in official create_listen_socket.
    pub warnings: Vec<io::Error>,
}
struct PendingPrivateListener {
    socket: Socket,
    path: crate::CreatedPath,
}
/// Bind atomically private and make the first actual listen use the given backlog.
/// Reuses the exact audited startup-only umask guard; no new native unsafe body.
/// The caller must exclude unrelated file creation/umask mutation and hostile
/// pathname replacement during startup. After bind, failed listen/nonblocking
/// setup closes the socket before the inode guard removes its owned pathname.
/// A failed SO_REUSEADDR is retained as a nonfatal diagnostic like the C caller.
pub fn bind_private_with_backlog(path: &Path, backlog: i32) -> io::Result<PrivateListener> {
    bind_private_with(path, None, |socket| socket.listen(backlog))
}
/// Bind privately with an explicit source permission mode before first listen.
/// A chmod failure is nonfatal and reported in warnings, matching the official
/// ARM caller. No callback/await runs inside the original umask guard.
pub fn bind_private_with_permissions(
    path: &Path,
    backlog: i32,
    mode: u32,
) -> io::Result<PrivateListener> {
    bind_private_with(path, Some(mode), |socket| socket.listen(backlog))
}
fn bind_private_with(
    path: &Path,
    mode: Option<u32>,
    listen: impl FnOnce(&Socket) -> io::Result<()>,
) -> io::Result<PrivateListener> {
    let address = SockAddr::unix(path)?;
    let _mask = PrivateUmaskGuard::new()?;
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    let mut warnings = Vec::new();
    if let Err(error) = socket.set_reuse_address(true) {
        warnings.push(error);
    }
    socket.set_nonblocking(true)?;
    socket.bind(&address)?;
    let pending = PendingPrivateListener {
        socket,
        path: crate::CreatedPath::capture(path.to_path_buf())?,
    };
    if let Some(mode) = mode {
        use std::os::unix::fs::PermissionsExt;
        if let Err(error) =
            std::fs::set_permissions(pending.path.path(), std::fs::Permissions::from_mode(mode))
        {
            warnings.push(error);
        }
    }
    listen(&pending.socket)?;
    let PendingPrivateListener { socket, path } = pending;
    Ok(PrivateListener {
        listener: socket.into(),
        path,
        warnings,
    })
}
#[cfg(test)]
mod private_backlog_tests {
    use super::*;
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Finite injected-listen regression asserts the real bound path and then its cleanup, returning actual fixture IO failures"
    )]
    fn actual_bound_path_is_cleaned_when_first_listen_fails() -> io::Result<()> {
        let directory =
            std::env::temp_dir().join(format!("gnunet-arm-backlog-failure-{}", std::process::id()));
        std::fs::create_dir(&directory)?;
        let path = directory.join("listener");
        let result = bind_private_with(&path, Some(0o770), |socket| {
            assert!(socket.local_addr()?.as_pathname().is_some());
            assert!(path.exists());
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path)?.permissions().mode() & 0o777,
                0o770
            );
            Err(io::Error::from_raw_os_error(libc::EIO))
        });
        let actual = result.as_ref().err().and_then(io::Error::raw_os_error);
        drop(result);
        let remains = path.exists();
        std::fs::remove_dir(directory)?;
        assert_eq!(actual, Some(libc::EIO));
        assert!(!remains);
        Ok(())
    }
}
