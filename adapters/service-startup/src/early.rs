//! Once-only early fd capture. Ordinary pipes are valid CLOSE_LSOCKS inputs.
use gnunet_service_runtime::{Activation, BoundListeners};
use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fs::{File, OpenOptions},
    io::{self, Read},
    os::{
        fd::{BorrowedFd, FromRawFd, OwnedFd, RawFd},
        unix::ffi::OsStrExt,
    },
    sync::atomic::{AtomicBool, Ordering},
};
static CAPTURED: AtomicBool = AtomicBool::new(false);
/// Compile-time service option routing the one inherited declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InheritedMode {
    /// Use validated actual listener sockets, the ordinary service behavior.
    AdoptListeners,
    /// Option4: hold inherited descriptors, bind configured listeners, then close.
    CloseAfterConfiguredBind,
}
/// Exactly one ownership route; the same raw fd cannot be in both variants.
#[derive(Debug)]
pub enum InheritedResources {
    /// Original sockets offered directly to BoundListeners.
    Listeners(Activation),
    /// Includes ARM's pipe write end; never offered to the listener runtime.
    CloseAfterBind(RebindHold),
}
/// Why no parent control owner was installed, corresponding to C's ignored hint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlNotice {
    /// Nonempty text contained no valid in-range hex descriptor prefix.
    InvalidDeclaration,
    /// Parsed descriptor was not open when captured; nothing was owned/closed.
    InvalidDescriptor,
}
/// All parent-declared resources captured before unrelated startup opens files.
#[derive(Debug)]
pub struct CapturedStartup {
    /// The mutually exclusive listener or close-after-bind ownership route.
    pub inherited: InheritedResources,
    /// Original parent-to-child signal stream, separate from readiness.
    pub parent_control: Option<ParentControl>,
    /// Explicit ignored malformed/closed control input; no successful install claim.
    pub control_notice: Option<ControlNotice>,
}
/// Inherited readiness resources retained until own listeners bind or startup fails.
#[derive(Debug)]
pub struct RebindHold {
    held: Vec<OwnedFd>,
}
/// Local release phase; either phase closes child ownership and may produce EOF.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleasePhase {
    /// Own configured listeners were successfully constructed.
    OwnListenersBound,
    /// Startup did not reach its own-listener bind phase.
    Aborted,
}
/// Only local ownership facts, not proof of full initialization or parent receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseReport {
    /// Number of owned descriptors whose Rust owners were consumed/dropped.
    pub owned_descriptors_released: usize,
    /// The explicit caller phase, not inferred from parent EOF.
    pub phase: ReleasePhase,
}
impl RebindHold {
    /// Count of independently owned inherited descriptor numbers.
    pub fn len(&self) -> usize {
        self.held.len()
    }
    /// Whether the inherited close set is empty.
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }
    /// Release only after a real BoundListeners value exists. This occurs before
    /// username changes/application init in C and claims neither later success.
    pub fn complete_after_bind(self, _bound: &BoundListeners) -> ReleaseReport {
        let count = self.held.len();
        drop(self);
        ReleaseReport {
            owned_descriptors_released: count,
            phase: ReleasePhase::OwnListenersBound,
        }
    }
    /// Release failed-startup ownership. It sends no success byte and EOF alone
    /// cannot be interpreted as successful initialization.
    pub fn abort(self) -> ReleaseReport {
        let count = self.held.len();
        drop(self);
        ReleaseReport {
            owned_descriptors_released: count,
            phase: ReleasePhase::Aborted,
        }
    }
}
/// Unique original parent-control read descriptor. No arbitrary raw fd close.
#[derive(Debug)]
pub struct ParentControl {
    file: File,
}
impl ParentControl {
    /// Transfer this same original descriptor into the common opaque reactor
    /// owner; no clone or late raw-fd reconstruction is performed.
    pub fn register(
        self,
    ) -> Result<crate::ControlReceiver, gnunet_service_runtime::readiness::RegisterError> {
        crate::ControlReceiver::from_owned(self.file.into())
    }
    /// Read one native signed-char signal code. WouldBlock/EINTR are actual I/O
    /// errors; EOF returns None. The reactor schedules readiness and dispatches
    /// only the corresponding installed handler after an actual byte.
    pub fn try_read_signal(&mut self) -> io::Result<Option<i8>> {
        let mut b = [0u8];
        match self.file.read(&mut b) {
            Ok(0) => Ok(None),
            Ok(1) => Ok(Some(b[0] as i8)),
            Ok(_) => Err(io::Error::other(
                "one-byte control read returned excess length",
            )),
            Err(e) => Err(e),
        }
    }
    /// Borrow the owned fd for an explicit poll/AsyncFd registration by a reactor.
    pub fn as_file(&self) -> &File {
        &self.file
    }
}
/// Capture the one inherited declaration plus optional signal-control fd.
/// Invalid outer listener counts are ignored as in C; malformed positive sets
/// are rejected atomically before transfer. Control invalidity is ignored with
/// an explicit notice. All aliases are rejected before either channel owns fds.
///
/// # Safety
/// Call exactly once in a fresh single-threaded exec child, before config/log/
/// runtime opens, stdio output, environment mutation or other owners of any
/// offered descriptor. The parent exclusively transfers every declared valid fd;
/// no concurrent close/reuse/exec is permitted. Do not call another activation
/// capture API. Any failure after adoption is fatal startup failure: exit without
/// retrying the declaration. This function only changes this new child's consumed
/// activation/control hints and restores offered low stdio slots to /dev/null.
#[expect(
    unsafe_code,
    reason = "The early exec-child caller transfers exclusive foreign descriptors and permits one-shot consumption of inherited environment hints"
)]
pub unsafe fn capture_from_environment(mode: InheritedMode) -> io::Result<CapturedStartup> {
    if CAPTURED.swap(true, Ordering::AcqRel) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "startup descriptors already captured",
        ));
    }
    let count = std::env::var_os("LISTEN_FDS");
    let names = std::env::var_os("LISTEN_FDNAMES");
    let listed = declaration(count.as_deref(), names.as_deref())?;
    let mut unique = BTreeSet::new();
    for fd in &listed {
        if !unique.insert(*fd) {
            return Err(invalid("duplicate inherited descriptor"));
        }
        let f = flags(*fd)?;
        if f & libc::FD_CLOEXEC != 0 {
            return Err(invalid("original inherited descriptor has CLOEXEC"));
        }
    }
    let control_hint = std::env::var_os("GNUNET_OS_CONTROL_PIPE");
    let mut notice = None;
    let control = match control_hint.as_ref().filter(|s| !s.is_empty()) {
        None => None,
        Some(s) => match hex_prefix(s.as_bytes()) {
            None => {
                notice = Some(ControlNotice::InvalidDeclaration);
                None
            }
            Some(fd) => {
                if unique.contains(&fd) {
                    return Err(invalid(
                        "signal-control fd aliases inherited listener/readiness fd",
                    ));
                }
                match flags(fd) {
                    Ok(_) => Some(fd),
                    Err(_) => {
                        notice = Some(ControlNotice::InvalidDescriptor);
                        None
                    }
                }
            }
        },
    };
    // Validate both sets completely before the first caller-visible transfer.
    let inherited = match mode {
        InheritedMode::AdoptListeners => {
            // SAFETY: this is the sole activation-capture call in fresh main;
            // disjoint control fds remain foreign and stable until adopted below.
            InheritedResources::Listeners(unsafe { gnunet_service_runtime::capture()? })
        }
        InheritedMode::CloseAfterConfiguredBind => {
            let held = adopt(&listed)?;
            InheritedResources::CloseAfterBind(RebindHold { held })
        }
    };
    let parent_control = if let Some(fd) = control {
        let mut v = adopt(&[fd])?;
        let owned = v
            .pop()
            .ok_or_else(|| invalid("missing adopted control fd"))?;
        let current =
            OFlag::from_bits_retain(fcntl(&owned, FcntlArg::F_GETFL).map_err(io::Error::from)?);
        fcntl(&owned, FcntlArg::F_SETFL(current | OFlag::O_NONBLOCK)).map_err(io::Error::from)?;
        Some(ParentControl {
            file: File::from(owned),
        })
    } else {
        None
    };
    if !listed.is_empty() {
        // SAFETY: the startup contract excludes every other environment reader
        // or writer, and this consumes only the fresh child's original hint.
        unsafe { std::env::remove_var("LISTEN_FDS") };
    }
    // SAFETY: same exclusive early-child environment contract. C sets this
    // hint empty even for absent/invalid control input to prevent a second take.
    unsafe { std::env::set_var("GNUNET_OS_CONTROL_PIPE", "") };
    Ok(CapturedStartup {
        inherited,
        parent_control,
        control_notice: notice,
    })
}
fn declaration(count: Option<&OsStr>, names: Option<&OsStr>) -> io::Result<Vec<RawFd>> {
    let (Some(count), Some(names)) = (count, names) else {
        return Ok(Vec::new());
    };
    let Some(count) = unsigned(count.as_bytes()).filter(|n| *n > 0 && *n < libc::FD_SETSIZE as u32)
    else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    out.try_reserve_exact(count as usize)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    for token in names
        .as_bytes()
        .split(|b| *b == b':')
        .filter(|b| !b.is_empty())
    {
        if out.len() == count as usize {
            return Err(invalid("more inherited descriptors than count"));
        }
        let fd = unsigned(token)
            .filter(|n| *n < libc::FD_SETSIZE as u32)
            .ok_or_else(|| invalid("invalid inherited descriptor number"))?;
        out.push(fd as RawFd);
    }
    if out.len() != count as usize {
        return Err(invalid("fewer inherited descriptors than count"));
    }
    Ok(out)
}
fn unsigned(mut b: &[u8]) -> Option<u32> {
    while b
        .first()
        .is_some_and(|x| *x == b' ' || (9..=13).contains(x))
    {
        b = &b[1..]
    }
    let neg = b.first() == Some(&b'-');
    if neg || b.first() == Some(&b'+') {
        b = &b[1..]
    }
    if b.is_empty() {
        return None;
    }
    let mut n = 0u32;
    for c in b {
        if !c.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add(u32::from(*c - b'0'))?;
    }
    Some(if neg { 0u32.wrapping_sub(n) } else { n })
}
fn hex_prefix(mut b: &[u8]) -> Option<RawFd> {
    while b
        .first()
        .is_some_and(|x| *x == b' ' || (9..=13).contains(x))
    {
        b = &b[1..]
    }
    let neg = b.first() == Some(&b'-');
    if neg || b.first() == Some(&b'+') {
        b = &b[1..]
    }
    if b.len() >= 3 && b[0] == b'0' && (b[1] == b'x' || b[1] == b'X') && b[2].is_ascii_hexdigit() {
        b = &b[2..]
    }
    let mut n = 0u64;
    let mut seen = false;
    for c in b {
        let v = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => break,
        };
        seen = true;
        n = n.checked_mul(16)?.checked_add(u64::from(v))?;
    }
    if !seen {
        return None;
    }
    let n = if neg { 0u64.wrapping_sub(n) } else { n };
    (n < libc::FD_SETSIZE as u64).then_some(n as RawFd)
}
#[expect(
    unsafe_code,
    reason = "F_GETFD is an integer-only read and accepts invalid descriptors without touching Rust memory"
)]
fn flags(fd: RawFd) -> io::Result<i32> {
    // SAFETY: F_GETFD has no pointer/variadic payload and returns errno for bad fd.
    let result = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}
#[expect(
    unsafe_code,
    reason = "Validated stable foreign ownership is transferred once; duplication creates only fresh uniquely owned fds"
)]
fn adopt(fds: &[RawFd]) -> io::Result<Vec<OwnedFd>> {
    let mut moved = Vec::new();
    moved
        .try_reserve_exact(3)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    for fd in fds.iter().filter(|fd| **fd < 3) {
        // SAFETY: whole-set validation established an open still-foreign fd;
        // the outer unsafe startup contract prevents all reuse/close races.
        let borrowed = unsafe { BorrowedFd::borrow_raw(*fd) };
        let fresh = fcntl(borrowed, FcntlArg::F_DUPFD_CLOEXEC(3)).map_err(io::Error::from)?;
        // SAFETY: successful F_DUPFD_CLOEXEC returned fresh exclusive ownership.
        moved.push((*fd, unsafe { OwnedFd::from_raw_fd(fresh) }));
    }
    if !moved.is_empty() {
        let null = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")?;
        for (fd, _) in &moved {
            match fd {
                0 => nix::unistd::dup2_stdin(&null),
                1 => nix::unistd::dup2_stdout(&null),
                2 => nix::unistd::dup2_stderr(&null),
                _ => return Err(invalid("unexpected stdio relocation")),
            }
            .map_err(io::Error::from)?;
        }
    }
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(fds.len())
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    for fd in fds {
        let value = if *fd < 3 {
            let pos = moved
                .iter()
                .position(|(n, _)| n == fd)
                .ok_or_else(|| invalid("missing moved stdio fd"))?;
            moved.swap_remove(pos).1
        } else {
            // SAFETY: no other Rust owner exists and all complete validation finished
            // before any original descriptor was adopted or stdio slot restored.
            unsafe { OwnedFd::from_raw_fd(*fd) }
        };
        fcntl(&value, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).map_err(io::Error::from)?;
        owned.push(value)
    }
    Ok(owned)
}
fn invalid(m: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, m)
}
#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "Pure deterministic component fixtures unwrap only fixed valid local test values"
    )]
    use super::*;
    #[test]
    fn native_hex_prefix_and_full_unsigned_profiles_are_distinct() {
        for (input, expected) in [
            (b"80zz".as_slice(), Some(128)),
            (b"0x80tail", Some(128)),
            (b" \t+80", Some(128)),
            (b"-0", Some(0)),
            (b"-1", None),
            (b"0x", Some(0)),
            (b"0xg", Some(0)),
            (b"xyz", None),
            (b"10000000000000000", None),
            (b"400", None),
        ] {
            assert_eq!(hex_prefix(input), expected);
        }
        assert_eq!(unsigned(b"  +128"), Some(128));
        assert_eq!(unsigned(b"128tail"), None);
        assert_eq!(unsigned(b"-0"), Some(0));
        assert_eq!(unsigned(b"-1"), Some(u32::MAX));
    }
    #[test]
    fn full_count_preflight_rejects_missing_extra_and_preserves_empty_components() {
        assert_eq!(
            declaration(Some(OsStr::new("2")), Some(OsStr::new(":128::160:"))).unwrap(),
            vec![128, 160]
        );
        assert!(declaration(Some(OsStr::new("2")), Some(OsStr::new("128"))).is_err());
        assert!(declaration(Some(OsStr::new("1")), Some(OsStr::new("128:160"))).is_err());
        assert!(
            declaration(Some(OsStr::new("bogus")), Some(OsStr::new("128")))
                .unwrap()
                .is_empty()
        );
    }
}
