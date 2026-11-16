//! Explicit 64-bit Darwin PF state control. No policy, routes or devices are
//! configured implicitly. A complete snapshot precedes every mutating sweep.
mod abi;
use abi::{Id, Key, Record, STATE_BYTES, invalid};
use std::{
    fmt,
    fs::{File, OpenOptions},
    io,
    net::IpAddr,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    time::Instant,
};

/// Complete native table and selected-flow resource bounds.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum complete native state rows, including unrelated traffic.
    pub states: usize,
    /// Maximum states for selected local-source DNS flows.
    pub targets: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            states: 65536,
            targets: 4096,
        }
    }
}
impl Limits {
    fn validate(self) -> io::Result<()> {
        if self.states == 0
            || self.targets == 0
            || self
                .states
                .checked_add(1)
                .and_then(|rows| rows.checked_mul(STATE_BYTES))
                .is_none_or(|bytes| bytes > i32::MAX as usize)
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(())
    }
}
struct Selection {
    ids: Vec<Id>,
    keys: Vec<Key>,
}
enum Phase {
    Ready(usize),
    Failed,
}
#[derive(Debug)]
struct Failure {
    original: io::Error,
    attempted: usize,
    completed: usize,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}; PF state calls attempted={}, completed={}",
            self.original, self.attempted, self.completed
        )
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}

/// One original PF descriptor, DNS selection, and immutable native deadline.
/// Every kill uses exact UDP endpoints and the original PF interface name.
/// The scope includes every native state for these local-source UDP DNS flows,
/// regardless of PF's internal direction. Matching replacement state may also
/// be removed: Darwin's kill predicate has no state-ID comparator. Retired
/// states are not reconstructed.
pub struct DnsStates {
    file: File,
    buffer: Vec<u8>,
    selection: Selection,
    limits: Limits,
    until: Instant,
    phase: Phase,
    attempted: usize,
    completed: usize,
}
impl fmt::Debug for DnsStates {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsStates")
            .field("states", &self.selection.ids.len())
            .field("flows", &self.selection.keys.len())
            .field("attempted", &self.attempted)
            .field("completed", &self.completed)
            .finish_non_exhaustive()
    }
}
fn timely(until: Instant) -> io::Result<()> {
    if Instant::now() >= until {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original PF state deadline",
        ))
    } else {
        Ok(())
    }
}

#[expect(
    unsafe_code,
    reason = "uname fills one initialized SDK character-array record; no pointer escapes this synchronous version observation"
)]
fn qualify_abi() -> io::Result<()> {
    // SAFETY: every SDK field is a character array, for which all zeroes are valid.
    let mut name: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: exact writable SDK layout remains exclusively borrowed for uname.
    if unsafe { libc::uname(&mut name) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut major = 0_u32;
    for byte in name.release {
        if byte == b'.' as libc::c_char {
            if (20..=27).contains(&major) {
                return Ok(());
            }
            break;
        }
        let byte = byte as u8;
        if !byte.is_ascii_digit() {
            break;
        }
        major = major
            .checked_mul(10)
            .and_then(|value| value.checked_add(u32::from(byte - b'0')))
            .ok_or_else(invalid)?;
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "unqualified Darwin PF state ABI",
    ))
}

fn select(bytes: &[u8], local: &[IpAddr], limits: Limits) -> io::Result<Selection> {
    if !bytes.len().is_multiple_of(STATE_BYTES) || bytes.len() / STATE_BYTES > limits.states {
        return Err(invalid());
    }
    let mut ids = Vec::new();
    let mut keys = Vec::new();
    for bytes in bytes.as_chunks::<STATE_BYTES>().0 {
        let record = Record::parse(bytes)?;
        if let Some(key) = record.dns(local) {
            if ids.len() == limits.targets {
                return Err(io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "PF DNS candidate capacity",
                ));
            }
            ids.try_reserve(1).map_err(io::Error::other)?;
            keys.try_reserve(1).map_err(io::Error::other)?;
            ids.push(record.id());
            keys.push(key);
        }
    }
    ids.sort_unstable();
    if ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invalid());
    }
    keys.sort_unstable();
    keys.dedup();
    Ok(Selection { ids, keys })
}

fn absence(bytes: &[u8], original: &[Id]) -> io::Result<()> {
    if !bytes.len().is_multiple_of(STATE_BYTES) {
        return Err(invalid());
    }
    for bytes in bytes.as_chunks::<STATE_BYTES>().0 {
        let id = Record::parse(bytes)?.id();
        if original.binary_search(&id).is_ok() {
            return Err(io::Error::other(
                "original Darwin DNS PF state retirement unconfirmed",
            ));
        }
    }
    Ok(())
}

#[expect(
    unsafe_code,
    reason = "The exact Darwin ioctl borrows one initialized fixed SDK layout and the original owned descriptor synchronously"
)]
fn query(file: &File, buffer: &mut abi::States, until: Instant) -> io::Result<()> {
    timely(until)?;
    // SAFETY: writable fixed layout and its optional caller-owned output buffer
    // remain live and exclusively borrowed until this synchronous call returns.
    if unsafe { libc::ioctl(file.as_raw_fd(), abi::GET_STATES, buffer) } != 0 {
        return Err(io::Error::last_os_error());
    }
    timely(until)
}

fn snapshot(file: &File, data: &mut Vec<u8>, limits: Limits, until: Instant) -> io::Result<()> {
    capture(data, limits, until, |output| query(file, output, until))
}

fn capture(
    data: &mut Vec<u8>,
    limits: Limits,
    until: Instant,
    mut query: impl FnMut(&mut abi::States) -> io::Result<()>,
) -> io::Result<()> {
    let mut probe = abi::States {
        bytes: 0,
        buffer: std::ptr::null_mut(),
    };
    timely(until)?;
    query(&mut probe)?;
    let needed = usize::try_from(probe.bytes).map_err(|_| invalid())?;
    if !needed.is_multiple_of(STATE_BYTES) {
        return Err(invalid());
    }
    // The size probe can count states unlinked before the actual read. Keep
    // that estimate within our bound and qualify the complete returned table.
    let mut rows = (needed / STATE_BYTES + 1).min(limits.states + 1).max(1);
    loop {
        timely(until)?;
        let bytes = rows.checked_mul(STATE_BYTES).ok_or_else(invalid)?;
        if bytes > data.len() {
            data.try_reserve_exact(bytes - data.len())
                .map_err(io::Error::other)?;
        }
        data.resize(bytes, 0);
        let mut output = abi::States {
            bytes: i32::try_from(bytes).map_err(|_| invalid())?,
            buffer: data.as_mut_ptr(),
        };
        query(&mut output)?;
        timely(until)?;
        let returned = usize::try_from(output.bytes).map_err(|_| invalid())?;
        if !returned.is_multiple_of(STATE_BYTES) || returned > bytes {
            return Err(invalid());
        }
        if returned < bytes {
            data.truncate(returned);
            return Ok(());
        }
        // An exactly full native buffer can be a truncated prefix. Grow within
        // the original bound/deadline instead of certifying that prefix.
        let maximum = limits.states + 1;
        if rows == maximum {
            return Err(invalid());
        }
        rows = rows.saturating_mul(2).min(maximum);
    }
}

impl DnsStates {
    /// Open the original PF device and preflight the whole DNS selection before
    /// admitting any kill. `local` is the caller's native assigned-address scope.
    ///
    /// # Errors
    /// Native, capacity and malformed snapshot errors leave
    /// kernel state untouched. Requires permission to open `/dev/pf` read/write.
    pub fn select(local: &[IpAddr], until: Instant, limits: Limits) -> io::Result<Self> {
        limits.validate()?;
        timely(until)?;
        qualify_abi()?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open("/dev/pf")?;
        use std::os::unix::fs::FileTypeExt;
        if !file.metadata()?.file_type().is_char_device() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "PF path is not a character device",
            ));
        }
        let mut buffer = Vec::new();
        snapshot(&file, &mut buffer, limits, until)?;
        let selection = select(&buffer, local, limits)?;
        timely(until)?;
        Ok(Self {
            file,
            buffer,
            selection,
            limits,
            until,
            phase: Phase::Ready(0),
            attempted: 0,
            completed: 0,
        })
    }
    /// Complete one exact selected-flow kill; false means no target remains.
    /// A true result is a command completion, not a count of deleted states.
    /// Call `finish` to confirm absence of every original selected state ID.
    ///
    /// # Errors
    /// Any error permanently removes mutation admission from this owner. A
    /// completed late syscall can already have removed state; Drop only closes
    /// the original descriptor. Synchronous kernel calls cannot be canceled.
    pub fn retire_next(&mut self) -> io::Result<bool> {
        self.advance().map_err(|error| self.failure(error))
    }
    fn failure(&self, original: io::Error) -> io::Error {
        io::Error::new(
            original.kind(),
            Failure {
                original,
                attempted: self.attempted,
                completed: self.completed,
            },
        )
    }
    #[expect(
        unsafe_code,
        reason = "The original descriptor and fully initialized aligned216-byte Darwin selector stay borrowed for one synchronous ioctl"
    )]
    fn advance(&mut self) -> io::Result<bool> {
        let next = match self.phase {
            Phase::Ready(next) => next,
            Phase::Failed => {
                return Err(io::Error::other(
                    "original PF state retirement already failed",
                ));
            }
        };
        let Some(key) = self.selection.keys.get(next) else {
            return Ok(false);
        };
        self.phase = Phase::Failed;
        timely(self.until)?;
        let mut command = key.command();
        self.attempted += 1;
        // SAFETY: command contains only exact UDP endpoints and an original
        // terminated interface name; this private ABI accepts the aligned bytes.
        if unsafe { libc::ioctl(self.file.as_raw_fd(), abi::KILL_STATES, &mut command) } != 0 {
            return Err(io::Error::last_os_error());
        }
        self.completed += 1;
        timely(self.until)?;
        self.phase = Phase::Ready(next + 1);
        Ok(true)
    }
    /// Consume this owner after complete-table original-ID readback.
    ///
    /// # Errors
    /// Refuses an unfinished/failed sweep, incomplete readback, surviving original
    /// identity or expired original deadline. No new kill or rollback is attempted.
    pub fn finish(mut self) -> io::Result<()> {
        let result = (|| {
            if !matches!(self.phase, Phase::Ready(next) if next == self.selection.keys.len()) {
                return Err(io::Error::other("original PF state sweep is incomplete"));
            }
            snapshot(&self.file, &mut self.buffer, self.limits, self.until)?;
            absence(&self.buffer, &self.selection.ids)?;
            timely(self.until)
        })();
        result.map_err(|error| self.failure(error))
    }
}

#[cfg(test)]
mod tests;
