//! Shared source-shaped native GNUnet process ownership and launch port.
//! No libgnunet production FFI is used; real native admission is distinct from
//! target exec or service readiness. The caller retains independent wait rights.
use crate::native_spawn;
pub use crate::readiness;
use gnunet_config::{Configuration, Environment};
use nix::{
    fcntl::{FcntlArg, FdFlag, OFlag, fcntl},
    unistd::{AccessFlags, Pid, access},
};
use std::{
    collections::{BTreeMap, VecDeque},
    ffi::{CString, OsStr, OsString},
    io,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
        unix::ffi::{OsStrExt, OsStringExt},
    },
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::signal::unix::{Signal, SignalKind, signal};
/// An immutable explicit environment/cwd snapshot; constructing it never mutates
/// the calling process or another task's environment.
#[derive(Clone, Debug)]
pub struct EnvironmentSnapshot {
    values: BTreeMap<Vec<u8>, Vec<u8>>,
    cwd: PathBuf,
}
impl EnvironmentSnapshot {
    /// Read this process's current native environment and cwd.
    pub fn system() -> io::Result<Self> {
        let mut values = BTreeMap::new();
        for (k, v) in std::env::vars_os() {
            values.insert(k.into_vec(), v.into_vec());
        }
        let cwd = std::env::current_dir().unwrap_or_else(|_| {
            PathBuf::from(OsString::from_vec(
                values
                    .get(b"PWD".as_slice())
                    .cloned()
                    .unwrap_or_else(|| b"./".to_vec()),
            ))
        });
        Ok(Self { values, cwd })
    }
    /// Explicit native environment for isolated embeddings/children. This does
    /// not set a process-global variable or change its current directory.
    pub fn from_values(
        values: impl IntoIterator<Item = (OsString, OsString)>,
        cwd: PathBuf,
    ) -> Result<Self, LaunchError> {
        if !cwd.is_absolute() || cwd.as_os_str().as_bytes().contains(&0) {
            return Err(LaunchError::InvalidInput);
        }
        let mut out = BTreeMap::new();
        for (k, v) in values {
            let (k, v) = (k.into_vec(), v.into_vec());
            if k.is_empty() || k.contains(&0) || k.contains(&b'=') || v.contains(&0) {
                return Err(LaunchError::InvalidInput);
            }
            out.insert(k, v);
        }
        Ok(Self { values: out, cwd })
    }
    fn strings(&self, maximum: usize) -> Result<Vec<CString>, LaunchError> {
        let mut total = 0usize;
        let mut out = Vec::new();
        out.try_reserve_exact(self.values.len())
            .map_err(|_| LaunchError::Capacity)?;
        for (k, v) in &self.values {
            total = total
                .checked_add(k.len())
                .and_then(|n| n.checked_add(v.len()))
                .and_then(|n| n.checked_add(2))
                .ok_or(LaunchError::Capacity)?;
            if total > maximum {
                return Err(LaunchError::Capacity);
            }
            let mut b = Vec::new();
            b.try_reserve_exact(k.len() + v.len() + 1)
                .map_err(|_| LaunchError::Capacity)?;
            b.extend(k);
            b.push(b'=');
            b.extend(v);
            out.push(CString::new(b).map_err(|_| LaunchError::InvalidInput)?);
        }
        Ok(out)
    }
}
impl Environment for EnvironmentSnapshot {
    fn variable(&self, name: &[u8]) -> Option<Vec<u8>> {
        self.values.get(name).cloned()
    }
    fn current_dir(&self) -> io::Result<PathBuf> {
        Ok(self.cwd.clone())
    }
}
/// Explicit local limits, not GNUnet configuration keys or protocol bounds.
#[derive(Clone, Copy, Debug)]
pub struct LaunchLimits {
    /// Maximum complete command text bytes.
    pub max_command_bytes: usize,
    /// Maximum parsed native arguments, including argv0.
    pub max_arguments: usize,
    /// Maximum children retained until real waitpid completion.
    pub max_children: usize,
    /// Maximum total native key/value environment bytes including separators.
    pub max_environment_bytes: usize,
}
impl Default for LaunchLimits {
    fn default() -> Self {
        Self {
            max_command_bytes: 1024 * 1024,
            max_arguments: 4096,
            max_children: 64,
            max_environment_bytes: 4 * 1024 * 1024,
        }
    }
}
/// Real preparation/OS resource errors, distinct from source callback outcomes.
#[derive(Debug)]
pub enum LaunchError {
    /// Explicit finite resource bound was reached; no business outcome invented.
    Capacity,
    /// Original child/writer belongs to a foreign registry or was actually retired.
    Stale,
    /// Native command/environment contained an unrepresentable NUL/key.
    InvalidInput,
    /// Original configuration expansion/resource failure.
    Configuration(gnunet_config::Error),
    /// Actual pipe/spawn/poll/wait error.
    Io(io::Error),
}
impl std::fmt::Display for LaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Capacity => f.write_str("ARM launch resource capacity"),
            Self::Stale => f.write_str("stale original child authority"),
            Self::InvalidInput => f.write_str("invalid ARM native launch input"),
            Self::Configuration(e) => write!(f, "ARM configuration: {e}"),
            Self::Io(e) => write!(f, "ARM launch I/O: {e}"),
        }
    }
}
impl std::error::Error for LaunchError {}
impl From<io::Error> for LaunchError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<nix::errno::Errno> for LaunchError {
    fn from(e: nix::errno::Errno) -> Self {
        Self::Io(e.into())
    }
}
impl From<gnunet_config::Error> for LaunchError {
    fn from(e: gnunet_config::Error) -> Self {
        Self::Configuration(e)
    }
}
enum Executable {
    Allowed,
    Refused(Option<io::Error>),
}
fn nonblocking(fd: &OwnedFd) -> io::Result<()> {
    let flags = OFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFL)?);
    fcntl(fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;
    fcntl(fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
    Ok(())
}
/// Create one uniquely owned nonblocking, close-on-exec pipe above standard FDs.
/// This performs native I/O without registering a reactor or transferring either end.
pub fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let (read, write) = std::io::pipe()?;
    let (read, write): (OwnedFd, OwnedFd) = (read.into(), write.into());
    let read = native_spawn::lift(read)?;
    let write = native_spawn::lift(write)?;
    nonblocking(&read)?;
    nonblocking(&write)?;
    Ok((read, write))
}
/// Parse exactly the two original C passes, including quote-state carry and last
/// token length. Only literal spaces delimit; apostrophes/tabs are ordinary data.
/// Opaque bytes are retained and the effective C string stops at its first NUL.
/// This function never invokes a shell or executes a command.
pub fn parse_command(
    command: &[u8],
    maximum_arguments: usize,
) -> Result<Vec<OsString>, LaunchError> {
    let len = command
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(command.len());
    let mut cmd = Vec::new();
    cmd.try_reserve_exact(len + 1)
        .map_err(|_| LaunchError::Capacity)?;
    cmd.extend_from_slice(&command[..len]);
    cmd.push(0);
    let mut quoted = false;
    let mut count = 1usize;
    let mut i = 0usize;
    while i < len {
        match cmd[i] {
            b'"' => quoted = !quoted,
            b'\\' => i += 1,
            b' ' => {
                if !quoted {
                    count = count.checked_add(1).ok_or(LaunchError::Capacity)?;
                }
                while cmd[i + 1] == b' ' {
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    // The C allocation bound is checked separately from actual argument count.
    if count > maximum_arguments.saturating_add(1) {
        return Err(LaunchError::Capacity);
    }
    let mut result = Vec::new();
    result
        .try_reserve_exact(count.min(maximum_arguments))
        .map_err(|_| LaunchError::Capacity)?;
    let (mut start, mut skip) = (0usize, 0usize);
    i = 0;
    let append = |out: &mut Vec<OsString>,
                  buf: &[u8],
                  start: usize,
                  maximum: usize|
     -> Result<(), LaunchError> {
        if out.len() == maximum_arguments {
            return Err(LaunchError::Capacity);
        }
        let end = start.saturating_add(maximum).min(buf.len());
        let bytes = &buf[start..end];
        let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
        out.push(OsString::from_vec(bytes[..end].to_vec()));
        Ok(())
    };
    while i < len {
        match cmd[i] {
            b'"' => {
                quoted = !quoted;
                skip += 1;
            }
            b' ' => {
                if !quoted && i != start {
                    append(&mut result, &cmd, start, i - start - skip)?;
                    skip = 0;
                }
                while cmd[i + 1] == b' ' {
                    i += 1;
                }
                if !quoted {
                    start = i + 1;
                }
            }
            b'\\' => {
                i += 1;
                skip += 1;
                cmd[i - skip] = cmd[i];
            }
            c => cmd[i - skip] = c,
        }
        i += 1;
    }
    if i != start {
        append(&mut result, &cmd, start, i - start)?;
    }
    Ok(result)
}
/// Actual native child completion, never a service-ready/operation result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildExit {
    /// Actual WIFEXITED exit code.
    Exited(i32),
    /// Actual WIFSIGNALED signal and OS core-dump flag.
    Signaled {
        /// Native signal number.
        signal: i32,
        /// Actual wait status core-dump indicator.
        core_dumped: bool,
    },
}
#[derive(Debug)]
struct RegistryIdentity {
    _nonzero: u8,
}
/// Lookup capability for one original admitted child, never numeric-PID authority
/// by itself. Clones share identity only; the registry uniquely owns PID/wait/pipe.
#[derive(Clone, Debug)]
pub struct OriginalChild {
    identity: Arc<RegistryIdentity>,
    generation: u64,
    pid: u32,
}
impl PartialEq for OriginalChild {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.identity, &other.identity)
            && self.generation == other.generation
            && self.pid == other.pid
    }
}
impl Eq for OriginalChild {}
impl std::hash::Hash for OriginalChild {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::ptr::hash(Arc::as_ptr(&self.identity), state);
        std::hash::Hash::hash(&self.generation, state);
        std::hash::Hash::hash(&self.pid, state);
    }
}
impl OriginalChild {
    /// Diagnostic original PID. Passing this number elsewhere does not transfer
    /// wait/signal authority, and it must never be used after this child's reap.
    pub fn pid(&self) -> u32 {
        self.pid
    }
}
/// Opaque capability naming this original child's registry-owned control writer.
/// No OS descriptor is cloned, transferred or constructed by cloning this token.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ControlWriterToken {
    child: OriginalChild,
}
impl ControlWriterToken {
    /// Original child associated with this actual writer.
    pub fn child(&self) -> &OriginalChild {
        &self.child
    }
}
/// One original PID's actual consuming waitpid observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reaped {
    /// Positive original PID, retired before exposing this observation.
    pub pid: u32,
    /// Original generation/registry identity, already retired for native actions.
    pub child: OriginalChild,
    /// Actual exit/signalled status; no inferred readiness.
    pub exit: ChildExit,
}
/// Validated kernel resource counters from this original child's consuming
/// wait4 observation. These are lifetime measurements, not sampled estimates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceUsage {
    /// Actual user CPU time in microseconds.
    pub user_micros: u64,
    /// Actual system CPU time in microseconds.
    pub system_micros: u64,
    /// Native maximum resident-set counter: bytes on macOS, KiB on Linux.
    pub max_rss: u64,
    /// Actual block input operations reported by the kernel.
    pub in_blocks: u64,
    /// Actual block output operations reported by the kernel.
    pub out_blocks: u64,
    /// Actual voluntary context switches reported by the kernel.
    pub voluntary_switches: u64,
    /// Actual involuntary context switches reported by the kernel.
    pub involuntary_switches: u64,
}
impl ResourceUsage {
    fn from_native(usage: &libc::rusage) -> io::Result<Self> {
        fn invalid() -> io::Error {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid native child resource usage",
            )
        }
        fn micros(value: libc::timeval) -> io::Result<u64> {
            let seconds = u64::try_from(value.tv_sec).map_err(|_| invalid())?;
            let fraction = u64::try_from(value.tv_usec).map_err(|_| invalid())?;
            if fraction >= 1_000_000 {
                return Err(invalid());
            }
            seconds
                .checked_mul(1_000_000)
                .and_then(|base| base.checked_add(fraction))
                .ok_or_else(invalid)
        }
        fn counter(value: libc::c_long) -> io::Result<u64> {
            u64::try_from(value).map_err(|_| invalid())
        }
        Ok(Self {
            user_micros: micros(usage.ru_utime)?,
            system_micros: micros(usage.ru_stime)?,
            max_rss: counter(usage.ru_maxrss)?,
            in_blocks: counter(usage.ru_inblock)?,
            out_blocks: counter(usage.ru_oublock)?,
            voluntary_switches: counter(usage.ru_nvcsw)?,
            involuntary_switches: counter(usage.ru_nivcsw)?,
        })
    }
}
struct ChildRecord {
    pid: Pid,
    child: OriginalChild,
    control: Option<OwnedFd>,
}
/// Exact source signal-attempt result; neither variant proves process death.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalAttempt {
    /// Exactly one signal byte was really written to the original control pipe.
    ControlPipe,
    /// No usable pipe or failed/short pipe write; the actual original PID's kill
    /// syscall returned success. Native errno on failure remains an error.
    NativeKill,
}
/// Actual control-pipe syscall outcome, retained when native kill succeeds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PipeWriteOutcome {
    /// This original process has no control writer.
    Absent,
    /// Exactly one byte was really written.
    Complete,
    /// Source write returned a length other than exactly1.
    Short(usize),
    /// Source write returned this actual native IO error.
    Error {
        /// Portable IO error class.
        kind: io::ErrorKind,
        /// Native errno, if supplied by the OS.
        errno: Option<i32>,
    },
}
/// Observable actual signal route and its original write diagnostic. It does not
/// acknowledge application processing or imply that the child has terminated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignalReport {
    /// Actual successful source route.
    pub attempt: SignalAttempt,
    /// Exact preceding write result; a fallback does not discard this evidence.
    pub pipe: PipeWriteOutcome,
}
/// Caller-owned bounded wait and control authority for actually admitted PIDs.
/// This value outlives launcher/host borrows. Final Drop does not kill or wait a
/// daemon; retain it and explicitly drain original children, like std Child.
/// External/concurrent wait of these PIDs violates its exclusive wait contract.
#[must_use = "retain and explicitly drain/reap original children after the host is dropped"]
pub struct ChildRegistry {
    children: Vec<ChildRecord>,
    completed: VecDeque<Reaped>,
    resource_usage: Option<VecDeque<Option<ResourceUsage>>>,
    child_signal: Option<Signal>,
    maximum: usize,
    identity: Arc<RegistryIdentity>,
    generation: u64,
}
impl ChildRegistry {
    /// Allocate bounded metadata; no signal handler/runtime/child exists yet.
    pub fn new(maximum: usize) -> Result<Self, LaunchError> {
        if maximum == 0 {
            return Err(LaunchError::InvalidInput);
        }
        let mut children = Vec::new();
        children
            .try_reserve_exact(maximum)
            .map_err(|_| LaunchError::Capacity)?;
        let mut completed = VecDeque::new();
        completed
            .try_reserve_exact(maximum)
            .map_err(|_| LaunchError::Capacity)?;
        Ok(Self {
            children,
            completed,
            resource_usage: None,
            child_signal: None,
            maximum,
            identity: Arc::new(RegistryIdentity { _nonzero: 1 }),
            generation: 0,
        })
    }
    /// Consume an actual wait event and release its metadata credit.
    pub fn take_reaped(&mut self) -> Option<Reaped> {
        self.take_completed_with_usage().map(|(event, _)| event)
    }
    /// Enable consuming wait4 resource observations before admitting children.
    /// All queue capacity is reserved here; reaping requires no new allocation.
    /// Repeated calls after successful enabling do not reset queued observations.
    pub fn enable_resource_usage(&mut self) -> Result<(), LaunchError> {
        if self.resource_usage.is_some() {
            return Ok(());
        }
        if !self.children.is_empty() || !self.completed.is_empty() {
            return Err(LaunchError::InvalidInput);
        }
        let mut usage = VecDeque::new();
        usage
            .try_reserve_exact(self.maximum)
            .map_err(|_| LaunchError::Capacity)?;
        self.resource_usage = Some(usage);
        Ok(())
    }
    /// Consume the original wait event and its paired resource observation.
    /// `None` means collection was disabled, or an invalid kernel counter already
    /// caused `reap_completed` to report an error while retaining this real exit.
    /// Taking either event form releases both queues' original metadata credit.
    pub fn take_completed_with_usage(&mut self) -> Option<(Reaped, Option<ResourceUsage>)> {
        let event = self.completed.pop_front()?;
        let usage = self
            .resource_usage
            .as_mut()
            .and_then(VecDeque::pop_front)
            .flatten();
        Some((event, usage))
    }
    /// Diagnostics for still-original, unreaped PIDs; no implicit signal request.
    pub fn child_pids(&self) -> impl Iterator<Item = u32> + '_ {
        self.children.iter().map(|record| record.child.pid)
    }
    /// Lookup capabilities for original currently owned children.
    pub fn children(&self) -> impl Iterator<Item = &OriginalChild> + '_ {
        self.children.iter().map(|record| &record.child)
    }
    /// Whether this registry still owns exactly this original wait/signal authority.
    pub fn owns(&self, child: &OriginalChild) -> bool {
        self.children.iter().any(|record| record.child == *child)
    }
    /// Prepare SIGCHLD in the caller's reactor before actual admission.
    pub fn prepare(&mut self) -> Result<(), LaunchError> {
        if self.child_signal.is_none() {
            if tokio::runtime::Handle::try_current().is_err() {
                return Err(io::Error::other("child registry requires a Tokio reactor").into());
            }
            self.child_signal = Some(signal(SignalKind::child())?);
        }
        Ok(())
    }
    /// Actual original PIDs still awaiting consuming waitpid.
    pub fn pending_children(&self) -> usize {
        self.children.len()
    }
    /// Recoverable active/completed-event credit check, independent of the
    /// permanent generation limit. Client drivers may defer only for this credit.
    pub fn credit_available(&self, maximum_children: usize) -> bool {
        self.children.len() < maximum_children
            && self.children.len() + self.completed.len() < self.maximum
    }
    /// Full admission preflight. Generation exhaustion returns a real resource
    /// error when spawn is attempted; cleanup/signal/wait never mint generations.
    pub fn capacity_available(&self, maximum_children: usize) -> bool {
        self.credit_available(maximum_children) && self.generation < u64::MAX
    }
    /// Poll the real SIGCHLD notification without removing wait authority.
    pub fn poll_child_signal(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), LaunchError>> {
        if self.children.is_empty() {
            return std::task::Poll::Pending;
        }
        let Some(signal) = &mut self.child_signal else {
            return std::task::Poll::Ready(Err(
                io::Error::other("missing owned child event port").into()
            ));
        };
        let notification = signal.poll_recv(cx).map(|value| {
            value.ok_or_else(|| io::Error::other("child signal stream closed").into())
        });
        if notification.is_ready() {
            // Tokio replaces its notification future after Ready. The next
            // poll must register that future's waiter even when this SIGCHLD
            // concerned another registry and our consuming waits found no exit.
            // Otherwise a driver returning Pending can sleep through its own
            // child's later death. One actual notification grants one repoll.
            cx.waker().wake_by_ref();
        }
        notification
    }
    /// Nonblocking wait of only this registry's original PIDs. EINTR keeps
    /// authority for retry; ECHILD removes it and closes its control writer before
    /// returning the real ownership-loss error, without fabricating an exit.
    /// Resource collection selects wait4; other registries retain waitpid.
    /// Invalid resource counters report an error after retaining the actual exit.
    pub fn reap_completed(&mut self) -> Result<usize, LaunchError> {
        let mut count = 0;
        let mut i = 0;
        while i < self.children.len() {
            let pid = self.children[i].pid;
            let waited = if self.resource_usage.is_some() {
                native_spawn::wait_original_usage(pid)
                    .map(|observation| observation.map(|value| (value.status, value.resources)))
            } else {
                native_spawn::wait_original_status(pid)
                    .map(|observation| observation.map(|status| (status, None)))
            };
            let (exit, resources) = match waited {
                Ok(Some((status, resources))) if libc::WIFEXITED(status) => (
                    Some(ChildExit::Exited(libc::WEXITSTATUS(status))),
                    resources,
                ),
                Ok(Some((status, resources))) if libc::WIFSIGNALED(status) => (
                    Some(ChildExit::Signaled {
                        signal: libc::WTERMSIG(status),
                        core_dumped: libc::WCOREDUMP(status),
                    }),
                    resources,
                ),
                Ok(_) => (None, None),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => (None, None),
                Err(error) if error.raw_os_error() == Some(libc::ECHILD) => {
                    drop(self.children.swap_remove(i));
                    return Err(error.into());
                }
                Err(error) => return Err(error.into()),
            };
            if let Some(exit) = exit {
                let record = self.children.swap_remove(i);
                let event = Reaped {
                    pid: record.child.pid,
                    child: record.child.clone(),
                    exit,
                };
                drop(record);
                self.completed.push_back(event);
                if let Some(usage) = &mut self.resource_usage {
                    let converted = resources
                        .as_ref()
                        .ok_or_else(|| io::Error::other("terminal wait4 omitted resource usage"))
                        .and_then(ResourceUsage::from_native);
                    match converted {
                        Ok(resource) => usage.push_back(Some(resource)),
                        Err(error) => {
                            // The consuming wait is already real. Keep the
                            // original exit and aligned metadata before reporting
                            // its independent resource validation failure.
                            usage.push_back(None);
                            return Err(error.into());
                        }
                    }
                }
                count += 1;
            } else {
                i += 1;
            }
        }
        Ok(count)
    }
    /// Wait for actual completion; canceling this future retains every child and
    /// control writer. This function sends no signal and never infers readiness.
    pub async fn drain_children(&mut self) -> Result<(), LaunchError> {
        while !self.children.is_empty() {
            self.reap_completed()?;
            if self.children.is_empty() {
                break;
            }
            let Some(signal) = &mut self.child_signal else {
                return Err(io::Error::other("missing owned child event port").into());
            };
            if signal.recv().await.is_none() {
                return Err(io::Error::other("child signal stream closed").into());
            }
        }
        Ok(())
    }
    /// Attempt the official pipe-then-kill signal policy for this original child.
    /// A one-byte pipe success is not death. This does not change the parent's
    /// SIGPIPE disposition/mask: a default unblocked SIGPIPE may terminate the
    /// caller on a broken pipe, as native C write does; Rust-host tests use IGN.
    pub fn signal(
        &mut self,
        child: &OriginalChild,
        signal: i32,
    ) -> Result<SignalAttempt, LaunchError> {
        self.signal_report(child, signal)
            .map(|report| report.attempt)
    }
    /// Apply the same source signal policy while preserving the actual write
    /// outcome. In particular EINTR, EPIPE and EAGAIN remain distinguishable.
    pub fn signal_report(
        &mut self,
        child: &OriginalChild,
        signal: i32,
    ) -> Result<SignalReport, LaunchError> {
        let mut pipe = PipeWriteOutcome::Absent;
        let attempt = self.signal_using(child, signal, |writer, byte| {
            let result = nix::unistd::write(writer, byte).map_err(io::Error::from);
            pipe = match &result {
                Ok(1) => PipeWriteOutcome::Complete,
                Ok(n) => PipeWriteOutcome::Short(*n),
                Err(error) => PipeWriteOutcome::Error {
                    kind: error.kind(),
                    errno: error.raw_os_error(),
                },
            };
            result
        })?;
        Ok(SignalReport { attempt, pipe })
    }
    /// Issue a native signal to this registry's original unreaped child.
    ///
    /// This direct route supports terminal escalation such as SIGKILL after an
    /// original bounded shutdown wait. It does not write to the control pipe.
    /// Foreign or reaped child capabilities fail before any native operation.
    /// Success means only that the original kill syscall returned zero; retain
    /// this registry's exclusive wait authority until an actual consuming reap.
    /// Native signal validation and errno are preserved, including signal zero.
    pub fn signal_native(&mut self, child: &OriginalChild, signal: i32) -> Result<(), LaunchError> {
        let record = self
            .children
            .iter()
            .find(|record| record.child == *child)
            .ok_or(LaunchError::Stale)?;
        native_spawn::signal_original(record.pid, signal)?;
        Ok(())
    }
    fn signal_using(
        &mut self,
        child: &OriginalChild,
        signal: i32,
        mut write: impl FnMut(&OwnedFd, &[u8]) -> io::Result<usize>,
    ) -> Result<SignalAttempt, LaunchError> {
        let record = self
            .children
            .iter()
            .find(|record| record.child == *child)
            .ok_or(LaunchError::Stale)?;
        if let Some(writer) = &record.control
            && write(writer, &[signal as u8]).is_ok_and(|written| written == 1)
        {
            return Ok(SignalAttempt::ControlPipe);
        }
        // Native kill permits signal0. Invalid/unsupported values preserve EINVAL.
        native_spawn::signal_original(record.pid, signal)?;
        Ok(SignalAttempt::NativeKill)
    }
    /// Close this original registry-owned writer without discarding PID/wait
    /// authority. ARM-self calls this after admission to match process_destroy;
    /// managed services retain it for later pipe-first signal attempts.
    pub fn close_control(&mut self, token: &ControlWriterToken) -> Result<(), LaunchError> {
        let record = self
            .children
            .iter_mut()
            .find(|record| record.child == token.child && record.control.is_some())
            .ok_or(LaunchError::Stale)?;
        drop(record.control.take());
        Ok(())
    }
    /// Signal with the checked actual writer capability and retain its native
    /// write diagnostic, without cloning or transferring the OS descriptor.
    pub fn signal_control_report(
        &mut self,
        token: &ControlWriterToken,
        signal: i32,
    ) -> Result<SignalReport, LaunchError> {
        if !self
            .children
            .iter()
            .any(|record| record.child == token.child && record.control.is_some())
        {
            return Err(LaunchError::Stale);
        }
        self.signal_report(&token.child, signal)
    }
    /// Signal only with the token minted for this actual registry-owned writer.
    /// Reaped/foreign generations reject before writing or issuing native kill.
    pub fn signal_control(
        &mut self,
        token: &ControlWriterToken,
        signal: i32,
    ) -> Result<SignalAttempt, LaunchError> {
        if !self
            .children
            .iter()
            .any(|record| record.child == token.child && record.control.is_some())
        {
            return Err(LaunchError::Stale);
        }
        self.signal(&token.child, signal)
    }
}

/// Native descriptor mapping with borrowed original ownership. Private staging
/// duplicates prevent overlapping child targets from clobbering later sources.
#[derive(Clone, Copy, Debug)]
pub struct DescriptorMap<'fd> {
    /// Original resource remains exclusively owned by its external caller.
    pub source: BorrowedFd<'fd>,
    /// Explicit nonnegative child descriptor; targets must be unique.
    pub target: i32,
}
/// Source-compatible inherited-stdio observation captured before launch resources
/// may occupy originally closed slots. It carries no owning FD or native mutation.
#[derive(Clone, Copy, Debug)]
pub struct StdioSnapshot {
    inheritance: u32,
    closed: u8,
}
impl StdioSnapshot {
    /// Read actual closed/CLOEXEC standard descriptor state without opening files.
    pub fn capture(inheritance: u32) -> Result<Self, LaunchError> {
        Ok(Self {
            inheritance,
            closed: native_spawn::inherited_closed_stdio(inheritance)?,
        })
    }
}
/// One source process-option environment mutation, applied after automatic
/// control/listener hints in original option order. None means unset.
#[derive(Clone, Debug)]
pub struct EnvironmentChange {
    /// Nonempty raw native key, without NUL or equals.
    pub key: OsString,
    /// Raw replacement value or an explicit unset.
    pub value: Option<OsString>,
}
/// Explicit source native process command. No shell expansion is performed.
/// filename is the actual execvp filename and may differ from argv0 (SIMPLE).
pub struct NativeCommand<'fd> {
    /// Raw native executable filename, independently checked and executed.
    pub filename: OsString,
    /// Complete raw argv, conventionally including argv0, and always NUL-free.
    /// Empty argv preserves run_command_argv native exec behavior.
    pub argv: Vec<OsString>,
    /// Immutable explicit native environment/cwd reference for checks.
    pub environment: EnvironmentSnapshot,
    /// Source explicit environment options, applied after native generated hints.
    pub environment_changes: Vec<EnvironmentChange>,
    /// Child-only cwd change; None preserves inherited actual process cwd.
    pub cwd: Option<PathBuf>,
    /// Official stdin/out/err bits1/2/4 and pipe-control bit8.
    pub stdio: u32,
    /// Optional real earlier stdio capture, for ARM-self's pre-readiness-pipe order.
    pub stdio_snapshot: Option<StdioSnapshot>,
    /// Source INHERIT_LSOCK order; can be a readiness WRITE pipe for ARM-self.
    /// Numeric LISTEN_FDNAMES are generated from actual private target FDs.
    pub listeners: Vec<BorrowedFd<'fd>>,
    /// Explicit native child mappings, with no parent ownership transfer.
    pub mappings: Vec<DescriptorMap<'fd>>,
}
/// Explicit host resource bounds for the shared process port.
#[derive(Clone, Copy, Debug)]
pub struct ProcessLimits {
    /// Existing command/argument/environment/active-child budgets.
    pub launch: LaunchLimits,
    /// Maximum helper/filename/cwd metadata bytes per string, independent of
    /// the original command's argv/text budget.
    pub max_auxiliary_bytes: usize,
    /// Maximum combined explicit and advertised descriptor mappings.
    pub max_descriptors: usize,
    /// Largest child descriptor number admitted by this host profile.
    pub max_descriptor_number: i32,
}
impl Default for ProcessLimits {
    fn default() -> Self {
        Self {
            launch: LaunchLimits::default(),
            max_auxiliary_bytes: 1024 * 1024,
            max_descriptors: 4096,
            max_descriptor_number: libc::FD_SETSIZE as i32 - 1,
        }
    }
}
/// A native-admission receipt. Target exec/readiness is deliberately not implied.
#[derive(Clone, Debug)]
pub struct Spawned {
    /// Lookup capability for this original PID/wait authority.
    pub child: OriginalChild,
    /// Present only when an actual parent control writer is registry-owned.
    pub control: Option<ControlWriterToken>,
}
/// Actual no-child refusal versus a real native admission.
#[derive(Debug)]
pub enum SpawnResult {
    /// Native helper/executable check or actual spawn failed without a child.
    Refused {
        /// Actual native diagnostic when provided by the source boundary.
        error: Option<io::Error>,
    },
    /// A real PID was installed in the caller registry before returning.
    Admitted(Spawned),
}
fn literal_path(environment: &EnvironmentSnapshot, path: &[u8]) -> PathBuf {
    let p = Path::new(OsStr::from_bytes(path));
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        environment.cwd.join(p)
    }
}
trait ExecutableIo {
    fn access_x(&mut self, path: &Path) -> io::Result<()>;
    fn real_uid(&mut self) -> u32;
    fn stat(&mut self, path: &Path) -> io::Result<()>;
}
struct NativeExecutableIo;
impl ExecutableIo for NativeExecutableIo {
    fn access_x(&mut self, path: &Path) -> io::Result<()> {
        access(path, AccessFlags::X_OK).map_err(io::Error::from)
    }
    fn real_uid(&mut self) -> u32 {
        nix::unistd::getuid().as_raw()
    }
    fn stat(&mut self, path: &Path) -> io::Result<()> {
        std::fs::metadata(path).map(|_metadata| ())
    }
}
fn executable_after_path(path: &Path, io: &mut impl ExecutableIo) -> Executable {
    if let Err(error) = io.access_x(path) {
        return Executable::Refused(Some(error));
    }
    if io.real_uid() == 0 {
        return Executable::Allowed;
    }
    match io.stat(path) {
        Ok(()) => Executable::Allowed,
        Err(error) => Executable::Refused(Some(error)),
    }
}
fn executable(
    config: &Configuration,
    environment: &EnvironmentSnapshot,
    name: &OsStr,
) -> Result<Executable, LaunchError> {
    let b = name.as_bytes();
    if b.is_empty() {
        return Ok(Executable::Refused(None));
    }
    if b.starts_with(b"/") || b.starts_with(b"./") {
        return Ok(executable_after_path(
            literal_path(environment, b).as_path(),
            &mut NativeExecutableIo,
        ));
    }
    let Some(paths) = environment.variable(b"PATH") else {
        return Ok(Executable::Refused(None));
    };
    for directory in paths.split(|byte| *byte == b':') {
        let mut p = directory.to_vec();
        p.push(b'/');
        p.extend_from_slice(b);
        let expanded = config.expand_filename(&p, environment)?;
        if std::fs::metadata(&expanded).is_ok_and(|metadata| metadata.is_file())
            && access(&expanded, AccessFlags::F_OK).is_ok()
        {
            return Ok(executable_after_path(
                literal_path(environment, &p).as_path(),
                &mut NativeExecutableIo,
            ));
        }
    }
    Ok(Executable::Refused(None))
}
/// Create the actual source-shaped nonblocking/CLOEXEC pipe, lifting low stdio
/// numbers without taking foreign descriptor ownership.
/// Admit one actual helper child and retain its original PID/control writer in
/// the caller registry before any return/await/callback. This executes no shell,
/// mutates no parent cwd/env/original fd flags, and uses one shared native boundary.
/// Caller serializes process-global cwd/signal changes with this synchronous call.
/// Resource/preparation errors return Err; actual executable/spawn no-child
/// failures are Refused. Target exec after helper admission can later exit1.
pub fn spawn(
    config: &Configuration,
    helper: &Path,
    command: NativeCommand<'_>,
    limits: ProcessLimits,
    registry: &mut ChildRegistry,
) -> Result<SpawnResult, LaunchError> {
    if limits.max_auxiliary_bytes == 0
        || limits.max_descriptor_number < 3
        || limits.launch.max_arguments == 0
        || limits.launch.max_command_bytes == 0
        || limits.launch.max_environment_bytes == 0
        || limits.launch.max_children == 0
    {
        return Err(LaunchError::InvalidInput);
    }
    if command.argv.len() > limits.launch.max_arguments
        || command
            .listeners
            .len()
            .checked_add(command.mappings.len())
            .is_none_or(|len| len > limits.max_descriptors)
    {
        return Err(LaunchError::Capacity);
    }
    if !registry.capacity_available(limits.launch.max_children) {
        return Err(LaunchError::Capacity);
    }
    let snapshot = match command.stdio_snapshot {
        Some(snapshot) if snapshot.inheritance == command.stdio => snapshot,
        Some(_) => return Err(LaunchError::InvalidInput),
        None => StdioSnapshot::capture(command.stdio)?,
    };
    if command.filename.as_bytes().len() > limits.max_auxiliary_bytes
        || helper.as_os_str().as_bytes().len() > limits.max_auxiliary_bytes
        || command
            .cwd
            .as_ref()
            .is_some_and(|path| path.as_os_str().as_bytes().len() > limits.max_auxiliary_bytes)
    {
        return Err(LaunchError::Capacity);
    }
    let filename =
        CString::new(command.filename.as_bytes()).map_err(|_| LaunchError::InvalidInput)?;
    let mut total = 0usize;
    for arg in &command.argv {
        total = total
            .checked_add(arg.as_bytes().len())
            .ok_or(LaunchError::Capacity)?;
        if arg.as_bytes().contains(&0) {
            return Err(LaunchError::InvalidInput);
        }
    }
    if total > limits.launch.max_command_bytes {
        return Err(LaunchError::Capacity);
    }
    if let Some(cwd) = &command.cwd
        && (!cwd.is_absolute() || cwd.as_os_str().as_bytes().contains(&0))
    {
        return Err(LaunchError::InvalidInput);
    }
    let mut targets = std::collections::BTreeSet::new();
    for mapping in &command.mappings {
        if mapping.target < 0
            || mapping.target > limits.max_descriptor_number
            || !targets.insert(mapping.target)
        {
            return Err(LaunchError::InvalidInput);
        }
    }
    if let Executable::Refused(error) = executable(config, &command.environment, &command.filename)?
    {
        return Ok(SpawnResult::Refused { error });
    }
    registry.prepare()?;
    let mut environment = command.environment;
    environment
        .values
        .remove(b"GNUNET_OS_CONTROL_PIPE".as_slice());
    let control = if command.stdio & 8 != 0 {
        Some(pipe()?)
    } else {
        None
    };
    let null_in = if command.stdio & 1 == 0 && !targets.contains(&0) {
        Some(native_spawn::lift(
            std::fs::File::open("/dev/null")?.into(),
        )?)
    } else {
        None
    };
    let null_out = if (command.stdio & 2 == 0 && !targets.contains(&1))
        || (command.stdio & 4 == 0 && !targets.contains(&2))
    {
        Some(native_spawn::lift(
            std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/null")?
                .into(),
        )?)
    } else {
        None
    };
    let minimum = targets
        .iter()
        .next_back()
        .copied()
        .unwrap_or(2)
        .max(2)
        .checked_add(1)
        .ok_or(LaunchError::Capacity)?;
    let mut staged = Vec::new();
    let mut reservations = Vec::new();
    let mut target_fds = Vec::new();
    let mut advertised = Vec::new();
    let mut stage = |source: BorrowedFd<'_>, target: Option<i32>| -> Result<i32, LaunchError> {
        let target = match target {
            Some(target) => target,
            None => {
                let reserved = native_spawn::duplicate_at_least(source, minimum)?;
                let target = reserved.as_raw_fd();
                reservations.push(reserved);
                target
            }
        };
        // Distinct source/target is essential across the helper and final exec:
        // do not rely on a platform's same-FD spawn dup action clearing CLOEXEC.
        let own = native_spawn::duplicate_at_least(source, minimum)?;
        if own.as_raw_fd() > limits.max_descriptor_number || target > limits.max_descriptor_number {
            return Err(LaunchError::Capacity);
        }
        staged.push(own);
        target_fds.push(target);
        Ok(target)
    };
    if let Some(fd) = &null_in {
        stage(fd.as_fd(), Some(0))?;
    }
    if let Some(fd) = &null_out {
        if command.stdio & 2 == 0 && !targets.contains(&1) {
            stage(fd.as_fd(), Some(1))?;
        }
        if command.stdio & 4 == 0 && !targets.contains(&2) {
            stage(fd.as_fd(), Some(2))?;
        }
    }
    for mapping in &command.mappings {
        stage(mapping.source, Some(mapping.target))?;
    }
    for source in &command.listeners {
        advertised.push(stage(*source, None)?);
    }
    if !advertised.is_empty() {
        environment.values.insert(
            b"LISTEN_FDS".to_vec(),
            advertised.len().to_string().into_bytes(),
        );
        environment.values.insert(
            b"LISTEN_FDNAMES".to_vec(),
            advertised
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(":")
                .into_bytes(),
        );
    }
    if let Some((read, _)) = &control {
        let target = stage(read.as_fd(), None)?;
        environment.values.insert(
            b"GNUNET_OS_CONTROL_PIPE".to_vec(),
            format!("{target:x}").into_bytes(),
        );
    }
    let mappings = staged
        .iter()
        .zip(target_fds)
        .map(|(source, target)| (source.as_fd(), target))
        .collect::<Vec<_>>();
    let program =
        CString::new(helper.as_os_str().as_bytes()).map_err(|_| LaunchError::InvalidInput)?;
    let mut argv = Vec::new();
    argv.try_reserve_exact(command.argv.len() + 5)
        .map_err(|_| LaunchError::Capacity)?;
    argv.push(program.clone());
    argv.push(
        CString::new(
            command
                .cwd
                .as_ref()
                .map_or(b"".as_slice(), |path| path.as_os_str().as_bytes()),
        )
        .map_err(|_| LaunchError::InvalidInput)?,
    );
    argv.push(
        CString::new(if native_spawn::inherited_pipe_ignore()? {
            "ignore"
        } else {
            "default"
        })
        .map_err(|_| LaunchError::InvalidInput)?,
    );
    let mapped_stdio = targets
        .iter()
        .filter(|target| **target < 3)
        .fold(0u8, |mask, target| mask | (1 << target));
    argv.push(
        CString::new((snapshot.closed & !mapped_stdio).to_string())
            .map_err(|_| LaunchError::InvalidInput)?,
    );
    argv.push(filename);
    for arg in command.argv {
        argv.push(CString::new(arg.into_vec()).map_err(|_| LaunchError::InvalidInput)?);
    }
    for change in command.environment_changes {
        let key = change.key.into_vec();
        if key.is_empty() || key.contains(&0) || key.contains(&b'=') {
            return Err(LaunchError::InvalidInput);
        }
        match change.value {
            Some(value) => {
                let value = value.into_vec();
                if value.contains(&0) {
                    return Err(LaunchError::InvalidInput);
                }
                environment.values.insert(key, value);
            }
            None => {
                environment.values.remove(&key);
            }
        }
    }
    let env = environment.strings(limits.launch.max_environment_bytes)?;
    match native_spawn::spawn(&program, &argv, &env, &mappings) {
        Err(error) => Ok(SpawnResult::Refused { error: Some(error) }),
        Ok(pid) => {
            // The exclusive registry capacity/generation was checked before all
            // native work; no fallible allocation or token counter follows spawn.
            registry.generation += 1;
            let child = OriginalChild {
                identity: Arc::clone(&registry.identity),
                generation: registry.generation,
                pid: pid.as_raw() as u32,
            };
            let control = control.map(|(_, write)| write);
            let token = control.as_ref().map(|_| ControlWriterToken {
                child: child.clone(),
            });
            registry.children.push(ChildRecord {
                pid,
                child: child.clone(),
                control,
            });
            Ok(SpawnResult::Admitted(Spawned {
                child,
                control: token,
            }))
        }
    }
}

/// Exec-helper entrypoint. The iterator excludes this helper's argv0.
///
/// # Safety
/// Call only once in the dedicated fresh exec helper, before opening files,
/// runtimes/threads or constructing Rust owners for stdio slots. The internal
/// parent-provided mask identifies foreign stdio that must be closed before exec;
/// no other Rust owner may refer to those slots. Success never returns. This is
/// not a safe general-purpose exec API callable from a running host/library. Success
/// replaces the same process; target exec failure exits1 and closes its inherited
/// readiness writer naturally. Helper creation is never target/readiness proof.
#[expect(
    unsafe_code,
    reason = "The explicit fresh-helper caller owns foreign stdio exclusively; only this entry invokes the native exec/stdio restoration boundary"
)]
pub unsafe fn helper_main(arguments: impl IntoIterator<Item = OsString>) -> std::process::ExitCode {
    let mut args = arguments.into_iter();
    let Some(cwd) = args.next() else {
        return std::process::ExitCode::from(2);
    };
    let pipe_ignore = match args.next().as_deref() {
        Some(value) if value == "ignore" => true,
        Some(value) if value == "default" => false,
        _ => return std::process::ExitCode::from(2),
    };
    let closed_stdio = match args
        .next()
        .and_then(|s| s.into_string().ok())
        .and_then(|s| s.parse::<u8>().ok())
    {
        Some(mask) if mask <= 7 => mask,
        _ => return std::process::ExitCode::from(2),
    };
    let Some(filename) = args
        .next()
        .and_then(|value| CString::new(value.into_vec()).ok())
    else {
        return std::process::ExitCode::from(2);
    };
    let argv = args
        .map(|value| CString::new(value.into_vec()))
        .collect::<Result<Vec<_>, _>>();
    let Ok(argv) = argv else {
        return std::process::ExitCode::from(2);
    };
    if !cwd.is_empty() && std::env::set_current_dir(cwd).is_err() {
        return std::process::ExitCode::from(1);
    }
    // SAFETY: upheld by this unsafe entrypoint's fresh-exec contract; no
    // standard descriptor has a Rust owner and no file/runtime/thread was opened.
    let _error =
        unsafe { native_spawn::exec_original(&filename, &argv, pipe_ignore, closed_stdio) };
    std::process::ExitCode::from(1)
}

#[cfg(test)]
mod boundaries {
    //! Actual private counter/error-class boundaries with real owned helper children.
    //! Injected write returns below are explicit finite seams, not actual EINTR
    //! syscall claims; the fallback kill and consuming wait are genuinely native.
    use super::*;
    type Test = Result<(), Box<dyn std::error::Error>>;
    struct Registry(ChildRegistry);
    impl Drop for Registry {
        fn drop(&mut self) {
            for record in &self.0.children {
                drop(native_spawn::signal_original(record.pid, libc::SIGKILL));
            }
            let until = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while !self.0.children.is_empty() && std::time::Instant::now() < until {
                drop(self.0.reap_completed());
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
    }
    fn runtime() -> io::Result<tokio::runtime::Runtime> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
    }
    fn actual_child(registry: &mut ChildRegistry) -> Result<Spawned, LaunchError> {
        let command = NativeCommand {
            filename: OsString::from("/bin/sleep"),
            argv: vec![OsString::from("sleep"), OsString::from("30")],
            environment: EnvironmentSnapshot::system()?,
            environment_changes: Vec::new(),
            cwd: None,
            stdio: 8,
            stdio_snapshot: None,
            listeners: Vec::new(),
            mappings: Vec::new(),
        };
        actual_command(registry, command)
    }
    fn actual_command(
        registry: &mut ChildRegistry,
        command: NativeCommand<'_>,
    ) -> Result<Spawned, LaunchError> {
        let executable = std::env::current_exe()?;
        let debug = executable
            .parent()
            .and_then(Path::parent)
            .ok_or(LaunchError::InvalidInput)?;
        let helper = debug.join("gnunet-arm-spawn-helper");
        match spawn(
            &Configuration::default(),
            &helper,
            command,
            ProcessLimits::default(),
            registry,
        )? {
            SpawnResult::Admitted(value) => Ok(value),
            SpawnResult::Refused { error } => Err(error
                .unwrap_or_else(|| {
                    io::Error::other("finite test helper must be freshly built before unit checks")
                })
                .into()),
        }
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "A real unrelated SIGCHLD must not strand actual owned-child death until the outer deadline"
    )]
    fn unrelated_child_notification_cannot_suspend_the_next_owned_death() -> Test {
        runtime()?.block_on(async {
            let mut registry = Registry(ChildRegistry::new(1)?);
            let (read, write) = std::io::pipe()?;
            let command = NativeCommand {
                filename: OsString::from("/bin/cat"),
                argv: vec![OsString::from("cat")],
                environment: EnvironmentSnapshot::system()?,
                environment_changes: Vec::new(),
                cwd: None,
                stdio: 0,
                stdio_snapshot: None,
                listeners: Vec::new(),
                mappings: vec![DescriptorMap {
                    source: read.as_fd(),
                    target: 0,
                }],
            };
            let child = actual_command(&mut registry.0, command)?;
            drop(read);
            // Observe SIGCHLD before consuming this other registry's exit.
            // FreeBSD wait can dequeue an as-yet-undelivered child signal.
            let mut unrelated = Registry(ChildRegistry::new(1)?);
            let other = actual_command(
                &mut unrelated.0,
                NativeCommand {
                    filename: OsString::from("/usr/bin/true"),
                    argv: vec![OsString::from("true")],
                    environment: EnvironmentSnapshot::system()?,
                    environment_changes: Vec::new(),
                    cwd: None,
                    stdio: 0,
                    stdio_snapshot: None,
                    listeners: Vec::new(),
                    mappings: Vec::new(),
                },
            )?;
            let mut unrelated_exit = None;
            let mut notified = false;
            let (release, receive) = std::sync::mpsc::channel();
            let closer = std::thread::spawn(move || -> io::Result<()> {
                receive.recv().map_err(io::Error::other)?;
                std::thread::sleep(std::time::Duration::from_millis(25));
                drop(write);
                Ok(())
            });
            let mut release = Some(release);
            let started = std::time::Instant::now();
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                std::future::poll_fn(|cx| {
                    registry.0.reap_completed()?;
                    if let Some(event) = registry.0.take_reaped() {
                        return std::task::Poll::Ready(Ok::<_, LaunchError>(event));
                    }
                    match registry.0.poll_child_signal(cx) {
                        std::task::Poll::Ready(Err(error)) => {
                            return std::task::Poll::Ready(Err(error));
                        }
                        std::task::Poll::Ready(Ok(())) => {
                            // Deliberately return Pending after the notification
                            // produced no managed death, as a host driver does.
                            notified = true;
                        }
                        std::task::Poll::Pending => {}
                    }
                    if notified && unrelated_exit.is_none() {
                        unrelated.0.reap_completed()?;
                        if let Some(event) = unrelated.0.take_reaped() {
                            unrelated_exit = Some(event);
                            if let Some(release) = release.take() {
                                release.send(()).map_err(io::Error::other)?;
                            }
                        }
                    }
                    std::task::Poll::Pending
                }),
            )
            .await;
            // Also release/join the finite native worker on an earlier failure.
            if let Some(release) = release.take() {
                release.send(()).map_err(io::Error::other)?;
            }
            closer
                .join()
                .map_err(|_| io::Error::other("owned pipe worker panicked"))??;
            let event = result??;
            let unrelated_exit = unrelated_exit
                .ok_or_else(|| io::Error::other("unrelated child notification was not observed"))?;
            assert_eq!(unrelated_exit.child, other.child);
            assert_eq!(unrelated_exit.exit, ChildExit::Exited(0));
            assert_eq!(event.child, child.child);
            assert_eq!(event.exit, ChildExit::Exited(0));
            // An outer deadline wake must not masquerade as a child wake.
            assert!(started.elapsed() < std::time::Duration::from_secs(1));
            Ok(())
        })
    }
    #[test]
    fn helper_check_observes_xok_then_uid_then_nonroot_stat_without_file_type_policy() {
        struct Io {
            uid: u32,
            x: bool,
            stat: bool,
            calls: Vec<&'static str>,
        }
        impl ExecutableIo for Io {
            fn access_x(&mut self, _: &Path) -> io::Result<()> {
                self.calls.push("x");
                if self.x {
                    Ok(())
                } else {
                    Err(io::ErrorKind::PermissionDenied.into())
                }
            }
            fn real_uid(&mut self) -> u32 {
                self.calls.push("uid");
                self.uid
            }
            fn stat(&mut self, _: &Path) -> io::Result<()> {
                self.calls.push("stat");
                if self.stat {
                    Ok(())
                } else {
                    Err(io::ErrorKind::NotFound.into())
                }
            }
        }
        for (uid, x, stat, allowed, expected) in [
            (501, false, false, false, vec!["x"]),
            (0, true, false, true, vec!["x", "uid"]),
            (501, true, true, true, vec!["x", "uid", "stat"]),
            (501, true, false, false, vec!["x", "uid", "stat"]),
        ] {
            let mut io = Io {
                uid,
                x,
                stat,
                calls: Vec::new(),
            };
            assert_eq!(
                matches!(
                    executable_after_path(Path::new("/finite-component"), &mut io),
                    Executable::Allowed
                ),
                allowed
            );
            assert_eq!(io.calls, expected);
        }
        // This is an explicitly finite IO seam, not an actual OS stat-race claim.
        // Actual directory acceptance/late-exec is separately run against C.
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Actual original child and private exhausted-counter outcomes are finite test invariants"
    )]
    fn exhausted_admission_generation_cannot_block_original_signal_and_reap() -> Test {
        runtime()?.block_on(async {
            let mut registry = Registry(ChildRegistry::new(1)?);
            let child = actual_child(&mut registry.0)?;
            registry.0.generation = u64::MAX;
            assert!(!registry.0.capacity_available(1));
            registry
                .0
                .close_control(child.control.as_ref().ok_or("actual control writer")?)?;
            assert_eq!(
                registry.0.signal(&child.child, 15)?,
                SignalAttempt::NativeKill
            );
            tokio::time::timeout(
                std::time::Duration::from_secs(3),
                registry.0.drain_children(),
            )
            .await??;
            let result = registry.0.take_reaped().ok_or("actual wait missing")?;
            assert_eq!(result.child, child.child);
            assert_eq!(
                result.exit,
                ChildExit::Signaled {
                    signal: 15,
                    core_dumped: false
                }
            );
            assert!(matches!(
                registry.0.signal(&child.child, 0),
                Err(LaunchError::Stale)
            ));
            assert_eq!(registry.0.generation, u64::MAX);
            Ok(())
        })
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Finite EINTR/zero seams must execute a real original-PID fallback kill and actual wait"
    )]
    fn interrupted_and_zero_write_seams_execute_real_kill_without_false_pipe_success() -> Test {
        runtime()?.block_on(async {
            for interrupted in [true, false] {
                let mut registry = Registry(ChildRegistry::new(1)?);
                let child = actual_child(&mut registry.0)?;
                let mut calls = 0;
                assert_eq!(
                    registry
                        .0
                        .signal_using(&child.child, 15, |_writer, bytes| {
                            calls += 1;
                            assert_eq!(bytes, [15]);
                            if interrupted {
                                Err(io::ErrorKind::Interrupted.into())
                            } else {
                                Ok(0)
                            }
                        })?,
                    SignalAttempt::NativeKill
                );
                assert_eq!(calls, 1);
                tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    registry.0.drain_children(),
                )
                .await??;
                assert_eq!(
                    registry
                        .0
                        .take_reaped()
                        .ok_or("real killed child wait")?
                        .exit,
                    ChildExit::Signaled {
                        signal: 15,
                        core_dumped: false
                    }
                );
            }
            Ok(())
        })
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Marker values are intentionally identical; token authority must use allocation identity in equality and hashing"
    )]
    fn child_identity_uses_arc_address_and_token_keeps_old_identity_alive() -> Test {
        use std::hash::{Hash, Hasher};
        let first = ChildRegistry::new(1)?;
        let original = OriginalChild {
            identity: Arc::clone(&first.identity),
            generation: 1,
            pid: 1,
        };
        drop(first);
        let second = ChildRegistry::new(1)?;
        let other = OriginalChild {
            identity: Arc::clone(&second.identity),
            generation: 1,
            pid: 1,
        };
        assert_ne!(original, other);
        #[derive(Default)]
        struct Recording(Vec<u8>);
        impl Hasher for Recording {
            fn write(&mut self, bytes: &[u8]) {
                self.0.extend_from_slice(bytes);
            }
            fn finish(&self) -> u64 {
                0
            }
        }
        let mut a = Recording::default();
        original.hash(&mut a);
        let mut b = Recording::default();
        other.hash(&mut b);
        assert_ne!(a.0, b.0);
        assert_eq!(original, original.clone());
        Ok(())
    }
}
