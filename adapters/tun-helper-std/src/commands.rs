//! EXIT's original global forwarding/NAT operations, before TUN publication.
//! There is no shell, configuration ACK, inferred rule absence or rule deletion.
use crate::{failure::Failure, native, options::Options};
use gnunet_native::nat_helper::Signals;
use std::{
    ffi::OsStr,
    fmt, fs,
    io::{self, Read},
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::{ffi::OsStrExt, fs::MetadataExt, process::CommandExt},
    },
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};
const CAPTURE: usize = 4096;
const COMMAND_LIFETIME: Duration = Duration::from_secs(30);
const CADENCE: i32 = 100;

pub(super) fn configure(options: &Options, parent: i32, signals: &Signals) -> Result<(), Failure> {
    let Some(egress) = &options.egress else {
        return Ok(());
    };
    let sysctl = tool("sysctl", ["/sbin/sysctl", "/usr/sbin/sysctl"])?;
    let iptables = if options.v4.is_some() {
        Some(tool("iptables", ["/sbin/iptables", "/usr/sbin/iptables"])?)
    } else {
        None
    };
    // SIG_IGN/SA_NOCLDWAIT inherited from a caller would invalidate Child's wait
    // receipt. This dedicated process establishes and restores its own policy.
    let mut reaping =
        Reaping::install().map_err(|cause| Failure::new("EXIT child wait policy", cause))?;
    let mut result = (|| {
        if options.v6.is_some() {
            execute(
                sysctl,
                &[
                    OsStr::new("-w"),
                    OsStr::new("net.ipv6.conf.all.forwarding=1"),
                ],
                parent,
                signals,
            )?;
        }
        if options.v4.is_some() {
            execute(
                sysctl,
                &[OsStr::new("-w"), OsStr::new("net.ipv4.ip_forward=1")],
                parent,
                signals,
            )?;
            let iptables = iptables
                .ok_or_else(|| Failure::invalid("EXIT setup", "missing resolved IPv4 tool"))?;
            execute(
                iptables,
                &[
                    OsStr::new("-t"),
                    OsStr::new("nat"),
                    OsStr::new("-A"),
                    OsStr::new("POSTROUTING"),
                    OsStr::new("-o"),
                    OsStr::from_bytes(egress),
                    OsStr::new("-j"),
                    OsStr::new("MASQUERADE"),
                ],
                parent,
                signals,
            )?;
        }
        Ok(())
    })();
    if let Err(cause) = reaping.restore() {
        retain(&mut result, "child wait policy restore", cause);
    }
    result
}
fn retain(result: &mut Result<(), Failure>, stage: &'static str, cause: io::Error) {
    if let Err(original) = result {
        original.add(stage, cause);
    } else {
        *result = Err(Failure::new(stage, cause));
    }
}

#[derive(Debug)]
struct Lookup {
    name: &'static str,
    causes: [io::Error; 2],
}
impl fmt::Display for Lookup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} approved paths refused: {}; {}",
            self.name, self.causes[0], self.causes[1]
        )
    }
}
impl std::error::Error for Lookup {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.causes[0])
    }
}
fn tool(name: &'static str, paths: [&'static str; 2]) -> Result<&'static str, Failure> {
    let check = |path: &str| -> io::Result<()> {
        let metadata = fs::metadata(path)?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || metadata.mode() & 0o111 == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "expected a root-owned non-writable executable regular file",
            ));
        }
        Ok(())
    };
    let first = match check(paths[0]) {
        Ok(()) => return Ok(paths[0]),
        Err(cause) => cause,
    };
    let second = match check(paths[1]) {
        Ok(()) => return Ok(paths[1]),
        Err(cause) => cause,
    };
    Err(Failure::new(
        "EXIT tool lookup",
        io::Error::other(Lookup {
            name,
            causes: [first, second],
        }),
    ))
}

#[derive(Debug)]
struct Capture {
    bytes: Vec<u8>,
    total: u64,
}
impl Capture {
    fn new() -> io::Result<Self> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(CAPTURE)
            .map_err(|_| io::Error::other("bounded command capture allocation failed"))?;
        Ok(Self { bytes, total: 0 })
    }
    fn append(&mut self, input: &[u8]) {
        self.total = self.total.saturating_add(input.len() as u64);
        let keep = input.len().min(CAPTURE - self.bytes.len());
        self.bytes.extend_from_slice(&input[..keep]);
        // Excess bytes are actually drained and discarded. Retention stays
        // bounded even if a child writes indefinitely until its original hard.
    }
}
struct Pipe {
    file: Option<fs::File>,
    capture: Capture,
}
impl Pipe {
    fn fd(&self) -> i32 {
        self.file.as_ref().map_or(-1, AsRawFd::as_raw_fd)
    }
    fn close(&mut self) -> io::Result<()> {
        match self.file.take() {
            Some(file) => native::close(OwnedFd::from(file)),
            None => Ok(()),
        }
    }
    fn read_once(&mut self) -> io::Result<()> {
        let Some(file) = &mut self.file else {
            return Ok(());
        };
        let mut bytes = [0u8; 1024];
        match file.read(&mut bytes) {
            Ok(0) => self.close(),
            Ok(count) => {
                self.capture.append(&bytes[..count]);
                Ok(())
            }
            Err(cause)
                if matches!(
                    cause.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(())
            }
            Err(cause) => Err(cause),
        }
    }
}

#[derive(Debug)]
struct CommandFailure {
    tool: &'static str,
    status: Option<ExitStatus>,
    stdout: Capture,
    stderr: Capture,
    issues: [Option<(&'static str, io::Error)>; 10],
    expired: bool,
    stopped: bool,
}
impl CommandFailure {
    fn issue(&mut self, stage: &'static str, cause: io::Error) {
        // At most two setup, two read, one poll, one status, one kill, one
        // original wait and two close failures occur in this one attempt.
        if let Some(slot) = self.issues.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some((stage, cause));
        }
    }
    fn failed(&self) -> bool {
        self.expired
            || self.stopped
            || !self.status.is_some_and(|status| status.success())
            || self.issues.iter().any(Option::is_some)
    }
}
impl fmt::Display for CommandFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} status={:?} expired={} stopped={}",
            self.tool, self.status, self.expired, self.stopped
        )?;
        for (stage, cause) in self.issues.iter().flatten() {
            write!(f, "; {stage}: {cause}")?;
        }
        write!(
            f,
            "; stdout {}/{}={:?}; stderr {}/{}={:?}",
            self.stdout.bytes.len(),
            self.stdout.total,
            String::from_utf8_lossy(&self.stdout.bytes),
            self.stderr.bytes.len(),
            self.stderr.total,
            String::from_utf8_lossy(&self.stderr.bytes)
        )
    }
}
impl std::error::Error for CommandFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.issues
            .iter()
            .flatten()
            .next()
            .map(|(_, cause)| cause as _)
    }
}

fn execute(
    tool: &'static str,
    args: &[&OsStr],
    parent: i32,
    signals: &Signals,
) -> Result<(), Failure> {
    let started = Instant::now();
    let hard = started
        .checked_add(COMMAND_LIFETIME)
        .ok_or_else(|| Failure::invalid("EXIT command", "native deadline overflow"))?;
    let stdout = Capture::new().map_err(|cause| Failure::new("EXIT capture", cause))?;
    let stderr = Capture::new().map_err(|cause| Failure::new("EXIT capture", cause))?;
    let mut report = CommandFailure {
        tool,
        status: None,
        stdout,
        stderr,
        issues: std::array::from_fn(|_| None),
        expired: false,
        stopped: false,
    };
    if signals.stopped() || parent <= 1 || native::parent() != parent {
        report.stopped = true;
        return Err(Failure::new(
            "EXIT command before spawn",
            io::Error::other(report),
        ));
    }
    let mut command = Command::new(Path::new(tool));
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/sbin:/usr/bin:/bin")
        .env("LC_ALL", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    child_lifetime(&mut command);
    if Instant::now() >= hard || signals.stopped() || native::parent() != parent {
        report.expired = Instant::now() >= hard;
        report.stopped = signals.stopped() || native::parent() != parent;
        return Err(Failure::new(
            "EXIT command before spawn",
            io::Error::other(report),
        ));
    }
    let mut child = command
        .spawn()
        .map_err(|cause| Failure::new("EXIT command spawn", cause))?;
    let mut output = Pipe {
        file: child
            .stdout
            .take()
            .map(|pipe| fs::File::from(OwnedFd::from(pipe))),
        capture: report.stdout,
    };
    let mut error_output = Pipe {
        file: child
            .stderr
            .take()
            .map(|pipe| fs::File::from(OwnedFd::from(pipe))),
        capture: report.stderr,
    };
    // Move capture ownership back into the final diagnostic after all original
    // pipe/child ownership settles; no output is ever forwarded to fd1.
    report.stdout = Capture {
        bytes: Vec::new(),
        total: 0,
    };
    report.stderr = Capture {
        bytes: Vec::new(),
        total: 0,
    };
    for (pipe, stage) in [(&output, "stdout setup"), (&error_output, "stderr setup")] {
        if let Some(file) = &pipe.file {
            if let Err(cause) = nonblocking(file) {
                report.issue(stage, cause);
            }
        } else {
            report.issue(
                stage,
                io::Error::other("piped descriptor missing after actual spawn"),
            );
        }
    }
    let mut may_wait = true;
    let mut cursor = false;
    while !report.expired && !report.stopped && report.issues.iter().all(Option::is_none) {
        // Original child status is checked on every bounded round, even when a
        // capture pipe stays readable. Native hard never derives from activity.
        if Instant::now() >= hard {
            report.expired = true;
            break;
        }
        if signals.stopped() || native::parent() != parent {
            report.stopped = true;
            break;
        }
        match child.try_wait() {
            Ok(Some(status)) => report.status = Some(status),
            Ok(None) => {}
            Err(cause) => {
                may_wait = cause.raw_os_error() != Some(libc::ECHILD);
                report.issue("actual status", cause);
                break;
            }
        }
        if report.status.is_some() && output.file.is_none() && error_output.file.is_none() {
            break;
        }
        let mut descriptors = [poll_entry(output.fd()), poll_entry(error_output.fd())];
        let timeout = i32::try_from(
            hard.saturating_duration_since(Instant::now())
                .as_millis()
                .clamp(1, CADENCE as u128),
        )
        .unwrap_or(CADENCE);
        if let Err(cause) = poll(&mut descriptors, timeout) {
            if cause.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            report.issue("capture poll", cause);
            break;
        }
        for offset in 0..2 {
            if Instant::now() >= hard {
                report.expired = true;
                break;
            }
            if signals.stopped() || native::parent() != parent {
                report.stopped = true;
                break;
            }
            let index = (usize::from(cursor) + offset) % 2;
            let events = descriptors[index].revents;
            let (pipe, stage) = if index == 0 {
                (&mut output, "stdout read")
            } else {
                (&mut error_output, "stderr read")
            };
            if events & libc::POLLNVAL != 0 {
                report.issue(stage, io::Error::from_raw_os_error(libc::EBADF));
            } else if events & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
                && let Err(cause) = pipe.read_once()
            {
                report.issue(stage, cause);
            }
        }
        cursor = !cursor;
    }
    if report.status.is_none() && may_wait {
        // Child::kill uses this unreaped original Child. Never signal a raw PID
        // after ECHILD, which would no longer prove ownership against PID reuse.
        if let Err(cause) = child.kill() {
            report.issue("original child kill", cause);
        }
        wait_original(&mut child, &mut report);
    }
    for (pipe, stage) in [
        (&mut output, "stdout close"),
        (&mut error_output, "stderr close"),
    ] {
        if let Err(cause) = pipe.close() {
            report.issue(stage, cause);
        }
    }
    report.stdout = output.capture;
    report.stderr = error_output.capture;
    if report.failed() {
        Err(Failure::new("EXIT network setup", io::Error::other(report)))
    } else {
        Ok(())
    }
}
fn wait_original(child: &mut Child, report: &mut CommandFailure) {
    loop {
        match child.wait() {
            Ok(status) => {
                report.status = Some(status);
                break;
            }
            Err(cause) if cause.kind() == io::ErrorKind::Interrupted => {}
            Err(cause) => {
                report.issue("original child wait", cause);
                break;
            }
        }
    }
}
fn poll_entry(fd: i32) -> libc::pollfd {
    libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }
}
#[expect(
    unsafe_code,
    reason = "poll borrows only this initialized fixed descriptor array for the synchronous call"
)]
fn poll(descriptors: &mut [libc::pollfd; 2], timeout: i32) -> io::Result<()> {
    // SAFETY: two initialized entries remain exclusive and alive for this call.
    if unsafe { libc::poll(descriptors.as_mut_ptr(), 2, timeout) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
#[expect(
    unsafe_code,
    reason = "F_SETFL affects only a newly created, exclusively owned command-capture pipe read end, never inherited helper stdio"
)]
fn nonblocking(file: &fs::File) -> io::Result<()> {
    // SAFETY: this live file owns the descriptor; F_GETFL has no extra argument.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: F_SETFL accepts the original integer flags plus O_NONBLOCK.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
#[expect(
    unsafe_code,
    reason = "Dedicated single-threaded helper installs an async-signal-safe Linux child-parent lifetime check before exec"
)]
fn child_lifetime(command: &mut Command) {
    // SAFETY: getpid has no pointers or ownership effects.
    let helper = unsafe { libc::getpid() };
    // SAFETY: the closure uses only prctl/getppid and errno capture; it does not
    // allocate, lock, access Rust global owners or call the packet pump after fork.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(
                libc::PR_SET_PDEATHSIG,
                libc::SIGKILL as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != helper {
                return Err(io::Error::from_raw_os_error(libc::ECANCELED));
            }
            Ok(())
        });
    }
}
struct Reaping {
    original: libc::sigaction,
    restored: bool,
}
impl Reaping {
    #[expect(
        unsafe_code,
        reason = "sigaction owns one saved process disposition in this fresh single-threaded helper"
    )]
    fn install() -> io::Result<Self> {
        // SAFETY: sigaction is a plain libc scalar record; zero has valid fields.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = libc::SIG_DFL;
        // SAFETY: sa_mask is initialized writable storage and sigemptyset fills it.
        if unsafe { libc::sigemptyset(&mut action.sa_mask) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: sigaction is plain C storage and is written by the following call.
        let mut original: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: both fixed records stay live, initialized and nonaliasing.
        if unsafe { libc::sigaction(libc::SIGCHLD, &action, &mut original) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            original,
            restored: false,
        })
    }
    #[expect(
        unsafe_code,
        reason = "Restore the exact original SIGCHLD action once after all original child waits"
    )]
    fn restore(&mut self) -> io::Result<()> {
        if self.restored {
            return Ok(());
        }
        // SAFETY: original was filled by successful sigaction and remains owned.
        if unsafe { libc::sigaction(libc::SIGCHLD, &self.original, std::ptr::null_mut()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        self.restored = true;
        Ok(())
    }
}
