//! Actual original Rust helper child ownership. No shell, inherited stdin,
//! READY protocol or fake process completion. stdout is bounded line framing.
use crate::{Error, deadline::Bounds};
use gnunet_nat::{
    address::parse_ipv4,
    state::{Reversal, Source},
};
use gnunet_types::Error as Fault;
use std::{
    future::Future,
    io,
    net::Ipv4Addr,
    path::PathBuf,
    pin::Pin,
    process::Stdio,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, ReadBuf},
    process::{Child, ChildStdout, Command},
    time::{Instant, Sleep},
};
static INSTANCE: AtomicU64 = AtomicU64::new(1);
/// Original non-reused child generation; a PID alone never grants callback authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Helper {
    instance: u64,
    serial: u64,
}
impl Helper {
    /// Local diagnostic serial, not a GNUnet wire id.
    pub const fn serial(self) -> u64 {
        self.serial
    }
}
/// Explicit Rust binary paths selected through official SUID_BINARY_PATH/libexec
/// configuration. These paths are never shell parsed or implicitly replaced by C.
#[derive(Clone, Debug)]
pub struct Paths {
    /// Actual Rust gnunet-helper-nat-server executable.
    pub server: PathBuf,
    /// Actual Rust gnunet-helper-nat-client executable.
    pub client: PathBuf,
}
/// Finite child/partial-input/retirement resources.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum simultaneously owned children, including retiring ones.
    pub children: usize,
    /// Original incomplete stdout-line native lifetime.
    pub line_lifetime: Duration,
    /// Original native wait/reap bound after stop.
    pub retirement: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            children: 256,
            line_lifetime: Duration::from_secs(10),
            retirement: Duration::from_secs(5),
        }
    }
}
/// Original child role; server lifetime follows a real local interface lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// Actual ongoing reversal observation helper.
    Server {
        /// Local interface address captured for this exact helper generation.
        local: [u8; 4],
    },
    /// Already admitted finite public NAT_TEST sender; original MQ EOF is not a wire cancellation.
    Test {
        /// Original requester retained after its MQ closes.
        source: Source,
    },
    /// One-shot actual raw sender requested on this original registration MQ.
    Client {
        /// Original requesting MQ.
        source: Source,
    },
}
/// Independent child observations, never reverse-connect or remote publication success.
#[derive(Debug)]
pub enum Event {
    /// One actual complete stdout observation from the original server child.
    Observation {
        /// Original child generation.
        helper: Helper,
        /// Original local interface.
        local: [u8; 4],
        /// Actual public outer source parsed by the helper.
        remote: [u8; 4],
        /// Actual observed port (0=diagnostic only).
        port: u16,
    },
    /// Actual wait result; exit0 on a client means both complete local sends only.
    Exited {
        /// Original child.
        helper: Helper,
        /// Original role/source.
        role: Role,
        /// Actual OS wait status.
        status: std::process::ExitStatus,
    },
    /// Original read/write/parse/deadline failure; cleanup is independently polled.
    Failed {
        /// Original child.
        helper: Helper,
        /// Original role/source.
        role: Role,
        /// Actual original failure.
        error: Error,
    },
    /// Actual signal/stop attempt failed; preserve independently from primary failure.
    StopFailed {
        /// Original child.
        helper: Helper,
        /// Actual native error.
        error: io::Error,
    },
    /// Original retirement bound elapsed; no false Reaped/exit0 is emitted.
    RetirementUnknown {
        /// Original child.
        helper: Helper,
        /// Original role/source.
        role: Role,
    },
    /// Bounded positive read/native activity without a full observation.
    Activity,
}
struct Row {
    helper: Helper,
    role: Role,
    child: Child,
    stdout: Option<ChildStdout>,
    bytes: [u8; 256],
    at: usize,
    used: usize,
    line: [u8; 32],
    line_used: usize,
    line_until: Option<Instant>,
    bounds: Option<Bounds>,
    retiring: Option<Instant>,
    failure: Option<Error>,
    stop_error: Option<io::Error>,
    exit: Option<std::process::ExitStatus>,
    wait_failed: bool,
}
/// Caller-polled child owner. Drop physically requests kill for each remaining
/// original child; async shutdown must still drive real wait/retirement results.
pub struct Supervisor {
    instance: u64,
    next: u64,
    paths: Paths,
    limits: Limits,
    rows: Vec<Row>,
    cursor: usize,
    timer: Pin<Box<Sleep>>,
}
impl Supervisor {
    /// Validate paths and finite bounds, without launching or checking a binary.
    pub fn new(paths: Paths, limits: Limits) -> Result<Self, Error> {
        if limits.children == 0 || limits.line_lifetime.is_zero() || limits.retirement.is_zero() {
            return Err(Fault::InvalidInput.into());
        }
        let instance = INSTANCE
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| Fault::Overflow)?;
        Ok(Self {
            instance,
            next: 1,
            paths,
            limits,
            rows: Vec::new(),
            cursor: 0,
            timer: Box::pin(tokio::time::sleep(Duration::ZERO)),
        })
    }
    fn next(&mut self) -> Result<Helper, Error> {
        if self.rows.len() >= self.limits.children {
            return Err(Fault::WouldBlock.into());
        }
        self.rows.try_reserve(1).map_err(|_| Fault::Capacity)?;
        let serial = self.next;
        self.next = serial.checked_add(1).ok_or(Fault::Overflow)?;
        Ok(Helper {
            instance: self.instance,
            serial,
        })
    }
    fn row(&self, helper: Helper) -> Result<usize, Error> {
        if helper.instance != self.instance {
            return Err(Fault::StaleGeneration.into());
        }
        self.rows
            .iter()
            .position(|r| r.helper == helper)
            .ok_or(Fault::StaleGeneration.into())
    }
    fn insert(&mut self, helper: Helper, role: Role, mut child: Child, bounds: Option<Bounds>) {
        let stdout = child.stdout.take();
        self.rows.push(Row {
            helper,
            role,
            child,
            stdout,
            bytes: [0; 256],
            at: 0,
            used: 0,
            line: [0; 32],
            line_used: 0,
            line_until: None,
            bounds,
            retiring: None,
            failure: None,
            stop_error: None,
            exit: None,
            wait_failed: false,
        });
    }
    /// Start a real server for one actual currently-present local IPv4 lease.
    pub fn start_server(&mut self, local: [u8; 4]) -> Result<Helper, Error> {
        if !self.paths.server.is_absolute() {
            return Err(Fault::Unavailable.into());
        }
        let helper = self.next()?;
        let mut command = Command::new(&self.paths.server);
        command
            .arg(Ipv4Addr::from(local).to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        let child = command.spawn()?;
        self.insert(helper, Role::Server { local }, child, None);
        Ok(helper)
    }
    /// Start the official two-packet raw reversal sender for the original source.
    /// Original bounds are checked before process creation and never recomputed.
    pub fn start_client(
        &mut self,
        reversal: Reversal,
        bounds: Bounds,
        clock: &dyn gnunet_service_runtime::clock::RuntimeClock,
    ) -> Result<Helper, Error> {
        let source = reversal.source;
        self.start_sender(reversal, bounds, clock, Role::Client { source })
    }
    /// Already admitted finite NAT_TEST action, retained even after its original request MQ closes as in the official test server.
    pub fn start_test(
        &mut self,
        reversal: Reversal,
        bounds: Bounds,
        clock: &dyn gnunet_service_runtime::clock::RuntimeClock,
    ) -> Result<Helper, Error> {
        let source = reversal.source;
        self.start_sender(reversal, bounds, clock, Role::Test { source })
    }
    fn start_sender(
        &mut self,
        reversal: Reversal,
        bounds: Bounds,
        clock: &dyn gnunet_service_runtime::clock::RuntimeClock,
        role: Role,
    ) -> Result<Helper, Error> {
        bounds.check(clock)?;
        if !self.paths.client.is_absolute() {
            return Err(Fault::Unavailable.into());
        }
        let helper = self.next()?;
        let mut command = Command::new(&self.paths.client);
        command
            .arg(Ipv4Addr::from(reversal.local).to_string())
            .arg(Ipv4Addr::from(reversal.remote).to_string())
            .arg(reversal.port.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        let child = command.spawn()?;
        self.insert(helper, role, child, Some(bounds));
        Ok(helper)
    }
    /// Actual native PID only for diagnostics, never authority or reattachment.
    pub fn pid(&self, helper: Helper) -> Result<Option<u32>, Error> {
        Ok(self.rows[self.row(helper)?].child.id())
    }
    /// Stop one original child once. Actual wait/independent kill failure remain
    /// owned here; another helper/source is untouched.
    pub fn stop(&mut self, helper: Helper) -> Result<(), Error> {
        let i = self.row(helper)?;
        self.stop_index(i, None);
        Ok(())
    }
    fn stop_index(&mut self, i: usize, failure: Option<Error>) {
        let row = &mut self.rows[i];
        if row.failure.is_none() {
            row.failure = failure;
        }
        if row.retiring.is_none() {
            row.retiring = Some(
                Instant::now()
                    .checked_add(self.limits.retirement)
                    .unwrap_or_else(Instant::now),
            );
            row.stdout = None;
            row.bounds = None;
            row.line_until = None;
            row.stop_error = row.child.start_kill().err();
        }
    }
    /// Physical source loss retires only its original client-helper processes.
    pub fn source_stopped(&mut self, source: Source) {
        for i in 0..self.rows.len() {
            if self.rows[i].role == (Role::Client { source }) {
                self.stop_index(i, None);
            }
        }
    }
    /// Stop all originals without needing canonical clock or Resolver success.
    pub fn stop_all(&mut self) {
        for i in 0..self.rows.len() {
            self.stop_index(i, None);
        }
    }
    /// Current actual owned children, including original retirement debt.
    pub fn pending(&self) -> usize {
        self.rows.len()
    }
    /// Independently enforce native bounds/register alarm before a canonical
    /// clock wait. It does no new network action; only stops expired children.
    pub fn poll_native(&mut self, cx: &mut Context<'_>) -> Option<Event> {
        let now = Instant::now();
        for i in 0..self.rows.len() {
            if self.rows[i].bounds.is_some_and(|b| now >= b.hard)
                || self.rows[i].line_until.is_some_and(|t| now >= t)
            {
                self.stop_index(i, Some(Fault::Deadline.into()));
            }
        }
        let due = self
            .rows
            .iter()
            .flat_map(|r| {
                r.bounds
                    .map(|b| b.hard)
                    .into_iter()
                    .chain(r.line_until)
                    .chain(r.retiring)
            })
            .min();
        if let Some(due) = due {
            self.timer.as_mut().reset(due);
            if self.timer.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
        for row in &mut self.rows {
            if let Some(error) = row.failure.take() {
                return Some(Event::Failed {
                    helper: row.helper,
                    role: row.role,
                    error,
                });
            }
            if let Some(error) = row.stop_error.take() {
                return Some(Event::StopFailed {
                    helper: row.helper,
                    error,
                });
            }
        }
        for i in 0..self.rows.len() {
            if self.rows[i].retiring.is_none() {
                continue;
            }
            if self.rows[i].exit.is_none() && !self.rows[i].wait_failed {
                let result = {
                    let mut wait = std::pin::pin!(self.rows[i].child.wait());
                    wait.as_mut().poll(cx)
                };
                match result {
                    Poll::Ready(Ok(status)) => self.rows[i].exit = Some(status),
                    Poll::Ready(Err(error)) => {
                        self.rows[i].wait_failed = true;
                        return Some(Event::Failed {
                            helper: self.rows[i].helper,
                            role: self.rows[i].role,
                            error: error.into(),
                        });
                    }
                    Poll::Pending => {}
                }
            }
            if let Some(status) = self.rows[i].exit.take() {
                let row = self.rows.swap_remove(i);
                return Some(Event::Exited {
                    helper: row.helper,
                    role: row.role,
                    status,
                });
            }
            if self.rows[i].retiring.is_some_and(|t| Instant::now() >= t) {
                let row = self.rows.swap_remove(i);
                return Some(Event::RetirementUnknown {
                    helper: row.helper,
                    role: row.role,
                });
            }
        }
        None
    }
    fn line(row: &mut Row) -> Result<Option<Event>, Error> {
        while row.at < row.used {
            let b = row.bytes[row.at];
            row.at += 1;
            if b == b'\n' {
                let line = &row.line[..row.line_used];
                let (remote, port) = if let Some(n) = line.iter().position(|&b| b == b':') {
                    let remote = parse_ipv4(&line[..n])?;
                    let value =
                        core::str::from_utf8(&line[n + 1..]).map_err(|_| Fault::Malformed)?;
                    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                        return Err(Fault::Malformed.into());
                    }
                    (remote, value.parse::<u16>().map_err(|_| Fault::Malformed)?)
                } else {
                    (parse_ipv4(line)?, 0)
                };
                row.line_used = 0;
                row.line_until = None;
                let Role::Server { local } = row.role else {
                    return Err(Fault::Conflict.into());
                };
                return Ok(Some(Event::Observation {
                    helper: row.helper,
                    local,
                    remote,
                    port,
                }));
            }
            if row.line_used >= row.line.len() {
                return Err(Fault::TooLarge.into());
            }
            row.line[row.line_used] = b;
            row.line_used += 1;
        }
        row.at = 0;
        row.used = 0;
        Ok(None)
    }
    /// Poll one actual bounded read/wait. Source callbacks require the caller's
    /// current helper/interface generation check; output is never moved to a retry.
    pub fn poll(&mut self, cx: &mut Context<'_>, now: Option<u64>) -> Poll<Event> {
        if let Some(event) = self.poll_native(cx) {
            return Poll::Ready(event);
        }
        for n in 0..self.rows.len() {
            let i = (self.cursor + n) % self.rows.len();
            if now.is_some_and(|now| self.rows[i].bounds.is_some_and(|b| now >= b.expires)) {
                self.stop_index(i, Some(Fault::Deadline.into()));
            }
            if self.rows[i].retiring.is_some_and(|t| Instant::now() >= t) {
                let row = self.rows.swap_remove(i);
                return Poll::Ready(Event::RetirementUnknown {
                    helper: row.helper,
                    role: row.role,
                });
            }
            if self.rows[i].retiring.is_none() {
                match Self::line(&mut self.rows[i]) {
                    Ok(Some(e)) => {
                        self.cursor = (i + 1) % self.rows.len();
                        return Poll::Ready(e);
                    }
                    Err(e) => {
                        self.stop_index(i, Some(e));
                        return Poll::Ready(Event::Activity);
                    }
                    Ok(None) => {}
                }
                let row = &mut self.rows[i];
                if let Some(stdout) = &mut row.stdout {
                    let mut read = ReadBuf::new(&mut row.bytes);
                    match Pin::new(stdout).poll_read(cx, &mut read) {
                        Poll::Pending => {}
                        Poll::Ready(Err(e)) => {
                            self.stop_index(i, Some(e.into()));
                            return Poll::Ready(Event::Activity);
                        }
                        Poll::Ready(Ok(())) => {
                            let used = read.filled().len();
                            if used == 0 {
                                let failure = (row.line_used != 0).then(|| Fault::Truncated.into());
                                self.stop_index(i, failure);
                            } else {
                                row.used = used;
                                row.at = 0;
                                if row.line_until.is_none() {
                                    row.line_until =
                                        Instant::now().checked_add(self.limits.line_lifetime);
                                }
                                self.cursor = (i + 1) % self.rows.len();
                            }
                            return Poll::Ready(Event::Activity);
                        }
                    }
                }
            }
            if self.rows[i].exit.is_none() && !self.rows[i].wait_failed {
                let status = {
                    let mut waiting = std::pin::pin!(self.rows[i].child.wait());
                    waiting.as_mut().poll(cx)
                };
                match status {
                    Poll::Ready(Ok(status)) => self.rows[i].exit = Some(status),
                    Poll::Ready(Err(error)) => {
                        self.rows[i].wait_failed = true;
                        self.stop_index(i, Some(error.into()));
                        return Poll::Ready(Event::Activity);
                    }
                    Poll::Pending => {}
                }
            }
            if self.rows[i].exit.is_some()
                && (self.rows[i].stdout.is_none() || self.rows[i].retiring.is_some())
            {
                let mut row = self.rows.swap_remove(i);
                let Some(status) = row.exit.take() else {
                    return Poll::Ready(Event::Activity);
                };
                self.cursor = if self.rows.is_empty() {
                    0
                } else {
                    i % self.rows.len()
                };
                return Poll::Ready(Event::Exited {
                    helper: row.helper,
                    role: row.role,
                    status,
                });
            }
        }
        Poll::Pending
    }
}
impl Drop for Supervisor {
    fn drop(&mut self) {
        self.stop_all();
    }
}
