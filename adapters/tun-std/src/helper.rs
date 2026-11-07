//! Caller-polled official Linux VPN helper transport. A child/pipe epoch is not
//! a TUN descriptor or proof that this process owns the observed kernel device.
//! Read-only kernel observations and actual child wait results remain separate.
use crate::{
    AdminFailure, Epoch, Info, Ipv6Watch, Ipv6WatchOptions, Limits, Loss, LossCause, Mode,
    NativeSnapshot, PacketError, ReadEvent, Received, RouteQuery, Stamp, Unsent, WriteEvent,
    WriteId, decode, prefix, version,
};
use std::{
    cell::Cell,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    pin::Pin,
    process::{ExitStatus, Stdio},
    rc::Rc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command},
    time::{Instant, Sleep},
};
const HEADER: usize = 4;
const TYPE: u16 = 185;
const DIAGNOSTIC_BYTES: usize = 4096;
/// Original configuration, using the official five positional helper arguments.
#[derive(Clone, Debug)]
pub struct Options {
    /// Absolute Rust helper path, or an explicitly selected official helper.
    pub executable: PathBuf,
    /// Requested fresh kernel interface name.
    pub interface: String,
    /// IPv4 interface address/netmask; None passes two official "-" arguments.
    pub ipv4: Option<(Ipv4Addr, Ipv4Addr)>,
    /// IPv6 interface address/prefix; None passes two official "-" arguments.
    pub ipv6: Option<(Ipv6Addr, u8)>,
    /// Explicit Rust helper override. None preserves the C helper's native MTU.
    /// GNUNET_VPN_HELPER_MTU is not an option understood by the C helper.
    pub mtu: Option<u32>,
    /// Original finite initialization/qualification deadline, never refreshed.
    pub until: Instant,
    /// Native cap from the first byte of each incomplete stdout frame.
    pub partial_lifetime: Duration,
}
/// Actual child result and independent native shutdown failures. Exiting zero
/// says nothing about packet delivery; a requested kill is normal retirement.
#[derive(Debug)]
pub struct Report {
    /// Actual original OS wait result, if wait succeeded.
    pub status: Option<ExitStatus>,
    /// Original PID observed at spawn, diagnostic only.
    pub pid: Option<u32>,
    /// Actual first stop-signal/kill error, independently retained.
    pub kill_error: Option<io::Error>,
    /// Actual earlier nonblocking wait error, independently retained.
    pub poll_wait_error: Option<io::Error>,
    /// Actual final child wait error, independently retained.
    pub wait_error: Option<io::Error>,
    /// Actual stderr read failure, independently retained from wait/packet I/O.
    pub stderr_error: Option<io::Error>,
    /// First bounded actual stderr bytes, never parsed as an error/ready ACK.
    pub stderr: Vec<u8>,
    /// Actual stderr bytes read after the retained diagnostic capacity filled.
    pub stderr_discarded: u64,
    /// Whether actual stderr EOF was observed; false is not silently called drain.
    pub stderr_eof: bool,
    /// Whole frames accepted by the original helper stdin pipe, not TUN writes.
    pub submitted: u64,
    /// Actual stdout bytes read before retirement.
    pub read_bytes: u64,
    /// Bytes of the last incomplete stdout frame when the source was closed.
    pub partial_bytes: usize,
    /// Last observed kernel interface identity. This is not a child ownership ACK.
    pub interface: Info,
}
impl Report {
    /// Whether actual wait/kill errors prevent clean process-retirement reporting.
    #[must_use]
    pub fn failed(&self) -> bool {
        self.kill_error.is_some()
            || self.poll_wait_error.is_some()
            || self.wait_error.is_some()
            || self.stderr_error.is_some()
            || self.status.is_none()
    }
}
impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VPN helper process retirement: {self:?}")
    }
}
impl std::error::Error for Report {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.kill_error
            .as_ref()
            .or(self.poll_wait_error.as_ref())
            .or(self.wait_error.as_ref())
            .or(self.stderr_error.as_ref())
            .map(|e| e as _)
    }
}
struct Diagnostic {
    io: Option<ChildStderr>,
    bytes: Vec<u8>,
    discarded: u64,
    error: Option<io::Error>,
    eof: bool,
}
impl Diagnostic {
    fn poll(&mut self, cx: &mut Context<'_>) -> bool {
        let Some(io) = &mut self.io else {
            return false;
        };
        let mut chunk = [0; 256];
        let mut buffer = ReadBuf::new(&mut chunk);
        match Pin::new(io).poll_read(cx, &mut buffer) {
            Poll::Pending => false,
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {
                cx.waker().wake_by_ref();
                false
            }
            Poll::Ready(Err(error)) => {
                self.error = Some(error);
                self.io.take();
                true
            }
            Poll::Ready(Ok(())) => {
                let data = buffer.filled();
                if data.is_empty() {
                    self.eof = true;
                    self.io.take();
                    return true;
                }
                let retain = data.len().min(DIAGNOSTIC_BYTES - self.bytes.len());
                self.bytes.extend_from_slice(&data[..retain]);
                self.discarded = self.discarded.saturating_add((data.len() - retain) as u64);
                cx.waker().wake_by_ref();
                true
            }
        }
    }
}
enum Guard {
    WriteExpired(WriteId),
    Lost(Loss),
}
struct Pending {
    id: WriteId,
    frame: Vec<u8>,
    raw: usize,
    at: usize,
    until: Instant,
    alarm: Pin<Box<Sleep>>,
}
/// Original child, its unique pipes and immutable packet debt. No detached
/// task, replacement registration, private ACK or fallback device is created.
pub struct Link {
    child: Option<Child>,
    input: Option<ChildStdin>,
    output: Option<ChildStdout>,
    diagnostic: Diagnostic,
    epoch: Epoch,
    info: Info,
    options: Options,
    maximum: usize,
    next: u64,
    pending: Option<Pending>,
    rx: Vec<u8>,
    tx_spare: Vec<u8>,
    rx_used: usize,
    rx_needed: usize,
    partial: Option<(Instant, Pin<Box<Sleep>>)>,
    interval: Pin<Box<Sleep>>,
    startup: Pin<Box<Sleep>>,
    status: Option<ExitStatus>,
    pid: Option<u32>,
    kill_error: Option<io::Error>,
    poll_wait_error: Option<io::Error>,
    wait_error: Option<io::Error>,
    closing: bool,
    submitted: u64,
    reported: bool,
    exit_profile: bool,
    prepared: bool,
    read_bytes: u64,
    partial_bytes: usize,
}
impl Link {
    /// Validate and reserve all packet memory before real spawn. Successful spawn
    /// admits only a child and pipes; poll_prepare still needs native state.
    pub fn spawn(options: Options, limits: Limits) -> io::Result<Self> {
        Self::spawn_profile(options, None, limits)
    }
    /// Launch the official EXIT six-argument helper. Some egress inserts its
    /// exact name; None inserts the official "-" disable argument. This grants
    /// no forwarding/NAT or helper-ready ACK; all packet lifecycle is unchanged.
    pub fn spawn_exit(
        options: Options,
        physical: Option<String>,
        limits: Limits,
    ) -> io::Result<Self> {
        if physical.as_ref().is_some_and(|name| {
            name.is_empty()
                || name.len() >= libc::IFNAMSIZ
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
        }) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid EXIT egress interface",
            ));
        }
        Self::spawn_profile(options, Some(physical), limits)
    }
    fn spawn_profile(
        options: Options,
        physical: Option<Option<String>>,
        limits: Limits,
    ) -> io::Result<Self> {
        limits.validate()?;
        let now = Instant::now();
        if !options.executable.is_absolute()
            || options.interface.is_empty()
            || options.interface.len() >= libc::IFNAMSIZ
            || options.interface.as_bytes().contains(&0)
            || options.until <= now
            || options.partial_lifetime.is_zero()
            || now.checked_add(options.partial_lifetime).is_none()
            || options.mtu.is_some_and(|mtu| !(68..=65535).contains(&mtu))
            || options
                .ipv6
                .is_some_and(|(_, bits)| bits == 0 || bits > 127)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VPN helper options",
            ));
        }
        if !cfg!(target_os = "linux") {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "official VPN helper is Linux-only",
            ));
        }
        match crate::platform::index(&options.interface) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "fresh helper interface already exists",
                ));
            }
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::ENXIO | libc::ENODEV | libc::ENOENT)
                ) => {}
            Err(e) => return Err(e),
        }
        let maximum = limits.packet_bytes.min(u16::MAX as usize - HEADER - 4);
        let minimum = if options.ipv6.is_some() { 1280 } else { 68 };
        if maximum < minimum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "helper packet capacity below family MTU minimum",
            ));
        }

        if options
            .mtu
            .is_some_and(|mtu| mtu as usize > maximum || (options.ipv6.is_some() && mtu < 1280))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "helper MTU exceeds official frame/family bounds",
            ));
        }
        let capacity = maximum
            .checked_add(HEADER + 4)
            .ok_or_else(|| io::Error::other("helper capacity overflow"))?;
        let mut rx = Vec::new();
        rx.try_reserve_exact(capacity)
            .map_err(|_| io::Error::other("helper RX capacity"))?;
        rx.resize(capacity, 0);
        let mut tx_spare = Vec::new();
        tx_spare
            .try_reserve_exact(capacity)
            .map_err(|_| io::Error::other("helper TX capacity"))?;
        let mut diagnostic = Vec::new();
        diagnostic
            .try_reserve_exact(DIAGNOSTIC_BYTES)
            .map_err(|_| io::Error::other("helper diagnostic capacity"))?;
        let exit_profile = physical.is_some();
        let mut command = Command::new(&options.executable);
        command.arg(&options.interface);
        if let Some(physical) = physical {
            command.arg(physical.as_deref().unwrap_or("-"));
        }
        match options.ipv6 {
            Some((address, bits)) => {
                command.arg(address.to_string()).arg(bits.to_string());
            }
            None => {
                command.arg("-").arg("-");
            }
        }
        match options.ipv4 {
            Some((address, mask)) => {
                command.arg(address.to_string()).arg(mask.to_string());
            }
            None => {
                command.arg("-").arg("-");
            }
        }
        // The default remains usable with the original C helper. An explicit
        // override selects the documented Rust helper extension only.
        command.env_remove("GNUNET_VPN_HELPER_MTU");
        if let Some(mtu) = options.mtu {
            command.env("GNUNET_VPN_HELPER_MTU", mtu.to_string());
        }
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(false);
        if Instant::now() >= options.until {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let mut child = command.spawn()?;
        let pid = child.id();
        // Tokio's successful piped spawn supplies both ends; retain the Child
        // even if a platform unexpectedly fails to supply one, so explicit
        // poll_prepare failure still goes through actual stop + wait.
        let input = child.stdin.take();
        let output = child.stdout.take();
        let diagnostic = Diagnostic {
            io: child.stderr.take(),
            bytes: diagnostic,
            discarded: 0,
            error: None,
            eof: false,
        };
        let info = Info {
            name: options.interface.clone(),
            index: 0,
            mode: Mode::LinuxPi,
        };
        let startup = Box::pin(tokio::time::sleep_until(options.until));
        Ok(Self {
            child: Some(child),
            input,
            output,
            diagnostic,
            epoch: Epoch(Rc::new(Stamp {
                alive: Cell::new(true),
            })),
            info,
            options,
            maximum,
            next: 0,
            pending: None,
            rx,
            tx_spare,
            rx_used: 0,
            rx_needed: HEADER,
            partial: None,
            interval: Box::pin(tokio::time::sleep(Duration::ZERO)),
            startup,
            status: None,
            pid,
            kill_error: None,
            poll_wait_error: None,
            wait_error: None,
            closing: false,
            submitted: 0,
            reported: false,
            exit_profile,
            prepared: false,
            read_bytes: 0,
            partial_bytes: 0,
        })
    }
    /// Original real process/pipe lifetime; not an authentication/ownership proof.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.epoch.clone()
    }
    /// Captured actual kernel index is zero until the first successful query.
    #[must_use]
    pub fn info(&self) -> &Info {
        &self.info
    }
    /// Exact-MTU mode is used only for an explicit Rust helper override.
    #[must_use]
    pub fn explicit_mtu(&self) -> Option<u32> {
        self.options.mtu
    }
    /// Original finite helper initialization deadline.
    #[must_use]
    pub fn initial_deadline(&self) -> Instant {
        self.options.until
    }
    /// Whether this actual MTU fits explicit override or default native policy.
    #[must_use]
    pub fn accepts_mtu(&self, mtu: u32) -> bool {
        let minimum = if self.options.ipv6.is_some() {
            1280
        } else {
            68
        };
        mtu >= minimum
            && mtu as usize <= self.maximum
            && self.options.mtu.is_none_or(|explicit| mtu == explicit)
    }
    fn stopped(&mut self) -> Option<io::Error> {
        if self.status.is_some() || self.poll_wait_error.is_some() {
            return Some(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "original VPN helper exited",
            ));
        }
        match self.child.as_mut().map(Child::try_wait) {
            Some(Ok(Some(status))) => {
                self.status = Some(status);
                Some(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "original VPN helper exited",
                ))
            }
            Some(Err(error)) => {
                let result = io::Error::new(
                    error.kind(),
                    "original VPN helper wait failed; cause retained",
                );
                self.poll_wait_error = Some(error);
                Some(result)
            }
            _ => None,
        }
    }
    fn wake_interval(&mut self, cx: &mut Context<'_>) {
        if self.interval.as_mut().poll(cx).is_ready() {
            self.interval
                .as_mut()
                .reset(Instant::now() + Duration::from_millis(20));
            let _registered = self.interval.as_mut().poll(cx);
        }
    }
    /// Await actual kernel snapshot equality, not a process-ready ACK. The
    /// observed ifindex becomes fixed and later replacement fails the source.
    pub fn poll_prepare(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), AdminFailure>> {
        if self.closing {
            return Poll::Ready(Err(AdminFailure::SourceRetired));
        }
        if Instant::now() >= self.options.until || self.startup.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(AdminFailure::Deadline));
        }
        self.diagnostic.poll(cx);
        if self.diagnostic.error.is_some() {
            return Poll::Ready(Err(io::Error::other(
                "helper stderr read failed; original cause retained",
            )
            .into()));
        }
        if let Some(error) = self.stopped() {
            return Poll::Ready(Err(error.into()));
        }
        if self.input.is_none() || self.output.is_none() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "missing original helper pipe",
            )
            .into()));
        }
        self.wake_interval(cx);
        if self.info.index == 0 {
            match crate::platform::index(&self.info.name) {
                Ok(index) => self.info.index = index,
                Err(e)
                    if matches!(
                        e.raw_os_error(),
                        Some(libc::ENXIO | libc::ENODEV | libc::ENOENT)
                    ) =>
                {
                    return Poll::Pending;
                }
                Err(e) => return Poll::Ready(Err(e.into())),
            }
        }
        let mut observation = self.snapshot(self.options.until)?;
        let v4 = self.options.ipv4.is_none_or(|(address, mask)| {
            observation.ipv4_address() == crate::Ipv4Observation::Present(address)
                && observation.ipv4_netmask() == crate::Ipv4Observation::Present(mask)
        });
        let mtu = self.accepts_mtu(observation.mtu());
        if let Some(error) = observation.take_close_error() {
            return Poll::Ready(Err(error.into()));
        }
        if observation.up() && v4 && mtu {
            self.prepared = true;
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
    /// Actual snapshot for the captured kernel interface and original pipe epoch.
    pub fn snapshot(&self, until: Instant) -> Result<NativeSnapshot, AdminFailure> {
        crate::admin::snapshot(self.epoch(), self.info.clone(), until, || {
            check_interface(&self.epoch, &self.info, until)
        })
    }
    /// Actual read-only route query, never route creation or ownership evidence.
    pub fn query_route(
        &self,
        destination: IpAddr,
        prefix: u8,
        gateway: Option<IpAddr>,
        until: Instant,
    ) -> Result<RouteQuery, AdminFailure> {
        crate::routes::query::query(
            self.epoch(),
            self.info.clone(),
            destination,
            prefix,
            gateway,
            until,
        )
    }
    /// Actual read-only IPv6/DAD observer on the captured interface generation.
    pub fn watch_ipv6(
        &self,
        address: Ipv6Addr,
        prefix: u8,
        until: Instant,
        options: Ipv6WatchOptions,
    ) -> io::Result<Ipv6Watch> {
        crate::readiness::watch(
            self.epoch(),
            self.info.clone(),
            address,
            prefix,
            until,
            options,
        )
    }
    fn begin_close(&mut self) {
        if self.closing {
            return;
        }
        self.closing = true;
        self.epoch.0.alive.set(false);
        self.input.take();
        self.output.take();
        if self.status.is_none()
            && let Some(child) = &mut self.child
            && self.poll_wait_error.is_none()
            && self.wait_error.is_none()
        {
            // Both profiles require the actual same Child's unreaped state.
            // Unknown/ECHILD errors forbid any later explicit or implicit PID
            // signal; the diagnostic self.pid never restores that authority.
            match child.try_wait() {
                Ok(Some(status)) => self.status = Some(status),
                Ok(None) => {
                    let signal = if self.exit_profile {
                        child
                            .id()
                            .ok_or_else(|| {
                                io::Error::other("original EXIT helper has no live child PID")
                            })
                            .and_then(|pid| i32::try_from(pid).map_err(io::Error::other))
                            .and_then(|pid| {
                                if pid > 0 {
                                    Ok(pid)
                                } else {
                                    Err(io::Error::other("original child PID is not positive"))
                                }
                            })
                            .and_then(|pid| {
                                nix::sys::signal::kill(
                                    nix::unistd::Pid::from_raw(pid),
                                    nix::sys::signal::Signal::SIGTERM,
                                )
                                .map_err(io::Error::from)
                            })
                    } else {
                        child.start_kill()
                    };
                    if let Err(error) = signal {
                        self.kill_error = Some(error);
                    }
                }
                Err(error) => self.poll_wait_error = Some(error),
            }
        }
    }
    fn loss(&mut self, cause: LossCause) -> Loss {
        let mut pending = self.pending.take();
        if let Some(p) = &mut pending {
            p.frame.fill(0);
        }
        self.partial_bytes = self.rx_used;
        self.rx.fill(0);
        self.begin_close();
        Loss {
            epoch: self.epoch(),
            pending: pending.map(|p| p.id),
            cause,
            close_error: None,
        }
    }
    /// Close original pipes and request the original child stop. EXIT sends
    /// SIGTERM through the actual unreaped Child so the Rust helper can settle
    /// its setup subprocess; VPN retains its original kill request. Neither is
    /// reap, and an external C helper status cannot prove its descendants joined.
    pub fn close(&mut self) -> Loss {
        self.loss(LossCause::Closed)
    }
    /// Real mandatory child wait. Native OS waiting is not replaced by a socket
    /// deadline. A caller must retain this future/owner until the actual result.
    pub async fn reap(&mut self) -> Option<Report> {
        if self.reported {
            return None;
        }
        self.begin_close();
        if self.status.is_none()
            && let Some(child) = &mut self.child
        {
            let mut waiting = std::pin::pin!(child.wait());
            let diagnostic = &mut self.diagnostic;
            let result = std::future::poll_fn(|cx| {
                diagnostic.poll(cx);
                waiting.as_mut().poll(cx)
            })
            .await;
            match result {
                Ok(status) => self.status = Some(status),
                Err(error) => self.wait_error = Some(error),
            }
        }
        self.child.take();
        // A finite final read quantum after real wait captures already available
        // diagnostics. A still-open/inherited pipe is closed and reported as
        // non-EOF, never a fabricated process completion or full drain.
        std::future::poll_fn(|cx| {
            for _ in 0..16 {
                if !self.diagnostic.poll(cx) {
                    break;
                }
            }
            Poll::Ready(())
        })
        .await;
        self.diagnostic.io.take();
        self.reported = true;
        Some(Report {
            status: self.status,
            pid: self.pid,
            kill_error: self.kill_error.take(),
            poll_wait_error: self.poll_wait_error.take(),
            wait_error: self.wait_error.take(),
            stderr_error: self.diagnostic.error.take(),
            stderr: std::mem::take(&mut self.diagnostic.bytes),
            stderr_discarded: self.diagnostic.discarded,
            stderr_eof: self.diagnostic.eof,
            submitted: self.submitted,
            interface: self.info.clone(),
            read_bytes: self.read_bytes,
            partial_bytes: self.partial_bytes,
        })
    }
    /// Check/register original stream and write hard limits before any clock wait.
    /// This performs no packet I/O and never renews an admitted deadline.
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<ReadEvent> {
        self.guard(cx).map(|event| match event {
            Guard::WriteExpired(write) => ReadEvent::WriteExpired(write),
            Guard::Lost(loss) => ReadEvent::Lost(loss),
        })
    }
    fn guard(&mut self, cx: &mut Context<'_>) -> Option<Guard> {
        if self.closing {
            return None;
        }
        if self.diagnostic.error.is_some() {
            return Some(Guard::Lost(self.loss(LossCause::Io(io::Error::other(
                "helper stderr read failed; original cause retained",
            )))));
        }
        if !self.prepared
            && (Instant::now() >= self.options.until || self.startup.as_mut().poll(cx).is_ready())
        {
            return Some(Guard::Lost(
                self.loss(LossCause::Io(io::ErrorKind::TimedOut.into())),
            ));
        }
        if let Some((until, alarm)) = &mut self.partial
            && (Instant::now() >= *until || alarm.as_mut().poll(cx).is_ready())
        {
            return Some(Guard::Lost(
                self.loss(LossCause::Io(io::ErrorKind::TimedOut.into())),
            ));
        }
        if let Some(p) = &mut self.pending
            && (Instant::now() >= p.until || p.alarm.as_mut().poll(cx).is_ready())
        {
            if p.at > 0 {
                return Some(Guard::Lost(
                    self.loss(LossCause::Io(io::ErrorKind::TimedOut.into())),
                ));
            }
            let mut p = self.pending.take()?;
            p.frame.fill(0);
            p.frame.clear();
            self.tx_spare = p.frame;
            return Some(Guard::WriteExpired(p.id));
        }
        if let Some(error) = self.stopped() {
            return Some(Guard::Lost(self.loss(LossCause::Io(error))));
        }
        self.wake_interval(cx);
        None
    }
    /// Admit one immutable packet into the original bounded helper writer. Whole
    /// acceptance later proves only pipe acceptance, not helper kernel delivery.
    pub fn queue(&mut self, raw: &[u8], until: Instant) -> io::Result<WriteId> {
        if self.closing || !self.epoch.current() {
            return Err(io::ErrorKind::NotConnected.into());
        }
        if self.pending.is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if Instant::now() >= until {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if raw.len() > self.maximum {
            return Err(PacketError::TooLarge.into());
        }
        let version = version(raw)?;
        let size = raw.len() + HEADER + 4;
        let next = self
            .next
            .checked_add(1)
            .ok_or_else(|| io::Error::other("helper write serial exhausted"))?;
        let mut frame = std::mem::take(&mut self.tx_spare);
        frame.clear();
        frame.extend_from_slice(
            &(u16::try_from(size).map_err(|_| PacketError::TooLarge)?).to_be_bytes(),
        );
        frame.extend_from_slice(&TYPE.to_be_bytes());
        frame.extend_from_slice(&prefix(Mode::LinuxPi, version));
        frame.extend_from_slice(raw);
        self.next = next;
        let id = WriteId {
            epoch: self.epoch(),
            serial: self.next,
            helper_prefix: 0,
        };
        self.pending = Some(Pending {
            id: id.clone(),
            frame,
            raw: raw.len(),
            at: 0,
            until,
            alarm: Box::pin(tokio::time::sleep_until(until)),
        });
        Ok(id)
    }
    /// Cancel this exact original retained frame. An exposed prefix cannot be
    /// withdrawn from a stream: stop the original source and retain real wait
    /// debt instead of splicing another packet into the incomplete frame.
    pub fn cancel(&mut self, id: &WriteId) -> io::Result<WriteEvent> {
        let Some(p) = self.pending.as_ref() else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        if &p.id != id {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if p.at > 0 {
            return Ok(WriteEvent::Lost(self.loss(LossCause::Closed)));
        }
        let mut p = self
            .pending
            .take()
            .ok_or_else(|| io::Error::other("original helper frame absent"))?;
        p.frame.fill(0);
        p.frame.clear();
        self.tx_spare = p.frame;
        Ok(WriteEvent::Unsent {
            write: p.id,
            reason: if Instant::now() >= p.until {
                Unsent::Deadline
            } else {
                Unsent::Cancelled
            },
        })
    }
    /// Perform at most one real stdin write, retaining every positive partial
    /// prefix on this same frame. Cancel/expiry after exposure is never Unsent.
    pub fn poll_write(&mut self, cx: &mut Context<'_>) -> Poll<WriteEvent> {
        if let Some(event) = self.guard(cx) {
            return Poll::Ready(match event {
                Guard::WriteExpired(write) => WriteEvent::Unsent {
                    write,
                    reason: Unsent::Deadline,
                },
                Guard::Lost(loss) => WriteEvent::Lost(loss),
            });
        }
        if self.closing {
            return Poll::Ready(WriteEvent::Closed);
        }
        self.diagnostic.poll(cx);
        if self.diagnostic.error.is_some() {
            return Poll::Ready(WriteEvent::Lost(self.loss(LossCause::Io(
                io::Error::other("helper stderr read failed; original cause retained"),
            ))));
        }
        let Some(p) = &mut self.pending else {
            return Poll::Ready(WriteEvent::Idle);
        };
        let Some(input) = &mut self.input else {
            return Poll::Ready(WriteEvent::Lost(self.loss(LossCause::Eof)));
        };
        match Pin::new(input).poll_write(cx, &p.frame[p.at..]) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Err(error)) => {
                Poll::Ready(WriteEvent::Lost(self.loss(LossCause::Io(error))))
            }
            Poll::Ready(Ok(0)) => Poll::Ready(WriteEvent::Lost(self.loss(LossCause::WriteZero))),
            Poll::Ready(Ok(n)) => {
                p.at += n;
                p.id.helper_prefix = p.at;
                if p.at != p.frame.len() {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                let Some(mut p) = self.pending.take() else {
                    return Poll::Ready(WriteEvent::Closed);
                };
                p.frame.fill(0);
                p.frame.clear();
                self.tx_spare = p.frame;
                self.submitted = self.submitted.saturating_add(1);
                Poll::Ready(WriteEvent::Written {
                    write: p.id,
                    raw_bytes: p.raw,
                })
            }
        }
    }
    /// At most one real stdout read per turn. The four-byte message header and
    /// complete Linux PI packet are retained across caller-future cancellation.
    pub fn poll_read(&mut self, cx: &mut Context<'_>) -> Poll<ReadEvent> {
        if let Some(event) = self.poll_native_guard(cx) {
            return Poll::Ready(event);
        }
        if self.closing {
            return Poll::Ready(ReadEvent::Closed);
        }
        self.diagnostic.poll(cx);
        if self.diagnostic.error.is_some() {
            return Poll::Ready(ReadEvent::Lost(self.loss(LossCause::Io(io::Error::other(
                "helper stderr read failed; original cause retained",
            )))));
        }
        let Some(output) = &mut self.output else {
            return Poll::Ready(ReadEvent::Lost(self.loss(LossCause::Eof)));
        };
        let mut buffer = ReadBuf::new(&mut self.rx[self.rx_used..self.rx_needed]);
        let n = match Pin::new(output).poll_read(cx, &mut buffer) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Ready(Err(error)) => {
                return Poll::Ready(ReadEvent::Lost(self.loss(LossCause::Io(error))));
            }
            Poll::Ready(Ok(())) => buffer.filled().len(),
        };
        if n == 0 {
            return Poll::Ready(ReadEvent::Lost(self.loss(LossCause::Eof)));
        }
        if self.partial.is_none() {
            let Some(until) = Instant::now().checked_add(self.options.partial_lifetime) else {
                return Poll::Ready(ReadEvent::Lost(self.loss(LossCause::Capacity)));
            };
            self.partial = Some((until, Box::pin(tokio::time::sleep_until(until))));
        }
        self.read_bytes = self.read_bytes.saturating_add(n as u64);
        self.rx_used += n;
        if self.rx_used == HEADER && self.rx_needed == HEADER {
            let size = usize::from(u16::from_be_bytes([self.rx[0], self.rx[1]]));
            if u16::from_be_bytes([self.rx[2], self.rx[3]]) != TYPE
                || size < HEADER + 4 + 20
                || size > self.rx.len()
            {
                return Poll::Ready(ReadEvent::Lost(self.loss(LossCause::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "official VPN helper frame header",
                )))));
            }
            self.rx_needed = size;
        }
        if self.rx_used != self.rx_needed {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let decoded = decode(Mode::LinuxPi, &self.rx[HEADER..self.rx_needed]);
        let event = match decoded {
            Ok((version, _)) => {
                let mut frame = Vec::new();
                if frame.try_reserve_exact(self.rx_needed - HEADER).is_err() {
                    return Poll::Ready(ReadEvent::Lost(self.loss(LossCause::Capacity)));
                }
                frame.extend_from_slice(&self.rx[HEADER..self.rx_needed]);
                ReadEvent::Packet(Received {
                    epoch: self.epoch(),
                    mode: Mode::LinuxPi,
                    version,
                    frame,
                })
            }
            Err(error) => ReadEvent::Rejected(error),
        };
        self.rx[..self.rx_needed].fill(0);
        self.rx_used = 0;
        self.rx_needed = HEADER;
        self.partial = None;
        Poll::Ready(event)
    }
}
impl Drop for Link {
    fn drop(&mut self) {
        self.begin_close();
        self.rx.fill(0);
        self.tx_spare.fill(0);
        if let Some(p) = &mut self.pending {
            p.frame.fill(0);
        }
        // Drop makes only the explicit same-Child authorized stop attempt. Both
        // profiles disable Tokio kill_on_drop: an unknown/ECHILD wait error must
        // not leave a later implicit PID signal armed. No wait/reap is claimed;
        // normal callers must retain and drive reap().
    }
}
/// Check an observed kernel interface against the original child/pipe lifetime.
/// No descriptor adoption, process readiness or administrative ownership follows.
pub(crate) fn check_interface(
    epoch: &Epoch,
    info: &Info,
    until: Instant,
) -> Result<(), AdminFailure> {
    if !epoch.current() || info.index == 0 {
        return Err(AdminFailure::SourceRetired);
    }
    if Instant::now() >= until {
        return Err(AdminFailure::Deadline);
    }
    let actual = crate::platform::index(&info.name)?;
    if actual != info.index {
        return Err(AdminFailure::SourceRetired);
    }
    Ok(())
}
