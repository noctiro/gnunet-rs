//! Actual original Rust-helper process/pipes with bounded immutable MQ cursors.
mod process;
use crate::{Error, core::Effect};
use gnunet_service_runtime::framing::OwnedFrame;
use gnunet_types::Error as Fault;
use process::{Child, Input, Output as PipeOutput, Stop};
use std::future::Future;
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    pin::Pin,
    process::ExitStatus,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Instant, Sleep},
};
use zeroize::Zeroizing;
/// Original explicit privileged helper invocation. The program must be the
/// installed Rust helper from this implementation; no C binary is wrapped.
pub struct HelperOptions {
    /// Absolute actual executable path.
    pub program: PathBuf,
    /// Requested interface, checked by actual kernel helper.
    pub interface: String,
    /// Actual original configured IPv6 address.
    pub ipv6: Ipv6Addr,
    /// Actual prefix0..128.
    pub prefix: u8,
    /// Actual configured IPv4 address.
    pub ipv4: Ipv4Addr,
    /// Actual configured contiguous netmask.
    pub mask: Ipv4Addr,
    /// Official SKIP_ROUTING_SETUP, no firewall installed when true.
    pub skip_routing: bool,
    /// Complete helper frame cap,64..65535.
    pub frame_bytes: usize,
    /// Per-syscall pipe slice.
    pub io_slice_bytes: usize,
    /// Fixed first-byte through whole input bound.
    pub input_lifetime: Duration,
    /// Graceful stop through forced native termination budget.
    pub stop_grace: Duration,
}
/// Actual helper source/process observation. No invented READY/configuration ACK.
pub enum HelperEvent<'id> {
    /// Complete actual original stdout frame.
    Frame(OwnedFrame),
    /// Positive original stdin prefix/whole local write.
    Written {
        /// Original immutable output attempt.
        effect: Effect<'id>,
        /// Positive bytes written in this syscall.
        bytes: usize,
        /// Whole original frame reached the local pipe.
        complete: bool,
    },
    /// One positive input slice.
    Read(usize),
    /// Original source failed; caller must physically retire it.
    Failed(io::Error),
    /// Actual wait result retained on that original child.
    Exited(HelperExit),
    /// Existing source is stopping; no original data replay.
    Stopping,
}
impl std::fmt::Debug for HelperEvent<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Frame(frame) => f
                .debug_struct("Frame")
                .field("bytes", &frame.len())
                .finish(),
            Self::Written {
                effect,
                bytes,
                complete,
            } => f
                .debug_struct("Written")
                .field("effect", effect)
                .field("bytes", bytes)
                .field("complete", complete)
                .finish(),
            Self::Read(bytes) => f.debug_tuple("Read").field(bytes).finish(),
            Self::Failed(error) => f.debug_tuple("Failed").field(error).finish(),
            Self::Exited(exit) => f.debug_tuple("Exited").field(exit).finish(),
            Self::Stopping => f.write_str("Stopping"),
        }
    }
}
/// Original process exit and independent stop/wait failures. Native process
/// termination does not prove privileged interception controls were removed.
#[derive(Debug)]
pub struct HelperExit {
    /// Completed native exit status. A failed wait cannot construct this receipt.
    pub status: ExitStatus,
    /// First independent graceful/forced native stop failure.
    pub signal_error: Option<io::Error>,
    /// First failed wait, retained even if a subsequent original-object wait succeeds.
    pub wait_error: Option<io::Error>,
    /// Hard budget requested native forced termination; firewall outcome may be unknown.
    pub forced: bool,
    /// Original pending output exposure at retirement.
    pub pending: Option<(usize, usize)>,
    /// Original incomplete stdout frame prefix, without exposing its bytes.
    pub input_prefix: Option<(usize, usize)>,
}
struct Output<'id> {
    effect: Effect<'id>,
    frame: OwnedFrame,
    offset: usize,
    until: Instant,
}
/// Exactly one owned real process/pipe source, never recreated or replayed.
pub struct Helper<'id> {
    child: Option<Child>,
    stdin: Option<Input>,
    stdout: Option<PipeOutput>,
    rx: Zeroizing<Vec<u8>>,
    read: usize,
    wanted: usize,
    input_until: Option<Instant>,
    tx: Option<Output<'id>>,
    limit: usize,
    slice: usize,
    input_lifetime: Duration,
    grace: Duration,
    stopping: Option<Instant>,
    signal_error: Option<io::Error>,
    startup_error: Option<io::Error>,
    wait_error: Option<io::Error>,
    wait_retry: Option<Instant>,
    wait_failed: bool,
    forced: bool,
    pending: Option<(usize, usize)>,
    timer: Pin<Box<Sleep>>,
    turn: bool,
}
impl<'id> Helper<'id> {
    /// Actual process creation, not DNS interception readiness. No detached task,
    /// shell, C helper fallback, private input frame or auto-reconnect is used.
    pub fn spawn(options: HelperOptions) -> Result<Self, Error> {
        tokio::runtime::Handle::try_current().map_err(|e| io::Error::other(e.to_string()))?;

        if !options.program.is_absolute()
            || options.interface.is_empty()
            || options.interface.len() >= 16
            || !options
                .interface
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            || options.prefix > 128
            || !(64..=65535).contains(&options.frame_bytes)
            || options.io_slice_bytes == 0
            || options.input_lifetime.is_zero()
            || options.stop_grace.is_zero()
        {
            return Err(Fault::InvalidInput.into());
        }
        if Instant::now().checked_add(options.input_lifetime).is_none()
            || Instant::now().checked_add(options.stop_grace).is_none()
        {
            return Err(Fault::Overflow.into());
        }
        let mut rx = Vec::new();
        rx.try_reserve_exact(options.frame_bytes)
            .map_err(|_| Fault::Capacity)?;
        rx.resize(options.frame_bytes, 0);
        let process::Spawned {
            child,
            stdin,
            stdout,
            startup_error,
        } = process::spawn(&options)?;
        Ok(Self {
            child: Some(child),
            stdin,
            stdout,
            rx: Zeroizing::new(rx),
            read: 0,
            wanted: 4,
            input_until: None,
            tx: None,
            limit: options.frame_bytes,
            slice: options.io_slice_bytes,
            input_lifetime: options.input_lifetime,
            grace: options.stop_grace,
            stopping: None,
            signal_error: None,
            startup_error,
            wait_error: None,
            wait_retry: None,
            wait_failed: false,
            forced: false,
            pending: None,
            timer: Box::pin(tokio::time::sleep_until(Instant::now())),
            turn: false,
        })
    }
    /// Actual expected process/pipe ownership, without configuration-ready proof.
    pub fn initialized(&self) -> bool {
        self.child.is_some()
            && self.stdin.is_some()
            && self.stdout.is_some()
            && self.startup_error.is_none()
    }
    pub(crate) fn take_startup_error(&mut self) -> Option<io::Error> {
        self.startup_error.take()
    }
    /// Actual original PID metadata for incomplete cleanup diagnostics.
    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().and_then(Child::id)
    }
    /// One immutable original queue admission, before any positive pipe write.
    pub fn queue(
        &mut self,
        effect: Effect<'id>,
        frame: OwnedFrame,
        until: Instant,
    ) -> Result<(), (Error, OwnedFrame)> {
        if self.stopping.is_some() || self.stdin.is_none() {
            return Err((Fault::Closed.into(), frame));
        }
        if self.tx.is_some() {
            return Err((Fault::WouldBlock.into(), frame));
        }
        if frame.len() > self.limit {
            return Err((Fault::TooLarge.into(), frame));
        }
        if Instant::now() >= until {
            return Err((Fault::Deadline.into(), frame));
        }
        self.tx = Some(Output {
            effect,
            frame,
            offset: 0,
            until,
        });
        Ok(())
    }
    /// Exact original queued/exposed prefix for independent no-clock cleanup.
    pub fn pending(&self) -> Option<(Effect<'id>, usize, usize)> {
        self.tx
            .as_ref()
            .map(|o| (o.effect, o.offset, o.frame.len()))
    }
    /// Whether this actual original output queue has a free slot.
    pub fn writable(&self) -> bool {
        self.stdin.is_some() && self.stopping.is_none() && self.tx.is_none()
    }
    fn stop_child(&mut self, stop: Stop) {
        if let Some(child) = self.child.as_ref()
            && let Err(error) = child.stop(stop)
            && self.signal_error.is_none()
        {
            self.signal_error = Some(error);
        }
    }
    /// Close local pipe admission before retiring the original core source.
    /// Pending IOCP work remains reactor-owned; closure is not child consumption
    /// or native I/O completion. The child stays owned until its actual exit.
    pub fn request_stop(&mut self) {
        if self.stopping.is_none() {
            self.pending = self.tx.as_ref().map(|o| (o.offset, o.frame.len()));
            self.tx = None;
            self.stdin = None;
            self.stdout = None;
            self.stopping = Instant::now().checked_add(self.grace);
            if self.stopping.is_none() {
                self.forced = true;
                self.stop_child(Stop::Force);
            } else {
                self.stop_child(Stop::Graceful);
            }
        }
    }
    /// Actual process retirement, driven independently from canonical clock.
    pub fn poll_exit(&mut self, cx: &mut Context<'_>) -> Poll<HelperExit> {
        if self.stopping.is_some_and(|d| Instant::now() >= d) && !self.forced {
            self.forced = true;
            self.stop_child(Stop::Force);
        }
        let Some(child) = self.child.as_mut() else {
            return Poll::Pending;
        };
        let status = if self.wait_retry.is_none_or(|at| Instant::now() >= at) {
            self.wait_retry = None;
            child.poll_exit(cx)
        } else {
            Poll::Pending
        };
        if let Poll::Ready(Err(error)) = status {
            if self.wait_error.is_none() {
                self.wait_error = Some(error);
                self.wait_failed = true;
            }
            // Wait failure is not an exit receipt. Keep the original child and
            // all cleanup authority; retry without spinning or admitting data.
            self.request_stop();
            self.wait_retry = Instant::now().checked_add(Duration::from_millis(50));
        } else if let Poll::Ready(Ok(status)) = status {
            self.pending = self
                .pending
                .take()
                .or_else(|| self.tx.as_ref().map(|o| (o.offset, o.frame.len())));
            self.stdin = None;
            self.stdout = None;
            self.tx = None;
            self.child = None;
            return Poll::Ready(HelperExit {
                status,
                wait_error: self.wait_error.take(),
                signal_error: self.signal_error.take(),
                forced: self.forced,
                pending: self.pending.take(),
                input_prefix: (self.read != 0).then_some((self.read, self.wanted)),
            });
        }
        let wake = self
            .stopping
            .filter(|_| !self.forced)
            .into_iter()
            .chain(self.wait_retry)
            .min();
        if let Some(at) = wake {
            self.timer.as_mut().reset(at);
            if self.timer.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
        Poll::Pending
    }
    fn write(&mut self, cx: &mut Context<'_>) -> Poll<HelperEvent<'id>> {
        let Some(output) = self.tx.as_mut() else {
            return Poll::Pending;
        };
        if Instant::now() >= output.until {
            return Poll::Ready(HelperEvent::Failed(io::Error::new(
                io::ErrorKind::TimedOut,
                "original DNS helper output deadline",
            )));
        }
        let Some(stdin) = self.stdin.as_mut() else {
            return Poll::Pending;
        };
        let end = output
            .frame
            .len()
            .min(output.offset.saturating_add(self.slice));
        match Pin::new(stdin).poll_write(cx, &output.frame.bytes()[output.offset..end]) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(HelperEvent::Failed(e)),
            Poll::Ready(Ok(0)) => Poll::Ready(HelperEvent::Failed(io::Error::new(
                io::ErrorKind::WriteZero,
                "DNS helper stdin",
            ))),
            Poll::Ready(Ok(n)) => {
                output.offset += n;
                let effect = output.effect;
                let complete = output.offset == output.frame.len();
                if complete {
                    self.tx = None;
                }
                Poll::Ready(HelperEvent::Written {
                    effect,
                    bytes: n,
                    complete,
                })
            }
        }
    }
    fn read(&mut self, cx: &mut Context<'_>) -> Poll<HelperEvent<'id>> {
        if self.input_until.is_some_and(|d| Instant::now() >= d) {
            return Poll::Ready(HelperEvent::Failed(io::Error::new(
                io::ErrorKind::TimedOut,
                "DNS helper original partial input",
            )));
        }
        let Some(stdout) = self.stdout.as_mut() else {
            return Poll::Pending;
        };
        let end = self.wanted.min(self.read.saturating_add(self.slice));
        let mut read = ReadBuf::new(&mut self.rx[self.read..end]);
        match Pin::new(stdout).poll_read(cx, &mut read) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(HelperEvent::Failed(e)),
            Poll::Ready(Ok(())) => {
                let n = read.filled().len();
                if n == 0 {
                    return Poll::Ready(HelperEvent::Failed(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "DNS helper stdout",
                    )));
                }
                self.read += n;
                self.input_until
                    .get_or_insert_with(|| Instant::now() + self.input_lifetime);
                if self.read == 4 && self.wanted == 4 {
                    let size = usize::from(u16::from_be_bytes([self.rx[0], self.rx[1]]));
                    if size < 8 || size > self.limit {
                        return Poll::Ready(HelperEvent::Failed(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "DNS helper frame size",
                        )));
                    }
                    self.wanted = size;
                }
                if self.read == self.wanted {
                    let frame = match OwnedFrame::copy_from(&self.rx[..self.read]) {
                        Ok(f) => f,
                        Err(e) => return Poll::Ready(HelperEvent::Failed(io::Error::other(e))),
                    };
                    self.rx[..self.read].fill(0);
                    self.read = 0;
                    self.wanted = 4;
                    self.input_until = None;
                    return Poll::Ready(HelperEvent::Frame(frame));
                }
                Poll::Ready(HelperEvent::Read(n))
            }
        }
    }
    /// Original native process/pipe deadlines only; no logical clock or new
    /// read/write. Called by an outer coordinator before waiting for its clock.
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Poll<HelperEvent<'id>> {
        if let Some(error) = self.startup_error.take() {
            return Poll::Ready(HelperEvent::Failed(error));
        }
        if let Poll::Ready(exit) = self.poll_exit(cx) {
            return Poll::Ready(HelperEvent::Exited(exit));
        }
        if self.input_until.is_some_and(|d| Instant::now() >= d)
            || self.tx.as_ref().is_some_and(|o| Instant::now() >= o.until)
        {
            return Poll::Ready(HelperEvent::Failed(io::Error::new(
                io::ErrorKind::TimedOut,
                "original DNS helper source deadline",
            )));
        }
        if let Some(at) = self
            .input_until
            .into_iter()
            .chain(self.tx.as_ref().map(|o| o.until))
            .min()
        {
            self.timer.as_mut().reset(at);
            if self.timer.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
        Poll::Pending
    }
    /// One fair actual child/pipe event. A dropped wait leaves original cursors.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<HelperEvent<'id>> {
        if let Some(error) = self.startup_error.take() {
            return Poll::Ready(HelperEvent::Failed(error));
        }

        if let Poll::Ready(exit) = self.poll_exit(cx) {
            return Poll::Ready(HelperEvent::Exited(exit));
        }
        if std::mem::take(&mut self.wait_failed) {
            return Poll::Ready(HelperEvent::Failed(io::Error::other(
                "DNS helper original wait failed; child retirement remains pending",
            )));
        }
        if self.stopping.is_some() {
            return Poll::Pending;
        }
        for class in [self.turn, !self.turn] {
            let event = if class { self.read(cx) } else { self.write(cx) };
            if event.is_ready() {
                self.turn = !class;
                return event;
            }
        }
        let wake = self
            .input_until
            .into_iter()
            .chain(self.tx.as_ref().map(|o| o.until))
            .min();
        if let Some(wake) = wake {
            self.timer.as_mut().reset(wake);
            if self.timer.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
        Poll::Pending
    }
}
impl Drop for Helper<'_> {
    fn drop(&mut self) {
        self.request_stop();
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn check_group(pid: u32) -> io::Result<()> {
    use std::io::Read;
    // Spawn's caller uses its original post-exec child PID; the helper uses
    // getppid() before any privileged configuration. Neither process changes GID.
    let path = format!("/proc/{pid}/status");
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(16385)
        .map_err(|_| io::Error::other("DNS helper credential observation allocation"))?;
    std::fs::File::open(path)?
        .take(16385)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 16384 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS helper credential status bound",
        ));
    }
    let line = bytes
        .split(|b| *b == b'\n')
        .find(|line| line.starts_with(b"Gid:"))
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "DNS helper actual GID absent")
        })?;
    let effective = line
        .split(|b| b.is_ascii_whitespace())
        .filter(|v| !v.is_empty())
        .nth(2)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS helper actual effective GID absent",
            )
        })?;
    let effective = std::str::from_utf8(effective)
        .ok()
        .and_then(|n| n.parse::<u32>().ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS helper actual effective GID malformed",
            )
        })?;
    if effective != nix::unistd::getegid().as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "DNS daemon/helper effective GIDs differ; upstream DNS would be intercepted recursively",
        ));
    }
    Ok(())
}
