//! Actual nonblocking pipe/TUN pump. AsyncFd owns duplicated original stdio
//! descriptors, avoiding Tokio stdin's implicit blocking-worker thread.
use super::*;
use gnunet_service_runtime::framing::OwnedFrame;
use gnunet_service_runtime::readiness::RegisteredIo;
use gnunet_tun_host::{AsyncTun, Loss, ReadEvent, WriteEvent, WriteId};
use std::future::{Future, poll_fn};
use std::{
    os::fd::{AsFd, OwnedFd},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::signal::unix::{Signal, SignalKind};
use zeroize::Zeroizing;
struct Pipe(RegisteredIo);
impl Pipe {
    fn new(fd: OwnedFd) -> io::Result<Self> {
        use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
        let descriptor_flags = fcntl(&fd, FcntlArg::F_GETFD).map_err(io::Error::from)?;
        fcntl(
            &fd,
            FcntlArg::F_SETFD(FdFlag::from_bits_truncate(descriptor_flags) | FdFlag::FD_CLOEXEC),
        )
        .map_err(io::Error::from)?;
        let flags = fcntl(&fd, FcntlArg::F_GETFL).map_err(io::Error::from)?;
        fcntl(
            &fd,
            FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK),
        )
        .map_err(io::Error::from)?;
        Ok(Self(
            RegisteredIo::new(fd).map_err(|failure| failure.error)?,
        ))
    }
    fn read(&self, cx: &mut Context<'_>, bytes: &mut [u8]) -> Poll<io::Result<usize>> {
        self.0.poll_read(cx, bytes)
    }
    fn write(&self, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        self.0.poll_write(cx, bytes)
    }
}
/// Actual metadata only; DNS payload bytes never enter diagnostic fields.
#[derive(Debug, Default)]
pub(super) struct PumpReport {
    pub captured: u64,
    pub tun_written: u64,
    pub pipe_written: u64,
    pub discarded: u64,
    pub pending_prefix: Option<(usize, usize)>,
    pub input_prefix: Option<(usize, usize)>,
    pub native_loss: Option<Loss>,
    pub first: Option<io::Error>,
}
struct Output {
    frame: OwnedFrame,
    offset: usize,
    until: tokio::time::Instant,
}
/// Original pumps/signals prepared before any privileged routing mutation.
pub(super) struct Pump {
    input: Pipe,
    output: Pipe,
    rx: Zeroizing<Vec<u8>>,
    read: usize,
    wanted: usize,
    read_until: Option<tokio::time::Instant>,
    out: Option<Output>,
    write: Option<WriteId>,
    signals: [Signal; 3],
    timer: Pin<Box<tokio::time::Sleep>>,
    turn: usize,
    report: PumpReport,
}
impl Pump {
    pub fn new() -> io::Result<Self> {
        let stdin = std::io::stdin();
        let stdout = std::io::stdout();
        let input = Pipe::new(nix::unistd::dup(stdin.as_fd()).map_err(io::Error::from)?)?;
        let output = Pipe::new(nix::unistd::dup(stdout.as_fd()).map_err(io::Error::from)?)?;
        let mut rx = Vec::new();
        rx.try_reserve_exact(65535)
            .map_err(|_| io::Error::other("DNS helper input allocation"))?;
        rx.resize(65535, 0);
        Ok(Self {
            input,
            output,
            rx: Zeroizing::new(rx),
            read: 0,
            wanted: 4,
            read_until: None,
            out: None,
            write: None,
            signals: [
                tokio::signal::unix::signal(SignalKind::interrupt())?,
                tokio::signal::unix::signal(SignalKind::terminate())?,
                tokio::signal::unix::signal(SignalKind::hangup())?,
            ],
            timer: Box::pin(tokio::time::sleep_until(tokio::time::Instant::now())),
            turn: 0,
            report: PumpReport::default(),
        })
    }
    fn step(&mut self, cx: &mut Context<'_>, tun: &mut AsyncTun) -> Poll<io::Result<bool>> {
        for signal in &mut self.signals {
            if let Poll::Ready(result) = signal.poll_recv(cx) {
                return Poll::Ready(result.map(|()| Ok(false)).unwrap_or_else(|| {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "DNS helper signal source closed",
                    ))
                }));
            }
        }
        if self
            .read_until
            .is_some_and(|at| tokio::time::Instant::now() >= at)
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "DNS helper original input lifetime",
            )));
        }
        if self
            .out
            .as_ref()
            .is_some_and(|o| tokio::time::Instant::now() >= o.until)
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "DNS helper original stdout lifetime",
            )));
        }
        for n in 0..4 {
            let class = (self.turn + n) % 4;
            let progress = match class {
                0 => {
                    if let Some(output) = self.out.as_mut() {
                        let result = self
                            .output
                            .write(cx, &output.frame.bytes()[output.offset..]);
                        match result {
                            Poll::Pending => Poll::Pending,
                            Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::BrokenPipe => {
                                Poll::Ready(Ok(false))
                            }
                            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                            Poll::Ready(Ok(0)) => Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "DNS helper stdout",
                            ))),
                            Poll::Ready(Ok(n)) => {
                                output.offset += n;
                                self.report.pipe_written =
                                    self.report.pipe_written.saturating_add(n as u64);
                                if output.offset == output.frame.len() {
                                    self.out = None;
                                }
                                Poll::Ready(Ok(true))
                            }
                        }
                    } else {
                        Poll::Pending
                    }
                }
                1 => {
                    if self.write.is_some() {
                        match tun.poll_write(cx) {
                            Poll::Pending => Poll::Pending,
                            Poll::Ready(WriteEvent::Written { write, .. }) => {
                                if self.write.as_ref() != Some(&write) {
                                    return Poll::Ready(Err(io::Error::other(
                                        "DNS original TUN write mismatch",
                                    )));
                                }
                                self.write = None;
                                self.report.tun_written = self.report.tun_written.saturating_add(1);
                                Poll::Ready(Ok(true))
                            }
                            Poll::Ready(WriteEvent::Lost(loss)) => {
                                self.report.native_loss = Some(loss);
                                Poll::Ready(Err(io::Error::other("DNS original TUN source lost")))
                            }
                            Poll::Ready(WriteEvent::Unsent { .. }) => {
                                self.write = None;
                                Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::TimedOut,
                                    "DNS original TUN packet was not submitted",
                                )))
                            }
                            Poll::Ready(WriteEvent::Idle) => {
                                Poll::Ready(Err(io::Error::other("DNS TUN write disappeared")))
                            }
                            Poll::Ready(WriteEvent::Closed) => Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::NotConnected,
                                "DNS TUN closed",
                            ))),
                            Poll::Ready(WriteEvent::WaitDeadline) => Poll::Pending,
                        }
                    } else {
                        Poll::Pending
                    }
                }
                2 => {
                    if self.write.is_some() {
                        Poll::Pending
                    } else {
                        match self.input.read(cx, &mut self.rx[self.read..self.wanted]) {
                            Poll::Pending => Poll::Pending,
                            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                            Poll::Ready(Ok(0)) if self.read == 0 => Poll::Ready(Ok(false)),
                            Poll::Ready(Ok(0)) => Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "DNS helper original partial input closed",
                            ))),
                            Poll::Ready(Ok(n)) => {
                                self.read += n;
                                self.read_until.get_or_insert(
                                    tokio::time::Instant::now() + Duration::from_secs(30),
                                );
                                if self.read == 4 && self.wanted == 4 {
                                    let size =
                                        usize::from(u16::from_be_bytes([self.rx[0], self.rx[1]]));
                                    if !(8..=65535).contains(&size) {
                                        return Poll::Ready(Err(io::Error::new(
                                            io::ErrorKind::InvalidData,
                                            "DNS helper incoming frame size",
                                        )));
                                    }
                                    self.wanted = size;
                                }
                                if self.read == self.wanted {
                                    let raw = crate::core::helper_packet(&self.rx[..self.read])
                                        .map_err(io::Error::other)?;
                                    let packet = gnunet_vpn::packet::Packet::parse(raw)
                                        .map_err(io::Error::other)?;
                                    packet.validate_checksums().map_err(io::Error::other)?;
                                    if packet.protocol() != gnunet_vpn::packet::UDP
                                        || packet.ports().map_err(io::Error::other)?.0 != 53
                                    {
                                        return Poll::Ready(Err(io::Error::new(
                                            io::ErrorKind::PermissionDenied,
                                            "DNS helper permits only original UDP53 replies",
                                        )));
                                    }
                                    let id = tun.queue(
                                        raw,
                                        tokio::time::Instant::now() + Duration::from_secs(30),
                                    )?;
                                    self.write = Some(id);
                                    self.rx[..self.read].fill(0);
                                    self.read = 0;
                                    self.wanted = 4;
                                    self.read_until = None;
                                }
                                Poll::Ready(Ok(true))
                            }
                        }
                    }
                }
                _ => {
                    if self.out.is_some() {
                        Poll::Pending
                    } else {
                        match tun.poll_read(cx) {
                            Poll::Pending => Poll::Pending,
                            Poll::Ready(ReadEvent::Packet(received)) => {
                                let raw = received.bytes();
                                let packet = match gnunet_vpn::packet::Packet::parse(raw) {
                                    Ok(p) => p,
                                    Err(_) => {
                                        self.report.discarded =
                                            self.report.discarded.saturating_add(1);
                                        return Poll::Ready(Ok(true));
                                    }
                                };
                                if packet.protocol() != gnunet_vpn::packet::UDP
                                    || packet.ports().map_err(io::Error::other)?.1 != 53
                                    || raw.len() + 8 > 65535
                                {
                                    self.report.discarded = self.report.discarded.saturating_add(1);
                                    return Poll::Ready(Ok(true));
                                }
                                let mut frame = Vec::new();
                                frame.try_reserve_exact(raw.len() + 8).map_err(|_| {
                                    io::Error::other("DNS helper output allocation")
                                })?;
                                frame.resize(raw.len() + 8, 0);
                                crate::core::encode_helper(raw, &mut frame)
                                    .map_err(io::Error::other)?;
                                self.out = Some(Output {
                                    frame: OwnedFrame::new(frame),
                                    offset: 0,
                                    until: tokio::time::Instant::now() + Duration::from_secs(30),
                                });
                                self.report.captured = self.report.captured.saturating_add(1);
                                Poll::Ready(Ok(true))
                            }
                            Poll::Ready(ReadEvent::Rejected(_)) => {
                                self.report.discarded = self.report.discarded.saturating_add(1);
                                Poll::Ready(Ok(true))
                            }
                            Poll::Ready(ReadEvent::Lost(loss)) => {
                                self.report.native_loss = Some(loss);
                                Poll::Ready(Err(io::Error::other(
                                    "DNS actual TUN read source lost",
                                )))
                            }
                            Poll::Ready(ReadEvent::Closed) => Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::NotConnected,
                                "DNS original TUN closed",
                            ))),
                            Poll::Ready(ReadEvent::WriteExpired(_)) => {
                                self.write = None;
                                Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::TimedOut,
                                    "DNS original TUN write expired",
                                )))
                            }
                            Poll::Ready(ReadEvent::WaitDeadline) => Poll::Pending,
                        }
                    }
                }
            };
            if progress.is_ready() {
                self.turn = (class + 1) % 4;
                return progress;
            }
        }
        let wake = self
            .read_until
            .into_iter()
            .chain(self.out.as_ref().map(|o| o.until))
            .min();
        if let Some(at) = wake {
            self.timer.as_mut().reset(at);
            if self.timer.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
        Poll::Pending
    }
    pub async fn run(mut self, tun: &mut AsyncTun) -> PumpReport {
        loop {
            match poll_fn(|cx| self.step(cx, tun)).await {
                Ok(true) => {}
                Ok(false) => break,
                Err(e) => {
                    self.report.first = Some(e);
                    break;
                }
            }
        }
        self.report.pending_prefix = self.out.as_ref().map(|o| (o.offset, o.frame.len()));
        self.report.input_prefix = (self.read != 0).then_some((self.read, self.wanted));
        if let Some(id) = self.write.take()
            && let Err(e) = tun.cancel(&id)
            && self.report.first.is_none()
        {
            self.report.first = Some(e);
        }
        self.report
    }
}
