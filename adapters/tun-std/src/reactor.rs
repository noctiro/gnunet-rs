//! One original immutable packet write and one bounded RX buffer; no hidden task.
use crate::{Epoch, Info, Mode, OwnedTun, PacketError, Version, decode, prefix, version};
use std::{
    future::{Future, poll_fn},
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::time::{Instant, Sleep};
mod registration;
pub use registration::Refusal as RegistrationFailure;
use registration::{Input, Registered};
/// Original write authority; another device or epoch cannot settle/cancel it.
#[derive(Clone, Debug)]
pub struct WriteId {
    pub(crate) epoch: Epoch,
    pub(crate) serial: u64,
    pub(crate) helper_prefix: usize,
}
impl PartialEq for WriteId {
    fn eq(&self, other: &Self) -> bool {
        self.epoch == other.epoch && self.serial == other.serial
    }
}
impl Eq for WriteId {}
impl WriteId {
    /// Actual original helper stdin bytes accepted before this token was
    /// returned in a loss. Zero is not an Unsent proof for other native kinds.
    #[must_use]
    pub const fn helper_accepted_prefix(&self) -> usize {
        self.helper_prefix
    }

    /// Actual original device lifetime.
    #[must_use]
    pub const fn epoch(&self) -> &Epoch {
        &self.epoch
    }
    /// Diagnostic-only sequence, incapable of recreating write authority.
    #[must_use]
    pub const fn diagnostic(&self) -> u64 {
        self.serial
    }
}
/// Original cause observed before the one native close attempt.
#[derive(Debug)]
pub enum LossCause {
    /// Original native read/write/registration error.
    Io(io::Error),
    /// Actual read EOF.
    Eof,
    /// A packet write transferred a positive short prefix; outcome unknown.
    ShortWrite {
        /// Actual native bytes, including any framing prefix.
        bytes: usize,
        /// Original complete native packet size.
        expected: usize,
    },
    /// Native write returned zero; no suffix is retried.
    WriteZero,
    /// Caller permanently closed this original descriptor.
    Closed,
    /// A bounded local allocation failed after input was consumed.
    Capacity,
    /// Windows: retire this session while retaining the original adapter for
    /// explicit recovery. No queued packet moves to the replacement epoch.
    #[cfg(windows)]
    SessionRestart,
    /// Windows: a complete native interface table no longer contains the
    /// original LUID. This is not a kernel-route cleanup receipt.
    #[cfg(windows)]
    InterfaceMissing,
}
/// Actual source retirement, including any original uncompleted write id.
#[derive(Debug)]
pub struct Loss {
    /// Retired original packet-source identity.
    pub epoch: Epoch,
    /// Original queued write, if any; ShortWrite means exposure unknown.
    pub pending: Option<WriteId>,
    /// Original source cause.
    pub cause: LossCause,
    /// Independent actual close failure; close is never retried.
    pub close_error: Option<io::Error>,
    /// Windows: the original ended session's adapter retained for explicit
    /// restart. Dropping this owner releases that adapter; explicit close and
    /// allocation-failure teardown do not produce a restart owner.
    #[cfg(windows)]
    pub recovery: Option<Box<crate::WintunRecovery>>,
}
impl Loss {
    /// Release the optional retained Windows adapter when the caller chooses
    /// shutdown rather than recovery. Original loss/close diagnostics remain;
    /// this grants no independent native interface-removal acknowledgement.
    pub fn release_wintun_recovery(&mut self) {
        #[cfg(windows)]
        if let Some(recovery) = self.recovery.take() {
            recovery.close();
        }
        #[cfg(not(windows))]
        let _unchanged = self;
    }
}
/// Unchanged actual packet and original source, normalized without extra protocol.
pub struct Received {
    pub(crate) epoch: Epoch,
    pub(crate) mode: Mode,
    pub(crate) version: Version,
    pub(crate) frame: Vec<u8>,
}
impl Received {
    /// Original verified source.
    #[must_use]
    pub const fn epoch(&self) -> &Epoch {
        &self.epoch
    }
    /// Structurally validated raw packet version; checksums remain unverified.
    #[must_use]
    pub const fn version(&self) -> Version {
        self.version
    }
    /// Complete raw IP bytes for VPN/EXIT core packet parsing.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.frame[self.mode.prefix_len()..]
    }
    /// Transfer the original native frame allocation without copying or stripping
    /// its prefix. Read `bytes`/`native_bytes` before transfer to retain the raw
    /// IP offset; the caller assumes buffer erasure and subsequent ownership.
    #[must_use]
    pub fn into_native_bytes(self) -> Vec<u8> {
        self.frame
    }
    /// Exact actual native frame, including its original framing prefix.
    #[must_use]
    pub fn native_bytes(&self) -> &[u8] {
        &self.frame
    }
}
/// Actual read observation. Expired writes remain local unsent outcomes.
pub enum ReadEvent {
    /// One actual complete normalized packet.
    Packet(Received),
    /// One consumed packet rejected by explicit framing policy.
    Rejected(PacketError),
    /// Original queued packet expired with no write exposure.
    WriteExpired(WriteId),
    /// Original packet-source retirement happened before this observation.
    Lost(Loss),
    /// This caller's finite wait ended; no source/packet success is inferred.
    WaitDeadline,
    /// Original source is already closed.
    Closed,
}
/// Why an immutable queued packet was never submitted to the kernel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Unsent {
    /// Explicit original cancellation before a write admitted bytes.
    Cancelled,
    /// Original finite queue deadline.
    Deadline,
}
/// Exact whole-packet write/local retirement, never downstream IP/peer receipt.
#[derive(Debug)]
pub enum WriteEvent {
    /// The original native boundary accepted one complete packet (a device
    /// write or Wintun send-ring submission), without network/delivery evidence.
    Written {
        /// Exact original packet.
        write: WriteId,
        /// Raw IP bytes, excluding native prefix.
        raw_bytes: usize,
    },
    /// Packet removed before any bytes were admitted.
    Unsent {
        /// Exact original packet.
        write: WriteId,
        /// Actual local retirement reason.
        reason: Unsent,
    },
    /// Original FD physically closed; never retry its partial suffix.
    Lost(Loss),
    /// No original packet is queued.
    Idle,
    /// Original source is already closed.
    Closed,
    /// This one caller wait ended, leaving the original packet retained.
    WaitDeadline,
}
struct Pending {
    id: WriteId,
    frame: Vec<u8>,
    raw: usize,
    until: Instant,
    alarm: Pin<Box<Sleep>>,
}
/// Caller-driven async registration over exactly one verified OwnedTun. Dropping
/// read/write futures preserves the source, complete RX framing and immutable TX.
pub struct AsyncTun {
    io: Option<Registered>,
    info: Info,
    epoch: Epoch,
    rx: Vec<u8>,
    maximum: usize,
    next: u64,
    pending: Option<Pending>,
}
impl AsyncTun {
    /// Register a verified descriptor on the caller's current Tokio reactor.
    /// Failure closes this consumed descriptor. No runtime/task is constructed.
    pub fn new(tun: OwnedTun) -> io::Result<Self> {
        Self::try_new(tun).map_err(|failure| {
            let (tun, error) = failure.into_parts();
            tun.setup_error(error)
        })
    }
    /// Register without consuming the original owner on refusal. This permits
    /// explicit recovery after allocation/reactor setup failure, without replay.
    /// The entered runtime must enable I/O and time; missing enabled drivers can
    /// panic in Tokio rather than returning a registration refusal.
    pub fn try_new(tun: OwnedTun) -> Result<Self, Box<RegistrationFailure>> {
        let maximum = tun.limits.packet_bytes;
        let info = tun.info.clone();
        let epoch = tun.epoch();
        let prepared = (|| {
            tokio::runtime::Handle::try_current().map_err(|e| io::Error::other(e.to_string()))?;
            let cap = maximum
                .checked_add(info.mode.prefix_len() + 1)
                .ok_or_else(|| io::Error::other("TUN read capacity overflow"))?;
            let mut rx = Vec::new();
            rx.try_reserve_exact(cap)
                .map_err(|_| io::Error::other("TUN read allocation"))?;
            rx.resize(cap, 0);
            Ok(rx)
        })();
        let rx = match prepared {
            Ok(rx) => rx,
            Err(cause) => return Err(Box::new(RegistrationFailure { tun, cause })),
        };
        let registered = match Registered::new(tun) {
            Ok(io) => io,
            Err(refusal) => {
                return Err(refusal);
            }
        };
        Ok(Self {
            io: Some(registered),
            info,
            epoch,
            rx,
            maximum,
            next: 0,
            pending: None,
        })
    }
    /// Exact original verified metadata.
    #[must_use]
    pub const fn info(&self) -> &Info {
        &self.info
    }
    /// Original physical device lifetime.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.epoch.clone()
    }
    /// Issue an explicit administrative effect without exposing mutable FD
    /// replacement through the reactor registration.
    pub fn plan(&mut self, action: crate::Action, until: Instant) -> io::Result<crate::Effect> {
        self.io
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "TUN closed"))?
            .get_mut()
            .plan(action, until)
    }
    /// Apply one actual native configuration action to this same source.
    pub fn apply(
        &mut self,
        effect: crate::Effect,
    ) -> Result<crate::NativeApplied, crate::ApplyFailure> {
        match self.io.as_mut() {
            Some(io) => io.get_mut().apply(effect),
            None => Err(crate::ApplyFailure {
                effect,
                error: io::Error::new(io::ErrorKind::NotConnected, "TUN closed"),
                attempted: false,
            }),
        }
    }
    /// Begin a real bounded route transaction while retaining the original
    /// TUN source identity. The returned owner must be polled/cancelled explicitly.
    pub fn route(
        &mut self,
        effect: crate::Effect,
    ) -> Result<crate::NativeRoute, crate::ApplyFailure> {
        match self.io.as_mut() {
            Some(io) => io.get_mut().route(effect),
            None => Err(crate::ApplyFailure {
                effect,
                error: io::Error::new(io::ErrorKind::NotConnected, "TUN closed"),
                attempted: false,
            }),
        }
    }
    /// Observe exact original IPv6 address readiness without configuring the OS.
    /// The watcher retains epoch identity, not the TUN descriptor.
    pub fn watch_ipv6(
        &self,
        address: std::net::Ipv6Addr,
        prefix: u8,
        until: Instant,
        options: crate::Ipv6WatchOptions,
    ) -> io::Result<crate::Ipv6Watch> {
        self.io
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "TUN closed"))?
            .get_ref()
            .watch_ipv6(address, prefix, until, options)
    }
    /// Read actual original interface administration state without mutation.
    pub fn snapshot(
        &self,
        until: Instant,
        options: crate::SnapshotOptions,
    ) -> Result<crate::NativeSnapshot, crate::AdminFailure> {
        self.io
            .as_ref()
            .ok_or(crate::AdminFailure::SourceRetired)?
            .get_ref()
            .snapshot(until, options)
    }
    /// Query one exact original interface route with a finite native deadline.
    /// The owned job retains identity, never the TUN descriptor or route ownership.
    pub fn query_route(
        &self,
        destination: std::net::IpAddr,
        prefix: u8,
        gateway: Option<std::net::IpAddr>,
        until: Instant,
    ) -> Result<crate::RouteQuery, crate::AdminFailure> {
        self.io
            .as_ref()
            .ok_or(crate::AdminFailure::SourceRetired)?
            .get_ref()
            .query_route(destination, prefix, gateway, until)
    }
    /// Reserve exactly one immutable complete packet and finite original deadline.
    /// A WouldBlock capacity rejection admits no new packet or native bytes.
    pub fn queue(&mut self, raw: &[u8], until: Instant) -> io::Result<WriteId> {
        if self.io.is_none() {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "TUN closed"));
        }
        if self.pending.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "original packet retained",
            ));
        }
        if Instant::now() >= until {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "packet queue deadline",
            ));
        }
        if raw.len() > self.maximum {
            return Err(PacketError::TooLarge.into());
        }
        let v = version(raw).map_err(io::Error::from)?;
        let size = raw.len() + self.info.mode.prefix_len();
        let mut frame = Vec::new();
        frame
            .try_reserve_exact(size)
            .map_err(|_| io::Error::other("TUN packet allocation"))?;
        let p = prefix(self.info.mode, v);
        frame.extend_from_slice(&p[..self.info.mode.prefix_len()]);
        frame.extend_from_slice(raw);
        let next = self
            .next
            .checked_add(1)
            .ok_or_else(|| io::Error::other("TUN write identity exhausted"))?;
        let id = WriteId {
            epoch: self.epoch.clone(),
            serial: next,
            helper_prefix: 0,
        };
        self.pending = Some(Pending {
            id: id.clone(),
            frame,
            raw: raw.len(),
            until,
            alarm: Box::pin(tokio::time::sleep_until(until)),
        });
        self.next = next;
        Ok(id)
    }
    /// Cancel only a still-retained original packet. Every retained write has
    /// admitted zero bytes: positive short writes retire the FD synchronously.
    pub fn cancel(&mut self, id: &WriteId) -> io::Result<WriteEvent> {
        if self.pending.as_ref().is_none_or(|p| &p.id != id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "stale original packet",
            ));
        }
        let p = self
            .pending
            .take()
            .ok_or_else(|| io::Error::other("missing original packet"))?;
        if let Some(io) = &mut self.io {
            io.reset_write_wait();
        }
        Ok(WriteEvent::Unsent {
            write: p.id,
            reason: if Instant::now() >= p.until {
                Unsent::Deadline
            } else {
                Unsent::Cancelled
            },
        })
    }
    fn expired(&mut self, cx: &mut Context<'_>) -> Option<WriteId> {
        if self
            .pending
            .as_mut()
            .is_some_and(|p| Instant::now() >= p.until || p.alarm.as_mut().poll(cx).is_ready())
        {
            if let Some(io) = &mut self.io {
                io.reset_write_wait();
            }
            self.pending.take().map(|p| p.id)
        } else {
            None
        }
    }
    fn retire(&mut self, cause: LossCause) -> Loss {
        // Retirement is visible before unregistering callbacks or invoking
        // provider cleanup, including reentrant wake code on that path.
        self.epoch.0.alive.set(false);
        let pending = self.pending.take().map(|p| p.id);
        self.rx.fill(0);
        #[cfg(unix)]
        let close_error = self.io.take().and_then(|io| io.into_inner().close().err());
        #[cfg(windows)]
        let (close_error, recovery) = match self.io.take() {
            Some(io) if !matches!(cause, LossCause::Closed | LossCause::Capacity) => {
                (None, Some(Box::new(io.into_inner().retain_wintun())))
            }
            Some(io) => (io.into_inner().close().err(), None),
            None => (None, None),
        };
        Loss {
            epoch: self.epoch.clone(),
            pending,
            cause,
            close_error,
            #[cfg(windows)]
            recovery,
        }
    }
    /// Attempt native close before retiring the queued packet/epoch; close errno
    /// remains explicit and is never retried against a potentially reused FD.
    pub fn close(&mut self) -> Loss {
        self.retire(LossCause::Closed)
    }
    /// End the original Windows session, returning its adapter in Loss::recovery.
    /// The old epoch, queued write and read registration retire before restart.
    #[cfg(windows)]
    pub fn retire_wintun_session(&mut self) -> Loss {
        self.retire(LossCause::SessionRestart)
    }
    /// Retire a physically missing original Windows interface while retaining
    /// its adapter for explicit recovery. A present or reused LUID is not loss
    /// proof; native query failures stay errors. This performs no route cleanup.
    ///
    /// # Errors
    /// Preserves native complete-table, capacity and compartment errors.
    #[cfg(windows)]
    pub fn retire_missing_wintun(&mut self) -> io::Result<Option<Loss>> {
        let Some(io) = self.io.as_ref() else {
            return Ok(None);
        };
        let presence = io
            .get_ref()
            .session()
            .adapter()
            .port()
            .identity()
            .presence(gnunet_native::interfaces::RetirementLimits::default())?;
        match presence {
            gnunet_native::interfaces::InterfacePresence::Missing => {
                Ok(Some(self.retire(LossCause::InterfaceMissing)))
            }
            gnunet_native::interfaces::InterfacePresence::Present => Ok(None),
            gnunet_native::interfaces::InterfacePresence::Reused => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "original Wintun LUID was reused",
            )),
        }
    }
    /// Defer persistent interface destruction during a surrounding destructor.
    /// Packet FD close still runs. A later close reports the deferred cleanup
    /// as DeviceCleanupError with its original explicit recovery capability;
    /// it cannot become evidence of successful interface removal.
    #[cfg(unix)]
    pub fn defer_interface_cleanup(&mut self) {
        if let Some(io) = self.io.as_mut() {
            io.get_mut().defer_interface_cleanup();
        }
    }
    /// Perform at most one actual native read per poll. Oversized/truncated IP,
    /// nonzero PI flags and native family mismatches are explicit consumed rejects.
    pub fn poll_read(&mut self, cx: &mut Context<'_>) -> Poll<ReadEvent> {
        if let Some(id) = self.expired(cx) {
            return Poll::Ready(ReadEvent::WriteExpired(id));
        }
        let Some(io) = &mut self.io else {
            return Poll::Ready(ReadEvent::Closed);
        };
        let result = io.read(cx, &mut self.rx);
        let result = match result {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(value) => value,
        };
        let n = match result {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Err(e) => return Poll::Ready(ReadEvent::Lost(self.retire(LossCause::Io(e)))),
            Ok(Input::Data(0)) => return Poll::Ready(ReadEvent::Lost(self.retire(LossCause::Eof))),
            Ok(Input::Data(n)) => n,
            #[cfg(windows)]
            Ok(Input::Oversize) => return Poll::Ready(ReadEvent::Rejected(PacketError::TooLarge)),
        };
        if n > self.maximum + self.info.mode.prefix_len() {
            return Poll::Ready(ReadEvent::Rejected(PacketError::TooLarge));
        }
        let (v, _) = match decode(self.info.mode, &self.rx[..n]) {
            Ok(value) => value,
            Err(error) => return Poll::Ready(ReadEvent::Rejected(error)),
        };
        let mut frame = Vec::new();
        if frame.try_reserve_exact(n).is_err() {
            return Poll::Ready(ReadEvent::Lost(self.retire(LossCause::Capacity)));
        }
        frame.extend_from_slice(&self.rx[..n]);
        Poll::Ready(ReadEvent::Packet(Received {
            epoch: self.epoch.clone(),
            mode: self.info.mode,
            version: v,
            frame,
        }))
    }
    /// Perform at most one original whole-packet write per poll. Never splice or
    /// resume a positive short packet suffix on any device/source.
    pub fn poll_write(&mut self, cx: &mut Context<'_>) -> Poll<WriteEvent> {
        if let Some(write) = self.expired(cx) {
            return Poll::Ready(WriteEvent::Unsent {
                write,
                reason: Unsent::Deadline,
            });
        }
        let Some(io) = &mut self.io else {
            return Poll::Ready(WriteEvent::Closed);
        };
        let Some(p) = &self.pending else {
            return Poll::Ready(WriteEvent::Idle);
        };
        let expected = p.frame.len();
        let result = io.write(cx, &p.frame);
        let result = match result {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(value) => value,
        };
        match result {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(WriteEvent::Lost(self.retire(LossCause::Io(e)))),
            Ok(0) => Poll::Ready(WriteEvent::Lost(self.retire(LossCause::WriteZero))),
            Ok(n) if n != expected => Poll::Ready(WriteEvent::Lost(
                self.retire(LossCause::ShortWrite { bytes: n, expected }),
            )),
            Ok(_) => match self.pending.take() {
                Some(p) => Poll::Ready(WriteEvent::Written {
                    write: p.id,
                    raw_bytes: p.raw,
                }),
                None => Poll::Ready(WriteEvent::Closed),
            },
        }
    }
    /// Wait for one bounded original read observation. Cancellation preserves
    /// all owner state; the supplied absolute deadline is never restarted.
    pub async fn read(&mut self, until: Instant) -> ReadEvent {
        let mut alarm = Box::pin(tokio::time::sleep_until(until));
        poll_fn(|cx| {
            if alarm.as_mut().poll(cx).is_ready() {
                return Poll::Ready(ReadEvent::WaitDeadline);
            }
            self.poll_read(cx)
        })
        .await
    }
    /// Wait for original packet settlement within this one observation deadline.
    /// WaitDeadline leaves the original immutable packet and queue deadline intact.
    pub async fn write(&mut self, until: Instant) -> WriteEvent {
        let mut alarm = Box::pin(tokio::time::sleep_until(until));
        poll_fn(|cx| {
            if alarm.as_mut().poll(cx).is_ready() {
                return Poll::Ready(WriteEvent::WaitDeadline);
            }
            self.poll_write(cx)
        })
        .await
    }
}
impl From<PacketError> for io::Error {
    fn from(value: PacketError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, value)
    }
}
