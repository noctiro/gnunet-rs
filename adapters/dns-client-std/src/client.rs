use crate::{EndpointSource, Error, ipc};
use gnunet_client_host::channel::{Channel, ConnectionStep};
use gnunet_service_runtime::{
    clock::RuntimeClock,
    framing::{Accounting, Budget, Class, Limits as FrameLimits, OwnedFrame, ReadStep},
};
use gnunet_types::Error as Fault;
use std::{
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
/// Caller-owned identity domain. No socket, task or global counter is created.
#[derive(Default)]
pub struct Instance {
    next: AtomicU64,
}
impl Instance {
    /// Empty original domain.
    pub const fn new() -> Self {
        Self {
            next: AtomicU64::new(0),
        }
    }
}
/// One actual attached physical MQ, never a logical reconnect intent.
#[derive(Clone, Copy)]
pub struct Epoch<'a> {
    owner: &'a Instance,
    allocation: u64,
    serial: u64,
}
impl PartialEq for Epoch<'_> {
    fn eq(&self, o: &Self) -> bool {
        std::ptr::eq(self.owner, o.owner)
            && self.allocation == o.allocation
            && self.serial == o.serial
    }
}
impl Eq for Epoch<'_> {}
impl std::fmt::Debug for Epoch<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Epoch")
            .field(&self.allocation)
            .field(&self.serial)
            .finish()
    }
}
/// Original callback capability; raw service IDs cannot reconstruct it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Request<'a> {
    epoch: Epoch<'a>,
    serial: u64,
}
impl<'a> Request<'a> {
    /// Original physical source.
    pub const fn epoch(self) -> Epoch<'a> {
        self.epoch
    }
}
/// Explicit finite resource and lifetime limits.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Live original callbacks, including replied frames not fully written.
    pub requests: usize,
    /// Maximum complete IPC frame, at most65535.
    pub frame_bytes: usize,
    /// Aggregate retained outbound source frames.
    pub source_bytes: usize,
    /// Syscall byte slice.
    pub io_slice_bytes: usize,
    /// Canonical original callback deadline and independent native lifetime.
    pub request_timeout: Duration,
    /// Finite INIT/partial-input local bound.
    pub input_timeout: Duration,
    /// Bounded drain after a callback is dropped at its logical deadline.
    pub drain_grace: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            requests: 256,
            frame_bytes: 65535,
            source_bytes: 1024 * 1024,
            io_slice_bytes: 65535,
            request_timeout: Duration::from_secs(60),
            input_timeout: Duration::from_secs(10),
            drain_grace: Duration::from_secs(2),
        }
    }
}
struct Row<'a> {
    token: Request<'a>,
    id: [u8; 8],
    until: u64,
    hard: Instant,
    drain: Option<Instant>,
    reply: Option<OwnedFrame>,
    queued: bool,
    sent: usize,
    total: usize,
}
#[derive(Clone, Copy)]
struct Tag<'a> {
    epoch: Epoch<'a>,
    request: Option<Request<'a>>,
}
/// Owned original intercepted request. Dropping it does not forward or answer.
pub struct Notification<'a> {
    request: Request<'a>,
    id: [u8; 8],
    frame: OwnedFrame,
    until: u64,
    hard: Instant,
}
impl<'a> Notification<'a> {
    /// Original callback capability.
    pub const fn request(&self) -> Request<'a> {
        self.request
    }
    /// Original opaque eight-byte service identifier.
    pub const fn id(&self) -> [u8; 8] {
        self.id
    }
    /// Borrow exact DNS payload without another allocation.
    pub fn dns(&self) -> &[u8] {
        &self.frame.bytes()[16..]
    }
    /// Original logical deadline, never recomputed on retry.
    pub const fn expires(&self) -> u64 {
        self.until
    }
    /// Original independent native deadline.
    pub const fn hard(&self) -> Instant {
        self.hard
    }
}
/// Actual original-source termination. No variant invents a remote response.
#[derive(Debug)]
pub enum Cause {
    /// Explicit close.
    Closed,
    /// Explicit caller cancellation retires this physical source.
    Cancelled,
    /// Native EOF.
    Eof,
    /// Original native error.
    Io(io::Error),
    /// Malformed message.
    Protocol(Fault),
    /// Canonical clock failure.
    Clock(Fault),
    /// Original native hard/partial-frame/INIT bound elapsed.
    Deadline,
}
/// Actual IO or callback progress; Written is a local byte fact only.
pub enum Progress<'a> {
    /// Physical attachment only, before INIT whole-write.
    Connected(Epoch<'a>),
    /// INIT has actually fully written; there is no ACK.
    InitWritten(Epoch<'a>),
    /// Actual original callback.
    Request(Notification<'a>),
    /// Original reply actually fully written.
    Written(Request<'a>),
    /// This exact callback expired and its original Drop reply was actually admitted locally.
    Dropping(Request<'a>),
    /// Actual positive transfer.
    Activity {
        /// Source.
        epoch: Epoch<'a>,
        /// Actual input bytes.
        read: usize,
        /// Actual output bytes.
        written: usize,
    },
    /// Physical source ended; every token from epoch is retired.
    Lost {
        /// Original source.
        epoch: Option<Epoch<'a>>,
        /// Independent original cause.
        cause: Cause,
        /// Retired original callbacks.
        requests: usize,
    },
    /// Real connect failure; a finite source retry is selected.
    Retry {
        /// Actual native failure.
        error: io::Error,
        /// Source-selected backoff.
        delay: Duration,
    },
    /// Source configuration/Resolver refused.
    Unavailable(Error),
    /// Caller observation wait elapsed.
    Wait,
    /// Permanently closed.
    Closed,
}
/// One bounded native stream with explicit callback ownership and no worker.
pub struct Client<'a> {
    owner: &'a Instance,
    allocation: u64,
    next: u64,
    channel: Channel<Tag<'a>>,
    clock: Arc<dyn RuntimeClock>,
    flags: u32,
    limits: Limits,
    rows: Vec<Row<'a>>,
    epoch: Option<Epoch<'a>>,
    init: bool,
    init_hard: Option<Instant>,
    input_hard: Option<Instant>,
    alarm: Option<Pin<Box<Sleep>>>,
    bytes: usize,
    closed: bool,
    read_first: bool,
    needs_reconnect: bool,
    // A synchronous reply refusal still owes its actual physical retirement.
    pending_loss: Option<Progress<'a>>,
}
fn micros(d: Duration) -> Result<u64, Fault> {
    let n = u64::try_from(d.as_micros()).map_err(|_| Fault::Overflow)?;
    if n == 0 {
        return Err(Fault::InvalidInput);
    }
    Ok(n)
}
impl<'a> Client<'a> {
    /// Reserve finite metadata and shared clock subscription; no native IO.
    pub fn new(
        owner: &'a Instance,
        source: EndpointSource,
        flags: u32,
        limits: Limits,
    ) -> Result<Self, Error> {
        if flags == 0
            || flags & !15 != 0
            || limits.requests == 0
            || limits.requests > 65536
            || !(16..=65535).contains(&limits.frame_bytes)
            || limits.source_bytes < 16
            || limits.io_slice_bytes == 0
        {
            return Err(Fault::InvalidInput.into());
        }
        for d in [
            limits.request_timeout,
            limits.input_timeout,
            limits.drain_grace,
        ] {
            micros(d)?;
            Instant::now().checked_add(d).ok_or(Fault::Overflow)?;
        }
        let allocation = owner
            .next
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| Fault::Overflow)?
            .checked_add(1)
            .ok_or(Fault::Overflow)?;
        let clock = source.clock();
        let channel = Channel::new(
            source,
            FrameLimits {
                frame_bytes: limits.frame_bytes,
                ordinary: Budget {
                    frames: 1,
                    bytes: limits.frame_bytes,
                },
                reserved: Budget::default(),
                accounting: Accounting::Retained,
                io_slice_bytes: limits.io_slice_bytes,
            },
        )?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(limits.requests)
            .map_err(|_| Fault::Capacity)?;
        Ok(Self {
            owner,
            allocation,
            next: 0,
            channel,
            clock,
            flags,
            limits,
            rows,
            epoch: None,
            init: false,
            init_hard: None,
            input_hard: None,
            alarm: None,
            bytes: 0,
            closed: false,
            read_first: false,
            needs_reconnect: false,
            pending_loss: None,
        })
    }
    /// Exact canonical clock shared with the endpoint source.
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    /// Currently attached original source.
    pub const fn epoch(&self) -> Option<Epoch<'a>> {
        self.epoch
    }
    fn serial(&mut self) -> Result<u64, Fault> {
        self.next = self.next.checked_add(1).ok_or(Fault::Overflow)?;
        Ok(self.next)
    }
    fn index(&self, token: Request<'a>) -> Result<usize, Fault> {
        if self.epoch != Some(token.epoch) {
            return Err(Fault::Stale);
        }
        self.rows
            .iter()
            .position(|r| r.token == token)
            .ok_or(Fault::Stale)
    }
    fn lost(&mut self, cause: Cause) -> Progress<'a> {
        self.channel.detach();
        self.needs_reconnect = true;
        let epoch = self.epoch.take();
        let requests = self.rows.len();
        self.rows.clear();
        self.bytes = 0;
        self.init = false;
        self.init_hard = None;
        self.input_hard = None;
        self.alarm = None;
        Progress::Lost {
            epoch,
            cause,
            requests,
        }
    }
    /// Physically detach this exact MQ before invalidating all original callback
    /// tokens. Preserve the real independent reason; a later explicit reconnect
    /// starts a fresh epoch and never replays any old opaque ID or reply bytes.
    pub fn retire(&mut self, cause: Cause) -> Progress<'a> {
        let current = self.lost(cause);
        // Physical IO is detached above even when an earlier synchronous
        // failure already owns the real epoch, callback count and cause.
        self.pending_loss.take().unwrap_or(current)
    }
    /// Cancel physically retires this MQ and all original callbacks; there is no
    /// invented wire cancellation. A new epoch requires explicit reconnect.
    pub fn cancel(&mut self) -> Progress<'a> {
        self.closed = true;
        let p = self.retire(Cause::Cancelled);
        self.channel.close();
        p
    }
    /// Permanently close native IO and retire every original callback.
    pub fn close(&mut self) -> Progress<'a> {
        self.closed = true;
        let p = self.retire(Cause::Closed);
        self.channel.close();
        p
    }
    /// Start explicit fresh connection selection after a loss. No old callback,
    /// answer or opaque ID can move into the future physical source.
    pub fn reconnect(&mut self) -> Result<(), Error> {
        if self.closed {
            return Err(Fault::Closed.into());
        }
        if self.epoch.is_some() {
            return Err(Fault::Conflict.into());
        }
        self.channel.schedule_retry()?;
        self.needs_reconnect = false;
        Ok(())
    }
    fn now(&self) -> Result<u64, Fault> {
        Ok(self.clock.sample()?.now.as_micros())
    }
    fn set_reply(&mut self, i: usize, decision: ipc::Decision<'_>) -> Result<(), Error> {
        if self.rows[i].reply.is_some() || self.rows[i].queued {
            return Err(Fault::Replay.into());
        }
        if matches!(decision, ipc::Decision::Answer(_))
            && self.flags & (ipc::PRE_RESOLUTION | ipc::POST_RESOLUTION) == 0
        {
            return Err(Fault::PermissionDenied.into());
        }
        let req = ipc::Request::Reply {
            id: self.rows[i].id,
            decision,
        };
        let n = req.encoded_len()?;
        if n > self.limits.frame_bytes
            || self
                .bytes
                .checked_add(n)
                .is_none_or(|v| v > self.limits.source_bytes)
        {
            return Err(Fault::Capacity.into());
        }
        let mut v = Vec::new();
        v.try_reserve_exact(n).map_err(|_| Fault::Capacity)?;
        v.resize(n, 0);
        req.encode(&mut v)?;
        self.rows[i].reply = Some(OwnedFrame::new(v));
        self.rows[i].total = n;
        self.bytes += n;
        Ok(())
    }
    /// Resolve only this original callback. Canonical/native expiry is checked
    /// before admission; response queueing or whole-write asserts no IP delivery.
    pub fn reply(&mut self, token: Request<'a>, decision: ipc::Decision<'_>) -> Result<(), Error> {
        let i = self.index(token)?;
        let now = match self.now() {
            Ok(n) => n,
            Err(e) => {
                self.pending_loss = Some(self.lost(Cause::Clock(e)));
                return Err(e.into());
            }
        };
        if now >= self.rows[i].until || Instant::now() >= self.rows[i].hard {
            return Err(Fault::Deadline.into());
        }
        self.set_reply(i, decision)
    }
    fn native_due(&self) -> Option<Instant> {
        self.rows
            .iter()
            .map(|r| r.drain.unwrap_or(r.hard))
            .chain(self.init_hard)
            .chain(self.input_hard)
            .min()
    }
    fn poll_alarm(&mut self, cx: &mut Context<'_>) -> bool {
        let Some(at) = self.native_due() else {
            self.alarm = None;
            return false;
        };
        if Instant::now() >= at {
            return true;
        }
        let alarm = self
            .alarm
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(at)));
        alarm.as_mut().reset(at);
        alarm.as_mut().poll(cx).is_ready()
    }
    /// Check and arm original native deadlines without sampling the canonical
    /// clock or performing socket IO. Higher-level owners call this before
    /// their own clock wait so INIT and partial-input bounds remain effective.
    /// A returned loss has already physically detached the original MQ.
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<Progress<'a>> {
        if let Some(loss) = self.pending_loss.take() {
            return Some(loss);
        }
        if !self.closed && self.poll_alarm(cx) {
            Some(self.lost(Cause::Deadline))
        } else {
            None
        }
    }
    fn expire(&mut self, now: u64) -> Result<Option<Request<'a>>, Error> {
        for i in 0..self.rows.len() {
            if self.rows[i].until <= now && self.rows[i].drain.is_none() {
                if self.rows[i].queued {
                    let token = self.rows[i].token;
                    let removed = self
                        .channel
                        .framing_mut()
                        .ok_or(Fault::NotReady)?
                        .remove_unwritten(|tag, _| tag.request == Some(token), |_, _| {});
                    if removed == 0 {
                        return Err(Fault::Deadline.into());
                    }
                    self.rows[i].queued = false;
                }
                if self.rows[i].total != 0 {
                    self.bytes = self
                        .bytes
                        .checked_sub(self.rows[i].total)
                        .ok_or(Fault::Conflict)?;
                }
                self.rows[i].reply = None;
                self.rows[i].total = 0;
                self.rows[i].sent = 0;
                self.set_reply(i, ipc::Decision::Drop)?;
                self.rows[i].drain = Some(
                    Instant::now()
                        .checked_add(self.limits.drain_grace)
                        .ok_or(Fault::Overflow)?
                        .min(self.rows[i].hard),
                );
                return Ok(Some(self.rows[i].token));
            }
        }
        Ok(None)
    }
    fn prepare(&mut self) -> Result<(), Error> {
        let epoch = self.epoch.ok_or(Fault::NotReady)?;
        let framed = self.channel.framing_mut().ok_or(Fault::NotReady)?;
        if framed.queued_frames() != 0 {
            return Ok(());
        }
        if !self.init {
            let mut v = Vec::new();
            v.try_reserve_exact(8).map_err(|_| Fault::Capacity)?;
            v.resize(8, 0);
            ipc::Request::Init { flags: self.flags }.encode(&mut v)?;
            framed
                .enqueue_owned(
                    OwnedFrame::new(v),
                    Tag {
                        epoch,
                        request: None,
                    },
                    Class::Ordinary,
                )
                .map_err(|e| e.reason)?;
            self.init = true;
            return Ok(());
        }
        if self.init_hard.is_some() {
            return Ok(());
        }
        if let Some(r) = self
            .rows
            .iter_mut()
            .find(|r| r.reply.is_some() && !r.queued)
        {
            let bytes = r.reply.take().ok_or(Fault::Conflict)?;
            if let Err(e) = framed.enqueue_owned(
                bytes,
                Tag {
                    epoch,
                    request: Some(r.token),
                },
                Class::Ordinary,
            ) {
                r.reply = Some(e.value.0);
                return Err(e.reason.into());
            }
            r.queued = true;
        }
        Ok(())
    }
    fn write(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress<'a>, Error>> {
        let epoch = self.epoch.ok_or(Fault::NotReady)?;
        let p = match self
            .channel
            .framing_mut()
            .ok_or(Fault::NotReady)?
            .poll_write(cx)
        {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Ok(self.lost(Cause::Io(e)))),
            Poll::Ready(Ok(p)) => p,
        };
        if p.origin.epoch != epoch {
            return Poll::Ready(Err(Fault::Stale.into()));
        }
        if let Some(token) = p.origin.request {
            let i = self.index(token)?;
            self.rows[i].sent = self.rows[i]
                .sent
                .checked_add(p.bytes)
                .ok_or(Fault::Overflow)?;
            if p.complete {
                let r = self.rows.remove(i);
                if r.sent != r.total {
                    return Poll::Ready(Err(Fault::Conflict.into()));
                }
                self.bytes = self.bytes.checked_sub(r.total).ok_or(Fault::Conflict)?;
                return Poll::Ready(Ok(Progress::Written(token)));
            }
        } else if p.complete {
            self.init_hard = None;
            return Poll::Ready(Ok(Progress::InitWritten(epoch)));
        }
        self.read_first = true;
        Poll::Ready(Ok(Progress::Activity {
            epoch,
            read: 0,
            written: p.bytes,
        }))
    }
    fn dispatch(&mut self) -> Result<Progress<'a>, Error> {
        let epoch = self.epoch.ok_or(Fault::NotReady)?;
        if self.init_hard.is_some() {
            return Err(Fault::Malformed.into());
        }
        let input = self
            .channel
            .framing()
            .and_then(|f| f.frame())
            .ok_or(Fault::NotReady)?;
        let decoded = ipc::Response::decode(input)?;
        let id = decoded.id;
        if self.rows.iter().any(|r| r.id == id) {
            return Err(Fault::Replay.into());
        }
        if self.rows.len() >= self.limits.requests {
            return Err(Fault::Capacity.into());
        }
        let frame = OwnedFrame::copy_from(input)?;
        let now = self.now()?;
        let until = now
            .checked_add(micros(self.limits.request_timeout)?)
            .filter(|n| *n != u64::MAX)
            .ok_or(Fault::Overflow)?;
        let hard = Instant::now()
            .checked_add(self.limits.request_timeout)
            .ok_or(Fault::Overflow)?;
        let token = Request {
            epoch,
            serial: self.serial()?,
        };
        self.rows.push(Row {
            token,
            id,
            until,
            hard,
            drain: None,
            reply: None,
            queued: false,
            sent: 0,
            total: 0,
        });
        self.channel
            .framing_mut()
            .ok_or(Fault::NotReady)?
            .release_frame();
        self.input_hard = None;
        Ok(Progress::Request(Notification {
            request: token,
            id,
            frame,
            until,
            hard,
        }))
    }
    fn read(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress<'a>, Error>> {
        let epoch = self.epoch.ok_or(Fault::NotReady)?;
        let p = match self
            .channel
            .framing_mut()
            .ok_or(Fault::NotReady)?
            .poll_read(cx)
        {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Ok(self.lost(Cause::Io(e)))),
            Poll::Ready(Ok(p)) => p,
        };
        match p {
            ReadStep::Eof => Poll::Ready(Ok(self.lost(Cause::Eof))),
            ReadStep::Progress { bytes, complete } => {
                if self.input_hard.is_none() {
                    self.input_hard = Some(
                        Instant::now()
                            .checked_add(self.limits.input_timeout)
                            .ok_or(Fault::Overflow)?,
                    )
                }
                if complete {
                    return Poll::Ready(match self.dispatch() {
                        Ok(p) => Ok(p),
                        Err(e) => {
                            let cause = match e {
                                Error::Protocol(f) => Cause::Protocol(f),
                                other => Cause::Io(io::Error::other(other)),
                            };
                            Ok(self.lost(cause))
                        }
                    });
                }
                self.read_first = false;
                Poll::Ready(Ok(Progress::Activity {
                    epoch,
                    read: bytes,
                    written: 0,
                }))
            }
        }
    }
    /// Poll one original event. Independent native bounds and their alarm are
    /// checked before waiting for a stable canonical clock, including clock races.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<Instant>,
    ) -> Poll<Result<Progress<'a>, Error>> {
        if let Some(loss) = self.poll_native_guard(cx) {
            return Poll::Ready(Ok(loss));
        }
        if self.closed {
            return Poll::Ready(Ok(Progress::Closed));
        }
        if wait.is_some_and(|at| Instant::now() >= at) {
            return Poll::Ready(Ok(Progress::Wait));
        }
        match self.channel.poll_clock(cx) {
            Poll::Pending => {
                return self
                    .channel
                    .poll_wait(cx, wait)
                    .map(|r| r.map(|()| Progress::Wait));
            }
            Poll::Ready(Err(e)) => {
                let p = self.lost(Cause::Io(io::Error::other(e)));
                return Poll::Ready(Ok(p));
            }
            Poll::Ready(Ok(())) => {}
        }
        let now = match self.now() {
            Ok(n) => n,
            Err(e) => return Poll::Ready(Ok(self.lost(Cause::Clock(e)))),
        };
        match self.expire(now) {
            Err(e) => return Poll::Ready(Ok(self.lost(Cause::Io(io::Error::other(e))))),
            Ok(Some(token)) => return Poll::Ready(Ok(Progress::Dropping(token))),
            Ok(None) => {}
        }
        if self.poll_alarm(cx) {
            return Poll::Ready(Ok(self.lost(Cause::Deadline)));
        }
        if self.epoch.is_none() && self.needs_reconnect {
            return self
                .channel
                .poll_wait(cx, wait)
                .map(|r| r.map(|()| Progress::Wait));
        }
        if self.epoch.is_none() {
            match self.channel.poll_connect(cx) {
                Poll::Pending => {
                    return self
                        .channel
                        .poll_wait(cx, wait)
                        .map(|r| r.map(|()| Progress::Wait));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(ConnectionStep::Attached)) => {
                    let epoch = Epoch {
                        owner: self.owner,
                        allocation: self.allocation,
                        serial: self.serial()?,
                    };
                    self.epoch = Some(epoch);
                    self.init_hard = Some(
                        Instant::now()
                            .checked_add(self.limits.input_timeout)
                            .ok_or(Fault::Overflow)?,
                    );
                    return Poll::Ready(Ok(Progress::Connected(epoch)));
                }
                Poll::Ready(Ok(ConnectionStep::Retry { error, retry_after })) => {
                    return Poll::Ready(Ok(Progress::Retry {
                        error,
                        delay: retry_after,
                    }));
                }
                Poll::Ready(Ok(ConnectionStep::Unavailable(e))) => {
                    return Poll::Ready(Ok(Progress::Unavailable(e)));
                }
            }
        }
        self.prepare()?;
        let first = if self.read_first {
            self.read(cx)
        } else {
            self.write(cx)
        };
        if first.is_ready() {
            return first;
        }
        let second = if self.read_first {
            self.write(cx)
        } else {
            self.read(cx)
        };
        if second.is_ready() {
            return second;
        }
        self.channel
            .poll_wait(cx, wait)
            .map(|r| r.map(|()| Progress::Wait))
    }
    /// Canceling this wait preserves actual native cursors and original callbacks.
    pub async fn drive(&mut self, wait: Option<Instant>) -> Result<Progress<'a>, Error> {
        poll_fn(|cx| self.poll(cx, wait)).await
    }
}
