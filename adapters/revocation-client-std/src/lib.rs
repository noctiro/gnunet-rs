//! One actual QUERY or REVOKE per original MQ. No wire RID/CANCEL/ACK extension,
//! hidden task, Resolver, proof validation, replay or generic success1 exists.
#![forbid(unsafe_code)]
use gnunet_client_host::channel::{Channel, ConnectionStep};
pub use gnunet_client_host::{ConnectError as Error, EndpointSource};
pub use gnunet_gnsrecord::ZoneKey;
pub use gnunet_revocation::{Certificate, Proof, ipc};
/// Explicit caller clock ports; constructing them grants no MQ readiness.
pub use gnunet_service_runtime::clock;
use gnunet_service_runtime::{
    clock::{Deadline, RuntimeClock},
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
/// Stable caller-owned domain for bounded independent requests.
#[derive(Debug, Default)]
pub struct Instance {
    next: AtomicU64,
}
impl Instance {
    /// Fresh domain, without a socket/task/entropy source.
    pub const fn new() -> Self {
        Self {
            next: AtomicU64::new(0),
        }
    }
}
macro_rules! token {
    ($name:ident,$doc:literal) => {
        #[doc=$doc]
        #[derive(Clone, Copy, Debug)]
        pub struct $name<'id> {
            owner: &'id Instance,
            serial: u64,
        }
        impl PartialEq for $name<'_> {
            fn eq(&self, other: &Self) -> bool {
                core::ptr::eq(self.owner, other.owner) && self.serial == other.serial
            }
        }
        impl Eq for $name<'_> {}
        impl $name<'_> {
            /// Diagnostic only; this number cannot reconstruct authority.
            pub const fn diagnostic(self) -> u64 {
                self.serial
            }
        }
    };
}
token!(
    Job,
    "One original revocation IPC request, never a wire RID."
);
token!(Epoch, "One actually attached original revocation MQ.");
#[derive(Clone, Copy)]
struct Origin<'id> {
    job: Job<'id>,
    epoch: Epoch<'id>,
}
/// Original absolute logical send and result deadline. Phases never renew them.
#[derive(Clone, Copy, Debug)]
pub struct Deadlines {
    /// Original whole-send bound.
    pub send_until: u64,
    /// Original complete reply bound.
    pub until: u64,
}
/// Bounded one-request physical storage and syscall quanta.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum frame, at least380, at most65535.
    pub frame_bytes: usize,
    /// Nonzero native syscall slice.
    pub io_slice_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            frame_bytes: ipc::REVOKE_BYTES,
            io_slice_bytes: ipc::REVOKE_BYTES,
        }
    }
}
impl Limits {
    fn framing(self) -> FrameLimits {
        FrameLimits {
            frame_bytes: self.frame_bytes,
            ordinary: Budget {
                frames: 1,
                bytes: self.frame_bytes,
            },
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: self.io_slice_bytes,
        }
    }
}
/// Local physical byte state; none is service acceptance or proof validity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Submission {
    /// No byte exposed.
    Unsent,
    /// A positive original prefix; outcome is unknown without a reply.
    Partial {
        /// Actual byte count.
        bytes: usize,
        /// Original complete length.
        total: usize,
    },
    /// Whole original frame locally written; outcome still unknown.
    Written {
        /// Original complete length.
        bytes: usize,
    },
}
/// Original terminal cause, preserved independently from the physical drop.
#[derive(Debug)]
pub enum Cause {
    /// Explicit cancellation.
    Cancelled,
    /// Explicit close.
    Closed,
    /// Original send bound elapsed.
    SendDeadline,
    /// Original reply bound elapsed.
    Deadline,
    /// Actual EOF.
    Eof,
    /// Actual I/O error.
    Io(io::Error),
    /// Actual protocol fault.
    Protocol(Fault),
    /// Exact clock fault.
    Clock(Fault),
    /// Exact CLIENT/Resolver/clock port failure.
    Ports(Error),
}
/// Actual original physical retirement; underlying Drop exposes no close errno.
#[derive(Debug)]
pub struct End<'id> {
    /// Original request.
    pub job: Job<'id>,
    /// Actual attached source if any.
    pub epoch: Option<Epoch<'id>>,
    /// Original byte exposure; exposed REVOKE loss is Unknown.
    pub submission: Submission,
    /// Actual original cause.
    pub cause: Cause,
}
/// One real original service reply, after closing its exact dedicated MQ.
#[derive(Debug)]
pub struct Reply<'id> {
    /// Original request.
    pub job: Job<'id>,
    /// Actual responding physical source.
    pub epoch: Epoch<'id>,
    /// Raw operation-specific status, never normalized.
    pub response: ipc::Response,
}
/// Caller-driven observations. Submitted is local I/O, never a response.
pub enum Progress<'id> {
    /// Actual original native attachment.
    Connected(Epoch<'id>),
    /// Actual immutable FIFO admission.
    Queued(Job<'id>, Epoch<'id>),
    /// Actual complete local writing.
    Submitted(Job<'id>, Epoch<'id>),
    /// Actual source read/write bytes.
    Activity(usize, usize),
    /// Actual original service response.
    Reply(Reply<'id>),
    /// Physically closed original source.
    Ended(End<'id>),
    /// Actual preattachment connection failure and original retry.
    Retry(io::Error, Duration),
    /// Actual source/config refusal, still before exposure.
    Unavailable(Error),
    /// Caller observation budget only.
    WaitDeadline,
    /// Terminal observation already delivered.
    Closed,
}
/// One original physical request owner. Cancellation is actual MQ close, matching
/// the C public API. There is no suffix transferred to any replacement source.
pub struct Client<'id> {
    channel: Channel<Origin<'id>>,
    clock: Arc<dyn RuntimeClock>,
    job: Job<'id>,
    epoch: Option<Epoch<'id>>,
    source: Option<OwnedFrame>,
    deadlines: Deadlines,
    hard: Instant,
    send_hard: Instant,
    native: Pin<Box<Sleep>>,
    alarm: Option<Pin<Box<Deadline>>>,
    alarm_at: Option<u64>,
    revoke: bool,
    total: usize,
    sent: usize,
    written: bool,
    closed: bool,
}
impl<'id> Client<'id> {
    /// Prepare one real public-key query, without connecting or validating crypto.
    pub fn query(
        instance: &'id Instance,
        source: EndpointSource,
        key: ZoneKey,
        deadlines: Deadlines,
        limits: Limits,
    ) -> Result<Self, Error> {
        Self::new(
            instance,
            source,
            ipc::Request::Query(key),
            deadlines,
            limits,
        )
    }
    /// Prepare one actual REVOKE. Structural parse is not signature/PoW checking.
    pub fn revoke(
        instance: &'id Instance,
        source: EndpointSource,
        proof: Proof<'_>,
        deadlines: Deadlines,
        limits: Limits,
    ) -> Result<Self, Error> {
        Self::new(
            instance,
            source,
            ipc::Request::Revoke(proof),
            deadlines,
            limits,
        )
    }
    fn new(
        instance: &'id Instance,
        source: EndpointSource,
        request: ipc::Request<'_>,
        deadlines: Deadlines,
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.framing().validate()?;
        if limits.frame_bytes < ipc::REVOKE_BYTES {
            return Err(Fault::Capacity.into());
        }
        let source = source.snapshot()?;
        let clock = source.clock();
        let now = clock.sample()?.now.as_micros();
        if deadlines.send_until <= now
            || deadlines.send_until > deadlines.until
            || deadlines.until == u64::MAX
        {
            return Err(Fault::Deadline.into());
        }
        let hard = Instant::now()
            .checked_add(Duration::from_micros(deadlines.until - now))
            .ok_or(Fault::Overflow)?;
        let send_hard = Instant::now()
            .checked_add(Duration::from_micros(deadlines.send_until - now))
            .ok_or(Fault::Overflow)?
            .min(hard);
        let serial = instance
            .next
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| Fault::Overflow)?
            .checked_add(1)
            .ok_or(Fault::Overflow)?;
        let total = request.encoded_len();
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(total)
            .map_err(|_| Fault::Capacity)?;
        bytes.resize(total, 0);
        request.encode(&mut bytes)?;
        let channel = Channel::new(source, limits.framing())?;
        Ok(Self {
            channel,
            clock,
            job: Job {
                owner: instance,
                serial,
            },
            epoch: None,
            source: Some(OwnedFrame::new(bytes)),
            deadlines,
            hard,
            send_hard,
            native: Box::pin(tokio::time::sleep_until(send_hard)),
            alarm: None,
            alarm_at: None,
            revoke: matches!(request, ipc::Request::Revoke(_)),
            total,
            sent: 0,
            written: false,
            closed: false,
        })
    }
    /// Original typed operation, never serialized.
    pub const fn job(&self) -> Job<'id> {
        self.job
    }
    /// Original attached physical epoch, which remains historical after retirement.
    pub const fn epoch(&self) -> Option<Epoch<'id>> {
        self.epoch
    }
    /// Whether the original source was physically stopped, independent of reply.
    pub const fn closed(&self) -> bool {
        self.closed
    }
    /// Same original source clock. No waiter is created by this accessor.
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    /// Current actual physical exposure; even whole REVOKE writing is Unknown.
    pub fn submission(&self) -> Submission {
        if self.written {
            Submission::Written { bytes: self.total }
        } else if self.sent != 0 {
            Submission::Partial {
                bytes: self.sent,
                total: self.total,
            }
        } else {
            Submission::Unsent
        }
    }
    fn end(&mut self, cause: Cause) -> End<'id> {
        self.channel.close();
        self.closed = true;
        self.source = None;
        self.alarm = None;
        self.alarm_at = None;
        End {
            job: self.job,
            epoch: self.epoch,
            submission: self.submission(),
            cause,
        }
    }
    /// Physically close the exact original MQ before returning local retirement.
    /// No clock sample or wire CANCEL is required, including after partial writes.
    pub fn cancel(&mut self) -> Option<End<'id>> {
        if self.closed {
            None
        } else {
            Some(self.end(Cause::Cancelled))
        }
    }
    /// Physical original close, independent of every clock/Resolver failure.
    pub fn close(&mut self) -> Option<End<'id>> {
        if self.closed {
            None
        } else {
            Some(self.end(Cause::Closed))
        }
    }
    fn expire_native(&mut self, cx: &mut Context<'_>) -> Option<Progress<'id>> {
        let at = if self.written {
            self.hard
        } else {
            self.send_hard.min(self.hard)
        };
        self.native.as_mut().reset(at);
        if Instant::now() >= at || self.native.as_mut().poll(cx).is_ready() {
            Some(Progress::Ended(self.end(if self.written {
                Cause::Deadline
            } else {
                Cause::SendDeadline
            })))
        } else {
            None
        }
    }
    fn poll_inner(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<Instant>,
    ) -> Poll<Result<Progress<'id>, Error>> {
        if self.closed {
            return Poll::Ready(Ok(Progress::Closed));
        }
        if let Some(end) = self.expire_native(cx) {
            return Poll::Ready(Ok(end));
        }
        match self.channel.poll_clock(cx) {
            Poll::Pending => {
                return self
                    .channel
                    .poll_wait(cx, wait)
                    .map_ok(|()| Progress::WaitDeadline);
            }
            Poll::Ready(Err(e)) => {
                return Poll::Ready(Ok(Progress::Ended(self.end(Cause::Ports(e)))));
            }
            Poll::Ready(Ok(())) => {}
        }
        let now = match self.clock.sample() {
            Ok(s) => s.now.as_micros(),
            Err(e) => return Poll::Ready(Ok(Progress::Ended(self.end(Cause::Clock(e))))),
        };
        if now >= self.deadlines.until || !self.written && now >= self.deadlines.send_until {
            return Poll::Ready(Ok(Progress::Ended(self.end(if self.written {
                Cause::Deadline
            } else {
                Cause::SendDeadline
            }))));
        }
        let target = if self.written {
            self.deadlines.until
        } else {
            self.deadlines.send_until
        };
        if self.alarm_at != Some(target) {
            self.alarm = Some(Box::pin(Deadline::at(
                self.clock.clone(),
                gnunet_types::AbsoluteTime::from_micros(target),
            )?));
            self.alarm_at = Some(target)
        }
        if let Some(alarm) = &mut self.alarm {
            match alarm.as_mut().poll(cx) {
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Ok(Progress::Ended(self.end(Cause::Clock(e)))));
                }
                Poll::Ready(Ok(())) => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Pending => {}
            }
        }
        if wait.is_some_and(|at| Instant::now() >= at) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        if self.channel.framing().is_none() {
            return match self.channel.poll_connect(cx) {
                Poll::Pending => self
                    .channel
                    .poll_wait(cx, wait)
                    .map_ok(|()| Progress::WaitDeadline),
                Poll::Ready(Err(e)) => Poll::Ready(Ok(Progress::Ended(self.end(Cause::Ports(e))))),
                Poll::Ready(Ok(ConnectionStep::Attached)) => {
                    let epoch = Epoch {
                        owner: self.job.owner,
                        serial: self.job.serial,
                    };
                    self.epoch = Some(epoch);
                    Poll::Ready(Ok(Progress::Connected(epoch)))
                }
                Poll::Ready(Ok(ConnectionStep::Retry { error, retry_after })) => {
                    Poll::Ready(Ok(Progress::Retry(error, retry_after)))
                }
                Poll::Ready(Ok(ConnectionStep::Unavailable(e))) => {
                    Poll::Ready(Ok(Progress::Unavailable(e)))
                }
            };
        }
        let epoch = self.epoch.ok_or(Fault::Stale)?;
        if let Some(source) = self.source.take() {
            let frame = self.channel.framing_mut().ok_or(Fault::Stale)?;
            if let Err(refused) = frame.enqueue_owned(
                source,
                Origin {
                    job: self.job,
                    epoch,
                },
                Class::Ordinary,
            ) {
                self.source = Some(refused.value.0);
                return Poll::Ready(Err(refused.reason.into()));
            }
            return Poll::Ready(Ok(Progress::Queued(self.job, epoch)));
        }
        if !self.written {
            match self
                .channel
                .framing_mut()
                .ok_or(Fault::Stale)?
                .poll_write(cx)
            {
                Poll::Ready(Ok(w)) => {
                    if w.origin.job != self.job || w.origin.epoch != epoch {
                        return Poll::Ready(Err(Fault::Stale.into()));
                    }
                    self.sent = self.sent.checked_add(w.bytes).ok_or(Fault::Overflow)?;
                    if self.sent > self.total {
                        return Poll::Ready(Err(Fault::Stale.into()));
                    }
                    if w.complete {
                        if self.sent != self.total {
                            return Poll::Ready(Err(Fault::Stale.into()));
                        }
                        self.written = true;
                        return Poll::Ready(Ok(Progress::Submitted(self.job, epoch)));
                    }
                    return Poll::Ready(Ok(Progress::Activity(0, w.bytes)));
                }
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Ok(Progress::Ended(self.end(Cause::Io(e)))));
                }
                Poll::Pending => {}
            }
        }
        if self.channel.framing().and_then(|f| f.frame()).is_none() {
            match self
                .channel
                .framing_mut()
                .ok_or(Fault::Stale)?
                .poll_read(cx)
            {
                Poll::Ready(Ok(ReadStep::Eof)) => {
                    return Poll::Ready(Ok(Progress::Ended(self.end(Cause::Eof))));
                }
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Ok(Progress::Ended(self.end(Cause::Io(e)))));
                }
                Poll::Ready(Ok(ReadStep::Progress {
                    bytes,
                    complete: false,
                })) => return Poll::Ready(Ok(Progress::Activity(bytes, 0))),
                Poll::Ready(Ok(ReadStep::Progress { complete: true, .. })) => {}
                Poll::Pending => {
                    return self
                        .channel
                        .poll_wait(cx, wait)
                        .map_ok(|()| Progress::WaitDeadline);
                }
            }
        }
        if !self.written {
            return Poll::Ready(Err(Fault::Malformed.into()));
        }
        let response = ipc::Response::decode(
            self.channel
                .framing()
                .and_then(|f| f.frame())
                .ok_or(Fault::Stale)?,
        )?;
        if !matches!(
            (self.revoke, response),
            (true, ipc::Response::Revoke(_)) | (false, ipc::Response::Query(_))
        ) {
            return Poll::Ready(Err(Fault::Malformed.into()));
        }
        self.channel.close();
        self.closed = true;
        self.alarm = None;
        self.source = None;
        Poll::Ready(Ok(Progress::Reply(Reply {
            job: self.job,
            epoch,
            response,
        })))
    }
    /// Poll original cursors. Every error physically stops the original owner;
    /// cancellation of a waiting future retains cursors until explicit close/drop.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<Instant>,
    ) -> Poll<Result<Progress<'id>, Error>> {
        let result = self.poll_inner(cx, wait);
        if matches!(result, Poll::Ready(Err(_))) {
            self.channel.close();
            self.closed = true;
            self.source = None;
            self.alarm = None;
        }
        result
    }
    /// Wait for an actual step, preserving the owner if this future is canceled.
    pub async fn drive(&mut self, wait: Option<Instant>) -> Result<Progress<'id>, Error> {
        poll_fn(|cx| self.poll(cx, wait)).await
    }
}
impl Drop for Client<'_> {
    fn drop(&mut self) {
        self.channel.close();
        self.source = None;
        self.alarm = None;
    }
}
