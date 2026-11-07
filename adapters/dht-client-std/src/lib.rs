//! Caller-driven official DHT client on original native MQs.
//!
//! The pure DHT client owns logical requests, bounded sources and original output
//! capabilities. This adapter owns shared CLIENT attempts, canonical clock ports
//! and retained Framed cursors. It starts no DHT service or Resolver task.
#![forbid(unsafe_code)]
/// Original native/configuration/protocol error.
pub use gnunet_client_host::ConnectError as Error;
/// Explicit CLIENT/clock/Resolver source; no Resolver is created here.
pub use gnunet_client_host::EndpointSource;
/// Explicit live CLIENT configuration; replacement does not start or reconnect IO.
pub use gnunet_client_host::LiveConfiguration;
/// Caller-owned clock, timer and lookup ports; no Resolver broker is imported.
pub use gnunet_client_host::resolution;
use gnunet_client_host::{
    ConnectionAttempt, Endpoint,
    resolution::{PortError, ResolutionTimer},
};
use gnunet_dht_client::Client as Core;
pub use gnunet_dht_client::{
    Action, Attempt, AttemptId, Cancel, Completion, Epoch, Event, Get, GetId, HelloId, Ignored,
    Instance, Monitor, MonitorId, MonitorKind, OperationId, Outcome, Received, Snapshot, ipc,
};
/// Canonical process clock traits.
pub use gnunet_service_runtime::clock;
use gnunet_service_runtime::{
    clock::{ClockSubscription, RuntimeClock},
    framing::{Accounting, Budget, Class, Framed, Limits as FrameLimits, OwnedFrame, ReadStep},
};
use gnunet_types::Error as ProtocolError;
use gnunet_wire::official::AbsoluteTime;
use std::{
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
mod physical;
use physical::{ConnectionStep, Physical};
/// Explicit independent protocol/source and native wire budgets.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Bounded logical requests, original attempts and source allocations.
    pub protocol: gnunet_dht_client::Limits,
    /// Retained original physical output frames/bytes.
    pub output: Budget,
    /// Maximum actual bytes in one native read/write; nonzero.
    pub io_slice_bytes: usize,
    /// HELLO parser resource limits; addresses are not authenticated in029.
    pub hello: gnunet_hello::Limits,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            protocol: gnunet_dht_client::Limits::default(),
            output: Budget {
                frames: 64,
                bytes: 1024 * 1024,
            },
            io_slice_bytes: 65535,
            hello: gnunet_hello::Limits {
                maximum_input_bytes: 65535,
                maximum_address_bytes: 8192,
                maximum_addresses: 128,
            },
        }
    }
}
impl Limits {
    fn validate(self) -> Result<(), ProtocolError> {
        if self.output.frames == 0
            || self.output.bytes < self.protocol.frame_bytes
            || self.io_slice_bytes == 0
        {
            return Err(ProtocolError::Capacity);
        }
        Ok(())
    }
    fn framing(self) -> FrameLimits {
        FrameLimits {
            frame_bytes: self.protocol.frame_bytes,
            ordinary: self.output,
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: self.io_slice_bytes,
        }
    }
}
/// Actual cause for retirement of the original physical stream.
#[derive(Debug)]
pub enum LossCause {
    /// Actual clean EOF between complete frames.
    Eof,
    /// Actual IO failure or truncated-frame EOF.
    Io(io::Error),
    /// Actual invalid service message.
    Protocol(ProtocolError),
    /// A preflighted output could not be retained.
    Resource(ProtocolError),
    /// Explicit physical reconnect request.
    Requested,
    /// Permanent caller close.
    Closed,
}
/// One bounded observation; local writing never asserts service/network success.
pub enum Progress<'a> {
    /// Original physical connection attached. No node identity is inferred.
    Connected(Epoch<'a>),
    /// Actual complete input with original logical recipients.
    Inbound(Received<'a>),
    /// Actual full local control/subscription write; no service acknowledgement.
    Written {
        /// Original stream.
        epoch: Epoch<'a>,
        /// Original action.
        action: Action<'a>,
    },
    /// Original one-shot terminal notice, exactly once.
    Completed(Completion<'a>),
    /// Original stream retired before logical restoration can begin.
    Lost {
        /// Original stream.
        epoch: Epoch<'a>,
        /// Actual original cause.
        cause: LossCause,
        /// Retained bounded logical state after retirement.
        retained: Snapshot,
    },
    /// Retained complete input could not be copied; no logical state was applied.
    Capacity(Epoch<'a>),
    /// Failed original native connect with retained source scheduling.
    ConnectRetry {
        /// Actual cause.
        error: io::Error,
        /// Original next delay.
        retry_after: Duration,
    },
    /// Current CLIENT endpoint could not be selected.
    Unavailable(Error),
    /// Actual positive native byte transfer.
    Activity {
        /// Original stream.
        epoch: Epoch<'a>,
        /// Actual received bytes.
        read_bytes: usize,
        /// Actual written bytes.
        written_bytes: usize,
    },
    /// Only the caller's wait ended; no operation was canceled.
    WaitDeadline,
    /// Permanently closed, after original terminal notices were taken.
    Closed,
}
/// Movable caller-driven native DHT owner. Instances outlive all logical tokens.
pub struct Client<'a> {
    physical: Physical<'a>,
    core: Core<'a>,
    hello_scratch: Vec<u8>,
    read_first: bool,
    closed: bool,
}
impl<'a> Client<'a> {
    /// Reserve bounded protocol metadata, HELLO scratch and one canonical-clock
    /// subscription without starting native IO.
    pub fn new(
        instance: &'a mut Instance,
        source: EndpointSource,
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        let core = Core::new(instance, limits.protocol)?;
        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(limits.hello.maximum_address_bytes)
            .map_err(|_| ProtocolError::Capacity)?;
        scratch.resize(limits.hello.maximum_address_bytes, 0);
        let physical = Physical::new(source, limits)?;
        Ok(Self {
            physical,
            core,
            hello_scratch: scratch,
            read_first: false,
            closed: false,
        })
    }
    /// Admit an original logical GET, including while a socket is unavailable.
    pub fn get(&mut self, get: Get<'_>) -> Result<GetId<'a>, Error> {
        Ok(self.core.get(get)?)
    }
    /// Atomically add explicit original known-result filters.
    pub fn known(&mut self, get: GetId<'a>, hashes: &[[u8; 64]]) -> Result<(), Error> {
        Ok(self.core.known(get, hashes)?)
    }
    /// Suppress original GET callbacks and drain its original STOP FIFO if issued.
    pub fn stop(&mut self, get: GetId<'a>) -> Result<Cancel, Error> {
        Ok(self.core.stop(get)?)
    }
    /// Admit one original PUT; no service ACK exists and loss never replays it.
    pub fn put(&mut self, put: ipc::Put<'_>) -> Result<OperationId<'a>, Error> {
        Ok(self.core.put(put)?)
    }
    /// Cancel only this original one-shot. Issued bytes keep their immutable FIFO.
    pub fn cancel(&mut self, operation: OperationId<'a>) -> Result<Cancel, Error> {
        Ok(self.core.cancel(operation)?)
    }
    /// Add a monitor restored as fresh attempts after physical MQ replacement.
    pub fn monitor(&mut self, monitor: Monitor) -> Result<MonitorId<'a>, Error> {
        Ok(self.core.monitor(monitor)?)
    }
    /// Remove only this original logical monitor.
    pub fn stop_monitor(&mut self, monitor: MonitorId<'a>) -> Result<Cancel, Error> {
        Ok(self.core.stop_monitor(monitor)?)
    }
    /// Request an unverified public HELLO observation.
    pub fn hello(&mut self) -> Result<HelloId<'a>, Error> {
        Ok(self.core.hello()?)
    }
    /// Suppress only this original logical HELLO callback.
    pub fn cancel_hello(&mut self, hello: HelloId<'a>) -> Result<Cancel, Error> {
        Ok(self.core.cancel_hello(hello)?)
    }
    /// Validate metadata signature/expiry at explicit UTC and offer the original
    /// URL. Coverage remains MetadataOnly; completion is only local writing.
    pub fn offer_hello(
        &mut self,
        url: &[u8],
        now: AbsoluteTime,
    ) -> Result<(OperationId<'a>, gnunet_hello::SignatureCoverage), Error> {
        Ok(self.core.offer_hello(
            url,
            &mut self.hello_scratch,
            self.physical.limits.hello,
            now,
        )?)
    }
    /// Diagnostic current usage; no handles can be reconstructed from counts.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        self.core.snapshot()
    }
    /// Current original physical stream; connection establishes no node identity.
    #[must_use]
    pub fn epoch(&self) -> Option<Epoch<'a>> {
        self.core.epoch()
    }
    /// Original opaque correlation data, without capability reconstruction.
    pub fn request_id(&self, get: GetId<'a>) -> Result<ipc::RequestId, Error> {
        Ok(self.core.request_id(get)?)
    }
    fn retire(&mut self, cause: LossCause) -> Result<Progress<'a>, Error> {
        let epoch = self.core.epoch().ok_or(ProtocolError::NotReady)?;
        self.physical.stop();
        self.core.lost(epoch)?;
        self.physical.schedule();
        Ok(Progress::Lost {
            epoch,
            cause,
            retained: self.core.snapshot(),
        })
    }
    /// Take one actual retained one-shot terminal notice without sampling a
    /// clock or issuing IO. This is also available after permanent physical close.
    pub fn take_completion(&mut self) -> Option<Completion<'a>> {
        self.core.completion()
    }
    /// Explicitly retire the old stream, retaining only safe logical intent.
    pub fn reconnect(&mut self) -> Result<Progress<'a>, Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        self.retire(LossCause::Requested)
    }
    /// Physically retire this original MQ or pending native connection attempt
    /// without sampling a clock or starting replacement IO. Every original
    /// one-shot is lost rather than replayed; retained terminal notices remain
    /// available through `take_completion`. No epoch returns None, which does
    /// not imply that no native connection attempt was present. Later callers
    /// may drive the same client again for independent logical work.
    pub fn retire_io(&mut self) -> Result<Option<Progress<'a>>, Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        let epoch = self.core.epoch();
        self.physical.stop();
        if let Some(epoch) = epoch {
            self.core.lost(epoch)?;
            self.physical.schedule();
            Ok(Some(Progress::Lost {
                epoch,
                cause: LossCause::Requested,
                retained: self.core.snapshot(),
            }))
        } else {
            self.physical.schedule();
            Ok(None)
        }
    }
    /// Permanently retire original IO. Drain `drive` for outstanding one-shot
    /// notices before Closed when their terminal outcomes are needed.
    pub fn close(&mut self) -> Option<Progress<'a>> {
        if self.closed {
            return None;
        }
        let epoch = self.core.epoch();
        self.physical.stop();
        self.core.close();
        self.physical.subscription = None;
        self.closed = true;
        epoch.map(|epoch| Progress::Lost {
            epoch,
            cause: LossCause::Closed,
            retained: self.core.snapshot(),
        })
    }
    /// Explicit recovery of an original refused clock/timer/Resolver port. Closed
    /// clients cannot allocate another listener or revive a native connection.
    pub fn recover_ports(&mut self) -> Result<(), Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        self.physical.recover_ports()
    }
    fn dispatch(&mut self, epoch: Epoch<'a>) -> Result<Progress<'a>, Error> {
        let input = self
            .physical
            .framed
            .as_ref()
            .ok_or(ProtocolError::NotReady)?
            .frame()
            .ok_or(ProtocolError::NotReady)?;
        let received = match self.core.receive(epoch, input) {
            Ok(event) => event,
            Err(ProtocolError::Capacity) => return Ok(Progress::Capacity(epoch)),
            Err(error) => return self.retire(LossCause::Protocol(error)),
        };
        if !self
            .physical
            .framed
            .as_mut()
            .ok_or(ProtocolError::NotReady)?
            .release_frame()
        {
            return Err(ProtocolError::Stale.into());
        }
        Ok(Progress::Inbound(received))
    }
    fn prepare(&mut self) -> Result<Option<Progress<'a>>, Error> {
        let Some(n) = self.core.next_size() else {
            return Ok(None);
        };
        let framed = self
            .physical
            .framed
            .as_mut()
            .ok_or(ProtocolError::NotReady)?;
        if !framed.capacity(n, Class::Ordinary) {
            return Ok(None);
        }
        framed.reserve(n, Class::Ordinary)?;
        let output = self.core.outbound()?.ok_or(ProtocolError::Stale)?;
        let (attempt, bytes) = output.into_parts();
        if let Err(rejected) =
            framed.enqueue_owned(OwnedFrame::new(bytes), attempt, Class::Ordinary)
        {
            return self.retire(LossCause::Resource(rejected.reason)).map(Some);
        }
        Ok(None)
    }
    fn write(
        &mut self,
        cx: &mut Context<'_>,
        epoch: Epoch<'a>,
    ) -> Poll<Result<Progress<'a>, Error>> {
        match self
            .physical
            .framed
            .as_mut()
            .ok_or(ProtocolError::NotReady)?
            .poll_write(cx)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(self.retire(LossCause::Io(error))),
            Poll::Ready(Ok(progress)) => {
                self.read_first = true;
                if progress.complete {
                    let action = self.core.written(progress.origin)?;
                    if let Some(completion) = self.core.completion() {
                        Poll::Ready(Ok(Progress::Completed(completion)))
                    } else {
                        Poll::Ready(Ok(Progress::Written { epoch, action }))
                    }
                } else {
                    Poll::Ready(Ok(Progress::Activity {
                        epoch,
                        read_bytes: 0,
                        written_bytes: progress.bytes,
                    }))
                }
            }
        }
    }
    fn read(
        &mut self,
        cx: &mut Context<'_>,
        epoch: Epoch<'a>,
    ) -> Poll<Result<Progress<'a>, Error>> {
        match self
            .physical
            .framed
            .as_mut()
            .ok_or(ProtocolError::NotReady)?
            .poll_read(cx)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(self.retire(LossCause::Io(error))),
            Poll::Ready(Ok(ReadStep::Eof)) => Poll::Ready(self.retire(LossCause::Eof)),
            Poll::Ready(Ok(ReadStep::Progress { bytes, complete })) => {
                self.read_first = false;
                if complete {
                    Poll::Ready(self.dispatch(epoch))
                } else {
                    Poll::Ready(Ok(Progress::Activity {
                        epoch,
                        read_bytes: bytes,
                        written_bytes: 0,
                    }))
                }
            }
        }
    }
    /// Poll the original owner, optionally withholding input delivery. When
    /// `receive` is false, complete retained input is not dispatched and no
    /// further read is issued. Original clock/connect/output/STOP cursors and
    /// the supplied native observation deadline still progress. The caller
    /// wakes and polls again when its input capacity becomes available.
    pub fn poll_with_input(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Option<Instant>,
        receive: bool,
    ) -> Poll<Result<Progress<'a>, Error>> {
        if let Some(completion) = self.core.completion() {
            return Poll::Ready(Ok(Progress::Completed(completion)));
        }
        if self.closed {
            return Poll::Ready(Ok(Progress::Closed));
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        match self.physical.clock(cx) {
            // The caller's fixed native observation target remains live even
            // while the canonical clock is waiting for a consistent revision.
            Poll::Pending => {
                return self
                    .physical
                    .poll_wait(cx, deadline)
                    .map(|result| result.map(|()| Progress::WaitDeadline));
            }
            Poll::Ready(result) => result?,
        }
        // Canonical clock work is charged to this same observation budget.
        // Expiry is not GET completion or permission to renew its owner's hard.
        if deadline.is_some_and(|target| Instant::now() >= target) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        if self.physical.framed.is_none() {
            match self.physical.poll_connect(cx) {
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(ConnectionStep::Retry(error, retry_after))) => {
                    return Poll::Ready(Ok(Progress::ConnectRetry { error, retry_after }));
                }
                Poll::Ready(Ok(ConnectionStep::Unavailable(error))) => {
                    return Poll::Ready(Ok(Progress::Unavailable(error)));
                }
                Poll::Ready(Ok(ConnectionStep::Attached)) => {
                    let epoch = match self.core.connect() {
                        Ok(epoch) => epoch,
                        Err(error) => {
                            self.physical.stop();
                            return Poll::Ready(Err(error.into()));
                        }
                    };
                    return Poll::Ready(Ok(Progress::Connected(epoch)));
                }
                Poll::Pending => {
                    return self
                        .physical
                        .poll_wait(cx, deadline)
                        .map_ok(|()| Progress::WaitDeadline);
                }
            }
        }
        let epoch = self.core.epoch().ok_or(ProtocolError::NotReady)?;
        if receive
            && self
                .physical
                .framed
                .as_ref()
                .is_some_and(|f| f.frame().is_some())
        {
            return Poll::Ready(self.dispatch(epoch));
        }
        if let Some(retired) = self.prepare()? {
            return Poll::Ready(Ok(retired));
        }
        if self.read_first {
            if receive && let Poll::Ready(event) = self.read(cx, epoch) {
                return Poll::Ready(event);
            }
            if let Poll::Ready(event) = self.write(cx, epoch) {
                return Poll::Ready(event);
            }
        } else {
            if let Poll::Ready(event) = self.write(cx, epoch) {
                return Poll::Ready(event);
            }
            if receive && let Poll::Ready(event) = self.read(cx, epoch) {
                return Poll::Ready(event);
            }
        }
        self.physical
            .poll_wait(cx, deadline)
            .map_ok(|()| Progress::WaitDeadline)
    }
    /// Wait for one bounded action. Dropping this future preserves the original
    /// native attempt, timers, partial RX/TX, logical intent and source buffers.
    pub async fn drive(&mut self, deadline: Option<Instant>) -> Result<Progress<'a>, Error> {
        poll_fn(|cx| self.poll_with_input(cx, deadline, true)).await
    }
}
impl Drop for Client<'_> {
    fn drop(&mut self) {
        self.physical.stop();
        self.core.close();
        self.physical.subscription = None;
    }
}
