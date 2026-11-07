//! Native official PILS client on one original MQ and canonical process clock.
//!
//! All protocol/key decisions belong to gnunet-pils. This driver owns retained
//! CLIENT attempts, common secure Framed I/O and explicit bounded scheduling.
//! Cancellation of a drive future never cancels an operation or drops cursors.
//! A native Tokio runtime is required only while polling, not constructing.
/// Preserve actual configuration, protocol and native I/O causes.
pub use gnunet_client_host::ConnectError as Error;
/// Actual public CLIENT/Resolver/clock source. No hidden resolver is created.
pub use gnunet_client_host::EndpointSource;
use gnunet_client_host::{
    ConnectGuard, ConnectionAttempt, Endpoint,
    resolution::{PortError, ResolutionTimer},
};
use gnunet_pils::{
    ActiveIdentity, HelloLimits, MasterKey, Profile,
    client::{
        Epoch, HeapClient as Core, Identity, Inbound, Instance, KeyTarget, LocalKeyStatus,
        LossReport, OperationId, Outbound, TransmitId, Written,
    },
};
/// Canonical clock and subscription types for caller-defined process ports.
pub use gnunet_service_runtime::clock;
use gnunet_service_runtime::{
    clock::{ClockSample, ClockSubscription, RuntimeClock},
    framing::{
        Accounting, Budget, Class, Framed, Limits as FrameLimits, OwnedFrame, ReadStep,
        WriteProgress,
    },
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

/// Explicit native capacities. Pending metadata slots are bounded additionally
/// by Client's O parameter; request/announcement payloads allocate actual lengths.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum pending logical operations, from1 through O.
    pub pending_operations: usize,
    /// Maximum complete official frame, from176 through65535.
    pub frame_bytes: usize,
    /// Maximum bytes per native read/write, nonzero; partial cursors are retained.
    pub io_slice_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            pending_operations: 32,
            frame_bytes: 65535,
            io_slice_bytes: 65535,
        }
    }
}
/// Why an established original MQ was retired. Port refusals are not IO loss.
#[derive(Debug)]
pub enum LossCause {
    /// Clean physical EOF between complete frames.
    Eof,
    /// Actual native error, including truncated-frame EOF.
    Io(io::Error),
    /// A known PILS frame/announcement failed validation.
    Protocol(ProtocolError),
    /// Bounded setup or received-frame storage resources were refused.
    Resource(ProtocolError),
    /// Native output setup/admission failed; original MQ is explicitly retired.
    Setup(Error),
    /// Caller explicitly retired the original MQ to reconnect.
    Requested,
}
/// One owned event. Secret completions have no Debug/Clone and erase on drop.
#[expect(
    clippy::large_enum_variant,
    reason = "Bounded owned secrets and loss reports return without a fallible allocation after response consumption or physical retirement"
)]
#[must_use = "original progress may own operation results or loss reports"]
pub enum Progress<'a, const O: usize = 32> {
    /// Physical stream attached to this original logical MQ; identity is not ready yet.
    Connected(Epoch<'a>),
    /// Actual public identity or original owned crypto result.
    Inbound(Inbound<'a>),
    /// Full original local write; FEED remains local submission, not application.
    Written(Written<'a>),
    /// Original MQ retired before its retry time is sampled/registered.
    Lost {
        /// Original epoch.
        epoch: Epoch<'a>,
        /// Actual cause.
        cause: LossCause,
        /// Unacknowledged pending feeds and retained crypto count.
        report: LossReport<'a, O>,
    },
    /// Initial CLIENT socket attempt failed. Same MQ/operation IDs are retained.
    ConnectRetry {
        /// Same logical MQ.
        epoch: Epoch<'a>,
        /// Original next CLIENT delay.
        retry_after: Duration,
        /// Actual failed native attempt.
        error: io::Error,
    },
    /// CLIENT could not create an MQ from current service configuration.
    Unavailable(Error),
    /// One actual positive I/O step; no callback, credit or delivery is inferred.
    Activity {
        /// Actual native received bytes.
        read_bytes: usize,
        /// Actual native written bytes.
        written_bytes: usize,
    },
    /// Caller-native wait budget elapsed; no operation is canceled.
    WaitDeadline,
    /// Permanently closed owner.
    Closed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Origin<'a> {
    epoch: Epoch<'a>,
    transmit: TransmitId<'a>,
}
/// Movable, caller-driven native PILS owner. O bounds only small operation
/// metadata; variable requests and public announcement use optional heap backing.
/// The caller must supply distinct Instance storage and the intended shared
/// CLIENT/Resolver domain. No callbacks/global task/self-reference is retained.
pub struct Client<'a, const O: usize = 32> {
    // Stop original attempts and stream before core/key ownership is dropped.
    connecting: Option<ConnectionAttempt>,
    framed: Option<Framed<Origin<'a>>>,
    core: Core<'a, O>,
    source: EndpointSource,
    limits: Limits,
    clock: Arc<dyn RuntimeClock>,
    subscription: Option<Box<dyn ClockSubscription>>,
    revision: u64,
    endpoint: Option<Endpoint>,
    socket_round: u64,
    socket_backoff: u64,
    socket_timer: Option<ResolutionTimer>,
    socket_needs_timer: bool,
    socket_ready: bool,
    port_error: Option<PortError>,
    wait: Option<Pin<Box<Sleep>>>,
    output: Option<Outbound<'a>>,
    scratch: Vec<u8>,
    read_first: bool,
    connect_guard: Option<ConnectGuard>,
    closed: bool,
}
fn clock_error(error: ProtocolError) -> Error {
    let kind = if error == ProtocolError::Capacity {
        io::ErrorKind::OutOfMemory
    } else {
        io::ErrorKind::Other
    };
    Error::Io(PortError::mark(io::Error::new(kind, error)))
}
fn bytes(len: usize) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    out.try_reserve_exact(len)
        .map_err(|_| ProtocolError::Capacity)?;
    out.resize(len, 0);
    Ok(out)
}
impl<'a, const O: usize> Client<'a, O> {
    /// Reserve one independent canonical-clock listener without starting I/O.
    /// Source/HELLO/profile remain explicit; local IKM is supplied separately.
    pub fn new(
        instance: &'a mut Instance,
        source: EndpointSource,
        profile: Profile,
        limits: Limits,
        hello: HelloLimits,
    ) -> Result<Self, Error> {
        Self::new_inner(instance, source, profile, limits, hello, None)
    }
    /// Same original identity owner with an owned native connection gate. A
    /// source snapshot alone is not a newly observed PILS identity or loss.
    pub fn new_guarded(
        instance: &'a mut Instance,
        source: EndpointSource,
        profile: Profile,
        limits: Limits,
        hello: HelloLimits,
        guard: ConnectGuard,
    ) -> Result<Self, Error> {
        Self::new_inner(instance, source, profile, limits, hello, Some(guard))
    }
    fn new_inner(
        instance: &'a mut Instance,
        source: EndpointSource,
        profile: Profile,
        limits: Limits,
        hello: HelloLimits,
        connect_guard: Option<ConnectGuard>,
    ) -> Result<Self, Error> {
        if limits.pending_operations == 0
            || limits.pending_operations > O
            || !(176..=65535).contains(&limits.frame_bytes)
            || limits.io_slice_bytes == 0
        {
            return Err(ProtocolError::Capacity.into());
        }
        let clock = source.clock();
        let subscription = clock.subscribe().map_err(clock_error)?;
        let scratch = bytes(hello.maximum_address_bytes)?;
        let core = Core::new(instance, profile, hello)?;
        Ok(Self {
            connecting: None,
            framed: None,
            core,
            source,
            limits,
            clock,
            subscription: Some(subscription),
            revision: 0,
            endpoint: None,
            socket_round: 0,
            socket_backoff: 0,
            socket_timer: None,
            socket_needs_timer: false,
            socket_ready: false,
            port_error: None,
            wait: None,
            output: None,
            scratch,
            read_first: true,
            connect_guard,
            closed: false,
        })
    }
    fn capacity(&self) -> Result<(), Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        if self.core.pending() >= self.limits.pending_operations {
            return Err(ProtocolError::Capacity.into());
        }
        Ok(())
    }
    /// Actual native frame/operation policy retained by this original owner.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }
    /// Actual retained announcement policy; adoption does not replace it.
    #[must_use]
    pub fn hello_limits(&self) -> HelloLimits {
        self.core.hello_limits()
    }
    /// Current owned buffer capacities plus an explicit allowance for all
    /// configured pending request frames and future RX/TX/announcement frames.
    /// This fixed-endpoint handoff reservation includes shared selector storage
    /// once; fixed Client layout, clock/Resolver/native allocations and RSS are
    /// separate. A nonfixed selector cannot claim this fixed-profile bound.
    pub fn storage_reservation_bytes(&self) -> Result<usize, Error> {
        let source = self
            .source
            .fixed_endpoint_storage_bytes()?
            .ok_or(ProtocolError::InvalidInput)?;
        let framed = self
            .framed
            .as_ref()
            .map_or(Ok(0), Framed::retained_storage_bytes)?;
        let current = self
            .core
            .retained_storage_bytes()?
            .checked_add(self.scratch.capacity())
            .and_then(|n| n.checked_add(framed))
            .and_then(|n| n.checked_add(source))
            .ok_or(ProtocolError::Overflow)?;
        let future = self
            .limits
            .pending_operations
            .checked_add(3)
            .and_then(|n| n.checked_mul(self.limits.frame_bytes))
            .ok_or(ProtocolError::Overflow)?;
        current
            .checked_add(future)
            .ok_or_else(|| ProtocolError::Overflow.into())
    }
    /// Current verified original-MQ observation, not global authorization.
    #[must_use]
    pub fn identity(&self) -> Option<Identity<'a>> {
        self.core.identity()
    }
    /// Exact latest public announcement only while that MQ remains current.
    #[must_use]
    pub fn announcement(&self) -> Option<&[u8]> {
        self.core.identity().map(|_| self.core.last_announcement())
    }
    /// Original shared process clock. Duplicates only the Arc; creates no
    /// subscription, network operation, key access or implicit clock domain.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    /// Current logical MQ, possibly still establishing its initial native stream.
    #[must_use]
    pub fn epoch(&self) -> Option<Epoch<'a>> {
        self.core.epoch()
    }
    /// Admitted operation count, independent of output queue/socket progress.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.core.pending()
    }
    /// No tracked local logical operation or copied output lease remains. This
    /// is neither remote quiescence nor an acknowledgment of earlier requests.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.core.pending() == 0 && self.output.is_none()
    }
    /// Optional local derivation status; mismatch never publishes a wrong key.
    #[must_use]
    pub fn local_key_status(&self) -> LocalKeyStatus {
        self.core.local_key_status()
    }
    /// Borrow only the current matched local key, preventing concurrent mutation.
    #[must_use]
    pub fn local_key(&self) -> Option<&ActiveIdentity> {
        self.core.local_key()
    }
    /// Enable existing persisted IKM without file creation or a writer claim.
    pub fn enable_local_key(&mut self, master: MasterKey) -> Result<LocalKeyStatus, Error> {
        Ok(self.core.enable_local_key(master)?)
    }
    /// Retire local key/IKM access without changing public service requests.
    pub fn disable_local_key(&mut self) {
        self.core.disable_local_key();
    }
    /// Explicitly construct a separate matched key owner; outer Node owns its epochs.
    pub fn with_active_seed<T>(&self, construct: impl FnOnce(&[u8; 32]) -> T) -> Result<T, Error> {
        Ok(self.core.with_active_seed(construct)?)
    }
    /// Admit original exact purpose bytes. Driver failures do not revoke this ID.
    pub fn sign(&mut self, region: &[u8], target: KeyTarget<'a>) -> Result<OperationId<'a>, Error> {
        self.capacity()?;
        if gnunet_wire::official::pils::sign_request_len(region.len())? > self.limits.frame_bytes {
            return Err(ProtocolError::TooLarge.into());
        }
        Ok(self.core.sign(region, target)?)
    }
    /// Admit the official purpose7 HELLO region under this one explicit profile.
    pub fn sign_hello(
        &mut self,
        builder: &gnunet_hello::HelloBuilder<'_>,
        expiration: AbsoluteTime,
        target: KeyTarget<'a>,
    ) -> Result<OperationId<'a>, Error> {
        self.capacity()?;
        if self.limits.frame_bytes < 88 {
            return Err(ProtocolError::TooLarge.into());
        }
        Ok(self.core.sign_hello(builder, expiration, target)?)
    }
    /// Admit DHKEM while online/offline; Exact binding uses ordered MQ context.
    pub fn decapsulate(
        &mut self,
        encapsulation: [u8; 32],
        target: KeyTarget<'a>,
    ) -> Result<OperationId<'a>, Error> {
        self.capacity()?;
        Ok(self.core.decapsulate(encapsulation, target)?)
    }
    /// Admit legacy hashed ECDH, with no invented peer field in its response.
    pub fn ecdh(
        &mut self,
        public: [u8; 32],
        target: KeyTarget<'a>,
    ) -> Result<OperationId<'a>, Error> {
        self.capacity()?;
        Ok(self.core.ecdh(public, target)?)
    }
    /// One connected-MQ unsigned address feed. No desired-state persistence or
    /// remote ACK is inferred; caller must explicitly re-feed after reconnect.
    pub fn feed_addresses(
        &mut self,
        builder: &gnunet_hello::HelloBuilder<'_>,
    ) -> Result<OperationId<'a>, Error> {
        self.capacity()?;
        let epoch = self.core.epoch().ok_or(ProtocolError::NotReady)?;
        let length = builder.block_len()?;
        if length.checked_add(8).ok_or(ProtocolError::Overflow)? > self.limits.frame_bytes {
            return Err(ProtocolError::TooLarge.into());
        }
        let now = self.clock.sample().map_err(clock_error)?.now;
        let mut scratch = bytes(length)?;
        Ok(self
            .core
            .feed_addresses(epoch, builder, now, &mut scratch)?)
    }
    /// Suppress only the original logical operation; copied/partial bytes drain.
    pub fn cancel(&mut self, operation: OperationId<'a>) -> Result<(), Error> {
        Ok(self.core.cancel(operation)?)
    }
    /// Original-operation quiescence includes the native copied-frame cursor.
    /// A logical cancellation may still require the original frame to drain or
    /// its physical MQ to retire. This says nothing about remote side effects.
    pub fn operation_quiescent(&self, operation: OperationId<'a>) -> Result<bool, Error> {
        Ok(self.core.operation_quiescent(operation)?
            && self
                .output
                .is_none_or(|outbound| outbound.operation != operation))
    }
    fn stop_physical(&mut self) {
        drop(self.connecting.take());
        self.socket_timer = None;
        if let Some(mut framed) = self.framed.take() {
            framed.retire();
        }
        self.output = None;
        self.endpoint = None;
        self.socket_round = 0;
        self.socket_backoff = 0;
        self.socket_needs_timer = false;
        self.socket_ready = false;
        self.port_error = None;
        self.wait = None;
    }
    fn retire(&mut self, cause: LossCause) -> Result<Progress<'a, O>, Error> {
        let epoch = self.core.epoch().ok_or(ProtocolError::Stale)?;
        self.stop_physical();
        let report = self.core.prepare_connection_lost(epoch)?;
        Ok(Progress::Lost {
            epoch,
            cause,
            report,
        })
    }
    /// Explicitly close original physical I/O before scheduling a new MQ.
    /// A previously written FEED remains local submission with unknown application.
    pub fn reconnect(&mut self) -> Result<Progress<'a, O>, Error> {
        // Return retired feed ownership immediately; a later close cannot
        // silently discard an undelivered pending loss report.
        self.retire(LossCause::Requested)
    }
    /// Retry an explicitly refused CLIENT time/resolution resource before stream
    /// attachment. This never replaces the canonical clock or replays callbacks.
    pub fn recover_ports(&mut self) -> Result<(), Error> {
        if self.framed.is_some() || self.port_error.is_none() {
            return Err(ProtocolError::NotReady.into());
        }
        drop(self.connecting.take());
        self.port_error = None;
        self.socket_timer = None;
        self.socket_ready = !self.socket_needs_timer;
        Ok(())
    }
    /// Permanently close, wiping original native storage before retiring IDs/keys.
    pub fn close(&mut self) -> [Option<OperationId<'a>>; O] {
        self.stop_physical();
        self.subscription = None;
        self.closed = true;
        self.core.close()
    }
    fn poll_clock(&mut self, cx: &mut Context<'_>) -> Poll<Result<ClockSample, Error>> {
        let subscription = self.subscription.as_mut().ok_or(ProtocolError::Closed)?;
        match subscription.poll_changed(cx, self.revision) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(clock_error(e))),
            Poll::Ready(Ok(s)) => self.revision = s.revision,
            Poll::Pending => {}
        }
        let sample = self.clock.sample().map_err(clock_error)?;
        match subscription.poll_changed(cx, sample.revision) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(clock_error(e))),
            Poll::Ready(Ok(_)) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Pending => {}
        }
        self.revision = sample.revision;
        Poll::Ready(Ok(sample))
    }
    // One reused native timer serves both the caller's observation target and
    // the currently computable logical wake. No logical time is fabricated when
    // the canonical subscription has not yielded a consistent sample.
    fn poll_timer(&mut self, cx: &mut Context<'_>, target: Option<Instant>) -> Poll<()> {
        let Some(target) = target else {
            return Poll::Pending;
        };
        let timer = self
            .wait
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(target)));
        timer.as_mut().reset(target);
        let polled = timer.as_mut().poll(cx);
        if polled.is_ready() {
            self.wait = None;
        }
        polled
    }
    fn poll_wait(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Option<Instant>,
        now: AbsoluteTime,
    ) -> Poll<Result<Progress<'a, O>, Error>> {
        let logical = self
            .core
            .next_wakeup()
            .filter(|at| at.as_micros() != u64::MAX)
            .map(|at| {
                Instant::now()
                    .checked_add(Duration::from_micros(
                        at.as_micros().saturating_sub(now.as_micros()),
                    ))
                    .ok_or(ProtocolError::Overflow)
            })
            .transpose()?;
        let Some(target) = [deadline, logical].into_iter().flatten().min() else {
            return Poll::Pending;
        };
        match self.poll_timer(cx, Some(target)) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(()) => {
                if deadline.is_some_and(|d| Instant::now() >= d) {
                    Poll::Ready(Ok(Progress::WaitDeadline))
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        }
    }
    fn setup_output(&mut self, epoch: Epoch<'a>) -> Result<(), Error> {
        if self.output.is_some() {
            return Ok(());
        }
        let Some(length) = self.core.next_request_len(epoch)? else {
            return Ok(());
        };
        let framed = self.framed.as_mut().ok_or(ProtocolError::NotReady)?;
        framed.reserve(length, Class::Ordinary)?;
        let mut body = bytes(length)?;
        let outbound = self
            .core
            .next_request(epoch, &mut body)?
            .ok_or(ProtocolError::NotReady)?;
        let origin = Origin {
            epoch,
            transmit: outbound.transmit,
        };
        framed
            .enqueue_owned(OwnedFrame::new(body), origin, Class::Ordinary)
            .map_err(|rejected| rejected.reason)?;
        self.output = Some(outbound);
        Ok(())
    }
    fn dispatch_frame(&mut self, epoch: Epoch<'a>) -> Result<Progress<'a, O>, Error> {
        // A time-port refusal retains the exact complete original secret frame;
        // it is not consumed/relabelled or turned into a socket loss.
        let now = self.clock.sample().map_err(clock_error)?.now;
        let framed = self.framed.as_mut().ok_or(ProtocolError::NotReady)?;
        let frame = framed.frame_mut().ok_or(ProtocolError::NotReady)?;
        let result = self.core.receive(epoch, frame, &mut self.scratch, now);
        let released = framed.release_frame();
        if !released {
            return Err(ProtocolError::NotReady.into());
        }
        match result {
            Ok(event) => Ok(Progress::Inbound(event)),
            Err(ProtocolError::Capacity) => {
                self.retire(LossCause::Resource(ProtocolError::Capacity))
            }
            Err(error) => self.retire(LossCause::Protocol(error)),
        }
    }
    fn write(
        &mut self,
        cx: &mut Context<'_>,
        epoch: Epoch<'a>,
        before_io: &mut impl FnMut() -> Result<(), Error>,
    ) -> Poll<Result<Progress<'a, O>, Error>> {
        before_io()?;
        let result = self
            .framed
            .as_mut()
            .ok_or(ProtocolError::NotReady)?
            .poll_write(cx);
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(self.retire(LossCause::Io(error))),
            Poll::Ready(Ok(WriteProgress {
                origin,
                bytes,
                complete,
            })) => {
                let original = self.output.ok_or(ProtocolError::Stale)?;
                if origin
                    != (Origin {
                        epoch,
                        transmit: original.transmit,
                    })
                {
                    return Poll::Ready(self.retire(LossCause::Protocol(ProtocolError::Stale)));
                }
                self.read_first = true;
                if complete {
                    let written = self.core.written(epoch, origin.transmit)?;
                    self.output = None;
                    Poll::Ready(Ok(Progress::Written(written)))
                } else {
                    Poll::Ready(Ok(Progress::Activity {
                        read_bytes: 0,
                        written_bytes: bytes,
                    }))
                }
            }
        }
    }
    fn read(
        &mut self,
        cx: &mut Context<'_>,
        epoch: Epoch<'a>,
        before_io: &mut impl FnMut() -> Result<(), Error>,
    ) -> Poll<Result<Progress<'a, O>, Error>> {
        before_io()?;
        let result = self
            .framed
            .as_mut()
            .ok_or(ProtocolError::NotReady)?
            .poll_read(cx);
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(self.retire(LossCause::Io(error))),
            Poll::Ready(Ok(ReadStep::Eof)) => Poll::Ready(self.retire(LossCause::Eof)),
            Poll::Ready(Ok(ReadStep::Progress { bytes, complete })) => {
                self.read_first = false;
                if complete {
                    Poll::Ready(self.dispatch_frame(epoch))
                } else {
                    Poll::Ready(Ok(Progress::Activity {
                        read_bytes: bytes,
                        written_bytes: 0,
                    }))
                }
            }
        }
    }
    fn poll_drive(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Option<Instant>,
    ) -> Poll<Result<Progress<'a, O>, Error>> {
        self.poll_guarded(cx, deadline, &mut || Ok(()))
    }
    /// Poll original retained cursors with a caller-owned native/canonical
    /// cancellation gate after provider work and before every driver-level
    /// connect/read/write. Refusal leaves old owners intact for explicit close;
    /// it creates no replacement identity, request, epoch or processing receipt.
    pub fn poll_guarded(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Option<Instant>,
        before_io: &mut impl FnMut() -> Result<(), Error>,
    ) -> Poll<Result<Progress<'a, O>, Error>> {
        if self.closed {
            return Poll::Ready(Ok(Progress::Closed));
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        before_io()?;
        if let Some(error) = &self.port_error {
            return Poll::Ready(Err(Error::Io(error.to_io())));
        }
        let sample = match self.poll_clock(cx) {
            Poll::Pending => {
                return self
                    .poll_timer(cx, deadline)
                    .map(|()| Ok(Progress::WaitDeadline));
            }
            Poll::Ready(sample) => sample?,
        };
        before_io()?;
        if self.core.retry_registration_pending() {
            self.core.register_retry(sample.now)?;
        }
        if self.core.epoch().is_none() {
            if !self.core.connection_needed(sample.now) {
                return self.poll_wait(cx, deadline, sample.now);
            }
            match self.source.resolve() {
                Ok(endpoint) => {
                    self.core.begin_connection(sample.now)?;
                    self.endpoint = Some(endpoint);
                    self.socket_ready = true;
                }
                Err(error) => {
                    self.core.prepare_connection_unavailable(sample.now)?;
                    return Poll::Ready(Ok(Progress::Unavailable(error)));
                }
            }
        }
        let epoch = self.core.epoch().ok_or(ProtocolError::NotReady)?;
        if self.framed.is_none() {
            if self.socket_needs_timer {
                match self
                    .source
                    .timer(Duration::from_micros(self.socket_backoff))
                {
                    Ok(timer) => {
                        self.socket_timer = Some(timer);
                        self.socket_needs_timer = false;
                    }
                    Err(error) => {
                        let error = PortError::mark(error);
                        self.port_error = PortError::from_io(&error).cloned();
                        return Poll::Ready(Err(Error::Io(error)));
                    }
                }
            }
            if let Some(timer) = &mut self.socket_timer {
                match timer.as_mut().poll(cx) {
                    Poll::Pending => return self.poll_wait(cx, deadline, sample.now),
                    Poll::Ready(Ok(())) => {
                        self.socket_timer = None;
                        self.socket_ready = true;
                    }
                    Poll::Ready(Err(error)) => {
                        let error = PortError::mark(error);
                        self.port_error = PortError::from_io(&error).cloned();
                        self.socket_timer = None;
                        self.socket_needs_timer = true;
                        return Poll::Ready(Err(Error::Io(error)));
                    }
                }
            }
            if self.connecting.is_none() && self.socket_ready {
                let round = self
                    .socket_round
                    .checked_add(1)
                    .ok_or(ProtocolError::Overflow)?;
                let endpoint = self.endpoint.as_ref().ok_or(ProtocolError::NotReady)?;
                self.connecting = Some(match &self.connect_guard {
                    Some(guard) => endpoint.attempt_guarded(self.socket_round, guard.clone()),
                    None => endpoint.attempt(self.socket_round),
                });
                self.socket_round = round;
                self.socket_ready = false;
            }
            if let Some(connecting) = &mut self.connecting {
                before_io()?;
                match Pin::new(connecting).poll(cx) {
                    Poll::Pending => return self.poll_wait(cx, deadline, sample.now),
                    Poll::Ready(Err(error)) => {
                        drop(self.connecting.take());
                        if let Some(port) = PortError::from_io(&error) {
                            self.port_error = Some(port.clone());
                            return Poll::Ready(Err(Error::Io(error)));
                        }
                        self.socket_backoff = if self.socket_backoff == 0 {
                            1000
                        } else {
                            self.socket_backoff.saturating_mul(2).min(900_000_000)
                        };
                        self.socket_needs_timer = true;
                        return Poll::Ready(Ok(Progress::ConnectRetry {
                            epoch,
                            retry_after: Duration::from_micros(self.socket_backoff),
                            error,
                        }));
                    }
                    Poll::Ready(Ok(connection)) => {
                        self.connecting = None;
                        let limits = FrameLimits {
                            frame_bytes: self.limits.frame_bytes,
                            ordinary: Budget {
                                frames: 1,
                                bytes: self.limits.frame_bytes,
                            },
                            reserved: Budget::default(),
                            accounting: Accounting::Retained,
                            io_slice_bytes: self.limits.io_slice_bytes,
                        };
                        match Framed::new(connection, limits) {
                            Ok(framed) => {
                                self.framed = Some(framed);
                                return Poll::Ready(Ok(Progress::Connected(epoch)));
                            }
                            Err(error) => {
                                return Poll::Ready(self.retire(LossCause::Resource(error)));
                            }
                        }
                    }
                }
            }
            return self.poll_wait(cx, deadline, sample.now);
        }
        if self.framed.as_ref().is_some_and(|f| f.frame().is_some()) {
            return Poll::Ready(self.dispatch_frame(epoch));
        }
        if let Err(error) = self.setup_output(epoch) {
            return Poll::Ready(self.retire(LossCause::Setup(error)));
        }
        if self.read_first {
            if let Poll::Ready(event) = self.read(cx, epoch, before_io) {
                return Poll::Ready(event);
            }
            if let Poll::Ready(event) = self.write(cx, epoch, before_io) {
                return Poll::Ready(event);
            }
        } else {
            if let Poll::Ready(event) = self.write(cx, epoch, before_io) {
                return Poll::Ready(event);
            }
            if let Poll::Ready(event) = self.read(cx, epoch, before_io) {
                return Poll::Ready(event);
            }
        }
        self.poll_wait(cx, deadline, sample.now)
    }
    /// Wait for one original event. A native deadline limits only this wait;
    /// dropping this future preserves connection attempts, RX/TX and operations.
    pub async fn drive(&mut self, deadline: Option<Instant>) -> Result<Progress<'a, O>, Error> {
        poll_fn(|cx| self.poll_drive(cx, deadline)).await
    }
}
impl<const O: usize> Drop for Client<'_, O> {
    fn drop(&mut self) {
        self.stop_physical();
        let _retired = self.core.close();
        self.subscription = None;
    }
}
