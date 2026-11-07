//! Long-lived official STATISTICS client with a caller-owned Unix/TCP driver.
//!
//! Mutations are admitted synchronously to a bounded virtual MQ. Socket retries
//! do not change that MQ's identity. An established connection failure retires
//! its epoch and re-registers live watches with fresh wire WIDs.
//!
//! Configured owners use the exact canonical clock source supplied by their
//! shared Resolver context; raw Unix owners explicitly select SystemClock.
//! Each enabled owner reserves one distinct clock subscription at construction,
//! in addition to any native CLIENT retry timer. Close releases that subscription
//! even if the closed handle is retained. Wait budgets remain native Tokio time.
//! A time-port refusal after command admission is reported by drive while the
//! returned original operation ID remains admitted. It never becomes a native
//! connection loss or a fabricated callback. Error continuations return before
//! their original retry deadline is registered from a fresh source sample.
#![doc = include_str!("handle_lifetimes.md")]

use crate::IpcError;
use gnunet_client::{
    statistics::{Selector, Statistic, WatchValue},
    statistics_handle::{
        ConnectionEpoch, DestroyReport, GetCompletion, GetFlow, GetId, Inbound, Outbound,
        SetterAdmission, StatisticsHandle as Core, WatchId,
    },
};
use gnunet_client_host::{ConnectionAttempt as Connect, Endpoint, EndpointSource as Source};
use gnunet_config::Configuration;
use gnunet_service_runtime::connection::Connection;
use gnunet_types::{AbsoluteTime, Error};
use gnunet_wire::official::MessageHeader;
use std::{
    future::{Future, poll_fn},
    io,
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, ReadBuf},
    time::{Instant, Sleep},
};

/// Caller-owned allocation-free identity for one STATISTICS client owner.
pub use gnunet_client::statistics_handle::Instance;

/// Host buffers and per-write fairness, independent of core action capacities.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum complete request/response size, between 4 and 65535.
    pub max_frame_bytes: usize,
    /// Maximum bytes in one actual socket write. Must be nonzero. This can
    /// fragment a frame without changing any official protocol bytes.
    pub write_chunk_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frame_bytes: 65535,
            write_chunk_bytes: 65535,
        }
    }
}

/// Synchronous callback effects, borrowing names/data only for this invocation.
#[derive(Clone, Copy, Debug)]
pub enum Event<'owner, 'a> {
    /// One row belonging to the original current GET.
    GetValue {
        /// Original request generation.
        get: GetId<'owner>,
        /// Exact official row.
        statistic: Statistic<'a>,
    },
    /// An enabled GET continuation. Explicit cancellation suppresses this event.
    GetComplete(GetCompletion<'owner>),
    /// One notification, using its original logical selector after reconnect.
    WatchValue {
        /// Stable logical subscription generation.
        watch: WatchId<'owner>,
        /// Original registration, never supplied by the server.
        selector: Selector<'a>,
        /// Exact server notification fields.
        notification: WatchValue,
    },
    /// A socket is ready in this virtual MQ epoch.
    Connected(ConnectionEpoch<'owner>),
    /// Initial socket establishment failed; queued work remains in this epoch.
    ConnectRetry {
        /// Original virtual MQ epoch.
        epoch: ConnectionEpoch<'owner>,
        /// Delay registered in the selected logical source after the actual
        /// native failure. Clock revisions can change the physical wait.
        retry_after: Duration,
    },
    /// Service configuration prevented MQ creation. Pending operations remain
    /// coalescible and have no connection epoch. The detailed failure can be
    /// taken with `StatisticsHandle::take_connect_error` after this callback.
    ConnectionUnavailable {
        /// Next STATISTICS-owner retry, independent of socket retry backoff.
        next_attempt: AbsoluteTime,
    },
    /// An established connection was retired. Unsent actions may reconnect;
    /// admitted mutations are not replayed or acknowledged by this event.
    ConnectionLost {
        /// Retired epoch.
        epoch: ConnectionEpoch<'owner>,
        /// Classified failure.
        cause: Error,
    },
    /// All original operations and sockets have been retired.
    Destroyed(DestroyReport),
}

/// Result of driving one progress/callback step. A wait deadline does not
/// cancel any original GET or extend the core's admitted destruction deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// An actual I/O, timer or callback step was performed.
    Activity,
    /// The initially lazy owner has no connection, work or timer to drive.
    Idle,
    /// This call's optional waiting budget elapsed; all partial cursors remain.
    WaitDeadline,
    /// The owner is permanently closed and all terminal effects were consumed.
    Closed,
}

fn bytes(capacity: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| Error::Capacity)?;
    bytes.resize(capacity, 0);
    Ok(bytes)
}
type ClockSource = Arc<dyn gnunet_service_runtime::clock::RuntimeClock>;
fn clock_error(error: Error) -> IpcError {
    let kind = if error == Error::Capacity {
        io::ErrorKind::OutOfMemory
    } else {
        io::ErrorKind::Other
    };
    IpcError::Io(gnunet_client_host::resolution::PortError::mark(
        io::Error::new(kind, error),
    ))
}
fn clock_now(source: &ClockSource) -> Result<AbsoluteTime, IpcError> {
    Ok(source.sample().map_err(clock_error)?.now)
}

fn validate_size(limits: Limits, fixed: usize, selector: Selector<'_>) -> Result<(), Error> {
    if selector.subsystem.contains(&0) || selector.name.contains(&0) {
        return Err(Error::InvalidInput);
    }
    let size = fixed
        .checked_add(selector.subsystem.len())
        .and_then(|n| n.checked_add(selector.name.len()))
        .and_then(|n| n.checked_add(2))
        .ok_or(Error::Overflow)?;
    if size > usize::from(u16::MAX) {
        return Err(Error::TooLarge);
    }
    if size > limits.max_frame_bytes {
        return Err(Error::Capacity);
    }
    Ok(())
}
struct Envelope<'owner> {
    bytes: Vec<u8>,
    frame: Option<Outbound<'owner>>,
    written: usize,
    first_attempt: bool,
}
impl<'owner> Envelope<'owner> {
    fn new(capacity: usize) -> Result<Self, Error> {
        Ok(Self {
            bytes: bytes(capacity)?,
            frame: None,
            written: 0,
            first_attempt: false,
        })
    }
}
struct Scheduler<'owner> {
    source: Source,
    endpoint: Option<Endpoint>,
    unavailable: Option<AbsoluteTime>,
    unavailable_pending: bool,
    pending_clock_error: Option<gnunet_client_host::resolution::PortError>,
    last_connect_error: Option<IpcError>,
    epoch: Option<ConnectionEpoch<'owner>>,
    envelopes: [Envelope<'owner>; 2],
    head: usize,
    len: usize,
    socket_retry: Option<gnunet_client_host::resolution::ResolutionTimer>,
    socket_ready: bool,
    socket_port_error: Option<gnunet_client_host::resolution::PortError>,
    pending_native_error: Option<io::Error>,
    socket_backoff: Duration,
    socket_round: u64,
}
impl<'owner> Scheduler<'owner> {
    fn new(capacity: usize, source: Source) -> Result<Self, Error> {
        Ok(Self {
            source,
            endpoint: None,
            unavailable: None,
            unavailable_pending: false,
            pending_clock_error: None,
            last_connect_error: None,
            epoch: None,
            envelopes: [Envelope::new(capacity)?, Envelope::new(capacity)?],
            head: 0,
            len: 0,
            socket_retry: None,
            socket_ready: false,
            socket_port_error: None,
            pending_native_error: None,
            socket_backoff: Duration::ZERO,
            socket_round: 0,
        })
    }
    fn clear(&mut self) {
        for envelope in &mut self.envelopes {
            envelope.frame = None;
            envelope.written = 0;
            envelope.first_attempt = false;
        }
        self.head = 0;
        self.len = 0;
        self.socket_retry = None;
        self.socket_ready = false;
        self.socket_port_error = None;
        self.pending_native_error = None;
        self.socket_backoff = Duration::ZERO;
        self.socket_round = 0;
        self.endpoint = None;
        // An epoch change retires transport state, not an unreported caller
        // time-source failure. drive observes that original boundary separately.
        self.unavailable_pending = false;
    }
    fn remember_clock_error(&mut self, error: &io::Error) {
        // One unobserved host boundary remains the original cause even when
        // another operation encounters a different refusal before drive.
        if self.pending_clock_error.is_none() {
            self.pending_clock_error =
                gnunet_client_host::resolution::PortError::from_io(error).cloned();
        }
    }
    fn pump<const A: usize, const N: usize, const W: usize, const WW: usize, const T: usize>(
        &mut self,
        core: &mut Core<'owner, A, N, W, WW, T>,
        source: &ClockSource,
        register_allowed: bool,
    ) -> Result<(), IpcError> {
        if core.ready_destroy_pending() {
            return Ok(());
        }
        if core.retry_registration_pending()
            && (!register_allowed || core.pending_completions() != 0)
        {
            return Ok(());
        }
        if core.retry_registration_pending() {
            // C reconnect_later calls add_delayed only after do_disconnect's
            // synchronous continuation. This one post-return sample owns the
            // new target. A previous or subsequent sample must not replace it
            // or create an MQ immediately after a between-read rollback.
            core.register_retry(clock_now(source)?)?;
            if self.unavailable_pending {
                self.unavailable = core.next_wakeup();
                self.unavailable_pending = false;
            }
            return Ok(());
        }
        let now = if core.is_closed() {
            AbsoluteTime::from_micros(0)
        } else {
            clock_now(source)?
        };
        core.tick(now)?;
        if core.is_closed() {
            self.clear();
            self.pending_clock_error = None;
            self.epoch = None;
            self.unavailable = None;
            return Ok(());
        }
        let mut endpoint = None;
        if core.connection_epoch().is_none() && core.connection_needed(now) {
            match self.source.resolve() {
                Ok(resolved) => {
                    core.begin_connection(now)?;
                    endpoint = Some(resolved);
                }
                Err(error) => {
                    core.prepare_connection_unavailable(now)?;
                    self.unavailable_pending = true;
                    self.last_connect_error = Some(error.into());
                    if register_allowed {
                        core.register_retry(clock_now(source)?)?;
                        self.unavailable = core.next_wakeup();
                        self.unavailable_pending = false;
                    }
                }
            }
        }
        if self.epoch != core.connection_epoch() {
            self.clear();
            self.epoch = core.connection_epoch();
            if self.epoch.is_some() {
                self.socket_ready = true;
            }
        }
        if let Some(endpoint) = endpoint {
            self.endpoint = Some(endpoint);
        }
        if let Some(epoch) = self.epoch {
            while self.len < 2 {
                let index = (self.head + self.len) % 2;
                let envelope = &mut self.envelopes[index];
                let Some(frame) = core.next_request(epoch, &mut envelope.bytes)? else {
                    break;
                };
                envelope.frame = Some(frame);
                envelope.written = 0;
                envelope.first_attempt = false;
                self.len += 1;
            }
        }
        Ok(())
    }
    fn pop(&mut self) {
        let envelope = &mut self.envelopes[self.head];
        envelope.frame = None;
        envelope.written = 0;
        envelope.first_attempt = false;
        self.head = (self.head + 1) % 2;
        self.len -= 1;
    }
}

/// Restricted callback access to this same original owner. Commands admitted
/// here are scheduled before another buffered row can dispatch. Destruction is
/// deliberately absent: the C API forbids destroying a handle in GET completion.
pub struct CallbackContext<
    'owner,
    'a,
    const A: usize,
    const N: usize,
    const W: usize,
    const WW: usize,
    const T: usize,
> {
    core: &'a mut Core<'owner, A, N, W, WW, T>,
    scheduler: &'a mut Scheduler<'owner>,
    subsystem: &'a [u8],
    limits: Limits,
    clock_source: &'a ClockSource,
    register_allowed: bool,
}
impl<'owner, const A: usize, const N: usize, const W: usize, const WW: usize, const T: usize>
    CallbackContext<'owner, '_, A, N, W, WW, T>
{
    fn pump(&mut self) -> Result<(), IpcError> {
        match self
            .scheduler
            .pump(self.core, self.clock_source, self.register_allowed)
        {
            Err(IpcError::Io(error))
                if gnunet_client_host::resolution::PortError::from_io(&error).is_some() =>
            {
                self.scheduler.remember_clock_error(&error);
                Ok(())
            }
            result => result,
        }
    }
    /// Queue/coalesce an absolute value in the creating subsystem.
    pub fn set(
        &mut self,
        name: &[u8],
        value: u64,
        persistent: bool,
    ) -> Result<SetterAdmission, IpcError> {
        validate_size(
            self.limits,
            16,
            Selector {
                subsystem: self.subsystem,
                name,
            },
        )?;
        let result = self.core.set(name, value, persistent)?;
        self.pump()?;
        Ok(result)
    }
    /// Queue/coalesce a signed update. Calling update(0) is a complete no-op.
    pub fn update(
        &mut self,
        name: &[u8],
        delta: i64,
        persistent: bool,
    ) -> Result<SetterAdmission, IpcError> {
        if delta == 0 {
            return Ok(self.core.update(name, delta, persistent)?);
        }
        validate_size(
            self.limits,
            16,
            Selector {
                subsystem: self.subsystem,
                name,
            },
        )?;
        let result = self.core.update(name, delta, persistent)?;
        self.pump()?;
        Ok(result)
    }
    /// Queue a GET with independent empty-string wildcards.
    pub fn get(&mut self, selector: Selector<'_>) -> Result<GetId<'owner>, IpcError> {
        validate_size(self.limits, 4, selector)?;
        let id = self.core.get(selector)?;
        self.pump()?;
        Ok(id)
    }
    /// Cancel a GET from this same owner. An active query still drains its END.
    pub fn get_cancel(&mut self, get: GetId<'owner>) -> Result<(), IpcError> {
        self.core.get_cancel(get)?;
        Ok(())
    }
    /// Register an exact selector and retain its logical identity across sockets.
    pub fn watch(&mut self, selector: Selector<'_>) -> Result<WatchId<'owner>, IpcError> {
        validate_size(self.limits, 4, selector)?;
        let id = self.core.watch(selector)?;
        self.pump()?;
        Ok(id)
    }
    /// Cancel only this owner's logical watch; no wire unwatch message exists.
    pub fn watch_cancel(&mut self, watch: WatchId<'owner>) -> Result<(), IpcError> {
        self.core.watch_cancel(watch)?;
        Ok(())
    }
    /// Whether an original GET still owns a stream tombstone or completion.
    #[must_use]
    pub fn owns_get(&self, get: GetId<'owner>) -> bool {
        self.core.owns_get(get)
    }
    /// Whether a GET can still dispatch a row or continuation. Applications
    /// with per-ID closures can release cancelled or interrupted-aborted state
    /// even though the C-compatible owner deliberately emits no continuation.
    #[must_use]
    pub fn get_callbacks_enabled(&self, get: GetId<'owner>) -> bool {
        self.core.get_callbacks_enabled(get)
    }
    /// Whether this original logical watch still owns callback authority.
    #[must_use]
    pub fn owns_watch(&self, watch: WatchId<'owner>) -> bool {
        self.core.owns_watch(watch)
    }
}

enum IoEvent<'owner> {
    Connected(ConnectionEpoch<'owner>),
    Retry(ConnectionEpoch<'owner>, Duration),
    Lost(ConnectionEpoch<'owner>, Error),
    Frame(ConnectionEpoch<'owner>, usize),
    Activity,
    WaitDeadline,
    Idle,
    Closed,
    Unavailable(AbsoluteTime),
}

/// Caller-owned Unix/TCP host for the official queued STATISTICS owner.
///
/// No task or unbounded channel is created. Public queue methods admit virtual
/// MQ envelopes synchronously, even before the socket is ready. `drive` performs
/// actual work. Dropping one drive future preserves partial RX/TX cursors;
/// cancelling an original GET is explicit. Dropping the driver closes its socket
/// and all callback authority. IDs are valid only for this same instance.
pub struct StatisticsHandle<
    'owner,
    const A: usize,
    const N: usize,
    const W: usize,
    const WW: usize,
    const T: usize,
> {
    core: Core<'owner, A, N, W, WW, T>,
    subsystem: Vec<u8>,
    limits: Limits,
    clock_source: ClockSource,
    clock_subscription: Option<Box<dyn gnunet_service_runtime::clock::ClockSubscription>>,
    clock_revision: u64,
    pending_frame: Option<(ConnectionEpoch<'owner>, usize)>,
    scheduler: Scheduler<'owner>,
    io_epoch: Option<ConnectionEpoch<'owner>>,
    stream: Option<Connection>,
    connecting: Option<Connect>,
    input: Vec<u8>,
    used: usize,
    expected: usize,
    watch_names: Vec<u8>,
    timer: Option<Pin<Box<Sleep>>>,
    last_io_error: Option<io::Error>,
    read_first: bool,
}
impl<'owner, const A: usize, const N: usize, const W: usize, const WW: usize, const T: usize>
    StatisticsHandle<'owner, A, N, W, WW, T>
{
    /// Create a lazy owner. No socket or runtime task is created by this call.
    /// Disabled owners return None, matching official create(DISABLE=YES).
    pub fn new(
        instance: &'owner mut Instance,
        path: impl AsRef<Path>,
        subsystem: &[u8],
        enabled: bool,
        limits: Limits,
    ) -> Result<Option<Self>, IpcError> {
        Self::with_source(
            instance,
            Source::unix(path.as_ref().to_path_buf()),
            subsystem,
            enabled,
            limits,
        )
    }
    fn with_source(
        instance: &'owner mut Instance,
        source: Source,
        subsystem: &[u8],
        enabled: bool,
        limits: Limits,
    ) -> Result<Option<Self>, IpcError> {
        let Some(core) = Core::new(instance, subsystem, enabled)? else {
            return Ok(None);
        };
        if !(4..=65535).contains(&limits.max_frame_bytes) || limits.write_chunk_bytes == 0 {
            return Err(Error::InvalidInput.into());
        }
        let clock_source = source.clock();
        let clock_subscription = clock_source.subscribe().map_err(clock_error)?;
        Ok(Some(Self {
            core,
            subsystem: subsystem.to_vec(),
            limits,
            clock_source,
            clock_subscription: Some(clock_subscription),
            clock_revision: 0,
            pending_frame: None,
            scheduler: Scheduler::new(limits.max_frame_bytes, source)?,
            io_epoch: None,
            stream: None,
            connecting: None,
            input: bytes(limits.max_frame_bytes)?,
            used: 0,
            expected: 4,
            watch_names: bytes(N)?,
            timer: None,
            last_io_error: None,
            read_first: false,
        }))
    }
    /// Snapshot the official configuration and read DISABLE. Only YES disables.
    /// Service endpoint validation is lazy, like C create: invalid configuration
    /// produces ConnectionUnavailable when work is queued, retaining the pending
    /// actions for the owner's real retry instead of creating a fictitious MQ.
    pub fn from_config(
        instance: &'owner mut Instance,
        config: &Configuration,
        resolution: gnunet_client_host::resolution::SharedResolution,
        subsystem: &[u8],
        limits: Limits,
    ) -> Result<Option<Self>, IpcError> {
        if matches!(config.get_yesno(b"statistics", b"DISABLE"), Ok(true)) {
            return Ok(None);
        }
        Self::with_source(
            instance,
            Source::configuration(config.duplicate()?, b"statistics", resolution),
            subsystem,
            true,
            limits,
        )
    }
    /// Retain the caller's live statistics configuration identity. DISABLE is
    /// read once at creation; later MQ creation rereads endpoint fields while
    /// an existing MQ retains its cached TCP and samples only live UNIXPATH.
    /// Resolver selection remains independently owned by the supplied context.
    pub fn from_live_config(
        instance: &'owner mut Instance,
        config: gnunet_client_host::LiveConfiguration,
        resolution: gnunet_client_host::resolution::SharedResolution,
        subsystem: &[u8],
        limits: Limits,
    ) -> Result<Option<Self>, IpcError> {
        if matches!(
            config.snapshot()?.get_yesno(b"statistics", b"DISABLE"),
            Ok(true)
        ) {
            return Ok(None);
        }
        Self::with_source(
            instance,
            Source::live(config, b"statistics", resolution),
            subsystem,
            true,
            limits,
        )
    }
    fn context(&mut self) -> CallbackContext<'owner, '_, A, N, W, WW, T> {
        CallbackContext {
            core: &mut self.core,
            scheduler: &mut self.scheduler,
            subsystem: &self.subsystem,
            limits: self.limits,
            clock_source: &self.clock_source,
            register_allowed: false,
        }
    }
    fn admission_context(&mut self) -> CallbackContext<'owner, '_, A, N, W, WW, T> {
        let mut context = self.context();
        context.register_allowed = true;
        context
    }
    fn sync_transport(&mut self) {
        if self.io_epoch != self.scheduler.epoch {
            self.stream = None;
            self.connecting = None;
            self.used = 0;
            self.expected = 4;
            self.io_epoch = self.scheduler.epoch;
            self.pending_frame = None;
        }
        if self.core.is_closed() {
            self.clock_subscription = None;
            self.timer = None;
        }
    }
    fn pump(&mut self) -> Result<(), IpcError> {
        self.scheduler
            .pump(&mut self.core, &self.clock_source, true)?;
        self.sync_transport();
        Ok(())
    }
    /// Queue an absolute value, using this handle's creating subsystem.
    pub fn set(
        &mut self,
        name: &[u8],
        value: u64,
        persistent: bool,
    ) -> Result<SetterAdmission, IpcError> {
        let result = self.admission_context().set(name, value, persistent);
        self.sync_transport();
        result
    }
    /// Queue a signed relative update. Zero creates no action or connection.
    pub fn update(
        &mut self,
        name: &[u8],
        delta: i64,
        persistent: bool,
    ) -> Result<SetterAdmission, IpcError> {
        let result = self.admission_context().update(name, delta, persistent);
        self.sync_transport();
        result
    }
    /// Queue a GET and return its original generational identity.
    pub fn get(&mut self, selector: Selector<'_>) -> Result<GetId<'owner>, IpcError> {
        let result = self.admission_context().get(selector);
        self.sync_transport();
        result
    }
    /// Cancel queued/current GET callbacks without assigning its END to another query.
    pub fn get_cancel(&mut self, get: GetId<'owner>) -> Result<(), IpcError> {
        let result = self.admission_context().get_cancel(get);
        self.sync_transport();
        result
    }
    /// Register a logical watch, retained across connection epochs.
    pub fn watch(&mut self, selector: Selector<'_>) -> Result<WatchId<'owner>, IpcError> {
        let result = self.admission_context().watch(selector);
        self.sync_transport();
        result
    }
    /// Cancel a logical watch from this same instance.
    pub fn watch_cancel(&mut self, watch: WatchId<'owner>) -> Result<(), IpcError> {
        let result = self.admission_context().watch_cancel(watch);
        self.sync_transport();
        result
    }
    /// Apply the official destroy(sync_first) queue-length condition and fixed
    /// shutdown deadline. Drive until Destroyed to dispatch enabled continuations.
    /// A processing confirmation never claims durable storage.
    pub fn destroy(&mut self, sync_first: bool) -> Result<(), IpcError> {
        let deferred = sync_first
            && self.core.connection_epoch().is_some()
            && self.core.mq_nontransmitted_length() != 0;
        let now = if deferred {
            clock_now(&self.clock_source)?
        } else {
            AbsoluteTime::from_micros(0)
        };
        self.core.begin_destroy(sync_first, now)?;
        match self.pump() {
            Err(IpcError::Io(error))
                if gnunet_client_host::resolution::PortError::from_io(&error).is_some() =>
            {
                self.scheduler.remember_clock_error(&error);
            }
            Err(error) => return Err(error),
            Ok(()) => {}
        }
        self.sync_transport();
        Ok(())
    }
    /// Whether no queued/current/transmit/continuation work remains. Idle live
    /// watches retain the connection and still need driving for notifications.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.core.is_idle()
    }
    /// Whether final destruction has permanently retired this owner.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.core.is_closed()
    }
    /// Most recent actual OS failure, independently of classified callbacks.
    pub fn take_io_error(&mut self) -> Option<io::Error> {
        self.last_io_error.take()
    }
    /// Take an unconsumed configuration/MQ-creation failure, or the last socket
    /// failure. This is diagnostic state, never an acknowledgement of a setter.
    pub fn take_connect_error(&mut self) -> Option<IpcError> {
        self.scheduler
            .last_connect_error
            .take()
            .or_else(|| self.last_io_error.take().map(IpcError::Io))
    }
    /// Current virtual connection identity; it can exist before socket readiness.
    #[must_use]
    pub fn connection_epoch(&self) -> Option<ConnectionEpoch<'owner>> {
        self.core.connection_epoch()
    }
    /// Whether an original GET still owns a queued/current request or a
    /// completion; a cancelled current request remains only to drain its END.
    #[must_use]
    pub fn owns_get(&self, get: GetId<'owner>) -> bool {
        self.core.owns_get(get)
    }
    /// Whether this GET can still dispatch any callback. Use this to retire
    /// application-owned per-ID closures after explicit cancellation or an
    /// aborted iteration interrupted by connection loss, which has no terminal
    /// callback in the official C lifecycle.
    #[must_use]
    pub fn get_callbacks_enabled(&self, get: GetId<'owner>) -> bool {
        self.core.get_callbacks_enabled(get)
    }
    /// Whether an original logical watch remains registered in this owner.
    #[must_use]
    pub fn owns_watch(&self, watch: WatchId<'owner>) -> bool {
        self.core.owns_watch(watch)
    }

    fn lose(
        &mut self,
        epoch: ConnectionEpoch<'owner>,
        cause: Error,
    ) -> Result<IoEvent<'owner>, IpcError> {
        if self.core.connection_epoch() == Some(epoch) {
            self.core.prepare_connection_lost(epoch, cause)?;
        }
        self.scheduler.epoch = self.core.connection_epoch();
        self.sync_transport();
        Ok(IoEvent::Lost(epoch, cause))
    }
    fn poll_timer(
        &mut self,
        context: &mut Context<'_>,
        deadline: Option<Instant>,
    ) -> Poll<Result<IoEvent<'owner>, IpcError>> {
        let now = clock_now(&self.clock_source)?;
        let core_wake = self
            .core
            .next_wakeup()
            .filter(|at| at.as_micros() != u64::MAX)
            .map(|at| {
                Instant::now()
                    .checked_add(Duration::from_micros(
                        at.as_micros().saturating_sub(now.as_micros()),
                    ))
                    .ok_or(Error::Overflow)
            })
            .transpose()?;
        let wake = [deadline, core_wake].into_iter().flatten().min();
        let Some(wake) = wake else {
            return Poll::Pending;
        };
        let timer = self
            .timer
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(wake)));
        timer.as_mut().reset(wake);
        timer.as_mut().poll(context).map(|()| Ok(IoEvent::Activity))
    }
    fn poll_write(
        &mut self,
        context: &mut Context<'_>,
        deadline: Option<Instant>,
    ) -> Poll<Result<IoEvent<'owner>, IpcError>> {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Poll::Ready(Ok(IoEvent::WaitDeadline));
        }
        if self.scheduler.len == 0 {
            return Poll::Pending;
        }
        let Some(stream) = self.stream.as_ref() else {
            return Poll::Pending;
        };
        match stream.poll_write_ready(context) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => {
                self.last_io_error = Some(error);
                let epoch = self.io_epoch.ok_or(Error::Stale)?;
                return Poll::Ready(self.lose(epoch, Error::Io));
            }
            Poll::Ready(Ok(())) => {}
        }
        // Checking readiness does not count as the C MQ's first actual attempt.
        // try_write after readiness corresponds to socket_send, including EAGAIN.
        if !self.core.ready_destroy_pending() {
            self.core.tick(clock_now(&self.clock_source)?)?;
        }
        if self.core.is_closed() {
            self.pump()?;
            return Poll::Ready(Ok(IoEvent::Closed));
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Poll::Ready(Ok(IoEvent::WaitDeadline));
        }
        let index = self.scheduler.head;
        let envelope = &self.scheduler.envelopes[index];
        let frame = envelope.frame.ok_or(Error::Stale)?;
        let end = frame.len.min(
            envelope
                .written
                .saturating_add(self.limits.write_chunk_bytes),
        );
        let result = stream.try_write(&envelope.bytes[envelope.written..end]);
        let count = match result {
            // client.c treats an actual zero-byte send like EAGAIN: an
            // irreversible first attempt, but not a full frame or remote ACK.
            Ok(0) => None,
            Ok(count) => Some(count),
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::Interrupted =>
            {
                None
            }
            Err(error) => {
                self.last_io_error = Some(error);
                return Poll::Ready(self.lose(frame.epoch, Error::Io));
            }
        };
        let envelope = &mut self.scheduler.envelopes[index];
        if let Some(count) = count {
            envelope.written += count;
        }
        if envelope.written == frame.len {
            self.core.on_frame_written(frame.epoch, frame.transmit)?;
            self.scheduler.pop();
        } else if !envelope.first_attempt {
            envelope.first_attempt = true;
            self.core
                .on_first_send_attempt(frame.epoch, frame.transmit)?;
        }
        self.pump()?;
        Poll::Ready(Ok(IoEvent::Activity))
    }
    fn poll_read(
        &mut self,
        context: &mut Context<'_>,
        deadline: Option<Instant>,
    ) -> Poll<Result<IoEvent<'owner>, IpcError>> {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Poll::Ready(Ok(IoEvent::WaitDeadline));
        }
        let Some(stream) = self.stream.as_mut() else {
            return Poll::Pending;
        };
        let epoch = self.io_epoch.ok_or(Error::Stale)?;
        if !self.core.ready_destroy_pending() {
            self.core.tick(clock_now(&self.clock_source)?)?;
        }
        if self.core.is_closed() {
            self.pump()?;
            return Poll::Ready(Ok(IoEvent::Closed));
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Poll::Ready(Ok(IoEvent::WaitDeadline));
        }
        let mut read = ReadBuf::new(&mut self.input[self.used..self.expected]);
        match Pin::new(stream).poll_read(context, &mut read) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                self.last_io_error = Some(error);
                Poll::Ready(self.lose(epoch, Error::Io))
            }
            Poll::Ready(Ok(())) => {
                let count = read.filled().len();
                if count == 0 {
                    return Poll::Ready(self.lose(
                        epoch,
                        if self.used == 0 {
                            Error::Io
                        } else {
                            Error::Truncated
                        },
                    ));
                }
                self.used += count;
                if self.used == 4 {
                    let header = match MessageHeader::decode(&self.input[..4]) {
                        Ok(header) => header,
                        Err(error) => return Poll::Ready(self.lose(epoch, error)),
                    };
                    if header.size() > self.input.len() {
                        return Poll::Ready(self.lose(epoch, Error::Capacity));
                    }
                    self.expected = header.size();
                }
                if self.used == self.expected {
                    let size = self.expected;
                    self.used = 0;
                    self.expected = 4;
                    Poll::Ready(Ok(IoEvent::Frame(epoch, size)))
                } else {
                    Poll::Ready(Ok(IoEvent::Activity))
                }
            }
        }
    }
    fn register_socket_failure(
        &mut self,
        epoch: ConnectionEpoch<'owner>,
    ) -> Result<IoEvent<'owner>, IpcError> {
        let delay = self
            .scheduler
            .socket_backoff
            .max(Duration::from_millis(1))
            .saturating_mul(2)
            .min(Duration::from_secs(900));
        // Time registration is after the actual socket failure. Refusal leaves
        // the exact native error and old backoff intact; only registration may
        // be retried, never its consumed native connect effect.
        let timer = self.scheduler.source.timer(delay)?;
        let error = self
            .scheduler
            .pending_native_error
            .take()
            .ok_or(Error::NotReady)?;
        self.scheduler.socket_retry = Some(timer);
        self.scheduler.socket_backoff = delay;
        self.last_io_error = Some(error);
        Ok(IoEvent::Retry(epoch, delay))
    }
    fn poll_io(
        &mut self,
        context: &mut Context<'_>,
        deadline: Option<Instant>,
    ) -> Poll<Result<IoEvent<'owner>, IpcError>> {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Poll::Ready(Ok(IoEvent::WaitDeadline));
        }
        if self.core.is_closed() {
            self.sync_transport();
            return Poll::Ready(Ok(IoEvent::Closed));
        }
        if let Some(subscription) = &mut self.clock_subscription {
            match subscription.poll_changed(context, self.clock_revision) {
                Poll::Ready(Err(error)) => return Poll::Ready(Err(clock_error(error))),
                Poll::Ready(Ok(sample)) => self.clock_revision = sample.revision,
                Poll::Pending => {}
            }
            let sample = self.clock_source.sample().map_err(clock_error)?;
            self.clock_revision = sample.revision;
            match subscription.poll_changed(context, sample.revision) {
                Poll::Ready(Err(error)) => return Poll::Ready(Err(clock_error(error))),
                Poll::Ready(Ok(_)) => {
                    context.waker().wake_by_ref();
                    return Poll::Ready(Ok(IoEvent::Activity));
                }
                Poll::Pending => {}
            }
        }
        self.pump()?;
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Poll::Ready(Ok(IoEvent::WaitDeadline));
        }
        if self.core.is_closed() {
            return Poll::Ready(Ok(IoEvent::Closed));
        }
        if let Some(next_attempt) = self.scheduler.unavailable.take() {
            return Poll::Ready(Ok(IoEvent::Unavailable(next_attempt)));
        }
        if self.core.pending_completions() != 0 {
            return Poll::Ready(Ok(IoEvent::Activity));
        }
        let Some(epoch) = self.scheduler.epoch else {
            if self.core.next_wakeup().is_none() {
                return Poll::Ready(Ok(IoEvent::Idle));
            }
            return self.poll_timer(context, deadline);
        };
        if self.stream.is_none() {
            if let Some(error) = &self.scheduler.socket_port_error {
                return Poll::Ready(Err(IpcError::Io(error.to_io())));
            }
            if self.scheduler.pending_native_error.is_some() {
                return Poll::Ready(self.register_socket_failure(epoch));
            }
            if self.connecting.is_none() {
                if let Some(timer) = &mut self.scheduler.socket_retry {
                    match timer.as_mut().poll(context) {
                        Poll::Ready(Ok(())) => {
                            self.scheduler.socket_retry = None;
                            self.scheduler.socket_ready = true;
                        }
                        Poll::Ready(Err(error)) => {
                            let error = gnunet_client_host::resolution::PortError::mark(error);
                            self.scheduler.socket_port_error =
                                gnunet_client_host::resolution::PortError::from_io(&error).cloned();
                            self.scheduler.socket_retry = None;
                            return Poll::Ready(Err(IpcError::Io(error)));
                        }
                        Poll::Pending => {}
                    }
                }
                if self.scheduler.socket_ready {
                    let endpoint = self.scheduler.endpoint.clone().ok_or(Error::NotReady)?;
                    self.connecting = Some(endpoint.attempt(self.scheduler.socket_round));
                    self.scheduler.socket_round = self.scheduler.socket_round.wrapping_add(1);
                    self.scheduler.socket_ready = false;
                }
            }
            if let Some(connecting) = &mut self.connecting {
                match Pin::new(connecting).poll(context) {
                    Poll::Ready(Ok(stream)) => {
                        self.connecting = None;
                        self.stream = Some(stream);
                        self.scheduler.socket_retry = None;
                        return Poll::Ready(Ok(IoEvent::Connected(epoch)));
                    }
                    Poll::Ready(Err(error)) => {
                        if gnunet_client_host::resolution::PortError::from_io(&error).is_some() {
                            // The original attempt retains its terminal refusal.
                            // Keep the epoch/envelopes and native backoff intact.
                            return Poll::Ready(Err(IpcError::Io(error)));
                        }
                        self.connecting = None;
                        self.scheduler.pending_native_error = Some(error);
                        return Poll::Ready(self.register_socket_failure(epoch));
                    }
                    Poll::Pending => {}
                }
            }
            return self.poll_timer(context, deadline);
        }
        self.read_first = !self.read_first;
        let first = if self.read_first {
            self.poll_read(context, deadline)
        } else {
            self.poll_write(context, deadline)
        };
        if first.is_ready() {
            return first;
        }
        let second = if self.read_first {
            self.poll_write(context, deadline)
        } else {
            self.poll_read(context, deadline)
        };
        if second.is_ready() {
            return second;
        }
        self.poll_timer(context, deadline)
    }

    /// Drive one step and dispatch its synchronous callback. `deadline` bounds
    /// this wait only; None has no wait budget. Dropping this future preserves
    /// cursor/epoch state, and does not call get_cancel or disconnect the owner.
    /// Return flow is used only for GET row iteration; WATCH ignores it as C does.
    pub async fn drive(
        &mut self,
        deadline: Option<Instant>,
        callback: impl FnMut(
            Event<'owner, '_>,
            &mut CallbackContext<'owner, '_, A, N, W, WW, T>,
        ) -> GetFlow,
    ) -> Result<Progress, IpcError> {
        let progress = self.drive_step(deadline, callback).await?;
        if progress == Progress::Activity {
            tokio::task::yield_now().await;
        }
        Ok(progress)
    }
    async fn drive_step(
        &mut self,
        deadline: Option<Instant>,
        mut callback: impl FnMut(
            Event<'owner, '_>,
            &mut CallbackContext<'owner, '_, A, N, W, WW, T>,
        ) -> GetFlow,
    ) -> Result<Progress, IpcError> {
        if (self.core.retry_registration_pending() || self.core.is_closed())
            && let Some(completion) = self.core.take_completion()
        {
            callback(Event::GetComplete(completion), &mut self.context());
            self.pump()?;
            return Ok(Progress::Activity);
        }
        if self.core.ready_destroy_pending() {
            self.core.finalize_ready_destroy()?;
        }
        if !self.core.is_closed()
            && let Some(error) = self.scheduler.pending_clock_error.take()
        {
            return Err(IpcError::Io(error.to_io()));
        }
        self.pump()?;
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Ok(Progress::WaitDeadline);
        }
        if let Some(completion) = self.core.take_completion() {
            callback(Event::GetComplete(completion), &mut self.context());
            self.pump()?;
            return Ok(Progress::Activity);
        }
        if let Some(report) = self.core.take_destroy_report() {
            callback(Event::Destroyed(report), &mut self.context());
            self.pump()?;
            return Ok(Progress::Closed);
        }
        let event = if let Some((epoch, size)) = self.pending_frame.take() {
            IoEvent::Frame(epoch, size)
        } else {
            poll_fn(|context| self.poll_io(context, deadline)).await?
        };
        let mut flow_target = None;
        match event {
            IoEvent::WaitDeadline => return Ok(Progress::WaitDeadline),
            IoEvent::Idle => return Ok(Progress::Idle),
            IoEvent::Closed => {
                if self.core.pending_completions() != 0 {
                    return Ok(Progress::Activity);
                }
                if let Some(report) = self.core.take_destroy_report() {
                    callback(Event::Destroyed(report), &mut self.context());
                }
                return Ok(Progress::Closed);
            }
            IoEvent::Activity => {}
            IoEvent::Connected(epoch) => {
                callback(Event::Connected(epoch), &mut self.context());
            }
            IoEvent::Retry(epoch, retry_after) => {
                callback(
                    Event::ConnectRetry { epoch, retry_after },
                    &mut self.context(),
                );
            }
            IoEvent::Unavailable(next_attempt) => {
                callback(
                    Event::ConnectionUnavailable { next_attempt },
                    &mut self.context(),
                );
            }
            IoEvent::Lost(epoch, cause) => {
                callback(Event::ConnectionLost { epoch, cause }, &mut self.context());
            }
            IoEvent::Frame(epoch, size) => {
                let now = match clock_now(&self.clock_source) {
                    Ok(now) => now,
                    Err(error) => {
                        self.pending_frame = Some((epoch, size));
                        return Err(error);
                    }
                };
                let inbound = self.core.receive_staged(epoch, &self.input[..size], now);
                match inbound {
                    Ok(Inbound::None) => {}
                    Ok(Inbound::GetValue { get, statistic }) => {
                        let mut context = CallbackContext {
                            core: &mut self.core,
                            scheduler: &mut self.scheduler,
                            subsystem: &self.subsystem,
                            limits: self.limits,
                            clock_source: &self.clock_source,
                            register_allowed: false,
                        };
                        flow_target = Some((
                            get,
                            callback(Event::GetValue { get, statistic }, &mut context),
                        ));
                    }
                    Ok(Inbound::WatchValue {
                        watch,
                        notification,
                    }) => {
                        let selector = self.core.watch_selector(watch, &mut self.watch_names)?;
                        let mut context = CallbackContext {
                            core: &mut self.core,
                            scheduler: &mut self.scheduler,
                            subsystem: &self.subsystem,
                            limits: self.limits,
                            clock_source: &self.clock_source,
                            register_allowed: false,
                        };
                        callback(
                            Event::WatchValue {
                                watch,
                                selector,
                                notification,
                            },
                            &mut context,
                        );
                    }
                    Err(cause) => {
                        self.pump()?;
                        // The fixed destroy deadline can expire between the
                        // read poll and frame dispatch. The core has already
                        // completed destruction; dispatch its original deadline
                        // outcome on the next step, without inventing an IO loss.
                        if cause != Error::Deadline || !self.core.is_closed() {
                            callback(Event::ConnectionLost { epoch, cause }, &mut self.context());
                        }
                    }
                }
            }
        }
        if let Some((get, flow)) = flow_target {
            self.core.get_value_result(get, flow)?;
        }
        self.pump()?;
        Ok(Progress::Activity)
    }
}
