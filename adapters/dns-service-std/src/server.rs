//! Actual accepted IPC; every client callback belongs to its original MQ.
use crate::core::{self, Client, Destination, Effect, Engine, Work};
use gnunet_service_runtime::{
    accepted::{AcceptState, AcceptedConnection, SocketEvent},
    clock::{ClockSubscription, RuntimeClock},
    credentials::UnixAccess,
    framing::{Accounting, Budget, Class, Framed, Limits as Framing, OwnedFrame, ReadStep},
    service::{Listener, PeerAddress, ServiceOptions},
};
use gnunet_types::Error as Fault;
use std::{
    fmt,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
use zeroize::Zeroizing;
/// Actual native failure; known protocol/source faults retain their raw code.
#[derive(Debug)]
pub enum Error {
    /// Original core or framing refusal.
    Protocol(Fault),
    /// Original independent OS failure.
    Io(io::Error),
}
impl From<Fault> for Error {
    fn from(e: Fault) -> Self {
        Self::Protocol(e)
    }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(e) => write!(f, "DNS interception: {e}"),
            Self::Io(e) => write!(f, "DNS native IO: {e}"),
        }
    }
}
impl std::error::Error for Error {}
/// Explicit native per-MQ bounds. One original immutable callback frame per MQ.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Actual local MQ ceiling.
    pub clients: usize,
    /// Full official frame ceiling,20..65535.
    pub frame_bytes: usize,
    /// Syscall slice cap, positive.
    pub io_slice_bytes: usize,
    /// First accepted through actual INIT/read partial bound.
    pub input_lifetime: Duration,
    /// Actual callback queue through reply bound, never reset by progress.
    pub callback_lifetime: Duration,
    /// Canonical expiration poll cap.
    pub maintenance: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            clients: 16,
            frame_bytes: 65535,
            io_slice_bytes: 65535,
            input_lifetime: Duration::from_secs(10),
            callback_lifetime: Duration::from_secs(30),
            maintenance: Duration::from_millis(50),
        }
    }
}
impl Limits {
    fn validate(self) -> Result<(), Error> {
        if !(1..=64).contains(&self.clients)
            || !(20..=65535).contains(&self.frame_bytes)
            || self.io_slice_bytes == 0
            || self.maintenance.is_zero()
        {
            return Err(Fault::InvalidInput.into());
        }
        for d in [
            self.input_lifetime,
            self.callback_lifetime,
            self.maintenance,
        ] {
            if d.is_zero() || Instant::now().checked_add(d).is_none() {
                return Err(Fault::InvalidInput.into());
            }
        }
        Ok(())
    }
}
/// Observed physical/local facts, never synthetic DNS answers or registration ACK.
#[derive(Debug)]
pub enum Event<'id> {
    /// Shared actual listener/accept diagnostics.
    Socket(SocketEvent),
    /// Actual accepted and authorized original MQ.
    Accepted(Client<'id>),
    /// Original source physically closed with first cause.
    Closed {
        /// Exact original accepted MQ allocation.
        client: Client<'id>,
        /// Original physical/protocol cause.
        reason: Error,
        /// Original queued attempt, written prefix and total bytes.
        queued: Option<(Effect<'id>, usize, usize)>,
    },
    /// Original callback lost after real physical source retirement. Written
    /// means local whole writing only, never a processed application decision.
    CallbackLost {
        /// Original callback whose MQ has actually retired.
        effect: Effect<'id>,
        /// Original observed local stage, not remote receipt.
        state: core::OutputPhase,
    },
    /// Original helper output after its actual pipe owners retired.
    HelperOutputLost {
        /// Original helper-bound output.
        effect: Effect<'id>,
        /// Actual original pipe byte prefix.
        written: usize,
        /// Immutable original total frame length.
        total: usize,
    },
    /// Actual INIT/reply consumed; no response ACK exists.
    Input(Client<'id>),
    /// Actual immutable original callback enqueued.
    Queued(Effect<'id>),
    /// Actual original byte prefix/whole local write.
    Written {
        /// Original immutable callback attempt.
        effect: Effect<'id>,
        /// Actual bytes in this write observation.
        bytes: usize,
        /// Whole local frame written; no application ACK implied.
        complete: bool,
    },
    /// Independent original cleanup fault.
    Cleanup(Fault),
}
/// One fair original progress observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// One actual native/core step.
    Activity,
    /// Only caller wait ended, original cursors remain.
    WaitDeadline,
    /// Every original local MQ is retired.
    Stopped,
}
/// Real counters with no DNSSEC/remote-delivery claims.
#[derive(Clone, Copy, Debug, Default)]
pub struct Report {
    /// Actual accepted count.
    pub accepted: u64,
    /// Actual closed count.
    pub closed: u64,
    /// Actual local frames read.
    pub inputs: u64,
    /// Stale/expired original client responses consumed without a matching callback.
    pub client_responses_discarded: u64,
    /// Actual callback whole local writes.
    pub callbacks_written: u64,
    /// Actual local bytes written.
    pub bytes_written: u64,
}
struct App<'id> {
    client: Client<'id>,
    io: Framed<Effect<'id>>,
    queued: Option<Effect<'id>>,
    written: usize,
    total: usize,
    input_until: Option<Instant>,
    callback_until: Option<Instant>,
    turn: usize,
}
/// One actual shared SERVICE owner. Callbacks and helper/query ports are separate.
pub struct Server<'id> {
    core: Engine<'id>,
    apps: Vec<Option<App<'id>>>,
    limits: Limits,
    options: ServiceOptions,
    unix: UnixAccess,
    clock: Arc<dyn RuntimeClock>,
    subscription: Box<dyn ClockSubscription>,
    revision: u64,
    accept: AcceptState,
    app_cursor: usize,
    listener_cursor: usize,
    request_cursor: usize,
    turn: bool,
    scratch: Zeroizing<Vec<u8>>,
    stopped: bool,
    timer: Pin<Box<Sleep>>,
    report: Report,
}
impl<'id> Server<'id> {
    /// Fixed metadata, lazy actual accepted RX and one bounded shared encode slab.
    pub fn new(
        core: Engine<'id>,
        clock: Arc<dyn RuntimeClock>,
        limits: Limits,
        options: ServiceOptions,
        unix: UnixAccess,
    ) -> Result<Self, Error> {
        limits.validate()?;
        tokio::runtime::Handle::try_current().map_err(|e| io::Error::other(e.to_string()))?;
        if core.client_capacity() != limits.clients
            || core
                .payload_limit()
                .checked_add(16)
                .is_none_or(|n| n > limits.frame_bytes)
        {
            return Err(Fault::InvalidInput.into());
        }

        let subscription = clock.subscribe()?;
        let revision = clock.sample()?.revision;
        let mut apps = Vec::new();
        apps.try_reserve_exact(limits.clients)
            .map_err(|_| Fault::Capacity)?;
        apps.resize_with(limits.clients, || None);
        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(limits.frame_bytes)
            .map_err(|_| Fault::Capacity)?;
        scratch.resize(limits.frame_bytes, 0);
        Ok(Self {
            core,
            apps,
            limits,
            options,
            unix,
            clock,
            subscription,
            revision,
            accept: AcceptState::default(),
            app_cursor: 0,
            listener_cursor: 0,
            request_cursor: 0,
            turn: false,
            scratch: Zeroizing::new(scratch),
            stopped: false,
            timer: Box::pin(tokio::time::sleep_until(Instant::now())),
            report: Report::default(),
        })
    }
    /// Same real canonical clock, no new listener or source.
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        Arc::clone(&self.clock)
    }
    /// Bounded pure state, not provider success.
    pub const fn engine(&self) -> &Engine<'id> {
        &self.core
    }
    /// Explicit coordinator provider ports; do not take over local client effects.
    pub fn engine_mut(&mut self) -> &mut Engine<'id> {
        &mut self.core
    }
    /// Actual native counters.
    pub const fn report(&self) -> Report {
        self.report
    }
    fn framing(&self) -> Framing {
        Framing {
            frame_bytes: self.limits.frame_bytes,
            ordinary: Budget {
                frames: 1,
                bytes: self.limits.frame_bytes,
            },
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: self.limits.io_slice_bytes,
        }
    }
    /// Register both sides of canonical clock coherence; native hard limits are
    /// always checked by poll before this can wait/fail.
    pub fn now(&mut self, cx: &mut Context<'_>) -> Result<u64, Error> {
        for _ in 0..4 {
            if let Poll::Ready(changed) = self.subscription.poll_changed(cx, self.revision) {
                self.revision = changed?.revision;
            }
            let sample = self.clock.sample()?;
            self.revision = sample.revision;
            match self.subscription.poll_changed(cx, sample.revision) {
                Poll::Pending => return Ok(sample.now.as_micros()),
                Poll::Ready(Err(e)) => return Err(e.into()),
                Poll::Ready(Ok(changed)) => self.revision = changed.revision,
            }
        }
        cx.waker().wake_by_ref();
        Err(Fault::NotReady.into())
    }
    /// Original native MQ bounds are checked and armed before canonical-clock
    /// coherency. No socket read/write or logical-time sampling occurs here.
    pub fn poll_native_guard(
        &mut self,
        cx: &mut Context<'_>,
        until: Option<Instant>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        let now = Instant::now();
        for i in 0..self.apps.len() {
            if self.apps[i].as_ref().is_some_and(|a| {
                a.input_until.is_some_and(|d| now >= d)
                    || a.callback_until.is_some_and(|d| now >= d)
            }) {
                let client = self.apps[i].as_ref().ok_or(Fault::Conflict)?.client;
                self.close_client(client, Fault::Deadline.into(), observe)?;
                return Poll::Ready(Ok(Progress::Activity));
            }
        }
        let wake = now
            .checked_add(self.limits.maintenance)
            .ok_or(Fault::Overflow)?;
        let wake = self
            .apps
            .iter()
            .flatten()
            .flat_map(|a| a.input_until.into_iter().chain(a.callback_until))
            .chain(until)
            .fold(wake, Instant::min);
        self.timer.as_mut().reset(wake);
        if self.timer.as_mut().poll(cx).is_ready() {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
    /// Actual accepted source/ACL precedes pure attachment; no arbitrary raw stream.
    pub fn admit(
        &mut self,
        accepted: AcceptedConnection,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<Option<Client<'id>>, Error> {
        let (connection, address, diagnostics) = accepted.into_parts();
        for d in diagnostics {
            observe(Event::Socket(SocketEvent::Diagnostic(d)))
        }
        let allowed = match address {
            PeerAddress::Unix => self.unix.allows(&connection)?,
            PeerAddress::Tcp(peer) => self.options.access.allows(peer.ip()),
        };
        if !allowed || self.stopped {
            drop(connection);
            return Ok(None);
        }
        let index = self
            .apps
            .iter()
            .position(Option::is_none)
            .ok_or(Fault::Capacity)?;
        let mut framed = Framed::new(connection, self.framing())?;
        let client = match self.core.attach_client() {
            Ok(c) => c,
            Err(e) => {
                framed.retire();
                return Err(e.into());
            }
        };
        self.apps[index] = Some(App {
            client,
            io: framed,
            queued: None,
            written: 0,
            total: 0,
            input_until: Some(
                Instant::now()
                    .checked_add(self.limits.input_lifetime)
                    .ok_or(Fault::Overflow)?,
            ),
            callback_until: None,
            turn: 0,
        });
        self.report.accepted = self.report.accepted.saturating_add(1);
        observe(Event::Accepted(client));
        Ok(Some(client))
    }
    /// Physically stop first without reading the clock. Then settle only this
    /// original client generation and preserve any original queued effect metadata.
    pub fn close_client(
        &mut self,
        client: Client<'id>,
        reason: Error,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        let index = self
            .apps
            .iter()
            .position(|a| a.as_ref().is_some_and(|a| a.client == client))
            .ok_or(Fault::StaleGeneration)?;
        let mut app = self.apps[index].take().ok_or(Fault::StaleGeneration)?;
        app.io.retire();
        self.accept.client_closed();
        self.report.closed = self.report.closed.saturating_add(1);
        if let Ok(outputs) = self.core.client_outputs(client) {
            for (effect, state) in outputs {
                observe(Event::CallbackLost { effect, state });
            }
        }
        let result = self.core.client_lost(client);
        observe(Event::Closed {
            client,
            reason,
            queued: app.queued.map(|effect| (effect, app.written, app.total)),
        });
        if let Err(e) = result {
            observe(Event::Cleanup(e));
            return Err(e.into());
        }
        Ok(())
    }
    fn input(&mut self, i: usize, observe: &mut impl FnMut(Event<'id>)) -> Result<bool, Error> {
        let app = self.apps[i].as_ref().ok_or(Fault::StaleGeneration)?;
        let Some(bytes) = app.io.frame() else {
            return Ok(false);
        };
        let client = app.client;
        let header = gnunet_wire::official::Frame::decode(bytes)?.header();
        if self.options.tolerant
            && header.message_type() != gnunet_wire::official::message_type::DNS_CLIENT_INIT
            && header.message_type() != gnunet_wire::official::message_type::DNS_CLIENT_RESPONSE
        {
            let app = self.apps[i].as_mut().ok_or(Fault::StaleGeneration)?;
            if !app.io.release_frame() {
                return Err(Fault::Conflict.into());
            }
            app.input_until = None;
            return Ok(true);
        }
        let result = match core::wire::Request::decode(bytes) {
            Ok(core::wire::Request::Init { flags }) => self.core.init(client, flags),
            Ok(core::wire::Request::Reply { id, decision }) => {
                self.core.reply(client, id, decision).map(|matched| {
                    if !matched {
                        self.report.client_responses_discarded =
                            self.report.client_responses_discarded.saturating_add(1);
                    }
                })
            }
            Err(e) => Err(e),
        };
        if let Err(e) = result {
            self.close_client(client, e.into(), observe)?;
            return Ok(true);
        }
        let pending = self.core.pending_client(client)?;
        let app = self.apps[i].as_mut().ok_or(Fault::StaleGeneration)?;
        if !app.io.release_frame() {
            return Err(Fault::Conflict.into());
        }
        app.input_until = None;
        if !pending {
            app.callback_until = None;
        }
        self.report.inputs = self.report.inputs.saturating_add(1);
        observe(Event::Input(client));
        Ok(true)
    }
    fn queue(&mut self, i: usize, observe: &mut impl FnMut(Event<'id>)) -> Result<bool, Error> {
        let app = self.apps[i].as_ref().ok_or(Fault::StaleGeneration)?;
        if app.queued.is_some() {
            return Ok(false);
        }
        let client = app.client;
        let count = self.core.request_capacity();
        for n in 0..count {
            let index = (self.request_cursor + n) % count;
            let Some(request) = self.core.request_at(index) else {
                continue;
            };
            match self.core.next_work(request) {
                Ok(Work::Close(Destination::Client(c))) if c == client => {
                    self.close_client(client, Fault::Deadline.into(), observe)?;
                    return Ok(true);
                }
                Ok(Work::Client { request, client: c }) if c == client => {
                    // One original callback (including its actual application
                    // decision) per MQ. This bounds retained replies and gives
                    // callback_until one exact immutable original deadline.
                    if self.core.pending_client(client)? {
                        continue;
                    }
                    let (effect, len) =
                        self.core
                            .prepare_client(request, client, &mut self.scratch)?;
                    let frame = match OwnedFrame::copy_from(&self.scratch[..len]) {
                        Ok(f) => f,
                        Err(e) => {
                            self.core.reject_prepared(effect)?;
                            return Err(e.into());
                        }
                    };
                    match self.apps[i]
                        .as_mut()
                        .ok_or(Fault::StaleGeneration)?
                        .io
                        .enqueue_owned(frame, effect, Class::Ordinary)
                    {
                        Ok(()) => {
                            self.core.queued(effect)?;
                            let app = self.apps[i].as_mut().ok_or(Fault::StaleGeneration)?;
                            app.queued = Some(effect);
                            app.written = 0;
                            app.total = len;
                            app.callback_until.get_or_insert(
                                Instant::now()
                                    .checked_add(self.limits.callback_lifetime)
                                    .ok_or(Fault::Overflow)?,
                            );
                            self.request_cursor = (index + 1) % count;
                            observe(Event::Queued(effect));
                            return Ok(true);
                        }
                        Err(rejected) => {
                            self.core.reject_prepared(effect)?;
                            return if matches!(rejected.reason, Fault::Capacity | Fault::WouldBlock)
                            {
                                Ok(false)
                            } else {
                                Err(rejected.reason.into())
                            };
                        }
                    }
                }
                Ok(Work::Retire(_)) => {}
                Err(Fault::WouldBlock) => {}
                Err(e) => return Err(e.into()),
                _ => {}
            }
        }
        Ok(false)
    }
    fn app(
        &mut self,
        cx: &mut Context<'_>,
        i: usize,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        for n in 0..3 {
            let Some(app) = self.apps[i].as_ref() else {
                return Poll::Pending;
            };
            let class = (app.turn + n) % 3;
            let client = app.client;
            let result = match class {
                0 => {
                    if self.apps[i].as_ref().is_none_or(|a| a.queued.is_none()) {
                        Poll::Pending
                    } else {
                        match self.apps[i]
                            .as_mut()
                            .ok_or(Fault::StaleGeneration)?
                            .io
                            .poll_write(cx)
                        {
                            Poll::Pending => Poll::Pending,
                            Poll::Ready(Err(e)) => {
                                self.close_client(client, e.into(), observe)?;
                                Poll::Ready(Ok(Progress::Activity))
                            }
                            Poll::Ready(Ok(p)) => {
                                let effect = self.apps[i]
                                    .as_ref()
                                    .and_then(|a| a.queued)
                                    .ok_or(Fault::Conflict)?;
                                if p.origin != effect {
                                    return Poll::Ready(Err(Fault::StaleGeneration.into()));
                                }
                                let app = self.apps[i].as_mut().ok_or(Fault::StaleGeneration)?;
                                app.written = app
                                    .written
                                    .checked_add(p.bytes)
                                    .filter(|n| *n <= app.total)
                                    .ok_or(Fault::Conflict)?;
                                if p.complete != (app.written == app.total) {
                                    return Poll::Ready(Err(Fault::Conflict.into()));
                                }
                                if p.bytes > 0 {
                                    self.core.exposed(effect)?;
                                }
                                if p.complete {
                                    self.core.written(effect)?;
                                    self.apps[i].as_mut().ok_or(Fault::StaleGeneration)?.queued =
                                        None;
                                    self.report.callbacks_written =
                                        self.report.callbacks_written.saturating_add(1);
                                }
                                self.report.bytes_written =
                                    self.report.bytes_written.saturating_add(p.bytes as u64);
                                observe(Event::Written {
                                    effect,
                                    bytes: p.bytes,
                                    complete: p.complete,
                                });
                                Poll::Ready(Ok(Progress::Activity))
                            }
                        }
                    }
                }
                1 => {
                    if self.queue(i, observe)? {
                        Poll::Ready(Ok(Progress::Activity))
                    } else {
                        Poll::Pending
                    }
                }
                _ => {
                    if self.apps[i]
                        .as_ref()
                        .is_some_and(|a| a.io.frame().is_some())
                    {
                        if self.input(i, observe)? {
                            Poll::Ready(Ok(Progress::Activity))
                        } else {
                            Poll::Pending
                        }
                    } else {
                        match self.apps[i]
                            .as_mut()
                            .ok_or(Fault::StaleGeneration)?
                            .io
                            .poll_read(cx)
                        {
                            Poll::Pending => Poll::Pending,
                            Poll::Ready(Ok(ReadStep::Eof)) => {
                                self.close_client(client, Fault::Closed.into(), observe)?;
                                Poll::Ready(Ok(Progress::Activity))
                            }
                            Poll::Ready(Err(e)) => {
                                self.close_client(client, e.into(), observe)?;
                                Poll::Ready(Ok(Progress::Activity))
                            }
                            Poll::Ready(Ok(ReadStep::Progress { .. })) => {
                                let app = self.apps[i].as_mut().ok_or(Fault::StaleGeneration)?;
                                app.input_until.get_or_insert(
                                    Instant::now()
                                        .checked_add(self.limits.input_lifetime)
                                        .ok_or(Fault::Overflow)?,
                                );
                                Poll::Ready(Ok(Progress::Activity))
                            }
                        }
                    }
                }
            };
            if result.is_ready() {
                if let Some(app) = self.apps[i].as_mut() {
                    app.turn = (class + 1) % 3
                }
                return result;
            }
        }
        Poll::Pending
    }
    /// Immediate no-clock cleanup of every original actual local MQ. Does not stop
    /// helper/resolver owners; Gateway closes those independently.
    pub fn close_all(&mut self, observe: &mut impl FnMut(Event<'id>)) -> Option<Error> {
        self.stopped = true;
        for a in self.apps.iter_mut().flatten() {
            a.io.retire()
        }
        let mut first = None;
        for i in 0..self.apps.len() {
            if let Some(client) = self.apps[i].as_ref().map(|a| a.client)
                && let Err(e) = self.close_client(client, Fault::Closed.into(), observe)
                && first.is_none()
            {
                first = Some(e)
            }
        }
        first
    }
    /// One fair bounded scheduling poll. Dropped waits retain original cursors.
    fn poll_inner(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        until: Option<Instant>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        if self.stopped {
            return Poll::Ready(Ok(Progress::Stopped));
        }
        if let Poll::Ready(progress) = self.poll_native_guard(cx, until, observe) {
            return Poll::Ready(progress);
        }
        let now = match self.now(cx) {
            Ok(n) => n,
            Err(Error::Protocol(Fault::NotReady)) => return Poll::Pending,
            Err(e) => {
                let _cleanup = self.close_all(observe);
                return Poll::Ready(Err(e));
            }
        };
        self.core.expire(now);
        if until.is_some_and(|d| Instant::now() >= d) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        for class in [self.turn, !self.turn] {
            if class {
                for n in 0..self.apps.len() {
                    let i = (self.app_cursor + n) % self.apps.len();
                    if self.apps[i].is_some() {
                        let r = self.app(cx, i, observe);
                        if r.is_ready() {
                            self.app_cursor = (i + 1) % self.apps.len();
                            self.turn = false;
                            return r;
                        }
                    }
                }
            } else if self.accept.ready() && self.apps.iter().any(Option::is_none) {
                for n in 0..listeners.len() {
                    let i = (self.listener_cursor + n) % listeners.len();
                    match listeners[i].poll_canonical_connection(cx) {
                        Poll::Pending => {}
                        Poll::Ready(Err(e)) => {
                            observe(Event::Socket(self.accept.failed(e)));
                            self.listener_cursor = (i + 1) % listeners.len();
                            self.turn = true;
                            return Poll::Ready(Ok(Progress::Activity));
                        }
                        Poll::Ready(Ok(a)) => {
                            self.admit(a, observe)?;
                            self.listener_cursor = (i + 1) % listeners.len();
                            self.turn = true;
                            return Poll::Ready(Ok(Progress::Activity));
                        }
                    }
                }
            }
        }
        let wake = Instant::now()
            .checked_add(self.limits.maintenance)
            .ok_or(Fault::Overflow)?;
        let wake = self
            .apps
            .iter()
            .flatten()
            .flat_map(|a| a.input_until.into_iter().chain(a.callback_until))
            .chain(until)
            .fold(wake, Instant::min);
        self.timer.as_mut().reset(wake);
        if self.timer.as_mut().poll(cx).is_ready() {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
    /// Any fatal original error physically closes all local MQs before returning.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        until: Option<Instant>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        match self.poll_inner(cx, listeners, until, observe) {
            Poll::Ready(Err(e)) => {
                let _cleanup = self.close_all(observe);
                Poll::Ready(Err(e))
            }
            other => other,
        }
    }
}
impl Drop for Server<'_> {
    fn drop(&mut self) {
        for app in self.apps.iter_mut().flatten() {
            app.io.retire();
            let _lost = self.core.client_lost(app.client);
        }
    }
}
