//! Actual bounded app IPC and official CADET CLIENT scheduling; all partial
//! bodies stay with their original native owner across cancelled waiting futures.
use gnunet_cadet_host as cadet;
use gnunet_service_runtime::{
    accepted::{AcceptState, AcceptedConnection, SocketEvent},
    clock::{Deadline, RuntimeClock},
    credentials::UnixAccess,
    framing::{Accounting, Budget, Class, Framed, Limits as FrameLimits, OwnedFrame, ReadStep},
    service::{Listener, PeerAddress, ServiceOptions, ShutdownMode},
};
use gnunet_setu::{
    service::{Client as CoreClient, Effect, Operation, Service},
    union::Transmission,
    zlib::Zlib,
};
use gnunet_types::Error as Fault;
use gnunet_wire::official::{
    Frame, MessageHeader, cadet::MAX_APPLICATION_MESSAGE_SIZE, message_type as mt,
};
use std::{
    collections::VecDeque,
    fmt,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
mod types;
pub use types::{CloseCause, Error, Event, Limits, Progress, Report, Shutdown};
mod apps;
mod peers;
struct App {
    client: CoreClient,
    io: Framed<u64>,
    held: Option<(OwnedFrame, u64, Instant)>,
    writes: VecDeque<(u64, Instant)>,
    cursor: usize,
    read_hard: Option<Instant>,
}
struct Bound<'id> {
    client: CoreClient,
    app: [u8; 64],
    port: Option<cadet::Port<'id>>,
    ready: bool,
    closing: bool,
    hard: Option<Instant>,
}
struct Input<'id> {
    packet: cadet::Received<'id>,
    at: usize,
}
struct Peer<'id> {
    channel: cadet::Channel<'id>,
    operation: Option<Operation>,
    listener: Option<CoreClient>,
    expires: u64,
    opening: bool,
    closing: bool,
    remote_closed: bool,
    hard: Option<Instant>,
    send: Option<(Transmission, OwnedFrame)>,
    input: Option<Input<'id>>,
}
enum Action<'id> {
    Open(cadet::Channel<'id>),
    PortOpen(cadet::Port<'id>),
    PortClose(cadet::Port<'id>),
    Send {
        channel: cadet::Channel<'id>,
        operation: Operation,
        transmission: Transmission,
    },
    Destroy(cadet::Channel<'id>),
    Ack(cadet::Channel<'id>),
    Internal,
}
struct Opening {
    operation: Operation,
    peer: [u8; 32],
    app: [u8; 64],
}
struct Pending<'id> {
    transmit: cadet::Transmit<'id>,
    action: Action<'id>,
    hard: Instant,
}
/// One actual service and exactly one shared CADET MQ. Slot/Instance storage is
/// explicitly borrowed from its foreground; neither self-reference nor thread is hidden.
pub struct Server<'id, 'slots> {
    core: Service,
    cadet: cadet::Client<'id, 'slots>,
    codec: Zlib,
    apps: Vec<Option<App>>,
    ports: Vec<Option<Bound<'id>>>,
    peers: Vec<Option<Peer<'id>>>,
    opens: Vec<Option<Opening>>,
    pending: Option<Pending<'id>>,
    read_hard: Option<Instant>,
    limits: Limits,
    options: ServiceOptions,
    unix: UnixAccess,
    accept: AcceptState,
    clock: Arc<dyn RuntimeClock>,
    logical: Option<(u64, Deadline)>,
    timer: Pin<Box<Sleep>>,
    next_output: u64,
    cursor: usize,
    peer_cursor: usize,
    class: usize,
    listener_cursor: usize,
    shutdown: Option<ShutdownMode>,
    stopped: bool,
    report: Report,
}
fn slots<T>(n: usize) -> Result<Vec<Option<T>>, Fault> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Fault::Capacity)?;
    v.resize_with(n, || None);
    Ok(v)
}
fn buffer(n: usize) -> Result<Vec<u8>, Fault> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Fault::Capacity)?;
    v.resize(n, 0);
    Ok(v)
}
fn retry(e: &cadet::Error) -> bool {
    matches!(
        e,
        cadet::Error::Protocol(Fault::WouldBlock | Fault::Capacity | Fault::NotReady)
    )
}
impl<'id, 'slots> Server<'id, 'slots> {
    /// Own one pure service and one real original CADET client. Creates no socket,
    /// listener, thread or persistence job; the endpoint's canonical clock is shared.
    pub fn new(
        core: Service,
        cadet: cadet::Client<'id, 'slots>,
        limits: Limits,
        options: ServiceOptions,
        unix: UnixAccess,
    ) -> Result<Self, Error> {
        limits.validate()?;
        let clock = cadet.clock();
        Ok(Self {
            core,
            cadet,
            codec: Zlib::new(),
            apps: slots(limits.clients)?,
            ports: slots(limits.ports)?,
            peers: slots(limits.channels)?,
            opens: slots(limits.channels)?,
            pending: None,
            read_hard: None,
            limits,
            options,
            unix,
            accept: AcceptState::default(),
            clock,
            logical: None,
            timer: Box::pin(tokio::time::sleep(Duration::ZERO)),
            next_output: 0,
            cursor: 0,
            peer_cursor: 0,
            class: 0,
            listener_cursor: 0,
            shutdown: None,
            stopped: false,
            report: Report::default(),
        })
    }
    /// Borrow actual canonical clock without allocating a listener.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    /// Actual current local counters, without remote-receipt claims.
    #[must_use]
    pub const fn report(&self) -> Report {
        self.report
    }
    fn now(&self) -> Result<u64, Error> {
        Ok(self.clock.sample()?.now.as_micros())
    }
    fn expires(&self, now: u64) -> Result<u64, Error> {
        let us = u64::try_from(self.limits.operation_lifetime.as_micros())
            .map_err(|_| Fault::Overflow)?;
        let target = now.checked_add(us).ok_or(Fault::Overflow)?;
        if target == u64::MAX {
            return Err(Fault::Overflow.into());
        }
        Ok(target)
    }
    fn hard(&self) -> Result<Instant, Error> {
        Instant::now()
            .checked_add(self.limits.retirement_grace)
            .ok_or(Fault::Overflow.into())
    }
    fn framing(&self) -> FrameLimits {
        FrameLimits {
            frame_bytes: self.limits.frame_bytes,
            ordinary: Budget {
                frames: self.limits.output_frames,
                bytes: self.limits.output_bytes,
            },
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: self.limits.io_slice_bytes,
        }
    }
    fn peer_index(&self, channel: cadet::Channel<'id>) -> Option<usize> {
        self.peers
            .iter()
            .position(|p| p.as_ref().is_some_and(|p| p.channel == channel))
    }
    fn op_index(&self, operation: &Operation) -> Option<usize> {
        self.peers.iter().position(|p| {
            p.as_ref()
                .is_some_and(|p| p.operation.as_ref() == Some(operation))
        })
    }
    fn mark_close(&mut self, index: usize) -> Result<(), Error> {
        let hard = self.hard()?;
        let p = self.peers[index].as_mut().ok_or(Fault::Stale)?;
        p.closing = true;
        p.hard.get_or_insert(hard);
        p.send = None;
        // Local cancellation/failure/close revokes unprocessed input now. A
        // later remote Destroyed cannot make that abandoned packet live again.
        p.input = None;
        Ok(())
    }
    fn finish_peer(&mut self, index: usize) -> Result<(), Error> {
        let p = self.peers[index].take().ok_or(Fault::Stale)?;
        if let Some(operation) = p.operation {
            self.core.retired(&operation)?;
        }
        Ok(())
    }
    /// Stop accepting immediately. Soft lifetime waits for actual app owners to
    /// disconnect; the foreground must still enforce its finite shutdown grace.
    pub fn request_shutdown(&mut self, mode: ShutdownMode) {
        if self.shutdown != Some(ShutdownMode::Immediate) {
            self.shutdown = Some(mode);
        }
        if mode == ShutdownMode::Immediate {
            self.core.shutdown();
        }
    }
    /// Synchronously physically close all original app sockets and the one CADET
    /// MQ before consuming their pure retirement callbacks. Does not depend on a
    /// working clock, peer, credit, partial suffix, Resolver or another poll.
    pub fn shutdown(&mut self, mut observe: impl FnMut(Event<'id>)) -> Shutdown {
        self.shutdown = Some(ShutdownMode::Immediate);
        self.core.shutdown();
        let mut failure = None;
        for i in 0..self.apps.len() {
            if self.apps[i].is_some()
                && let Err(e) = self.stop_app(i, CloseCause::Shutdown, &mut observe)
                && failure.is_none()
            {
                failure = Some(e)
            }
        }
        // Physical MQ close comes before dropping pending partial frame metadata.
        match self.cadet.close() {
            Ok(Some(report)) => {
                self.report.cadet_losses = self.report.cadet_losses.saturating_add(1);
                observe(Event::CadetLost {
                    report,
                    cause: cadet::LossCause::Requested,
                });
            }
            Ok(None) => {}
            Err(e) => {
                if failure.is_none() {
                    failure = Some(e.into());
                }
            }
        }
        self.pending = None;
        self.read_hard = None;
        for i in 0..self.peers.len() {
            if self.peers[i].is_some()
                && let Err(e) = self.finish_peer(i)
                && failure.is_none()
            {
                failure = Some(e)
            }
        }
        for i in 0..self.opens.len() {
            if let Some(open) = self.opens[i].take()
                && let Err(e) = self.core.retired(&open.operation)
                && failure.is_none()
            {
                failure = Some(e.into())
            }
        }
        for i in 0..self.ports.len() {
            if self.ports[i].as_ref().is_some_and(|bound| bound.closing) {
                let Some(bound) = self.ports[i].take() else {
                    continue;
                };
                if let Err(e) = self.core.listener_closed(&bound.client)
                    && failure.is_none()
                {
                    failure = Some(e.into())
                }
            }
        }
        self.consume_shutdown_effects(&mut observe, &mut failure);
        self.ports.iter_mut().for_each(|bound| *bound = None);
        self.logical = None;
        if !self.core.is_quiescent() && failure.is_none() {
            failure = Some(Fault::NotReady.into());
        }
        self.stopped = true;
        Shutdown {
            report: self.report,
            failure,
        }
    }
    fn consume_shutdown_effects(
        &mut self,
        observe: &mut impl FnMut(Event<'id>),
        failure: &mut Option<Error>,
    ) {
        // Bounds are original metadata capacities, not an unbounded shutdown loop.
        for _ in 0..self
            .limits
            .clients
            .saturating_add(self.limits.ports)
            .saturating_add(self.limits.channels)
            .saturating_mul(4)
        {
            let Some(effect) = self.core.next_effect() else {
                break;
            };
            let result = match effect {
                Effect::Close { operation } => self.core.retired(&operation),
                Effect::Unlisten { client, .. } => {
                    for slot in &mut self.ports {
                        if slot.as_ref().is_some_and(|bound| bound.client == client) {
                            *slot = None;
                        }
                    }
                    self.core.listener_closed(&client)
                }
                Effect::Listen { client, .. } => {
                    self.core.listener_ready(&client, Err(Fault::Closed))
                }
                Effect::Open { operation, .. } => {
                    self.core.connect_failed(&operation, Fault::Closed)
                }
                Effect::CloseClient { client, .. } => self.core.client_closed(&client),
                Effect::Send { operation, .. } => {
                    observe(Event::Refused {
                        operation: Some(operation.clone()),
                        error: Fault::Closed,
                    });
                    self.core.abort(&operation, Fault::Closed)
                }
            };
            if let Err(e) = result
                && e != Fault::Stale
                && failure.is_none()
            {
                *failure = Some(e.into())
            }
        }
    }
    fn accept(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        if self.shutdown.is_some() || !self.accept.ready() || self.apps.iter().all(Option::is_some)
        {
            return Poll::Pending;
        }
        for n in 0..listeners.len() {
            let i = (self.listener_cursor + n) % listeners.len();
            match listeners[i].poll_canonical_connection(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(e)) => {
                    self.listener_cursor = (i + 1) % listeners.len();
                    observe(Event::Socket(self.accept.failed(e)));
                    return Poll::Ready(Ok(Progress::Activity));
                }
                Poll::Ready(Ok(a)) => {
                    self.listener_cursor = (i + 1) % listeners.len();
                    if let Err(e) = self.admit(a, observe) {
                        observe(Event::AdmissionFailed(e));
                    }
                    return Poll::Ready(Ok(Progress::Activity));
                }
            }
        }
        Poll::Pending
    }
    fn deadlines(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        let target = self
            .core
            .next_deadline()
            .into_iter()
            .chain(
                self.peers
                    .iter()
                    .flatten()
                    .filter(|p| p.operation.is_none() && !p.closing)
                    .map(|p| p.expires),
            )
            .min();
        if target != self.logical.as_ref().map(|(at, _)| *at) {
            self.logical = target
                .map(|target| {
                    Deadline::at(
                        self.clock.clone(),
                        gnunet_types::AbsoluteTime::from_micros(target),
                    )
                    .map(|d| (target, d))
                })
                .transpose()?;
        }
        if let Some((_, deadline)) = &mut self.logical {
            match Pin::new(deadline).poll(cx) {
                Poll::Pending => {}
                Poll::Ready(result) => {
                    result?;
                    self.logical = None;
                    let now = self.now()?;
                    self.core.expire(now);
                    for i in 0..self.peers.len() {
                        if self.peers[i].as_ref().is_some_and(|p| {
                            p.operation.is_none() && !p.closing && now >= p.expires
                        }) {
                            self.mark_close(i)?;
                        }
                    }
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
    fn hard_limits(&mut self, observe: &mut impl FnMut(Event<'id>)) -> Result<bool, Error> {
        let now = Instant::now();
        for i in 0..self.apps.len() {
            if self.apps[i].as_ref().is_some_and(|a| {
                a.writes.front().is_some_and(|(_, d)| now >= *d)
                    || a.held.as_ref().is_some_and(|(_, _, d)| now >= *d)
                    || a.read_hard.is_some_and(|d| now >= d)
            }) {
                self.stop_app(i, CloseCause::Deadline, observe)?;
                return Ok(true);
            }
        }
        if self.read_hard.is_some_and(|d| now >= d)
            || self.pending.as_ref().is_some_and(|p| now >= p.hard)
            || self
                .peers
                .iter()
                .flatten()
                .any(|p| p.hard.is_some_and(|d| now >= d))
            || self
                .ports
                .iter()
                .flatten()
                .any(|p| p.hard.is_some_and(|d| now >= d))
        {
            // Shared native frame cannot be spliced or transferred to a new MQ.
            // Reset physically closes that original MQ before loss callbacks.
            if self.cadet.epoch().is_some() {
                let event = self.cadet.reconnect()?;
                self.native_event(event, observe)?;
                return Ok(true);
            }
            // Already detached old MQ has no live channel bytes to drain.
            for i in 0..self.peers.len() {
                if self.peers[i].is_some() {
                    self.finish_peer(i)?;
                }
            }
            return self.retire_closed_ports();
        }
        Ok(false)
    }
    fn arm_timer(&mut self, cx: &mut Context<'_>, deadline: Option<Instant>) {
        let at = deadline
            .into_iter()
            .chain(self.read_hard)
            .chain(self.pending.iter().map(|p| p.hard))
            .chain(self.peers.iter().flatten().filter_map(|p| p.hard))
            .chain(self.ports.iter().flatten().filter_map(|p| p.hard))
            .chain(self.apps.iter().flatten().flat_map(|a| {
                a.writes
                    .front()
                    .map(|(_, d)| *d)
                    .into_iter()
                    .chain(a.held.as_ref().map(|(_, _, d)| *d))
                    .chain(a.read_hard)
            }))
            .min();
        if let Some(at) = at {
            self.timer.as_mut().reset(at);
            if self.timer.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
    }
    /// Poll bounded fair app/CADET/effect/algorithm work without hidden tasks.
    /// Original partial streams, leases and received DATA survive cancelled waits.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        deadline: Option<Instant>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        if self.stopped {
            return Poll::Ready(Ok(Progress::Stopped));
        }
        if deadline.is_some_and(|at| Instant::now() >= at) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        if self.hard_limits(observe)? || self.deadlines(cx)? {
            return Poll::Ready(Ok(Progress::Activity));
        }
        if self.shutdown.is_some()
            && self.apps.iter().all(Option::is_none)
            && self.peers.iter().all(Option::is_none)
            && self.opens.iter().all(Option::is_none)
            && self.ports.iter().all(Option::is_none)
        {
            let stopped = self.shutdown(&mut *observe);
            return Poll::Ready(match stopped.failure {
                Some(e) => Err(e),
                None => Ok(Progress::Stopped),
            });
        }
        for n in 0..7 {
            let class = (self.class + n) % 7;
            let result = match class {
                0 => self.poll_apps(cx, observe),
                1 => self.poll_cadet(cx, observe),
                2 => {
                    if self.effect(observe)? {
                        Poll::Ready(Ok(Progress::Activity))
                    } else {
                        Poll::Pending
                    }
                }
                3 => {
                    if self.peer_work(observe)? {
                        Poll::Ready(Ok(Progress::Activity))
                    } else {
                        Poll::Pending
                    }
                }
                4 => {
                    if self.results(observe)? {
                        Poll::Ready(Ok(Progress::Activity))
                    } else {
                        Poll::Pending
                    }
                }
                5 => {
                    if self.core.advance(&mut self.codec, 1)? > 0 {
                        Poll::Ready(Ok(Progress::Activity))
                    } else {
                        Poll::Pending
                    }
                }
                _ => self.accept(cx, listeners, observe),
            };
            if result.is_ready() {
                self.class = (class + 1) % 7;
                return result;
            }
        }
        self.arm_timer(cx, deadline);
        Poll::Pending
    }
    /// Caller-driven cancellation-safe observation. No background task is spawned.
    pub async fn drive(
        &mut self,
        listeners: &[Listener<'_>],
        deadline: Option<Instant>,
        mut observe: impl FnMut(Event<'id>),
    ) -> Result<Progress, Error> {
        poll_fn(|cx| self.poll(cx, listeners, deadline, &mut observe)).await
    }
}
impl Drop for Server<'_, '_> {
    fn drop(&mut self) {
        let _closed = self.shutdown(|_| {});
    }
}
