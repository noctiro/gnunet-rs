//! Actual original MQ ownership. A peer's frame/result stays on that physical
//! source; output capacity is preflighted before any actual cache mutation.
use crate::dispatch::{self, Kind};
use gnunet_namecache::{Cache, Stats};
use gnunet_service_runtime::{
    accepted::{AcceptState, AcceptedConnection},
    clock::ClockSubscription,
    framing::{Accounting, Budget, Class, Framed, Limits as FrameLimits, OwnedFrame, ReadStep},
    service::{Listener, PeerAddress, ShutdownMode},
};
use gnunet_types::Error as Fault;
use gnunet_wire::official::{Frame, message_type as mt};
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
mod metrics;
mod types;
pub use metrics::Metrics;
pub use types::*;
#[derive(Clone, Copy)]
struct Origin {
    client: u64,
    write: u64,
    rid: u32,
}
struct Peer {
    client: Client,
    io: Framed<Origin>,
    next_write: u64,
    first: bool,
    first_until: Instant,
    input_until: Option<Instant>,
    output_until: Option<Instant>,
    read_first: bool,
}
/// Caller-driven actual NAMECACHE service with one explicit volatile backend.
/// No constructor spawns an executor, thread, resolver or storage worker.
pub struct Server {
    cache: Cache,
    limits: Limits,
    ports: Ports,
    peers: Vec<Option<Peer>>,
    domain: Rc<Domain>,
    next_client: u64,
    accept: AcceptState,
    subscription: Box<dyn ClockSubscription>,
    revision: u64,
    next_sweep: u64,
    timer: Pin<Box<Sleep>>,
    cursor: usize,
    listener_cursor: usize,
    accept_first: bool,
    shutdown: Option<ShutdownMode>,
    report: Report,
    metrics: Metrics,
    yield_due: bool,
}
impl Limits {
    fn framing(self) -> FrameLimits {
        FrameLimits {
            frame_bytes: self.frame_bytes,
            ordinary: Budget {
                frames: self.output_frames,
                bytes: self.output_bytes,
            },
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: self.io_slice_bytes,
        }
    }
    fn validate(self) -> Result<(), Fault> {
        self.framing().validate()?;
        if self.clients == 0
            || self.clients > 1024
            || self.output_frames > 4096
            || self.frame_bytes < 72
            || self.output_bytes < self.frame_bytes
        {
            return Err(Fault::Capacity);
        }
        self.clients
            .checked_mul(
                self.output_bytes
                    .checked_add(self.frame_bytes)
                    .ok_or(Fault::Overflow)?,
            )
            .ok_or(Fault::Overflow)?;
        for d in [
            self.first_input,
            self.input_lifetime,
            self.output_lifetime,
            self.maintenance_interval,
        ] {
            if d.is_zero()
                || u64::try_from(d.as_micros()).is_err()
                || Instant::now().checked_add(d).is_none()
            {
                return Err(Fault::Deadline);
            }
        }
        Ok(())
    }
}
impl Server {
    /// Consume an actual cache and supplied shared clock/service policy. This
    /// allocates bounded owner metadata but opens no socket or filesystem.
    pub fn new(cache: Cache, limits: Limits, ports: Ports) -> Result<Self, Error> {
        limits.validate()?;
        let subscription = ports.clock.subscribe().map_err(Error::Clock)?;
        let sample = ports.clock.sample().map_err(Error::Clock)?;
        let delay =
            u64::try_from(limits.maintenance_interval.as_micros()).map_err(|_| Fault::Overflow)?;
        let next_sweep = sample
            .now
            .as_micros()
            .checked_add(delay)
            .ok_or(Fault::Overflow)?;
        let mut peers = Vec::new();
        peers
            .try_reserve_exact(limits.clients)
            .map_err(|_| Fault::Capacity)?;
        peers.resize_with(limits.clients, || None);
        Ok(Self {
            cache,
            limits,
            ports,
            peers,
            domain: Rc::new(Domain),
            next_client: 0,
            accept: AcceptState::default(),
            subscription,
            revision: sample.revision,
            next_sweep,
            timer: Box::pin(tokio::time::sleep(Duration::ZERO)),
            cursor: 0,
            listener_cursor: 0,
            accept_first: false,
            shutdown: None,
            report: Report::default(),
            metrics: Metrics::default(),
            yield_due: false,
        })
    }
    /// Actual source counters, without packet or ciphertext dumps.
    pub const fn report(&self) -> Report {
        self.report
    }
    /// Actual volatile allocation/resource summary.
    pub fn cache_stats(&self) -> Stats {
        self.cache.stats()
    }
    /// Actual official handler/callback observations, distinct from cache bytes
    /// and native write totals. Reading never grants a result or mutates state.
    #[must_use]
    pub const fn metrics(&self) -> Metrics {
        self.metrics
    }
    /// Canonical acceptance and access checks precede frame allocation. A fault
    /// on this unadmitted source never closes another source or mutates cache.
    pub fn admit(
        &mut self,
        accepted: AcceptedConnection,
        observe: &mut impl FnMut(Event),
    ) -> Result<Option<Client>, Error> {
        let (connection, address, diagnostics) = accepted.into_parts();
        for d in diagnostics {
            observe(Event::Socket(
                gnunet_service_runtime::accepted::SocketEvent::Diagnostic(d),
            ));
        }
        let allowed = match address {
            PeerAddress::Tcp(p) => self.ports.options.access.allows(p.ip()),
            PeerAddress::Unix => match self.ports.unix.allows(&connection) {
                Ok(v) => v,
                Err(error) => {
                    drop(connection);
                    observe(Event::AdmissionIo { address, error });
                    return Ok(None);
                }
            },
        };
        if !allowed {
            drop(connection);
            observe(Event::Rejected(address));
            return Ok(None);
        }
        let attempt = (|| -> Result<_, Fault> {
            if self.shutdown.is_some() {
                return Err(Fault::Closed);
            }
            let index = self
                .peers
                .iter()
                .position(Option::is_none)
                .ok_or(Fault::Capacity)?;
            let first_until = Instant::now()
                .checked_add(self.limits.first_input)
                .ok_or(Fault::Overflow)?;
            let serial = self.next_client.checked_add(1).ok_or(Fault::Overflow)?;
            Ok((index, first_until, serial))
        })();
        let (index, first_until, serial) = match attempt {
            Ok(v) => v,
            Err(reason) => {
                drop(connection);
                observe(Event::AdmissionFault { address, reason });
                return Ok(None);
            }
        };
        let io = match Framed::new(connection, self.limits.framing()) {
            Ok(io) => io,
            Err(reason) => {
                observe(Event::AdmissionFault { address, reason });
                return Ok(None);
            }
        };
        let client = Client {
            domain: Rc::clone(&self.domain),
            serial,
        };
        self.next_client = serial;
        self.peers[index] = Some(Peer {
            client: client.clone(),
            io,
            next_write: 0,
            first: true,
            first_until,
            input_until: None,
            output_until: None,
            read_first: false,
        });
        self.report.accepted = self.report.accepted.saturating_add(1);
        observe(Event::Accepted(client.clone()));
        Ok(Some(client))
    }
    fn close_index(&mut self, index: usize, cause: CloseCause, observe: &mut impl FnMut(Event)) {
        if let Some(mut peer) = self.peers[index].take() {
            peer.io.retire();
            self.accept.client_closed();
            self.report.closed = self.report.closed.saturating_add(1);
            observe(Event::Closed {
                client: peer.client,
                cause,
            });
        }
    }
    /// Physically retire only this original source, without a cache rollback or
    /// invented cancel frame. Already committed memory effects remain actual.
    pub fn close(&mut self, client: &Client, observe: &mut impl FnMut(Event)) -> Result<(), Error> {
        let i = self
            .peers
            .iter()
            .position(|p| p.as_ref().is_some_and(|p| p.client == *client))
            .ok_or(Fault::Stale)?;
        self.close_index(i, CloseCause::Shutdown, observe);
        Ok(())
    }
    /// Stop original sockets independently of clock/Resolver availability.
    pub fn close_all(&mut self, observe: &mut impl FnMut(Event)) {
        self.shutdown = Some(ShutdownMode::Immediate);
        for i in 0..self.peers.len() {
            self.close_index(i, CloseCause::Shutdown, observe);
        }
    }
    /// Stop new admission. Soft drains already complete input and retained FIFO
    /// output; it does not read a new request or prolong the caller's grace.
    pub fn request_shutdown(&mut self, mode: ShutdownMode) {
        if self.shutdown != Some(ShutdownMode::Immediate) {
            self.shutdown = Some(mode);
        }
    }
    fn release(peer: &mut Peer) -> Result<(), Fault> {
        if !peer.io.release_frame() {
            return Err(Fault::Stale);
        }
        peer.input_until = None;
        Ok(())
    }
    fn process(&mut self, i: usize, observe: &mut impl FnMut(Event)) -> Result<bool, Fault> {
        let peer = self.peers[i].as_ref().ok_or(Fault::Stale)?;
        let input = peer.io.frame().ok_or(Fault::NotReady)?;
        let message = Frame::decode(input)?.header().message_type();
        let known = matches!(
            message,
            mt::NAMECACHE_LOOKUP_BLOCK | mt::NAMECACHE_BLOCK_CACHE | mt::NAMECACHE_BLOCK_DELETE
        );
        if !known {
            if !self.ports.options.tolerant {
                return Err(Fault::Unsupported);
            }
            Self::release(self.peers[i].as_mut().ok_or(Fault::Stale)?)?;
            return Ok(true);
        }
        let size = dispatch::response_size(&self.cache, input)?;
        let peer = self.peers[i].as_mut().ok_or(Fault::Stale)?;
        if !peer.io.capacity(size, Class::Ordinary) {
            return Ok(false);
        }
        // Both metadata and final frame storage are ready before actual effect.
        match peer.io.reserve(size, Class::Ordinary) {
            Ok(()) => {}
            Err(Fault::Capacity | Fault::WouldBlock) => return Ok(false),
            Err(e) => return Err(e),
        }
        let mut bytes = match dispatch::allocate(size) {
            Ok(bytes) => bytes,
            Err(Fault::Capacity) => return Ok(false),
            Err(e) => return Err(e),
        };
        let write = peer.next_write.checked_add(1).ok_or(Fault::Overflow)?;
        let output_until = match peer.output_until {
            Some(until) => until,
            None => Instant::now()
                .checked_add(self.limits.output_lifetime)
                .ok_or(Fault::Overflow)?,
        };
        let metrics = &mut self.metrics;
        let applied = dispatch::apply_observed(
            &mut self.cache,
            peer.io.frame().ok_or(Fault::NotReady)?,
            &mut bytes,
            |event| metrics.observe(event),
        )?;
        self.report.handled = self.report.handled.saturating_add(1);
        if let Some(result) = applied.result {
            observe(Event::Result {
                client: peer.client.clone(),
                rid: applied.rid,
                delete: applied.kind == Kind::Delete,
                result,
            });
        }
        if applied.size != size {
            return Err(Fault::Stale);
        }
        // No other peer, callback or native poll can alter this queue between
        // reserve and enqueue. A terminal internal failure closes only this MQ;
        // the already actual memory effect is never retried or moved elsewhere.
        peer.io
            .enqueue_owned(
                OwnedFrame::new(bytes),
                Origin {
                    client: peer.client.serial,
                    write,
                    rid: applied.rid,
                },
                Class::Ordinary,
            )
            .map_err(|e| e.reason)?;
        peer.next_write = write;
        peer.output_until = Some(output_until);
        Self::release(peer)?;
        observe(Event::Queued {
            client: peer.client.clone(),
            rid: applied.rid,
            write,
        });
        Ok(true)
    }
    fn read_peer(
        &mut self,
        cx: &mut Context<'_>,
        i: usize,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        if self.peers[i]
            .as_ref()
            .is_some_and(|p| p.io.frame().is_some())
        {
            return match self.process(i, observe) {
                Ok(true) => Poll::Ready(Ok(Progress::Activity)),
                Ok(false) => Poll::Pending,
                Err(e) => {
                    self.close_index(i, CloseCause::Protocol(e), observe);
                    Poll::Ready(Ok(Progress::Activity))
                }
            };
        }
        if self.shutdown.is_some() {
            return Poll::Pending;
        }
        match self.peers[i].as_mut().ok_or(Fault::Stale)?.io.poll_read(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => {
                self.close_index(i, CloseCause::Io(e), observe);
                Poll::Ready(Ok(Progress::Activity))
            }
            Poll::Ready(Ok(ReadStep::Eof)) => {
                self.close_index(i, CloseCause::Eof, observe);
                Poll::Ready(Ok(Progress::Activity))
            }
            Poll::Ready(Ok(ReadStep::Progress { complete, .. })) => {
                let peer = self.peers[i].as_mut().ok_or(Fault::Stale)?;
                if complete {
                    peer.first = false;
                }
                if peer.input_until.is_none() {
                    peer.input_until = Some(
                        Instant::now()
                            .checked_add(self.limits.input_lifetime)
                            .ok_or(Fault::Overflow)?,
                    );
                }
                Poll::Ready(Ok(Progress::Activity))
            }
        }
    }
    fn write_peer(
        &mut self,
        cx: &mut Context<'_>,
        i: usize,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        match self.peers[i]
            .as_mut()
            .ok_or(Fault::Stale)?
            .io
            .poll_write(cx)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => {
                self.close_index(i, CloseCause::Io(e), observe);
                Poll::Ready(Ok(Progress::Activity))
            }
            Poll::Ready(Ok(progress)) => {
                let peer = self.peers[i].as_mut().ok_or(Fault::Stale)?;
                if progress.origin.client != peer.client.serial {
                    self.close_index(i, CloseCause::Protocol(Fault::Stale), observe);
                    return Poll::Ready(Ok(Progress::Activity));
                }
                if progress.complete {
                    self.report.written = self.report.written.saturating_add(1);
                    observe(Event::Written {
                        client: peer.client.clone(),
                        rid: progress.origin.rid,
                        write: progress.origin.write,
                    });
                }
                if peer.io.queued_frames() == 0 {
                    peer.output_until = None;
                }
                Poll::Ready(Ok(Progress::Activity))
            }
        }
    }
    fn peer(
        &mut self,
        cx: &mut Context<'_>,
        i: usize,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        let now = Instant::now();
        let peer = self.peers[i].as_ref().ok_or(Fault::Stale)?;
        if peer.first && now >= peer.first_until
            || peer.input_until.is_some_and(|t| now >= t)
            || peer.output_until.is_some_and(|t| now >= t)
        {
            self.close_index(i, CloseCause::Deadline, observe);
            return Poll::Ready(Ok(Progress::Activity));
        }
        if self.shutdown.is_some() && peer.io.frame().is_none() && peer.io.queued_frames() == 0 {
            self.close_index(i, CloseCause::Shutdown, observe);
            return Poll::Ready(Ok(Progress::Activity));
        }
        let read_first = peer.read_first;
        for direction in 0..2 {
            let reading = (direction == 0) == read_first;
            let step = if reading {
                self.read_peer(cx, i, observe)
            } else {
                self.write_peer(cx, i, observe)
            };
            if step.is_ready() {
                if let Some(peer) = self.peers[i].as_mut() {
                    peer.read_first = !reading;
                }
                return step;
            }
        }
        Poll::Pending
    }
    fn accept(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        if self.shutdown.is_some() || !self.accept.ready() || self.peers.iter().all(Option::is_some)
        {
            return Poll::Pending;
        }
        for n in 0..listeners.len() {
            let i = (self.listener_cursor + n) % listeners.len();
            match listeners[i].poll_canonical_connection(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(e)) => {
                    observe(Event::Socket(self.accept.failed(e)));
                    self.listener_cursor = (i + 1) % listeners.len();
                    return Poll::Ready(Ok(Progress::Activity));
                }
                Poll::Ready(Ok(a)) => {
                    self.listener_cursor = (i + 1) % listeners.len();
                    self.admit(a, observe)?;
                    return Poll::Ready(Ok(Progress::Activity));
                }
            }
        }
        Poll::Pending
    }
    fn poll_inner(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        until: Option<Instant>,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        if self.shutdown == Some(ShutdownMode::Immediate) {
            self.close_all(observe);
        }
        if self.shutdown.is_some() && self.peers.iter().all(Option::is_none) {
            return Poll::Ready(Ok(Progress::Stopped));
        }
        if until.is_some_and(|u| Instant::now() >= u) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        match self.subscription.poll_changed(cx, self.revision) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(Error::Clock(e))),
            Poll::Ready(Ok(s)) => self.revision = s.revision,
            Poll::Pending => {}
        }
        let sample = self.ports.clock.sample().map_err(Error::Clock)?;
        self.revision = sample.revision;
        match self.subscription.poll_changed(cx, sample.revision) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(Error::Clock(e))),
            Poll::Ready(Ok(_)) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Pending => {}
        }
        if sample.now.as_micros() >= self.next_sweep {
            let count = self.cache.expire_before(sample.now);
            let delay = u64::try_from(self.limits.maintenance_interval.as_micros())
                .map_err(|_| Fault::Overflow)?;
            self.next_sweep = sample
                .now
                .as_micros()
                .checked_add(delay)
                .ok_or(Fault::Overflow)?;
            self.report.expired = self
                .report
                .expired
                .saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
            if count != 0 {
                observe(Event::Expired { count });
            }
            return Poll::Ready(Ok(Progress::Activity));
        }
        for direction in 0..2 {
            let accepting = (direction == 0) == self.accept_first;
            let mut result = if accepting {
                self.accept(cx, listeners, observe)
            } else {
                Poll::Pending
            };
            if !accepting {
                for n in 0..self.peers.len() {
                    let i = (self.cursor + n) % self.peers.len();
                    if self.peers[i].is_some() {
                        let step = self.peer(cx, i, observe);
                        if step.is_ready() {
                            self.cursor = (i + 1) % self.peers.len();
                            result = step;
                            break;
                        }
                    }
                }
            }
            if result.is_ready() {
                self.accept_first = !accepting;
                return result;
            }
        }
        let logical_due = Instant::now()
            .checked_add(Duration::from_micros(
                self.next_sweep - sample.now.as_micros(),
            ))
            .ok_or(Fault::Overflow)?;
        let mut target = until.map_or(logical_due, |u| u.min(logical_due));
        for p in self.peers.iter().flatten() {
            for due in p
                .first
                .then_some(p.first_until)
                .into_iter()
                .chain(p.input_until)
                .chain(p.output_until)
            {
                target = target.min(due);
            }
        }
        self.timer.as_mut().reset(target);
        if self.timer.as_mut().poll(cx).is_ready() {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
    /// One cancellation-safe bounded turn. Source errors physically close only
    /// that source. A shared clock failure is a process-port failure: all sources
    /// close independently before the original error reaches the foreground.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        until: Option<Instant>,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        if self.yield_due {
            self.yield_due = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let result = self.poll_inner(cx, listeners, until, observe);
        if matches!(&result, Poll::Ready(Err(_))) {
            self.close_all(observe);
        }
        if matches!(&result, Poll::Ready(Ok(Progress::Activity))) {
            self.yield_due = true;
        }
        result
    }
    /// Wait by polling this same owner. Dropping the future retains original
    /// RX/TX cursors and hard deadlines, without replay or source replacement.
    pub async fn drive(
        &mut self,
        listeners: &[Listener<'_>],
        until: Option<Instant>,
        mut observe: impl FnMut(Event),
    ) -> Result<Progress, Error> {
        poll_fn(|cx| self.poll(cx, listeners, until, &mut observe)).await
    }
    /// Independently close all physical sources and return actual volatile state
    /// counters. No storage worker, filesystem flush, fsync or disk join is claimed.
    pub fn shutdown(&mut self, mut observe: impl FnMut(Event)) -> Shutdown {
        self.close_all(&mut observe);
        Shutdown {
            report: self.report,
            cache: self.cache.stats(),
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.close_all(&mut |_| {});
    }
}
