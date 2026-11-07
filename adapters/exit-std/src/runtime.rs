//! Original actual CADET/TUN/literal-DNS reactor, with no hidden task/thread.
use gnunet_cadet_host as cadet;
use gnunet_exit::{
    engine::{self as core, Engine, Flow, Input, Source, Target, Tun, Write},
    nat::Entropy,
};
use gnunet_service_runtime::{clock::RuntimeClock, framing::OwnedFrame};
use gnunet_tun_host as tun;
use gnunet_types::{Error as Fault, MonoInstant};
use gnunet_wire::official::Frame;
use std::{
    fmt,
    future::{Future, poll_fn},
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    time::{Instant, Sleep},
};
mod types;
pub use types::{
    Binding, BindingStatus, BuildFailure, Error, Event, Limits, OsEntropy, Parts, Progress, Report,
    Resolver, Shutdown,
};
mod admin;
mod packet_source;
pub use packet_source::PacketSource;
mod device;
mod dns;
mod peers;
struct Port<'id> {
    binding: Binding,
    port: Option<cadet::Port<'id>>,
    disabled: bool,
}
struct Outer<'id> {
    packet: cadet::Received<'id>,
    // Captured at actual DATA admission, used only for draining a gone peer.
    expires: MonoInstant,
    until: Instant,
    at: usize,
    next: usize,
    pending: Option<Input>,
    ready: bool,
    receipts: Vec<Input>,
}
struct Peer<'id> {
    channel: cadet::Channel<'id>,
    flow: Option<Flow>,
    input: Option<Outer<'id>>,
    closing: bool,
    remote_closed: bool,
    hard: Option<Instant>,
    first: Option<Instant>,
}
enum Action<'id> {
    PortOpen,
    PortClose(usize),
    Data {
        channel: cadet::Channel<'id>,
        write: Write,
    },
    Ack {
        channel: cadet::Channel<'id>,
        receipts: Vec<Input>,
    },
    Destroy(cadet::Channel<'id>),
    Internal,
}
struct Pending<'id> {
    transmit: cadet::Transmit<'id>,
    action: Action<'id>,
    hard: Instant,
}
struct Held {
    flow: Flow,
    write: Write,
    until: Instant,
}
struct TunPending {
    native: tun::WriteId,
    write: Write,
    flow: Flow,
}
struct TunInput {
    packet: tun::Received,
    until: Instant,
}
struct DnsJob {
    job: core::Dns,
    flow: Flow,
    query: OwnedFrame,
    question: Vec<u8>,
    socket: Option<UdpSocket>,
    until: Instant,
    expires: MonoInstant,
    next_send: Instant,
    written: bool,
    response: Option<Vec<u8>>,
}
/// Actual production runtime over one explicit CADET client, one native/helper
/// packet source and bounded original DNS sockets. Caller retains borrowed CADET slot storage.
pub struct Driver<'cfg, 'id, 'slots, E: Entropy> {
    engine: Engine<'cfg>,
    cadet: cadet::Client<'id, 'slots>,
    tun: Option<PacketSource>,
    retiring_tun: Option<PacketSource>,
    tun_epoch: Option<tun::Epoch>,
    core_tun: Option<Tun>,
    source: Option<(cadet::Epoch<'id>, Source)>,
    ports: Vec<Port<'id>>,
    peers: Vec<Option<Peer<'id>>>,
    pending: Option<Pending<'id>>,
    peer_held: Option<Held>,
    tun_held: Option<Held>,
    tun_pending: Option<TunPending>,
    tun_input: Option<TunInput>,
    dns_jobs: Vec<Option<DnsJob>>,
    dns_buffer: Vec<u8>,
    resolver: Option<Resolver>,
    limits: Limits,
    entropy: E,
    clock: Arc<dyn RuntimeClock>,
    anchor: Instant,
    last_clock: Option<u64>,
    flow_timer: Option<(u64, Pin<Box<Sleep>>)>,
    timer: Pin<Box<Sleep>>,
    read_hard: Option<Instant>,
    class: usize,
    cursor: usize,
    dns_cursor: usize,
    stopping: bool,
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
        cadet::Error::Protocol(Fault::WouldBlock | Fault::NotReady)
    )
}
impl<'cfg, 'id, 'slots, E: Entropy> Driver<'cfg, 'id, 'slots, E> {
    /// Consume actual prepared native owners, with no TUN provisioning/routes,
    /// ambient lookup, advertisement or detached task. CADET must be fresh/idle.
    pub fn new(
        engine: Engine<'cfg>,
        cadet: cadet::Client<'id, 'slots>,
        tun: Option<tun::OwnedTun>,
        bindings: &[Binding],
        resolver: Option<Resolver>,
        limits: Limits,
        entropy: E,
    ) -> Result<Self, Error> {
        if !engine.is_pristine() {
            return Err(Fault::Conflict.into());
        }
        let tun = tun.map(PacketSource::native).transpose()?;
        Self::try_new(
            Parts {
                engine,
                cadet,
                tun,
                entropy,
            },
            bindings,
            resolver,
            limits,
        )
        .map_err(|failure| failure.error)
    }
    /// Build with explicit original owners and an untouched forwarding engine.
    /// Refusal returns every part, including an already-spawned helper, for
    /// mandatory physical close and actual wait.
    #[expect(
        clippy::result_large_err,
        reason = "Refusal returns actual linear owners without a fallible cleanup allocation"
    )]
    pub fn try_new(
        parts: Parts<'cfg, 'id, 'slots, E>,
        bindings: &[Binding],
        resolver: Option<Resolver>,
        limits: Limits,
    ) -> Result<Self, BuildFailure<'cfg, 'id, 'slots, E>> {
        let Parts {
            mut engine,
            cadet,
            tun,
            entropy,
        } = parts;
        let prepared = (|| -> Result<_, Error> {
            if !engine.is_pristine() {
                return Err(Fault::Conflict.into());
            }
            limits.validate(&engine)?;
            if cadet.epoch().is_some()
                || cadet.pending_transmit().is_some()
                || tun.as_ref().is_some_and(|t| !t.epoch().current())
                || bindings.len() > limits.ports
            {
                return Err(Fault::Conflict.into());
            }
            if let Some(r) = resolver
                && (r.retry.is_zero() || Instant::now().checked_add(r.retry).is_none())
            {
                return Err(Fault::InvalidInput.into());
            }
            if bindings.iter().any(|b| b.target == Target::Dns) && resolver.is_none() {
                return Err(Fault::Unavailable.into());
            }
            if tun.is_none() && bindings.iter().any(|b| b.target != Target::Dns) {
                return Err(Fault::Unavailable.into());
            }
            let mut ports = Vec::new();
            ports
                .try_reserve_exact(bindings.len())
                .map_err(|_| Fault::Capacity)?;
            for (i, b) in bindings.iter().enumerate() {
                let expected = match b.target {
                    Target::Internet(family) => Binding::internet(family).hash,
                    Target::Service(hash) => hash,
                    Target::Dns => Binding::dns().hash,
                };
                if expected != b.hash {
                    return Err(Fault::InvalidInput.into());
                }
                if bindings[..i].iter().any(|old| old.hash == b.hash) {
                    return Err(Fault::Conflict.into());
                }
                ports.push(Port {
                    binding: *b,
                    port: None,
                    disabled: false,
                });
            }
            let peers = slots(limits.channels)?;
            let dns_jobs = slots(limits.dns_jobs)?;
            let dns_buffer = buffer(limits.dns_bytes.checked_add(1).ok_or(Fault::Overflow)?)?;
            let clock = cadet.clock();
            let epoch = tun.as_ref().map(PacketSource::epoch);
            let core_tun = if tun.is_some() {
                Some(engine.tun_attached()?)
            } else {
                None
            };
            Ok((ports, peers, dns_jobs, dns_buffer, clock, epoch, core_tun))
        })();
        let (ports, peers, dns_jobs, dns_buffer, clock, epoch, core_tun) = match prepared {
            Ok(value) => value,
            Err(error) => {
                return Err(BuildFailure {
                    error,
                    parts: Parts {
                        engine,
                        cadet,
                        tun,
                        entropy,
                    },
                });
            }
        };
        Ok(Self {
            engine,
            cadet,
            tun,
            retiring_tun: None,
            tun_epoch: epoch,
            core_tun,
            source: None,
            ports,
            peers,
            pending: None,
            peer_held: None,
            tun_held: None,
            tun_pending: None,
            tun_input: None,
            dns_jobs,
            dns_buffer,
            resolver,
            limits,
            entropy,
            clock,
            anchor: Instant::now(),
            last_clock: None,
            flow_timer: None,
            timer: Box::pin(tokio::time::sleep(Duration::ZERO)),
            read_hard: None,
            class: 0,
            cursor: 0,
            dns_cursor: 0,
            stopping: false,
            stopped: false,
            report: Report::default(),
        })
    }
    /// Explicit access to the caller's original entropy port and real failures.
    pub fn entropy_mut(&mut self) -> &mut E {
        &mut self.entropy
    }
    /// Actual local counters, no remote delivery assertion.
    #[must_use]
    pub const fn report(&self) -> Report {
        self.report
    }
    /// Whether this owner's original native TUN epoch is still current. This
    /// reports physical source liveness only, not route or address readiness.
    #[must_use]
    pub fn tun_source_current(&self) -> bool {
        self.tun.as_ref().is_some_and(|tun| tun.epoch().current())
    }
    /// Read actual local port writing state for a separately owned advertiser.
    pub fn binding_status(&self, index: usize) -> Result<BindingStatus, Error> {
        let p = self.ports.get(index).ok_or(Fault::NotFound)?;
        Ok(BindingStatus {
            binding: p.binding,
            announced: !p.disabled
                && p.port
                    .is_some_and(|port| self.cadet.port_announced(port).unwrap_or(false)),
        })
    }
    fn now(&mut self) -> Result<MonoInstant, Error> {
        // Validate the actual configured absolute provider without using its
        // adjustable value as the flow/idle/DNS elapsed scheduling coordinate.
        self.clock.sample()?;
        let elapsed = Instant::now()
            .checked_duration_since(self.anchor)
            .ok_or(Fault::TimeUncertain)?;
        let now = MonoInstant(u64::try_from(elapsed.as_micros()).map_err(|_| Fault::Overflow)?);
        if self.last_clock.is_some_and(|old| now.0 < old) {
            return Err(Fault::TimeUncertain.into());
        }
        self.last_clock = Some(now.0);
        Ok(now)
    }
    fn until(
        &self,
        now: MonoInstant,
        expires: MonoInstant,
        maximum: Option<Duration>,
    ) -> Result<Instant, Fault> {
        if expires <= now {
            return Err(Fault::Deadline);
        }
        let original = self
            .anchor
            .checked_add(Duration::from_micros(expires.0))
            .ok_or(Fault::Overflow)?;
        let target = match maximum {
            Some(grace) => original.min(Instant::now().checked_add(grace).ok_or(Fault::Overflow)?),
            None => original,
        };
        if Instant::now() >= target {
            return Err(Fault::Deadline);
        }
        Ok(target)
    }
    fn hard(&self) -> Result<Instant, Fault> {
        Instant::now()
            .checked_add(self.limits.io_grace)
            .ok_or(Fault::Overflow)
    }
    fn peer(&self, channel: cadet::Channel<'id>) -> Option<usize> {
        self.peers
            .iter()
            .position(|p| p.as_ref().is_some_and(|p| p.channel == channel))
    }
    fn flow(&self, flow: &Flow) -> Option<usize> {
        self.peers
            .iter()
            .position(|p| p.as_ref().is_some_and(|p| p.flow.as_ref() == Some(flow)))
    }
    fn pending(
        &mut self,
        transmit: cadet::Transmit<'id>,
        action: Action<'id>,
        started: Instant,
    ) -> Result<(), Error> {
        if self.pending.is_some() {
            return Err(Fault::Conflict.into());
        }
        self.pending = Some(Pending {
            transmit,
            action,
            hard: started
                .checked_add(self.limits.io_grace)
                .ok_or(Fault::Overflow)?,
        });
        Ok(())
    }
    fn action_channel(action: &Action<'id>) -> Option<cadet::Channel<'id>> {
        match action {
            Action::Data { channel, .. }
            | Action::Ack { channel, .. }
            | Action::Destroy(channel) => Some(*channel),
            _ => None,
        }
    }
    fn closing(&mut self, i: usize) -> Result<(), Error> {
        let hard = self.hard()?;
        let p = self.peers[i].as_mut().ok_or(Fault::Stale)?;
        p.closing = true;
        p.hard.get_or_insert(hard);
        if let Some(flow) = &p.flow {
            self.engine.close(flow)?;
        }
        Ok(())
    }
    fn finish_peer(&mut self, i: usize) -> Result<(), Error> {
        let p = self.peers[i].take().ok_or(Fault::Stale)?;
        if let Some(flow) = p.flow {
            self.engine.closed(&flow)?;
            if let Some(outer) = p.input {
                for input in outer.receipts.into_iter().chain(outer.pending) {
                    match self.engine.processing_retired(&input) {
                        Ok(()) | Err(Fault::Stale) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
            }
        }
        Ok(())
    }
    /// Request original source retirement. The caller continues driving actual
    /// callbacks or invokes synchronous shutdown; no TTL declares IO quiescent.
    pub fn request_shutdown(&mut self) {
        self.stopping = true;
        self.engine.shutdown();
    }
    fn timers(
        &mut self,
        cx: &mut Context<'_>,
        now: MonoInstant,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        let drain_actual = Instant::now();
        for i in 0..self.peers.len() {
            if self.peers[i].as_ref().is_some_and(|p| {
                p.remote_closed
                    && !p.closing
                    && (p.input.as_ref().is_some_and(|outer| now >= outer.expires)
                        || p.hard.is_some_and(|hard| drain_actual >= hard))
            }) {
                self.closing(i)?;
                return Ok(true);
            }
        }
        let target = self
            .engine
            .next_deadline()
            .into_iter()
            .chain(self.dns_jobs.iter().flatten().map(|d| d.expires))
            .chain(self.peers.iter().flatten().filter_map(|p| {
                if p.remote_closed && !p.closing {
                    p.input.as_ref().map(|outer| outer.expires)
                } else {
                    None
                }
            }))
            .map(|n| n.0)
            .min();
        if target != self.flow_timer.as_ref().map(|(n, _)| *n) {
            self.flow_timer = target
                .map(|n| {
                    let original = self
                        .anchor
                        .checked_add(Duration::from_micros(n))
                        .ok_or(Fault::Overflow)?;
                    Ok::<_, Fault>((n, Box::pin(tokio::time::sleep_until(original))))
                })
                .transpose()?;
        }
        if let Some((_, deadline)) = &mut self.flow_timer {
            match deadline.as_mut().poll(cx) {
                Poll::Pending => {}
                Poll::Ready(()) => {
                    self.flow_timer = None;
                    self.engine.advance(now)?;
                    self.expire_dns(now, observe)?;
                    return Ok(true);
                }
            }
        }
        let actual = Instant::now();
        for i in 0..self.peers.len() {
            if self.peers[i]
                .as_ref()
                .is_some_and(|p| p.first.is_some_and(|d| actual >= d) && !p.closing)
            {
                self.closing(i)?;
                return Ok(true);
            }
        }
        if (self.pending.as_ref().is_some_and(|p| actual >= p.hard)
            || self.read_hard.is_some_and(|d| actual >= d)
            || self
                .peers
                .iter()
                .flatten()
                .any(|p| !p.remote_closed && p.hard.is_some_and(|d| actual >= d)))
            && self.cadet.epoch().is_some()
        {
            let event = self.cadet.reconnect()?;
            self.cadet_event(event, now, observe)?;
            return Ok(true);
        }
        if self.peer_held.as_ref().is_some_and(|p| actual >= p.until) {
            let p = self.peer_held.take().ok_or(Fault::Stale)?;
            if let Some((_, source)) = &self.source {
                self.engine.peer_unsent(source, &p.write, Fault::Deadline)?;
            }
            return Ok(true);
        }
        if self.tun_held.as_ref().is_some_and(|p| actual >= p.until) {
            let p = self.tun_held.take().ok_or(Fault::Stale)?;
            if let Some(tun) = &self.core_tun {
                self.engine.tun_unsent(tun, &p.write, Fault::Deadline)?;
            }
            return Ok(true);
        }
        if self.tun_input.as_ref().is_some_and(|p| actual >= p.until) {
            self.tun_input = None;
            observe(Event::TunDropped(Fault::Deadline));
            return Ok(true);
        }
        self.expire_dns(now, observe)
    }
    fn arm(&mut self, cx: &mut Context<'_>, wait: Option<Instant>) {
        let at = wait
            .into_iter()
            .chain(self.pending.iter().map(|p| p.hard))
            .chain(self.read_hard)
            .chain(self.peers.iter().flatten().flat_map(|p| {
                p.first
                    .into_iter()
                    .chain(p.hard.filter(|_| !p.remote_closed || !p.closing))
            }))
            .chain(self.peer_held.iter().map(|p| p.until))
            .chain(self.tun_held.iter().map(|p| p.until))
            .chain(self.tun_input.iter().map(|p| p.until))
            .chain(self.dns_jobs.iter().flatten().flat_map(|j| {
                Some(j.until).into_iter().chain(
                    (j.response.is_none() && j.next_send > Instant::now()).then_some(j.next_send),
                )
            }))
            .min();
        if let Some(at) = at {
            self.timer.as_mut().reset(at);
            if self.timer.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
    }
    /// One bounded fair source/domain action. Waiting futures may be cancelled
    /// without transferring any original source, byte cursor, packet or receipt.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<Instant>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        if self.stopped {
            return Poll::Ready(Ok(Progress::Stopped));
        }
        if self.poll_native_guard(cx, observe)? {
            return Poll::Ready(Ok(Progress::Activity));
        }
        if wait.is_some_and(|d| Instant::now() >= d) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        let now = self.now()?;
        if self.timers(cx, now, observe)? {
            return Poll::Ready(Ok(Progress::Activity));
        }
        if self.stopping && self.engine.is_quiescent() {
            self.stopped = true;
            return Poll::Ready(Ok(Progress::Stopped));
        }
        for n in 0..6 {
            let class = (self.class + n) % 6;
            let r = match class {
                0 => self.poll_cadet(cx, now, observe),
                1 => {
                    if self.peer_work(now, observe)? {
                        Poll::Ready(Ok(Progress::Activity))
                    } else {
                        Poll::Pending
                    }
                }
                2 => {
                    if self.effect(now, observe)? {
                        Poll::Ready(Ok(Progress::Activity))
                    } else {
                        Poll::Pending
                    }
                }
                3 => self.poll_tun(cx, now, observe),
                4 => self.poll_dns(cx, now, observe),
                _ => {
                    if let Some(closed) = self.engine.next_closed() {
                        observe(Event::FlowClosed(closed));
                        Poll::Ready(Ok(Progress::Activity))
                    } else {
                        Poll::Pending
                    }
                }
            };
            if r.is_ready() {
                self.class = (class + 1) % 6;
                return r;
            }
        }
        self.arm(cx, wait);
        Poll::Pending
    }
    /// Caller-driven wait over the original owners; never spawns a task.
    pub async fn drive(
        &mut self,
        wait: Option<Instant>,
        mut observe: impl FnMut(Event<'id>),
    ) -> Result<Progress, Error> {
        poll_fn(|cx| self.poll(cx, wait, &mut observe)).await
    }
    /// Independently physically close every actual source before its callbacks,
    /// including on a failed clock. First failure never skips another cleanup.
    pub fn shutdown(&mut self, mut observe: impl FnMut(Event<'id>)) -> Shutdown {
        self.stopping = true;
        self.engine.shutdown();
        let mut failure = None;
        if let Err(e) = self.close_cadet(&mut observe) {
            failure = Some(e)
        }
        if let Some(native) = &mut self.tun {
            let loss = native.close();
            if let Err(e) = self.tun_loss(loss, &mut observe)
                && failure.is_none()
            {
                failure = Some(e)
            }
        }
        for i in 0..self.dns_jobs.len() {
            if self.dns_jobs[i].is_some()
                && let Err(e) = self.cancel_dns(i, None, &mut observe)
                && failure.is_none()
            {
                failure = Some(e)
            }
        }
        self.flow_timer = None;
        self.tun_input = None;
        self.peer_held = None;
        self.tun_held = None;
        self.stopped = true;
        let quiescent = self.engine.is_quiescent();
        if !quiescent && failure.is_none() {
            failure = Some(Fault::NotReady.into())
        }
        Shutdown {
            report: self.report,
            failure,
            quiescent,
        }
    }
}
impl<E: Entropy> Drop for Driver<'_, '_, '_, E> {
    fn drop(&mut self) {
        let _stopped = self.shutdown(|_| {});
    }
}
