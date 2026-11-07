//! Real original-port binding and bounded native polling; no detached tasks.
use crate::{
    discovery,
    metrics::{Counter, Metrics},
};
use gnunet_cadet_host as cadet;
use gnunet_client_host::EndpointSource;
use gnunet_dns_client_host as dns;
use gnunet_pt::{
    core::{self, Attempt, Core, Discovery, Job, Request, Source, Stage, Tunnel, Work},
    packet::{Address, Replacement},
};
use gnunet_service_runtime::clock::{ClockSubscription, Deadline, RuntimeClock};
use gnunet_types::Error as Fault;
use gnunet_vpn_client_host as vpn;
use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
/// Independent actual boundary failure; diagnostics never contain private keys.
pub type Failure = Box<dyn Error>;
/// Original caller-owned instance/storage brands, without self-references.
pub struct Identities<'a, 'slots> {
    /// Pure PT domain.
    pub core: &'a core::Instance,
    /// Independent actual DNS clients share this explicit domain.
    pub dns: &'a dns::Instance,
    /// Original VPN client identity.
    pub vpn: &'a mut vpn::Instance,
    /// Original CADET application identity.
    pub cadet: &'a mut cadet::Instance,
    /// Caller-owned CADET port slots (PT listens on none).
    pub ports: &'slots mut [cadet::PortSlot],
    /// Caller-owned bounded channel slots.
    pub channels: &'slots mut [cadet::ChannelSlot],
}
/// Explicit endpoint selectors. All must share the same real clock/Resolver.
pub struct Sources<'a> {
    /// PRE_RESOLUTION original DNS MQ, only for TUNNEL_DNS.
    pub pre: Option<EndpointSource>,
    /// POST_RESOLUTION original DNS MQ, only for A/AAAA translation.
    pub post: Option<EndpointSource>,
    /// Actual VPN address-allocation service.
    pub vpn: Option<EndpointSource>,
    /// Actual CADET application service.
    pub cadet: Option<EndpointSource>,
    /// Explicit actual DHT query owner; no default substitute exists.
    pub discovery: Option<&'a mut dyn discovery::Port<'a>>,
}
/// Finite actual host resources and original-operation lifetimes.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Actual DNS callback/MQ resources.
    pub dns: dns::Limits,
    /// Actual VPN allocation/MQ resources.
    pub vpn: vpn::Limits,
    /// Actual CADET stream/channel resources.
    pub cadet: cadet::Limits,
    /// Finite local control/open/destroy/receive-done bound.
    pub control_timeout: Duration,
    /// Fresh actual DHT query window.
    pub discovery_timeout: Duration,
    /// Retry wake after resource refusal, never a work deadline reset.
    pub retry: Duration,
    /// Maximum accepted signed advertisement lifetime.
    pub advertisement_lifetime: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            dns: Default::default(),
            vpn: vpn::Limits {
                operations: 256,
                ..Default::default()
            },
            cadet: Default::default(),
            control_timeout: Duration::from_secs(10),
            discovery_timeout: Duration::from_secs(60),
            retry: Duration::from_millis(100),
            advertisement_lifetime: Duration::from_secs(86400),
        }
    }
}
#[derive(Clone, Copy)]
struct Bound {
    expires: u64,
    hard: Instant,
}
impl Bound {
    fn after(now: u64, d: Duration) -> Result<Self, Fault> {
        if d.is_zero() {
            return Err(Fault::Deadline);
        }
        let delta = u64::try_from(d.as_micros()).map_err(|_| Fault::Overflow)?;
        Ok(Self {
            expires: now
                .checked_add(delta)
                .filter(|n| *n != u64::MAX)
                .ok_or(Fault::Overflow)?,
            hard: Instant::now().checked_add(d).ok_or(Fault::Overflow)?,
        })
    }
    fn live(self, now: u64) -> bool {
        self.expires > now && Instant::now() < self.hard
    }
}
struct Callback<'a> {
    stage: Stage,
    native: dns::Request<'a>,
    id: [u8; 8],
    resolved: bool,
    core: Option<Request<'a>>,
    bounds: Bound,
}
struct Allocation<'a> {
    job: Job<'a>,
    request: Request<'a>,
    destination: Address,
    bounds: Bound,
    operation: Option<vpn::Operation<'a>>,
}
struct Channel<'a> {
    tunnel: Tunnel<'a>,
    peer: [u8; 32],
    channel: Option<cadet::Channel<'a>>,
    bounds: Bound,
    destroying: bool,
    remote_closed: bool,
}
#[derive(Clone, Copy)]
enum TxKind<'a> {
    Open,
    Send(Attempt<'a>),
    Destroy(Tunnel<'a>),
    ReceiveDone,
}
struct Transmit<'a> {
    original: cadet::Transmit<'a>,
    bounds: Bound,
    kind: TxKind<'a>,
}
struct AdLease {
    peer: [u8; 32],
    expires: u64,
    hard: Instant,
    retired: bool,
}
struct Received<'a> {
    input: cadet::Received<'a>,
    // Capture the original authenticated channel mapping before it can retire.
    tunnel: Tunnel<'a>,
    peer: [u8; 32],
    cursor: usize,
    processed: bool,
    needs_ack: bool,
    bounds: Bound,
}
/// Actual progress only. No event asserts NAT/TUN/route or Internet reachability.
pub enum Event {
    /// Attached original DNS source, before INIT whole-write.
    DnsAttached(Stage),
    /// Actual INIT complete local write.
    DnsInitWritten(Stage),
    /// Actual callback admitted or rejected/dropped.
    DnsRequest {
        /// Actual stage.
        stage: Stage,
        /// True only if pure core accepted the original callback.
        accepted: bool,
    },
    /// Actual original reply whole-write.
    DnsReplyWritten(Stage),
    /// Original physical source loss.
    DnsLost {
        /// Original stage.
        stage: Stage,
        /// Original loss fact.
        cause: dns::Cause,
    },
    /// Real public ad passed exact Rust signature/purpose/expiry validation.
    Advertisement,
    /// Real CADET state/byte progress.
    Cadet,
    /// Real original VPN progress; only actual matching USE_IP yields result.
    Vpn,
    /// One real command was locally admitted; no remote result is implied.
    Admitted,
    /// A finite resource blocked work; original bound is unchanged.
    Backpressure,
    /// Actual positive IO/protocol maintenance.
    Activity,
    /// Permanently stopped after explicit cleanup.
    Stopped,
    /// Actual independent provider/cleanup error, retained separately.
    CleanupFailure(Failure),
}
/// All independent cleanup failures remain separate from the original task error.
#[derive(Debug)]
pub struct Failures {
    /// Original task failure.
    pub original: Option<Failure>,
    /// Actual independent cleanup errors.
    pub cleanup: Vec<Failure>,
}
impl fmt::Display for Failures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(e) = &self.original {
            write!(f, "PT: {e}")?
        }
        for e in &self.cleanup {
            write!(f, "; cleanup: {e}")?
        }
        Ok(())
    }
}
impl Error for Failures {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.cleanup.first().map(|error| error.as_ref()))
    }
}
/// Complete native business owner. DHT is a caller-owned real port. No hidden
/// resolver, host-DNS fallback, private discovery, task, device or helper exists.
pub struct Owner<'a, 'slots> {
    core: Core<'a>,
    clock: Arc<dyn RuntimeClock>,
    subscription: Box<dyn ClockSubscription>,
    revision: u64,
    limits: Limits,
    pre: Option<dns::Client<'a>>,
    post: Option<dns::Client<'a>>,
    vpn: Option<vpn::Client<'a>>,
    cadet: Option<cadet::Client<'a, 'slots>>,
    dht: Option<&'a mut dyn discovery::Port<'a>>,
    pre_source: Option<(dns::Epoch<'a>, Source<'a>)>,
    post_source: Option<(dns::Epoch<'a>, Source<'a>)>,
    callbacks: Vec<Callback<'a>>,
    allocations: Vec<Allocation<'a>>,
    channels: Vec<Channel<'a>>,
    leases: Vec<AdLease>,
    transmit: Option<Transmit<'a>>,
    received: Option<Received<'a>>,
    discovery: Option<(Discovery<'a>, Bound)>,
    discovery_retry: Option<Instant>,
    native_alarm: Option<Pin<Box<Sleep>>>,
    logical_alarm: Option<Pin<Box<Deadline>>>,
    logical_at: Option<u64>,
    retry: Option<Pin<Box<Sleep>>>,
    cadet_input_hard: Option<Instant>,
    vpn_input_hard: Option<Instant>,
    cadet_lost: bool,
    failures: Vec<Failure>,
    cursor: usize,
    blocked: u8,
    metrics: Metrics,
    stopped: bool,
}
fn reserve<T>(n: usize) -> Result<Vec<T>, Fault> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Fault::Capacity)?;
    Ok(v)
}
fn retryable(e: &gnunet_client_host::ConnectError) -> bool {
    matches!(
        e,
        gnunet_client_host::ConnectError::Protocol(
            Fault::WouldBlock | Fault::Capacity | Fault::NotReady
        )
    )
}
fn addr(a: Address) -> vpn::Address {
    match a {
        Address::V4(b) => vpn::Address::V4(b),
        Address::V6(b) => vpn::Address::V6(b),
    }
}
fn allocated(a: vpn::Address) -> Address {
    match a {
        vpn::Address::V4(b) => Address::V4(b),
        vpn::Address::V6(b) => Address::V6(b),
    }
}
impl<'a, 'slots> Owner<'a, 'slots> {
    /// Build only after explicit source selection. No socket/task/entropy is used.
    /// TUNNEL_DNS requires explicit real DNS/CADET/discovery sources.
    pub fn new(
        ids: Identities<'a, 'slots>,
        sources: Sources<'a>,
        clock: Arc<dyn RuntimeClock>,
        pure: core::Limits,
        families: gnunet_pt::packet::Families,
        limits: Limits,
        af: vpn::AfProfile,
    ) -> Result<Self, Failure> {
        if sources.pre.is_some() != (sources.cadet.is_some() && sources.discovery.is_some())
            || sources.cadet.is_some() != sources.pre.is_some()
            || sources.discovery.is_some() != sources.pre.is_some()
        {
            return Err("TUNNEL_DNS requires actual DNS, CADET and production DHT ports".into());
        }
        if sources.post.is_some() != sources.vpn.is_some()
            || sources.post.is_some() != (families.ipv4 || families.ipv6)
        {
            return Err("A/AAAA translation requires original DNS and VPN ports".into());
        }
        if sources.pre.is_none() && sources.post.is_none() {
            return Err("PT has no enabled function".into());
        }
        for source in [&sources.pre, &sources.post, &sources.vpn, &sources.cadet]
            .into_iter()
            .flatten()
        {
            if !Arc::ptr_eq(&source.clock(), &clock) {
                return Err("PT sources must share the same clock Arc".into());
            }
        }
        if sources
            .discovery
            .as_ref()
            .is_some_and(|p| !Arc::ptr_eq(&p.clock(), &clock))
        {
            return Err("PT discovery clock domain differs".into());
        }
        let now = clock.sample()?.now.as_micros();
        for d in [
            limits.control_timeout,
            limits.discovery_timeout,
            limits.retry,
            limits.advertisement_lifetime,
        ] {
            Bound::after(now, d)?;
        }
        if limits.dns.requests < pure.requests
            || limits.vpn.operations < pure.requests
            || limits.dns.frame_bytes < pure.packet_bytes + 16
            || ids.channels.len() < pure.tunnels
        {
            return Err(Fault::Capacity.into());
        }
        let subscription = clock.subscribe()?;
        let pre = sources
            .pre
            .map(|s| dns::Client::new(ids.dns, s, dns::ipc::PRE_RESOLUTION, limits.dns))
            .transpose()?;
        let post = sources
            .post
            .map(|s| dns::Client::new(ids.dns, s, dns::ipc::POST_RESOLUTION, limits.dns))
            .transpose()?;
        let vpn = sources
            .vpn
            .map(|s| vpn::Client::new(ids.vpn, s, af, limits.vpn))
            .transpose()?;
        let cadet = sources
            .cadet
            .map(|s| cadet::Client::new(ids.cadet, s, ids.ports, ids.channels, limits.cadet))
            .transpose()?;
        Ok(Self {
            core: Core::new(ids.core, pure, families)?,
            clock,
            subscription,
            revision: 0,
            limits,
            pre,
            post,
            vpn,
            cadet,
            dht: sources.discovery,
            pre_source: None,
            post_source: None,
            callbacks: reserve(pure.requests.checked_mul(2).ok_or(Fault::Overflow)?)?,
            allocations: reserve(pure.requests)?,
            channels: reserve(pure.tunnels)?,
            leases: reserve(pure.exits)?,
            transmit: None,
            received: None,
            discovery: None,
            discovery_retry: None,
            native_alarm: None,
            logical_alarm: None,
            logical_at: None,
            retry: None,
            cadet_input_hard: None,
            vpn_input_hard: None,
            cadet_lost: false,
            failures: reserve(pure.requests + 32)?,
            cursor: 0,
            blocked: 0,
            metrics: Metrics::default(),
            stopped: false,
        })
    }
    /// Exact local official counter totals; no remote processing receipt.
    pub const fn metrics(&self) -> Metrics {
        self.metrics
    }
    fn dns(&mut self, stage: Stage) -> Result<&mut dns::Client<'a>, Failure> {
        match stage {
            Stage::Pre => self.pre.as_mut(),
            Stage::Post => self.post.as_mut(),
        }
        .ok_or_else(|| Fault::Unavailable.into())
    }
    fn source(&self, stage: Stage) -> Option<(dns::Epoch<'a>, Source<'a>)> {
        match stage {
            Stage::Pre => self.pre_source,
            Stage::Post => self.post_source,
        }
    }
    fn source_mut(&mut self, stage: Stage) -> &mut Option<(dns::Epoch<'a>, Source<'a>)> {
        match stage {
            Stage::Pre => &mut self.pre_source,
            Stage::Post => &mut self.post_source,
        }
    }
    fn failed_cleanup(&mut self, e: Failure) {
        self.failures.push(e)
    }
    fn cancel_job(&mut self, i: usize) {
        let row = self.allocations.remove(i);
        if let (Some(vpn), Some(op)) = (&mut self.vpn, row.operation)
            && let Err(e) = vpn.cancel(op)
        {
            self.failed_cleanup(e.into())
        }
    }
    fn source_lost(&mut self, stage: Stage) -> Result<(), Failure> {
        let source = self.source_mut(stage).take();
        let mut i = 0;
        while i < self.allocations.len() {
            let request = self.allocations[i].request;
            if self
                .callbacks
                .iter()
                .any(|c| c.stage == stage && c.core == Some(request))
            {
                self.cancel_job(i)
            } else {
                i += 1
            }
        }
        self.callbacks.retain(|c| c.stage != stage);
        if let Some((_, s)) = source {
            self.core.source_stopped(s)?;
        }
        Ok(())
    }
    fn on_dns(&mut self, stage: Stage, p: dns::Progress<'a>, now: u64) -> Result<Event, Failure> {
        let port = if stage == Stage::Pre { 1 } else { 2 };
        self.blocked &= !port;
        match p {
            dns::Progress::Connected(epoch) => {
                if self.source(stage).is_some() {
                    return Err(Fault::Conflict.into());
                }
                let source = self.core.attached(stage)?;
                *self.source_mut(stage) = Some((epoch, source));
                Ok(Event::DnsAttached(stage))
            }
            dns::Progress::InitWritten(_) => Ok(Event::DnsInitWritten(stage)),
            dns::Progress::Request(input) => {
                self.metrics.bump(if stage == Stage::Pre {
                    Counter::RequestsIntercepted
                } else {
                    Counter::RepliesIntercepted
                });

                let (epoch, source) = self.source(stage).ok_or(Fault::Stale)?;
                if input.request().epoch() != epoch {
                    return Err(Fault::Stale.into());
                }
                let bounds = Bound {
                    expires: input.expires(),
                    hard: input.hard(),
                };
                if self.callbacks.len() >= self.callbacks.capacity() {
                    return Err(Fault::Capacity.into());
                }
                let admission = if bounds.live(now) {
                    self.core
                        .admit(source, input.id(), input.dns(), bounds.expires, now)
                } else {
                    Err(Fault::Deadline)
                };
                let accepted = match admission {
                    Ok(request) => Some(request),
                    Err(error) => {
                        if stage == Stage::Pre
                            && matches!(
                                error,
                                Fault::Malformed | Fault::Truncated | Fault::InvalidInput
                            )
                        {
                            self.metrics.bump(Counter::Malformed);
                        }
                        None
                    }
                };
                if stage == Stage::Pre
                    && let Some(request) = accepted
                {
                    let channel = self.channels.iter().any(|c| {
                        c.channel.is_some()
                            && !c.destroying
                            && self.leases.iter().any(|l| {
                                l.peer == c.peer
                                    && !l.retired
                                    && l.expires > now
                                    && Instant::now() < l.hard
                            })
                    });
                    if !channel {
                        self.core.cancel(request)?;
                        self.metrics.bump(Counter::ChannelDown);
                    }
                }
                self.callbacks.push(Callback {
                    stage,
                    native: input.request(),
                    id: input.id(),
                    resolved: accepted.is_none(),
                    core: accepted,
                    bounds,
                });
                if accepted.is_none() {
                    self.dns(stage)?
                        .reply(input.request(), dns::ipc::Decision::Drop)?;
                }
                Ok(Event::DnsRequest {
                    stage,
                    accepted: accepted.is_some(),
                })
            }
            dns::Progress::Dropping(token) => {
                if let Some(row) = self.callbacks.iter_mut().find(|r| r.native == token) {
                    if stage == Stage::Pre && !row.resolved {
                        self.metrics.bump(Counter::Timeout);
                    }
                    row.resolved = true;
                }
                if let Some(row) = self.callbacks.iter().find(|r| r.native == token)
                    && let Some(request) = row.core
                {
                    self.core.cancel(request)?;
                    self.core.reply_queued(request)?;
                    let mut i = 0;
                    while i < self.allocations.len() {
                        if self.allocations[i].request == request {
                            self.cancel_job(i)
                        } else {
                            i += 1
                        }
                    }
                }
                Ok(Event::Admitted)
            }
            dns::Progress::Written(token) => {
                if let Some(i) = self
                    .callbacks
                    .iter()
                    .position(|r| r.native == token && r.stage == stage)
                {
                    let row = self.callbacks.remove(i);
                    if let Some(request) = row.core {
                        let (_, source) = self.source(stage).ok_or(Fault::Stale)?;
                        self.core.reply_written(source, request)?;
                    }
                }
                Ok(Event::DnsReplyWritten(stage))
            }
            dns::Progress::Lost { cause, .. } => {
                self.source_lost(stage)?;
                self.dns(stage)?.reconnect()?;
                Ok(Event::DnsLost { stage, cause })
            }
            dns::Progress::Retry { .. } | dns::Progress::Unavailable(_) => {
                self.blocked |= port;
                self.delay()?;
                Ok(Event::Backpressure)
            }
            dns::Progress::Activity { .. } | dns::Progress::Wait => Ok(Event::Activity),
            dns::Progress::Closed => Err(Fault::Closed.into()),
        }
    }
    fn on_vpn(&mut self, p: vpn::Progress<'a>, now: u64) -> Result<Event, Failure> {
        self.blocked &= !4;
        match &p {
            vpn::Progress::Activity { read_bytes, .. } if *read_bytes > 0 => {
                if self.vpn_input_hard.is_none() {
                    self.vpn_input_hard = Some(
                        Instant::now()
                            .checked_add(self.limits.control_timeout)
                            .ok_or(Fault::Overflow)?,
                    );
                }
            }
            vpn::Progress::Connected(_)
            | vpn::Progress::Lost { .. }
            | vpn::Progress::Closed
            | vpn::Progress::Ignored(_)
            | vpn::Progress::Completed {
                outcome: vpn::Outcome::Allocation(_),
                ..
            } => self.vpn_input_hard = None,
            _ => {}
        }
        if let vpn::Progress::Unavailable(error) = p {
            self.blocked |= 4;
            self.delay()?;
            return Ok(Event::CleanupFailure(error.into()));
        }
        if matches!(p, vpn::Progress::ConnectRetry { .. }) {
            self.blocked |= 4;
            self.delay()?;
            return Ok(Event::Backpressure);
        }
        if let vpn::Progress::Completed {
            operation, outcome, ..
        } = p
            && let Some(i) = self
                .allocations
                .iter()
                .position(|r| r.operation == Some(operation))
        {
            let row = self.allocations.remove(i);
            if row.bounds.live(now) {
                let allocation = match outcome {
                    vpn::Outcome::Allocation(Some(a)) => Some(Replacement {
                        address: allocated(a),
                        lease_until: row.bounds.expires,
                    }),
                    _ => None,
                };
                match self.core.allocation(row.job, allocation, now) {
                    Ok(()) => {
                        if allocation.is_some() {
                            self.metrics.bump(Counter::Modified);
                        }
                    }
                    Err(Fault::Stale) => {}
                    Err(e) => return Err(e.into()),
                }
            } else {
                match self.core.cancel(row.request) {
                    Ok(()) | Err(Fault::Stale) => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
        Ok(Event::Vpn)
    }
    fn delay(&mut self) -> Result<(), Failure> {
        if self.retry.is_none() {
            let at = Instant::now()
                .checked_add(self.limits.retry)
                .ok_or(Fault::Overflow)?;
            self.retry = Some(Box::pin(tokio::time::sleep_until(at)))
        }
        Ok(())
    }
    fn actual_tx(
        &mut self,
        original: cadet::Transmit<'a>,
        bounds: Bound,
        kind: TxKind<'a>,
    ) -> Result<(), Failure> {
        if self.transmit.is_some() {
            return Err(Fault::Conflict.into());
        }
        self.transmit = Some(Transmit {
            original,
            bounds,
            kind,
        });
        Ok(())
    }
    fn on_cadet(&mut self, p: cadet::Step<'a>, now: u64) -> Result<Event, Failure> {
        self.blocked &= !8;
        match p {
            cadet::Step::Written(w) => {
                let Some(tx) = self.transmit.take() else {
                    return Err(Fault::Stale.into());
                };
                if tx.original != w.transmit {
                    return Err(Fault::Stale.into());
                }
                match tx.kind {
                    TxKind::Send(a) => match self.core.send_written(a) {
                        Ok(()) | Err(Fault::Stale) => {}
                        Err(e) => return Err(e.into()),
                    },
                    TxKind::Destroy(t) => {
                        if self.received.as_ref().is_some_and(|r| r.tunnel == t) {
                            self.received = None;
                        }
                        self.core.tunnel_stopped(t, now)?;
                        self.channels.retain(|c| c.tunnel != t)
                    }
                    TxKind::Open | TxKind::ReceiveDone => {}
                }
                Ok(Event::Cadet)
            }
            cadet::Step::Credit { channel, available } => {
                self.cadet_input_hard = None;
                if let Some(row) = self.channels.iter().find(|r| r.channel == Some(channel)) {
                    match self.core.channel_credit(row.tunnel, available, now) {
                        Ok(()) | Err(Fault::Stale | Fault::Deadline) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                Ok(Event::Cadet)
            }
            cadet::Step::Destroyed(channel) => {
                self.cadet_input_hard = None;
                if let Some(i) = self
                    .channels
                    .iter()
                    .position(|r| r.channel == Some(channel))
                {
                    if let Some(received) = self
                        .received
                        .as_mut()
                        .filter(|r| r.input.channel() == channel)
                    {
                        // Classify already-owned replies before resetting this
                        // tunnel's DNS IDs or reselecting unanswered requests.
                        received.needs_ack = false;
                        self.channels[i].remote_closed = true;
                    } else {
                        let row = self.channels.remove(i);
                        self.core.tunnel_stopped(row.tunnel, now)?;
                    }
                }
                Ok(Event::Cadet)
            }
            cadet::Step::Data(input) => {
                self.cadet_input_hard = None;
                if self.received.is_some() {
                    return Err(Fault::Capacity.into());
                }
                let row = self
                    .channels
                    .iter()
                    .find(|row| row.channel == Some(input.channel()))
                    .ok_or(Fault::Stale)?;
                if row.destroying || row.remote_closed {
                    // Known local/remote retirement cannot acquire new input.
                    return Ok(Event::Cadet);
                }
                self.received = Some(Received {
                    input,
                    tunnel: row.tunnel,
                    peer: row.peer,
                    cursor: 0,
                    processed: false,
                    needs_ack: true,
                    bounds: Bound::after(now, self.limits.control_timeout)?,
                });
                Ok(Event::Cadet)
            }
            cadet::Step::Lost { .. } => {
                self.transmit = None;
                self.received = None;
                self.cadet_input_hard = None;
                for row in self.channels.drain(..) {
                    match self.core.tunnel_stopped(row.tunnel, now) {
                        Ok(()) | Err(Fault::Stale) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                Ok(Event::Cadet)
            }
            cadet::Step::Activity { read_bytes, .. } => {
                if read_bytes > 0 && self.cadet_input_hard.is_none() {
                    self.cadet_input_hard = Some(
                        Instant::now()
                            .checked_add(self.limits.control_timeout)
                            .ok_or(Fault::Overflow)?,
                    )
                }
                Ok(Event::Activity)
            }
            cadet::Step::RejectedIncoming { transmit, .. } => {
                self.cadet_input_hard = None;
                self.actual_tx(
                    transmit,
                    Bound::after(now, self.limits.control_timeout)?,
                    TxKind::ReceiveDone,
                )?;
                Ok(Event::Cadet)
            }
            cadet::Step::Blocked {
                input_retained: true,
                ..
            } => {
                self.blocked |= 8;
                if self.cadet_input_hard.is_none() {
                    self.cadet_input_hard = Some(
                        Instant::now()
                            .checked_add(self.limits.control_timeout)
                            .ok_or(Fault::Overflow)?,
                    );
                }
                self.delay()?;
                Ok(Event::Backpressure)
            }
            cadet::Step::Blocked { .. }
            | cadet::Step::ConnectRetry { .. }
            | cadet::Step::Unavailable(_) => {
                self.blocked |= 8;
                self.delay()?;
                Ok(Event::Backpressure)
            }
            cadet::Step::Ignored { .. } | cadet::Step::Incoming { .. } => {
                self.cadet_input_hard = None;
                Ok(Event::Cadet)
            }
            cadet::Step::Connected(_) | cadet::Step::WaitDeadline => Ok(Event::Cadet),
            cadet::Step::Closed => Err(Fault::Closed.into()),
        }
    }
    fn on_discovery(&mut self, p: discovery::Event<'a>, now: u64) -> Result<Event, Failure> {
        match p {
            discovery::Event::Result {
                original,
                query,
                block_type,
                block,
            } => {
                let Some((current, bounds)) = self.discovery else {
                    return Ok(Event::Activity);
                };
                if current != original || !bounds.live(now) {
                    return Ok(Event::Activity);
                }
                let bytes = block.bytes();
                if bytes.len() != 112 {
                    return Ok(Event::CleanupFailure(Fault::Malformed.into()));
                }
                let expires =
                    u64::from_be_bytes(bytes[72..80].try_into().map_err(|_| Fault::Truncated)?);
                let peer: [u8; 32] = bytes[80..112].try_into().map_err(|_| Fault::Truncated)?;
                let Some(delta) = expires.checked_sub(now) else {
                    return Ok(Event::Activity);
                };
                let lifetime = Duration::from_micros(delta);
                if lifetime.is_zero() || lifetime > self.limits.advertisement_lifetime {
                    return Ok(Event::Activity);
                }
                let existing = self.leases.iter().position(|r| r.peer == peer);
                if let Some(i) = existing {
                    if self.leases[i].retired && expires <= self.leases[i].expires {
                        return Ok(Event::Activity);
                    }
                } else if self.leases.len() >= self.leases.capacity() {
                    return Ok(Event::Backpressure);
                }
                if let Err(e) = self
                    .core
                    .advertisement(original, &query, block_type, bytes, now)
                {
                    return Ok(Event::CleanupFailure(e.into()));
                }
                let hard = Instant::now()
                    .checked_add(lifetime)
                    .ok_or(Fault::Overflow)?;
                if let Some(i) = existing {
                    if expires > self.leases[i].expires {
                        self.leases[i] = AdLease {
                            peer,
                            expires,
                            hard,
                            retired: false,
                        }
                    }
                } else {
                    self.leases.push(AdLease {
                        peer,
                        expires,
                        hard,
                        retired: false,
                    })
                }
                Ok(Event::Advertisement)
            }
            discovery::Event::SourceFailure { original: _, error } => {
                Ok(Event::CleanupFailure(error))
            }
            discovery::Event::Ended { original, error } => {
                if self.discovery.is_some_and(|(d, _)| d == original) {
                    self.discovery = None;
                    if let Err(cause) = self.core.discovery_stopped(original) {
                        return Err(Box::new(Failures {
                            original: error,
                            cleanup: vec![cause.into()],
                        }));
                    }
                    self.discovery_retry = Some(
                        Instant::now()
                            .checked_add(self.limits.retry)
                            .ok_or(Fault::Overflow)?,
                    )
                }
                if let Some(e) = error {
                    self.failed_cleanup(e)
                }
                Ok(Event::Activity)
            }
        }
    }
    fn stop_discovery(&mut self) -> Result<(), Failure> {
        if let Some((d, _)) = self.discovery.take() {
            let result = self.dht.as_mut().ok_or(Fault::Unavailable)?.stop(d);
            let stopped = self.core.discovery_stopped(d).map_err(Failure::from);
            match (result, stopped) {
                (Ok(()), Ok(())) => {}
                (Err(error), Ok(())) | (Ok(()), Err(error)) => return Err(error),
                (Err(original), Err(cleanup)) => {
                    return Err(Box::new(Failures {
                        original: Some(original),
                        cleanup: vec![cleanup],
                    }));
                }
            }
        }
        Ok(())
    }
    fn native_step(&mut self, cx: &mut Context<'_>) -> Result<Option<Event>, Failure> {
        let native = Instant::now();
        for stage in [Stage::Pre, Stage::Post] {
            let loss = match stage {
                Stage::Pre => self.pre.as_mut(),
                Stage::Post => self.post.as_mut(),
            }
            .and_then(|client| client.poll_native_guard(cx));
            if let Some(dns::Progress::Lost { cause, .. }) = loss {
                if stage == Stage::Pre {
                    for callback in &self.callbacks {
                        if callback.stage == stage
                            && !callback.resolved
                            && Instant::now() >= callback.bounds.hard
                        {
                            self.metrics.bump(Counter::Timeout);
                        }
                    }
                }
                self.source_lost(stage)?;
                self.dns(stage)?.reconnect()?;
                return Ok(Some(Event::DnsLost { stage, cause }));
            }
        }
        if self.vpn_input_hard.is_some_and(|at| native >= at) {
            if let Some(client) = &mut self.vpn {
                let _original = client.reconnect()?;
            }
            self.vpn_input_hard = None;
            // Original VPN IO was physically retired before local interests.
            // A prior allocation may still exist remotely; no revocation is claimed.
            while let Some(row) = self.allocations.pop() {
                match self.core.cancel(row.request) {
                    Ok(()) | Err(Fault::Stale) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            return Ok(Some(Event::Vpn));
        }
        if self.discovery_retry.is_some_and(|at| at <= native) {
            self.discovery_retry = None;
        }

        if let Some(stage) = self
            .callbacks
            .iter()
            .find(|r| native >= r.bounds.hard)
            .map(|r| r.stage)
        {
            if stage == Stage::Pre {
                for c in &self.callbacks {
                    if c.stage == stage && !c.resolved && native >= c.bounds.hard {
                        self.metrics.bump(Counter::Timeout);
                    }
                }
            }
            let p = self.dns(stage)?.retire(dns::Cause::Deadline);
            self.source_lost(stage)?;
            self.dns(stage)?.reconnect()?;
            if let dns::Progress::Lost { cause, .. } = p {
                return Ok(Some(Event::DnsLost { stage, cause }));
            }
            return Err(Fault::Conflict.into());
        }
        if let Some(i) = self
            .allocations
            .iter()
            .position(|r| native >= r.bounds.hard)
        {
            let request = self.allocations[i].request;
            self.cancel_job(i);
            match self.core.cancel(request) {
                Ok(()) | Err(Fault::Stale) => {}
                Err(e) => return Err(e.into()),
            }
            return Ok(Some(Event::Activity));
        }
        if self
            .transmit
            .as_ref()
            .is_some_and(|t| native >= t.bounds.hard)
            || self
                .received
                .as_ref()
                .is_some_and(|r| native >= r.bounds.hard)
            || self.cadet_input_hard.is_some_and(|at| native >= at)
        {
            if let Some(c) = &mut self.cadet {
                let _original = c.reconnect()?;
            }
            self.transmit = None;
            self.received = None;
            self.cadet_input_hard = None;
            self.cadet_lost = true;
            return Ok(Some(Event::Cadet));
        }
        if self.discovery.is_some_and(|(_, b)| native >= b.hard) {
            self.stop_discovery()?;
            self.discovery_retry = Some(
                native
                    .checked_add(self.limits.retry)
                    .ok_or(Fault::Overflow)?,
            );
            return Ok(Some(Event::Activity));
        }
        if let Some(i) = self
            .leases
            .iter()
            .position(|r| !r.retired && native >= r.hard)
        {
            let peer = self.leases[i].peer;
            self.leases[i].retired = true;
            self.core.withdraw_exit(peer)?;
            return Ok(Some(Event::Activity));
        }
        let due = self
            .callbacks
            .iter()
            .map(|r| r.bounds.hard)
            .chain(self.allocations.iter().map(|r| r.bounds.hard))
            .chain(self.transmit.as_ref().map(|r| r.bounds.hard))
            .chain(self.received.as_ref().map(|r| r.bounds.hard))
            .chain(self.cadet_input_hard)
            .chain(self.vpn_input_hard)
            .chain(self.discovery.map(|(_, b)| b.hard))
            .chain(self.leases.iter().filter(|r| !r.retired).map(|r| r.hard))
            .chain(self.discovery_retry)
            .min();
        if let Some(at) = due {
            let alarm = self
                .native_alarm
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(at)));
            alarm.as_mut().reset(at);
            if alarm.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        } else {
            self.native_alarm = None;
        }
        Ok(None)
    }
    fn clock(&mut self, cx: &mut Context<'_>) -> Poll<Result<u64, Failure>> {
        match self.subscription.poll_changed(cx, self.revision) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(s)) => self.revision = s.revision,
            Poll::Pending => {}
        }
        let sample = self.clock.sample()?;
        self.revision = sample.revision;
        match self.subscription.poll_changed(cx, sample.revision) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Pending => Poll::Ready(Ok(sample.now.as_micros())),
        }
    }
    fn maintain(&mut self, now: u64) -> Result<(), Failure> {
        if self.cadet_lost {
            for c in self.channels.drain(..) {
                match self.core.tunnel_stopped(c.tunnel, now) {
                    Ok(()) | Err(Fault::Stale) => {}
                    Err(e) => return Err(e.into()),
                }
            }
            self.cadet_lost = false;
        }
        self.core.expire(now)?;
        if self.transmit.as_ref().is_some_and(|t| !t.bounds.live(now))
            || self.received.as_ref().is_some_and(|r| !r.bounds.live(now))
        {
            if let Some(c) = &mut self.cadet {
                let _original = c.reconnect()?;
            }
            self.transmit = None;
            self.received = None;
            self.cadet_input_hard = None;
            self.cadet_lost = true;
        }
        for lease in &mut self.leases {
            if !lease.retired && lease.expires <= now {
                lease.retired = true;
                self.core.withdraw_exit(lease.peer)?;
            }
        }
        let mut i = 0;
        while i < self.allocations.len() {
            if !self.allocations[i].bounds.live(now) {
                let request = self.allocations[i].request;
                self.cancel_job(i);
                match self.core.cancel(request) {
                    Ok(()) | Err(Fault::Stale) => {}
                    Err(e) => return Err(e.into()),
                }
            } else {
                i += 1
            }
        }
        let mut i = 0;
        while i < self.channels.len() {
            if self.channels[i].channel.is_none() && !self.channels[i].bounds.live(now) {
                let row = self.channels.remove(i);
                self.core.tunnel_stopped(row.tunnel, now)?;
            } else {
                i += 1
            }
        }

        if self.discovery.is_some_and(|(_, b)| !b.live(now)) {
            self.stop_discovery()?;
            self.discovery_retry = Some(
                Instant::now()
                    .checked_add(self.limits.retry)
                    .ok_or(Fault::Overflow)?,
            );
        }
        Ok(())
    }
    fn providers(&mut self, now: u64) -> Result<Option<Event>, Failure> {
        if self.dht.is_some()
            && self.discovery.is_none()
            && self.discovery_retry.is_none_or(|at| Instant::now() >= at)
        {
            let bounds = Bound::after(now, self.limits.discovery_timeout)?;
            let d = self.core.begin_discovery(bounds.expires, now)?;
            let q = discovery::Query {
                original: d,
                key: gnunet_pt::exit::discovery_key(),
                block_type: 10,
                replication: 1,
                options: 1,
                expires: bounds.expires,
                hard: bounds.hard,
            };
            match self.dht.as_mut().ok_or(Fault::Unavailable)?.start(q) {
                Ok(()) => {
                    self.discovery = Some((d, bounds));
                    self.discovery_retry = None;
                    return Ok(Some(Event::Admitted));
                }
                Err(e) => {
                    if let Err(cause) = self.core.discovery_stopped(d) {
                        return Err(Box::new(Failures {
                            original: Some(e),
                            cleanup: vec![cause.into()],
                        }));
                    }
                    self.failed_cleanup(e);
                    self.discovery_retry = Some(
                        Instant::now()
                            .checked_add(self.limits.retry)
                            .ok_or(Fault::Overflow)?,
                    );
                    return Ok(Some(Event::Backpressure));
                }
            }
        }
        if let Some(i) = self.allocations.iter().position(|r| r.operation.is_none()) {
            let r = &self.allocations[i];
            if !r.bounds.live(now) {
                return Ok(None);
            }
            let desired = Some(match r.destination {
                Address::V4(_) => vpn::Family::V4,
                Address::V6(_) => vpn::Family::V6,
            });
            match self.vpn.as_mut().ok_or(Fault::Unavailable)?.internet(
                addr(r.destination),
                desired,
                r.bounds.expires,
                r.bounds.expires,
            ) {
                Ok(op) => {
                    self.allocations[i].operation = Some(op);
                    return Ok(Some(Event::Admitted));
                }
                Err(e) if retryable(&e) => {
                    self.delay()?;
                    return Ok(Some(Event::Backpressure));
                }
                Err(e) => {
                    let r = self.allocations.remove(i);
                    self.core.allocation(r.job, None, now)?;
                    self.failed_cleanup(e.into());
                    return Ok(Some(Event::Vpn));
                }
            }
        }
        if self.transmit.is_none()
            && let Some(i) = self
                .channels
                .iter()
                .position(|r| r.channel.is_none() && !r.destroying)
        {
            let r = &self.channels[i];
            if !r.bounds.live(now) {
                return Ok(None);
            }
            match self
                .cadet
                .as_mut()
                .ok_or(Fault::Unavailable)?
                .open(r.peer, gnunet_pt::exit::port_hash())
            {
                Ok(channel) => {
                    let transmit = self
                        .cadet
                        .as_ref()
                        .ok_or(Fault::Unavailable)?
                        .pending_transmit()
                        .ok_or(Fault::Conflict)?;
                    let tunnel = self.channels[i].tunnel;
                    let bounds = self.channels[i].bounds;
                    self.channels[i].channel = Some(channel);
                    self.core.opened(tunnel)?;
                    self.actual_tx(transmit, bounds, TxKind::Open)?;
                    return Ok(Some(Event::Admitted));
                }
                Err(e) if retryable(&e) => {
                    self.delay()?;
                    return Ok(Some(Event::Backpressure));
                }
                Err(e) => {
                    let r = self.channels.remove(i);
                    self.core.tunnel_stopped(r.tunnel, now)?;
                    self.failed_cleanup(e.into());
                    return Ok(Some(Event::Cadet));
                }
            }
        }
        if self.received.is_some() {
            let r = self.received.as_mut().ok_or(Fault::Conflict)?;
            let mut progressed = false;
            if !r.processed {
                let bytes = r.input.messages();
                while r.cursor < bytes.len() {
                    let result = gnunet_wire::official::Frame::decode_prefix(&bytes[r.cursor..]);
                    let (valid, end) = match result {
                        Ok((frame, _)) => {
                            let end = r
                                .cursor
                                .checked_add(frame.encoded_len())
                                .ok_or(Fault::Overflow)?;
                            (
                                self.core.response(r.tunnel, &bytes[r.cursor..end], now),
                                end,
                            )
                        }
                        Err(error) => (Err(error), r.cursor),
                    };
                    match valid {
                        Ok(accepted) => {
                            self.metrics.bump(if accepted {
                                Counter::Received
                            } else {
                                Counter::Late
                            });
                            r.cursor = end;
                            progressed = true;
                        }
                        Err(Fault::Capacity) => {
                            // Retain the exact original frame/cursor and bounds.
                            // Earlier accepted replies must never be replayed.
                            self.delay()?;
                            return Ok(Some(Event::Backpressure));
                        }
                        Err(_) => {
                            self.core.withdraw_exit(r.peer)?;
                            break;
                        }
                    }
                }
                r.processed = true;
            }
            if !r.needs_ack {
                let received = self.received.take().ok_or(Fault::Conflict)?;
                if let Some(index) = self
                    .channels
                    .iter()
                    .position(|row| row.tunnel == received.tunnel)
                {
                    let row = self.channels.remove(index);
                    self.core.tunnel_stopped(row.tunnel, now)?;
                }
                // Native channel is gone. Release only the local packet; its
                // old Delivery cannot authorize receive_done or a new ACK.
                return Ok(Some(Event::Cadet));
            }
            if self.transmit.is_none() {
                match self
                    .cadet
                    .as_mut()
                    .ok_or(Fault::Unavailable)?
                    .receive_done(r.input.delivery())
                {
                    Ok(tx) => {
                        let r = self.received.take().ok_or(Fault::Conflict)?;
                        self.actual_tx(tx, r.bounds, TxKind::ReceiveDone)?;
                        return Ok(Some(Event::Admitted));
                    }
                    Err(e) if retryable(&e) => {
                        self.delay()?;
                        return Ok(Some(Event::Backpressure));
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            if progressed {
                return Ok(Some(Event::Activity));
            }
        }
        Ok(None)
    }
    fn work(&mut self, now: u64) -> Result<Option<Event>, Failure> {
        let Some(work) = self.core.next_work(now)? else {
            return Ok(None);
        };
        match work {
            Work::Allocate {
                job,
                request,
                destination,
                lease_until,
                expires: _,
            } => {
                let callback = self
                    .callbacks
                    .iter()
                    .find(|r| r.core == Some(request))
                    .ok_or(Fault::Stale)?;
                if self.allocations.len() >= self.allocations.capacity() {
                    return Err(Fault::Capacity.into());
                }
                self.allocations.push(Allocation {
                    job,
                    request,
                    destination,
                    bounds: Bound {
                        expires: lease_until,
                        hard: callback.bounds.hard,
                    },
                    operation: None,
                });
                Ok(Some(Event::Admitted))
            }
            Work::Open {
                tunnel,
                peer,
                expires,
            } => {
                let lease = self
                    .leases
                    .iter()
                    .find(|r| r.peer == peer && !r.retired && r.expires >= expires)
                    .ok_or(Fault::Stale)?;
                if self.channels.len() >= self.channels.capacity() {
                    return Err(Fault::Capacity.into());
                }
                let control = Bound::after(now, self.limits.control_timeout)?;
                self.channels.push(Channel {
                    tunnel,
                    peer,
                    channel: None,
                    bounds: Bound {
                        expires: expires.min(control.expires),
                        hard: lease.hard.min(control.hard),
                    },
                    destroying: false,
                    remote_closed: false,
                });
                Ok(Some(Event::Admitted))
            }
            Work::Send {
                attempt,
                request,
                tunnel,
                message,
                expires,
            } => {
                if self.transmit.is_some() {
                    return Ok(None);
                }
                let original = self
                    .channels
                    .iter()
                    .find(|c| c.tunnel == tunnel)
                    .ok_or(Fault::Stale)?;
                if original.remote_closed || original.destroying {
                    // Retained input is the only authority left on a gone
                    // channel; a pending Work cannot admit another send.
                    return Ok(None);
                }
                let request_hard = self
                    .callbacks
                    .iter()
                    .find(|c| c.core == Some(request))
                    .map(|c| c.bounds.hard)
                    .ok_or(Fault::Stale)?;
                let lease = self
                    .leases
                    .iter()
                    .find(|l| l.peer == original.peer && !l.retired)
                    .ok_or(Fault::Stale)?;
                let expires = expires.min(lease.expires);
                let request_hard = request_hard.min(lease.hard);
                let channel = original.channel.ok_or(Fault::NotReady)?;
                match self
                    .cadet
                    .as_mut()
                    .ok_or(Fault::Unavailable)?
                    .send(channel, 0, message)
                {
                    Ok(tx) => {
                        self.core.send_queued(attempt)?;
                        self.actual_tx(
                            tx,
                            Bound {
                                expires,
                                hard: request_hard,
                            },
                            TxKind::Send(attempt),
                        )?;
                        Ok(Some(Event::Admitted))
                    }
                    Err(e) if retryable(&e) => {
                        self.delay()?;
                        Ok(Some(Event::Backpressure))
                    }
                    Err(e) => Err(e.into()),
                }
            }
            Work::Close { tunnel } => {
                // Core local cancellation/withdrawal/expiry wins over held
                // input. A later remote event cannot revive that old packet.
                if self.received.as_ref().is_some_and(|r| r.tunnel == tunnel) {
                    self.received = None;
                }
                if self.transmit.is_some() {
                    return Ok(None);
                }
                let Some(i) = self.channels.iter().position(|c| c.tunnel == tunnel) else {
                    self.core.tunnel_stopped(tunnel, now)?;
                    return Ok(Some(Event::Cadet));
                };
                if self.channels[i].destroying {
                    return Ok(None);
                }
                if self.channels[i].remote_closed {
                    let row = self.channels.remove(i);
                    self.core.tunnel_stopped(row.tunnel, now)?;
                    return Ok(Some(Event::Cadet));
                }
                let Some(channel) = self.channels[i].channel else {
                    self.channels.remove(i);
                    self.core.tunnel_stopped(tunnel, now)?;
                    return Ok(Some(Event::Cadet));
                };
                match self
                    .cadet
                    .as_mut()
                    .ok_or(Fault::Unavailable)?
                    .destroy(channel)
                {
                    Ok(tx) => {
                        self.channels[i].destroying = true;
                        let bound = Bound::after(now, self.limits.control_timeout)?;
                        self.actual_tx(tx, bound, TxKind::Destroy(tunnel))?;
                        Ok(Some(Event::Admitted))
                    }
                    Err(e) if retryable(&e) => {
                        self.delay()?;
                        Ok(Some(Event::Backpressure))
                    }
                    Err(e) => Err(e.into()),
                }
            }
            Work::Reply {
                request,
                source,
                id,
                decision,
                expires: _,
            } => {
                let row = self
                    .callbacks
                    .iter()
                    .find(|c| c.core == Some(request))
                    .ok_or(Fault::Stale)?;
                let stage = row.stage;
                let token = row.native;
                let attached = match stage {
                    Stage::Pre => self.pre_source,
                    Stage::Post => self.post_source,
                }
                .ok_or(Fault::Stale)?;
                if attached.1 != source || attached.0 != token.epoch() || row.id != id {
                    return Err(Fault::Stale.into());
                }

                let client = match stage {
                    Stage::Pre => self.pre.as_mut(),
                    Stage::Post => self.post.as_mut(),
                }
                .ok_or(Fault::Unavailable)?;
                match client.reply(token, decision) {
                    Ok(()) => {
                        if stage == Stage::Post && matches!(decision, dns::ipc::Decision::Answer(_))
                        {
                            self.metrics.bump(Counter::Mapped);
                        }
                        self.core.reply_queued(request)?;
                        self.callbacks
                            .iter_mut()
                            .find(|r| r.core == Some(request))
                            .ok_or(Fault::Stale)?
                            .resolved = true;
                        Ok(Some(Event::Admitted))
                    }
                    Err(gnunet_client_host::ConnectError::Protocol(Fault::Deadline)) => {
                        self.delay()?;
                        Ok(None)
                    }
                    Err(e) if retryable(&e) => {
                        self.delay()?;
                        Ok(Some(Event::Backpressure))
                    }
                    Err(e) => Err(e.into()),
                }
            }
        }
    }
    fn logical_alarm(&mut self, cx: &mut Context<'_>, now: u64) -> Result<(), Failure> {
        let at = self.core.next_deadline().filter(|n| *n > now);
        if at != self.logical_at {
            self.logical_at = at;
            self.logical_alarm = at
                .map(|n| {
                    Deadline::at(
                        self.clock.clone(),
                        gnunet_types::AbsoluteTime::from_micros(n),
                    )
                    .map(Box::pin)
                })
                .transpose()?;
        }
        if let Some(a) = &mut self.logical_alarm {
            match a.as_mut().poll(cx) {
                Poll::Ready(Err(e)) => return Err(e.into()),
                Poll::Ready(Ok(())) => {
                    self.logical_alarm = None;
                    self.logical_at = None;
                    cx.waker().wake_by_ref()
                }
                Poll::Pending => {}
            }
        }
        Ok(())
    }
    fn poll_inner(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event, Failure>> {
        if self.stopped {
            return Poll::Ready(Ok(Event::Stopped));
        }
        if let Some(event) = self.native_step(cx)? {
            return Poll::Ready(Ok(event));
        }
        if let Some(error) = self.failures.pop() {
            return Poll::Ready(Ok(Event::CleanupFailure(error)));
        }
        let now = match self.clock(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(r) => r?,
        };
        self.maintain(now)?;
        self.logical_alarm(cx, now)?;
        let work_ready = if let Some(retry) = &mut self.retry {
            if retry.as_mut().poll(cx).is_ready() {
                self.retry = None;
                true
            } else {
                false
            }
        } else {
            true
        };
        if work_ready {
            if let Some(event) = self.providers(now)? {
                return Poll::Ready(Ok(event));
            }
            if let Some(event) = self.work(now)? {
                return Poll::Ready(Ok(event));
            }
        }
        for offset in 0..5 {
            let selected = (self.cursor + offset) % 5;
            if !work_ready && selected < 4 && self.blocked & (1 << selected) != 0 {
                continue;
            }
            if selected == 4 && self.discovery.is_none() {
                continue;
            }
            let event = match selected {
                0 => {
                    if let Some(c) = &mut self.pre {
                        match c.poll(cx, None) {
                            Poll::Ready(r) => Some(self.on_dns(
                                Stage::Pre,
                                r?,
                                self.clock.sample()?.now.as_micros(),
                            )?),
                            Poll::Pending => None,
                        }
                    } else {
                        None
                    }
                }
                1 => {
                    if let Some(c) = &mut self.post {
                        match c.poll(cx, None) {
                            Poll::Ready(r) => Some(self.on_dns(
                                Stage::Post,
                                r?,
                                self.clock.sample()?.now.as_micros(),
                            )?),
                            Poll::Pending => None,
                        }
                    } else {
                        None
                    }
                }
                2 => {
                    let progress = if let Some(c) = &mut self.vpn {
                        let mut future = std::pin::pin!(c.drive(None));
                        future.as_mut().poll(cx)
                    } else {
                        Poll::Pending
                    };
                    match progress {
                        Poll::Ready(r) => {
                            Some(self.on_vpn(r?, self.clock.sample()?.now.as_micros())?)
                        }
                        Poll::Pending => None,
                    }
                }
                3 => {
                    if let Some(c) = &mut self.cadet {
                        match c.poll(cx, None) {
                            Poll::Ready(r) => {
                                Some(self.on_cadet(r?, self.clock.sample()?.now.as_micros())?)
                            }
                            Poll::Pending => None,
                        }
                    } else {
                        None
                    }
                }
                _ => {
                    if let Some(c) = &mut self.dht {
                        match c.poll(cx) {
                            Poll::Ready(r) => {
                                Some(self.on_discovery(r?, self.clock.sample()?.now.as_micros())?)
                            }
                            Poll::Pending => None,
                        }
                    } else {
                        None
                    }
                }
            };
            if let Some(event) = event {
                self.cursor = (selected + 1) % 5;
                return Poll::Ready(Ok(event));
            }
        }
        Poll::Pending
    }
    /// Poll all real owners fairly. Native hard bounds are checked before any
    /// canonical clock wait; any unrecoverable clock/port failure closes owners.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event, Failure>> {
        let result = self.poll_inner(cx);
        if let Poll::Ready(Err(original)) = result {
            let cleanup = self.stop();
            Poll::Ready(Err(Box::new(Failures {
                original: Some(original),
                cleanup,
            })))
        } else {
            result
        }
    }
    /// Canceling a wait preserves admitted original operations and native cursors.
    pub async fn drive(&mut self) -> Result<Event, Failure> {
        poll_fn(|cx| self.poll(cx)).await
    }
    /// Physical cleanup with no clock dependency; original errors remain separate.
    /// HTTP/DNS/VPN receipt or local close never fabricates lease revocation.
    pub fn stop(&mut self) -> Vec<Failure> {
        if self.stopped {
            return Vec::new();
        }
        self.stopped = true;
        if let Err(e) = self.stop_discovery() {
            self.failed_cleanup(e)
        }
        if let Some(c) = &mut self.pre {
            let _original = c.close();
        }
        if let Some(c) = &mut self.post {
            let _original = c.close();
        }
        if let Some(c) = &mut self.vpn
            && let Err(e) = c.close()
        {
            self.failed_cleanup(e.into())
        }
        if let Some(c) = &mut self.cadet
            && let Err(e) = c.close()
        {
            self.failed_cleanup(e.into())
        }
        self.callbacks.clear();
        self.allocations.clear();
        self.channels.clear();
        self.transmit = None;
        self.received = None;
        self.vpn_input_hard = None;
        self.native_alarm = None;
        self.logical_alarm = None;
        self.retry = None;
        std::mem::take(&mut self.failures)
    }
}
impl Drop for Owner<'_, '_> {
    fn drop(&mut self) {
        let _independent = self.stop();
    }
}
