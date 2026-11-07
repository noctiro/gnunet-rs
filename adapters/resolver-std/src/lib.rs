//! Actual bounded Unix/TCP Resolver reactor using the official request4/response5.
//! Caller backing, native IDNA capability and clocks/entropy are explicit.
//! No system DNS lookup, private frame, detached task or timeout reset is added.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
mod io;
pub mod startup;
pub mod storage;
use gnunet_client::resolver::{FamilyProfile, Request};
use gnunet_dns::{AbsoluteTime, Arena, Idna, Packet, Query, RData, Record};
use gnunet_dnsstub_host::{DnsStub, Event as UdpEvent, Flow, HostError as StubError, RequestId};
use gnunet_resolver_service_core::{
    files::{ResolverField, ResolverFile},
    owner::{ClientId, Effect, EffectTicket, Evaluation, LookupId, Resolver, Scratch},
    storage::TextScratch,
};
pub use gnunet_service_runtime::accepted::{AcceptError, SocketEvent};
use gnunet_service_runtime::accepted::{AcceptState, AcceptedConnection};
use gnunet_service_runtime::service::{Listener, PeerAddress, ServiceOptions, ShutdownMode};
use gnunet_service_runtime::{
    clock::{ClockSubscription, RuntimeClock},
    credentials::UnixAccess,
};
use gnunet_types::{Error, MonoInstant};
use gnunet_wire::official::{Frame, message_type};
use io::{Session, Step, Stream, bytes};
use std::{
    fmt,
    future::{Future, poll_fn},
    io as stdio,
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::Instant;
/// Real boundary failure. A caller can resume after a canceled drive future.
#[derive(Debug)]
pub enum HostError {
    /// The bounded core or parser rejected the operation.
    Core(Error),
    /// Receive-time UTC was unavailable. The untimeable datagram is discarded;
    /// its lookup/token/deadline remain live for a later response or shutdown.
    Clock(Error),
    /// Actual stream or listener I/O failure.
    Io(stdio::Error),
    /// Actual DNSSTUB host admission/entropy failure.
    Stub(StubError),
}
impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(e) => write!(f, "Resolver core: {e}"),
            Self::Clock(e) => write!(f, "Resolver receive UTC: {e}"),
            Self::Io(e) => write!(f, "Resolver I/O: {e}"),
            Self::Stub(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for HostError {}
impl From<Error> for HostError {
    fn from(e: Error) -> Self {
        Self::Core(e)
    }
}
impl From<stdio::Error> for HostError {
    fn from(e: stdio::Error) -> Self {
        Self::Io(e)
    }
}
impl From<stdio::ErrorKind> for HostError {
    fn from(e: stdio::ErrorKind) -> Self {
        Self::Io(e.into())
    }
}
impl From<StubError> for HostError {
    fn from(e: StubError) -> Self {
        Self::Stub(e)
    }
}
/// Host-only finite resources; these are not invented GNUnet configuration keys.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum simultaneous actual client streams.
    pub max_connections: usize,
    /// Maximum complete official incoming or outgoing frame, within 16..=65535.
    pub max_frame_bytes: usize,
    /// Maximum unsent bytes retained per stream, including partial writes.
    pub max_pending_bytes: usize,
    /// Optional interval without successful stream I/O; Duration::MAX disables it.
    pub idle_timeout: Duration,
    /// Maximum bytes offered to one actual read/write syscall poll, at least one.
    pub io_slice_bytes: usize,
    /// Maximum received DNS packet, within 12..=65535.
    pub maximum_dns_bytes: usize,
    /// Explicit expanded DNS name/payload arena bytes for one pending datagram.
    pub dns_arena_bytes: usize,
    /// Maximum parsed DNS query metadata slots admitted per datagram.
    pub maximum_dns_queries: usize,
    /// Maximum total record metadata slots across all three record sections.
    pub maximum_dns_records: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: 64,
            max_frame_bytes: 65535,
            max_pending_bytes: 256 * 1024,
            idle_timeout: Duration::MAX,
            io_slice_bytes: 65535,
            maximum_dns_bytes: 65535,
            dns_arena_bytes: 4 * 1024 * 1024,
            maximum_dns_queries: 13104,
            maximum_dns_records: 5956,
        }
    }
}
/// Explicit host ports. The monotonic epoch is retained across every drive call.
#[derive(Clone, Copy)]
pub struct Ports {
    /// Stable monotonic origin, retained across every drive and cancellation.
    pub epoch: Instant,
    /// Actual or caller-controlled UTC port, independent from the monotonic origin.
    pub utc: fn() -> Result<AbsoluteTime, Error>,
    /// Unbiased integer port returning a value below the supplied nonzero bound.
    pub random_below: fn(u32) -> Result<u32, Error>,
}
impl Ports {
    /// Select actual OS entropy and UTC with a fresh stable Tokio monotonic epoch.
    pub fn system() -> Self {
        Self {
            epoch: Instant::now(),
            utc: system_utc,
            random_below: system_random_below,
        }
    }
    fn mono(self) -> Result<MonoInstant, Error> {
        let d = Instant::now()
            .checked_duration_since(self.epoch)
            .ok_or(Error::TimeUncertain)?;
        Ok(MonoInstant(
            u64::try_from(d.as_micros()).map_err(|_| Error::Overflow)?,
        ))
    }
    fn at(self, m: MonoInstant) -> Result<Instant, Error> {
        self.epoch
            .checked_add(Duration::from_micros(m.0))
            .ok_or(Error::Overflow)
    }
}
struct SharedUtc {
    source: Arc<dyn RuntimeClock>,
    listener: Option<Box<dyn ClockSubscription>>,
    revision: u64,
}
fn selected_utc(
    source: Option<&dyn RuntimeClock>,
    fallback: fn() -> Result<AbsoluteTime, Error>,
) -> Result<AbsoluteTime, Error> {
    match source {
        Some(source) => source.sample().map(|sample| sample.now),
        None => fallback(),
    }
}
/// Obtain actual UTC without consulting NSS or DNS.
pub fn system_utc() -> Result<AbsoluteTime, Error> {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::TimeUncertain)?;
    Ok(AbsoluteTime::from_micros(
        u64::try_from(d.as_micros()).map_err(|_| Error::Overflow)?,
    ))
}
/// Unbiased actual OS entropy; no modulo-biased or deterministic production fallback.
pub fn system_random_below(bound: u32) -> Result<u32, Error> {
    if bound == 0 {
        return Err(Error::InvalidInput);
    }
    let low = bound.wrapping_neg() % bound;
    loop {
        let n = getrandom::u32().map_err(|_| Error::EntropyUnavailable)?;
        if n >= low {
            return Ok(n % bound);
        }
    }
}
/// Actual I/O and local ownership counters, not remote acknowledgements.
/// Each counter saturates at u64::MAX, which then means a lower bound. Diagnostic
/// overflow cannot make a copied effect replay or abort actual socket cleanup.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Report {
    /// OS accepts, including connections subsequently denied admission.
    pub accepted: u64,
    /// Connections actually assigned a core ClientId.
    pub admitted: u64,
    /// Connections refused before storing a live session.
    pub rejected: u64,
    /// Previously admitted physical streams actually dropped.
    pub closed: u64,
    /// Complete known request frames successfully dispatched to the core.
    pub requests: u64,
    /// Output effects copied into persistent bounded TX ownership.
    pub queued_frames: u64,
    /// Actual UDP send syscall attempts, irrespective of result.
    pub udp_sends: u64,
    /// Actual unsuccessful UDP send attempts; stub retry remains live.
    pub udp_send_failures: u64,
    /// Actual UDP receive errors observed by the stub host.
    pub udp_receive_failures: u64,
    /// Source-matching datagrams rejected by packet/native parsing.
    pub malformed_dns: u64,
    /// Datagrams without their original live lookup/stub ownership.
    pub stale_dns: u64,
    /// Parsed datagrams handed to the core, including ignored wrong IDs.
    pub dns_results: u64,
    /// Actual stub admissions that replaced an old request generation.
    pub stub_evictions: u64,
    /// Real stub admissions that failed before a token was adopted.
    pub unavailable_queries: u64,
}
fn inc(n: &mut u64) {
    *n = n.saturating_add(1);
}
/// One bounded drive return. WaitDeadline is not a DNS request timeout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// Only the caller's wait deadline elapsed; requests remain live.
    WaitDeadline,
    /// Final Stop physically closed stream and UDP owners.
    Stopped,
}
#[derive(Clone, Copy)]
struct Association {
    request: RequestId,
    lookup: LookupId,
}
#[derive(Clone, Copy)]
enum Pulse {
    Datagram {
        request: RequestId,
        len: usize,
        utc: Result<AbsoluteTime, Error>,
    },
    Sent(bool),
    Opened,
    ReadFailed,
    Discarded,
}
struct Receive {
    bytes: Vec<u8>,
    pulse: Option<Pulse>,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Settlement {
    Idle,
    TxBlocked,
    BudgetRemaining,
}
enum NetEvent {
    Accept(AcceptedConnection),
    AcceptFailure(AcceptError),
    Session(usize, Result<Step, HostError>),
    Udp,
    Wake,
}
/// One host owns actual streams and UDP stub. Backing and IDNA scratch outlive it.
/// All cursors, queues, token associations and pending datagrams live in this
/// object, so dropping a drive future does not revoke or replay submitted work.
pub struct Host<'a, 'i, I: Idna, const R: usize = 128, const N: usize = 271, const S: usize = 128> {
    core: Resolver<'a>,
    stage: Scratch<'a>,
    idna: &'i I,
    ports: Ports,
    runtime_clock: Option<SharedUtc>,
    source_started: bool,
    unix_access: UnixAccess,
    profile: FamilyProfile,
    limits: Limits,
    options: ServiceOptions,
    sessions: Vec<Option<Session>>,
    cursor: usize,
    stub: DnsStub<R, N, S>,
    association: Vec<Option<Association>>,
    receive: Receive,
    output: Vec<u8>,
    native: Vec<u8>,
    work: Vec<u8>,
    wire_name: Vec<u8>,
    parse_arena: Vec<u8>,
    report: Report,
    accepting: bool,
    accept_state: AcceptState,
    stopped: bool,
    io_first: bool,
}
impl<'a, 'i, I: Idna, const R: usize, const N: usize, const S: usize> Host<'a, 'i, I, R, N, S> {
    #[expect(
        clippy::too_many_arguments,
        reason = "Borrowed owner/staging, native capability, explicit ports, ABI, resource policy and real stub pool remain independent ownership inputs"
    )]
    /// Take the borrowed pure owner and staging plus explicit host/native capabilities. No sockets are opened until the caller drives or supplies existing streams.
    pub fn new(
        core: Resolver<'a>,
        stage: Scratch<'a>,
        idna: &'i I,
        ports: Ports,
        profile: FamilyProfile,
        limits: Limits,
        options: ServiceOptions,
        num_stub_sockets: usize,
    ) -> Result<Self, HostError> {
        if limits.max_connections == 0
            || !(16..=65535).contains(&limits.max_frame_bytes)
            || limits.max_pending_bytes < 8
            || limits.io_slice_bytes == 0
            || !(12..=65535).contains(&limits.maximum_dns_bytes)
        {
            return Err(Error::InvalidInput.into());
        }
        let mut sessions = Vec::new();
        sessions
            .try_reserve_exact(limits.max_connections)
            .map_err(|_| Error::Capacity)?;
        sessions.resize_with(limits.max_connections, || None);
        let mut association = Vec::new();
        association
            .try_reserve_exact(R)
            .map_err(|_| Error::Capacity)?;
        association.resize_with(R, || None);
        Ok(Self {
            core,
            stage,
            idna,
            ports,
            runtime_clock: None,
            source_started: false,
            unix_access: UnixAccess::default(),
            profile,
            limits,
            options,
            sessions,
            cursor: 0,
            stub: DnsStub::start(num_stub_sockets, limits.maximum_dns_bytes)?,
            association,
            receive: Receive {
                bytes: bytes(limits.maximum_dns_bytes, true)?,
                pulse: None,
            },
            output: bytes(limits.max_frame_bytes, true)?,
            native: bytes(65535, true)?,
            work: bytes(65535, true)?,
            wire_name: bytes(255, true)?,
            parse_arena: bytes(limits.dns_arena_bytes, true)?,
            report: Report::default(),
            accepting: true,
            accept_state: AcceptState::default(),
            stopped: false,
            io_first: true,
        })
    }
    /// Install the actual shared absolute UTC authority once, before loading
    /// machine data, adding endpoints or driving this host. Native monotonic
    /// epoch/entropy are unchanged. A live host cannot replace the source or
    /// reset any original request/partial-I/O deadline.
    pub fn set_runtime_clock(&mut self, source: Arc<dyn RuntimeClock>) -> Result<(), HostError> {
        if self.source_started || self.runtime_clock.is_some() || self.stopped {
            return Err(Error::Conflict.into());
        }
        let listener = source.subscribe().map_err(HostError::Clock)?;
        let sample = source.sample().map_err(HostError::Clock)?;
        self.runtime_clock = Some(SharedUtc {
            source,
            listener: Some(listener),
            revision: sample.revision,
        });
        Ok(())
    }
    /// Install real kernel Unix peer policy before this source admits data or
    /// connections. TCP addresses retain the existing independent IP ACL.
    pub fn set_unix_access(&mut self, policy: UnixAccess) -> Result<(), HostError> {
        if self.source_started || self.stopped {
            return Err(Error::Conflict.into());
        }
        self.unix_access = policy;
        Ok(())
    }
    fn utc(&self) -> Result<AbsoluteTime, Error> {
        selected_utc(
            self.runtime_clock.as_ref().map(|port| port.source.as_ref()),
            self.ports.utc,
        )
    }
    fn stop_io(&mut self) {
        self.accepting = false;
        let _stopped = self.stub.stop();
        self.association.fill(None);
        for session in &mut self.sessions {
            if session.take().is_some() {
                inc(&mut self.report.closed);
            }
        }
        self.receive.pulse = None;
        if let Some(port) = &mut self.runtime_clock {
            port.listener = None;
        }
        self.stopped = true;
    }
    /// Apply literal file bytes once at startup and add parsed port53 IPs in file
    /// order. Invalid literal addresses are counted, not normalized or resolved.
    pub fn load_machine_bytes(&mut self, hosts: &[u8], resolv: &[u8]) -> Result<usize, HostError> {
        self.source_started = true;
        self.core
            .load_machine_files(&mut self.stage, hosts, resolv)?;
        let mut rejected = 0;
        for field in ResolverFile::new(resolv) {
            if let ResolverField::NameServer(ip) = field {
                let Ok(ip) = std::str::from_utf8(ip) else {
                    rejected += 1;
                    continue;
                };
                match self.stub.add_dns_ip(ip) {
                    Ok(_) => {}
                    Err(Error::InvalidInput) => rejected += 1,
                    Err(error) => return Err(error.into()),
                }
            }
        }
        Ok(rejected)
    }
    /// Isolated embedding/test transport capability, never a resolver config key.
    pub fn add_dns_endpoint(&mut self, address: SocketAddr) -> Result<(), HostError> {
        self.source_started = true;
        self.stub.add_dns_sa(address)?;
        Ok(())
    }
    /// Change future stub retry periods without resetting an existing due retry.
    pub fn set_dns_retry(&mut self, d: gnunet_types::Duration) -> Result<(), HostError> {
        self.stub.set_retry(d)?;
        Ok(())
    }
    /// Current saturated local I/O counters; no remote acknowledgement is inferred.
    pub fn report(&self) -> Report {
        self.report
    }
    /// Recover the exact leased core effect after cancellation or TX backpressure.
    pub fn current_effect(&self) -> Option<EffectTicket> {
        self.core.current_effect()
    }
    /// Number of original logical service lookups, including evicted/no-server waits.
    pub fn pending_lookups(&self) -> usize {
        self.core.lookup_count()
    }
    /// Whether an already consumed raw datagram remains owned for safe retry.
    pub fn has_pending_dns_datagram(&self) -> bool {
        matches!(self.receive.pulse, Some(Pulse::Datagram { .. }))
    }
    /// Number of actually admitted live DNSSTUB request tokens.
    pub fn pending_stub_requests(&self) -> usize {
        self.stub.pending_requests()
    }
    /// Number of currently owned actual client streams.
    pub fn connections(&self) -> usize {
        self.sessions.iter().filter(|s| s.is_some()).count()
    }
    /// Sum of persistent unsent stream bytes, including partial frames.
    pub fn pending_tx_bytes(&self) -> usize {
        self.sessions.iter().flatten().map(Session::pending).sum()
    }
    /// Actual retained local UDP endpoint for a slot/family, including canceled slots.
    pub fn cached_udp_socket(
        &self,
        slot: usize,
        family: gnunet_dnsstub_host::Family,
    ) -> Option<SocketAddr> {
        self.stub.cached_socket(slot, family).map(|(_, a)| a)
    }
    /// Whether final Stop has closed all client streams and UDP socket owners.
    pub fn is_stopped(&self) -> bool {
        self.stopped
    }
    /// Immediate is official Resolver OPTION_NONE. Soft is an explicit reusable
    /// library choice and waits for connected clients, not active lookup count.
    pub fn shutdown(&mut self, mode: ShutdownMode) -> Result<(), HostError> {
        self.accepting = false;
        let immediate = matches!(mode, ShutdownMode::Immediate);
        let result = (|| -> Result<(), HostError> {
            match mode {
                ShutdownMode::Immediate => self.core.shutdown(&mut self.stage)?,
                ShutdownMode::Soft => self.core.begin_soft_shutdown(&mut self.stage)?,
            }
            self.settle()?;
            Ok(())
        })();
        // A failed core cleanup or clock authority cannot leave real original
        // streams/datagrams awaiting a later successful sample or callback.
        if immediate {
            self.stop_io();
        }
        result
    }
    fn remove_association(&mut self, id: RequestId) {
        for a in &mut self.association {
            if a.is_some_and(|a| a.request == id) {
                *a = None
            }
        }
    }
    fn close_physical(&mut self, id: ClientId) -> Result<(), Error> {
        if let Some(i) = self
            .sessions
            .iter()
            .position(|s| s.as_ref().is_some_and(|s| s.client == id))
        {
            drop(self.sessions[i].take());
            self.accept_state.client_closed();
            inc(&mut self.report.closed);
        }
        Ok(())
    }
    fn disconnect(&mut self, id: ClientId) -> Result<(), HostError> {
        self.close_physical(id)?;
        if self.core.owns_client(id) {
            self.core.disconnect(&mut self.stage, id)?;
        }
        Ok(())
    }
    fn settle(&mut self) -> Result<Settlement, HostError> {
        for _ in 0..64 {
            let Some(ticket) = self.core.take_effect()? else {
                return Ok(Settlement::Idle);
            };
            match self.core.effect(ticket)? {
                Effect::Output(o) => {
                    let client = o.client;
                    let Some(i) = self
                        .sessions
                        .iter()
                        .position(|s| s.as_ref().is_some_and(|s| s.client == client))
                    else {
                        return Err(Error::StaleGeneration.into());
                    };
                    let n = match o.encode(&mut self.output) {
                        Ok(n) => n,
                        Err(Error::Capacity | Error::TooLarge) => {
                            self.disconnect(client)?;
                            continue;
                        }
                        Err(e) => return Err(e.into()),
                    };
                    if n > self.limits.max_pending_bytes {
                        self.disconnect(client)?;
                        continue;
                    }
                    if !self.sessions[i]
                        .as_mut()
                        .ok_or(Error::StaleGeneration)?
                        .queue(&self.output[..n], self.limits.max_pending_bytes)
                    {
                        return Ok(Settlement::TxBlocked);
                    }
                    inc(&mut self.report.queued_frames);
                    self.core.release_effect(ticket)?;
                }
                Effect::StartQuery(q) => {
                    // Release an expired start before normal timeout/output
                    // draining. Ticking an older lookup while retaining this
                    // lease can fill the effect queue and prevent recovery.
                    let now = self.ports.mono()?;
                    if q.deadline <= now {
                        let lookup = q.lookup;
                        self.core.query_unavailable(&mut self.stage, lookup)?;
                        self.core.release_effect(ticket)?;
                        continue;
                    }
                    let lookup = q.lookup;
                    let admitted = self.stub.resolve(q.bytes);
                    match admitted {
                        Ok(a) => {
                            if let Some(old) = a.evicted {
                                self.remove_association(old);
                                self.core.stub_evicted(old);
                                inc(&mut self.report.stub_evictions);
                            }
                            if let Err(e) = self.core.query_admitted(&mut self.stage, lookup, a) {
                                if self.stub.owns_request(a.request) {
                                    self.stub.resolve_cancel(a.request)?;
                                }
                                self.core.query_unavailable(&mut self.stage, lookup)?;
                                self.core.release_effect(ticket)?;
                                return Err(e.into());
                            }
                            let index = a.request.resource_id().index as usize;
                            *self
                                .association
                                .get_mut(index)
                                .ok_or(Error::StaleGeneration)? = Some(Association {
                                request: a.request,
                                lookup,
                            });
                        }
                        Err(e) => {
                            self.core.query_unavailable(&mut self.stage, lookup)?;
                            inc(&mut self.report.unavailable_queries);
                            self.core.release_effect(ticket)?;
                            match e {
                                StubError::Core(Error::Unavailable) => continue,
                                e => return Err(e.into()),
                            }
                        }
                    }
                    self.core.release_effect(ticket)?;
                }
                Effect::CancelQuery(id) => {
                    self.remove_association(id);
                    if self.stub.owns_request(id) {
                        self.stub.resolve_cancel(id)?;
                    }
                    self.core.release_effect(ticket)?;
                }
                Effect::DropClient { client, .. } => {
                    self.close_physical(client)?;
                    self.core.release_effect(ticket)?;
                }
                Effect::Stop => {
                    self.stop_io();
                    self.core.release_effect(ticket)?;
                    return Ok(Settlement::Idle);
                }
            }
        }
        Ok(if self.core.effect_count() != 0 {
            Settlement::BudgetRemaining
        } else {
            Settlement::Idle
        })
    }
    /// Admit one canonically initialized accepted connection through the normal
    /// ACL, Unix credential and capacity gates. Rejection closes that connection
    /// and returns false; native diagnostics retain their original order.
    pub fn admit(
        &mut self,
        connection: AcceptedConnection,
        mut observe: impl FnMut(SocketEvent),
    ) -> Result<bool, HostError> {
        self.source_started = true;
        let (stream, peer, diagnostics) = connection.into_parts();
        for diagnostic in diagnostics {
            observe(SocketEvent::Diagnostic(diagnostic));
        }
        self.admit_stream(stream, peer)
    }
    fn admit_stream(&mut self, stream: Stream, peer: PeerAddress) -> Result<bool, HostError> {
        inc(&mut self.report.accepted);
        if !self.accepting
            || matches!(peer, PeerAddress::Tcp(p) if !self.options.access.allows(p.ip()))
        {
            inc(&mut self.report.rejected);
            return Ok(false);
        }
        if stream.is_unix() {
            match self.unix_access.allows(&stream) {
                Ok(true) => {}
                Ok(false) => {
                    inc(&mut self.report.rejected);
                    return Ok(false);
                }
                Err(error) => {
                    inc(&mut self.report.rejected);
                    return Err(error.into());
                }
            }
        }
        let Some(i) = self.sessions.iter().position(Option::is_none) else {
            inc(&mut self.report.rejected);
            return Ok(false);
        };
        let client = match self.core.connect() {
            Ok(c) => c,
            Err(Error::Capacity | Error::Closed) => {
                inc(&mut self.report.rejected);
                return Ok(false);
            }
            Err(e) => return Err(e.into()),
        };
        match Session::new(stream, client, self.limits) {
            Ok(s) => {
                self.sessions[i] = Some(s);
                inc(&mut self.report.admitted);
                Ok(true)
            }
            Err(e) => {
                self.core.disconnect(&mut self.stage, client)?;
                inc(&mut self.report.rejected);
                Err(e.into())
            }
        }
    }
    fn dispatch(&mut self, index: usize) -> Result<(), HostError> {
        let session = self.sessions[index]
            .as_ref()
            .ok_or(Error::StaleGeneration)?;
        let client = session.client;
        let frame = Frame::decode(&session.rx[..session.expected])?;
        if frame.header().message_type() != message_type::RESOLVER_REQUEST {
            if self.options.tolerant {
                self.sessions[index]
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?
                    .reset();
                return Ok(());
            }
            self.disconnect(client)?;
            return Ok(());
        }
        let request = match Request::decode(frame, self.profile) {
            Ok(r) => r,
            Err(_) => {
                self.disconnect(client)?;
                return Ok(());
            }
        };
        let mut random = self.ports.random_below;
        let mut p = Evaluation {
            mono: self.ports.mono()?,
            utc: self.utc().map_err(HostError::Clock)?,
            idna: self.idna,
            random: &mut random,
            text: TextScratch {
                native: &mut self.native,
                work: &mut self.work,
                wire_name: &mut self.wire_name,
            },
        };
        match self.core.request(&mut self.stage, client, request, &mut p) {
            Ok(_) => {
                inc(&mut self.report.requests);
                if let Some(s) = self.sessions[index].as_mut() {
                    s.reset();
                }
                Ok(())
            }
            Err(Error::Capacity | Error::TooLarge) => {
                self.disconnect(client)?;
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }
    fn pulse(&mut self) -> Result<(), HostError> {
        let result = self.process_pulse();
        if result.is_ok() || matches!(result, Err(HostError::Clock(_))) {
            self.receive.pulse = None;
        }
        result
    }
    fn process_pulse(&mut self) -> Result<(), HostError> {
        let Some(pulse) = self.receive.pulse else {
            return Ok(());
        };
        match pulse {
            Pulse::Sent(ok) => {
                inc(&mut self.report.udp_sends);
                if !ok {
                    inc(&mut self.report.udp_send_failures);
                }
            }
            Pulse::ReadFailed => inc(&mut self.report.udp_receive_failures),
            Pulse::Opened | Pulse::Discarded => {}
            Pulse::Datagram { request, len, utc } => {
                let Some(a) = self
                    .association
                    .get(request.resource_id().index as usize)
                    .copied()
                    .flatten()
                    .filter(|a| a.request == request)
                else {
                    inc(&mut self.report.stale_dns);
                    return Ok(());
                };
                // One callback UTC fixes this datagram's absolute TTLs across
                // resource retries. Business cache lookup uses current UTC.
                let parsed_utc = utc.map_err(HostError::Clock)?;
                let utc = self.utc().map_err(HostError::Clock)?;
                let b = &self.receive.bytes[..len];
                let header = match gnunet_dns::Header::decode(b) {
                    Ok(h) => h,
                    Err(_) => {
                        self.core.malformed_dns(a.lookup, request)?;
                        inc(&mut self.report.malformed_dns);
                        return Ok(());
                    }
                };
                let q = header.counts.queries as usize;
                let count = usize::from(header.counts.answers)
                    + usize::from(header.counts.authority)
                    + usize::from(header.counts.additional);
                let minimum = 12usize
                    .checked_add(q.checked_mul(5).ok_or(Error::Overflow)?)
                    .and_then(|n| n.checked_add(count.checked_mul(11)?))
                    .ok_or(Error::Overflow)?;
                if minimum > b.len() {
                    self.core.malformed_dns(a.lookup, request)?;
                    inc(&mut self.report.malformed_dns);
                    return Ok(());
                }
                if q > self.limits.maximum_dns_queries || count > self.limits.maximum_dns_records {
                    return Err(Error::Capacity.into());
                }
                let mut queries = Vec::new();
                queries.try_reserve_exact(q).map_err(|_| Error::Capacity)?;
                queries.resize_with(q, || Query::EMPTY);
                let mut records = Vec::new();
                records
                    .try_reserve_exact(count)
                    .map_err(|_| Error::Capacity)?;
                records.resize_with(count, || Record::EMPTY);
                let mut arena = Arena::new(&mut self.parse_arena);
                let parsed = Packet::parse(
                    b,
                    parsed_utc,
                    &mut arena,
                    &mut queries,
                    &mut records,
                    gnunet_dns::Limits::DNS,
                );
                let packet = match parsed {
                    Ok(p) => p,
                    Err(Error::Capacity | Error::TooLarge | Error::Overflow) => {
                        return Err(Error::Capacity.into());
                    }
                    Err(_) => {
                        self.core.malformed_dns(a.lookup, request)?;
                        inc(&mut self.report.malformed_dns);
                        return Ok(());
                    }
                };
                if let Err(e) = validate_native(packet, self.idna, &mut self.work, &mut self.native)
                {
                    match e {
                        Error::Malformed | Error::InvalidInput | Error::Truncated => {
                            self.core.malformed_dns(a.lookup, request)?;
                            inc(&mut self.report.malformed_dns);
                            return Ok(());
                        }
                        e => return Err(e.into()),
                    }
                }
                let mut random = self.ports.random_below;
                let mut p = Evaluation {
                    mono: self.ports.mono()?,
                    utc,
                    idna: self.idna,
                    random: &mut random,
                    text: TextScratch {
                        native: &mut self.native,
                        work: &mut self.work,
                        wire_name: &mut self.wire_name,
                    },
                };
                match self
                    .core
                    .dns_result(&mut self.stage, a.lookup, request, packet, &mut p)
                {
                    Ok(_) => inc(&mut self.report.dns_results),
                    Err(Error::StaleGeneration | Error::Stale) => inc(&mut self.report.stale_dns),
                    Err(e) => return Err(e.into()),
                }
            }
        }
        Ok(())
    }
    /// Drive actual OS I/O until a wait deadline or stop. Cancellation retains
    /// current_effect, RX/TX cursors, copied DNS pulse, token maps and deadlines.
    pub async fn drive(
        &mut self,
        listeners: &[Listener<'_>],
        deadline: Option<Instant>,
        mut observe: impl FnMut(SocketEvent),
    ) -> Result<Progress, HostError> {
        self.source_started = true;
        loop {
            let settlement = self.settle()?;
            if settlement == Settlement::BudgetRemaining {
                if deadline.is_some_and(|at| Instant::now() >= at) {
                    return Ok(Progress::WaitDeadline);
                }
                tokio::task::yield_now().await;
                continue;
            }
            let mut blocked = settlement == Settlement::TxBlocked;
            if self.stopped {
                return Ok(Progress::Stopped);
            }
            let now = self.ports.mono()?;
            if !blocked && self.core.next_wakeup().is_some_and(|at| at <= now) {
                self.core.tick(&mut self.stage, now)?;
                continue;
            }
            if !blocked {
                self.pulse()?;
                let settlement = self.settle()?;
                if settlement == Settlement::BudgetRemaining {
                    if deadline.is_some_and(|at| Instant::now() >= at) {
                        return Ok(Progress::WaitDeadline);
                    }
                    tokio::task::yield_now().await;
                    continue;
                }
                blocked = settlement == Settlement::TxBlocked;
            }
            if self.stopped {
                return Ok(Progress::Stopped);
            }
            let now = self.ports.mono()?;
            if !blocked && self.core.next_wakeup().is_some_and(|at| at <= now) {
                self.core.tick(&mut self.stage, now)?;
                continue;
            }
            if deadline.is_some_and(|d| Instant::now() >= d) {
                return Ok(Progress::WaitDeadline);
            }
            let mut wake = deadline;
            if !blocked && let Some(due) = self.core.next_wakeup() {
                let at = self.ports.at(due)?;
                wake = Some(wake.map_or(at, |w| w.min(at)));
            }
            for s in self.sessions.iter().flatten() {
                if let Some(at) = s.idle {
                    wake = Some(wake.map_or(at, |w| w.min(at)))
                }
            }
            let accept = self.accepting && self.accept_state.ready();
            let limits = self.limits;
            let first = self.io_first;
            self.io_first = !first;
            let skip_dns = self.receive.pulse.is_some();
            let utc = self.ports.utc;
            let source_clock = self.runtime_clock.as_ref().map(|port| port.source.clone());
            let runtime_clock = &mut self.runtime_clock;
            let event = {
                let receive = &mut self.receive;
                let mut dns = std::pin::pin!(self.stub.drive(wake, |event, _| {
                    receive.pulse = Some(match event {
                        UdpEvent::Datagram(d) => {
                            receive.bytes[..d.bytes.len()].copy_from_slice(d.bytes);
                            Pulse::Datagram {
                                request: d.request,
                                len: d.bytes.len(),
                                utc: selected_utc(source_clock.as_deref(), utc),
                            }
                        }
                        UdpEvent::Sent { result, .. } => Pulse::Sent(result.is_ok()),
                        UdpEvent::SocketOpened { .. } => Pulse::Opened,
                        UdpEvent::ReceiveFailed { .. } => Pulse::ReadFailed,
                        UdpEvent::Discarded { .. } => Pulse::Discarded,
                    });
                    Flow::Return
                }));
                let sessions = &mut self.sessions;
                let cursor = &mut self.cursor;
                let mut timer = wake.map(|at| Box::pin(tokio::time::sleep_until(at)));
                poll_fn(|cx| {
                    // The original independently owned listener is registered
                    // before sampling time inside any DNS callback. Pending
                    // logical adjustments never block native I/O/deadlines.
                    if let Some(port) = runtime_clock.as_mut()
                        && let Some(listener) = &mut port.listener
                    {
                        match listener.poll_changed(cx, port.revision) {
                            Poll::Ready(Ok(sample)) => {
                                port.revision = sample.revision;
                                return Poll::Ready(Ok(NetEvent::Wake));
                            }
                            Poll::Ready(Err(error)) => {
                                return Poll::Ready(Err(HostError::Clock(error)));
                            }
                            Poll::Pending => {}
                        }
                    }
                    if first
                        && let Poll::Ready(e) =
                            poll_network(cx, listeners, sessions, cursor, limits, accept, true)
                    {
                        return Poll::Ready(e);
                    }
                    if !skip_dns {
                        match dns.as_mut().poll(cx) {
                            Poll::Ready(Ok(_)) => return Poll::Ready(Ok(NetEvent::Udp)),
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                            Poll::Pending => {}
                        }
                    }
                    if !first
                        && let Poll::Ready(e) =
                            poll_network(cx, listeners, sessions, cursor, limits, accept, true)
                    {
                        return Poll::Ready(e);
                    }
                    if timer
                        .as_mut()
                        .is_some_and(|t| t.as_mut().poll(cx).is_ready())
                    {
                        return Poll::Ready(Ok(NetEvent::Wake));
                    }
                    Poll::Pending
                })
                .await?
            };
            match event {
                NetEvent::Accept(connection) => {
                    self.admit(connection, &mut observe)?;
                }
                NetEvent::AcceptFailure(failure) => {
                    if matches!(&failure, AcceptError::Initialization(_)) {
                        inc(&mut self.report.accepted);
                        inc(&mut self.report.rejected);
                    }
                    observe(self.accept_state.failed(failure));
                }
                NetEvent::Session(i, Ok(Step::Frame)) => self.dispatch(i)?,
                NetEvent::Session(i, Ok(Step::Eof) | Err(_)) => {
                    let id = self.sessions[i]
                        .as_ref()
                        .ok_or(Error::StaleGeneration)?
                        .client;
                    self.disconnect(id)?;
                }
                NetEvent::Session(_, Ok(Step::Activity)) | NetEvent::Udp | NetEvent::Wake => {}
            }
        }
    }
}
impl<I: Idna, const R: usize, const N: usize, const S: usize> Drop for Host<'_, '_, I, R, N, S> {
    fn drop(&mut self) {
        self.stop_io();
    }
}
fn poll_network(
    cx: &mut Context<'_>,
    listeners: &[Listener<'_>],
    sessions: &mut [Option<Session>],
    cursor: &mut usize,
    limits: Limits,
    accept: bool,
    dispatch: bool,
) -> Poll<Result<NetEvent, HostError>> {
    // Rotate through every client and listener. A permanently readable client
    // cannot starve accept, and a hot Unix listener cannot starve TCP listeners.
    let count = sessions.len() + if accept { listeners.len() } else { 0 };
    for offset in 0..count {
        let i = (*cursor + offset) % count;
        if i < sessions.len() {
            if let Some(session) = sessions[i].as_mut()
                && let Poll::Ready(step) = session.poll(cx, limits, dispatch)
            {
                *cursor = (i + 1) % count;
                return Poll::Ready(Ok(NetEvent::Session(i, step)));
            }
        } else {
            match listeners[i - sessions.len()].poll_canonical_connection(cx) {
                Poll::Ready(Ok(connection)) => {
                    *cursor = (i + 1) % count;
                    return Poll::Ready(Ok(NetEvent::Accept(connection)));
                }
                Poll::Ready(Err(error)) => {
                    *cursor = (i + 1) % count;
                    return Poll::Ready(Ok(NetEvent::AcceptFailure(error)));
                }
                Poll::Pending => {}
            }
        }
    }
    Poll::Pending
}

fn validate_native(
    packet: Packet<'_, '_>,
    idna: &impl Idna,
    work: &mut [u8],
    native: &mut [u8],
) -> Result<(), Error> {
    let mut name = |n: gnunet_dns::Name<'_>| n.write_native_text(idna, work, native).map(|_| ());
    for q in packet.queries {
        name(q.name)?;
    }
    for r in packet
        .answers
        .iter()
        .chain(packet.authority)
        .chain(packet.additional)
    {
        name(r.name)?;
        match r.data {
            RData::Hostname(n) => name(n)?,
            RData::Mx(m) => name(m.host)?,
            RData::Srv(s) => name(s.target)?,
            RData::Soa(s) => {
                name(s.mname)?;
                name(s.rname)?;
            }
            RData::Uri(u) if u.target.contains(&0) => return Err(Error::Malformed),
            _ => {}
        }
    }
    Ok(())
}
/// Read only the production literal paths once. Missing/read-failed files retain
/// service startup with empty bytes and explicit diagnostics, as upstream does.
pub struct MachineFiles {
    /// Owned literal hosts-file bytes, or explicitly supplied embedding fixture bytes.
    pub hosts: Vec<u8>,
    /// Owned literal resolver-file bytes, retaining the exact native line syntax.
    pub resolv: Vec<u8>,
    /// Path-qualified actual read or resource failures; they are not successful loads.
    pub diagnostics: Vec<(&'static str, stdio::Error)>,
}
impl MachineFiles {
    /// Open only literal /etc/hosts and /etc/resolv.conf, with a caller-selected
    /// byte ceiling for each file. Read/limit failures are explicit diagnostics
    /// and supply empty bytes for that failed file, matching startup continuation.
    pub fn production(maximum_file_bytes: usize) -> Self {
        fn read(path: &str, maximum: usize) -> stdio::Result<Vec<u8>> {
            use std::io::Read;
            let mut file = std::fs::File::open(path)?;
            let mut bytes = Vec::new();
            let mut block = [0u8; 8192];
            loop {
                let count = file.read(&mut block)?;
                if count == 0 {
                    return Ok(bytes);
                }
                if count > maximum.saturating_sub(bytes.len()) {
                    return Err(stdio::Error::new(
                        stdio::ErrorKind::InvalidData,
                        "machine file exceeds explicit host byte capacity",
                    ));
                }
                bytes.try_reserve_exact(count).map_err(|_| {
                    stdio::Error::new(
                        stdio::ErrorKind::OutOfMemory,
                        "machine-file allocation capacity",
                    )
                })?;
                bytes.extend_from_slice(&block[..count]);
            }
        }
        let mut diagnostics = Vec::new();
        let mut load = |path: &'static str| match read(path, maximum_file_bytes) {
            Ok(bytes) => bytes,
            Err(error) => {
                diagnostics.push((path, error));
                Vec::new()
            }
        };
        let hosts = load("/etc/hosts");
        let resolv = load("/etc/resolv.conf");
        Self {
            hosts,
            resolv,
            diagnostics,
        }
    }
}

#[cfg(test)]
mod accepted_stream_tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Real accepted native flags are finite regression assertions"
    )]
    use super::*;
    #[test]
    fn canonical_acceptance_options_before_admission() -> Result<(), Box<dyn std::error::Error>> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let listener =
                    tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
                let _peer = tokio::net::TcpStream::connect(listener.local_addr()?).await?;
                let mut cursor = 0;
                let event = std::future::poll_fn(|cx| {
                    poll_network(
                        cx,
                        &[Listener::Tcp(&listener)],
                        &mut [],
                        &mut cursor,
                        Limits::default(),
                        true,
                        true,
                    )
                })
                .await?;
                let NetEvent::Accept(accepted) = event else {
                    return Err("expected owned TCP accept".into());
                };
                assert!(accepted.diagnostics().is_empty());
                let (stream, peer, _) = accepted.into_parts();
                assert!(matches!(peer, PeerAddress::Tcp(_)));
                let native = socket2::SockRef::from(&stream);
                assert!(native.nonblocking()?);
                assert!(
                    native.tcp_nodelay()?,
                    "official accepted TCP_NODELAY must be set before core admission"
                );
                Ok(())
            })
    }
}
