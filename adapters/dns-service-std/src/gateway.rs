//! Actual SERVICE/helper/DNSSTUB composition; every original result is matched
//! before core application. Pure phase/effect declarations never become success.
use crate::{
    core::{self, Destination, Request, Resolve, Source, Work},
    server::{Error, Event, Progress, Report, Server},
    transport::{Helper, HelperEvent, HelperExit},
};
use gnunet_dnsstub_host::{DnsStub, Event as StubEvent, Flow, RequestId};
use gnunet_service_runtime::{framing::OwnedFrame, service::Listener};
use gnunet_types::Error as Fault;
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
use zeroize::Zeroizing;
/// Original request policy, independent from per-MQ IO and caller waits.
#[derive(Clone, Copy, Debug)]
pub struct GatewayLimits {
    /// Captured helper packet through all phases, finite.
    pub request_lifetime: Duration,
    /// Native output and request hard-stop, finite; never extended by rewrites.
    pub request_hard_lifetime: Duration,
    /// Actual DNSSTUB cache count1..16.
    pub resolver_sockets: usize,
}
impl Default for GatewayLimits {
    fn default() -> Self {
        Self {
            request_lifetime: Duration::from_secs(30),
            request_hard_lifetime: Duration::from_secs(45),
            resolver_sockets: 16,
        }
    }
}
/// Actual useful gateway progress, not DNS/publication acknowledgements.
#[derive(Debug)]
pub enum GatewayProgress<'id> {
    /// One actual local source/output event.
    Activity,
    /// Actual bounded helper packet could not be admitted/parsed.
    PacketDropped(Fault),
    /// Exact original real resolver operation admitted.
    ResolverQueued {
        /// Exact original intercepted query.
        request: Request<'id>,
        /// Actual DNSSTUB operation returned by admission.
        native: RequestId,
    },
    /// The real resolver rejected admission before changing any provider state.
    /// This original request is dropped without a fabricated negative answer.
    ResolverRefused {
        /// Exact original query dropped without a fabricated answer.
        request: Request<'id>,
        /// Actual provider pre-admission failure.
        reason: gnunet_dnsstub_host::HostError,
    },
    /// Actual original datagram was malformed/mismatched, request still waits.
    ResolverDiscarded {
        /// Original actual provider request ID.
        native: RequestId,
        /// Actual mismatch, malformed packet or bounded resource refusal.
        reason: Fault,
    },
    /// Actual helper process retirement; report retains complete original status.
    HelperExited,
    /// Original shutdown is physically complete for owned processes/MQs.
    Stopped,
    /// Only caller wait budget ended.
    WaitDeadline,
}
/// Actual whole-node counters and independent original cleanup observations.
#[derive(Debug, Default)]
pub struct GatewayReport {
    /// Actual local MQ counts.
    pub ipc: Report,
    /// Actual helper raw packets read.
    pub packets: u64,
    /// Actual helper pipe queue admissions, the original official answered counter.
    pub helper_frames_queued: u64,
    /// Actual native DNSSTUB lazy socket opening failures.
    pub resolver_socket_failures: u64,
    /// Actual source-delivered DNS responses rejected by original correlation.
    pub resolver_discarded: u64,
    /// Actual non-DNS UDP helper packets rejected by the interception boundary.
    pub non_dns_udp: u64,
    /// Actual helper pipe whole frames written, no TUN/remote ACK.
    pub helper_frames_written: u64,
    /// Actual real resolver operations admitted.
    pub resolver_queries: u64,
    /// Real resolver admissions refused without affecting other requests.
    pub resolver_refusals: u64,
    /// Original valid source-bound resolver datagrams applied.
    pub resolver_answers: u64,
    /// Original DNSSTUB callback-authority evictions.
    pub resolver_evictions: u64,
    /// Actual helper wait and signal outcomes.
    pub helper_exit: Option<HelperExit>,
    /// First original fatal cause.
    pub first: Option<Error>,
    /// First independent cleanup fault.
    pub cleanup: Option<Error>,
    /// Total independent cleanup faults attempted.
    pub cleanup_count: usize,
}
struct ResolveMap<'id> {
    job: Resolve<'id>,
    native: RequestId,
}
#[derive(Clone, Copy)]
struct Span<'id> {
    request: Request<'id>,
    hard: Instant,
}
enum Captured {
    Datagram {
        request: RequestId,
        frame: OwnedFrame,
    },
    Refused {
        request: RequestId,
        reason: Fault,
    },
    SocketFailure,
    Activity,
}
/// One actual shared native SERVICE with one original helper and one DNSSTUB
/// owner. Configured DNS exits are numeric addresses, with no hidden resolver.
pub struct Gateway<'id> {
    server: Server<'id>,
    helper: Helper<'id>,
    source: Source<'id>,
    stub: DnsStub<16, 65479, 4>,
    maps: Vec<Option<ResolveMap<'id>>>,
    spans: Vec<Option<Span<'id>>>,
    limits: GatewayLimits,
    scratch: Zeroizing<Vec<u8>>,
    held_input: Option<(OwnedFrame, Instant)>,
    cursor: usize,
    class: usize,
    closing: bool,
    helper_done: bool,
    timer: Pin<Box<Sleep>>,
    report: GatewayReport,
}
struct Parts<'id> {
    stub: DnsStub<16, 65479, 4>,
    maps: Vec<Option<ResolveMap<'id>>>,
    spans: Vec<Option<Span<'id>>>,
    scratch: Vec<u8>,
}
/// Failed composition retains actual original owners; caller must physically
/// close MQs and drive the same helper's retirement rather than orphan it.
pub struct RejectedGateway<'id> {
    /// Original construction error.
    pub error: Error,
    /// Original local MQ/core owner, unchanged on rejection.
    pub server: Server<'id>,
    /// Original process/pipe owner, no fake cleanup proof.
    pub helper: Helper<'id>,
}
impl std::fmt::Debug for RejectedGateway<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RejectedDnsGateway(owners retained)")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
impl<'id> Gateway<'id> {
    /// Actual helper must already own its real process/pipes. Attaching it is not
    /// a routing-setup ACK. Resolver construction alone opens/sends no socket.
    #[expect(
        clippy::result_large_err,
        reason = "Rejected construction retains both original physical owners for explicit no-clock retirement, without a fallible error allocation"
    )]
    pub fn new(
        mut server: Server<'id>,
        mut helper: Helper<'id>,
        exit: std::net::IpAddr,
        limits: GatewayLimits,
    ) -> Result<Self, RejectedGateway<'id>> {
        if let Some(error) = helper.take_startup_error() {
            return Err(RejectedGateway {
                error: Error::Io(error),
                server,
                helper,
            });
        }
        let prepared = (|| -> Result<Parts<'id>, Error> {
            if !helper.initialized()
                || !(1..=16).contains(&limits.resolver_sockets)
                || limits.request_lifetime.is_zero()
                || limits.request_hard_lifetime < limits.request_lifetime
            {
                return Err(Fault::InvalidInput.into());
            }
            for d in [limits.request_lifetime, limits.request_hard_lifetime] {
                if Instant::now().checked_add(d).is_none() || u64::try_from(d.as_micros()).is_err()
                {
                    return Err(Fault::Overflow.into());
                }
            }
            let mut stub = DnsStub::start(limits.resolver_sockets, core::MAX_DNS_BYTES)?;
            stub.add_dns_sa(std::net::SocketAddr::new(exit, 53))?;
            let count = server.engine().request_capacity();
            let mut maps = Vec::new();
            maps.try_reserve_exact(16).map_err(|_| Fault::Capacity)?;
            maps.resize_with(16, || None);
            let mut spans = Vec::new();
            spans
                .try_reserve_exact(count)
                .map_err(|_| Fault::Capacity)?;
            spans.resize_with(count, || None);
            let mut scratch = Vec::new();
            scratch
                .try_reserve_exact(65535)
                .map_err(|_| Fault::Capacity)?;
            scratch.resize(65535, 0);
            Ok(Parts {
                stub,
                maps,
                spans,
                scratch,
            })
        })();
        let Parts {
            stub,
            maps,
            spans,
            scratch,
        } = match prepared {
            Ok(p) => p,
            Err(error) => {
                return Err(RejectedGateway {
                    error,
                    server,
                    helper,
                });
            }
        };
        let source = match server.engine_mut().attach_source() {
            Ok(source) => source,
            Err(error) => {
                return Err(RejectedGateway {
                    error: error.into(),
                    server,
                    helper,
                });
            }
        };
        Ok(Self {
            server,
            helper,
            source,
            stub,
            maps,
            spans,
            limits,
            scratch: Zeroizing::new(scratch),
            held_input: None,
            cursor: 0,
            class: 0,
            closing: false,
            helper_done: false,
            timer: Box::pin(tokio::time::sleep_until(Instant::now())),
            report: GatewayReport::default(),
        })
    }
    /// Actual captured outcomes, not a full-node/cryptographic acceptance claim.
    pub const fn report(&self) -> &GatewayReport {
        &self.report
    }
    /// Consume this original owner and retain its actual errors and helper exit
    /// report. This first performs the existing clock-free physical close; it
    /// does not wait for a child, certify firewall cleanup or synthesize an exit.
    /// A caller requiring confirmed retirement must first drive `Stopped`.
    /// An absent helper exit remains unconfirmed and the original Helper Drop
    /// fallback still runs when this consumed Gateway is dropped.
    pub fn into_report(mut self) -> GatewayReport {
        self.close(None, &mut |_| {});
        std::mem::take(&mut self.report)
    }
    /// Exact live local totals for the six upstream nonpersistent DNS statistics.
    /// The answered label means helper queue admission as in the C producer,
    /// never a TUN write, response delivery or STATISTICS processing receipt.
    pub fn statistics(&self) -> [u64; 6] {
        [
            self.report.helper_frames_queued,
            self.report.resolver_socket_failures,
            self.report.resolver_discarded,
            self.server.report().client_responses_discarded,
            self.report.non_dns_udp,
            self.report.packets,
        ]
    }
    fn cleanup(&mut self, error: Error) {
        self.report.cleanup_count = self.report.cleanup_count.saturating_add(1);
        if self.report.cleanup.is_none() {
            self.report.cleanup = Some(error)
        }
    }
    /// Physical MQs/pipes/sockets stop independently before logical settlement.
    /// Canonical clock is not sampled, and child wait/firewall cleanup stays owned.
    pub fn close(&mut self, cause: Option<Error>, observe: &mut impl FnMut(Event<'id>)) {
        if self.report.first.is_none() {
            self.report.first = cause;
        }
        if self.closing {
            return;
        }
        self.closing = true;
        if let Some(error) = self.server.close_all(observe) {
            self.cleanup(error)
        }
        self.held_input = None;
        let pending = self.helper.pending();
        self.helper.request_stop();
        if let Some((effect, written, total)) = pending {
            observe(Event::HelperOutputLost {
                effect,
                written,
                total,
            });
        }
        let _stopped = self.stub.stop();
        if let Err(e) = self.server.engine_mut().source_lost(self.source) {
            self.cleanup(e.into())
        }
        for i in 0..self.maps.len() {
            if let Some(map) = self.maps[i].take()
                && let Err(e) = self.server.engine_mut().resolve_stopped(map.job)
            {
                self.cleanup(e.into())
            }
        }
        for i in 0..self.spans.len() {
            if let Some(span) = self.spans[i].take() {
                if let Err(e) = self.server.engine_mut().abort(span.request) {
                    self.cleanup(e.into());
                }
                if let Err(e) = self.server.engine_mut().retire(span.request) {
                    self.cleanup(e.into())
                }
            }
        }
        self.report.ipc = self.server.report();
    }
    fn hard_expire(&mut self) -> Result<(), Error> {
        let now = Instant::now();
        for span in self.spans.iter().flatten() {
            if now >= span.hard {
                self.server.engine_mut().abort(span.request)?;
            }
        }
        Ok(())
    }
    fn core_work(
        &mut self,
        observe: &mut impl FnMut(Event<'id>),
        admit: bool,
    ) -> Result<Option<GatewayProgress<'id>>, Error> {
        let cap = self.server.engine().request_capacity();
        for n in 0..cap {
            let i = (self.cursor + n) % cap;
            let Some(request) = self.server.engine().request_at(i) else {
                continue;
            };
            let work = match self.server.engine_mut().next_work(request) {
                Ok(w) => w,
                Err(Fault::WouldBlock) => continue,
                Err(e) => return Err(e.into()),
            };
            match work {
                Work::Resolve(request) => {
                    if !admit {
                        continue;
                    }
                    let Some(slot) = self.maps.iter().position(Option::is_none) else {
                        continue;
                    };
                    // DNSSTUB admission does no IO and all fallible preflights
                    // precede its mutation. A refusal affects only this query.
                    let admission = match self.stub.resolve(self.server.engine().payload(request)?)
                    {
                        Ok(admission) => admission,
                        Err(reason) => {
                            self.server.engine_mut().abort(request)?;
                            self.report.resolver_refusals =
                                self.report.resolver_refusals.saturating_add(1);
                            self.cursor = (i + 1) % cap;
                            return Ok(Some(GatewayProgress::ResolverRefused { request, reason }));
                        }
                    };
                    if let Some(evicted) = admission.evicted {
                        let old = self
                            .maps
                            .iter_mut()
                            .find(|m| m.as_ref().is_some_and(|m| m.native == evicted))
                            .and_then(Option::take)
                            .ok_or(Fault::StaleGeneration)?;
                        self.server.engine_mut().resolve_stopped(old.job)?;
                        self.report.resolver_evictions =
                            self.report.resolver_evictions.saturating_add(1);
                    }
                    let job = match self.server.engine_mut().resolving(request) {
                        Ok(job) => job,
                        Err(e) => {
                            let _cancel = self.stub.resolve_cancel(admission.request);
                            return Err(e.into());
                        }
                    };
                    self.maps[slot] = Some(ResolveMap {
                        job,
                        native: admission.request,
                    });
                    self.cursor = (i + 1) % cap;
                    self.report.resolver_queries = self.report.resolver_queries.saturating_add(1);
                    return Ok(Some(GatewayProgress::ResolverQueued {
                        request,
                        native: admission.request,
                    }));
                }
                Work::Cancel(job) => {
                    let index = self
                        .maps
                        .iter()
                        .position(|m| m.as_ref().is_some_and(|m| m.job == job))
                        .ok_or(Fault::StaleGeneration)?;
                    let map = self.maps[index].as_ref().ok_or(Fault::StaleGeneration)?;
                    self.stub.resolve_cancel(map.native)?;
                    self.server.engine_mut().resolve_stopped(job)?;
                    self.maps[index] = None;
                    self.cursor = (i + 1) % cap;
                    return Ok(Some(GatewayProgress::Activity));
                }
                Work::Helper { request, source } => {
                    if !admit {
                        continue;
                    }
                    if source != self.source {
                        return Err(Fault::StaleGeneration.into());
                    }
                    if !self.helper.writable() {
                        continue;
                    }
                    let hard = self
                        .spans
                        .iter()
                        .flatten()
                        .find(|s| s.request == request)
                        .ok_or(Fault::StaleGeneration)?
                        .hard;
                    let (effect, len) = self
                        .server
                        .engine_mut()
                        .prepare_helper(request, &mut self.scratch)?;
                    let frame = match OwnedFrame::copy_from(&self.scratch[..len]) {
                        Ok(f) => f,
                        Err(e) => {
                            self.server.engine_mut().reject_prepared(effect)?;
                            return Err(e.into());
                        }
                    };
                    match self.helper.queue(effect, frame, hard) {
                        Ok(()) => {
                            self.server.engine_mut().queued(effect)?;
                            self.report.helper_frames_queued =
                                self.report.helper_frames_queued.saturating_add(1);
                        }
                        Err((e, _)) => {
                            self.server.engine_mut().reject_prepared(effect)?;
                            return Err(e);
                        }
                    }
                    self.cursor = (i + 1) % cap;
                    return Ok(Some(GatewayProgress::Activity));
                }
                Work::Close(Destination::Helper(source)) => {
                    if source != self.source {
                        return Err(Fault::StaleGeneration.into());
                    }
                    return Err(Fault::Deadline.into());
                }
                Work::Close(Destination::Client(client)) => {
                    self.server
                        .close_client(client, Fault::Deadline.into(), observe)?;
                    return Ok(Some(GatewayProgress::Activity));
                }
                Work::Retire(request) => {
                    self.server.engine_mut().retire(request)?;
                    for slot in &mut self.spans {
                        if slot.is_some_and(|s| s.request == request) {
                            *slot = None;
                            break;
                        }
                    }
                    self.cursor = (i + 1) % cap;
                    return Ok(Some(GatewayProgress::Activity));
                }
                _ => {}
            }
        }
        Ok(None)
    }
    fn helper_event(
        &mut self,
        event: HelperEvent<'id>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<GatewayProgress<'id>, Error> {
        match event {
            HelperEvent::Frame(frame) => {
                if self.held_input.is_some() {
                    return Err(Fault::Conflict.into());
                }
                let hard = Instant::now()
                    .checked_add(self.limits.request_hard_lifetime)
                    .ok_or(Fault::Overflow)?;
                self.held_input = Some((frame, hard));
                Ok(GatewayProgress::Activity)
            }
            HelperEvent::Written {
                effect,
                bytes,
                complete,
            } => {
                if bytes > 0 {
                    self.server.engine_mut().exposed(effect)?;
                }
                if complete {
                    self.server.engine_mut().written(effect)?;
                    self.report.helper_frames_written =
                        self.report.helper_frames_written.saturating_add(1);
                }
                Ok(GatewayProgress::Activity)
            }
            HelperEvent::Read(_) => Ok(GatewayProgress::Activity),
            HelperEvent::Failed(e) => Err(e.into()),
            HelperEvent::Exited(exit) => {
                self.helper_done = true;
                self.report.helper_exit = Some(exit);
                self.close(Some(Fault::Closed.into()), observe);
                Ok(GatewayProgress::HelperExited)
            }
            HelperEvent::Stopping => Ok(GatewayProgress::Activity),
        }
    }
    fn admit_input(&mut self, now: u64) -> Result<Option<GatewayProgress<'id>>, Error> {
        let Some((frame, hard)) = self.held_input.take() else {
            return Ok(None);
        };
        if Instant::now() >= hard {
            return Ok(Some(GatewayProgress::PacketDropped(Fault::Deadline)));
        }
        let duration =
            u64::try_from(self.limits.request_lifetime.as_micros()).map_err(|_| Fault::Overflow)?;
        let until = now
            .checked_add(duration)
            .filter(|n| *n != u64::MAX)
            .ok_or(Fault::Overflow)?;
        let packet = match core::helper_packet(frame.bytes()) {
            Ok(p) => p,
            Err(e) => return Ok(Some(GatewayProgress::PacketDropped(e))),
        };
        if let Ok(parsed) = gnunet_vpn::packet::Packet::parse(packet)
            && parsed.protocol() == gnunet_vpn::packet::UDP
            && (parsed.ports().is_ok_and(|p| p.1 != 53) || parsed.segment().len() < 20)
        {
            self.report.non_dns_udp = self.report.non_dns_udp.saturating_add(1);
        }
        let Some(slot) = self.spans.iter().position(Option::is_none) else {
            return Ok(Some(GatewayProgress::PacketDropped(Fault::Capacity)));
        };
        match self
            .server
            .engine_mut()
            .intercept(self.source, packet, now, until)
        {
            Ok(request) => {
                self.spans[slot] = Some(Span { request, hard });
                self.report.packets = self.report.packets.saturating_add(1);
                Ok(Some(GatewayProgress::Activity))
            }
            Err(e) => Ok(Some(GatewayProgress::PacketDropped(e))),
        }
    }
    fn poll_stub(&mut self, cx: &mut Context<'_>) -> Poll<Result<GatewayProgress<'id>, Error>> {
        let mut captured = None;
        let progress = {
            let future = self.stub.drive(None, |event, _| {
                captured = Some(match event {
                    StubEvent::Datagram(packet) => match OwnedFrame::copy_from(packet.bytes) {
                        Ok(frame) => Captured::Datagram {
                            request: packet.request,
                            frame,
                        },
                        Err(reason) => Captured::Refused {
                            request: packet.request,
                            reason,
                        },
                    },
                    StubEvent::SocketOpened { result: Err(_), .. } => Captured::SocketFailure,
                    _ => Captured::Activity,
                });
                Flow::Return
            });
            let mut future = std::pin::pin!(future);
            future.as_mut().poll(cx)
        };
        match progress {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(Error::Io(std::io::Error::other(e)))),
            Poll::Ready(Ok(_)) => match captured.ok_or(Fault::Conflict)? {
                Captured::Activity => Poll::Ready(Ok(GatewayProgress::Activity)),
                Captured::SocketFailure => {
                    self.report.resolver_socket_failures =
                        self.report.resolver_socket_failures.saturating_add(1);
                    Poll::Ready(Ok(GatewayProgress::Activity))
                }
                Captured::Refused { request, reason } => {
                    Poll::Ready(Ok(GatewayProgress::ResolverDiscarded {
                        native: request,
                        reason,
                    }))
                }
                Captured::Datagram { request, frame } => {
                    let Some(index) = self
                        .maps
                        .iter()
                        .position(|m| m.as_ref().is_some_and(|m| m.native == request))
                    else {
                        self.report.resolver_discarded =
                            self.report.resolver_discarded.saturating_add(1);
                        return Poll::Ready(Ok(GatewayProgress::ResolverDiscarded {
                            native: request,
                            reason: Fault::StaleGeneration,
                        }));
                    };
                    let job = self.maps[index].as_ref().ok_or(Fault::StaleGeneration)?.job;
                    match self.server.engine_mut().resolved(job, frame.bytes()) {
                        Ok(()) => {
                            self.stub.resolve_cancel(request)?;
                            self.maps[index] = None;
                            self.report.resolver_answers =
                                self.report.resolver_answers.saturating_add(1);
                            Poll::Ready(Ok(GatewayProgress::Activity))
                        }
                        Err(reason) => {
                            self.report.resolver_discarded =
                                self.report.resolver_discarded.saturating_add(1);
                            Poll::Ready(Ok(GatewayProgress::ResolverDiscarded {
                                native: request,
                                reason,
                            }))
                        }
                    }
                }
            },
        }
    }
    /// One caller-driven fair SERVICE/helper/resolver step, no detached worker.
    /// Native hard bounds precede canonical clock coherency or any provider wait.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        until: Option<Instant>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<GatewayProgress<'id>, Error>> {
        if self.closing {
            if self.helper_done {
                return Poll::Ready(Ok(GatewayProgress::Stopped));
            }
            if let Poll::Ready(exit) = self.helper.poll_exit(cx) {
                self.report.helper_exit = Some(exit);
                self.helper_done = true;
                return Poll::Ready(Ok(GatewayProgress::Stopped));
            }
            if let Some(until) = until {
                if Instant::now() >= until {
                    return Poll::Ready(Ok(GatewayProgress::WaitDeadline));
                }
                self.timer.as_mut().reset(until);
                if self.timer.as_mut().poll(cx).is_ready() {
                    cx.waker().wake_by_ref();
                }
            }
            return Poll::Pending;
        }
        let result = (|| {
            self.hard_expire()?;
            if let Poll::Ready(event) = self.helper.poll_native_guard(cx) {
                return Poll::Ready(self.helper_event(event, observe));
            }
            if let Poll::Ready(progress) = self.server.poll_native_guard(cx, until, observe) {
                return Poll::Ready(progress.map(|_| GatewayProgress::Activity));
            }
            if let Some(at) = self
                .spans
                .iter()
                .flatten()
                .map(|s| s.hard)
                .chain(self.held_input.as_ref().map(|(_, h)| *h))
                .chain(until)
                .min()
            {
                self.timer.as_mut().reset(at);
                if self.timer.as_mut().poll(cx).is_ready() {
                    cx.waker().wake_by_ref();
                }
            }
            if self
                .held_input
                .as_ref()
                .is_some_and(|(_, h)| Instant::now() >= *h)
            {
                self.held_input = None;
                return Poll::Ready(Ok(GatewayProgress::PacketDropped(Fault::Deadline)));
            }
            if let Some(progress) = self.core_work(observe, false)? {
                return Poll::Ready(Ok(progress));
            }
            let now = match self.server.now(cx) {
                Ok(now) => now,
                Err(Error::Protocol(Fault::NotReady)) => return Poll::Pending,
                Err(error) => return Poll::Ready(Err(error)),
            };
            self.server.engine_mut().expire(now);
            if let Some(progress) = self.admit_input(now)? {
                return Poll::Ready(Ok(progress));
            }

            if until.is_some_and(|d| Instant::now() >= d) {
                return Poll::Ready(Ok(GatewayProgress::WaitDeadline));
            }
            if let Some(work) = self.core_work(observe, true)? {
                return Poll::Ready(Ok(work));
            }
            for n in 0..3 {
                let class = (self.class + n) % 3;
                let progress = match class {
                    0 => match self.server.poll(cx, listeners, until, observe) {
                        Poll::Pending => Poll::Pending,
                        Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                        Poll::Ready(Ok(Progress::WaitDeadline)) => {
                            Poll::Ready(Ok(GatewayProgress::WaitDeadline))
                        }
                        Poll::Ready(Ok(_)) => Poll::Ready(Ok(GatewayProgress::Activity)),
                    },
                    1 => match self.helper.poll(cx) {
                        Poll::Pending => Poll::Pending,
                        Poll::Ready(e) => Poll::Ready(self.helper_event(e, observe)),
                    },
                    _ => self.poll_stub(cx),
                };
                if progress.is_ready() {
                    self.class = (class + 1) % 3;
                    return progress;
                }
            }
            let wake = self
                .spans
                .iter()
                .flatten()
                .map(|s| s.hard)
                .chain(until)
                .min();
            if let Some(wake) = wake {
                self.timer.as_mut().reset(wake);
                if self.timer.as_mut().poll(cx).is_ready() {
                    cx.waker().wake_by_ref();
                }
            }
            Poll::Pending
        })();
        match result {
            Poll::Ready(Err(error)) => {
                self.close(Some(error), observe);
                Poll::Ready(Ok(GatewayProgress::Activity))
            }
            other => other,
        }
    }
    /// Waiting never cancels/changes an original request or actual partial cursor.
    pub async fn drive(
        &mut self,
        listeners: &[Listener<'_>],
        until: Option<Instant>,
        mut observe: impl FnMut(Event<'id>),
    ) -> Result<GatewayProgress<'id>, Error> {
        poll_fn(|cx| self.poll(cx, listeners, until, &mut observe)).await
    }
}
impl Drop for Gateway<'_> {
    fn drop(&mut self) {
        self.close(None, &mut |_| {});
    }
}
