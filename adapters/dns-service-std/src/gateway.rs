//! Actual SERVICE/helper/DNSSTUB composition; every original result is matched
//! before core application. Pure phase/effect declarations never become success.
use crate::{
    UPSTREAM_SOCKETS, Upstream,
    core::{Request, Resolve, Source},
    packet_source::{OriginalInput, PacketSource, ReplyPermit, Retirement},
    server::{Error, Event, Progress, Report, Server},
};
use gnunet_dnsstub_host::RequestId;
use gnunet_service_runtime::{framing::OwnedFrame, service::Listener};
use gnunet_types::Error as Fault;
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
mod construction;
mod input;
mod lifecycle;
mod work;

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
            resolver_sockets: UPSTREAM_SOCKETS,
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
    /// An original route or packet output was refused without retiring the source.
    PacketRefused {
        /// Original query, or none when route qualification preceded admission.
        request: Option<Request<'id>>,
        /// Actual original pre-admission or retired-operation error.
        reason: Error,
    },
    /// One original application flow stopped without closing other flows.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    FlowStopped {
        /// Original SDK flow allocation identity.
        flow: gnunet_native::dns_proxy::FlowId,
        /// Actual local stop cause, without a fabricated DNS response.
        reason: Error,
    },
    /// A native route-table observation failed without dropping a packet or
    /// replacing the last complete interface views.
    #[cfg(windows)]
    RouteObservationFailed {
        /// Original native enumeration, clock or snapshot validation error.
        reason: std::io::Error,
    },
    /// Original packet source retired; the report retains its native receipt.
    SourceRetired,
    /// Local source retirement and MQ closure completed; no remote delivery claim.
    Stopped,
    /// Only caller wait budget ended.
    WaitDeadline,
}
/// Actual whole-node counters and independent original cleanup observations.
#[derive(Debug, Default)]
pub struct GatewayReport {
    /// Actual local MQ counts.
    pub ipc: Report,
    /// Raw packets admitted from the original packet source.
    pub packets: u64,
    /// Packet-local route/output refusals; not one of the official DNS counters.
    pub packet_refusals: u64,
    /// Failed native interface observations, independent of packet refusals.
    pub route_observation_failures: u64,
    /// Packet-source queue admissions, the official answered counter.
    pub outputs_queued: u64,
    /// Actual native DNSSTUB lazy socket opening failures.
    pub resolver_socket_failures: u64,
    /// Actual source-delivered DNS responses rejected by original correlation.
    pub resolver_discarded: u64,
    /// Actual non-DNS UDP helper packets rejected by the interception boundary.
    pub non_dns_udp: u64,
    /// Complete local pipe writes or native packet submissions; no remote ACK.
    pub outputs_written: u64,
    /// Actual real resolver operations admitted.
    pub resolver_queries: u64,
    /// Real resolver admissions refused without affecting other requests.
    pub resolver_refusals: u64,
    /// Original valid source-bound resolver datagrams applied.
    pub resolver_answers: u64,
    /// Original DNSSTUB callback-authority evictions.
    pub resolver_evictions: u64,
    /// Original process exit or device-close observation.
    pub source_retirement: Option<Retirement>,
    /// Original source generations revoked before a fresh native attachment.
    pub source_outages: u64,
    /// Replacement source generations that actually became ready.
    pub source_recoveries: u64,
    /// First closed source generation's independent retirement observations.
    pub first_source_loss: Option<Retirement>,
    /// Original upstream sockets or native connection callback retirement.
    pub upstream_retirement: Option<crate::UpstreamRetirement>,
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
struct Span<'id> {
    request: Request<'id>,
    hard: Instant,
    permit: Option<ReplyPermit<'id>>,
    #[cfg(target_os = "linux")]
    ingress: Option<gnunet_native::transparent_dns::exclusion::IngressObservation>,
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    flow: Option<gnunet_native::dns_proxy::FlowId>,
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
/// Shared native SERVICE with one original packet source and one DNSSTUB
/// owner. Configured DNS exits are numeric addresses, with no hidden resolver.
pub struct Gateway<'id> {
    server: Server<'id>,
    packets: PacketSource<'id>,
    source: Source<'id>,
    stub: Upstream,
    maps: Vec<Option<ResolveMap<'id>>>,
    spans: Vec<Option<Span<'id>>>,
    limits: GatewayLimits,
    held_input: Option<(OriginalInput, Instant)>,
    cursor: usize,
    class: usize,
    closing: bool,
    source_done: bool,
    upstream_done: bool,
    source_settled: bool,
    source_attached: bool,
    source_suspended: bool,
    timer: Pin<Box<Sleep>>,
    report: GatewayReport,
}
/// Failed composition retains actual original owners; caller must physically
/// close MQs and drive the same packet source through retirement.
pub struct RejectedGateway<'id> {
    /// Original construction error.
    pub error: Error,
    /// Original local MQ/core owner, unchanged on rejection.
    pub server: Server<'id>,
    /// Original process/pipe or native device owner, retained for retirement.
    pub packets: PacketSource<'id>,
    /// Original upstream sockets; retain until the capture filter is retired.
    pub upstream: Option<Upstream>,
}
impl std::fmt::Debug for RejectedGateway<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RejectedDnsGateway(owners retained)")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
impl<'id> Gateway<'id> {
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
            if !self.upstream_done
                && let Poll::Ready(retirement) = self.stub.poll_retirement(cx)
            {
                self.report.upstream_retirement = Some(retirement);
                self.upstream_done = true;
            }
            if self.source_done && self.upstream_done {
                self.settle_source();
                return Poll::Ready(Ok(GatewayProgress::Stopped));
            }
            if !self.source_done
                && let Poll::Ready(exit) = self.packets.poll_retirement(cx)
            {
                self.report.source_retirement = Some(exit);
                self.source_done = true;
                if self.upstream_done {
                    self.settle_source();
                    return Poll::Ready(Ok(GatewayProgress::Stopped));
                }
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
            if !self.packets.matches_upstream(&self.stub) {
                return Poll::Ready(Err(Fault::StaleGeneration.into()));
            }
            self.hard_expire()?;
            if let Poll::Ready(event) = self.packets.poll_guard(cx) {
                return Poll::Ready(self.source_event(event, observe));
            }
            if let Poll::Ready(progress) = self.poll_stub_guard(cx) {
                return Poll::Ready(progress);
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
            if !self.source_suspended
                && let Some(progress) = self.admit_input(now)?
            {
                return Poll::Ready(Ok(progress));
            }

            if until.is_some_and(|d| Instant::now() >= d) {
                return Poll::Ready(Ok(GatewayProgress::WaitDeadline));
            }
            if let Some(work) = self.core_work(observe, !self.source_suspended)? {
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
                    1 => match self
                        .packets
                        .poll(cx, self.spans.iter().any(Option::is_none))
                    {
                        Poll::Pending => Poll::Pending,
                        Poll::Ready(e) => Poll::Ready(self.source_event(e, observe)),
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
