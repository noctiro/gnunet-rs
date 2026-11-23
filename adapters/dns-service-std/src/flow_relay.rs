//! Bounded TCP pass-through on original native flows and caller-owned upstreams.
use gnunet_native::dns_proxy::{FlowId, MAX_TCP_CHUNK_BYTES, TcpFlow, TcpRetirement};
use std::{
    future::{Future, poll_fn},
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
use zeroize::Zeroizing;
mod pool;
mod transfer;
mod upstream;
pub use pool::{RelayPool, RelayPoolProgress};
pub use upstream::TcpUpstream;

/// Per-flow memory and absolute operation bounds; reads share the idle bound.
#[derive(Clone, Copy, Debug)]
pub struct RelayLimits {
    /// Maximum copied bytes in either direction's one retained chunk.
    pub buffer_bytes: usize,
    /// Fixed original flow-open and upstream-readiness deadline.
    pub open_timeout: Duration,
    /// Fixed write/half-close deadline; partial progress does not renew it.
    pub write_timeout: Duration,
    /// Maximum interval without observed byte or EOF activity.
    pub idle_timeout: Duration,
}
impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            buffer_bytes: 64 * 1024,
            open_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
        }
    }
}
impl RelayLimits {
    fn validate(self, now: Instant) -> io::Result<Self> {
        if !(1..=MAX_TCP_CHUNK_BYTES).contains(&self.buffer_bytes) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        for duration in [self.open_timeout, self.write_timeout, self.idle_timeout] {
            if duration.is_zero() || now.checked_add(duration).is_none() {
                return Err(io::ErrorKind::InvalidInput.into());
            }
        }
        self.buffer_bytes
            .checked_mul(2)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        Ok(self)
    }
}
/// Refused relay creation retains both original resources for explicit cleanup.
#[derive(Debug)]
pub struct RejectedRelay {
    /// Actual pre-admission failure.
    pub error: io::Error,
    /// Original unopened native flow.
    pub flow: TcpFlow,
    /// Original supplied connected upstream.
    pub upstream: TcpUpstream,
}
/// Local byte observations and independent native callback retirement.
#[derive(Debug, Default)]
pub struct RelayReport {
    /// Bytes accepted by the original upstream socket; no remote receipt implied.
    pub application_to_upstream: u64,
    /// Bytes accepted by the native flow write callback, including late completion.
    pub upstream_to_application: u64,
    /// Native upstream send admitted at local stop; its acceptance remains unknown.
    pub abandoned_upstream_send: Option<usize>,
    /// Application write still awaiting its original callback at local stop.
    pub abandoned_application_write: Option<usize>,
    /// Original application write later completed successfully after stop/deadline.
    pub late_application_write_accepted: bool,
    /// Observed original application EOF.
    pub application_eof: bool,
    /// Observed original upstream EOF.
    pub upstream_eof: bool,
    /// First I/O/deadline error, retained through callback retirement.
    pub first_error: Option<io::Error>,
    /// Original native callback loans actually retired; SDK close returns void.
    pub retirement: Option<TcpRetirement>,
    /// Original native upstream cancellation and callback loans actually retired.
    pub upstream_retirement: Option<gnunet_native::dns_proxy::ConnectionRetirement>,
}
/// A caller wait ending leaves all original operations unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayProgress {
    /// One original local operation progressed.
    Activity,
    /// Only the caller's wait ended.
    WaitDeadline,
    /// Both flow directions closed and original callback loans retired.
    Stopped,
}
struct Chunk {
    bytes: Zeroizing<Vec<u8>>,
    written: usize,
    until: Instant,
}
/// One native application TCP flow bridged without parsing or rewriting bytes.
/// The supplied upstream must target the original remote endpoint and be
/// independently qualified for provider recursion exclusion. A socket is
/// already connected; native connection readiness shares the flow-open bound.
/// This constructor neither opens a connection nor installs native policy.
pub struct TcpRelay {
    flow: TcpFlow,
    upstream: TcpUpstream,
    limits: RelayLimits,
    opening: bool,
    flow_opened: bool,
    open_until: Instant,
    idle_until: Instant,
    from_flow: Option<Chunk>,
    reading_flow: bool,
    to_flow: Zeroizing<Vec<u8>>,
    to_flow_len: usize,
    writing_flow: bool,
    write_until: Option<Instant>,
    upstream_half_closed: bool,
    shutdown_until: Option<Instant>,
    closing: bool,
    stopped: bool,
    flow_retired: bool,
    upstream_retired: bool,
    turn: bool,
    timer: Pin<Box<Sleep>>,
    report: RelayReport,
}
impl std::fmt::Debug for TcpRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpRelay")
            .field("flow", &self.flow.id())
            .field("opening", &self.opening)
            .field("closing", &self.closing)
            .field("stopped", &self.stopped)
            .finish_non_exhaustive()
    }
}
impl TcpRelay {
    /// Adopt an explicitly supplied upstream matching the original remote peer.
    ///
    /// # Errors
    /// Returns both owners on wrong peer/zone, invalid bounds or allocation/open refusal.
    ///
    /// # Panics
    /// Requires an entered Tokio runtime with time enabled.
    #[expect(
        clippy::result_large_err,
        reason = "Pre-admission errors preserve original flow and socket owners without another allocation"
    )]
    pub fn new(
        mut flow: TcpFlow,
        upstream: TcpUpstream,
        limits: RelayLimits,
    ) -> Result<Self, RejectedRelay> {
        let now = Instant::now();
        let prepared = (|| {
            let limits = limits.validate(now)?;
            if !upstream.matches_flow(&flow)? {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "TCP upstream does not belong to the original flow or endpoint",
                ));
            }
            let mut to_flow = Zeroizing::new(Vec::new());
            to_flow
                .try_reserve_exact(limits.buffer_bytes)
                .map_err(|_| io::Error::other("TCP relay buffer allocation refused"))?;
            if to_flow.capacity() > limits.buffer_bytes {
                return Err(io::Error::other(
                    "TCP relay buffer exceeds configured bound",
                ));
            }
            to_flow.resize(limits.buffer_bytes, 0);
            flow.begin_open()?;
            Ok((limits, to_flow))
        })();
        let (limits, to_flow) = match prepared {
            Ok(parts) => parts,
            Err(error) => {
                return Err(RejectedRelay {
                    error,
                    flow,
                    upstream,
                });
            }
        };
        Ok(Self {
            flow,
            upstream,
            limits,
            opening: true,
            flow_opened: false,
            open_until: now + limits.open_timeout,
            idle_until: now + limits.idle_timeout,
            from_flow: None,
            reading_flow: false,
            to_flow,
            to_flow_len: 0,
            writing_flow: false,
            write_until: None,
            upstream_half_closed: false,
            shutdown_until: None,
            closing: false,
            stopped: false,
            flow_retired: false,
            upstream_retired: false,
            turn: false,
            timer: Box::pin(tokio::time::sleep_until(now)),
            report: RelayReport::default(),
        })
    }
    /// Original non-reused native flow identity.
    pub fn id(&self) -> FlowId {
        self.flow.id()
    }
    /// Current observations; missing retirement is explicitly unconfirmed.
    pub const fn report(&self) -> &RelayReport {
        &self.report
    }
    /// Stop admission and retain native callback loans for subsequent polling.
    pub fn close(&mut self) {
        if self.closing {
            return;
        }
        self.closing = true;
        self.report.abandoned_upstream_send = self.upstream.pending_send();
        if self.writing_flow {
            self.report.abandoned_application_write = Some(self.to_flow_len);
        }
        self.flow.request_close();
        self.upstream.close();
        self.from_flow = None;
        self.to_flow.fill(0);
    }
    /// Retain current observations without waiting or certifying native close.
    pub fn into_report(mut self) -> RelayReport {
        self.close();
        std::mem::take(&mut self.report)
    }
    fn fail(&mut self, error: io::Error) {
        if self.report.first_error.is_none() {
            self.report.first_error = Some(error);
        }
        self.close();
    }
    fn activity(&mut self) {
        self.idle_until = Instant::now() + self.limits.idle_timeout;
    }
    /// Drive the same operations after canceled waits; no task is spawned.
    pub async fn drive(&mut self, until: Option<Instant>) -> RelayProgress {
        poll_fn(|cx| self.poll(cx, until)).await
    }
    /// Poll original open, duplex byte transfer, half-close and callback retirement.
    pub fn poll(&mut self, cx: &mut Context<'_>, until: Option<Instant>) -> Poll<RelayProgress> {
        if self.stopped {
            return Poll::Ready(RelayProgress::Stopped);
        }
        let result = self.step(cx);
        if let Err(error) = result {
            self.fail(error);
            return Poll::Ready(RelayProgress::Activity);
        }
        if self.stopped {
            return Poll::Ready(RelayProgress::Stopped);
        }
        if matches!(result, Ok(true)) {
            return Poll::Ready(RelayProgress::Activity);
        }
        let now = Instant::now();
        if until.is_some_and(|until| now >= until) {
            return Poll::Ready(RelayProgress::WaitDeadline);
        }
        let wake = if self.closing {
            until
        } else {
            [
                Some(self.idle_until),
                self.opening.then_some(self.open_until),
                self.write_until,
                self.shutdown_until,
                self.from_flow.as_ref().map(|chunk| chunk.until),
                until,
            ]
            .into_iter()
            .flatten()
            .min()
        };
        if let Some(wake) = wake {
            self.timer.as_mut().reset(wake);
            if self.timer.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
        Poll::Pending
    }
}
impl Drop for TcpRelay {
    fn drop(&mut self) {
        self.close();
    }
}
fn same_endpoint(original: std::net::SocketAddr, actual: std::net::SocketAddr) -> bool {
    match (original, actual) {
        (std::net::SocketAddr::V4(a), std::net::SocketAddr::V4(b)) => a == b,
        (std::net::SocketAddr::V6(a), std::net::SocketAddr::V6(b)) => {
            a.ip() == b.ip() && a.port() == b.port() && a.scope_id() == b.scope_id()
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests;
