//! Source-bound read-only reconciliation. Get receipts never confer route ownership.
use super::*;
use crate::{AdminFailure, Epoch, OwnedTun};
use std::{net::IpAddr, time::Duration};
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as native;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as native;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod native {
    use super::*;
    pub(super) fn prepare(_: &RouteQueryTarget, _: u32) -> io::Result<Session> {
        Err(io::ErrorKind::Unsupported.into())
    }
    pub(super) fn reply(
        _: &[u8],
        _: &RouteQueryTarget,
        _: u32,
        _: u32,
        _: &mut Scan,
    ) -> io::Result<Option<Reply>> {
        Err(io::ErrorKind::Unsupported.into())
    }
}
/// Immutable original query authority; no descriptor or route is kept alive.
#[derive(Clone, Debug)]
pub struct RouteQueryTarget {
    epoch: Epoch,
    interface: Info,
    destination: IpAddr,
    prefix: u8,
    gateway: Option<IpAddr>,
    deadline: Instant,
}
impl RouteQueryTarget {
    /// Original physical device generation.
    #[must_use]
    pub const fn epoch(&self) -> &Epoch {
        &self.epoch
    }
    /// Original actual interface name/index.
    #[must_use]
    pub const fn interface(&self) -> &Info {
        &self.interface
    }
    /// Exact canonical requested network/address, never silently masked.
    #[must_use]
    pub const fn destination(&self) -> IpAddr {
        self.destination
    }
    /// Original prefix length.
    #[must_use]
    pub const fn prefix(&self) -> u8 {
        self.prefix
    }
    /// Original requested IP gateway, None means a direct interface route.
    #[must_use]
    pub const fn gateway(&self) -> Option<IpAddr> {
        self.gateway
    }
    /// Original finite native deadline, never reset by waits/progress.
    #[must_use]
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }
}
/// Actual native route fields used for exact matching. Constructor is private;
/// caller configuration cannot be converted into a kernel-observed record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteRecord {
    destination: IpAddr,
    prefix: u8,
    interface: u32,
    gateway: Option<IpAddr>,
    direct: bool,
    flags: u32,
    table: Option<u32>,
    kind: Option<u8>,
    scope: Option<u8>,
    protocol: Option<u8>,
    metric: Option<u32>,
    unsupported: bool,
}
impl RouteRecord {
    /// Actual returned canonical route destination.
    #[must_use]
    pub const fn destination(&self) -> IpAddr {
        self.destination
    }
    /// Actual returned prefix.
    #[must_use]
    pub const fn prefix(&self) -> u8 {
        self.prefix
    }
    /// Actual native output interface, zero only when kernel supplied none.
    #[must_use]
    pub const fn interface(&self) -> u32 {
        self.interface
    }
    /// Actual IP gateway; direct status is separate so an unsupported gateway
    /// cannot accidentally masquerade as a direct interface route.
    #[must_use]
    pub const fn gateway(&self) -> Option<IpAddr> {
        self.gateway
    }
    /// Kernel record uses supported direct-interface gateway semantics.
    #[must_use]
    pub const fn direct(&self) -> bool {
        self.direct
    }
    /// Actual native route flags.
    #[must_use]
    pub const fn flags(&self) -> u32 {
        self.flags
    }
    /// Actual Linux table; macOS uses interface-scoped native routing instead.
    #[must_use]
    pub const fn table(&self) -> Option<u32> {
        self.table
    }
    /// Actual Linux RTN_* type, when applicable.
    #[must_use]
    pub const fn kind(&self) -> Option<u8> {
        self.kind
    }
    /// Actual Linux RT_SCOPE_* value, when applicable.
    #[must_use]
    pub const fn scope(&self) -> Option<u8> {
        self.scope
    }
    /// Actual Linux RTPROT_* value, never treated as proof of our ownership.
    #[must_use]
    pub const fn protocol(&self) -> Option<u8> {
        self.protocol
    }
    /// Actual Linux priority metric when present.
    #[must_use]
    pub const fn metric(&self) -> Option<u32> {
        self.metric
    }
    /// Native route style is outside supported plain interface/IP-gateway matching.
    #[must_use]
    pub const fn unsupported(&self) -> bool {
        self.unsupported
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn exact(&self, target: &RouteQueryTarget) -> bool {
        if self.destination != target.destination
            || self.prefix != target.prefix
            || self.interface != target.interface.index
            || self.gateway != target.gateway
            || self.unsupported
        {
            return false;
        }
        #[cfg(target_os = "linux")]
        {
            self.table == Some(u32::from(libc::RT_TABLE_MAIN))
                && self.kind == Some(libc::RTN_UNICAST)
                && self.scope
                    == Some(if target.gateway.is_none() {
                        libc::RT_SCOPE_LINK
                    } else {
                        libc::RT_SCOPE_UNIVERSE
                    })
                && self.direct == target.gateway.is_none()
        }
        #[cfg(target_os = "macos")]
        {
            self.flags & libc::RTF_UP as u32 != 0
                && self.flags & (libc::RTF_REJECT | libc::RTF_BLACKHOLE | libc::RTF_GATEWAY) as u32
                    == if target.gateway.is_some() {
                        libc::RTF_GATEWAY as u32
                    } else {
                        0
                    }
                && self.direct == target.gateway.is_none()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            false
        }
    }
}
/// Honest reason a read-only result could not be established.
#[derive(Debug)]
pub enum RouteQueryProblem {
    /// Original TUN epoch/name/index retired; never retry on a fresh source.
    SourceRetired,
    /// Original finite query lifetime elapsed.
    Deadline,
    /// Caller explicitly canceled this original query.
    Cancelled,
    /// Actual native errno or checked malformed/truncated/overrun response.
    Kernel(io::Error),
    /// Exact route key has multiple kernel records; no arbitrary first row wins.
    Ambiguous {
        /// Actual matching key records observed in the complete dump.
        records: usize,
    },
    /// Fixed original datagram/byte inventory bound was exceeded.
    Capacity,
}
/// Actual native outcome, bound to its privately constructed completion target.
#[derive(Debug)]
pub enum RouteQueryOutcome {
    /// Canonical network/prefix/OIF/gateway/type/table requirements all matched.
    /// This is observation only and never grants delete/ownership authority.
    Exact(RouteRecord),
    /// Complete actual kernel query proved no requested key in the queried scope.
    Absent,
    /// Kernel supplied a route with different relevant actual fields, including
    /// a broader-prefix fallback on macOS. It is never treated as Exact.
    Different(RouteRecord),
    /// Source/deadline/native/protocol/ambiguity failure, never invented absence.
    Unknown(RouteQueryProblem),
}
/// Actual complete kernel read protocol evidence; local writing is insufficient.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteQueryEvidence {
    /// Matching Linux multipart dump completed without error/interruption.
    LinuxDump,
    /// Matching macOS native RTM_GET reply, including actual native ESRCH absence.
    MacRouteReply,
}
/// Actual exposure of the immutable read-only request, separate from its reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteQuerySubmission {
    /// No query bytes admitted.
    Unsent,
    /// Complete original query frame was written; no route result implied.
    Whole {
        /// Actual complete native bytes.
        bytes: usize,
    },
    /// Positive short query write; suffix is never retried.
    Partial {
        /// Actual native bytes.
        bytes: usize,
    },
    /// Native write error; original query admission is uncertain.
    Unknown,
}
/// Actual original query settlement. Private fields prevent forging a success
/// receipt or transplanting a RouteRecord onto an unrelated fresh Epoch.
#[derive(Debug)]
pub struct RouteQueryCompletion {
    target: RouteQueryTarget,
    outcome: RouteQueryOutcome,
    submission: RouteQuerySubmission,
    evidence: Option<RouteQueryEvidence>,
    kernel_errno: Option<i32>,
    observed_at: Instant,
    close_error: Option<io::Error>,
    write_error: Option<io::Error>,
}
impl RouteQueryCompletion {
    /// Exact original source/query/deadline.
    #[must_use]
    pub const fn target(&self) -> &RouteQueryTarget {
        &self.target
    }
    /// Actual result, never proof of ownership or permanent route state.
    #[must_use]
    pub const fn outcome(&self) -> &RouteQueryOutcome {
        &self.outcome
    }
    /// Actual original query exposure.
    #[must_use]
    pub const fn submission(&self) -> RouteQuerySubmission {
        self.submission
    }
    /// Complete actual native reply evidence, absent on local/unknown settlement.
    #[must_use]
    pub const fn evidence(&self) -> Option<RouteQueryEvidence> {
        self.evidence
    }
    /// Native errno for a genuine expected absence reply, when supplied.
    #[must_use]
    pub const fn kernel_errno(&self) -> Option<i32> {
        self.kernel_errno
    }
    /// Terminal observation time; a late result is classified Unknown Deadline.
    #[must_use]
    pub const fn observed_at(&self) -> Instant {
        self.observed_at
    }
    /// Actual original write errno, retained even if a correlated error reply
    /// later establishes genuine native absence.
    #[must_use]
    pub const fn write_error(&self) -> Option<&io::Error> {
        self.write_error.as_ref()
    }
    /// Independent actual query socket close errno, never retried.
    #[must_use]
    pub const fn close_error(&self) -> Option<&io::Error> {
        self.close_error.as_ref()
    }
}
/// One bounded caller-driven read-only native action.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "One bounded original terminal kernel receipt stays by value so reporting a completed native operation cannot require another fallible heap allocation"
)]
pub enum RouteQueryProgress {
    /// Native query write returned an error; original admission may have
    /// occurred synchronously. Await its original reply/deadline without retry.
    WriteError,
    /// Complete original query entered kernel; no successful Get implied.
    Submitted {
        /// Actual written native bytes.
        bytes: usize,
    },
    /// One bounded native datagram was consumed while awaiting original completion.
    Activity {
        /// Actual read bytes.
        bytes: usize,
    },
    /// Original query socket physically closed and its actual result retained.
    Complete(RouteQueryCompletion),
    /// Caller wait ended; original query and its deadline remain retained.
    WaitDeadline,
    /// Original result was already consumed.
    Finished,
}
#[derive(Default)]
struct Scan {
    #[cfg(target_os = "linux")]
    first: Option<RouteRecord>,
    #[cfg(target_os = "linux")]
    count: usize,
}
struct Reply {
    outcome: RouteQueryOutcome,
    evidence: RouteQueryEvidence,
    errno: Option<i32>,
}
/// Exactly one original private read-only route socket/query. No background
/// worker, mutation, ownership adoption, automatic retry or rollback exists.
#[must_use]
pub struct RouteQuery {
    target: RouteQueryTarget,
    io: Option<AsyncFd<OwnedFd>>,
    frame: Vec<u8>,
    sequence: u32,
    pid: u32,
    submission: RouteQuerySubmission,
    write_error: Option<io::Error>,
    alarm: Pin<Box<Sleep>>,
    source_alarm: Pin<Box<Sleep>>,
    rx: Box<[u8; 32768]>,
    datagrams: usize,
    bytes: usize,
    scan: Scan,
}
impl OwnedTun {
    /// Begin an actual read-only exact route reconciliation on this original
    /// device. Construction/whole query writing alone never means Get Exact.
    pub fn query_route(
        &self,
        destination: IpAddr,
        prefix: u8,
        gateway: Option<IpAddr>,
        until: Instant,
    ) -> Result<RouteQuery, AdminFailure> {
        self.admin_source(until)?;
        query(
            self.epoch(),
            self.info.clone(),
            destination,
            prefix,
            gateway,
            until,
        )
    }
}
impl RouteQuery {
    /// Original source/query metadata, never rebound or renewed.
    #[must_use]
    pub const fn target(&self) -> &RouteQueryTarget {
        &self.target
    }
    /// Actual current original query exposure; never means Get completion.
    #[must_use]
    pub const fn submission(&self) -> RouteQuerySubmission {
        self.submission
    }
    /// Actual original write errno while its correlated reply is still pending.
    #[must_use]
    pub const fn write_error(&self) -> Option<&io::Error> {
        self.write_error.as_ref()
    }
    fn finish(
        &mut self,
        mut outcome: RouteQueryOutcome,
        mut evidence: Option<RouteQueryEvidence>,
        mut errno: Option<i32>,
    ) -> RouteQueryProgress {
        let observed_at = Instant::now();
        let boundary = if !self.target.epoch.current() {
            Some(RouteQueryProblem::SourceRetired)
        } else if observed_at >= self.target.deadline {
            Some(RouteQueryProblem::Deadline)
        } else {
            None
        };
        if let Some(problem) = boundary {
            outcome = RouteQueryOutcome::Unknown(problem);
            evidence = None;
            errno = None;
        }
        let Some(io) = self.io.take() else {
            return RouteQueryProgress::Finished;
        };
        let close_error = nix::unistd::close(io.into_inner())
            .err()
            .map(io::Error::from);
        RouteQueryProgress::Complete(RouteQueryCompletion {
            target: self.target.clone(),
            outcome,
            submission: self.submission,
            evidence,
            kernel_errno: errno,
            observed_at,
            close_error,
            write_error: self.write_error.take(),
        })
    }
    fn unknown(&mut self, problem: RouteQueryProblem) -> RouteQueryProgress {
        self.finish(RouteQueryOutcome::Unknown(problem), None, None)
    }
    fn boundary(&self) -> Option<RouteQueryProblem> {
        if !self.target.epoch.current() {
            return Some(RouteQueryProblem::SourceRetired);
        }
        if Instant::now() >= self.target.deadline {
            return Some(RouteQueryProblem::Deadline);
        }
        match crate::platform::index(&self.target.interface.name) {
            Ok(index) if index == self.target.interface.index => None,
            Ok(_) => Some(RouteQueryProblem::SourceRetired),
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::ENXIO | libc::ENODEV | libc::ENOENT)
                ) =>
            {
                Some(RouteQueryProblem::SourceRetired)
            }
            Err(e) => Some(RouteQueryProblem::Kernel(e)),
        }
    }
    /// Cancel only this original read-only query and physically close its socket.
    /// No mutation, rollback or replacement-source reconciliation is performed.
    pub fn cancel(&mut self) -> RouteQueryProgress {
        let why = self.boundary().unwrap_or(RouteQueryProblem::Cancelled);
        self.unknown(why)
    }
    /// One native send/receive at most, with fixed128-datagram/1MiB dump bounds.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<RouteQueryProgress> {
        if self.io.is_none() {
            return Poll::Ready(RouteQueryProgress::Finished);
        }
        if let Some(problem) = self.boundary() {
            return Poll::Ready(self.unknown(problem));
        }
        if self.alarm.as_mut().poll(cx).is_ready() {
            return Poll::Ready(self.unknown(RouteQueryProblem::Deadline));
        }
        if self.source_alarm.as_mut().poll(cx).is_ready() {
            self.source_alarm
                .as_mut()
                .reset((Instant::now() + Duration::from_millis(100)).min(self.target.deadline));
            let _armed = self.source_alarm.as_mut().poll(cx);
        }
        let Some(io) = &self.io else {
            return Poll::Ready(RouteQueryProgress::Finished);
        };
        if self.submission == RouteQuerySubmission::Unsent {
            return match write_once(io, cx, &self.frame) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(e)) => {
                    self.submission = RouteQuerySubmission::Unknown;
                    self.write_error = Some(e);
                    Poll::Ready(RouteQueryProgress::WriteError)
                }
                Poll::Ready(Ok(0)) => Poll::Ready(
                    self.unknown(RouteQueryProblem::Kernel(io::ErrorKind::WriteZero.into())),
                ),
                Poll::Ready(Ok(n)) if n != self.frame.len() => {
                    self.submission = RouteQuerySubmission::Partial { bytes: n };
                    Poll::Ready(self.unknown(RouteQueryProblem::Kernel(io::Error::other(
                        "short route query; no suffix replay",
                    ))))
                }
                Poll::Ready(Ok(bytes)) => {
                    self.submission = RouteQuerySubmission::Whole { bytes };
                    Poll::Ready(RouteQueryProgress::Submitted { bytes })
                }
            };
        }
        let bytes = match read_once(io, cx, self.rx.as_mut()) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(self.unknown(RouteQueryProblem::Kernel(e))),
            Poll::Ready(Ok(n)) => n,
        };
        if bytes == 0 {
            return Poll::Ready(self.unknown(RouteQueryProblem::Kernel(
                io::ErrorKind::UnexpectedEof.into(),
            )));
        }
        self.datagrams += 1;
        self.bytes += bytes;
        if self.datagrams > 128 || self.bytes > 1048576 {
            return Poll::Ready(self.unknown(RouteQueryProblem::Capacity));
        }
        match native::reply(
            &self.rx[..bytes],
            &self.target,
            self.sequence,
            self.pid,
            &mut self.scan,
        ) {
            Err(e) => Poll::Ready(self.unknown(RouteQueryProblem::Kernel(e))),
            Ok(None) => Poll::Ready(RouteQueryProgress::Activity { bytes }),
            Ok(Some(reply)) => {
                if let Some(problem) = self.boundary() {
                    return Poll::Ready(self.unknown(problem));
                }
                Poll::Ready(self.finish(reply.outcome, Some(reply.evidence), reply.errno))
            }
        }
    }
    /// Await one bounded step. Dropping this future preserves original query,
    /// immutable request, partial read state and original finite deadline.
    pub async fn drive(&mut self, until: Instant) -> RouteQueryProgress {
        let mut wait = Box::pin(tokio::time::sleep_until(until));
        poll_fn(|cx| {
            if !self.target.epoch.current()
                || Instant::now() >= self.target.deadline
                || self.io.is_none()
            {
                return self.poll(cx);
            }
            if wait.as_mut().poll(cx).is_ready() {
                Poll::Ready(RouteQueryProgress::WaitDeadline)
            } else {
                self.poll(cx)
            }
        })
        .await
    }
}

/// Begin the same actual correlated read-only query for an observed interface
/// bound to an original live helper epoch; it grants no route ownership.
pub(crate) fn query(
    epoch: Epoch,
    info: Info,
    destination: IpAddr,
    prefix: u8,
    gateway: Option<IpAddr>,
    until: Instant,
) -> Result<RouteQuery, AdminFailure> {
    crate::helper::check_interface(&epoch, &info, until)?;
    network(destination, prefix)?;
    if gateway.is_some_and(|g| g.is_ipv4() != destination.is_ipv4()) {
        return Err(crate::platform::invalid("query gateway family").into());
    }
    tokio::runtime::Handle::try_current().map_err(|e| io::Error::other(e.to_string()))?;
    let target = RouteQueryTarget {
        epoch,
        interface: info,
        destination,
        prefix,
        gateway,
        deadline: until,
    };
    let sequence = sequence()?;
    let session = native::prepare(&target, sequence)?;
    #[expect(
        unsafe_code,
        reason = "Private read-only query owner retains exactly one nonblocking OwnedFd unchanged through deregistration and close"
    )]
    // SAFETY: this original unique FD has no mutable replacement API. into_inner
    // deregisters before close; pending futures never take over the descriptor.
    let io = unsafe { AsyncFd::register(session.fd) }.map_err(io::Error::from)?;
    Ok(RouteQuery {
        target,
        io: Some(io),
        frame: session.frame,
        sequence,
        pid: session.pid,
        submission: RouteQuerySubmission::Unsent,
        write_error: None,
        alarm: Box::pin(tokio::time::sleep_until(until)),
        source_alarm: Box::pin(tokio::time::sleep(Duration::ZERO)),
        rx: Box::new([0; 32768]),
        datagrams: 0,
        bytes: 0,
        scan: Scan::default(),
    })
}
