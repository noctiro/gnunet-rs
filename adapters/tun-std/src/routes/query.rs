//! Source-bound read-only reconciliation. Get receipts never confer route ownership.
use super::*;
use crate::{AdminFailure, Epoch, OwnedTun};
use std::{net::IpAddr, time::Duration};
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
mod netlink;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use netlink as native;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as native;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
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
        _: &[u8],
    ) -> io::Result<Option<Reply>> {
        Err(io::ErrorKind::Unsupported.into())
    }
}
use crate::route_query_types::*;
impl RouteRecord {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
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
            self.table == target.table
                && self.kind == Some(super::netlink::RTN_UNICAST)
                && self.scope
                    == Some(if target.gateway.is_none() {
                        super::netlink::DIRECT_SCOPE
                    } else {
                        super::netlink::RT_SCOPE_UNIVERSE
                    })
                && self.direct == target.gateway.is_none()
        }
        #[cfg(target_os = "freebsd")]
        {
            self.table == target.table
                && self.kind == Some(super::netlink::RTN_UNICAST)
                && self.scope == Some(super::netlink::RT_SCOPE_UNIVERSE)
                && self.flags & (libc::RTF_REJECT | libc::RTF_BLACKHOLE | libc::RTF_GATEWAY) as u32
                    == if target.gateway.is_some() {
                        libc::RTF_GATEWAY as u32
                    } else {
                        0
                    }
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
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
        {
            false
        }
    }
}
#[derive(Default)]
struct Scan {
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    first: Option<RouteRecord>,
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    count: usize,
}
struct Reply {
    outcome: RouteQueryOutcome,
    evidence: RouteQueryEvidence,
    errno: Option<i32>,
}
#[derive(Clone, Copy)]
enum Scope {
    Live,
    #[cfg(target_os = "freebsd")]
    Vacant,
}
/// Exactly one original private read-only route socket/query. No background
/// worker, mutation, ownership adoption, automatic retry or rollback exists.
#[must_use]
pub struct RouteQuery {
    target: RouteQueryTarget,
    scope: Scope,
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
        let boundary = self.time_boundary(observed_at);
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
        if let Some(problem) = self.time_boundary(Instant::now()) {
            return Some(problem);
        }
        #[cfg(target_os = "freebsd")]
        if matches!(self.scope, Scope::Vacant) {
            return match crate::platform::recovery::index_unoccupied(self.target.interface.index) {
                Ok(true) => None,
                Ok(false) => Some(RouteQueryProblem::SourceRetired),
                Err(error) => Some(RouteQueryProblem::Kernel(error)),
            };
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
    fn time_boundary(&self, now: Instant) -> Option<RouteQueryProblem> {
        let expected_live = matches!(self.scope, Scope::Live);
        if self.target.epoch.current() != expected_live {
            Some(RouteQueryProblem::SourceRetired)
        } else if now >= self.target.deadline {
            Some(RouteQueryProblem::Deadline)
        } else {
            None
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
            &self.frame,
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
            if self.time_boundary(Instant::now()).is_some() || self.io.is_none() {
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
    let target = RouteQueryTarget {
        table: epoch.route_table(),
        epoch,
        interface: info,
        destination,
        prefix,
        gateway,
        deadline: until,
    };
    start(target, Scope::Live).map_err(Into::into)
}

/// Query one old FreeBSD FIB key while the original interface index is vacant.
#[cfg(target_os = "freebsd")]
pub(crate) fn query_vacant(
    epoch: Epoch,
    info: Info,
    destination: IpAddr,
    prefix: u8,
    until: Instant,
) -> io::Result<RouteQuery> {
    network(destination, prefix)?;
    if Instant::now() >= until {
        return Err(io::ErrorKind::TimedOut.into());
    }
    if epoch.current() || !crate::platform::recovery::index_unoccupied(info.index)? {
        return Err(io::Error::other(
            "old FreeBSD route scope is still occupied",
        ));
    }
    start(
        RouteQueryTarget {
            table: epoch.route_table(),
            epoch,
            interface: info,
            destination,
            prefix,
            gateway: None,
            deadline: until,
        },
        Scope::Vacant,
    )
}

fn start(target: RouteQueryTarget, scope: Scope) -> io::Result<RouteQuery> {
    tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
    let until = target.deadline;
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
        scope,
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
