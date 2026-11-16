//! Original-key Windows route observation, never mutation or cleanup authority.
use crate::route_query_types::*;
use crate::{AdminFailure, OwnedTun};
use gnunet_native::wintun::{InterfacePort, Route, RouteLookup};
use std::{
    future::{Future, poll_fn},
    io,
    net::IpAddr,
    task::{Context, Poll},
};
use tokio::time::Instant;
/// One original caller-driven read-only IP Helper query. It retains identity,
/// never the packet session, adapter or DLL. Native calls are synchronous; their
/// result is checked against the original finite deadline after returning.
#[must_use]
pub struct RouteQuery {
    target: RouteQueryTarget,
    port: Option<InterfacePort>,
    submission: RouteQuerySubmission,
}
impl OwnedTun {
    /// Prepare an exact canonical destination/prefix/next-hop query without
    /// mutation. A successful getter is observation, never route ownership.
    pub fn query_route(
        &self,
        destination: IpAddr,
        prefix: u8,
        gateway: Option<IpAddr>,
        until: Instant,
    ) -> Result<RouteQuery, AdminFailure> {
        self.admin_source(until)?;
        crate::Action::Route {
            add: false,
            destination,
            prefix,
            gateway,
        }
        .validate()?;
        let port = self.session().adapter().port();
        port.interface()?;
        Ok(RouteQuery {
            target: RouteQueryTarget {
                epoch: self.epoch(),
                table: None,
                interface: self.info.clone(),
                destination,
                prefix,
                gateway,
                deadline: until,
            },
            port: Some(port),
            submission: RouteQuerySubmission::Unsent,
        })
    }
}
impl RouteQuery {
    /// Original immutable query identity; it is never rebound to a fresh source.
    #[must_use]
    pub const fn target(&self) -> &RouteQueryTarget {
        &self.target
    }
    /// Actual original query exposure, independent of its result.
    #[must_use]
    pub const fn submission(&self) -> RouteQuerySubmission {
        self.submission
    }
    /// This backend has no control-socket write or write error.
    #[must_use]
    pub const fn write_error(&self) -> Option<&io::Error> {
        None
    }
    fn finish(
        &mut self,
        mut outcome: RouteQueryOutcome,
        mut evidence: Option<RouteQueryEvidence>,
        mut errno: Option<i32>,
    ) -> RouteQueryProgress {
        self.port = None;
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
        RouteQueryProgress::Complete(RouteQueryCompletion {
            target: self.target.clone(),
            outcome,
            submission: self.submission,
            evidence,
            kernel_errno: errno,
            observed_at,
            close_error: None,
            write_error: None,
        })
    }
    /// Retire the not-yet-dispatched read-only query, without touching a route.
    pub fn cancel(&mut self) -> RouteQueryProgress {
        if self.port.is_none() {
            return RouteQueryProgress::Finished;
        }
        self.finish(
            RouteQueryOutcome::Unknown(RouteQueryProblem::Cancelled),
            None,
            None,
        )
    }
    /// Perform one real exact-key native lookup. Absence requires the original
    /// interface and its IP family to remain qualified after ERROR_NOT_FOUND.
    pub fn poll(&mut self, _cx: &mut Context<'_>) -> Poll<RouteQueryProgress> {
        if self.port.is_none() {
            return Poll::Ready(RouteQueryProgress::Finished);
        }
        if !self.target.epoch.current() || Instant::now() >= self.target.deadline {
            return Poll::Ready(self.finish(
                RouteQueryOutcome::Unknown(RouteQueryProblem::SourceRetired),
                None,
                None,
            ));
        }
        let Some(port) = self.port.take() else {
            return Poll::Ready(RouteQueryProgress::Finished);
        };
        self.submission = RouteQuerySubmission::NativeCall;
        let route = Route {
            destination: self.target.destination,
            prefix: self.target.prefix,
            gateway: self.target.gateway,
            metric: 0,
        };
        let (outcome, evidence, errno) = match port.find_route(route) {
            Ok(RouteLookup::Absent { errno }) => (
                RouteQueryOutcome::Absent,
                Some(RouteQueryEvidence::WindowsNativeReturn),
                Some(errno),
            ),
            Ok(RouteLookup::Present(row)) => {
                let record = RouteRecord {
                    destination: row.destination,
                    prefix: row.prefix,
                    interface: row.interface,
                    gateway: row.gateway,
                    direct: row.gateway.is_none() && !row.loopback,
                    table: None,
                    kind: None,
                    scope: None,
                    protocol: None,
                    metric: Some(row.metric),
                    windows_protocol: (row.protocol, row.origin),
                    unsupported: row.loopback,
                };
                let exact = record.destination == self.target.destination
                    && record.prefix == self.target.prefix
                    && record.interface == self.target.interface.index
                    && record.gateway == self.target.gateway
                    && !record.unsupported;
                (
                    if exact {
                        RouteQueryOutcome::Exact(record)
                    } else {
                        RouteQueryOutcome::Different(record)
                    },
                    Some(RouteQueryEvidence::WindowsNativeReturn),
                    None,
                )
            }
            Err(error) => (
                RouteQueryOutcome::Unknown(RouteQueryProblem::Kernel(error)),
                None,
                None,
            ),
        };
        Poll::Ready(self.finish(outcome, evidence, errno))
    }
    /// Wait once; dropping the borrowed future preserves the original query.
    pub async fn drive(&mut self, until: Instant) -> RouteQueryProgress {
        let mut wait = Box::pin(tokio::time::sleep_until(until));
        poll_fn(|cx| {
            if !self.target.epoch.current()
                || Instant::now() >= self.target.deadline
                || self.port.is_none()
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
