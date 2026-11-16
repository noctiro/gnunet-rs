//! Single-dispatch IP Helper effects with explicit synchronous-return evidence.
use crate::{
    Action, Effect, RouteCompletion, RouteOutcome, RouteProgress, RouteSubmission, Timing,
};
use gnunet_native::wintun::{InterfacePort, Route};
use std::{
    future::{Future, poll_fn},
    io,
    task::{Context, Poll},
};
use tokio::time::Instant;
/// One original caller-driven native route request. No device/session/DLL is
/// retained. The synchronous native call may block; a deadline cannot interrupt
/// it, undo it or convert its actual result into an Unsent outcome.
#[must_use]
pub struct NativeRoute {
    effect: Option<Effect>,
    port: Option<InterfacePort>,
    submission: RouteSubmission,
}
impl NativeRoute {
    pub(crate) fn start(effect: Effect, port: InterfacePort) -> Self {
        Self {
            effect: Some(effect),
            port: Some(port),
            submission: RouteSubmission::Unsent,
        }
    }
    /// Actual original exposure classification, independent of acceptance.
    #[must_use]
    pub const fn submission(&self) -> RouteSubmission {
        self.submission
    }
    /// This backend has no control-socket write operation or write error.
    #[must_use]
    pub const fn write_error(&self) -> Option<&io::Error> {
        None
    }
    fn complete(&mut self, outcome: RouteOutcome) -> RouteProgress {
        self.port = None;
        let Some(effect) = self.effect.take() else {
            return RouteProgress::Finished;
        };
        let timing = if !effect.id().epoch().current() {
            Timing::SourceRetired
        } else if Instant::now() >= effect.deadline() {
            Timing::Late
        } else {
            Timing::Timely
        };
        RouteProgress::Complete(RouteCompletion {
            id: effect.id().clone(),
            action: effect.action().clone(),
            interface: effect.interface().clone(),
            table: effect.id().epoch().route_table(),
            deadline: effect.deadline(),
            submission: self.submission,
            outcome,
            timing,
            close_error: None,
            write_error: None,
        })
    }
    /// Retire a not-yet-dispatched request. A completed synchronous call's result
    /// has already been returned by poll and cannot be replaced by cancellation.
    pub fn cancel(&mut self) -> RouteProgress {
        self.complete(RouteOutcome::Unsent(io::Error::new(
            io::ErrorKind::Interrupted,
            "original route cancelled before dispatch",
        )))
    }
    /// Dispatch at most one actual native mutation. Native-return evidence is
    /// distinct from a Unix socket ACK and preserves the original error code.
    pub fn poll(&mut self, _cx: &mut Context<'_>) -> Poll<RouteProgress> {
        let Some(effect) = self.effect.as_ref() else {
            return Poll::Ready(RouteProgress::Finished);
        };
        if !effect.current() {
            let kind = if effect.id().epoch().current() {
                io::ErrorKind::TimedOut
            } else {
                io::ErrorKind::NotConnected
            };
            return Poll::Ready(self.complete(RouteOutcome::Unsent(io::Error::new(
                kind,
                "original route deadline/source retired before dispatch",
            ))));
        }
        let Action::Route {
            add,
            destination,
            prefix,
            gateway,
        } = *effect.action()
        else {
            return Poll::Ready(
                self.complete(RouteOutcome::Unsent(io::ErrorKind::InvalidInput.into())),
            );
        };
        let Some(port) = self.port.take() else {
            return Poll::Ready(RouteProgress::Finished);
        };
        let route = Route {
            destination,
            prefix,
            gateway,
            metric: 0,
        };
        self.submission = RouteSubmission::NativeCall;
        let result = if add {
            port.create_route(route)
        } else {
            port.delete_route(route)
        };
        Poll::Ready(self.complete(RouteOutcome::NativeReturn(result)))
    }
    /// Wait once with a caller deadline; dropping this future before dispatch
    /// preserves the original job and its finite administrative deadline.
    pub async fn drive(&mut self, until: Instant) -> RouteProgress {
        let mut wait = Box::pin(tokio::time::sleep_until(until));
        poll_fn(|cx| {
            if wait.as_mut().poll(cx).is_ready() {
                Poll::Ready(RouteProgress::WaitDeadline)
            } else {
                self.poll(cx)
            }
        })
        .await
    }
}

#[path = "windows/query.rs"]
mod query;
pub use query::RouteQuery;
