//! Fresh-scope native writes; completed effects are never replayed on retry.
use super::super::{InterfaceFailure, RouteFailure, undo, verification::Plan};
use crate::Failure;
use gnunet_program_host::reporting::Reporter;
use gnunet_tun_host::{Action, AsyncTun, RouteProgress, Timing};
use std::task::{Context, Poll};
use tokio::time::Instant;

#[derive(Default)]
pub(super) struct Provisioning {
    action: usize,
    route: usize,
}
impl Provisioning {
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        source: &mut AsyncTun,
        plan: &Plan,
        until: Instant,
        added: &mut Vec<Action>,
        reports: &Reporter,
    ) -> Poll<Result<(), Failure>> {
        if Instant::now() >= until || !source.epoch().current() {
            return Poll::Ready(Err(
                "EXIT fresh-scope configuration target/source retired".into()
            ));
        }
        if self.action < 6 {
            if let Some(action) = plan.creation_action(self.action) {
                let effect = source.plan(action, until)?;
                let receipt = source.apply(effect)?;
                if receipt.timing() != Timing::Timely {
                    return Poll::Ready(Err(Box::new(InterfaceFailure(receipt))));
                }
                reports.debug(
                    "exit.packet.recovery.applied",
                    format_args!("EXIT fresh-scope native configuration: {receipt:?}"),
                );
            }
            self.action += 1;
        } else if let Some(action) = plan.creation_route(self.route) {
            // The completion ledger is reserved before the native mutation.
            added.try_reserve(1)?;
            let effect = source.plan(action, until)?;
            let mut job = source.route(effect)?;
            // The Windows route backend dispatches once synchronously and
            // returns its actual completion in this poll. It never leaves an
            // exposed job across a cancellation boundary.
            let done = match job.poll(cx) {
                Poll::Ready(RouteProgress::Complete(done)) => done,
                other => {
                    let retired = job.cancel();
                    return Poll::Ready(Err(format!("EXIT native route did not complete synchronously: {other:?}; retirement={retired:?}").into()));
                }
            };
            if done.outcome.is_success() {
                added.push(undo(&done.action)?);
            }
            if !done.outcome.is_success()
                || done.timing != Timing::Timely
                || done.close_error.is_some()
            {
                return Poll::Ready(Err(Box::new(RouteFailure(done))));
            }
            reports.debug(
                "exit.packet.recovery.route",
                format_args!("EXIT fresh-scope route completion: {done:?}"),
            );
            self.route += 1;
        } else {
            return Poll::Ready(Ok(()));
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
