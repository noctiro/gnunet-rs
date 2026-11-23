//! Reconcile configuration on a reopened FreeBSD TUN before packet admission.
use super::super::super::{
    InterfaceFailure, QueryCancelled, QueryFailure, RouteFailure, SnapshotFailure,
    verification::Plan,
};
use crate::{
    Failure,
    lifecycle::{CancelledRoute, CancelledWatch, Cleanup, Stage},
};
use gnunet_program_host::reporting::Reporter;
use gnunet_tun_host::{
    Action, AsyncTun, Epoch, Ipv6Progress, Ipv6State, Ipv6Watch, Ipv6WatchOptions, NativeRoute,
    RouteOutcome, RouteProgress, RouteQuery, RouteQueryCompletion, RouteQueryEvidence,
    RouteQueryOutcome, RouteQueryProgress, Timing,
};
use std::{
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;

enum RouteWork {
    Query(Box<RouteQuery>),
    Add {
        action: Action,
        job: Box<NativeRoute>,
    },
}

pub(in crate::network::recovery) struct RecreatedRoutes {
    intents: Vec<Action>,
    pub(in crate::network::recovery) acknowledged: Vec<Action>,
}
impl RecreatedRoutes {
    pub(in crate::network::recovery) fn new(intents: Vec<Action>) -> Self {
        Self {
            intents,
            acknowledged: Vec::new(),
        }
    }
}

pub(in crate::network::recovery) enum RouteScope<'a> {
    Retained(&'a [Action]),
    Recreated(&'a mut RecreatedRoutes),
}

enum Phase {
    Inspect,
    RoutePreflight {
        actions: [Option<Action>; 4],
        routes: RouteSequence,
    },
    Apply {
        actions: [Option<Action>; 4],
        index: usize,
    },
    Ipv6 {
        watch: Option<Ipv6Watch>,
        added: bool,
    },
    Routes(RouteSequence),
}

pub(in crate::network::recovery) struct Provisioning {
    phase: Phase,
    epoch: Epoch,
    until: Instant,
    dad: Duration,
}

impl Provisioning {
    pub(in crate::network::recovery) fn new(epoch: Epoch, until: Instant, dad: Duration) -> Self {
        Self {
            phase: Phase::Inspect,
            epoch,
            until,
            dad,
        }
    }

    pub(in crate::network::recovery) fn poll(
        &mut self,
        cx: &mut Context<'_>,
        source: &mut AsyncTun,
        plan: &Plan,
        scope: RouteScope<'_>,
        reports: &Reporter,
    ) -> Poll<Result<(), Failure>> {
        let until = self.until;
        if Instant::now() >= until {
            return Poll::Ready(Err(gnunet_types::Error::Deadline.into()));
        }
        if !self.epoch.current() || self.epoch != source.epoch() {
            return Poll::Ready(Err(gnunet_types::Error::StaleGeneration.into()));
        }
        match &mut self.phase {
            Phase::Inspect => {
                let snapshot = source.snapshot(until, plan.options())?;
                if snapshot.epoch() != &self.epoch || snapshot.close_error().is_some() {
                    return Poll::Ready(Err(Box::new(SnapshotFailure(snapshot))));
                }
                let actions = plan.restoration_actions(&snapshot)?;
                self.phase = Phase::RoutePreflight {
                    actions,
                    routes: RouteSequence::new(RoutePass::Preflight),
                };
            }
            Phase::RoutePreflight { actions, routes } => {
                match routes.poll(cx, source, scope, &self.epoch, until, reports) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) => {
                        self.phase = Phase::Apply {
                            actions: std::mem::take(actions),
                            index: 0,
                        };
                    }
                }
            }
            Phase::Apply { actions, index } => {
                if let Some(action) = actions.get_mut(*index) {
                    if let Some(action) = action.take() {
                        apply(source, action, &self.epoch, until, reports)?;
                    }
                    *index += 1;
                } else {
                    self.phase = Phase::Ipv6 {
                        watch: None,
                        added: false,
                    };
                }
            }
            Phase::Ipv6 { watch, added } => {
                let Some((address, prefix)) = plan.ipv6 else {
                    self.phase = Phase::Routes(RouteSequence::new(RoutePass::Restore));
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                };
                if watch.is_none() {
                    let address_until = Instant::now()
                        .checked_add(self.dad)
                        .ok_or(gnunet_types::Error::Overflow)?
                        .min(until);
                    *watch = Some(source.watch_ipv6(
                        address,
                        prefix,
                        address_until,
                        Ipv6WatchOptions::default(),
                    )?);
                }
                let Some(observer) = watch.as_mut() else {
                    return Poll::Ready(Err(gnunet_types::Error::NotReady.into()));
                };
                match observer.poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ipv6Progress::Observed(sample)) => {
                        if sample.target.epoch() != &self.epoch || sample.observed_at >= until {
                            return Poll::Ready(Err(gnunet_types::Error::StaleGeneration.into()));
                        }
                        match sample.state {
                            Ipv6State::Ready => {
                                let done = observer.cancel();
                                *watch = None;
                                if matches!(&done, Ipv6Progress::Complete(actual) if actual.close_error.is_some())
                                {
                                    return Poll::Ready(Err(Box::new(CancelledWatch(done))));
                                }
                                self.phase = Phase::Routes(RouteSequence::new(RoutePass::Restore));
                            }
                            Ipv6State::Missing if !*added => {
                                apply(
                                    source,
                                    Action::Ipv6Address { address, prefix },
                                    &self.epoch,
                                    until,
                                    reports,
                                )?;
                                *added = true;
                            }
                            Ipv6State::Missing | Ipv6State::Tentative => {}
                            state => {
                                return Poll::Ready(Err(format!(
                                    "EXIT FreeBSD recovery IPv6 conflict: {state:?}"
                                )
                                .into()));
                            }
                        }
                    }
                    Poll::Ready(Ipv6Progress::Complete(done)) => {
                        *watch = None;
                        return Poll::Ready(Err(Box::new(CancelledWatch(Ipv6Progress::Complete(
                            done,
                        )))));
                    }
                    Poll::Ready(Ipv6Progress::Finished) => {
                        return Poll::Ready(Err(
                            "EXIT original FreeBSD IPv6 observation is missing".into(),
                        ));
                    }
                    Poll::Ready(_) => {}
                }
            }
            Phase::Routes(routes) => {
                return routes.poll(cx, source, scope, &self.epoch, until, reports);
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    pub(in crate::network::recovery) fn cancel(&mut self, cleanup: &Cleanup) {
        match &mut self.phase {
            Phase::RoutePreflight { routes, .. } | Phase::Routes(routes) => {
                routes.cancel(cleanup);
            }
            Phase::Ipv6 { watch, .. } => {
                if let Some(mut observer) = watch.take() {
                    let retired = observer.cancel();
                    if matches!(&retired, Ipv6Progress::Complete(done) if done.close_error.is_some())
                    {
                        cleanup.retain(Stage::Watch, Box::new(CancelledWatch(retired)));
                    }
                }
            }
            _ => {}
        }
    }
}

/// Route inventory runs before any interface changes. The second pass samples
/// the actual table again after address configuration and only then may add.
#[derive(Clone, Copy, Eq, PartialEq)]
enum RoutePass {
    Preflight,
    Restore,
}
struct RouteSequence {
    pass: RoutePass,
    index: usize,
    work: Option<RouteWork>,
}
impl RouteSequence {
    fn new(pass: RoutePass) -> Self {
        Self {
            pass,
            index: 0,
            work: None,
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        source: &mut AsyncTun,
        scope: RouteScope<'_>,
        epoch: &Epoch,
        until: Instant,
        reports: &Reporter,
    ) -> Poll<Result<(), Failure>> {
        let restore = self.pass == RoutePass::Restore;
        let Self { index, work, .. } = self;
        let (intents, mut acknowledged) = match scope {
            RouteScope::Retained(intents) => (intents, None),
            RouteScope::Recreated(routes) => {
                (routes.intents.as_slice(), Some(&mut routes.acknowledged))
            }
        };
        let Some(
            intent @ Action::Route {
                add: false,
                destination,
                prefix,
                gateway,
            },
        ) = intents.get(*index)
        else {
            return if *index == intents.len() {
                Poll::Ready(Ok(()))
            } else {
                Poll::Ready(Err(gnunet_types::Error::Conflict.into()))
            };
        };
        if work.is_none() {
            *work = Some(RouteWork::Query(Box::new(source.query_route(
                *destination,
                *prefix,
                *gateway,
                until,
            )?)));
        }
        match work.as_mut() {
            Some(RouteWork::Query(query)) => match query.poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(RouteQueryProgress::Complete(done)) => {
                    *work = None;
                    let target = done.target();
                    if target.epoch() != epoch
                        || target.table() != epoch.route_table()
                        || target.destination() != *destination
                        || target.prefix() != *prefix
                        || target.gateway() != *gateway
                    {
                        return Poll::Ready(Err(Box::new(QueryFailure(done))));
                    }
                    match classify_route(done, until)? {
                        RoutePresence::Exact if acknowledged.is_some() => {
                            return Poll::Ready(Err(gnunet_types::Error::Conflict.into()));
                        }
                        RoutePresence::Exact => *index += 1,
                        RoutePresence::Absent if !restore => *index += 1,
                        RoutePresence::Absent => {
                            // A successful native add must have a preallocated
                            // cleanup entry even if the receipt is late.
                            if let Some(added) = acknowledged.as_mut() {
                                added.try_reserve(1)?;
                            }
                            let action = Action::Route {
                                add: true,
                                destination: *destination,
                                prefix: *prefix,
                                gateway: *gateway,
                            };
                            let effect = source.plan(action.clone(), until)?;
                            *work = Some(RouteWork::Add {
                                action,
                                job: Box::new(source.route(effect)?),
                            });
                        }
                    }
                }
                Poll::Ready(RouteQueryProgress::Finished) => {
                    return Poll::Ready(Err(
                        "EXIT original FreeBSD route observation is missing".into()
                    ));
                }
                Poll::Ready(_) => {}
            },
            Some(RouteWork::Add { action, job }) => match job.poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(RouteProgress::Complete(done)) => {
                    let applied = done.id.epoch() == epoch
                        && done.table == epoch.route_table()
                        && done.action == *action
                        && matches!(done.outcome, RouteOutcome::KernelAck(Ok(())));
                    if applied && let Some(added) = acknowledged.as_mut() {
                        added.push(intent.clone());
                    }
                    let good = applied
                        && done.timing == Timing::Timely
                        && done.close_error.is_none()
                        && done.write_error.is_none();
                    *work = None;
                    if !good {
                        return Poll::Ready(Err(Box::new(RouteFailure(done))));
                    }
                    reports.debug(
                        "exit.packet.recovery.route",
                        format_args!("EXIT restored original FreeBSD route: {done:?}"),
                    );
                    *index += 1;
                }
                Poll::Ready(RouteProgress::Finished) => {
                    return Poll::Ready(Err("EXIT original FreeBSD route ACK is missing".into()));
                }
                Poll::Ready(_) => {}
            },
            None => return Poll::Ready(Err(gnunet_types::Error::NotReady.into())),
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn cancel(&mut self, cleanup: &Cleanup) {
        match self.work.take() {
            Some(RouteWork::Query(mut query)) => {
                let retired = query.cancel();
                if matches!(&retired, RouteQueryProgress::Complete(done) if done.close_error().is_some())
                {
                    cleanup.retain(Stage::Routes, Box::new(QueryCancelled(retired)));
                }
            }
            Some(RouteWork::Add { mut job, .. }) => {
                let retired = job.cancel();
                if matches!(&retired, RouteProgress::Complete(done)
                    if done.close_error.is_some() || done.write_error.is_some()
                        || matches!(done.outcome, RouteOutcome::Uncertain(_)))
                {
                    cleanup.retain(Stage::Routes, Box::new(CancelledRoute(retired)));
                }
            }
            None => {}
        }
    }
}

fn apply(
    source: &mut AsyncTun,
    action: Action,
    epoch: &Epoch,
    until: Instant,
    reports: &Reporter,
) -> Result<(), Failure> {
    let effect = source.plan(action, until)?;
    let receipt = source.apply(effect)?;
    if receipt.id().epoch() != epoch || receipt.timing() != Timing::Timely {
        return Err(Box::new(InterfaceFailure(receipt)));
    }
    reports.debug(
        "exit.packet.recovery.applied",
        format_args!("EXIT restored original FreeBSD interface configuration: {receipt:?}"),
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::network) enum RoutePresence {
    Exact,
    Absent,
}

pub(in crate::network) fn classify_route(
    done: RouteQueryCompletion,
    until: Instant,
) -> Result<RoutePresence, Failure> {
    let clean = done.write_error().is_none() && done.close_error().is_none();
    presence(
        done.outcome(),
        done.evidence(),
        clean && done.observed_at() < until,
    )
    .ok_or_else(|| Box::new(QueryFailure(done)) as Failure)
}

fn presence(
    outcome: &RouteQueryOutcome,
    evidence: Option<RouteQueryEvidence>,
    timely_clean: bool,
) -> Option<RoutePresence> {
    if evidence != Some(RouteQueryEvidence::FreeBsdDump) || !timely_clean {
        return None;
    }
    match outcome {
        RouteQueryOutcome::Exact(record)
            if record
                .flags()
                .is_some_and(|flags| flags & libc::RTF_STATIC as u32 != 0) =>
        {
            // This ledger contains acknowledged explicit adds. A connected
            // prefix created by address configuration cannot inherit its debt.
            Some(RoutePresence::Exact)
        }
        RouteQueryOutcome::Absent => Some(RoutePresence::Absent),
        RouteQueryOutcome::Exact(_)
        | RouteQueryOutcome::Different(_)
        | RouteQueryOutcome::Unknown(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gnunet_tun_host::RouteQueryProblem;

    #[test]
    fn only_a_timely_complete_original_fib_dump_can_grant_absence() {
        let absent = RouteQueryOutcome::Absent;
        let complete = Some(RouteQueryEvidence::FreeBsdDump);
        assert_eq!(
            presence(&absent, complete, true),
            Some(RoutePresence::Absent)
        );
        assert_eq!(presence(&absent, None, true), None);
        assert_eq!(presence(&absent, complete, false), None);
        let unknown = RouteQueryOutcome::Unknown(RouteQueryProblem::Ambiguous { records: 2 });
        assert_eq!(presence(&unknown, complete, true), None);
    }
}
