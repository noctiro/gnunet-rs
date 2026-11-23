//! Real original TUN administration and correlated finite kernel transactions.
use crate::{
    Failure,
    foreground::{Exit, Stop},
    lifecycle::{Cleanup, Stage},
    settings::{Settings, TunMode},
};
use gnunet_tun_host::{
    Action, Ipv6Progress, Ipv6State, Ipv6Watch, Ipv6WatchOptions, NativeRoute, RouteCompletion,
    RouteOutcome, RouteProgress, Timing,
};
use std::{future::poll_fn, task::Poll};
use tokio::time::Instant;
pub(super) fn target(d: std::time::Duration) -> Result<Instant, Failure> {
    Instant::now()
        .checked_add(d)
        .ok_or_else(|| "native deadline overflow".into())
}
pub(super) mod device;
#[cfg(any(windows, target_os = "freebsd"))]
pub(super) mod recovery;
mod verification;
pub(super) use device::open;

struct RouteGuard {
    owner: NativeRoute,
    complete: bool,
    reports: gnunet_program_host::reporting::Reporter,
    cleanup: Cleanup,
}
impl Drop for RouteGuard {
    fn drop(&mut self) {
        if !self.complete {
            let retired = self.owner.cancel();
            self.reports.debug(
                "exit.route.cancelled",
                format_args!("EXIT actual original route cancel={retired:?}"),
            );
            self.cleanup.retain(
                Stage::Routes,
                Box::new(crate::lifecycle::CancelledRoute(retired)),
            );
        }
    }
}
struct WatchGuard {
    owner: Option<Ipv6Watch>,
    reports: gnunet_program_host::reporting::Reporter,
    cleanup: Cleanup,
}
impl Drop for WatchGuard {
    fn drop(&mut self) {
        if let Some(watch) = &mut self.owner {
            let retired = watch.cancel();
            self.reports.debug(
                "exit.ipv6.cancelled",
                format_args!("EXIT actual original DAD cancel={retired:?}"),
            );
            self.cleanup.retain(
                Stage::Watch,
                Box::new(crate::lifecycle::CancelledWatch(retired)),
            );
        }
    }
}
async fn route(
    owner: NativeRoute,
    stop: &mut Stop,
    interruptible: bool,
) -> Result<RouteCompletion, Failure> {
    let mut guarded = RouteGuard {
        owner,
        complete: false,
        reports: stop.reports.clone(),
        cleanup: stop.cleanup.clone(),
    };
    loop {
        let step = poll_fn(|cx| {
            if interruptible {
                match stop.poll(cx) {
                    Poll::Ready(Ok(())) => return Poll::Ready(Ok(guarded.owner.cancel())),
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {}
                }
            }
            guarded.owner.poll(cx).map(Ok)
        })
        .await?;
        match step {
            RouteProgress::Complete(value) => {
                guarded.complete = true;
                return Ok(value);
            }
            RouteProgress::Finished => return Err("route result already consumed".into()),
            RouteProgress::Submitted { .. }
            | RouteProgress::WriteError { .. }
            | RouteProgress::Activity { .. }
            | RouteProgress::WaitDeadline => tokio::task::yield_now().await,
        }
    }
}
fn undo(action: &Action) -> Result<Action, Failure> {
    match action {
        Action::Route {
            destination,
            prefix,
            gateway,
            ..
        } => Ok(Action::Route {
            add: false,
            destination: *destination,
            prefix: *prefix,
            gateway: *gateway,
        }),
        _ => Err("only a route ACK creates a route cleanup obligation".into()),
    }
}
pub(super) async fn configure(
    driver: &mut Exit<'_, '_, '_>,
    settings: &Settings,
    stop: &mut Stop,
    added: &mut Vec<Action>,
    startup: Instant,
) -> Result<Option<Ipv6Watch>, Failure> {
    if settings.mode == TunMode::None {
        return Ok(None);
    }
    let configuration_until = target(settings.configuration)?.min(startup);
    let until = driver
        .helper_initial_deadline()
        .map_or(configuration_until, |original| {
            original.min(configuration_until)
        });
    let readonly = driver.uses_helper();
    #[cfg(windows)]
    let readonly = readonly || settings.mode == TunMode::Existing;
    if readonly {
        return verify_existing(driver, settings, stop, until).await;
    }
    let mut actions = Vec::new();
    actions.try_reserve_exact(6)?;
    #[cfg(unix)]
    actions.push(Action::Mtu(settings.mtu));
    #[cfg(windows)]
    {
        if settings.ipv4.is_some() {
            actions.push(Action::IpMtu {
                version: gnunet_tun_host::Version::V4,
                bytes: settings.mtu,
            });
        }
        if settings.ipv6.is_some() {
            actions.push(Action::IpMtu {
                version: gnunet_tun_host::Version::V6,
                bytes: settings.mtu,
            });
        }
    }
    if let Some((a, m, _)) = settings.ipv4 {
        actions.push(Action::Ipv4Address(a));
        actions.push(Action::Ipv4Netmask(m));
    }
    if let Some((address, prefix)) = settings.ipv6 {
        actions.push(Action::Ipv6Address { address, prefix });
    }
    actions.push(Action::LinkUp(true));
    for action in actions {
        stop.check()?;
        let effect = driver.plan_tun_action(action, until)?;
        let applied = driver.apply_tun_action(effect)?;
        stop.reports.debug(
            "exit.interface.applied",
            format_args!("EXIT actual native interface applied: {applied:?}"),
        );
        if applied.timing() != Timing::Timely {
            return Err(Box::new(InterfaceFailure(applied)));
        }
    }
    for action in &settings.routes {
        stop.check()?;
        let effect = driver.plan_tun_action(action.clone(), until)?;
        let completion = route(driver.route_tun_action(effect)?, stop, true).await?;
        // A late successful ACK still changed the kernel and requires cleanup.
        if completion.outcome.is_success() {
            added.push(undo(&completion.action)?);
        }
        let timely = completion.timing == Timing::Timely;
        stop.reports.debug(
            "exit.route.complete",
            format_args!("EXIT actual route result: {completion:?}"),
        );
        if !completion.outcome.is_success() || completion.close_error.is_some() || !timely {
            return Err(Box::new(RouteFailure(completion)));
        }
    }
    if let Some((address, prefix)) = settings.ipv6 {
        let watcher = driver.watch_tun_ipv6(
            address,
            prefix,
            target(settings.dad)?.min(until),
            Ipv6WatchOptions::default(),
        )?;
        let mut guarded = WatchGuard {
            owner: Some(watcher),
            reports: stop.reports.clone(),
            cleanup: stop.cleanup.clone(),
        };
        loop {
            let watcher = guarded
                .owner
                .as_mut()
                .ok_or("missing original DAD observer")?;
            let step = poll_fn(|cx| {
                match stop.poll(cx) {
                    Poll::Ready(Ok(())) => {
                        return Poll::Ready(Err("shutdown during IPv6 DAD".into()));
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {}
                }
                watcher.poll(cx).map(Ok::<_, Failure>)
            })
            .await?;
            match step {
                Ipv6Progress::Observed(sample) => {
                    stop.reports.debug(
                        "exit.ipv6.observed",
                        format_args!("EXIT actual IPv6 observation: {sample:?}"),
                    );
                    match sample.state {
                        Ipv6State::Ready => return Ok(guarded.owner.take()),
                        Ipv6State::Tentative => {}
                        _ => {
                            return Err(
                                format!("IPv6 address is not ready: {:?}", sample.state).into()
                            );
                        }
                    }
                }
                Ipv6Progress::Complete(result) => {
                    return Err(Box::new(crate::lifecycle::CancelledWatch(
                        Ipv6Progress::Complete(result),
                    )));
                }
                Ipv6Progress::Finished => {
                    return Err("IPv6 DAD observer lost its completion".into());
                }
                Ipv6Progress::Activity { .. } | Ipv6Progress::WaitDeadline => {}
            }
            tokio::task::yield_now().await;
        }
    }
    Ok(None)
}
pub(super) async fn cleanup(
    driver: &mut Exit<'_, '_, '_>,
    added: &mut Vec<Action>,
    stop: &mut Stop,
    until: Instant,
) -> Result<(), Failure> {
    let mut failure = None;
    let mut remaining = added.len();
    while remaining != 0 {
        remaining -= 1;
        // Keep the original cleanup obligation through errors and cancellation.
        // There are at most 32 routes; preserving reverse order needs no new allocation.
        let action = added[remaining].clone();
        // Each deletion uses the same global shutdown target; no per-route extension.
        let result = async {
            #[cfg(target_os = "freebsd")]
            let Some(original) = scope_before_delete(driver, &action, until).await? else {
                return Ok(());
            };
            let effect = driver.plan_tun_action(action, until)?;
            let value = route(driver.route_tun_action(effect)?, stop, false).await?;
            stop.reports.debug(
                "exit.route.removed",
                format_args!("EXIT actual route cleanup: {value:?}"),
            );
            if !value.outcome.is_success() || value.close_error.is_some() {
                return Err(Box::new(RouteFailure(value)) as Failure);
            }
            #[cfg(target_os = "freebsd")]
            if value.id.epoch() != &original
                || value.table != original.route_table()
                || value.write_error.is_some()
            {
                return Err(Box::new(RouteFailure(value)) as Failure);
            }
            Ok(())
        }
        .await;
        if let Err(e) = result {
            stop.reports.warning(
                "exit.route.remove.failed",
                format_args!("EXIT original route cleanup failure: {e}"),
            );
            stop.cleanup.retain(Stage::Routes, e);
            if failure.is_none() {
                failure = Some(gnunet_types::Error::OutcomeUnknown.into());
            }
        } else {
            added.remove(remaining);
        }
    }
    match failure {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

#[cfg(target_os = "freebsd")]
async fn scope_before_delete(
    driver: &Exit<'_, '_, '_>,
    action: &Action,
    until: Instant,
) -> Result<Option<gnunet_tun_host::Epoch>, Failure> {
    use gnunet_tun_host::RouteQueryProgress;
    let Action::Route {
        add: false,
        destination,
        prefix,
        gateway,
    } = *action
    else {
        return Err(gnunet_types::Error::Conflict.into());
    };
    let mut query = driver.query_tun_route(destination, prefix, gateway, until)?;
    let done = loop {
        match poll_fn(|cx| query.poll(cx)).await {
            RouteQueryProgress::Complete(done) => break done,
            RouteQueryProgress::Finished => {
                return Err("EXIT FreeBSD cleanup route observation is missing".into());
            }
            _ => tokio::task::yield_now().await,
        }
    };
    let original = done.target().epoch().clone();
    match recovery::classify_route(done, until)? {
        recovery::RoutePresence::Exact => Ok(Some(original)),
        recovery::RoutePresence::Absent => Ok(None),
    }
}

#[derive(Debug)]
struct QueryFailure(gnunet_tun_host::RouteQueryCompletion);
impl std::fmt::Display for QueryFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "original EXIT route observation: {:?}", self.0)
    }
}
impl std::error::Error for QueryFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0
            .write_error()
            .or(self.0.close_error())
            .map(|e| e as &dyn std::error::Error)
    }
}
#[derive(Debug)]
struct SnapshotFailure(gnunet_tun_host::NativeSnapshot);
impl std::fmt::Display for SnapshotFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "actual EXIT kernel snapshot mismatch/failure: {:?}",
            self.0
        )
    }
}
impl std::error::Error for SnapshotFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.close_error().map(|e| e as &dyn std::error::Error)
    }
}
async fn verify_existing(
    driver: &mut Exit<'_, '_, '_>,
    settings: &Settings,
    stop: &mut Stop,
    until: Instant,
) -> Result<Option<Ipv6Watch>, Failure> {
    if driver.uses_helper() {
        poll_fn(|cx| {
            match stop.poll(cx) {
                Poll::Ready(Ok(())) => {
                    return Poll::Ready(Err(
                        "EXIT stopped during original helper qualification".into()
                    ));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }
            driver.poll_native_guard(cx, &mut |e| {
                crate::foreground::observe(e, &stop.reports, &stop.cleanup)
            })?;
            if stop.reports.failed() {
                return Poll::Ready(Err(
                    "EXIT selected Logger failed during helper qualification".into(),
                ));
            }
            driver
                .poll_helper_prepare(cx)
                .map_err(|e| Box::new(e) as Failure)
        })
        .await?;
    }
    stop.check()?;
    let plan = verification::Plan::new(settings)?;
    let snapshot = plan.snapshot(
        driver.snapshot_tun(until, plan.options())?,
        driver.uses_helper(),
    )?;
    stop.reports.debug(
        "exit.interface.kernel",
        format_args!(
            "EXIT actual kernel snapshot={snapshot:?}; read-only observation; no configuration or ownership receipt"
        ),
    );
    stop.check()?;
    for key in &plan.routes {
        stop.check()?;
        let mut query = driver.query_tun_route(key.destination, key.prefix, key.gateway, until)?;
        let result = loop {
            let step = poll_fn(|cx| {
                match stop.poll(cx) {
                    Poll::Ready(Ok(())) => {
                        return Poll::Ready(Err("EXIT stopped during original route query".into()));
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {}
                }
                driver.poll_native_guard(cx, &mut |e| {
                    crate::foreground::observe(e, &stop.reports, &stop.cleanup)
                })?;
                if stop.reports.failed() {
                    return Poll::Ready(Err(
                        "EXIT selected Logger failed during route observation".into(),
                    ));
                }
                query.poll(cx).map(Ok::<_, Failure>)
            })
            .await;
            match step {
                Ok(gnunet_tun_host::RouteQueryProgress::Complete(done)) => break Ok(done),
                Ok(gnunet_tun_host::RouteQueryProgress::Finished) => {
                    break Err("original EXIT route query terminal missing".into());
                }
                Ok(_) => tokio::task::yield_now().await,
                Err(error) => break Err(error),
            }
        };
        let done = match result {
            Ok(done) => done,
            Err(error) => {
                let retired = query.cancel();
                stop.reports.debug(
                    "exit.route.query.cancelled",
                    format_args!("EXIT actual route query retirement={retired:?}"),
                );
                stop.cleanup
                    .retain(Stage::Routes, Box::new(QueryCancelled(retired)));
                return Err(error);
            }
        };
        let done = verification::route(done, until)?;
        stop.reports.debug(
            "exit.route.observed",
            format_args!("EXIT actual exact readonly route={done:?}; no route-add receipt"),
        );
    }
    if let Some((address, bits)) = settings.ipv6 {
        stop.check()?;
        let dad = target(settings.dad)?.min(until);
        let mut watch = driver.watch_tun_ipv6(address, bits, dad, Ipv6WatchOptions::default())?;
        loop {
            let step = poll_fn(|cx| {
                match stop.poll(cx) {
                    Poll::Ready(Ok(())) => {
                        return Poll::Ready(Err("EXIT stopped during original helper DAD".into()));
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {}
                }
                driver.poll_native_guard(cx, &mut |e| {
                    crate::foreground::observe(e, &stop.reports, &stop.cleanup)
                })?;
                if stop.reports.failed() {
                    return Poll::Ready(Err("EXIT selected Logger failed during DAD".into()));
                }
                watch.poll(cx).map(Ok::<_, Failure>)
            })
            .await;
            match step {
                Ok(Ipv6Progress::Observed(sample)) if sample.state == Ipv6State::Ready => {
                    return Ok(Some(watch));
                }
                Ok(Ipv6Progress::Observed(sample)) if sample.state == Ipv6State::Tentative => {}
                Ok(Ipv6Progress::Observed(sample)) => {
                    let retired = watch.cancel();
                    stop.cleanup.retain(
                        Stage::Watch,
                        Box::new(crate::lifecycle::CancelledWatch(retired)),
                    );
                    return Err(format!("actual helper IPv6 address not ready: {sample:?}").into());
                }
                Ok(Ipv6Progress::Complete(done)) => {
                    return Err(Box::new(crate::lifecycle::CancelledWatch(
                        Ipv6Progress::Complete(done),
                    )));
                }
                Ok(Ipv6Progress::Finished) => {
                    return Err("original helper DAD terminal missing".into());
                }
                Ok(_) => {}
                Err(error) => {
                    let retired = watch.cancel();
                    stop.cleanup.retain(
                        Stage::Watch,
                        Box::new(crate::lifecycle::CancelledWatch(retired)),
                    );
                    return Err(error);
                }
            }
            tokio::task::yield_now().await;
        }
    }
    Ok(None)
}

#[derive(Debug)]
struct InterfaceFailure(gnunet_tun_host::NativeApplied);
impl std::fmt::Display for InterfaceFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            out,
            "EXIT interface completion after its original deadline: {:?}",
            self.0
        )
    }
}
impl std::error::Error for InterfaceFailure {}

#[derive(Debug)]
struct RouteFailure(gnunet_tun_host::RouteCompletion);
impl std::fmt::Display for RouteFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "original EXIT route transaction: {:?}", self.0)
    }
}
impl std::error::Error for RouteFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0.outcome {
            RouteOutcome::KernelAck(Err(e))
            | RouteOutcome::NativeReturn(Err(e))
            | RouteOutcome::Unsent(e)
            | RouteOutcome::Uncertain(e) => Some(e),
            _ => self
                .0
                .close_error
                .as_ref()
                .map(|e| e as &dyn std::error::Error),
        }
    }
}
#[derive(Debug)]
struct QueryCancelled(gnunet_tun_host::RouteQueryProgress);
impl std::fmt::Display for QueryCancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "original EXIT route query cancellation: {:?}", self.0)
    }
}
impl std::error::Error for QueryCancelled {}
