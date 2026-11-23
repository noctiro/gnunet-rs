//! Bounded recovery above a retired native packet epoch.
use super::verification::Plan;
use crate::{Failure, foreground::Stop, lifecycle::Cleanup, settings::Settings};
use gnunet_exit_host::runtime::{Event, Report as NativeReport};
use gnunet_program_host::reporting::Reporter;
use gnunet_tun_host::{Action, AsyncTun, Epoch, Loss, RecoveryBudget};
#[cfg(target_os = "freebsd")]
use gnunet_tun_host::{FreeBsdRecovery as OriginalRecovery, FreeBsdRecreate, FreeBsdReopen};
#[cfg(windows)]
use gnunet_tun_host::{
    WintunRecovery as OriginalRecovery, WintunReopen, WintunReplacementKind, WintunScopeRetirement,
};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;
mod admission;
#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(windows)]
mod provisioning;
mod verification;
#[cfg(windows)]
mod windows;
pub(crate) use admission::Admission;
use admission::Prepared;
#[cfg(target_os = "freebsd")]
use freebsd::{Provisioning as FreeBsdProvisioning, RecreatedRoutes, RouteScope};
#[cfg(target_os = "freebsd")]
pub(super) use freebsd::{RoutePresence, classify_route};
#[cfg(windows)]
use provisioning::Provisioning;
use verification::Verification;
#[cfg(windows)]
use windows::Restart;

#[derive(Debug, Default)]
pub(crate) struct Report {
    losses: u64,
    attempts: u64,
    restored: u64,
    first: Option<Loss>,
    last: Option<Loss>,
    first_error: Option<Failure>,
    last_error: Option<Failure>,
    #[cfg(windows)]
    first_scope: Option<WintunScopeRetirement>,
    #[cfg(windows)]
    last_scope: Option<WintunScopeRetirement>,
}
impl Report {
    fn loss(&mut self, loss: Loss) {
        self.losses = self.losses.saturating_add(1);
        if self.first.is_none() {
            self.first = Some(loss);
        } else {
            self.last = Some(loss);
        }
    }
    fn error(&mut self, error: Failure) {
        if self.first_error.is_none() {
            self.first_error = Some(error);
        } else {
            self.last_error = Some(error);
        }
    }
}
struct Candidate {
    verification: Verification,
    source: Option<AsyncTun>,
    cleanup: Cleanup,
    reports: Reporter,
    #[cfg(target_os = "freebsd")]
    provisioning: Option<FreeBsdProvisioning>,
    #[cfg(target_os = "freebsd")]
    recreated_routes: Option<RecreatedRoutes>,
    #[cfg(windows)]
    provisioning: Option<Provisioning>,
    #[cfg(windows)]
    owned_routes: Vec<Action>,
}
impl Drop for Candidate {
    fn drop(&mut self) {
        self.verification.cancel(&self.cleanup, &self.reports);
        #[cfg(target_os = "freebsd")]
        if let Some(provisioning) = &mut self.provisioning {
            provisioning.cancel(&self.cleanup);
        }
        #[cfg(target_os = "freebsd")]
        if let Some(recreated) = self.recreated_routes.take() {
            retain_candidate_routes(
                &self.cleanup,
                self.source.as_ref().map(AsyncTun::epoch),
                recreated.acknowledged,
            );
        }
        #[cfg(target_os = "freebsd")]
        if let Some(source) = self.source.take() {
            admission::close_uninstalled(source, &self.cleanup, &self.reports);
        }
        #[cfg(windows)]
        retain_candidate_routes(
            &self.cleanup,
            self.source.as_ref().map(AsyncTun::epoch),
            std::mem::take(&mut self.owned_routes),
        );
    }
}
enum State {
    Retained(Box<OriginalRecovery>),
    #[cfg(windows)]
    Refresh(Box<OriginalRecovery>),
    #[cfg(windows)]
    Reopen(Box<WintunReopen>),
    #[cfg(target_os = "freebsd")]
    FreeBsdReopen(Box<FreeBsdReopen>),
    #[cfg(target_os = "freebsd")]
    FreeBsdRecreate(Box<FreeBsdRecreate>),
    Candidate(Box<Candidate>),
}
pub(crate) struct Controller {
    plan: Plan,
    timeout: Duration,
    dad: Duration,
    budget: RecoveryBudget,
    state: Option<State>,
    hard: Option<(Instant, Pin<Box<tokio::time::Sleep>>)>,
    retry: Option<Pin<Box<tokio::time::Sleep>>>,
    delay: Duration,
    fatal: Option<Failure>,
    cleanup: Cleanup,
    report: Report,
    #[cfg(windows)]
    pending_scope: Option<WintunScopeRetirement>,
    #[cfg(windows)]
    reconciled: Option<Epoch>,
}
impl Controller {
    pub fn new(settings: &Settings, cleanup: Cleanup) -> Result<Self, Failure> {
        Ok(Self {
            plan: Plan::new(settings)?,
            timeout: settings.configuration,
            dad: settings.dad,
            budget: RecoveryBudget::default(),
            state: None,
            hard: None,
            retry: None,
            delay: Duration::from_millis(100),
            fatal: None,
            cleanup,
            report: Report::default(),
            #[cfg(windows)]
            pending_scope: None,
            #[cfg(windows)]
            reconciled: None,
        })
    }
    pub fn active(&self) -> bool {
        self.state.is_some() || self.fatal.is_some()
    }
    pub fn observe(&mut self, event: Event<'_>, reports: &Reporter) {
        let Event::TunLost(mut loss) = event else {
            crate::foreground::observe(event, reports, &self.cleanup);
            return;
        };
        #[cfg(windows)]
        let recovery = loss.recovery.take();
        #[cfg(target_os = "freebsd")]
        let recovery = loss.freebsd_recovery.take();
        let Some(recovery) = recovery else {
            crate::foreground::observe(Event::TunLost(loss), reports, &self.cleanup);
            return;
        };
        if self.active() || loss.close_error.is_some() || loss.epoch != *recovery.original_epoch() {
            #[cfg(windows)]
            recovery.close();
            #[cfg(target_os = "freebsd")]
            self.release_original(*recovery);
            self.fatal = Some("EXIT received conflicting original TUN recovery ownership".into());
            crate::foreground::observe(Event::TunLost(loss), reports, &self.cleanup);
            return;
        }
        reports.warning(
            "exit.packet.recovery",
            format_args!("EXIT original packet source retired; bounded session recovery: {loss:?}"),
        );
        self.report.loss(loss);
        match self
            .budget
            .begin(Instant::now(), self.timeout, Duration::from_secs(1))
        {
            Ok(hard) => {
                self.hard = Some((hard, Box::pin(tokio::time::sleep_until(hard))));
                self.state = Some(State::Retained(recovery));
                self.retry = None;
                self.delay = Duration::from_millis(100);
            }
            Err(error) => {
                #[cfg(windows)]
                recovery.close();
                #[cfg(target_os = "freebsd")]
                self.release_original(*recovery);
                self.fatal = Some(error.into());
            }
        }
    }
    pub fn healthy(&mut self, report: NativeReport, current: bool) {
        if !self.active()
            && current
            && self.budget.observe(
                Instant::now(),
                (report.tun_read, report.tun_written),
                Duration::from_secs(1),
            )
        {
            self.hard = None;
        }
    }
    pub fn admitted(&mut self, report: NativeReport) {
        self.report.restored = self.report.restored.saturating_add(1);
        self.budget
            .admitted(Instant::now(), (report.tun_read, report.tun_written));
    }
    fn failure(&mut self, error: Failure, reports: &Reporter) {
        reports.warning(
            "exit.packet.recovery.retry",
            format_args!("EXIT session recovery retains its original outage target: {error}"),
        );
        self.report.error(error);
    }
    fn retry(&mut self, state: State) {
        self.state = Some(state);
        self.retry = Some(Box::pin(tokio::time::sleep(self.delay)));
        self.delay = self.delay.saturating_mul(2).min(Duration::from_secs(1));
    }
    fn again(&mut self, state: State, error: Failure, reports: &Reporter) {
        self.failure(error, reports);
        self.retry(state);
    }
    fn candidate(
        &self,
        source: AsyncTun,
        #[cfg(windows)] kind: WintunReplacementKind,
        #[cfg(target_os = "freebsd")] provisioning: Option<FreeBsdProvisioning>,
        #[cfg(target_os = "freebsd")] recreated_routes: Option<RecreatedRoutes>,
        reports: &Reporter,
    ) -> State {
        State::Candidate(Box::new(Candidate {
            verification: Verification::new(),
            source: Some(source),
            cleanup: self.cleanup.clone(),
            reports: reports.clone(),
            #[cfg(target_os = "freebsd")]
            provisioning,
            #[cfg(target_os = "freebsd")]
            recreated_routes,
            #[cfg(windows)]
            provisioning: (kind == WintunReplacementKind::Created).then(Provisioning::default),
            #[cfg(windows)]
            owned_routes: Vec::new(),
        }))
    }
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        stop: &mut Stop,
        #[cfg(target_os = "freebsd")] owned_routes: &mut Vec<Action>,
    ) -> Poll<Result<Option<Prepared>, Failure>> {
        if let Some(error) = self.fatal.take() {
            return Poll::Ready(Err(error));
        }
        let Some((hard, alarm)) = self.hard.as_mut() else {
            return Poll::Pending;
        };
        if self.state.is_none() {
            return Poll::Pending;
        }
        if Instant::now() >= *hard || alarm.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err("EXIT original TUN recovery target expired".into()));
        }
        let hard = *hard;
        match stop.poll(cx) {
            Poll::Ready(Ok(())) => {
                return Poll::Ready(Ok(None));
            }
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => {}
        }
        if let Some(retry) = self.retry.as_mut()
            && retry.as_mut().poll(cx).is_pending()
        {
            return Poll::Pending;
        }
        self.retry = None;
        let Some(state) = self.state.take() else {
            return Poll::Pending;
        };
        match state {
            #[cfg(target_os = "freebsd")]
            State::Retained(recovery) => {
                self.begin_freebsd(*recovery, hard, owned_routes, &stop.reports)?
            }
            #[cfg(target_os = "freebsd")]
            State::FreeBsdReopen(owner) => {
                self.open_freebsd(*owner, hard, owned_routes, &stop.reports)?
            }
            #[cfg(target_os = "freebsd")]
            State::FreeBsdRecreate(owner) => {
                if self
                    .recreate_freebsd(cx, owner, hard, owned_routes, &stop.reports)?
                    .is_pending()
                {
                    return Poll::Pending;
                }
            }
            #[cfg(windows)]
            State::Retained(recovery) => {
                self.restart_wintun(*recovery, Restart::Retained, &stop.reports);
            }
            #[cfg(windows)]
            State::Refresh(recovery) => {
                self.restart_wintun(*recovery, Restart::Refresh, &stop.reports);
            }
            #[cfg(windows)]
            State::Reopen(owner) => self.reopen_wintun(*owner, hard, &stop.reports),
            State::Candidate(mut candidate) => {
                let Some(source) = candidate.source.as_mut() else {
                    return Poll::Ready(Err(
                        "EXIT recovery candidate lost its original source".into()
                    ));
                };
                #[cfg(target_os = "freebsd")]
                if let Some(provisioning) = candidate.provisioning.as_mut() {
                    let routes = match candidate.recreated_routes.as_mut() {
                        Some(routes) => RouteScope::Recreated(routes),
                        None => RouteScope::Retained(owned_routes),
                    };
                    match provisioning.poll(cx, source, &self.plan, routes, &stop.reports) {
                        Poll::Pending => {
                            self.state = Some(State::Candidate(candidate));
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => candidate.provisioning = None,
                    }
                }
                #[cfg(windows)]
                if let Some(provisioning) = candidate.provisioning.as_mut() {
                    match provisioning.poll(
                        cx,
                        source,
                        &self.plan,
                        hard,
                        &mut candidate.owned_routes,
                        &stop.reports,
                    ) {
                        Poll::Pending => {
                            self.state = Some(State::Candidate(candidate));
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => candidate.provisioning = None,
                    }
                }
                match candidate
                    .verification
                    .poll(cx, source, &self.plan, hard, self.dad)
                {
                    Poll::Pending => {
                        self.state = Some(State::Candidate(candidate));
                        return Poll::Pending;
                    }
                    Poll::Ready(Err(error)) => {
                        #[cfg(windows)]
                        {
                            candidate.verification.cancel(&self.cleanup, &stop.reports);
                            candidate.verification = Verification::new();
                            self.again(State::Candidate(candidate), error, &stop.reports);
                        }
                        #[cfg(target_os = "freebsd")]
                        return Poll::Ready(Err(error));
                    }
                    Poll::Ready(Ok(verification)) => {
                        let source = candidate
                            .source
                            .take()
                            .ok_or("EXIT recovery source already consumed")?;
                        return Poll::Ready(Ok(Some(Prepared {
                            source,
                            verification,
                            hard,
                            #[cfg(windows)]
                            routes: std::mem::take(&mut candidate.owned_routes),
                            #[cfg(target_os = "freebsd")]
                            routes: candidate
                                .recreated_routes
                                .take()
                                .map(|routes| routes.acknowledged),
                        })));
                    }
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
    pub fn close(&mut self) {
        let state = self.state.take();
        #[cfg(target_os = "freebsd")]
        match state {
            Some(State::Retained(recovery)) => self.release_original(*recovery),
            Some(State::FreeBsdReopen(owner)) => self.release_reopen(*owner),
            Some(State::FreeBsdRecreate(owner)) => self.release_recreate(*owner),
            other => drop(other),
        }
        #[cfg(windows)]
        drop(state);
        self.retry = None;
        self.hard = None;
    }
    pub fn take_report(&mut self) -> Report {
        std::mem::take(&mut self.report)
    }
}

fn retain_candidate_routes(cleanup: &Cleanup, epoch: Option<Epoch>, actions: Vec<Action>) {
    if !actions.is_empty() {
        cleanup.retain(
            crate::lifecycle::Stage::Routes,
            Box::new(CandidateRoutes { epoch, actions }),
        );
    }
}

#[derive(Debug)]
struct CandidateRoutes {
    epoch: Option<Epoch>,
    actions: Vec<Action>,
}
impl std::fmt::Display for CandidateRoutes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EXIT closed fresh source {:?} retains unconfirmed route cleanup: {:?}",
            self.epoch, self.actions
        )
    }
}
impl std::error::Error for CandidateRoutes {}
