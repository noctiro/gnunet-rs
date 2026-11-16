//! Bounded installed-service session recovery above the original Wintun owner.
use super::verification::Plan;
use crate::{Failure, foreground::Stop, lifecycle::Cleanup, settings::Settings};
use gnunet_exit_host::runtime::{Event, PacketSource, Report as NativeReport};
use gnunet_program_host::reporting::Reporter;
use gnunet_tun_host::{
    Action, AsyncTun, Epoch, Loss, RecoveryBudget, WintunRecovery, WintunReopen,
    WintunReplacementKind, WintunScopeRetirement,
};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;
mod admission;
mod provisioning;
mod verification;
pub(crate) use admission::Admission;
use admission::Prepared;
use provisioning::Provisioning;
use verification::Verification;

#[derive(Debug, Default)]
pub(crate) struct Report {
    losses: u64,
    attempts: u64,
    restored: u64,
    first: Option<Loss>,
    last: Option<Loss>,
    first_error: Option<Failure>,
    last_error: Option<Failure>,
    first_scope: Option<WintunScopeRetirement>,
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
    provisioning: Option<Provisioning>,
    owned_routes: Vec<Action>,
}
impl Drop for Candidate {
    fn drop(&mut self) {
        self.verification.cancel(&self.cleanup, &self.reports);
        if !self.owned_routes.is_empty() {
            self.cleanup.retain(
                crate::lifecycle::Stage::Routes,
                Box::new(CandidateRoutes {
                    epoch: self.source.as_ref().map(AsyncTun::epoch),
                    actions: std::mem::take(&mut self.owned_routes),
                }),
            );
        }
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
#[derive(Debug)]
struct RestartFailure {
    stage: gnunet_tun_host::WintunRestartStage,
    original: std::io::Error,
}
#[derive(Debug)]
struct PhysicalFailure {
    stage: gnunet_tun_host::WintunReopenStage,
    original: std::io::Error,
}
impl std::fmt::Display for PhysicalFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EXIT Wintun physical recovery {:?}: {}",
            self.stage, self.original
        )
    }
}
impl std::error::Error for PhysicalFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}
impl std::fmt::Display for RestartFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EXIT Wintun restart {:?}: {}", self.stage, self.original)
    }
}
impl std::error::Error for RestartFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}
enum State {
    Adapter(Box<WintunRecovery>),
    Refresh(Box<WintunRecovery>),
    Reopen(Box<WintunReopen>),
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
    pending_scope: Option<WintunScopeRetirement>,
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
            pending_scope: None,
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
        let Some(recovery) = loss.recovery.take() else {
            crate::foreground::observe(Event::TunLost(loss), reports, &self.cleanup);
            return;
        };
        if self.active() || loss.close_error.is_some() || loss.epoch != *recovery.original_epoch() {
            recovery.close();
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
                self.state = Some(State::Adapter(recovery));
                self.retry = None;
                self.delay = Duration::from_millis(100);
            }
            Err(error) => {
                recovery.close();
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
        kind: WintunReplacementKind,
        reports: &Reporter,
    ) -> State {
        State::Candidate(Box::new(Candidate {
            verification: Verification::new(),
            source: Some(source),
            cleanup: self.cleanup.clone(),
            reports: reports.clone(),
            provisioning: (kind == WintunReplacementKind::Created).then(Provisioning::default),
            owned_routes: Vec::new(),
        }))
    }
    fn reconcile_routes(
        &mut self,
        routes: &mut Vec<Action>,
        reports: &Reporter,
    ) -> Result<(), Failure> {
        if let Some(scope) = self.pending_scope.take() {
            let expected = self
                .report
                .last
                .as_ref()
                .or(self.report.first.as_ref())
                .ok_or("EXIT physical scope has no original loss")?;
            if scope.original_epoch() != &expected.epoch {
                return Err("EXIT physical retirement belongs to another packet source".into());
            }
            if self.reconciled.as_ref() != Some(scope.original_epoch()) {
                // Initial configuration jobs have completed before this serving
                // loop. The sealed receipt proves all old-LUID routes absent.
                reports.debug(
                    "exit.packet.scope.retired",
                    format_args!(
                        "EXIT actual old-scope observation: {scope:?}; released cleanup intents={}",
                        routes.len()
                    ),
                );
                routes.clear();
                self.reconciled = Some(scope.original_epoch().clone());
                if self.report.first_scope.is_none() {
                    self.report.first_scope = Some(scope);
                } else {
                    self.report.last_scope = Some(scope);
                }
            }
        }
        Ok(())
    }
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        stop: &mut Stop,
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
            return Poll::Ready(Err("EXIT original Wintun recovery target expired".into()));
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
        let refresh = matches!(&state, State::Refresh(_));
        match state {
            State::Adapter(recovery) | State::Refresh(recovery) => {
                self.report.attempts = self.report.attempts.saturating_add(1);
                let result = if refresh {
                    recovery.refresh_scope()
                } else {
                    recovery.restart()
                };
                match result {
                    Ok(source) => {
                        self.state = Some(self.candidate(
                            source,
                            WintunReplacementKind::Reopened,
                            &stop.reports,
                        ));
                    }
                    Err(error) => {
                        let (recovery, stage, original) = error.into_parts();
                        self.failure(Box::new(RestartFailure { stage, original }), &stop.reports);
                        if !refresh && stage == gnunet_tun_host::WintunRestartStage::Start {
                            self.state = Some(State::Refresh(Box::new(recovery)));
                        } else if refresh {
                            match recovery.detach_missing() {
                                Ok(owner) => self.state = Some(State::Reopen(Box::new(owner))),
                                Err(error) => {
                                    let (owner, stage, original) = error.into_parts();
                                    if original.kind() != std::io::ErrorKind::WouldBlock {
                                        self.failure(
                                            Box::new(RestartFailure { stage, original }),
                                            &stop.reports,
                                        );
                                    }
                                    self.retry(State::Adapter(Box::new(owner)));
                                }
                            }
                        } else {
                            self.retry(State::Adapter(Box::new(recovery)));
                        }
                    }
                }
            }
            State::Reopen(owner) => match owner.open_or_recreate(hard) {
                Ok(replacement) => {
                    let kind = replacement.kind();
                    let (source, scope) = replacement.into_parts();
                    self.pending_scope = Some(scope);
                    self.state = Some(self.candidate(source, kind, &stop.reports));
                }
                Err(error) => {
                    let (owner, stage, original) = error.into_parts();
                    self.failure(Box::new(PhysicalFailure { stage, original }), &stop.reports);
                    self.pending_scope = owner.retirement().cloned();
                    self.retry(State::Reopen(Box::new(owner)));
                }
            },
            State::Candidate(mut candidate) => {
                let Some(source) = candidate.source.as_mut() else {
                    return Poll::Ready(Err(
                        "EXIT recovery candidate lost its original source".into()
                    ));
                };
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
                        candidate.verification.cancel(&self.cleanup, &stop.reports);
                        candidate.verification = Verification::new();
                        self.again(State::Candidate(candidate), error, &stop.reports);
                    }
                    Poll::Ready(Ok(watch)) => {
                        let source = candidate
                            .source
                            .take()
                            .ok_or("EXIT recovery source already consumed")?;
                        return Poll::Ready(Ok(Some(Prepared {
                            source: PacketSource::Native(source),
                            watch,
                            hard,
                            routes: std::mem::take(&mut candidate.owned_routes),
                        })));
                    }
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
    pub fn close(&mut self) {
        self.state = None;
        self.retry = None;
        self.hard = None;
    }
    pub fn take_report(&mut self) -> Report {
        std::mem::take(&mut self.report)
    }
}
