//! Wintun provider restart and physical scope retirement.
use super::{Controller, OriginalRecovery, State};
use crate::Failure;
use gnunet_program_host::reporting::Reporter;
use gnunet_tun_host::{
    Action, WintunReopen, WintunReopenStage, WintunReplacementKind, WintunRestartStage,
};
use std::{fmt, io};
use tokio::time::Instant;

#[derive(Clone, Copy)]
pub(super) enum Restart {
    Retained,
    Refresh,
}

impl Controller {
    pub(super) fn restart_wintun(
        &mut self,
        recovery: OriginalRecovery,
        mode: Restart,
        reports: &Reporter,
    ) {
        self.report.attempts = self.report.attempts.saturating_add(1);
        let result = match mode {
            Restart::Retained => recovery.restart(),
            Restart::Refresh => recovery.refresh_scope(),
        };
        let failure = match result {
            Ok(source) => {
                self.state = Some(self.candidate(source, WintunReplacementKind::Reopened, reports));
                return;
            }
            Err(failure) => failure,
        };
        let (recovery, stage, original) = failure.into_parts();
        self.failure(Box::new(RestartFailure { stage, original }), reports);
        match mode {
            Restart::Retained if stage == WintunRestartStage::Start => {
                self.state = Some(State::Refresh(Box::new(recovery)));
            }
            Restart::Retained => self.retry(State::Retained(Box::new(recovery))),
            Restart::Refresh => match recovery.detach_missing() {
                Ok(owner) => self.state = Some(State::Reopen(Box::new(owner))),
                Err(error) => {
                    let (owner, stage, original) = error.into_parts();
                    if original.kind() != io::ErrorKind::WouldBlock {
                        self.failure(Box::new(RestartFailure { stage, original }), reports);
                    }
                    self.retry(State::Retained(Box::new(owner)));
                }
            },
        }
    }

    pub(super) fn reopen_wintun(&mut self, owner: WintunReopen, hard: Instant, reports: &Reporter) {
        match owner.open_or_recreate(hard) {
            Ok(replacement) => {
                let kind = replacement.kind();
                let (source, scope) = replacement.into_parts();
                self.pending_scope = Some(scope);
                self.state = Some(self.candidate(source, kind, reports));
            }
            Err(error) => {
                let (owner, stage, original) = error.into_parts();
                self.failure(Box::new(PhysicalFailure { stage, original }), reports);
                self.pending_scope = owner.retirement().cloned();
                self.retry(State::Reopen(Box::new(owner)));
            }
        }
    }

    pub(super) fn reconcile_routes(
        &mut self,
        routes: &mut Vec<Action>,
        reports: &Reporter,
    ) -> Result<(), Failure> {
        let Some(scope) = self.pending_scope.take() else {
            return Ok(());
        };
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
            // The sealed receipt proves all old-LUID routes absent.
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
        Ok(())
    }
}

#[derive(Debug)]
struct RestartFailure {
    stage: WintunRestartStage,
    original: io::Error,
}
impl fmt::Display for RestartFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EXIT Wintun restart {:?}: {}", self.stage, self.original)
    }
}
impl std::error::Error for RestartFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}

#[derive(Debug)]
struct PhysicalFailure {
    stage: WintunReopenStage,
    original: io::Error,
}
impl fmt::Display for PhysicalFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
