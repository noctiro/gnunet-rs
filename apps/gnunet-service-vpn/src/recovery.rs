//! Installed Windows policy; the coordinator owns the fixed outage/verification budget.
use crate::{
    Failure,
    lifecycle::{self, Cleanup, Stage},
};
use gnunet_program_host::reporting::Reporter;
use gnunet_tun_host::{
    Epoch, Loss, WintunRecovery, WintunReopen, WintunRestartStage, WintunScopeRetirement,
};
use gnunet_types::Error as Fault;
use gnunet_vpn_host::coordinator::{Coordinator, Error, WintunRecoveryFailure};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
mod physical;

#[derive(Debug, Default)]
pub(super) struct Report {
    losses: u64,
    restart_attempts: u64,
    installed: u64,
    verified: u64,
    adapter_releases: u64,
    first: Option<Loss>,
    last: Option<Loss>,
    first_error: Option<Failure>,
    last_error: Option<Failure>,
    first_scope: Option<WintunScopeRetirement>,
    last_scope: Option<WintunScopeRetirement>,
}
#[derive(Debug)]
struct RestartFailure {
    stage: WintunRestartStage,
    original: std::io::Error,
}
impl std::fmt::Display for RestartFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VPN Wintun restart {:?}: {}", self.stage, self.original)
    }
}
impl std::error::Error for RestartFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}
enum Owner {
    Session(WintunRecovery),
    Refresh(WintunRecovery),
    Physical(Box<WintunReopen>),
}
pub(super) struct Controller {
    owner: Option<Owner>,
    retry: Option<Pin<Box<tokio::time::Sleep>>>,
    installed: Option<Epoch>,
    delay: Duration,
    report: Report,
    cleanup: Cleanup,
}
impl Controller {
    pub fn new(cleanup: Cleanup) -> Self {
        Self {
            owner: None,
            retry: None,
            installed: None,
            delay: Duration::from_millis(100),
            report: Report::default(),
            cleanup,
        }
    }
    pub fn offer(&mut self, mut loss: Loss, reports: &Reporter) -> Result<(), Loss> {
        let Some(owner) = loss.recovery.take() else {
            return Err(loss);
        };
        if self.owner.is_some()
            || loss.close_error.is_some()
            || loss.epoch != *owner.original_epoch()
        {
            owner.close();
            self.report.adapter_releases = self.report.adapter_releases.saturating_add(1);
            return Err(loss);
        }
        reports.warning(
            "vpn.tun.recovery",
            format_args!("VPN packet session retired; retaining its original adapter: {loss:?}"),
        );
        self.report.losses = self.report.losses.saturating_add(1);
        if self.report.first.is_none() {
            self.report.first = Some(loss);
        } else {
            self.report.last = Some(loss);
        }
        self.owner = Some(Owner::Session(*owner));
        self.installed = None;
        self.retry = None;
        self.delay = Duration::from_millis(100);
        Ok(())
    }
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        vpn: &mut Coordinator<'_, '_, '_, '_, '_, '_>,
        reports: &Reporter,
    ) -> Poll<Result<bool, Failure>> {
        if self.installed.is_some() && self.installed == vpn.device_epoch() && vpn.tun_ready()? {
            self.report.verified = self.report.verified.saturating_add(1);
            self.installed = None;
            reports.debug(
                "vpn.tun.recovered",
                format_args!(
                    "VPN original adapter configuration passed fresh route and DAD verification"
                ),
            );
            return Poll::Ready(Ok(true));
        }
        if self.owner.is_none() {
            return Poll::Pending;
        }
        if let Some(retry) = self.retry.as_mut()
            && retry.as_mut().poll(cx).is_pending()
        {
            return Poll::Pending;
        }
        self.retry = None;
        let Some(owner) = self.owner.take() else {
            return Poll::Pending;
        };
        let (owner, refresh) = match owner {
            Owner::Session(owner) => (owner, false),
            Owner::Refresh(owner) => (owner, true),
            Owner::Physical(owner) => return self.poll_physical(*owner, cx, vpn, reports),
        };
        let result = if refresh {
            vpn.refresh_wintun(owner)
        } else {
            vpn.recover_wintun(owner)
        };
        match result {
            Ok(()) => {
                self.report.restart_attempts = self.report.restart_attempts.saturating_add(1);
                self.report.installed = self.report.installed.saturating_add(1);
                self.installed = vpn.device_epoch();
                Poll::Ready(Ok(true))
            }
            Err(WintunRecoveryFailure::Retained {
                recovery,
                error: Error::Protocol(Fault::WouldBlock),
            }) => {
                // The original coordinator/provider jobs already register
                // progress and deadline wakes; debt needs no polling timer.
                self.owner = Some(if refresh {
                    Owner::Refresh(recovery)
                } else {
                    Owner::Session(recovery)
                });
                Poll::Pending
            }
            Err(WintunRecoveryFailure::Retained { recovery, error }) => {
                recovery.close();
                self.report.adapter_releases = self.report.adapter_releases.saturating_add(1);
                Poll::Ready(Err(Box::new(error)))
            }
            Err(WintunRecoveryFailure::Restart(error)) => {
                self.report.restart_attempts = self.report.restart_attempts.saturating_add(1);
                let (owner, stage, original) = error.into_parts();
                let error: Failure = Box::new(RestartFailure { stage, original });
                self.error(error, reports);
                if !refresh && stage == WintunRestartStage::Start {
                    self.owner = Some(Owner::Refresh(owner));
                    cx.waker().wake_by_ref();
                } else if refresh {
                    match owner.detach_missing() {
                        Ok(owner) => {
                            self.report.adapter_releases =
                                self.report.adapter_releases.saturating_add(1);
                            self.owner = Some(Owner::Physical(Box::new(owner)));
                            cx.waker().wake_by_ref();
                        }
                        Err(error) => {
                            let (owner, stage, original) = error.into_parts();
                            if original.kind() != std::io::ErrorKind::WouldBlock {
                                self.error(Box::new(RestartFailure { stage, original }), reports);
                            }
                            self.owner = Some(Owner::Session(owner));
                            self.backoff(cx);
                        }
                    }
                } else {
                    self.owner = Some(Owner::Session(owner));
                    self.backoff(cx);
                }
                Poll::Pending
            }
            Err(WintunRecoveryFailure::Prepared { device, error }) => {
                self.report.restart_attempts = self.report.restart_attempts.saturating_add(1);
                let loss = (*device)
                    .into_io()
                    .close_native()
                    .ok_or("VPN recovery lost its provisional Wintun device")?;
                self.report.adapter_releases = self.report.adapter_releases.saturating_add(1);
                reports.debug(
                    "vpn.tun.recovery.closed",
                    format_args!("VPN refused new session close: {loss:?}"),
                );
                if loss.close_error.is_some() {
                    self.cleanup
                        .retain(Stage::ObservedTun, Box::new(lifecycle::TunLoss(loss)));
                }
                Poll::Ready(Err(Box::new(error)))
            }
            Err(WintunRecoveryFailure::Installed(error)) => {
                self.report.restart_attempts = self.report.restart_attempts.saturating_add(1);
                self.report.installed = self.report.installed.saturating_add(1);
                Poll::Ready(Err(Box::new(error)))
            }
        }
    }
    pub fn finish(&mut self) {
        if let Some(Owner::Session(owner) | Owner::Refresh(owner)) = self.owner.take() {
            owner.close();
            self.report.adapter_releases = self.report.adapter_releases.saturating_add(1);
        }
        self.installed = None;
        self.retry = None;
        if self.report.losses != 0
            || self.report.first_error.is_some()
            || self.report.first_scope.is_some()
        {
            self.cleanup
                .packet_recovery(std::mem::take(&mut self.report));
        }
    }
    pub fn error(&mut self, error: Failure, reports: &Reporter) {
        reports.warning(
            "vpn.tun.recovery.error",
            format_args!("VPN original recovery cause: {error}"),
        );
        if self.report.first_error.is_none() {
            self.report.first_error = Some(error);
        } else {
            self.report.last_error = Some(error);
        }
    }
    pub fn scope(&mut self, scope: WintunScopeRetirement, reports: &Reporter) {
        reports.debug(
            "vpn.tun.scope.retired",
            format_args!("VPN actual old native scope observation: {scope:?}"),
        );
        if self.report.first_scope.is_none() {
            self.report.first_scope = Some(scope);
        } else {
            self.report.last_scope = Some(scope);
        }
    }
    fn backoff(&mut self, cx: &Context<'_>) {
        self.retry = Some(Box::pin(tokio::time::sleep(self.delay)));
        self.delay = self.delay.saturating_mul(2).min(Duration::from_secs(1));
        cx.waker().wake_by_ref();
    }
}
impl Drop for Controller {
    fn drop(&mut self) {
        self.finish();
    }
}
