//! Installed physical retry policy never carries adapter ownership in diagnostics.
use super::{Controller, Owner};
use crate::{
    Failure,
    lifecycle::{self, Stage},
};
use gnunet_program_host::reporting::Reporter;
use gnunet_tun_host::{WintunReopen, WintunReopenError, WintunReopenStage};
use gnunet_types::Error as Fault;
use gnunet_vpn_host::coordinator::{Coordinator, Error, Event, WintunPhysicalFailure};
use std::task::{Context, Poll};

#[derive(Debug)]
struct PhysicalError {
    stage: WintunReopenStage,
    original: std::io::Error,
}
impl std::fmt::Display for PhysicalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "VPN physical recovery {:?}: {}",
            self.stage, self.original
        )
    }
}
impl std::error::Error for PhysicalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}
impl Controller {
    fn physical_error(&mut self, error: WintunReopenError, reports: &Reporter) -> WintunReopen {
        let (owner, stage, original) = error.into_parts();
        self.error(Box::new(PhysicalError { stage, original }), reports);
        owner
    }
    pub(super) fn poll_physical(
        &mut self,
        owner: WintunReopen,
        cx: &mut Context<'_>,
        vpn: &mut Coordinator<'_, '_, '_, '_, '_, '_>,
        reports: &Reporter,
    ) -> Poll<Result<bool, Failure>> {
        let result = vpn.restore_wintun(owner, &mut |event| {
            if let Event::InterfaceRetired(scope) = event {
                self.scope(scope, reports);
            }
        });
        match result {
            Ok(()) => {
                self.report.restart_attempts = self.report.restart_attempts.saturating_add(1);
                self.report.installed = self.report.installed.saturating_add(1);
                self.installed = Some(vpn.device_epoch());
                Poll::Ready(Ok(true))
            }
            Err(WintunPhysicalFailure::Retained {
                owner,
                error: Error::Protocol(Fault::WouldBlock),
            }) => {
                self.owner = Some(Owner::Physical(owner));
                Poll::Pending
            }
            Err(WintunPhysicalFailure::Retained { owner, error }) => {
                drop(owner);
                Poll::Ready(Err(Box::new(error)))
            }
            Err(WintunPhysicalFailure::Open(error)) => {
                self.report.restart_attempts = self.report.restart_attempts.saturating_add(1);
                let owner = self.physical_error(error, reports);
                self.owner = Some(Owner::Physical(Box::new(owner)));
                self.backoff(cx);
                Poll::Pending
            }
            Err(WintunPhysicalFailure::Reconcile { original, error }) => {
                self.report.restart_attempts = self.report.restart_attempts.saturating_add(1);
                drop(self.physical_error(original, reports));
                Poll::Ready(Err(Box::new(error)))
            }
            Err(WintunPhysicalFailure::Prepared { mut source, error }) => {
                self.report.restart_attempts = self.report.restart_attempts.saturating_add(1);
                let loss = source.close();
                self.report.adapter_releases = self.report.adapter_releases.saturating_add(1);
                reports.debug(
                    "vpn.tun.physical.closed",
                    format_args!("VPN provisional physical session close: {loss:?}"),
                );
                if loss.close_error.is_some() {
                    self.cleanup
                        .retain(Stage::ObservedTun, Box::new(lifecycle::TunLoss(loss)));
                }
                Poll::Ready(Err(Box::new(error)))
            }
            Err(WintunPhysicalFailure::Installed(error)) => {
                self.report.restart_attempts = self.report.restart_attempts.saturating_add(1);
                self.report.installed = self.report.installed.saturating_add(1);
                Poll::Ready(Err(Box::new(error)))
            }
        }
    }
}
