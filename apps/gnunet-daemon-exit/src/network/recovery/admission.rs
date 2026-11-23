//! Admission and cancellation retain native observations separately from forwarding state.
use super::{Controller, retain_candidate_routes, verification::Verified};
use crate::{
    Failure,
    foreground::{Exit, Stop, observe},
    lifecycle::{Cleanup, Stage},
};
use gnunet_exit_host::runtime::{Event, PacketSource};
use gnunet_program_host::reporting::Reporter;
#[cfg(any(windows, target_os = "freebsd"))]
use gnunet_tun_host::Action;
use gnunet_tun_host::{AsyncTun, Ipv6Progress, Ipv6Watch};
use std::task::{Context, Poll};
use tokio::time::Instant;

pub(crate) enum Admission {
    Restored,
    Stopped,
}
pub(super) struct Prepared {
    pub source: AsyncTun,
    pub verification: Verified,
    pub hard: Instant,
    #[cfg(windows)]
    pub routes: Vec<Action>,
    #[cfg(target_os = "freebsd")]
    pub routes: Option<Vec<Action>>,
}
pub(super) fn close_uninstalled(mut source: AsyncTun, cleanup: &Cleanup, reports: &Reporter) {
    #[cfg(target_os = "freebsd")]
    source.defer_interface_cleanup();
    observe(Event::TunLost(source.close()), reports, cleanup);
}
fn cancel_watch(
    watch: &mut Option<Ipv6Watch>,
    cleanup: &Cleanup,
    reports: &Reporter,
) -> Result<(), Failure> {
    if let Some(mut watch) = watch.take() {
        let actual = watch.cancel();
        reports.debug(
            "exit.packet.recovery.watch.closed",
            format_args!("EXIT recovery observer cancellation: {actual:?}"),
        );
        if let Ipv6Progress::Complete(mut done) = actual
            && let Some(error) = done.close_error.take()
        {
            cleanup.retain(Stage::Watch, error.into());
            return Err("EXIT recovery observer cleanup failed".into());
        }
    }
    Ok(())
}
impl Prepared {
    fn close(mut self, cleanup: &Cleanup, reports: &Reporter) {
        // Both owners retire even when observation cancellation fails.
        let mut watch = self.verification.take_watch();
        let _retained = cancel_watch(&mut watch, cleanup, reports);
        let epoch = Some(self.source.epoch());
        close_uninstalled(self.source, cleanup, reports);
        #[cfg(windows)]
        retain_candidate_routes(cleanup, epoch, self.routes);
        #[cfg(target_os = "freebsd")]
        if let Some(routes) = self.routes {
            retain_candidate_routes(cleanup, epoch, routes);
        }
    }
}
impl Controller {
    pub fn retire_watch(
        &self,
        watch: &mut Option<Ipv6Watch>,
        reports: &Reporter,
    ) -> Result<(), Failure> {
        if self.active() {
            cancel_watch(watch, &self.cleanup, reports)?;
        }
        Ok(())
    }
    pub fn poll_restore(
        &mut self,
        cx: &mut Context<'_>,
        stop: &mut Stop,
        exit: &mut Exit<'_, '_, '_>,
        watch: &mut Option<Ipv6Watch>,
        routes: &mut Vec<Action>,
    ) -> Poll<Result<Admission, Failure>> {
        self.retire_watch(watch, &stop.reports)?;
        let result = self.poll(
            cx,
            stop,
            #[cfg(target_os = "freebsd")]
            routes,
        );
        #[cfg(windows)]
        if let Err(error) = self.reconcile_routes(routes, &stop.reports) {
            if let Poll::Ready(Ok(Some(prepared))) = result {
                prepared.close(&self.cleanup, &stop.reports);
            }
            return Poll::Ready(Err(error));
        }
        let mut prepared = match result {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(None)) => return Poll::Ready(Ok(Admission::Stopped)),
            Poll::Ready(Ok(Some(prepared))) => prepared,
        };
        // Synchronous native qualification cannot be preempted. Poll stop again
        // before admitting any source returned by those calls.
        match stop.poll(cx) {
            Poll::Ready(Ok(())) => {
                prepared.close(&self.cleanup, &stop.reports);
                return Poll::Ready(Ok(Admission::Stopped));
            }
            Poll::Ready(Err(error)) => {
                prepared.close(&self.cleanup, &stop.reports);
                return Poll::Ready(Err(error));
            }
            Poll::Pending => {}
        }
        if Instant::now() >= prepared.hard {
            prepared.close(&self.cleanup, &stop.reports);
            return Poll::Ready(Err(
                "EXIT recovery configuration returned after its original target".into(),
            ));
        }
        if !prepared.verification.matches(&prepared.source) {
            prepared.close(&self.cleanup, &stop.reports);
            return Poll::Ready(Err(gnunet_types::Error::StaleGeneration.into()));
        }
        #[cfg(target_os = "freebsd")]
        if prepared.routes.is_some() && !routes.is_empty() {
            prepared.close(&self.cleanup, &stop.reports);
            return Poll::Ready(Err(gnunet_types::Error::Conflict.into()));
        }
        let source = PacketSource::Native(prepared.source);
        let epoch = Some(source.epoch());
        if let Err(mut refusal) = exit.replace_tun(source) {
            let mut watch = prepared.verification.take_watch();
            let _retained = cancel_watch(&mut watch, &self.cleanup, &stop.reports);
            #[cfg(target_os = "freebsd")]
            if let PacketSource::Native(source) = &mut refusal.source {
                source.defer_interface_cleanup();
            }
            observe(
                Event::TunLost(refusal.source.close()),
                &stop.reports,
                &self.cleanup,
            );
            #[cfg(windows)]
            retain_candidate_routes(&self.cleanup, epoch, prepared.routes);
            #[cfg(target_os = "freebsd")]
            if let Some(routes) = prepared.routes {
                retain_candidate_routes(&self.cleanup, epoch, routes);
            }
            return Poll::Ready(Err(Box::new(refusal.error)));
        }
        #[cfg(windows)]
        routes.append(&mut prepared.routes);
        #[cfg(target_os = "freebsd")]
        if let Some(acknowledged) = prepared.routes {
            *routes = acknowledged;
        }
        *watch = prepared.verification.take_watch();
        self.admitted(exit.report());
        stop.reports.debug(
            "exit.packet.recovered",
            format_args!("EXIT replacement packet source passed read-only configuration checks"),
        );
        Poll::Ready(Ok(Admission::Restored))
    }
}
