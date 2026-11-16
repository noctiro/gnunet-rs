//! Admission and cancellation retain native observations separately from forwarding state.
use super::Controller;
use crate::{
    Failure,
    foreground::{Exit, Stop, observe},
    lifecycle::{Cleanup, Stage},
};
use gnunet_exit_host::runtime::{Event, PacketSource};
use gnunet_program_host::reporting::Reporter;
use gnunet_tun_host::{Action, Ipv6Progress, Ipv6Watch};
use std::task::{Context, Poll};
use tokio::time::Instant;

pub(crate) enum Admission {
    Restored,
    Stopped,
}
pub(super) struct Prepared {
    pub source: PacketSource,
    pub watch: Option<Ipv6Watch>,
    pub hard: Instant,
    pub routes: Vec<Action>,
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
        let _retained = cancel_watch(&mut self.watch, cleanup, reports);
        let epoch = Some(self.source.epoch());
        observe(Event::TunLost(self.source.close()), reports, cleanup);
        if !self.routes.is_empty() {
            cleanup.retain(
                Stage::Routes,
                Box::new(super::CandidateRoutes {
                    epoch,
                    actions: self.routes,
                }),
            );
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
        let result = self.poll(cx, stop);
        self.reconcile_routes(routes, &stop.reports)?;
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
        let epoch = Some(prepared.source.epoch());
        if let Err(mut refusal) = exit.replace_tun(prepared.source) {
            let _retained = cancel_watch(&mut prepared.watch, &self.cleanup, &stop.reports);
            observe(
                Event::TunLost(refusal.source.close()),
                &stop.reports,
                &self.cleanup,
            );
            if !prepared.routes.is_empty() {
                self.cleanup.retain(
                    Stage::Routes,
                    Box::new(super::CandidateRoutes {
                        epoch,
                        actions: prepared.routes,
                    }),
                );
            }
            return Poll::Ready(Err(Box::new(refusal.error)));
        }
        routes.append(&mut prepared.routes);
        *watch = prepared.watch;
        self.admitted(exit.report());
        stop.reports.debug(
            "exit.packet.recovered",
            format_args!("EXIT replacement packet source passed read-only configuration checks"),
        );
        Poll::Ready(Ok(Admission::Restored))
    }
}
