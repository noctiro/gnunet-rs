//! One caller-polled read-only candidate, bounded by the original outage target.
use crate::{
    Failure,
    lifecycle::{Cleanup, Stage},
};
use gnunet_program_host::reporting::Reporter;
use gnunet_tun_host::{
    AsyncTun, Epoch, Ipv6Progress, Ipv6State, Ipv6Watch, Ipv6WatchOptions, RouteQuery,
    RouteQueryProgress,
};
use std::{
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;
#[derive(Clone, Copy)]
enum Phase {
    Snapshot,
    Routes,
    Address,
    FinalSnapshot,
    Done,
}
pub(super) struct Verification {
    phase: Phase,
    epoch: Option<Epoch>,
    route: usize,
    query: Option<RouteQuery>,
    watch: Option<Ipv6Watch>,
}
pub(super) struct Verified {
    epoch: Epoch,
    watch: Option<Ipv6Watch>,
}
impl Verified {
    pub(super) fn matches(&self, source: &AsyncTun) -> bool {
        self.epoch.current() && self.epoch == source.epoch()
    }

    pub(super) fn take_watch(&mut self) -> Option<Ipv6Watch> {
        self.watch.take()
    }
}
impl Verification {
    pub fn new() -> Self {
        Self {
            phase: Phase::Snapshot,
            epoch: None,
            route: 0,
            query: None,
            watch: None,
        }
    }
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        source: &AsyncTun,
        plan: &super::super::verification::Plan,
        hard: Instant,
        dad: Duration,
    ) -> Poll<Result<Verified, Failure>> {
        let epoch = source.epoch();
        if Instant::now() >= hard || !epoch.current() {
            return Poll::Ready(Err(
                "EXIT recovery verification target/source retired".into()
            ));
        }
        let original = self.epoch.get_or_insert_with(|| epoch.clone());
        if *original != epoch {
            return Poll::Ready(Err(gnunet_types::Error::StaleGeneration.into()));
        }
        match self.phase {
            Phase::Snapshot | Phase::FinalSnapshot => {
                let snapshot = source.snapshot(hard, plan.options())?;
                if snapshot.epoch() != &epoch {
                    return Poll::Ready(Err(gnunet_types::Error::StaleGeneration.into()));
                }
                plan.snapshot(snapshot, false)?;
                if Instant::now() >= hard {
                    return Poll::Ready(Err(
                        "EXIT recovery snapshot returned after its target".into()
                    ));
                }
                if matches!(self.phase, Phase::FinalSnapshot) {
                    self.phase = Phase::Done;
                    return Poll::Ready(Ok(Verified {
                        epoch,
                        watch: self.watch.take(),
                    }));
                }
                self.phase = Phase::Routes;
            }
            Phase::Routes => {
                if self.query.is_none() {
                    if let Some(key) = plan.routes.get(self.route) {
                        self.query = Some(source.query_route(
                            key.destination,
                            key.prefix,
                            key.gateway,
                            hard,
                        )?);
                    } else {
                        self.phase = Phase::Address;
                    }
                }
                if let Some(query) = self.query.as_mut() {
                    match query.poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(RouteQueryProgress::Complete(done)) => {
                            self.query = None;
                            if done.target().epoch() != &epoch {
                                return Poll::Ready(Err(
                                    gnunet_types::Error::StaleGeneration.into()
                                ));
                            }
                            super::super::verification::route(done, hard)?;
                            self.route += 1;
                        }
                        Poll::Ready(RouteQueryProgress::Finished) => {
                            return Poll::Ready(Err("EXIT recovery route terminal missing".into()));
                        }
                        Poll::Ready(_) => {}
                    }
                }
            }
            Phase::Address => {
                let Some((address, prefix)) = plan.ipv6 else {
                    self.phase = Phase::FinalSnapshot;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                };
                if self.watch.is_none() {
                    let until = Instant::now()
                        .checked_add(dad)
                        .ok_or(gnunet_types::Error::Overflow)?
                        .min(hard);
                    self.watch = Some(source.watch_ipv6(
                        address,
                        prefix,
                        until,
                        Ipv6WatchOptions::default(),
                    )?);
                }
                let Some(watch) = self.watch.as_mut() else {
                    return Poll::Ready(Err("EXIT recovery observer missing".into()));
                };
                match watch.poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ipv6Progress::Observed(sample)) => {
                        if sample.target.epoch() != &epoch {
                            return Poll::Ready(Err(gnunet_types::Error::StaleGeneration.into()));
                        }
                        match sample.state {
                            Ipv6State::Ready => self.phase = Phase::FinalSnapshot,
                            Ipv6State::Tentative => {}
                            _ => {
                                return Poll::Ready(Err(format!(
                                    "EXIT recovery IPv6 is not ready: {:?}",
                                    sample.state
                                )
                                .into()));
                            }
                        }
                    }
                    Poll::Ready(Ipv6Progress::Complete(done)) => {
                        self.watch = None;
                        return Poll::Ready(Err(Box::new(crate::lifecycle::CancelledWatch(
                            Ipv6Progress::Complete(done),
                        ))));
                    }
                    Poll::Ready(Ipv6Progress::Finished) => {
                        return Poll::Ready(Err("EXIT recovery DAD terminal missing".into()));
                    }
                    Poll::Ready(_) => {}
                }
            }
            Phase::Done => {
                return Poll::Ready(Err("EXIT recovery verification already consumed".into()));
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
    pub fn cancel(&mut self, cleanup: &Cleanup, reports: &Reporter) {
        if let Some(mut query) = self.query.take() {
            let done = query.cancel();
            reports.debug(
                "exit.packet.recovery.query.closed",
                format_args!("EXIT original recovery query cancellation: {done:?}"),
            );
            if matches!(&done, RouteQueryProgress::Complete(done) if done.close_error().is_some()) {
                cleanup.retain(Stage::Routes, Box::new(super::super::QueryCancelled(done)));
            }
        }
        if let Some(mut watch) = self.watch.take() {
            let done = watch.cancel();
            reports.debug(
                "exit.packet.recovery.watch.closed",
                format_args!("EXIT original recovery DAD cancellation: {done:?}"),
            );
            if let Ipv6Progress::Complete(mut done) = done
                && let Some(error) = done.close_error.take()
            {
                cleanup.retain(Stage::Watch, Box::new(error));
            }
        }
        self.phase = Phase::Done;
    }
}
