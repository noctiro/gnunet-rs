//! Recover a checkpointed FreeBSD packet source without transferring route debt.
use super::{Controller, OriginalRecovery, State};
use crate::{Failure, lifecycle::Stage};
use gnunet_program_host::reporting::Reporter;
use gnunet_tun_host::{
    Action, AsyncTun, Epoch, FreeBsdRecreate, FreeBsdRecreateStartError, FreeBsdReopen,
    FreeBsdReopenStage, FreeBsdReopenStartError, FreeBsdRouteKey,
};
use std::{
    io,
    task::{Context, Poll},
};
use tokio::time::Instant;

mod provisioning;
pub(super) use provisioning::{Provisioning, RecreatedRoutes, RouteScope};
pub(in crate::network) use provisioning::{RoutePresence, classify_route};

impl Controller {
    pub(super) fn begin_freebsd(
        &mut self,
        recovery: OriginalRecovery,
        hard: Instant,
        owned: &[Action],
        reports: &Reporter,
    ) -> Result<(), Failure> {
        self.report.attempts = self.report.attempts.saturating_add(1);
        match recovery.begin_reopen(hard) {
            Ok(owner) => self.state = Some(State::FreeBsdReopen(Box::new(owner))),
            Err(FreeBsdReopenStartError::Transient(owner)) => {
                return self.restart_freebsd(*owner, hard, owned, reports);
            }
            Err(FreeBsdReopenStartError::BeforeClose { owner, error })
                if error.kind() == io::ErrorKind::NotFound =>
            {
                return self.begin_recreate(
                    *owner,
                    owned,
                    reports,
                    |owner, keys| owner.begin_recreate(keys, hard),
                    State::Retained,
                );
            }
            Err(FreeBsdReopenStartError::BeforeClose { owner, error }) => {
                let state = State::Retained(owner);
                if retryable(&error) {
                    self.again(state, error.into(), reports);
                } else {
                    self.state = Some(state);
                    return Err(error.into());
                }
            }
            Err(FreeBsdReopenStartError::CloseUnconfirmed(owner)) => {
                let (original, cleanup) = owner.defer_cleanup();
                if let Err(error) = cleanup {
                    self.cleanup.retain(Stage::Tun, error.into());
                }
                return Err(original.into());
            }
        }
        Ok(())
    }

    fn restart_freebsd(
        &mut self,
        recovery: OriginalRecovery,
        hard: Instant,
        owned: &[Action],
        reports: &Reporter,
    ) -> Result<(), Failure> {
        match recovery.restart() {
            Ok(source) => self.state = Some(self.candidate(source, None, None, reports)),
            Err(failure) => {
                let (recovery, stage, original) = failure.into_parts();
                if stage == gnunet_tun_host::FreeBsdRestartStage::Qualify
                    && original.kind() == io::ErrorKind::NotFound
                {
                    return self.begin_recreate(
                        recovery,
                        owned,
                        reports,
                        |owner, keys| owner.begin_recreate(keys, hard),
                        State::Retained,
                    );
                }
                let retry = retryable(&original);
                let error = io::Error::new(original.kind(), RestartFailure { stage, original });
                let state = State::Retained(Box::new(recovery));
                if retry {
                    self.again(state, error.into(), reports);
                } else {
                    self.state = Some(state);
                    return Err(error.into());
                }
            }
        }
        Ok(())
    }

    pub(super) fn open_freebsd(
        &mut self,
        owner: FreeBsdReopen,
        hard: Instant,
        owned: &[Action],
        reports: &Reporter,
    ) -> Result<(), Failure> {
        match owner.open() {
            Ok(candidate) => {
                let (source, original, until) = candidate.into_parts();
                let source = self.qualify_physical(source, original, until, hard, reports)?;
                let provisioning = Some(Provisioning::new(source.epoch(), until, self.dad));
                self.state = Some(self.candidate(source, provisioning, None, reports));
            }
            Err(failure) => {
                let (owner, stage, original) = failure.into_parts();
                if matches!(
                    stage,
                    FreeBsdReopenStage::Open | FreeBsdReopenStage::Qualify
                ) && original.kind() == io::ErrorKind::NotFound
                {
                    return self.begin_recreate(
                        owner,
                        owned,
                        reports,
                        FreeBsdReopen::begin_recreate,
                        State::FreeBsdReopen,
                    );
                }
                let retry = retryable(&original);
                let error = io::Error::new(original.kind(), ReopenFailure { stage, original });
                let state = State::FreeBsdReopen(Box::new(owner));
                if retry {
                    self.again(state, error.into(), reports);
                } else {
                    self.state = Some(state);
                    return Err(error.into());
                }
            }
        }
        Ok(())
    }

    fn begin_recreate<S>(
        &mut self,
        owner: S,
        owned: &[Action],
        reports: &Reporter,
        start: impl FnOnce(
            S,
            Vec<FreeBsdRouteKey>,
        ) -> Result<FreeBsdRecreate, FreeBsdRecreateStartError<S>>,
        retain: impl FnOnce(Box<S>) -> State,
    ) -> Result<(), Failure> {
        let keys = match self.recreation_keys(owned) {
            Ok(keys) => keys,
            Err(error) => {
                self.state = Some(retain(Box::new(owner)));
                return Err(error);
            }
        };
        match start(owner, keys) {
            Ok(recreate) => self.state = Some(State::FreeBsdRecreate(Box::new(recreate))),
            Err(FreeBsdRecreateStartError::Refused { owner, error }) => {
                let state = retain(owner);
                if retryable(&error) {
                    self.again(state, error.into(), reports);
                } else {
                    self.state = Some(state);
                    return Err(error.into());
                }
            }
            Err(FreeBsdRecreateStartError::CloseUnconfirmed(owner)) => {
                let (original, cleanup) = owner.defer_cleanup();
                if let Err(error) = cleanup {
                    self.cleanup.retain(Stage::Tun, error.into());
                }
                return Err(original.into());
            }
        }
        Ok(())
    }

    fn recreation_keys(&self, owned: &[Action]) -> Result<Vec<FreeBsdRouteKey>, Failure> {
        let mut keys = Vec::new();
        keys.try_reserve_exact(
            self.plan
                .routes
                .len()
                .checked_add(owned.len())
                .ok_or(gnunet_types::Error::Overflow)?,
        )?;
        for route in &self.plan.routes {
            push_key(
                &mut keys,
                FreeBsdRouteKey::new(route.destination, route.prefix)?,
            );
        }
        for route in owned {
            let Action::Route {
                add: false,
                destination,
                prefix,
                ..
            } = *route
            else {
                return Err(gnunet_types::Error::Conflict.into());
            };
            push_key(&mut keys, FreeBsdRouteKey::new(destination, prefix)?);
        }
        Ok(keys)
    }

    pub(super) fn recreate_freebsd(
        &mut self,
        cx: &mut Context<'_>,
        mut owner: Box<FreeBsdRecreate>,
        hard: Instant,
        owned: &mut Vec<Action>,
        reports: &Reporter,
    ) -> Result<Poll<()>, Failure> {
        let vacancy = match owner.poll(cx) {
            Poll::Pending => {
                self.state = Some(State::FreeBsdRecreate(owner));
                return Ok(Poll::Pending);
            }
            Poll::Ready(Err(error)) => {
                self.release_recreate(*owner);
                return Err(error.into());
            }
            Poll::Ready(Ok(vacancy)) => vacancy,
        };
        if !self.physical_origin_matches(vacancy.original_epoch(), vacancy.deadline(), hard) {
            return Err(gnunet_types::Error::StaleGeneration.into());
        }
        let recreated = RecreatedRoutes::new(std::mem::take(owned));
        let (source, original, until) = vacancy.create()?.into_parts();
        let source = self.qualify_physical(source, original, until, hard, reports)?;
        let provisioning = Some(Provisioning::new(source.epoch(), until, self.dad));
        self.state = Some(self.candidate(source, provisioning, Some(recreated), reports));
        Ok(Poll::Ready(()))
    }

    fn physical_origin_matches(&self, original: &Epoch, until: Instant, hard: Instant) -> bool {
        let last = self.report.last.as_ref().or(self.report.first.as_ref());
        last.is_some_and(|loss| &loss.epoch == original) && !original.current() && until == hard
    }

    fn qualify_physical(
        &self,
        source: AsyncTun,
        original: Epoch,
        until: Instant,
        hard: Instant,
        reports: &Reporter,
    ) -> Result<AsyncTun, Failure> {
        let epoch = source.epoch();
        if !self.physical_origin_matches(&original, until, hard)
            || !epoch.current()
            || epoch == original
            || epoch.route_table().is_none()
            || epoch.route_table() != original.route_table()
        {
            super::admission::close_uninstalled(source, &self.cleanup, reports);
            return Err(gnunet_types::Error::StaleGeneration.into());
        }
        Ok(source)
    }

    pub(super) fn release_original(&self, mut recovery: OriginalRecovery) {
        // This original interface may have disappeared or changed. Keep the
        // checkpoint owner and avoid an administrative ioctl during shutdown.
        recovery.defer_interface_cleanup();
        if let Err(error) = recovery.close() {
            self.cleanup.retain(Stage::Tun, error.into());
        }
    }

    pub(super) fn release_reopen(&self, owner: FreeBsdReopen) {
        if let Err(error) = owner.defer_cleanup() {
            self.cleanup.retain(Stage::Tun, error.into());
        }
    }

    pub(super) fn release_recreate(&self, owner: FreeBsdRecreate) {
        if let Err(error) = owner.cancel() {
            self.cleanup.retain(Stage::Tun, error.into());
        }
    }
}

fn push_key(keys: &mut Vec<FreeBsdRouteKey>, key: FreeBsdRouteKey) {
    if !keys.contains(&key) {
        keys.push(key);
    }
}

fn retryable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::ResourceBusy
    )
}

#[derive(Debug)]
struct RestartFailure {
    stage: gnunet_tun_host::FreeBsdRestartStage,
    original: io::Error,
}
impl std::fmt::Display for RestartFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EXIT FreeBSD TUN restart {:?}: {}",
            self.stage, self.original
        )
    }
}
impl std::error::Error for RestartFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}

#[derive(Debug)]
struct ReopenFailure {
    stage: FreeBsdReopenStage,
    original: io::Error,
}
impl std::fmt::Display for ReopenFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EXIT FreeBSD TUN reopen {:?}: {}",
            self.stage, self.original
        )
    }
}
impl std::error::Error for ReopenFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacement_or_identity_failure_is_never_a_retry() {
        assert!(retryable(&io::ErrorKind::WouldBlock.into()));
        assert!(retryable(&io::ErrorKind::ResourceBusy.into()));
        for kind in [
            io::ErrorKind::NotFound,
            io::ErrorKind::NotConnected,
            io::ErrorKind::InvalidData,
        ] {
            assert!(!retryable(&kind.into()));
        }
    }
}
