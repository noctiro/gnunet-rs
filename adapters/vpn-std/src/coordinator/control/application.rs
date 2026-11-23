//! Application settings use one actual correlated completion per native job.
use super::*;
use provider::{RouteCompletion, RouteOutcome, RouteRequest};

impl<'id, 'store, 'bytes, 'cadet, 'cstore, 'policy>
    Coordinator<'id, 'store, 'bytes, 'cadet, 'cstore, 'policy>
{
    fn provider_request(
        &mut self,
        plan: core::RoutingRequest<'id>,
        deadline: Instant,
    ) -> Result<(), Error> {
        self.control.work = Some(plan.routing);
        self.control.plan = Some(plan);
        self.control.until = Some(deadline);
        self.server.engine().can_queue_routing(plan.routing)?;
        let owner = self.device.io.provider_mut().ok_or(Fault::Conflict)?;
        let id = owner.issue()?;
        let request = RouteRequest {
            id,
            action: plan.action,
            ipv4: plan.ipv4,
            ipv6: plan.ipv6,
            mtu: self.limits.mtu,
            deadline,
        };
        self.control.phase = match plan.action {
            core::RouteAction::Install => Phase::ProviderInstall,
            core::RouteAction::Remove => Phase::ProviderRemove,
            _ => return Err(Fault::Conflict.into()),
        };
        self.control.provider_pending = Some(ProviderWork::Prepared(request));
        let _accepted = self.admit_provider_route(request)?;
        Ok(())
    }

    fn admit_provider_route(&mut self, request: RouteRequest) -> Result<bool, Error> {
        let work = self.control.work.ok_or(Fault::NotReady)?;
        let owner = self.device.io.provider_mut().ok_or(Fault::Conflict)?;
        match owner.driver.begin_route(request) {
            Ok(()) => {
                self.control.provider_pending = Some(ProviderWork::Queued(request));
                self.server.engine_mut().routing_queued(work)?;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => {
                self.server.engine_mut().route_failed(work, Fault::Io)?;
                self.control.provider_pending = None;
                self.control.work = None;
                self.control
                    .provider_error
                    .get_or_insert(Error::Native(error));
                self.control.phase = if request.action == core::RouteAction::Remove {
                    Phase::Released
                } else {
                    Phase::Failed
                };
                self.request_shutdown();
            }
        }
        Ok(true)
    }

    fn provider_receipt(&mut self, receipt: RouteCompletion) -> Result<(), Error> {
        let source = self.source.ok_or(Fault::NotReady)?;
        if !matches!(self.control.provider_pending, Some(ProviderWork::Queued(request)) if request.id == receipt.id)
        {
            if self.control.phase != Phase::Ready
                || self.control.provider_installed != Some(receipt.id)
            {
                return Ok(());
            }
            let absent = match receipt.outcome {
                RouteOutcome::Installed => return Ok(()),
                RouteOutcome::Removed => true,
                RouteOutcome::Failed {
                    error,
                    routes_absent,
                } => {
                    self.control
                        .provider_error
                        .get_or_insert(Error::Native(error));
                    routes_absent
                }
            };
            self.server.engine_mut().route_lost(source, Fault::Closed)?;
            if absent {
                self.server.engine_mut().confirm_routes_absent(source)?;
            }
            self.control.provider_installed = None;
            self.control.phase = Phase::Failed;
            if self.control.provider_error.is_none() {
                self.control.provider_error = Some(Fault::Closed.into());
            }
            self.request_shutdown();
            return Ok(());
        }
        let work = self.control.work.ok_or(Fault::NotReady)?;
        let removing = self.control.phase == Phase::ProviderRemove;
        match receipt.outcome {
            RouteOutcome::Installed if !removing => {
                self.server.engine_mut().route_applied(work)?;
                self.control.provider_installed = Some(receipt.id);
                self.control.phase = Phase::Ready;
            }
            RouteOutcome::Removed if removing => {
                self.server.engine_mut().route_removed(work)?;
                self.control.provider_installed = None;
                self.control.phase = Phase::Released;
            }
            RouteOutcome::Failed {
                error,
                routes_absent,
            } => {
                self.server.engine_mut().route_failed(work, Fault::Io)?;
                if routes_absent {
                    self.server.engine_mut().confirm_routes_absent(source)?;
                }
                self.control
                    .provider_error
                    .get_or_insert(Error::Native(error));
                self.control.phase = if removing {
                    Phase::Released
                } else {
                    Phase::Failed
                };
                self.request_shutdown();
            }
            _ => {
                self.server
                    .engine_mut()
                    .route_failed(work, Fault::Conflict)?;
                self.control
                    .provider_error
                    .get_or_insert(Fault::Conflict.into());
                self.control.phase = if removing {
                    Phase::Released
                } else {
                    Phase::Failed
                };
                self.request_shutdown();
            }
        }
        self.control.provider_pending = None;
        self.control.work = None;
        self.control.until = None;
        Ok(())
    }

    pub(super) fn cancel_provider_control(&mut self) -> Result<(), Error> {
        let Some(pending) = self.control.provider_pending.take() else {
            return Ok(());
        };
        let work = self.control.work.ok_or(Fault::NotReady)?;
        let absent = match pending {
            ProviderWork::Prepared(_) => false,
            ProviderWork::Queued(request) => {
                let owner = self.device.io.provider_mut().ok_or(Fault::Conflict)?;
                match owner.driver.cancel_route(request.id) {
                    RouteOutcome::Removed => true,
                    RouteOutcome::Failed {
                        error,
                        routes_absent,
                    } => {
                        if error.kind() != io::ErrorKind::Interrupted && !routes_absent {
                            self.control
                                .provider_error
                                .get_or_insert(Error::Native(error));
                        }
                        routes_absent
                    }
                    RouteOutcome::Installed => false,
                }
            }
        };
        let removing = self.control.phase == Phase::ProviderRemove;
        if absent && removing {
            self.server.engine_mut().route_removed(work)?;
        } else {
            self.server.engine_mut().retire_routing(work)?;
            if absent {
                let source = self.source.ok_or(Fault::NotReady)?;
                self.server.engine_mut().confirm_routes_absent(source)?;
            }
        }
        self.control.work = None;
        self.control.until = None;
        self.control.phase = if removing {
            Phase::Released
        } else {
            Phase::Failed
        };
        Ok(())
    }

    pub(super) fn poll_provider_control(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        if self.control.dead || self.control.phase == Phase::Released {
            return Ok(false);
        }
        if self.control.provider_pending.is_some() {
            if self.control.until.is_some_and(|at| Instant::now() >= at) {
                self.cancel_provider_control()?;
                self.control
                    .provider_error
                    .get_or_insert(Fault::Deadline.into());
                self.request_shutdown();
                return Ok(true);
            }
            if self.stopping.is_some() && self.control.phase == Phase::ProviderInstall {
                self.cancel_provider_control()?;
                return Ok(true);
            }
        } else if self.stopping.is_some() {
            let Some(source) = self.source else {
                return Ok(false);
            };
            match self.server.engine_mut().route_cleanup_request(source) {
                Ok(plan) => {
                    let deadline = Self::deadline(self.limits.control_timeout)?
                        .min(self.stopping.ok_or(Fault::NotReady)?);
                    self.provider_request(plan, deadline)?;
                }
                Err(Fault::NotFound) => self.control.phase = Phase::Released,
                Err(error) => return Err(error.into()),
            }
            return Ok(true);
        } else if self.control.phase == Phase::New {
            let source = self.server.engine_mut().attach_tun()?;
            self.source = Some(source);
            let plan = self.server.engine_mut().routing_request(source)?;
            self.control.work = Some(plan.routing);
            if plan.ipv6.is_some() && self.limits.mtu < 1280 {
                return Err(Fault::InvalidInput.into());
            }
            self.provider_request(plan, Self::deadline(self.limits.control_timeout)?)?;
            return Ok(true);
        }
        let owner = self.device.io.provider_mut().ok_or(Fault::Conflict)?;
        let activity = if let Poll::Ready(receipt) = owner.driver.poll_route(cx) {
            self.provider_receipt(receipt)?;
            true
        } else {
            false
        };
        if let Some(ProviderWork::Prepared(request)) = self.control.provider_pending {
            // A canceled but already claimed native settings callback can keep
            // the provider busy. Keep this original revoke ID and deadline.
            return Ok(self.admit_provider_route(request)? || activity);
        }
        Ok(activity)
    }
}

#[cfg(test)]
mod tests;
