//! POST DNS translation and original VPN allocation interests.
use super::{
    Address, Allocation, Bound, Counter, Event, Failure, Fault, Job, Owner, Replacement, Request,
    addr, allocated, retryable, vpn,
};
impl<'a, 'slots> Owner<'a, 'slots> {
    pub(super) fn on_vpn_retirement(
        &mut self,
        progress: vpn::Progress<'a>,
    ) -> Result<Event, Failure> {
        self.blocked &= !4;
        match progress {
            vpn::Progress::Lost { .. } => {}
            vpn::Progress::Completed {
                operation,
                outcome: vpn::Outcome::Local { reason, submission },
                ..
            } => {
                if let Some(index) = self
                    .allocations
                    .iter()
                    .position(|row| row.operation == Some(operation))
                {
                    if reason == vpn::Reason::Lost && submission == vpn::Submission::Unsent {
                        self.allocations[index].operation = None;
                    } else {
                        let row = self.allocations.remove(index);
                        match self.core.cancel(row.request) {
                            Ok(()) | Err(Fault::Stale) => {}
                            Err(error) => return Err(error.into()),
                        }
                    }
                }
            }
            _ => return Err(Fault::Conflict.into()),
        }
        Ok(Event::Vpn)
    }
    pub(super) fn on_vpn(&mut self, p: vpn::Progress<'a>) -> Result<Event, Failure> {
        if matches!(
            &p,
            vpn::Progress::Lost { .. }
                | vpn::Progress::Completed {
                    outcome: vpn::Outcome::Local { .. },
                    ..
                }
        ) {
            return self.on_vpn_retirement(p);
        }
        self.blocked &= !4;
        if let vpn::Progress::Unavailable(error) = p {
            self.blocked |= 4;
            self.delay()?;
            return Ok(Event::CleanupFailure(error.into()));
        }
        if matches!(p, vpn::Progress::ConnectRetry { .. }) {
            self.blocked |= 4;
            self.delay()?;
            return Ok(Event::Backpressure);
        }
        if let vpn::Progress::Completed {
            operation,
            outcome: vpn::Outcome::Allocation(address),
            ..
        } = p
            && let Some(i) = self
                .allocations
                .iter()
                .position(|r| r.operation == Some(operation))
        {
            let now = self.clock.sample()?.now.as_micros();
            let row = self.allocations.remove(i);
            if row.bounds.live(now) {
                let allocation = address.map(|address| Replacement {
                    address: allocated(address),
                    lease_until: row.bounds.expires,
                });
                match self.core.allocation(row.job, allocation, now) {
                    Ok(()) => {
                        if allocation.is_some() {
                            self.metrics.bump(Counter::Modified);
                        }
                    }
                    Err(Fault::Stale) => {}
                    Err(e) => return Err(e.into()),
                }
            } else {
                match self.core.cancel(row.request) {
                    Ok(()) | Err(Fault::Stale) => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
        Ok(Event::Vpn)
    }
    pub(super) fn post_allocation(&mut self, now: u64) -> Result<Option<Event>, Failure> {
        if let Some(i) = self.allocations.iter().position(|r| r.operation.is_none()) {
            let r = &self.allocations[i];
            if !r.bounds.live(now) {
                return Ok(None);
            }
            let desired = Some(match r.destination {
                Address::V4(_) => vpn::Family::V4,
                Address::V6(_) => vpn::Family::V6,
            });
            match self.vpn.as_mut().ok_or(Fault::Unavailable)?.internet(
                addr(r.destination),
                desired,
                r.bounds.expires,
                r.bounds.expires,
            ) {
                Ok(op) => {
                    self.allocations[i].operation = Some(op);
                    return Ok(Some(Event::Admitted));
                }
                Err(e) if retryable(&e) => {
                    self.delay()?;
                    return Ok(Some(Event::Backpressure));
                }
                Err(e) => {
                    let r = self.allocations.remove(i);
                    self.core.allocation(r.job, None, now)?;
                    self.failed_cleanup(e.into());
                    return Ok(Some(Event::Vpn));
                }
            }
        }
        Ok(None)
    }

    pub(super) fn queue_allocation(
        &mut self,
        job: Job<'a>,
        request: Request<'a>,
        destination: Address,
        lease_until: u64,
    ) -> Result<Event, Failure> {
        let callback = self
            .callbacks
            .iter()
            .find(|r| r.core == Some(request))
            .ok_or(Fault::Stale)?;
        if self.allocations.len() >= self.allocations.capacity() {
            return Err(Fault::Capacity.into());
        }
        self.allocations.push(Allocation {
            job,
            request,
            destination,
            bounds: Bound {
                expires: lease_until,
                hard: callback.bounds.hard,
            },
            operation: None,
        });
        Ok(Event::Admitted)
    }
}

#[cfg(test)]
mod tests;
