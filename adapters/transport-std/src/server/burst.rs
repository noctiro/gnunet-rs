//! Actual original native1253 ownership/deadline and1254 written-source guard.
//! One fixed sidecar for the single burst; ordinary frames remain untagged.
use crate::server::*;
use gnunet_transport::{burst, dv_bridge::Source};
use gnunet_types::Duration as Micros;
pub(crate) struct Guard {
    id: burst::Id,
    owner: ClientId,
    hard: Instant,
    queued_end: Option<u64>,
}
impl Server {
    /// Borrow the exact original finite demand/selected communicator.
    pub fn burst_request(&self) -> Option<&burst::Request> {
        self.engine.burst_request()
    }
    /// Take the actual original terminal fact; no remote success is implied.
    pub fn take_burst_outcome(&mut self) -> Option<burst::Outcome> {
        self.engine.take_burst_outcome()
    }
    /// Bind actual confirmed measured DV RTT to this original Engine source.
    /// Only the actual actor/grant bridge supplies this synchronization hint.
    pub fn burst_dv_path(
        &mut self,
        source: &Source,
        peer: PeerId,
        rtt: Micros,
        remaining: Micros,
        times: Times,
    ) -> Result<(), Error> {
        self.engine
            .burst_dv_path(source, peer, rtt, remaining, times)
    }
    /// Supply a real HELLO-derived literal IP hint under its actual expiration.
    pub fn burst_candidate(
        &mut self,
        id: &burst::Id,
        address: &[u8],
        expiration: AbsoluteTime,
        times: Times,
    ) -> Result<(), Error> {
        self.engine.burst_candidate(id, address, expiration, times)
    }
    /// Cancel only original preparation; admitted commands require native close.
    pub fn cancel_burst(&mut self, id: &burst::Id, reason: burst::End) -> Result<(), Error> {
        self.engine.cancel_burst(id, reason)
    }
    /// Drive original delay/output admission, not remote traversal success.
    pub fn drive_burst(&mut self, times: Times) -> Result<bool, Error> {
        self.engine.drive_burst(times)
    }
    /// Register one original native command target before any1253 output IO.
    /// Repeated calls can only shorten it, never renew an old command's bound.
    pub fn arm_burst(&mut self, id: &burst::Id, hard: Instant) -> Result<(), Error> {
        let request = self
            .engine
            .burst_request()
            .filter(|r| r.id == *id)
            .ok_or(Error::Stale)?;
        let owner = request.selected.clone().ok_or(Error::NotReady)?;
        if !self.clients.iter().any(|c| c.id == owner) {
            return Err(Error::Stale);
        }
        if let Some(original) = &mut self.burst_deadline
            && original.id == *id
        {
            if original.owner != owner {
                return Err(Error::Stale);
            }
            original.hard = original.hard.min(hard);
        } else {
            self.burst_deadline = Some(Guard {
                id: id.clone(),
                owner,
                hard,
                queued_end: None,
            });
        }
        if let Some(owner) = self.burst_expired(Instant::now())? {
            self.close_client(&owner)?;
        }
        Ok(())
    }
    pub(crate) fn burst_expired(&mut self, now: Instant) -> Result<Option<ClientId>, Error> {
        let Some(guard) = &self.burst_deadline else {
            return Ok(None);
        };
        let matches = self
            .engine
            .burst_request()
            .is_some_and(|r| r.id == guard.id && r.selected.as_ref() == Some(&guard.owner));
        if !matches {
            self.burst_deadline = None;
            return Ok(None);
        }
        if now >= guard.hard
            || self
                .engine
                .burst_request()
                .is_some_and(|r| r.stage == burst::Stage::Closing)
        {
            let id = guard.id.clone();
            let owner = guard.owner.clone();
            self.engine.expire_burst_command(&id)?;
            return Ok(Some(owner));
        }
        Ok(None)
    }
    pub(crate) fn burst_next_deadline(&self) -> Option<Instant> {
        self.burst_deadline.as_ref().map(|g| g.hard)
    }
    pub(crate) fn burst_queue_allowed(&self, owner: &ClientId) -> bool {
        self.burst_deadline.as_ref().is_some_and(|g| {
            g.owner == *owner
                && Instant::now() < g.hard
                && self
                    .engine
                    .burst_request()
                    .is_some_and(|r| r.id == g.id && r.stage == burst::Stage::Enqueued)
        })
    }
    pub(crate) fn burst_queued(&mut self, owner: &ClientId, end: u64) -> Result<(), Error> {
        let guard = self
            .burst_deadline
            .as_mut()
            .filter(|g| g.owner == *owner)
            .ok_or(Error::Stale)?;
        if guard.queued_end.is_some() {
            return Err(Error::Stale);
        }
        guard.queued_end = Some(end);
        Ok(())
    }
    pub(crate) fn burst_callback_allowed(&self, owner: &ClientId) -> bool {
        self.burst_deadline.as_ref().is_some_and(|g| {
            g.owner == *owner
                && Instant::now() < g.hard
                && g.queued_end.is_some_and(|end| {
                    self.clients
                        .iter()
                        .find(|c| c.id == *owner)
                        .is_some_and(|c| c.io.written_cursor() >= end)
                })
                && self
                    .engine
                    .burst_request()
                    .is_some_and(|r| r.id == g.id && r.stage == burst::Stage::Enqueued)
        })
    }
    pub(crate) fn burst_native_closed(&mut self, owner: &ClientId) {
        if self
            .burst_deadline
            .as_ref()
            .is_some_and(|g| g.owner == *owner)
        {
            self.burst_deadline = None;
        }
    }
}
