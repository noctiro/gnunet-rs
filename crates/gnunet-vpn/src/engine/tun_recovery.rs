//! Fresh packet generations retain the same independently owned route scope.
use super::{Engine, Error, RouteAction, RouteState, Routing, RoutingRequest, Tun, TunState, Work};

impl<'id> Engine<'id, '_, '_> {
    /// Check whether the lost source's original jobs, flows and packet effects
    /// have quiesced enough to replace its packet session on the same interface.
    ///
    /// # Errors
    /// Returns WouldBlock while original debt remains, Closed after borrowed
    /// scope release, and StaleGeneration for an unrelated source.
    pub fn can_rebind_tun(&self, tun: Tun<'id>) -> Result<(), Error> {
        let old = self.tun_ref(tun, false)?;
        if old.routes == RouteState::BorrowedReleased {
            return Err(Error::Closed);
        }
        if !old.dead
            || old.routing.is_some()
            || self.store.flows.iter().any(|flow| flow.state.is_some())
            || self
                .store
                .packets
                .iter()
                .any(|packet| packet.state.is_some())
        {
            return Err(Error::WouldBlock);
        }
        Ok(())
    }

    /// Attach a fresh packet generation on the retained original native
    /// interface. The adapter must prove that identity separately; a reopened
    /// name, reused index or different device cannot use this port. Original
    /// owned route debt transfers without claiming absence or borrowed ownership.
    /// The new source remains unready until actual configuration verification.
    ///
    /// # Errors
    /// Returns the same errors as [`Self::can_rebind_tun`], or Overflow before
    /// changing the original source when the generation space is exhausted.
    pub fn rebind_tun_same_interface(&mut self, tun: Tun<'id>) -> Result<Tun<'id>, Error> {
        self.can_rebind_tun(tun)?;
        let old = self.tun_ref(tun, false)?;
        let routes = if old.routes.is_borrowed() {
            RouteState::BorrowedUnverified
        } else if old.routes == RouteState::Absent {
            RouteState::Absent
        } else {
            RouteState::Unknown
        };
        let serial = self.serial()?;
        self.tun = Some(TunState {
            serial,
            dead: false,
            routing: None,
            ready: false,
            failure: None,
            routes,
            routing_action: RouteAction::Install,
        });
        Ok(Tun {
            domain: self.domain,
            serial,
        })
    }

    /// Offer read-only verification of an already owned route scope on the
    /// same original interface. No configuration or mutation is authorized.
    ///
    /// # Errors
    /// Refuses borrowed or absent scopes, a ready/dead source, outstanding work
    /// and exhausted generation space. Refusal preserves existing route debt.
    pub fn routing_verification_request(
        &mut self,
        tun: Tun<'id>,
    ) -> Result<RoutingRequest<'id>, Error> {
        self.owned_recovery_request(tun, RouteAction::Verify)
    }

    /// Offer restoration after a proved packet descriptor close on the same
    /// exclusively owned interface. The provider must observe the original
    /// scope before repair and verify the complete plan before admission.
    ///
    /// # Errors
    /// Refuses the same states as [`Self::routing_verification_request`].
    pub fn routing_restoration_request(
        &mut self,
        tun: Tun<'id>,
    ) -> Result<RoutingRequest<'id>, Error> {
        self.owned_recovery_request(tun, RouteAction::Restore)
    }

    fn owned_recovery_request(
        &mut self,
        tun: Tun<'id>,
        action: RouteAction,
    ) -> Result<RoutingRequest<'id>, Error> {
        let old = self.tun_ref(tun, true)?;
        if !matches!(old.routes, RouteState::Present | RouteState::Unknown) {
            return Err(Error::PermissionDenied);
        }
        if old.ready || old.routing.is_some() {
            return Err(Error::WouldBlock);
        }
        let serial = self.serial()?;
        let state = self.tun.as_mut().ok_or(Error::StaleGeneration)?;
        state.routing = Some(Work {
            serial,
            queued: false,
            revoked: false,
        });
        state.routing_action = action;
        Ok(RoutingRequest {
            action,
            routing: Routing { tun, serial },
            ipv4: self.limits.ipv4,
            ipv6: self.limits.ipv6,
        })
    }

    /// Accept actual complete interface, route and DAD verification for the
    /// retained owned scope. The provider must finish its original query jobs;
    /// local admission or source replacement alone grants no readiness.
    ///
    /// # Errors
    /// Refuses another action, unqueued/revoked work and stale/dead sources.
    pub fn route_reverified(&mut self, routing: Routing<'id>) -> Result<(), Error> {
        self.finish_owned_recovery(routing, RouteAction::Verify)
    }

    /// Accept the completed restoration of the exact original owned plan.
    /// This requires current interface, address, DAD and route observations.
    ///
    /// # Errors
    /// Refuses the same states as [`Self::route_reverified`].
    pub fn route_restored(&mut self, routing: Routing<'id>) -> Result<(), Error> {
        self.finish_owned_recovery(routing, RouteAction::Restore)
    }

    fn finish_owned_recovery(
        &mut self,
        routing: Routing<'id>,
        action: RouteAction,
    ) -> Result<(), Error> {
        let old = self.tun_ref(routing.tun, true)?;
        let work = self.routing_ref(routing, true)?;
        if old.routing_action != action || old.routes.is_borrowed() {
            return Err(Error::PermissionDenied);
        }
        if !work.queued {
            return Err(Error::NotReady);
        }
        if work.revoked {
            return Err(Error::StaleGeneration);
        }
        let state = self.tun.as_mut().ok_or(Error::StaleGeneration)?;
        state.routing = None;
        state.routes = RouteState::Present;
        state.ready = true;
        state.failure = None;
        Ok(())
    }
}
