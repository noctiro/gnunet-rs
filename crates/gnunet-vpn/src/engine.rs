//! Bounded owner; actual asynchronous/physical ports are supplied by the caller.
mod effects;
mod forward;
mod leases;
use crate::*;
use core::ptr;
use gnunet_types::{AbsoluteTime, Error, MonoInstant};
/// Allocation-free actual lease/flow/packet owner. Shared caller packet slabs
/// retain immutable originals until exact writing or physical-source retirement.
pub struct Engine<'id, 'store, 'bytes> {
    domain: &'id Instance,
    store: Storage<'store, 'bytes>,
    limits: Limits,
    tun: Option<TunState>,
    request_cursor: usize,
    flow_cursor: usize,
    last_activity: Option<MonoInstant>,
}
impl<'id, 'store, 'bytes> Engine<'id, 'store, 'bytes> {
    /// Reserve only caller storage. No device, route, discovery, channel or
    /// successful allocation is fabricated by construction.
    pub fn new(
        domain: &'id mut Instance,
        store: Storage<'store, 'bytes>,
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.ipc_af.validate()?;
        limits.peer_af.validate()?;
        if limits.packet_bytes < 48
            || limits.packet_bytes > 65575
            || limits.idle_micros == 0
            || limits.idle_micros == u64::MAX
            || store.clients.is_empty()
            || store.requests.is_empty()
            || store.leases.is_empty()
            || store.flows.is_empty()
            || store.packets.is_empty()
            || store.clients.iter().any(|x| x.state.is_some())
            || store.requests.iter().any(|x| x.state.is_some())
            || store.leases.iter().any(|x| x.state.is_some())
            || store.flows.iter().any(|x| x.state.is_some())
            || store.packets.iter().any(|x| x.state.is_some())
        {
            return Err(Error::InvalidInput);
        }
        let body_limit = limits.packet_bytes.max(
            limits
                .packet_bytes
                .checked_add(4)
                .ok_or(Error::Overflow)?
                .min(gnunet_wire::official::cadet::MAX_APPLICATION_MESSAGE_SIZE),
        );
        if !store.packets.iter().any(|p| p.bytes.len() >= body_limit) {
            return Err(Error::InvalidInput);
        }
        if let Some(p) = limits.ipv4 {
            p.validate()?;
            if p.network.family() != Family::V4 {
                return Err(Error::InvalidInput);
            }
        }
        if let Some(p) = limits.ipv6 {
            p.validate()?;
            if p.network.family() != Family::V6 {
                return Err(Error::InvalidInput);
            }
        }
        Ok(Self {
            domain,
            store,
            limits,
            tun: None,
            request_cursor: 0,
            flow_cursor: 0,
            last_activity: None,
        })
    }
    /// Untouched origin suitable for binding one native activity epoch. Empty
    /// pools after prior work do not authorize restarting that original epoch.
    #[must_use]
    pub fn is_pristine(&self) -> bool {
        self.domain.next.get() == 0
            && self.last_activity.is_none()
            && self.tun.is_none()
            && self.request_cursor == 0
            && self.flow_cursor == 0
            && self.store.clients.iter().all(|row| row.state.is_none())
            && self.store.requests.iter().all(|row| row.state.is_none())
            && self.store.leases.iter().all(|row| row.state.is_none())
            && self.store.flows.iter().all(|row| row.state.is_none())
            && self.store.packets.iter().all(|row| row.state.is_none())
    }
    fn observe_activity(&mut self, now: MonoInstant) -> Result<(), Error> {
        if self.last_activity.is_some_and(|last| now < last) {
            return Err(Error::TimeUncertain);
        }
        self.last_activity = Some(now);
        Ok(())
    }
    fn serial(&self) -> Result<u64, Error> {
        let n = self
            .domain
            .next
            .get()
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        self.domain.next.set(n);
        Ok(n)
    }
    fn preflight(&self, n: u64) -> Result<(), Error> {
        self.domain
            .next
            .get()
            .checked_add(n)
            .ok_or(Error::Overflow)?;
        Ok(())
    }
    fn handle(&self, r: Reference) -> Handle<'id> {
        Handle {
            domain: self.domain,
            row: r.row,
            serial: r.serial,
        }
    }
    fn reference(&self, h: Handle<'id>) -> Result<Reference, Error> {
        if !ptr::eq(h.domain, self.domain) {
            return Err(Error::StaleGeneration);
        }
        Ok(Reference {
            row: h.row,
            serial: h.serial,
        })
    }
    fn client_ref(&self, client: Client<'id>) -> Result<Reference, Error> {
        let r = self.reference(client.0)?;
        if self
            .store
            .clients
            .get(r.row)
            .and_then(|x| x.state)
            .is_none_or(|x| x.serial != r.serial)
        {
            return Err(Error::StaleGeneration);
        }
        Ok(r)
    }
    fn request_ref(&self, request: Request<'id>) -> Result<Reference, Error> {
        let r = self.reference(request.0)?;
        if self
            .store
            .requests
            .get(r.row)
            .and_then(|x| x.state)
            .is_none_or(|x| x.serial != r.serial)
        {
            return Err(Error::StaleGeneration);
        }
        Ok(r)
    }
    fn lease_ref(&self, lease: Lease<'id>) -> Result<Reference, Error> {
        let r = self.reference(lease.0)?;
        if self
            .store
            .leases
            .get(r.row)
            .and_then(|x| x.state)
            .is_none_or(|x| x.serial != r.serial)
        {
            return Err(Error::StaleGeneration);
        }
        Ok(r)
    }
    fn flow_ref(&self, flow: Flow<'id>) -> Result<Reference, Error> {
        let r = self.reference(flow.0)?;
        if self
            .store
            .flows
            .get(r.row)
            .and_then(|x| x.state)
            .is_none_or(|x| x.serial != r.serial)
        {
            return Err(Error::StaleGeneration);
        }
        Ok(r)
    }
    fn buffer_ref(&self, buffer: Buffer<'id>) -> Result<Reference, Error> {
        let r = self.reference(buffer.0)?;
        if self
            .store
            .packets
            .get(r.row)
            .and_then(|x| x.state)
            .is_none_or(|x| x.serial != r.serial)
        {
            return Err(Error::StaleGeneration);
        }
        Ok(r)
    }
    fn tun_ref(&self, tun: Tun<'id>, live: bool) -> Result<TunState, Error> {
        if !ptr::eq(tun.domain, self.domain) {
            return Err(Error::StaleGeneration);
        }
        self.tun
            .filter(|t| t.serial == tun.serial && (!live || !t.dead))
            .ok_or(Error::StaleGeneration)
    }
    fn current_tun(&self) -> Result<Tun<'id>, Error> {
        let t = self
            .tun
            .filter(|t| !t.dead && t.ready)
            .ok_or(Error::Unavailable)?;
        Ok(Tun {
            domain: self.domain,
            serial: t.serial,
        })
    }
    fn flow(&self, r: Reference) -> Flow<'id> {
        Flow(self.handle(r))
    }
    fn peer_ref(&self, peer: Peer<'id>) -> Result<Reference, Error> {
        let r = self.flow_ref(peer.flow)?;
        let f = self.store.flows[r.row]
            .state
            .ok_or(Error::StaleGeneration)?;
        if f.source != Some(peer.serial) || f.peer != Some(peer.identity) {
            return Err(Error::StaleGeneration);
        }
        Ok(r)
    }
    fn peer(&self, r: Reference) -> Result<Peer<'id>, Error> {
        let f = self.store.flows[r.row]
            .state
            .ok_or(Error::StaleGeneration)?;
        Ok(Peer {
            flow: self.flow(r),
            serial: f.source.ok_or(Error::NotReady)?,
            identity: f.peer.ok_or(Error::NotReady)?,
        })
    }
    fn packet_slot(&self, len: usize) -> Result<usize, Error> {
        self.store
            .packets
            .iter()
            .enumerate()
            .filter(|(_, p)| p.state.is_none() && p.bytes.len() >= len)
            .min_by_key(|(_, p)| p.bytes.len())
            .map(|(i, _)| i)
            .ok_or(Error::Capacity)
    }
    /// Whether an original TUN source or unretired tombstone occupies this
    /// engine. A dead source still requires original jobs/effects to retire.
    #[must_use]
    pub const fn has_tun_source(&self) -> bool {
        self.tun.is_some()
    }
    /// Actual original native TUN attachment. The caller must already own the
    /// verified device; address leases require route_applied or an actual
    /// route_borrowed_verified receipt for this original source.
    pub fn attach_tun(&mut self) -> Result<Tun<'id>, Error> {
        if self.tun.is_some()
            || self.store.flows.iter().any(|f| f.state.is_some())
            || self.store.packets.iter().any(|p| p.state.is_some())
        {
            return Err(Error::Conflict);
        }
        let serial = self.serial()?;
        self.tun = Some(TunState {
            serial,
            dead: false,
            routing: None,
            ready: false,
            failure: None,
            routes: RouteState::Absent,
            routing_action: RouteAction::Install,
        });
        Ok(Tun {
            domain: self.domain,
            serial,
        })
    }
    /// Offer actual prefix/interface provisioning or verified-native-route work.
    /// Configuration validation and a queued write are not route success.
    pub fn routing_request(&mut self, tun: Tun<'id>) -> Result<RoutingRequest<'id>, Error> {
        let t = self.tun_ref(tun, true)?;
        if t.ready {
            return Err(Error::Conflict);
        }
        if t.routes == RouteState::BorrowedReleased {
            return Err(Error::Closed);
        }
        if self.limits.ipv4.is_none() && self.limits.ipv6.is_none() {
            return Err(Error::Unavailable);
        }
        let work = if let Some(w) = t.routing {
            if t.routing_action != RouteAction::Install {
                return Err(Error::WouldBlock);
            }
            if w.queued || w.revoked {
                return Err(Error::WouldBlock);
            }
            w
        } else {
            let w = Work {
                serial: self.serial()?,
                queued: false,
                revoked: false,
            };
            let t = self.tun.as_mut().ok_or(Error::StaleGeneration)?;
            t.routing = Some(w);
            t.routing_action = RouteAction::Install;
            w
        };
        Ok(RoutingRequest {
            action: RouteAction::Install,
            routing: Routing {
                tun,
                serial: work.serial,
            },
            ipv4: self.limits.ipv4,
            ipv6: self.limits.ipv6,
        })
    }
    fn routing_ref(&self, routing: Routing<'id>, live: bool) -> Result<Work, Error> {
        self.tun_ref(routing.tun, live)?
            .routing
            .filter(|w| w.serial == routing.serial)
            .ok_or(Error::StaleGeneration)
    }
    /// Check original live OS-route work before an actual native submission.
    pub fn can_queue_routing(&self, routing: Routing<'id>) -> Result<(), Error> {
        let t = self.tun_ref(routing.tun, false)?;
        let w = self.routing_ref(routing, false)?;
        if t.routing_action == RouteAction::Install && t.routes.is_borrowed() {
            return Err(Error::PermissionDenied);
        }
        if w.queued || w.revoked || (t.dead && t.routing_action == RouteAction::Install) {
            return Err(Error::Closed);
        }
        Ok(())
    }
    /// Check an original read-only external-route verification before native
    /// admission. Existing owned/uncertain effects cannot become borrowed.
    pub fn can_queue_borrowed_routing(&self, routing: Routing<'id>) -> Result<(), Error> {
        let t = self.tun_ref(routing.tun, true)?;
        let work = self.routing_ref(routing, true)?;
        if t.routing_action != RouteAction::Install {
            return Err(Error::Conflict);
        }
        if !matches!(
            t.routes,
            RouteState::Absent | RouteState::BorrowedUnverified
        ) {
            return Err(Error::PermissionDenied);
        }
        if work.queued || work.revoked {
            return Err(Error::Closed);
        }
        Ok(())
    }
    /// Atomically record this original query's read-only provider admission and
    /// borrowed mode, before the provider can produce effects or callbacks. An
    /// admission refusal then settles this original query through route_failed.
    /// Query failure/late completion creates no owned route cleanup authority.
    pub fn routing_borrowed_queued(&mut self, routing: Routing<'id>) -> Result<(), Error> {
        self.can_queue_borrowed_routing(routing)?;
        let t = self.tun.as_mut().ok_or(Error::StaleGeneration)?;
        t.routing.as_mut().ok_or(Error::StaleGeneration)?.queued = true;
        t.routes = RouteState::BorrowedUnverified;
        Ok(())
    }
    /// Original OS provision/verification/removal command actually admitted.
    pub fn routing_queued(&mut self, routing: Routing<'id>) -> Result<(), Error> {
        self.can_queue_routing(routing)?;
        self.tun
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .routing
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .queued = true;
        Ok(())
    }
    /// Only the actual successful OS-route/interface receipt may call this port.
    /// A helper/route command's local write alone must not call it.
    pub fn route_applied(&mut self, routing: Routing<'id>) -> Result<(), Error> {
        let w = self.routing_ref(routing, true)?;
        let t = self.tun_ref(routing.tun, true)?;
        if t.routing_action != RouteAction::Install {
            return Err(Error::Conflict);
        }
        if t.routes.is_borrowed() {
            return Err(Error::PermissionDenied);
        }
        if !w.queued {
            return Err(Error::NotReady);
        }
        if w.revoked {
            return Err(Error::StaleGeneration);
        }
        let t = self.tun.as_mut().ok_or(Error::StaleGeneration)?;
        t.routing = None;
        t.ready = true;
        t.routes = RouteState::Present;
        t.failure = None;
        Ok(())
    }
    /// Only actual current external-route/interface verification for the exact
    /// original query may grant borrowed readiness. This never owns those
    /// routes, requests their deletion, or converts them into an owned plan.
    pub fn route_borrowed_verified(&mut self, routing: Routing<'id>) -> Result<(), Error> {
        let work = self.routing_ref(routing, true)?;
        let t = self.tun_ref(routing.tun, true)?;
        if t.routing_action != RouteAction::Install || t.routes != RouteState::BorrowedUnverified {
            return Err(Error::Conflict);
        }
        if !work.queued {
            return Err(Error::NotReady);
        }
        if work.revoked {
            return Err(Error::StaleGeneration);
        }
        let t = self.tun.as_mut().ok_or(Error::StaleGeneration)?;
        t.routing = None;
        t.ready = true;
        t.routes = RouteState::BorrowedVerified;
        t.failure = None;
        Ok(())
    }
    /// Original OS job actually failed/retired; permits cleanup even for a revoked
    /// or physically lost old TUN source, never authenticates a replacement source.
    pub fn route_failed(&mut self, routing: Routing<'id>, reason: Error) -> Result<(), Error> {
        let work = self.routing_ref(routing, false)?;
        let t = self.tun.as_mut().ok_or(Error::StaleGeneration)?;
        t.routing = None;
        t.ready = false;
        t.failure = Some(reason);
        if matches!(
            t.routes,
            RouteState::BorrowedVerified | RouteState::BorrowedUnverified
        ) {
            t.routes = RouteState::BorrowedUnverified;
        } else if work.queued {
            t.routes = RouteState::Unknown;
        }
        Ok(())
    }
    /// Actual original route job quiesced after its result became stale. This
    /// consumes only its debt; it cannot make the TUN/routes ready again.
    pub fn retire_routing(&mut self, routing: Routing<'id>) -> Result<(), Error> {
        let work = self.routing_ref(routing, false)?;
        let t = self.tun.as_mut().ok_or(Error::StaleGeneration)?;
        t.routing = None;
        t.ready = false;
        if matches!(
            t.routes,
            RouteState::BorrowedVerified | RouteState::BorrowedUnverified
        ) {
            t.routes = RouteState::BorrowedUnverified;
        } else if work.queued {
            t.routes = RouteState::Unknown;
        }
        Ok(())
    }
    /// Actual native route observation invalidated this original ready plan.
    pub fn route_lost(&mut self, tun: Tun<'id>, reason: Error) -> Result<(), Error> {
        self.tun_ref(tun, true)?;
        let t = self.tun.as_mut().ok_or(Error::StaleGeneration)?;
        t.ready = false;
        t.failure = Some(reason);
        if matches!(
            t.routes,
            RouteState::BorrowedVerified | RouteState::BorrowedUnverified
        ) {
            t.routes = RouteState::BorrowedUnverified;
        } else if !t.routes.is_borrowed()
            && (t.routes != RouteState::Absent || t.routing.is_some_and(|w| w.queued))
        {
            t.routes = RouteState::Unknown;
        }
        if t.routing_action == RouteAction::Install
            && let Some(w) = t.routing.as_mut()
        {
            w.revoked = true;
        }
        for row in 0..self.store.flows.len() {
            if let Some(f) = self.store.flows[row].state {
                self.close_flow(
                    self.flow(Reference {
                        row,
                        serial: f.serial,
                    }),
                    reason,
                )?;
            }
        }
        Ok(())
    }
    /// Current original route/device readiness, never inferred from configuration.
    pub fn tun_ready(&self, tun: Tun<'id>) -> Result<bool, Error> {
        let t = self.tun_ref(tun, false)?;
        Ok(!t.dead && t.ready)
    }
    /// Original actual route/device failure classification, if any.
    pub fn tun_failure(&self, tun: Tun<'id>) -> Result<Option<Error>, Error> {
        Ok(self.tun_ref(tun, false)?.failure)
    }
    /// Original owned effects or borrowed verification/release state,
    /// independent of TUN fd and actual provider-job quiescence.
    pub fn route_state(&self, tun: Tun<'id>) -> Result<RouteState, Error> {
        Ok(self.tun_ref(tun, false)?.routes)
    }
    /// Offer real cleanup or reconciliation of the original owned route scope,
    /// even after its TUN fd stopped. Native provider must not remove other owners'
    /// routes. Source close/job retirement alone cannot satisfy this operation.
    pub fn route_cleanup_request(&mut self, tun: Tun<'id>) -> Result<RoutingRequest<'id>, Error> {
        let t = self.tun_ref(tun, false)?;
        if t.routing.is_some() {
            return Err(Error::WouldBlock);
        }
        if t.routes.is_borrowed() {
            return Err(Error::PermissionDenied);
        }
        if t.routes == RouteState::Absent {
            return Err(Error::NotFound);
        }
        let serial = self.serial()?;
        let t = self.tun.as_mut().ok_or(Error::StaleGeneration)?;
        t.routing = Some(Work {
            serial,
            queued: false,
            revoked: false,
        });
        t.routing_action = RouteAction::Remove;
        t.ready = false;
        for row in 0..self.store.flows.len() {
            if let Some(f) = self.store.flows[row].state {
                self.close_flow(
                    self.flow(Reference {
                        row,
                        serial: f.serial,
                    }),
                    Error::Closed,
                )?;
            }
        }
        Ok(RoutingRequest {
            action: RouteAction::Remove,
            routing: Routing { tun, serial },
            ipv4: self.limits.ipv4,
            ipv6: self.limits.ipv6,
        })
    }
    /// Only actual original-scope native cleanup/ownership-release verification
    /// may call this success port. A blind fd Drop or queued write is insufficient;
    /// a verified original-source platform close contract may prove the cleanup.
    pub fn route_removed(&mut self, routing: Routing<'id>) -> Result<(), Error> {
        let t = self.tun_ref(routing.tun, false)?;
        let work = self.routing_ref(routing, false)?;
        if t.routing_action != RouteAction::Remove || !work.queued || work.revoked {
            return Err(Error::NotReady);
        }
        let t = self.tun.as_mut().ok_or(Error::StaleGeneration)?;
        t.routing = None;
        t.routes = RouteState::Absent;
        t.ready = false;
        t.failure = None;
        Ok(())
    }
    /// Release only the logical borrowed view, after its actual original query
    /// job quiesced. External routes are neither deleted nor claimed absent.
    /// Existing channel/packet/source debt still retires independently.
    pub fn release_borrowed_routes(&mut self, tun: Tun<'id>) -> Result<(), Error> {
        let t = self.tun_ref(tun, false)?;
        if t.routing.is_some() {
            return Err(Error::WouldBlock);
        }
        if !t.routes.is_borrowed() {
            return Err(Error::PermissionDenied);
        }
        let t = self.tun.as_mut().ok_or(Error::StaleGeneration)?;
        t.ready = false;
        t.routes = RouteState::BorrowedReleased;
        for row in 0..self.store.flows.len() {
            if let Some(f) = self.store.flows[row].state {
                self.close_flow(
                    self.flow(Reference {
                        row,
                        serial: f.serial,
                    }),
                    Error::Closed,
                )?;
            }
        }
        Ok(())
    }
    /// Actual original-scope native proof confirms no owned route effects remain.
    /// This may use a verified platform close/device-removal contract instead of
    /// a new syscall. It must reference this original Tun, never a new epoch or a
    /// guessed reused ifindex. No pending original route job may reapply effects.
    pub fn confirm_routes_absent(&mut self, tun: Tun<'id>) -> Result<(), Error> {
        let t = self.tun_ref(tun, false)?;
        if t.routes.is_borrowed() {
            return Err(Error::PermissionDenied);
        }
        if t.routing.is_some() || t.ready {
            return Err(Error::WouldBlock);
        }
        self.tun.as_mut().ok_or(Error::StaleGeneration)?.routes = RouteState::Absent;
        Ok(())
    }
    /// Actual local IPC AF profile, so adapters decode with this same source
    /// profile rather than a second possibly inconsistent configuration value.
    #[must_use]
    pub const fn ipc_af(&self) -> AfProfile {
        self.limits.ipc_af
    }
    /// Original owning local MQ of a retained request, even after actual loss.
    /// This grants no permission to admit a replacement source or revive it.
    pub fn request_client(&self, request: Request<'id>) -> Result<Client<'id>, Error> {
        let r = self.request_ref(request)?;
        let request = self.store.requests[r.row]
            .state
            .ok_or(Error::StaleGeneration)?;
        Ok(Client(self.handle(request.client)))
    }
    /// Actual current flow facts; no source capability is minted by inspection.
    pub fn flow_info(&self, flow: Flow<'id>) -> Result<FlowInfo, Error> {
        let r = self.flow_ref(flow)?;
        let f = self.store.flows[r.row]
            .state
            .ok_or(Error::StaleGeneration)?;
        Ok(FlowInfo {
            tuple: f.tuple,
            target: f.target,
            phase: f.phase,
            last_used: f.used,
            failure: f.failure,
        })
    }
    /// Original allocation facts; an expired/reused lease token is stale.
    pub fn lease_info(&self, lease: Lease<'id>) -> Result<LeaseInfo, Error> {
        let r = self.lease_ref(lease)?;
        let l = self.store.leases[r.row]
            .state
            .ok_or(Error::StaleGeneration)?;
        Ok(LeaseInfo {
            address: l.address,
            target: l.target,
            expires: l.expires,
        })
    }
    /// Original response/callback outcome, separate from current lease validity.
    pub fn request_info(&self, request: Request<'id>) -> Result<RequestInfo<'id>, Error> {
        let r = self.request_ref(request)?;
        let s = self.store.requests[r.row]
            .state
            .ok_or(Error::StaleGeneration)?;
        Ok(RequestInfo {
            request_id: s.id,
            lease: s
                .lease
                .filter(|r| {
                    self.store
                        .leases
                        .get(r.row)
                        .and_then(|l| l.state)
                        .is_some_and(|l| l.serial == r.serial)
                })
                .map(|r| Lease(self.handle(r))),
            canceled: s.canceled,
            outcome: s.status,
        })
    }
    /// Original buffered packet's retained physical outcome.
    pub fn buffer_outcome(&self, buffer: Buffer<'id>) -> Result<Outcome, Error> {
        let r = self.buffer_ref(buffer)?;
        Ok(self.store.packets[r.row]
            .state
            .ok_or(Error::StaleGeneration)?
            .status)
    }
    /// Current complete bytes while this original buffer is retained. Initial
    /// peer AF metadata may be normalized at first actual source binding, before
    /// any prepared effect exists; prepared/native originals never change.
    pub fn buffer_bytes(&self, buffer: Buffer<'id>) -> Result<&[u8], Error> {
        let r = self.buffer_ref(buffer)?;
        let p = &self.store.packets[r.row];
        Ok(&p.bytes[..p.state.ok_or(Error::StaleGeneration)?.len])
    }
    /// Actual retained flow handles, including original close/drain debt.
    pub fn flows(&self) -> impl Iterator<Item = Flow<'id>> + '_ {
        self.store.flows.iter().enumerate().filter_map(|(row, f)| {
            f.state.map(|f| {
                self.flow(Reference {
                    row,
                    serial: f.serial,
                })
            })
        })
    }
    /// Original retained packet buffers; terminal facts require explicit release.
    pub fn buffers(&self) -> impl Iterator<Item = Buffer<'id>> + '_ {
        self.store
            .packets
            .iter()
            .enumerate()
            .filter_map(|(row, p)| {
                p.state.map(|p| {
                    Buffer(self.handle(Reference {
                        row,
                        serial: p.serial,
                    }))
                })
            })
    }
    /// Original retained redirection responses/callback metadata.
    pub fn requests(&self) -> impl Iterator<Item = Request<'id>> + '_ {
        self.store
            .requests
            .iter()
            .enumerate()
            .filter_map(|(row, r)| {
                r.state.map(|r| {
                    Request(self.handle(Reference {
                        row,
                        serial: r.serial,
                    }))
                })
            })
    }
}
