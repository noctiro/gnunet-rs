//! Bounded original-flow and injection authority for the Windows DNS callout.
#![no_std]
#![forbid(unsafe_code)]

mod arena;
pub mod device;
mod endpoints;
pub mod keys;
mod path;
mod requests;

use arena::{Arena, Key};
use core::num::NonZeroU64;
use endpoints::EndpointClosures;
pub use endpoints::FlowObservation;
pub use path::{Addresses, Family, LocalInterface, Path, PathError, ReceivePath};
pub use requests::{Gate, Injection, InjectionObservation, RequestId};

/// An opaque WFP flow context generated for one native association.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowId(Key);

impl FlowId {
    /// Decode a WFP callback observation. It conveys authority only after
    /// lookup against the currently owned association.
    pub const fn from_context(value: NonZeroU64) -> Self {
        Self(Key::from_context(value))
    }

    /// Exact opaque value to set when associating this original WFP flow.
    pub const fn context(self) -> NonZeroU64 {
        self.0.context()
    }
}

/// Flow identities observed on one original WFP datagram classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClassifiedFlow {
    id: FlowId,
    flow_handle: Option<NonZeroU64>,
    endpoint_handle: Option<NonZeroU64>,
}

impl ClassifiedFlow {
    /// Retain the required association context and each reported native handle.
    /// Reject reported zero handles before constructing this observation.
    pub const fn new(
        id: FlowId,
        flow_handle: Option<NonZeroU64>,
        endpoint_handle: Option<NonZeroU64>,
    ) -> Self {
        Self {
            id,
            flow_handle,
            endpoint_handle,
        }
    }

    /// Native transport endpoint reported by this classification, if present.
    #[must_use]
    pub const fn endpoint(self) -> Option<NonZeroU64> {
        self.endpoint_handle
    }

    fn agrees_with(self, flow: &Flow) -> bool {
        self.flow_handle.is_none_or(|handle| handle == flow.handle)
            && self
                .endpoint_handle
                .is_none_or(|endpoint| endpoint == flow.endpoint)
    }
}

/// One original flow context reserved before the native association call.
/// Its context is visible to WFP but cannot authorize capture until confirmation.
#[derive(Debug)]
pub struct PendingFlow {
    id: FlowId,
    flow: Flow,
}

impl PendingFlow {
    /// Exact original value to pass to `FwpsFlowAssociateContext0`.
    pub const fn context(&self) -> NonZeroU64 {
        self.id.context()
    }

    /// The exact original native flow paired with this context.
    pub const fn flow(&self) -> Flow {
        self.flow
    }
}

/// Kernel facts captured from one original WFP association.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Flow {
    /// Original WFP flow handle, used to remove the native association.
    pub handle: NonZeroU64,
    /// Original transport endpoint handle.
    pub endpoint: NonZeroU64,
    /// Native flow family.
    pub family: Family,
    /// Original network compartment.
    pub compartment: u32,
}

/// One original, authenticated device session admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionId(NonZeroU64);

/// One admission or retirement failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// No slot or non-reusable generation remains.
    Capacity,
    /// A service session already owns capture admission.
    Busy,
    /// The original session, flow, or request no longer has this authority.
    Stale,
    /// The original deadline has arrived.
    Expired,
    /// A native operation already owns the request.
    InFlight,
    /// Validated route facts disagree with the original flow.
    Path,
}

struct Association {
    flow: Flow,
    endpoint_closed: bool,
    phase: AssociationPhase,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum AssociationPhase {
    Reserving,
    Associated,
    Removing,
}

impl Association {
    fn open(&self) -> Option<Flow> {
        (self.phase == AssociationPhase::Associated && !self.endpoint_closed).then_some(self.flow)
    }
}

/// One physical slot's state after stopping native flow admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowRemoval {
    /// This physical slot has no original context.
    Empty,
    /// Native association is being established, or a native delete is pending.
    Pending(FlowId),
    /// This caller now owns the attempt to request native removal.
    Request(FlowId, Flow),
}

/// Fixed storage for original flow and request ownership.
///
/// The driver serializes access at the appropriate IRQL. Packet admission and
/// receive authorization are constant work. The instance and its injection
/// handles share one lifetime. Keep it until WFP rundown and every submitted
/// injection complete. The caller must reserve native association custody
/// before publishing its opaque context. Native success confirms the original
/// slot, while a native refusal or deletion retires the same generation.
pub struct State<const FLOWS: usize, const REQUESTS: usize> {
    flows: Arena<Association, FLOWS>,
    requests: Arena<requests::Original, REQUESTS>,
    closures: EndpointClosures,
    session: Option<SessionId>,
    next_session: Option<NonZeroU64>,
    sweep_cursor: usize,
    flow_count: usize,
    closed_flows: usize,
    native_debt: usize,
}

impl<const F: usize, const R: usize> State<F, R> {
    /// Construct the arena with no live session or associations. Capacities
    /// above 65,535 cannot issue contexts for their excess slots.
    pub const fn new() -> Self {
        Self {
            flows: Arena::new(),
            requests: Arena::new(),
            closures: EndpointClosures::new(),
            session: None,
            next_session: NonZeroU64::new(1),
            sweep_cursor: 0,
            flow_count: 0,
            closed_flows: 0,
            native_debt: 0,
        }
    }

    /// Admit one device session after its native access check.
    ///
    /// # Errors
    /// Refuses a concurrent owner or exhausted generation space.
    pub fn open_session(&mut self) -> Result<SessionId, Error> {
        if self.session.is_some() {
            return Err(Error::Busy);
        }
        let next = self.next_session.ok_or(Error::Capacity)?;
        self.next_session = next.checked_add(1);
        let session = SessionId(next);
        self.session = Some(session);
        Ok(session)
    }

    /// Revoke the original device session in constant time. Any accepted
    /// native injection remains charged until its original callback.
    ///
    /// # Errors
    /// Refuses another or already closed session.
    pub fn close_session(&mut self, session: SessionId) -> Result<(), Error> {
        self.check_session(session)?;
        self.session = None;
        Ok(())
    }

    /// Begin observing one original native indication before extracting its
    /// flow metadata. The observation is scoped to this state and indication.
    ///
    /// # Errors
    /// Refuses an exhausted endpoint-closure generation.
    pub fn begin_flow_observation(&self) -> Result<FlowObservation, Error> {
        self.closures.begin()
    }

    /// Reserve a unique context for the exact flow from the observed indication.
    ///
    /// # Errors
    /// Refuses closed endpoints, an overwritten observation window, and arena
    /// capacity or generation exhaustion.
    pub fn reserve_flow(
        &mut self,
        observation: FlowObservation,
        flow: Flow,
    ) -> Result<PendingFlow, Error> {
        self.closures.qualify(observation, flow.endpoint)?;
        if self.closed_flows != 0
            && self
                .flows
                .values()
                .any(|original| original.endpoint_closed && original.flow.endpoint == flow.endpoint)
        {
            return Err(Error::Stale);
        }
        let key = self
            .flows
            .insert(Association {
                flow,
                endpoint_closed: false,
                phase: AssociationPhase::Reserving,
            })
            .ok_or(Error::Capacity)?;
        self.flow_count += 1;
        Ok(PendingFlow {
            id: FlowId(key),
            flow,
        })
    }

    /// Settle a successful original native association. If closure won the
    /// race, WFP still owns deletion but the flow carries no traffic authority.
    ///
    /// # Errors
    /// Refuses a closed endpoint or an original already retired by flow deletion.
    pub fn confirm_flow(&mut self, PendingFlow { id, flow }: PendingFlow) -> Result<FlowId, Error> {
        let entry = self.flows.get_mut(id.0).ok_or(Error::Stale)?;
        if entry.phase != AssociationPhase::Reserving || entry.flow != flow {
            return Err(Error::Stale);
        }
        entry.phase = AssociationPhase::Associated;
        entry.open().map(|_| id).ok_or(Error::Stale)
    }

    /// Retire the original reservation after a definitive native refusal.
    /// The native flow-delete callback may already have retired this generation.
    pub fn refuse_flow(&mut self, PendingFlow { id, flow }: PendingFlow) {
        if self
            .flows
            .get(id.0)
            .is_some_and(|entry| entry.phase == AssociationPhase::Reserving && entry.flow == flow)
        {
            self.retire_flow(id);
        }
    }

    /// Observe an associated flow with an open endpoint and no removal attempt.
    pub fn flow(&self, flow: FlowId) -> Option<Flow> {
        self.flows.get(flow.0).and_then(Association::open)
    }

    /// Observe the live association for an original datagram classification.
    /// Each reported native handle must agree with the generation in its context.
    pub fn classified_flow(&self, observed: ClassifiedFlow) -> Option<Flow> {
        self.flow(observed.id)
            .filter(|flow| observed.agrees_with(flow))
    }

    /// Observe an owned association for native retirement, including a closed
    /// endpoint which still owes its original deletion callback.
    pub fn owned_flow(&self, flow: FlowId) -> Option<Flow> {
        self.flows.get(flow.0).map(|entry| entry.flow)
    }

    /// Revoke every original flow of a native endpoint as it begins closing.
    /// The exact ALE closure callback supplies the identifier. The bounded
    /// scan leaves each WFP association owned until its native flow deletion,
    /// and preserves any submitted request until native completion.
    pub fn close_endpoint(&mut self, endpoint: NonZeroU64) {
        self.closures.record(endpoint);
        if self.flow_count == self.closed_flows {
            return;
        }
        for original in self.flows.values_mut() {
            if original.flow.endpoint == endpoint && !original.endpoint_closed {
                original.endpoint_closed = true;
                self.closed_flows += 1;
            }
        }
    }

    /// Retire only the supplied original native flow association. Its former
    /// requests immediately lose authorization without a table scan.
    pub fn retire_flow(&mut self, flow: FlowId) -> Option<Flow> {
        let retired = self.flows.remove(flow.0)?;
        self.flow_count -= 1;
        self.closed_flows -= usize::from(retired.endpoint_closed);
        Some(retired.flow)
    }

    /// Number of original contexts retained for association or deletion.
    pub const fn flow_count(&self) -> usize {
        self.flow_count
    }

    /// Reserve original context removal at a physical slot and revoke its
    /// traffic authority. Stop and drain association admission before calling.
    /// A pending native request owns this slot until the flow-delete callback.
    pub fn begin_flow_removal(&mut self, slot: usize) -> FlowRemoval {
        let Some((key, entry)) = self.flows.at_mut(slot) else {
            return FlowRemoval::Empty;
        };
        let id = FlowId(key);
        if entry.phase != AssociationPhase::Associated {
            return FlowRemoval::Pending(id);
        }
        entry.phase = AssociationPhase::Removing;
        FlowRemoval::Request(id, entry.flow)
    }

    /// Release a removal attempt after a definitive refusal by the kernel.
    /// A still-associated flow can carry traffic only if its endpoint is open.
    /// Preserve any concurrent delete callback and any replacement generation.
    pub fn refuse_flow_removal(&mut self, flow: FlowId) {
        if let Some(entry) = self.flows.get_mut(flow.0)
            && entry.phase == AssociationPhase::Removing
        {
            entry.phase = AssociationPhase::Associated;
        }
    }

    /// Native reservations with a disposition still due. Closing a session or
    /// expiring a deadline never fabricates one of these dispositions.
    pub const fn native_debt(&self) -> usize {
        self.native_debt
    }

    fn check_session(&self, session: SessionId) -> Result<(), Error> {
        if self.session != Some(session) {
            return Err(Error::Stale);
        }
        Ok(())
    }
}

impl<const F: usize, const R: usize> Default for State<F, R> {
    fn default() -> Self {
        Self::new()
    }
}
