//! Original flow context custody across WFP calls and their delete callbacks.
use super::Runtime;
use crate::{device, flow, registration::Registration, sdk};
use core::{num::NonZeroU64, pin::Pin};
use gnunet_wfp_dns::{Error, Flow, FlowId, FlowRemoval};

/// Refusal from the original association or teardown boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssociationError {
    /// The supplied facts describe no admissible flow.
    InvalidFlow,
    /// The original runtime is unpublished.
    Uninitialized,
    /// No started file may intercept this exact original endpoint.
    Excluded,
    /// The same-family datagram callout is missing.
    Unregistered,
    /// Teardown did not drain the original outbound owner.
    WrongRundown,
    /// Native admission is closed or the caller is outside its IRQL contract.
    Admission(device::Error),
    /// The flow arena refused a new context.
    State(Error),
    /// The kernel refused the original operation.
    Native(sdk::NTSTATUS),
}

/// Outcome of requesting removal of one physical slot after closing admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Removal {
    /// This slot no longer owns native context.
    Empty,
    /// A native deletion was already requested for this generation.
    Pending(FlowId),
    /// The original delete callback retired the slot during a refused request.
    DeletedDuringRemoval {
        /// Exact original context retired by its callback.
        flow: FlowId,
        /// Actual refusal from the concurrent removal call.
        status: sdk::NTSTATUS,
    },
    /// Original removal was accepted. Flow deletion owns slot retirement.
    Requested {
        /// Original context.
        flow: FlowId,
        /// Original status, either success (synchronous) or pending.
        status: sdk::NTSTATUS,
    },
}

impl<const F: usize, const R: usize> Runtime<F, R> {
    /// Reserve context before entering the SDK. Release the exact reservation
    /// on native refusal, leaving any concurrent flow deletion settled.
    ///
    /// # Safety
    /// Call from the original ALE callback with live, matching WDK observations
    /// and current immutable IPv4/IPv6 datagram IDs from this driver. This
    /// pinned state and callback code remain live through native retirement.
    ///
    /// # Errors
    /// Returns the original admission, capacity, or SDK refusal.
    pub unsafe fn associate(
        self: Pin<&Self>,
        ids: [Option<u32>; 2],
        fixed: &sdk::FWPS_INCOMING_VALUES0,
        metadata: &sdk::FWPS_INCOMING_METADATA_VALUES0,
    ) -> Result<FlowId, AssociationError> {
        let observe = || {
            // SAFETY: the original ALE callback retains these native observations.
            unsafe { flow::outbound(fixed, metadata) }
        };
        // SAFETY: this reads only the same original indication after opening
        // its endpoint-closure observation under the original rundown.
        unsafe { self.associate_observed(ids, observe) }
    }

    /// Associate an existing outbound flow observed directly at DATAGRAM_DATA.
    /// Only native association success supplies context for the current packet.
    ///
    /// # Safety
    /// Call only from this driver's exact committed outbound datagram filter,
    /// after excluding self-injection and observing zero native flow context.
    /// Supply live same-callback metadata and original registered datagram IDs.
    /// Retain callback code and pinned state until actual native unregistration.
    ///
    /// # Errors
    /// Refuses missing native metadata, original admission or session authority,
    /// capacity, or any native association error. An existing association is
    /// never removed or adopted to handle an association race.
    pub unsafe fn associate_datagram(
        self: Pin<&Self>,
        ids: [Option<u32>; 2],
        fixed: &sdk::FWPS_INCOMING_VALUES0,
        metadata: &sdk::FWPS_INCOMING_METADATA_VALUES0,
    ) -> Result<FlowId, AssociationError> {
        let observe = || {
            // SAFETY: the original datagram callback retains these observations.
            unsafe { flow::datagram_outbound(fixed, metadata) }
        };
        // SAFETY: the same native callback and callout IDs remain live through
        // both the original observation and the association call.
        unsafe { self.associate_observed(ids, observe) }
    }

    unsafe fn associate_observed(
        self: Pin<&Self>,
        ids: [Option<u32>; 2],
        observe: impl FnOnce() -> Option<Flow>,
    ) -> Result<FlowId, AssociationError> {
        // SAFETY: callback and original allocation satisfy rundown's contracts.
        let _admission =
            unsafe { self.admission().acquire() }.map_err(AssociationError::Admission)?;
        // SAFETY: the original live callback acquires its nonpaged lock.
        let observation = unsafe { self.lock() }
            .ok_or(AssociationError::Uninitialized)?
            .core
            .begin_flow_observation()
            .map_err(AssociationError::State)?;
        let flow = observe().ok_or(AssociationError::InvalidFlow)?;
        let callout = match flow.family {
            gnunet_wfp_dns::Family::V4 => ids[0],
            gnunet_wfp_dns::Family::V6 => ids[1],
        }
        .ok_or(AssociationError::Unregistered)?;
        let context = {
            // SAFETY: caller has a live callback. Drop the lock before WFP.
            let mut state = unsafe { self.lock() }.ok_or(AssociationError::Uninitialized)?;
            if !state.channel.intercepts(flow.endpoint) {
                return Err(AssociationError::Excluded);
            }
            state
                .core
                .reserve_flow(observation, flow)
                .map_err(AssociationError::State)?
        };
        // SAFETY: the slot owns the context and the live loan excludes teardown.
        let status = unsafe { flow::associate(&context, callout) };
        if status == sdk::GNUNET_WFP_STATUS_SUCCESS {
            // SAFETY: the same live callback and loan still own this state.
            let mut state = unsafe { self.lock() }.ok_or(AssociationError::Uninitialized)?;
            return state
                .core
                .confirm_flow(context)
                .map_err(AssociationError::State);
        }
        // SAFETY: as above. This only removes the same reserved generation.
        if let Some(mut state) = unsafe { self.lock() } {
            state.core.refuse_flow(context);
        }
        Err(AssociationError::Native(status))
    }

    /// Retire only the original generation received in WFP's delete callback.
    ///
    /// # Safety
    /// Use the original registered callback, whose pinned state remains live
    /// independently of outbound rundown. Supply the matching published native
    /// datagram callout ID for this callback and its unaltered callback facts.
    pub unsafe fn flow_deleted(
        self: Pin<&Self>,
        registered_callout: u32,
        layer: u16,
        callout: u32,
        context: u64,
    ) -> bool {
        if callout != registered_callout {
            return false;
        }
        let Some(context) = NonZeroU64::new(context).map(FlowId::from_context) else {
            return false;
        };
        // SAFETY: original deletion callback retains the native allocation.
        let Some(mut state) = (unsafe { self.lock() }) else {
            return false;
        };
        if !state
            .core
            .owned_flow(context)
            .is_some_and(|current| flow::datagram_layer(current.family) == layer)
        {
            return false;
        }
        state.core.retire_flow(context).is_some()
    }

    /// Revoke the endpoint's original flow traffic while native deletion and
    /// completion retain their own owners. The UDP endpoint handle is unique
    /// even for unconnected sockets with more than one remote flow.
    ///
    /// # Safety
    /// Call from the original `ALE_ENDPOINT_CLOSURE` indication after
    /// authenticating the installed filter and native endpoint metadata.
    pub(crate) unsafe fn endpoint_closing(self: Pin<&Self>, endpoint: NonZeroU64) {
        // SAFETY: the original registered callback retains this pinned runtime.
        if let Some(mut state) = unsafe { self.lock() } {
            state.core.close_endpoint(endpoint);
        }
    }

    /// Request deletion of one original slot after outbound rundown. A pending
    /// removal remains owned by WFP until its original delete callback.
    ///
    /// # Safety
    /// Use the drained owner's original still-live registration. Keep native
    /// callbacks registered through this procedure and final callback drain.
    /// No native association may be made after admission has drained.
    ///
    /// # Errors
    /// Returns incorrect ownership, unavailable registration, or SDK refusal.
    pub unsafe fn remove_at(
        self: Pin<&Self>,
        drained: &device::Drained<'_>,
        registration: &Registration,
        slot: usize,
    ) -> Result<Removal, AssociationError> {
        if !drained.belongs_to(self.admission()) {
            return Err(AssociationError::WrongRundown);
        }
        // SAFETY: live original pinned state; release before calling WFP.
        let removal = unsafe { self.lock() }
            .ok_or(AssociationError::Uninitialized)?
            .core
            .begin_flow_removal(slot);
        let (context, flow) = match removal {
            FlowRemoval::Empty => return Ok(Removal::Empty),
            FlowRemoval::Pending(context) => return Ok(Removal::Pending(context)),
            FlowRemoval::Request(context, flow) => (context, flow),
        };
        let result = match registration.datagram(flow.family) {
            Some(callout) => {
                // SAFETY: the original slot, registration and shutdown owner
                // exclude replacement, and the state lock has been released.
                match unsafe { flow::remove(flow, callout) } {
                    status @ (sdk::GNUNET_WFP_STATUS_SUCCESS | sdk::GNUNET_WFP_STATUS_PENDING) => {
                        return Ok(Removal::Requested {
                            flow: context,
                            status,
                        });
                    }
                    status => AssociationError::Native(status),
                }
            }
            None => AssociationError::Unregistered,
        };
        // SAFETY: the same live state can release this definitive refusal. A
        // concurrent native deletion may already have retired that exact key.
        let mut state = unsafe { self.lock() }.ok_or(AssociationError::Uninitialized)?;
        if let AssociationError::Native(status) = result
            && state.core.owned_flow(context).is_none()
        {
            return Ok(Removal::DeletedDuringRemoval {
                flow: context,
                status,
            });
        }
        state.core.refuse_flow_removal(context);
        Err(result)
    }
}
