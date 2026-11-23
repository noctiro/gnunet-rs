//! Exclusive owners for the FWPS runtime registration IDs.
use crate::{ids, sdk};
use core::ptr::NonNull;
use gnunet_wfp_dns::Family;

/// Callbacks for the outbound flow and bidirectional datagram callouts.
/// Arrays use IPv4 then IPv6. Flow-delete callbacks belong to the datagram
/// callouts because that is where the driver associates its flow contexts.
pub struct Callbacks {
    /// Classify one outbound ALE flow-established indication per family.
    pub flow: [sdk::FWPS_CALLOUT_CLASSIFY_FN0; 2],
    /// Route original UDP datagrams or enforce the receive guard per family.
    pub datagram: [sdk::FWPS_CALLOUT_CLASSIFY_FN0; 2],
    /// Revoke each original UDP endpoint when ALE begins closing it.
    pub closure: [sdk::FWPS_CALLOUT_CLASSIFY_FN0; 2],
    /// Original filter lifetime notifications, in `Registration::ids` order.
    pub notify: [sdk::FWPS_CALLOUT_NOTIFY_FN0; 6],
    /// Original datagram flow-context deletion callback per family.
    pub flow_delete: [sdk::FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0; 2],
}

/// Exact native failure while registering, removing, or owning a WFP object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeFailure {
    /// Name of the SDK operation that produced the status.
    pub operation: &'static str,
    /// Original SDK NTSTATUS.
    pub status: sdk::NTSTATUS,
}

/// Failure while starting the original set of callouts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegisterError {
    /// An original partial or full registration still exists.
    AlreadyOwned,
    /// At least one required original callback was absent.
    MissingCallback,
    /// Registration failed at this SDK boundary. Earlier successes remain
    /// owned by the same registration and need explicit retirement.
    Native(NativeFailure),
}

/// One original registration set. Explicit retirement preserves failed IDs.
/// Keeping an ID here also requires keeping its callback code and original
/// device lifetime valid until native unregistration succeeds.
#[must_use]
pub struct Registration {
    ids: [Option<u32>; 6],
}

const CALLOUTS: [sdk::GUID; 6] = [
    ids::FLOW_V4,
    ids::FLOW_V6,
    ids::DATAGRAM_V4,
    ids::DATAGRAM_V6,
    ids::CLOSURE_V4,
    ids::CLOSURE_V6,
];

impl Registration {
    /// Construct an empty owner without native effects.
    pub const fn new() -> Self {
        Self { ids: [None; 6] }
    }

    /// Current original runtime IDs in flow-v4, flow-v6, datagram-v4,
    /// datagram-v6, closure-v4 and closure-v6 order. Some entries may still be
    /// pending retirement.
    pub const fn ids(&self) -> [Option<u32>; 6] {
        self.ids
    }

    /// Exact original target ID for a datagram flow association or removal.
    pub const fn datagram(&self, family: Family) -> Option<u32> {
        match family {
            Family::V4 => self.ids[2],
            Family::V6 => self.ids[3],
        }
    }

    /// Whether no original FWPS registration remains in this owner.
    pub fn retired(&self) -> bool {
        self.ids.iter().all(Option::is_none)
    }

    /// Register datagram callouts before flow discovery. Guards and capture
    /// policy use the fixed IDs and must be managed by their own owners.
    ///
    /// # Safety
    /// Call at `PASSIVE_LEVEL` with exclusive service ownership. The original
    /// I/O manager device object must remain live until all registrations have
    /// retired. All callbacks and any state they may borrow must already be
    /// prepared for immediate invocation. Keep this owner, the code and the
    /// original device alive even after a partial failure.
    ///
    /// # Errors
    /// Refuses absent callbacks or reuse with live original IDs. Returns the
    /// first native error without discarding prior successful registrations.
    pub unsafe fn register(
        &mut self,
        device: NonNull<sdk::DEVICE_OBJECT>,
        callbacks: &Callbacks,
    ) -> Result<(), RegisterError> {
        if !self.retired() {
            return Err(RegisterError::AlreadyOwned);
        }
        if callbacks.flow.iter().any(Option::is_none)
            || callbacks.datagram.iter().any(Option::is_none)
            || callbacks.closure.iter().any(Option::is_none)
            || callbacks.flow_delete.iter().any(Option::is_none)
            || callbacks.notify.iter().any(Option::is_none)
        {
            return Err(RegisterError::MissingCallback);
        }
        let classify = [
            callbacks.flow[0],
            callbacks.flow[1],
            callbacks.datagram[0],
            callbacks.datagram[1],
            callbacks.closure[0],
            callbacks.closure[1],
        ];
        let flow_delete = [
            None,
            None,
            callbacks.flow_delete[0],
            callbacks.flow_delete[1],
            None,
            None,
        ];
        for slot in [2, 3, 4, 5, 0, 1] {
            let callout = sdk::FWPS_CALLOUT0 {
                calloutKey: CALLOUTS[slot],
                flags: 0,
                classifyFn: classify[slot],
                notifyFn: callbacks.notify[slot],
                flowDeleteFn: flow_delete[slot],
            };
            let mut id = 0;
            // SAFETY: the caller pins the original device, callback code and
            // prepared state. The SDK reads this initialized registration and
            // writes one valid output on success.
            let status =
                unsafe { sdk::FwpsCalloutRegister0(device.as_ptr().cast(), &callout, &mut id) };
            if status != sdk::GNUNET_WFP_STATUS_SUCCESS {
                return Err(RegisterError::Native(NativeFailure {
                    operation: "FwpsCalloutRegister0",
                    status,
                }));
            }
            self.ids[slot] = Some(id);
        }
        Ok(())
    }

    /// Remove the original flow discovery and endpoint closure callbacks in
    /// reverse registration order.
    /// Preserve each independent failure and its runtime ID for the caller.
    ///
    /// # Safety
    /// Call at `PASSIVE_LEVEL` after stopping flow admission. Keep the device,
    /// callback code and referenced state live through the native operations.
    pub unsafe fn unregister_discovery(&mut self) -> [Result<Option<u32>, NativeFailure>; 4] {
        // SAFETY: the caller revoked original data policy and keeps the
        // callback code and exact runtime owners live until this cutoff.
        unsafe {
            [
                self.remove(1),
                self.remove(0),
                self.remove(5),
                self.remove(4),
            ]
        }
    }

    /// Remove both original datagram callbacks in reverse registration order.
    /// The original inbound UNKNOWN filters default to SDK BLOCK after their
    /// callouts unregister. Keep them installed while injection handles retire.
    ///
    /// # Safety
    /// Call at PASSIVE_LEVEL after removing outbound filters and discovery
    /// registrations, draining submitters, and observing original flow
    /// deletions. Keep callback storage and handles live through successful
    /// unregistration. Preserve original IDs on failure.
    pub unsafe fn unregister_datagrams(&mut self) -> [Result<Option<u32>, NativeFailure>; 2] {
        // SAFETY: the caller proves retirement of dependencies and retains state.
        unsafe { [self.remove(3), self.remove(2)] }
    }

    unsafe fn remove(&mut self, slot: usize) -> Result<Option<u32>, NativeFailure> {
        let Some(id) = self.ids[slot] else {
            return Ok(None);
        };
        // SAFETY: the caller retains the original native lifetime, meets the
        // passive-level requirement and supplies an ID returned to this owner.
        let status = unsafe { sdk::FwpsCalloutUnregisterById0(id) };
        if status != sdk::GNUNET_WFP_STATUS_SUCCESS {
            return Err(NativeFailure {
                operation: "FwpsCalloutUnregisterById0",
                status,
            });
        }
        self.ids[slot] = None;
        Ok(Some(id))
    }
}

impl Default for Registration {
    fn default() -> Self {
        Self::new()
    }
}
