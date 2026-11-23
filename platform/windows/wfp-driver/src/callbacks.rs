//! Original WFP callback routing through one published nonpaged owner.
//!
//! Filter IDs are installed only from the driver's original successful FWPM
//! additions. Notifications never create authority. Keep this publication and
//! every native dependency alive until actual FWPS unregistration has stopped
//! and synchronized every callback entry; clearing a pointer is not that proof.
use crate::{flow, registration, runtime::Runtime, sdk};
use core::{
    ffi::c_void,
    fmt,
    marker::PhantomPinned,
    num::{NonZeroU32, NonZeroU64},
    pin::Pin,
    ptr::{self, NonNull},
    sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, Ordering},
};
use gnunet_wfp_dns::Family;

/// Original flow contexts retained by one driver allocation.
pub const FLOWS: usize = 256;
/// Original captures and native replies retained by one driver allocation.
pub const REQUESTS: usize = 32;

static PUBLISHED: AtomicPtr<State> = AtomicPtr::new(ptr::null_mut());

/// Invalid original publication or configuration transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Another publication is still available to the native callbacks.
    AlreadyPublished,
    /// This original state was already published and cannot be reused.
    AlreadyUsed,
    /// The supplied original is not the current native publication.
    NotPublished,
    /// Original datagram registrations must precede committed filter IDs.
    NotRegistered,
    /// This original registration or filter group has already been configured.
    AlreadyConfigured,
    /// Different native objects were supplied the same identifier.
    DuplicateId,
}

impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::AlreadyPublished => "another original WFP state is published",
            Self::AlreadyUsed => "original WFP callback state cannot be republished",
            Self::NotPublished => "this original WFP state is not published",
            Self::NotRegistered => "original datagram callouts are not registered",
            Self::AlreadyConfigured => "original WFP identifiers were already configured",
            Self::DuplicateId => "different original WFP objects have the same identifier",
        })
    }
}
impl core::error::Error for Error {}

/// Pinned original callback recipient and once-configured native identities.
///
/// There is no Drop retirement. The runtime, original injection handles, native
/// registrations, filters and this allocation have independent native debts.
/// Filter ID observations cannot extend any of those lifetimes.
#[must_use]
pub struct State {
    runtime: Pin<&'static Runtime<FLOWS, REQUESTS>>,
    handles: [NonNull<c_void>; 2],
    lifetime_ticks: NonZeroU64,
    datagrams: [AtomicU32; 2],
    guards: [AtomicU64; 2],
    capture: [AtomicU64; 6],
    published_once: AtomicBool,
    registered_once: AtomicBool,
    filters_once: AtomicBool,
    capture_revoked: AtomicBool,
    _pin: PhantomPinned,
}

// SAFETY: the runtime serializes its state using its original initialized
// nonpaged lock; route identifiers use atomic operations. The unsafe creation
// and publication contracts retain all original handles and callback storage.
// No method frees a dependency or turns pointer publication into lifetime proof.
unsafe impl Sync for State {}

impl State {
    /// Prepare a callback recipient without publishing it or entering the SDK.
    /// Deadline units are native monotonic 100 ns ticks.
    ///
    /// # Safety
    /// Supply the initialized original pinned nonpaged runtime and both live
    /// transport injection handles in IPv4/IPv6 order. Keep them valid through
    /// the eventual native callback cutoff, including after outbound admission
    /// stops. The runtime must refuse capture until the authenticated file owns
    /// its committed original upstream exclusions; an endpoint number alone
    /// grants no socket lifetime or bypass authority.
    pub const unsafe fn new(
        runtime: Pin<&'static Runtime<FLOWS, REQUESTS>>,
        handles: [NonNull<c_void>; 2],
        lifetime_ticks: NonZeroU64,
    ) -> Self {
        Self {
            runtime,
            handles,
            lifetime_ticks,
            datagrams: [const { AtomicU32::new(0) }; 2],
            guards: [const { AtomicU64::new(0) }; 2],
            capture: [const { AtomicU64::new(0) }; 6],
            published_once: AtomicBool::new(false),
            registered_once: AtomicBool::new(false),
            filters_once: AtomicBool::new(false),
            capture_revoked: AtomicBool::new(false),
            _pin: PhantomPinned,
        }
    }

    /// Publish this exact original before native callback registration begins.
    ///
    /// # Safety
    /// Preparation exclusively owns this final pinned nonpaged allocation.
    /// Keep it and all dependencies live through actual native unregistration,
    /// even on partial setup failure. Do not replace it during that lifetime.
    /// Every typed native callback may read it immediately after this call.
    ///
    /// # Errors
    /// Refuses an existing global publication or reuse of this same original.
    pub unsafe fn publish(self: Pin<&'static Self>) -> Result<(), Error> {
        if self.published_once.swap(true, Ordering::AcqRel) {
            return Err(Error::AlreadyUsed);
        }
        let original = ptr::from_ref(self.get_ref()).cast_mut();
        if PUBLISHED
            .compare_exchange(
                ptr::null_mut(),
                original,
                Ordering::Release,
                Ordering::Acquire,
            )
            .is_err()
        {
            self.published_once.store(false, Ordering::Release);
            return Err(Error::AlreadyPublished);
        }
        Ok(())
    }

    /// Install the original successful datagram registration IDs, IPv4 then IPv6.
    ///
    /// # Safety
    /// Supply only the actual IDs returned to this driver's original FWPS
    /// registrations. Serialize configuration; keep both registrations live
    /// through all flow deletion and receive callbacks. No filter admission may
    /// start until these IDs and the original committed guards are installed.
    ///
    /// # Errors
    /// Refuses duplicate IDs or another configuration of this original group.
    pub unsafe fn set_datagram_ids(self: Pin<&Self>, ids: [NonZeroU32; 2]) -> Result<(), Error> {
        if ids[0] == ids[1] {
            return Err(Error::DuplicateId);
        }
        once(&self.registered_once)?;
        for (target, id) in self.datagrams.iter().zip(ids) {
            target.store(id.get(), Ordering::Release);
        }
        Ok(())
    }

    /// Stage the IDs from the original native transaction before its commit.
    /// The guard order is IPv4 then IPv6. The outbound order is discovery
    /// IPv4/IPv6, capture IPv4/IPv6, then endpoint closure IPv4/IPv6.
    ///
    /// # Safety
    /// Every ID must come from this driver's live transaction for the correct
    /// layer and action. Outbound runtime authority must stay closed until
    /// successful commit and an intact-policy check. Retain original guard
    /// IDs and handles through the native receive cutoff, even on rollback.
    ///
    /// # Errors
    /// Refuses missing registrations, duplicate IDs or reuse of this group.
    pub unsafe fn stage_policy(
        self: Pin<&Self>,
        guards: [NonZeroU64; 2],
        capture: [NonZeroU64; 6],
    ) -> Result<(), Error> {
        self.require_registered()?;
        let [a, b] = guards;
        let [c, d, e, f, g, h] = capture;
        let ids = [a, b, c, d, e, f, g, h];
        for (index, id) in ids.iter().enumerate() {
            if ids[..index].contains(id) {
                return Err(Error::DuplicateId);
            }
        }
        once(&self.filters_once)?;
        for (target, id) in self.guards.iter().chain(&self.capture).zip(ids) {
            target.store(id.get(), Ordering::Release);
        }
        Ok(())
    }

    /// Permanently stop discovery and capture for this original policy.
    /// Retain exact IDs for native deletion and in-flight receive callbacks.
    pub fn stop_capture(self: Pin<&Self>) {
        self.capture_revoked.store(true, Ordering::Release);
    }

    /// Whether the staged policy has complete IDs and no observed revocation.
    /// The controller must independently have observed a successful commit.
    #[must_use]
    pub fn policy_intact(&self) -> bool {
        !self.capture_revoked.load(Ordering::Acquire)
            && self
                .guards
                .iter()
                .chain(&self.capture)
                .all(|id| id.load(Ordering::Acquire) != 0)
    }

    /// Clear only this exact publication after all native entries have ended.
    ///
    /// # Safety
    /// All original FWPS callouts must have successfully unregistered, including
    /// any partial-registration rollback. Every native classify, notify and
    /// flow-delete entry must actually have retired. Keep the runtime, handles
    /// and this allocation live until then. This operation cannot create that
    /// cutoff and must never be used as a substitute for native synchronization.
    ///
    /// # Errors
    /// Refuses a missing or different original publication.
    pub unsafe fn clear_after_unregister(self: Pin<&Self>) -> Result<(), Error> {
        let original = ptr::from_ref(self.get_ref()).cast_mut();
        PUBLISHED
            .compare_exchange(
                original,
                ptr::null_mut(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|_| Error::NotPublished)
    }

    fn require_registered(&self) -> Result<(), Error> {
        if self
            .datagrams
            .iter()
            .all(|id| id.load(Ordering::Acquire) != 0)
        {
            Ok(())
        } else {
            Err(Error::NotRegistered)
        }
    }
}

/// Real WDK-typed entry points, using IPv4 then IPv6 in each family array.
/// Their original publication must precede registration and outlive retirement.
#[must_use]
pub const fn functions() -> registration::Callbacks {
    registration::Callbacks {
        flow: [Some(flow_v4), Some(flow_v6)],
        datagram: [Some(datagram_v4), Some(datagram_v6)],
        closure: [Some(closure_v4), Some(closure_v6)],
        notify: [Some(notify); 6],
        flow_delete: [Some(delete_v4), Some(delete_v6)],
    }
}

fn once(configured: &AtomicBool) -> Result<(), Error> {
    if configured.swap(true, Ordering::AcqRel) {
        Err(Error::AlreadyConfigured)
    } else {
        Ok(())
    }
}

unsafe fn original() -> Option<Pin<&'static State>> {
    let state = NonNull::new(PUBLISHED.load(Ordering::Acquire))?;
    // SAFETY: the original publisher keeps this exact pinned nonpaged allocation
    // alive until native registration has stopped and synchronized these entries.
    Some(unsafe { Pin::new_unchecked(state.as_ref()) })
}

fn continue_policy(output: &mut sdk::FWPS_CLASSIFY_OUT0) {
    if output.rights & sdk::FWPS_RIGHT_ACTION_WRITE != 0 {
        output.actionType = sdk::FWP_ACTION_CONTINUE;
    }
}

const fn index(family: Family) -> usize {
    match family {
        Family::V4 => 0,
        Family::V6 => 1,
    }
}

const fn flow_layer(family: Family) -> i32 {
    match family {
        Family::V4 => sdk::FWPS_BUILTIN_LAYERS__FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4,
        Family::V6 => sdk::FWPS_BUILTIN_LAYERS__FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6,
    }
}

const fn datagram_layer(family: Family) -> i32 {
    match family {
        Family::V4 => sdk::FWPS_BUILTIN_LAYERS__FWPS_LAYER_DATAGRAM_DATA_V4,
        Family::V6 => sdk::FWPS_BUILTIN_LAYERS__FWPS_LAYER_DATAGRAM_DATA_V6,
    }
}

const fn closure_layer(family: Family) -> i32 {
    match family {
        Family::V4 => sdk::FWPS_BUILTIN_LAYERS__FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4,
        Family::V6 => sdk::FWPS_BUILTIN_LAYERS__FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V6,
    }
}

unsafe fn endpoint_closure(
    family: Family,
    fixed: *const sdk::FWPS_INCOMING_VALUES0,
    metadata: *const sdk::FWPS_INCOMING_METADATA_VALUES0,
    filter: *const sdk::FWPS_FILTER0,
    output: *mut sdk::FWPS_CLASSIFY_OUT0,
) {
    // SAFETY: the original callback retains its writable classify output.
    if let Some(output) = unsafe { output.as_mut() } {
        continue_policy(output);
    }
    // SAFETY: the callback pins the original state and SDK pointer arguments.
    let (Some(state), Some(fixed), Some(filter)) =
        (unsafe { (original(), fixed.as_ref(), filter.as_ref()) })
    else {
        return;
    };
    if i32::from(fixed.layerId) != closure_layer(family)
        || filter.filterId == 0
        || filter.filterId != state.capture[index(family) + 4].load(Ordering::Acquire)
        || filter.action.type_ != sdk::FWP_ACTION_CALLOUT_INSPECTION
    {
        return;
    }
    // SAFETY: ALE supplies metadata for this exact original close indication.
    let Some(endpoint) = (unsafe { metadata.as_ref() }).and_then(flow::endpoint) else {
        // WFP documents an exact endpoint handle at this layer. A malformed
        // original indication cannot safely identify the closing endpoint.
        state.stop_capture();
        // SAFETY: the authenticated callback retains its original runtime.
        unsafe { state.runtime.revoke_policy(None) };
        return;
    };
    // SAFETY: the original installed closure filter and actual metadata have
    // been matched. The runtime revokes traffic while preserving native debt.
    unsafe { state.runtime.endpoint_closing(endpoint) };
}

unsafe fn discover(
    family: Family,
    fixed: *const sdk::FWPS_INCOMING_VALUES0,
    metadata: *const sdk::FWPS_INCOMING_METADATA_VALUES0,
    filter: *const sdk::FWPS_FILTER0,
    output: *mut sdk::FWPS_CLASSIFY_OUT0,
) {
    // SAFETY: these are WFP's original synchronous callback parameters.
    let Some(output) = (unsafe { output.as_mut() }) else {
        return;
    };
    continue_policy(output);
    // SAFETY: typed original native callback supplies every non-null argument.
    let (Some(state), Some(fixed), Some(metadata), Some(filter)) = (unsafe {
        (
            original(),
            fixed.as_ref(),
            metadata.as_ref(),
            filter.as_ref(),
        )
    }) else {
        return;
    };
    let slot = index(family);
    if state.capture_revoked.load(Ordering::Acquire)
        || i32::from(fixed.layerId) != flow_layer(family)
        || filter.filterId == 0
        || filter.filterId != state.capture[slot].load(Ordering::Acquire)
        || filter.action.type_ != sdk::FWP_ACTION_CALLOUT_INSPECTION
    {
        return;
    }
    let ids = state
        .datagrams
        .each_ref()
        .map(|id| NonZeroU32::new(id.load(Ordering::Acquire)).map(NonZeroU32::get));
    // SAFETY: publisher retains this original runtime and native IDs. Runtime
    // takes its own outbound loan, checks the original endpoint against active
    // file policy under the reservation lock, and settles any native refusal.
    let _ = unsafe { state.runtime.associate(ids, fixed, metadata) };
}

unsafe fn datagram(
    family: Family,
    fixed: *const sdk::FWPS_INCOMING_VALUES0,
    metadata: *const sdk::FWPS_INCOMING_METADATA_VALUES0,
    packet: *mut c_void,
    filter: *const sdk::FWPS_FILTER0,
    context: u64,
    output: *mut sdk::FWPS_CLASSIFY_OUT0,
) {
    // SAFETY: WFP owns the original output until this callback returns.
    let Some(output) = (unsafe { output.as_mut() }) else {
        return;
    };
    continue_policy(output);
    // SAFETY: original native callback supplies every non-null argument.
    let (Some(state), Some(fixed), Some(filter)) =
        (unsafe { (original(), fixed.as_ref(), filter.as_ref()) })
    else {
        return;
    };
    let slot = index(family);
    if i32::from(fixed.layerId) != datagram_layer(family) || filter.filterId == 0 {
        return;
    }
    // SAFETY: nullable metadata is the original metadata of this indication.
    let metadata = unsafe { metadata.as_ref() };
    let packet = packet.cast::<sdk::NET_BUFFER_LIST>();
    if filter.filterId == state.guards[slot].load(Ordering::Acquire) {
        // Do not require a flow context, metadata, UDP path or endpoint here.
        // Native injection provenance must be checked even for a replacement
        // socket or malformed/stale context, so those cannot bypass the guard.
        // SAFETY: original guard ID and layer select the original live runtime;
        // native handles and every callback argument remain live until return.
        let _ = unsafe {
            state
                .runtime
                .receive(&state.handles, packet, fixed, metadata, context, output)
        };
        return;
    }
    if state.capture_revoked.load(Ordering::Acquire)
        || filter.filterId != state.capture[slot + 2].load(Ordering::Acquire)
        || filter.action.type_ != sdk::FWP_ACTION_CALLOUT_UNKNOWN
        || filter.action.calloutId != state.datagrams[slot].load(Ordering::Acquire)
        || packet.is_null()
    {
        return;
    }
    let Some(metadata) = metadata else { return };
    if flow::endpoint(metadata).is_none()
        // SAFETY: this original live NBL and both original handles remain valid.
        || unsafe { self_injected(&state.handles, packet) }
    {
        return;
    }
    let context = if context == 0 {
        let ids = state
            .datagrams
            .each_ref()
            .map(|id| NonZeroU32::new(id.load(Ordering::Acquire)).map(NonZeroU32::get));
        // Existing UDP flows need not replay ALE_FLOW_ESTABLISHED after policy
        // recovery. Use only native metadata and a successful real association;
        // OBJECT_NAME_EXISTS and every other failure leave policy unchanged.
        // SAFETY: the exact original outbound filter, non-self native packet
        // and zero context were checked above; this callback retains all inputs.
        match unsafe { state.runtime.associate_datagram(ids, fixed, metadata) } {
            Ok(flow) => flow.context().get(),
            Err(_) => return,
        }
    } else {
        context
    };
    let mut counter = 0;
    // SAFETY: the native monotonic read is allowed at this callback's IRQL.
    let now = unsafe { sdk::KeQueryInterruptTimePrecise(&raw mut counter) };
    let Some(expires) = now.checked_add(state.lifetime_ticks.get()) else {
        return;
    };
    // SAFETY: this exact original committed capture filter owns the callback;
    // native injection history was checked. Runtime checks its original flow's
    // endpoint against active file policy before reserving and publishing, and
    // commits bytes and original authority before block/absorb.
    let _ = unsafe {
        state
            .runtime
            .capture(packet, fixed, Some(metadata), context, output, expires)
    };
}

unsafe fn self_injected(
    handles: &[NonNull<c_void>; 2],
    packet: *const sdk::NET_BUFFER_LIST,
) -> bool {
    handles.iter().any(|handle| {
        // SAFETY: caller keeps the original handles and NBL live; no context is
        // needed to exclude self-injected history from outbound recapture.
        !matches!(
            unsafe {
                sdk::FwpsQueryPacketInjectionState0(handle.as_ptr(), packet, ptr::null_mut())
            },
            sdk::FWPS_PACKET_INJECTION_STATE__FWPS_PACKET_NOT_INJECTED
                | sdk::FWPS_PACKET_INJECTION_STATE__FWPS_PACKET_INJECTED_BY_OTHER
        )
    })
}

unsafe fn deleted(family: Family, layer: u16, callout: u32, context: u64) {
    // SAFETY: original registered WFP deletion entry keeps publication alive.
    let Some(state) = (unsafe { original() }) else {
        return;
    };
    let registered = state.datagrams[index(family)].load(Ordering::Acquire);
    if registered == 0 || i32::from(layer) != datagram_layer(family) || registered != callout {
        return;
    }
    // SAFETY: original delete context and matching native registration; this
    // path deliberately remains available after outbound admission stops.
    let _ = unsafe {
        state
            .runtime
            .flow_deleted(registered, layer, callout, context)
    };
}

unsafe extern "C" fn notify(
    kind: sdk::FWPS_CALLOUT_NOTIFY_TYPE,
    _key: *const sdk::GUID,
    filter: *mut sdk::FWPS_FILTER0,
) -> sdk::NTSTATUS {
    // SAFETY: original notify callback owns every non-null native filter record.
    if kind == sdk::FWPS_CALLOUT_NOTIFY_TYPE__FWPS_CALLOUT_NOTIFY_DELETE_FILTER
        && let (Some(state), Some(filter)) = unsafe { (original(), filter.as_ref()) }
        && filter.filterId != 0
    {
        // Preserve the identity of an already-entered guard callback, and
        // make any loss sticky across concurrent startup and local START.
        if state
            .guards
            .iter()
            .chain(&state.capture)
            .any(|id| id.load(Ordering::Acquire) == filter.filterId)
        {
            state.stop_capture();
            // SAFETY: native notify retains this original nonpaged runtime;
            // revocation performs only bounded local state work, without FWPM.
            unsafe { state.runtime.revoke_policy(None) };
        }
    }
    // ADD cannot authenticate ownership: it may precede FwpmFilterAdd's output,
    // and WFP does not replay existing filters when a callout registers. Only
    // the actual original owner's commit_* calls install classification IDs.
    sdk::GNUNET_WFP_STATUS_SUCCESS
}

unsafe extern "C" fn flow_v4(
    fixed: *const sdk::FWPS_INCOMING_VALUES0,
    metadata: *const sdk::FWPS_INCOMING_METADATA_VALUES0,
    _packet: *mut c_void,
    filter: *const sdk::FWPS_FILTER0,
    _context: u64,
    output: *mut sdk::FWPS_CLASSIFY_OUT0,
) {
    // SAFETY: WFP invoked this original typed IPv4 ALE callback.
    unsafe { discover(Family::V4, fixed, metadata, filter, output) };
}

unsafe extern "C" fn flow_v6(
    fixed: *const sdk::FWPS_INCOMING_VALUES0,
    metadata: *const sdk::FWPS_INCOMING_METADATA_VALUES0,
    _packet: *mut c_void,
    filter: *const sdk::FWPS_FILTER0,
    _context: u64,
    output: *mut sdk::FWPS_CLASSIFY_OUT0,
) {
    // SAFETY: WFP invoked this original typed IPv6 ALE callback.
    unsafe { discover(Family::V6, fixed, metadata, filter, output) };
}

unsafe extern "C" fn datagram_v4(
    fixed: *const sdk::FWPS_INCOMING_VALUES0,
    metadata: *const sdk::FWPS_INCOMING_METADATA_VALUES0,
    packet: *mut c_void,
    filter: *const sdk::FWPS_FILTER0,
    context: u64,
    output: *mut sdk::FWPS_CLASSIFY_OUT0,
) {
    // SAFETY: WFP invoked this original typed IPv4 datagram callback.
    unsafe { datagram(Family::V4, fixed, metadata, packet, filter, context, output) };
}

unsafe extern "C" fn datagram_v6(
    fixed: *const sdk::FWPS_INCOMING_VALUES0,
    metadata: *const sdk::FWPS_INCOMING_METADATA_VALUES0,
    packet: *mut c_void,
    filter: *const sdk::FWPS_FILTER0,
    context: u64,
    output: *mut sdk::FWPS_CLASSIFY_OUT0,
) {
    // SAFETY: WFP invoked this original typed IPv6 datagram callback.
    unsafe { datagram(Family::V6, fixed, metadata, packet, filter, context, output) };
}

unsafe extern "C" fn closure_v4(
    fixed: *const sdk::FWPS_INCOMING_VALUES0,
    metadata: *const sdk::FWPS_INCOMING_METADATA_VALUES0,
    _packet: *mut c_void,
    filter: *const sdk::FWPS_FILTER0,
    _context: u64,
    output: *mut sdk::FWPS_CLASSIFY_OUT0,
) {
    // SAFETY: WFP invoked this original typed IPv4 endpoint-closure callback.
    unsafe { endpoint_closure(Family::V4, fixed, metadata, filter, output) };
}

unsafe extern "C" fn closure_v6(
    fixed: *const sdk::FWPS_INCOMING_VALUES0,
    metadata: *const sdk::FWPS_INCOMING_METADATA_VALUES0,
    _packet: *mut c_void,
    filter: *const sdk::FWPS_FILTER0,
    _context: u64,
    output: *mut sdk::FWPS_CLASSIFY_OUT0,
) {
    // SAFETY: WFP invoked this original typed IPv6 endpoint-closure callback.
    unsafe { endpoint_closure(Family::V6, fixed, metadata, filter, output) };
}

unsafe extern "C" fn delete_v4(layer: u16, callout: u32, context: u64) {
    // SAFETY: WFP supplies this original native deletion for IPv4.
    unsafe { deleted(Family::V4, layer, callout, context) };
}

unsafe extern "C" fn delete_v6(layer: u16, callout: u32, context: u64) {
    // SAFETY: WFP supplies this original native deletion for IPv6.
    unsafe { deleted(Family::V6, layer, callout, context) };
}
