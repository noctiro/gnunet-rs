use super::resources::Resources;
use crate::sdk;
use core::{ffi::c_void, fmt, ptr::NonNull};
use gnunet_wfp_dns::Injection;

/// Actual completion of the original accepted WFP receive injection.
/// Its status and receive authorization do not prove socket consumption.
#[derive(Debug)]
#[must_use = "settle this original reservation and preserve its native status"]
pub struct Completion {
    /// The original unique core reservation, returned exactly once.
    pub injection: Injection,
    /// Untranslated status read from this original completed native NBL.
    pub native_status: sdk::NTSTATUS,
}

/// Original nonpaged completion recipient, retained by one native packet.
/// Notification executes at the actual WFP completion's IRQL, at most DISPATCH.
#[must_use]
pub struct Target {
    context: NonNull<c_void>,
    finish: unsafe fn(NonNull<c_void>, Completion),
}

impl Target {
    /// Bind the original completion recipient before any native submission.
    ///
    /// # Safety
    /// `context` identifies the same pinned nonpaged recipient through the
    /// original completion, including synchronous completion inside submission.
    /// `finish` and its code remain live until that call returns. Notification
    /// must not panic, block, wait, free its executing code or use pageable data.
    /// It must settle the original core reservation exactly once and preserve
    /// the supplied native status. A completion is not a device/callback cutoff.
    pub const unsafe fn new(
        context: NonNull<c_void>,
        finish: unsafe fn(NonNull<c_void>, Completion),
    ) -> Self {
        Self { context, finish }
    }
}

impl fmt::Debug for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InjectionTarget").finish_non_exhaustive()
    }
}

pub(super) struct Context<'owner> {
    pub resources: Resources<'owner>,
    pub injection: Injection,
    pub target: Target,
}

pub(super) unsafe extern "C" fn complete(
    context: *mut c_void,
    list: *mut sdk::NET_BUFFER_LIST,
    _dispatch_level: sdk::BOOLEAN,
) {
    // SAFETY: only a successful original FwpsInjectTransportReceiveAsync0 can
    // call this function, once for the newly allocated single-NBL packet. Its
    // original non-null context remains initialized and exclusively owned here.
    let Context {
        resources,
        injection,
        target,
    } = unsafe { context.cast::<Context<'_>>().read() };
    // SAFETY: WFP supplies the same live original NBL and its actual final status.
    let native_status = unsafe { sdk::gnunet_wfp_nbl_status(list) };
    // SAFETY: Target's construction contract retains this original nonpaged
    // recipient and its real completion/core-settlement function at this IRQL.
    unsafe {
        (target.finish)(
            target.context,
            Completion {
                injection,
                native_status,
            },
        )
    };
    // Resources lives on the stack, not inside the allocation being freed.
    // Retain the pool permit through notification and all native frees.
    drop(resources);
}
