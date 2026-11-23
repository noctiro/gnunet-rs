//! The original WFP transport injection handles, one per address family.
use crate::{registration::NativeFailure, sdk};
use core::{ffi::c_void, ptr::NonNull};

/// Ownership of the live WFP transport handles and their later destruction.
/// This object issues explicit retirement to preserve any native failure.
#[must_use]
pub struct Transport {
    handles: [Option<NonNull<c_void>>; 2],
}

/// Failure while acquiring the original pair of transport handles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenError {
    /// The original handles have not both retired.
    AlreadyOwned,
    /// Actual native failure.
    Native(NativeFailure),
    /// WFP returned success without its original non-null handle.
    MissingHandle,
}

impl Transport {
    /// An empty owner without native effects.
    pub const fn new() -> Self {
        Self { handles: [None; 2] }
    }

    /// Copy the two original handle values in IPv4/IPv6 order. Any native
    /// operation using the values must keep this original owner live and pinned.
    pub fn handles(&self) -> Option<[NonNull<c_void>; 2]> {
        Some([self.handles[0]?, self.handles[1]?])
    }

    /// Whether no live original native handle remains in this owner.
    pub fn retired(&self) -> bool {
        self.handles.iter().all(Option::is_none)
    }

    /// Acquire family-specific transport injection handles from WFP.
    ///
    /// # Safety
    /// Call at `PASSIVE_LEVEL`. Keep this owner on partial failure and retire
    /// any acquired handle. Serialize preparation and retirement with all
    /// native users of either original handle.
    ///
    /// # Errors
    /// Refuses reuse with an original handle, native failure, and success
    /// without a handle. Earlier successful acquisitions remain owned.
    pub unsafe fn open(&mut self) -> Result<(), OpenError> {
        if !self.retired() {
            return Err(OpenError::AlreadyOwned);
        }
        for (owner, family) in self.handles.iter_mut().zip([
            sdk::GNUNET_WFP_AF_INET as sdk::ADDRESS_FAMILY,
            sdk::GNUNET_WFP_AF_INET6 as sdk::ADDRESS_FAMILY,
        ]) {
            let mut handle = core::ptr::null_mut();
            // SAFETY: passive level was required, family and transport flag
            // come from the WDK, and the SDK borrows one initialized output.
            let status = unsafe {
                sdk::FwpsInjectionHandleCreate0(
                    family,
                    sdk::FWPS_INJECTION_TYPE_TRANSPORT,
                    &mut handle,
                )
            };
            if status != sdk::GNUNET_WFP_STATUS_SUCCESS {
                return Err(OpenError::Native(NativeFailure {
                    operation: "FwpsInjectionHandleCreate0",
                    status,
                }));
            }
            *owner = Some(NonNull::new(handle).ok_or(OpenError::MissingHandle)?);
        }
        Ok(())
    }

    /// Destroy both originals in reverse order. Independent failures retain
    /// their original slot. Each bool reports whether a handle was destroyed.
    ///
    /// # Safety
    /// Call at PASSIVE_LEVEL after stopping original submitters and successfully
    /// unregistering callback entries that could still query these handles. Keep
    /// the original native guards in place during this step. The SDK waits for
    /// its pending injections. Keep every failed handle in its original slot.
    pub unsafe fn close(&mut self) -> [Result<bool, NativeFailure>; 2] {
        // SAFETY: the original injection and observation paths have drained.
        unsafe { [self.destroy(1), self.destroy(0)] }
    }

    unsafe fn destroy(&mut self, family: usize) -> Result<bool, NativeFailure> {
        let Some(handle) = self.handles[family] else {
            return Ok(false);
        };
        // SAFETY: this is one original SDK handle and no user can still query
        // it. The native wait runs at passive level with no state lock held.
        let status = unsafe { sdk::FwpsInjectionHandleDestroy0(handle.as_ptr()) };
        if status != sdk::GNUNET_WFP_STATUS_SUCCESS {
            return Err(NativeFailure {
                operation: "FwpsInjectionHandleDestroy0",
                status,
            });
        }
        self.handles[family] = None;
        Ok(true)
    }
}

impl Default for Transport {
    fn default() -> Self {
        Self::new()
    }
}
