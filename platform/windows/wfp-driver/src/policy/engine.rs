use super::error::{Error, NativeFailure};
use crate::sdk;
use core::{
    ffi::c_void,
    ptr::{self, NonNull},
};

pub(super) fn check(operation: &'static str, status: sdk::NTSTATUS) -> Result<(), NativeFailure> {
    if status >= 0 {
        Ok(())
    } else {
        Err(NativeFailure { operation, status })
    }
}

pub(super) struct Engine(NonNull<c_void>);

impl Engine {
    pub(super) fn open(wait_ms: u32) -> Result<Self, Error> {
        // SAFETY: this C SDK input record permits zero integer/pointer members.
        let mut session = unsafe { core::mem::zeroed::<sdk::FWPM_SESSION0>() };
        session.flags = sdk::FWPM_SESSION_FLAG_DYNAMIC;
        session.txnWaitTimeoutInMSec = wait_ms;
        let mut handle = ptr::null_mut();
        // SAFETY: Policy's caller is at PASSIVE_LEVEL. Native input/output
        // storage remains live through this synchronous local engine open.
        check("FwpmEngineOpen0", unsafe {
            sdk::FwpmEngineOpen0(
                ptr::null(),
                sdk::GNUNET_WFP_RPC_C_AUTHN_WINNT as u32,
                ptr::null_mut(),
                &session,
                &mut handle,
            )
        })?;
        Ok(Self(NonNull::new(handle).ok_or(Error::MissingEngine)?))
    }

    pub(super) fn raw(&self) -> sdk::HANDLE {
        self.0.as_ptr()
    }

    pub(super) fn begin(&self) -> Result<(), NativeFailure> {
        // SAFETY: this original live engine is controlled exclusively at PASSIVE_LEVEL.
        check("FwpmTransactionBegin0", unsafe {
            sdk::FwpmTransactionBegin0(self.raw(), 0)
        })
    }

    pub(super) fn commit(&self) -> Result<(), NativeFailure> {
        // SAFETY: the owner retains its original unsettled transaction and live engine.
        check("FwpmTransactionCommit0", unsafe {
            sdk::FwpmTransactionCommit0(self.raw())
        })
    }

    pub(super) fn abort(&self) -> Result<(), NativeFailure> {
        // SAFETY: only an unsettled transaction on this same original engine is targeted.
        check("FwpmTransactionAbort0", unsafe {
            sdk::FwpmTransactionAbort0(self.raw())
        })
    }

    pub(super) fn close(&self) -> Result<(), NativeFailure> {
        // SAFETY: called at PASSIVE_LEVEL after real drain. A failed attempt
        // retains custody but is never retried against a potentially reused value.
        check("FwpmEngineClose0", unsafe {
            sdk::FwpmEngineClose0(self.raw())
        })
    }
}

pub(super) struct Allocation<T>(pub NonNull<T>);
impl<T> Drop for Allocation<T> {
    fn drop(&mut self) {
        let mut pointer = self.0.as_ptr().cast::<c_void>();
        // SAFETY: a successful original SDK allocation is freed once at PASSIVE_LEVEL.
        unsafe { sdk::FwpmFreeMemory0(&mut pointer) };
    }
}
