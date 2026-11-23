use super::{Error, error};
use crate::sdk;
use core::{
    ffi::c_void,
    fmt,
    marker::PhantomPinned,
    pin::Pin,
    ptr::{self, NonNull},
    sync::atomic::{AtomicUsize, Ordering},
};

const CLOSED: usize = 1 << (usize::BITS - 1);
const POOL_TAG: u32 = u32::from_le_bytes(*b"GDNB");

/// Original NDIS allocation pool with a fixed bound on native packet owners.
/// No `Drop` frees this pool: external submitters and WFP callbacks must drain.
#[must_use = "retain this pinned pool through all original native completions"]
pub struct Pool {
    handle: Option<NonNull<c_void>>,
    initialized: bool,
    capacity: usize,
    owners: AtomicUsize,
    _pin: PhantomPinned,
}

// SAFETY: initialization and final retirement require exclusive pinned access.
// Between them the original NDIS handle is immutable, NDIS pool allocations
// support concurrent callers, and owner admission uses one atomic state word.
unsafe impl Sync for Pool {}

impl Pool {
    /// Construct unpublished movable storage without any native allocation.
    pub const fn new() -> Self {
        Self {
            handle: None,
            initialized: false,
            capacity: 0,
            owners: AtomicUsize::new(CLOSED),
            _pin: PhantomPinned,
        }
    }

    /// Prepare one original pool, initially admitting at most `capacity` packets.
    ///
    /// # Errors
    /// Refuses reuse, zero capacity, excessive IRQL or native allocation failure.
    ///
    /// # Safety
    /// Call at PASSIVE_LEVEL before publication in the final nonpaged allocation.
    /// Retain its pin and native handle until external submitters and all actual
    /// native completions have drained and explicit retirement succeeds.
    pub unsafe fn initialize(self: Pin<&mut Self>, capacity: u16) -> Result<(), Error> {
        error::at_most(sdk::PASSIVE_LEVEL)?;
        // SAFETY: only fields are initialized, without moving this pinned owner.
        let owner = unsafe { self.get_unchecked_mut() };
        if owner.initialized {
            return Err(Error::AlreadyInitialized);
        }
        if capacity == 0 {
            return Err(Error::Capacity);
        }
        // SAFETY: zero is valid for every optional SDK pool input member.
        let mut parameters = unsafe { core::mem::zeroed::<sdk::NET_BUFFER_LIST_POOL_PARAMETERS>() };
        parameters.Header.Type = sdk::GNUNET_WFP_NDIS_OBJECT_TYPE_DEFAULT as u8;
        parameters.Header.Revision = sdk::GNUNET_WFP_NBL_POOL_PARAMS_REVISION as u8;
        parameters.Header.Size = sdk::GNUNET_WFP_NBL_POOL_PARAMS_SIZE as u16;
        parameters.ProtocolId = sdk::NDIS_PROTOCOL_ID_DEFAULT as u8;
        parameters.fAllocateNetBuffer = 1;
        parameters.PoolTag = POOL_TAG;
        // DataSize zero means the caller owns the MDL and its data allocation.
        // SAFETY: this synchronous real NDIS allocator accepts a null optional
        // NDIS caller handle and borrows the complete initialized parameters.
        let handle = unsafe { sdk::NdisAllocateNetBufferListPool(ptr::null_mut(), &parameters) };
        owner.handle = Some(NonNull::new(handle).ok_or(Error::Allocation {
            operation: "NdisAllocateNetBufferListPool",
        })?);
        owner.capacity = usize::from(capacity);
        owner.initialized = true;
        owner.owners.store(0, Ordering::Release);
        Ok(())
    }

    /// Stop further packet admission, without waiting or freeing any owner.
    pub fn stop(self: Pin<&Self>) {
        self.owners.fetch_or(CLOSED, Ordering::AcqRel);
    }

    /// Original preparations/completions still retaining this pool.
    /// Zero is an allocation observation, not a native callback cutoff proof.
    pub fn outstanding(&self) -> usize {
        self.owners.load(Ordering::Acquire) & !CLOSED
    }

    /// Free this original stopped pool after external and native drain.
    ///
    /// # Errors
    /// Refuses excessive IRQL, open admission and any outstanding original owner.
    ///
    /// # Safety
    /// Call at PASSIVE_LEVEL after stopping and joining every submitter and
    /// obtaining the actual WFP injection/callback cutoff. An observed counter
    /// of zero alone is insufficient. No foreign entry may still discover this
    /// original allocation, and no native user may retain an NBL from its pool.
    pub unsafe fn retire_after_drain(self: Pin<&mut Self>) -> Result<bool, Error> {
        error::at_most(sdk::PASSIVE_LEVEL)?;
        // SAFETY: external and native users are excluded by the caller's cutoff.
        let owner = unsafe { self.get_unchecked_mut() };
        let state = owner.owners.load(Ordering::Acquire);
        if state & CLOSED == 0 {
            return Err(Error::AdmissionOpen);
        }
        if state & !CLOSED != 0 {
            return Err(Error::Busy {
                outstanding: state & !CLOSED,
            });
        }
        let Some(handle) = owner.handle.take() else {
            return Ok(false);
        };
        // SAFETY: every original NBL retired; the caller excludes all entries.
        unsafe { sdk::NdisFreeNetBufferListPool(handle.as_ptr()) };
        Ok(true)
    }

    pub(super) fn claim(self: Pin<&Self>) -> Result<Permit<'_>, Error> {
        if self.handle.is_none() {
            return Err(Error::Uninitialized);
        }
        self.owners
            .try_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                (state & CLOSED == 0 && state < self.capacity).then_some(state + 1)
            })
            .map_err(|state| {
                if state & CLOSED != 0 {
                    Error::Stopping
                } else {
                    Error::Full
                }
            })?;
        Ok(Permit { owner: self })
    }
}
impl Default for Pool {
    fn default() -> Self {
        Self::new()
    }
}
impl fmt::Debug for Pool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InjectionPool")
            .field("initialized", &self.initialized)
            .field("capacity", &self.capacity)
            .field("outstanding", &self.outstanding())
            .finish_non_exhaustive()
    }
}

pub(super) struct Permit<'owner> {
    owner: Pin<&'owner Pool>,
}
impl Permit<'_> {
    pub(super) fn handle(&self) -> Result<NonNull<c_void>, Error> {
        self.owner.handle.ok_or(Error::Uninitialized)
    }
}
impl Drop for Permit<'_> {
    fn drop(&mut self) {
        self.owner.owners.fetch_sub(1, Ordering::Release);
    }
}
