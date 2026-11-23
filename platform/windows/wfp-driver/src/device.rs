//! Pinned native rundown for original device, callback and request storage.
//! This module creates no device, publishes no dispatch table and forwards no IRP.
//! Native contracts: [acquisition](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exacquirerundownprotection)
//! and [rundown](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exwaitforrundownprotectionrelease).
pub(crate) mod anchor;
pub mod dispatch;
pub mod object;

use crate::sdk;
use core::{
    cell::UnsafeCell,
    fmt,
    marker::{PhantomData, PhantomPinned},
    mem::MaybeUninit,
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
};

const UNINITIALIZED: usize = 0;
const PREPARED: usize = 1;
const OPEN: usize = 2;
const STOPPED: usize = 3;
const WAITING: usize = 4;
const DRAINED: usize = 5;
const PHASE_MASK: usize = 7;
const RESERVATION: usize = PHASE_MASK + 1;

/// Native admission, initialization or waiting refusal. No refusal resets an
/// existing original, consumes a live loan or claims that its storage is free.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Final pinned storage has not been initialized.
    NotInitialized,
    /// This original storage has already been initialized once.
    AlreadyInitialized,
    /// Storage is prepared, and original admission has not opened.
    NotActive,
    /// Admission is shut, or the native rundown refused a reference.
    Stopping,
    /// No further original rundown reservations are representable.
    Capacity,
    /// The caller must stop new admission before waiting.
    AdmissionOpen,
    /// Another caller owns the original native wait.
    WaitInProgress,
    /// The actual caller IRQL exceeds this operation's documented maximum.
    Irql {
        /// Actual current IRQL returned by the kernel.
        current: u8,
        /// Maximum IRQL for this operation.
        maximum: u32,
    },
}
impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialized => output.write_str("rundown is not initialized"),
            Self::AlreadyInitialized => output.write_str("original rundown is already initialized"),
            Self::NotActive => output.write_str("rundown admission has not opened"),
            Self::Stopping => output.write_str("rundown admission is closed"),
            Self::Capacity => output.write_str("rundown reservation count is exhausted"),
            Self::AdmissionOpen => output.write_str("rundown admission must stop before waiting"),
            Self::WaitInProgress => {
                output.write_str("original rundown wait is already in progress")
            }
            Self::Irql { current, maximum } => {
                write!(output, "rundown IRQL {current} exceeds {maximum}")
            }
        }
    }
}
impl core::error::Error for Error {}

/// One original kernel rundown block. Initialize only after pinning its final
/// nonpaged allocation; it is never reinitialized or repurposed by this owner.
///
/// `activate` opens admission once after native startup. `stop` shuts admission
/// and `try_drain` obtains the actual native zero-reference result. Drop and
/// refusal leave the original allocation in place. External registration must independently stop and synchronize every
/// entry path that can discover the raw allocation before that allocation is
/// freed. Rundown protects acquired loans, not a caller holding a stale pointer.
pub struct Rundown {
    native: UnsafeCell<MaybeUninit<sdk::EX_RUNDOWN_REF>>,
    // One atomic word closes admission and tracks both established loans and
    // entrants between reserving an operation and acquiring its native loan.
    state: AtomicUsize,
    _pin: PhantomPinned,
}
// SAFETY: the SDK's initialized EX_RUNDOWN_REF supports concurrent native
// acquire/release. UnsafeCell encloses every native write; publication and the
// once-only mutable-pin initialization are separated by the atomic phase.
// Its unsafe initialization/acquire contracts keep storage pinned/nonpaged and
// exclude external destruction. This grants no thread mobility to a Loan.
unsafe impl Sync for Rundown {}

impl Rundown {
    /// Construct movable, unpublished storage. No kernel API is called.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            native: UnsafeCell::new(MaybeUninit::uninit()),
            state: AtomicUsize::new(UNINITIALIZED),
            _pin: PhantomPinned,
        }
    }

    /// Initialize once in its original pinned storage, at IRQL <= `APC_LEVEL`.
    ///
    /// # Errors
    /// Returns `AlreadyInitialized` on reuse, or `Irql` before touching native
    /// storage when the actual caller is above `APC_LEVEL`.
    ///
    /// # Safety
    /// This is the final correctly aligned nonpaged kernel allocation. It must
    /// remain pinned, resident and valid until all acquired loans finish and all
    /// external callback/device/IRP entry paths are unregistered and synchronized.
    /// Do not publish the allocation before this call returns successfully. No
    /// foreign code may overwrite, reinitialize or directly modify the block.
    pub unsafe fn initialize(self: Pin<&mut Self>) -> Result<(), Error> {
        at_most(sdk::APC_LEVEL)?;
        if self.state.load(Ordering::Acquire) != UNINITIALIZED {
            return Err(Error::AlreadyInitialized);
        }
        // SAFETY: exclusive mutable pin, final resident allocation and no prior
        // initialization/publication are initialize's checked/unsafe contract.
        unsafe { sdk::ExInitializeRundownProtection(self.native.get().cast()) };
        self.state.store(PREPARED, Ordering::Release);
        Ok(())
    }

    /// Open this prepared original for its native entry paths once.
    ///
    /// # Errors
    /// Returns `NotInitialized`, `AdmissionOpen`, `Stopping` or `Irql`
    /// without opening a second admission.
    ///
    /// # Safety
    /// Call after all original callback state is initialized. Each external
    /// entry path must check its independent operation authority before
    /// acquiring effects and retain its original storage through drain.
    pub unsafe fn activate(self: Pin<&Self>) -> Result<(), Error> {
        at_most(sdk::APC_LEVEL)?;
        match self
            .state
            .compare_exchange(PREPARED, OPEN, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => Ok(()),
            Err(UNINITIALIZED) => Err(Error::NotInitialized),
            Err(OPEN) => Err(Error::AdmissionOpen),
            Err(_) => Err(Error::Stopping),
        }
    }

    /// Acquire one actual native reference while this original admits work.
    /// The operation is nonblocking and requires IRQL <= `DISPATCH_LEVEL`.
    ///
    /// # Errors
    /// Returns `NotInitialized`, `NotActive`, `Stopping`, `Capacity` or `Irql`.
    ///
    /// # Safety
    /// The original initialization/publication contract must remain in force
    /// throughout this call, including a failed acquisition. The returned loan
    /// must be released or dropped at IRQL <= `DISPATCH_LEVEL` while the block
    /// remains nonpaged. Its thread-local ownership must not be bypassed through
    /// foreign pointers. A loan guards lifetime only; it grants no state lock,
    /// packet authority, cancellation receipt or device/IRP completion.
    pub unsafe fn acquire(self: Pin<&Self>) -> Result<Loan<'_>, Error> {
        at_most(sdk::DISPATCH_LEVEL)?;
        self.state
            .try_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                if state & PHASE_MASK == OPEN {
                    state.checked_add(RESERVATION)
                } else {
                    None
                }
            })
            .map_err(|state| match state & PHASE_MASK {
                OPEN => Error::Capacity,
                PREPARED => Error::NotActive,
                UNINITIALIZED => Error::NotInitialized,
                _ => Error::Stopping,
            })?;
        // SAFETY: initialized stable nonpaged native storage, actual caller
        // IRQL checked above; the kernel synchronizes concurrent references.
        if unsafe { sdk::ExAcquireRundownProtection(self.native.get().cast()) } == 0 {
            self.state.fetch_sub(RESERVATION, Ordering::Release);
            return Err(Error::Stopping);
        }
        if self.state.load(Ordering::Acquire) & PHASE_MASK != OPEN {
            // SAFETY: this call acquired exactly one reference and checked its
            // IRQL. Return that same reference if stop won the admission race.
            unsafe { sdk::ExReleaseRundownProtection(self.native.get().cast()) };
            self.state.fetch_sub(RESERVATION, Ordering::Release);
            return Err(Error::Stopping);
        }
        Ok(Loan {
            owner: self,
            _thread: PhantomData,
        })
    }

    /// Permanently shut this original's admission at IRQL <= `DISPATCH_LEVEL`.
    /// This atomic gate does not wait and does not drain an existing loan.
    ///
    /// # Errors
    /// Returns `NotInitialized` or `Irql` without changing admission.
    pub fn stop(self: Pin<&Self>) -> Result<(), Error> {
        at_most(sdk::DISPATCH_LEVEL)?;
        match self
            .state
            .try_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                matches!(state & PHASE_MASK, PREPARED | OPEN)
                    .then_some((state & !PHASE_MASK) | STOPPED)
            }) {
            Ok(_) => Ok(()),
            Err(state) if state & PHASE_MASK >= STOPPED => Ok(()),
            Err(_) => Err(Error::NotInitialized),
        }
    }

    /// Finish the actual native rundown once logical reservations are drained.
    /// Returns `Ok(None)` while a caller can still acquire, release, or hold
    /// an original native reference. A result covers this rundown block only.
    ///
    /// # Errors
    /// Returns `NotInitialized`, `AdmissionOpen`, `WaitInProgress` or `Irql`.
    pub fn try_drain(self: Pin<&Self>) -> Result<Option<Drained<'_>>, Error> {
        at_most(sdk::APC_LEVEL)?;
        match self
            .state
            .compare_exchange(STOPPED, WAITING, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {}
            Err(DRAINED) => return Ok(Some(Drained { owner: self })),
            Err(state) => {
                return match state & PHASE_MASK {
                    PREPARED | OPEN => Err(Error::AdmissionOpen),
                    WAITING => Err(Error::WaitInProgress),
                    STOPPED => Ok(None),
                    _ => Err(Error::NotInitialized),
                };
            }
        }
        // SAFETY: the transition required stopped admission and zero logical
        // reservations. Each native release precedes retirement of its tracked
        // reservation and no new native acquire can begin. This remains the
        // actual WDK rundown, independent of raw external entry lifetimes.
        unsafe {
            sdk::ExWaitForRundownProtectionRelease(self.native.get().cast());
            sdk::ExRundownCompleted(self.native.get().cast());
        }
        self.state.store(DRAINED, Ordering::Release);
        Ok(Some(Drained { owner: self }))
    }
}
impl Default for Rundown {
    fn default() -> Self {
        Self::new()
    }
}
impl fmt::Debug for Rundown {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("Rundown")
            .field("state", &self.state.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

/// One actual original native reference. It cannot be safely transferred to
/// another Rust thread/task; its Drop only releases that reference, never waits.
#[must_use]
pub struct Loan<'owner> {
    owner: Pin<&'owner Rundown>,
    _thread: PhantomData<*mut ()>,
}
impl Loan<'_> {
    /// Release this one reference at the acquire contract's original IRQL bound.
    pub fn release(self) {
        drop(self);
    }
}
impl Drop for Loan<'_> {
    fn drop(&mut self) {
        // SAFETY: only successful native acquisition creates a Loan. Its
        // unsafe acquisition contract requires Drop <= DISPATCH_LEVEL and
        // original resident pinned storage; this non-Clone owner releases once.
        unsafe { sdk::ExReleaseRundownProtection(self.owner.native.get().cast()) };
        self.owner.state.fetch_sub(RESERVATION, Ordering::Release);
    }
}
impl fmt::Debug for Loan<'_> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.debug_struct("RundownLoan").finish_non_exhaustive()
    }
}

/// Actual completed native wait for one exact pinned allocation. This proves
/// only acquired-loan rundown, not unregistering foreign pointer-entry paths.
#[must_use]
pub struct Drained<'owner> {
    owner: Pin<&'owner Rundown>,
}
impl Drained<'_> {
    /// Check this result's original allocation before releasing containing
    /// storage. An equal address after reuse is not a new owner capability.
    #[must_use]
    pub fn belongs_to(&self, original: Pin<&Rundown>) -> bool {
        core::ptr::eq(self.owner.get_ref(), original.get_ref())
    }
}
impl fmt::Debug for Drained<'_> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("RundownDrained")
            .finish_non_exhaustive()
    }
}

fn at_most(maximum: u32) -> Result<(), Error> {
    // SAFETY: this SDK wrapper expands KeGetCurrentIrql's actual intrinsic or
    // macro at any IRQL. No assumed out-of-line kernel export is called.
    let current = unsafe { sdk::gnunet_wfp_current_irql() };
    if u32::from(current) > maximum {
        return Err(Error::Irql { current, maximum });
    }
    Ok(())
}
