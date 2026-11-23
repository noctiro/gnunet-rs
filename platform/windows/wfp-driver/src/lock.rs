//! Nonpaged state access under an original WDK spin lock.
use crate::sdk;
use core::{
    cell::UnsafeCell,
    marker::{PhantomData, PhantomPinned},
    ops::{Deref, DerefMut},
    pin::Pin,
};

/// Fixed state and its nonmoving kernel spin lock. Initialize it once at its
/// final nonpaged address before publishing a callback reference.
pub struct StateLock<T> {
    lock: UnsafeCell<sdk::KSPIN_LOCK>,
    state: UnsafeCell<T>,
    initialized: bool,
    _pinned: PhantomPinned,
}

// SAFETY: all shared access to state is serialized by the initialized kernel
// spin lock. Exclusive initialization occurs before any callback reference.
unsafe impl<T: Send> Sync for StateLock<T> {}

impl<T> StateLock<T> {
    /// Store initial state and reserve a lock without calling the SDK.
    pub const fn new(state: T) -> Self {
        Self {
            lock: UnsafeCell::new(0),
            state: UnsafeCell::new(state),
            initialized: false,
            _pinned: PhantomPinned,
        }
    }

    /// Initialize the lock at its final address. Returns false on repeat.
    ///
    /// # Safety
    /// The owner and its entire state must remain pinned and nonpaged until
    /// all native borrowers retire. Call before publishing a shared owner.
    pub unsafe fn initialize(self: Pin<&mut Self>) -> bool {
        // SAFETY: this only accesses fields in place and never moves state.
        let this = unsafe { self.get_unchecked_mut() };
        if this.initialized {
            return false;
        }
        // SAFETY: final nonpaged owner location and exclusive startup loan.
        unsafe { sdk::gnunet_wfp_initialize_spin_lock(this.lock.get()) };
        this.initialized = true;
        true
    }

    /// Acquire the live original lock, raising IRQL to `DISPATCH_LEVEL`.
    ///
    /// # Safety
    /// Enter from at most `DISPATCH_LEVEL` with this lock unheld on the
    /// current thread. Keep the lock and its entire state nonpaged. Release
    /// the returned bound on the same thread. Only perform DISPATCH-safe,
    /// bounded work while holding it, without waiting or calling unrelated I/O.
    pub unsafe fn lock(self: Pin<&Self>) -> Option<Locked<'_, T>> {
        let this = self.get_ref();
        if !this.initialized {
            return None;
        }
        // SAFETY: the caller meets the IRQL, ownership and storage contracts.
        let previous = unsafe { sdk::gnunet_wfp_acquire_spin_lock(this.lock.get()) };
        Some(Locked {
            owner: this,
            previous,
            _thread: PhantomData,
        })
    }
}

/// One original acquisition. Dropping releases the SDK lock and restores the
/// previous IRQL on the acquiring thread.
#[must_use]
pub struct Locked<'a, T> {
    owner: &'a StateLock<T>,
    previous: sdk::KIRQL,
    _thread: PhantomData<*mut ()>,
}

impl<T> Deref for Locked<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: this acquisition remains live and exclusively locks state.
        unsafe { &*self.owner.state.get() }
    }
}

impl<T> DerefMut for Locked<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: this acquisition remains live and exclusively locks state.
        unsafe { &mut *self.owner.state.get() }
    }
}

impl<T> Drop for Locked<'_, T> {
    fn drop(&mut self) {
        // SAFETY: release the same original lock at its acquired IRQL using
        // the exact token. The borrow is neither Send nor Sync.
        unsafe { sdk::gnunet_wfp_release_spin_lock(self.owner.lock.get(), self.previous) };
    }
}
