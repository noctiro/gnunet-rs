//! Stable BFE notifications across separately retired packet generations.
use super::Driver;
use crate::sdk;
use core::{
    cell::UnsafeCell,
    ffi::c_void,
    ptr::NonNull,
    sync::atomic::{AtomicU64, Ordering},
};

enum Subscription {
    Empty,
    Owned(NonNull<c_void>),
    Cancelled,
    Refused {
        original: NonNull<c_void>,
        status: sdk::NTSTATUS,
    },
    Unknown,
}

/// Original driver-wide subscription, independent of packet-generation reuse.
pub(super) struct State {
    subscription: UnsafeCell<Subscription>,
    losses: AtomicU64,
}

impl State {
    pub(super) const fn new() -> Self {
        Self {
            subscription: UnsafeCell::new(Subscription::Empty),
            losses: AtomicU64::new(0),
        }
    }

    /// Subscribe once before the lifecycle caller first queries BFE state.
    ///
    /// # Safety
    /// Call at PASSIVE_LEVEL under the original passive lifecycle gate, excluding
    /// simultaneous subscription or administrative cancellation. Keep the stable
    /// original driver, device and callback code live through successful cancel.
    /// Its generation access gate must be ready before immediate notification.
    pub(super) unsafe fn subscribe(&self, owner: &'static Driver) -> Result<(), sdk::NTSTATUS> {
        passive()?;
        // SAFETY: the lifecycle caller serializes original subscription mutation;
        // callbacks use only the independent atomic epoch in this object.
        let subscription = unsafe { &mut *self.subscription.get() };
        match *subscription {
            Subscription::Owned(_) => return Ok(()),
            Subscription::Refused { status, .. } => return Err(status),
            Subscription::Unknown => return Err(sdk::GNUNET_WFP_STATUS_INVALID_HANDLE),
            Subscription::Cancelled => return Err(sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE),
            Subscription::Empty => {}
        }
        let device = NonNull::new(owner.device.load(Ordering::Acquire))
            .ok_or(sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE)?;
        let mut original = core::ptr::null_mut();
        // SAFETY: this is the original stable device and Driver context, not a
        // replaceable Generation allocation. Subscribe precedes state queries.
        let status = unsafe {
            sdk::FwpmBfeStateSubscribeChanges0(
                device.as_ptr().cast(),
                Some(changed),
                core::ptr::from_ref(owner).cast_mut().cast(),
                &raw mut original,
            )
        };
        if status != sdk::GNUNET_WFP_STATUS_SUCCESS {
            return Err(status);
        }
        let Some(original) = NonNull::new(original) else {
            *subscription = Subscription::Unknown;
            return Err(sdk::GNUNET_WFP_STATUS_INVALID_HANDLE);
        };
        *subscription = Subscription::Owned(original);
        Ok(())
    }

    /// Observe loss notifications; equality alone never proves policy readiness.
    /// `u64::MAX` is terminal exhaustion and must refuse a fresh generation.
    pub(super) fn epoch(&self) -> u64 {
        self.losses.load(Ordering::Acquire)
    }

    /// End the original subscription after all packet generations have retired.
    /// A failed original cancellation is retained and is never retried.
    ///
    /// # Safety
    /// Call at PASSIVE_LEVEL under the exclusive administrative lifecycle gate,
    /// never from this subscription's own callback. Retain the stable original
    /// Driver and its code until successful cancellation has joined callbacks.
    pub(super) unsafe fn cancel(&self) -> Result<(), sdk::NTSTATUS> {
        passive()?;
        // SAFETY: administrative exclusion prevents simultaneous subscribe/cancel.
        // Native notifications touch only the separate atomic loss epoch.
        let subscription = unsafe { &mut *self.subscription.get() };
        let original = match *subscription {
            Subscription::Owned(original) => original,
            Subscription::Refused { original, status } => {
                // Keep exact original custody without issuing a repeated SDK call.
                let _ = original;
                return Err(status);
            }
            Subscription::Unknown => return Err(sdk::GNUNET_WFP_STATUS_INVALID_HANDLE),
            Subscription::Cancelled => return Ok(()),
            Subscription::Empty => {
                *subscription = Subscription::Cancelled;
                return Ok(());
            }
        };
        // SAFETY: original successful subscription handle, passive caller and
        // independent context; this is never its own notification callback.
        let status = unsafe { sdk::FwpmBfeStateUnsubscribeChanges0(original.as_ptr()) };
        if status != sdk::GNUNET_WFP_STATUS_SUCCESS {
            *subscription = Subscription::Refused { original, status };
            return Err(status);
        }
        *subscription = Subscription::Cancelled;
        Ok(())
    }

    fn lose(&self) -> u64 {
        // Saturation is fail-closed: the lifecycle owner must not start a new
        // generation with an exhausted epoch or reinterpret it as an old zero.
        match self
            .losses
            .try_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
                epoch.checked_add(1)
            }) {
            Ok(previous) => previous + 1,
            Err(exhausted) => exhausted,
        }
    }
}

/// Query only from a passive caller; other IRQLs cannot establish readiness.
pub(super) fn running() -> bool {
    if passive().is_err() {
        return false;
    }
    // SAFETY: the actual current IRQL was checked; this is a native observation,
    // not ownership of a session, policy generation or callback registration.
    unsafe { sdk::FwpmBfeStateGet0() == sdk::FWPM_SERVICE_STATE__FWPM_SERVICE_RUNNING }
}

fn passive() -> Result<(), sdk::NTSTATUS> {
    // SAFETY: the WDK wrapper reads the current IRQL without additional state.
    if u32::from(unsafe { sdk::gnunet_wfp_current_irql() }) == sdk::PASSIVE_LEVEL {
        Ok(())
    } else {
        Err(sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE)
    }
}

unsafe extern "C" fn changed(context: *mut c_void, state: sdk::FWPM_SERVICE_STATE) {
    if state == sdk::FWPM_SERVICE_STATE__FWPM_SERVICE_RUNNING {
        return;
    }
    let Some(owner) = NonNull::new(context.cast::<Driver>()) else {
        return;
    };
    // SAFETY: original subscription context is the stable Driver, retained
    // independently of each replaceable packet generation until cancel joins.
    let owner = unsafe { owner.as_ref() };
    let loss = owner.bfe.lose();
    // Publish the epoch even while replacement blocks access. Never borrow a
    // generation before this reservation, including a failed admission path.
    let Some(_access) = owner.access.enter() else {
        return;
    };
    // SAFETY: this original outer access reservation excludes generation reuse.
    let generation = unsafe { owner.generation() };
    // SAFETY: callback access retains this original pinned packet generation.
    // The epoch comparison and revocation share the runtime lock, so a delayed
    // loss cannot revoke a newer policy after observing an older epoch.
    if !unsafe { generation.runtime().revoke_policy(Some(loss)) } {
        return;
    }
    // SAFETY: the accessor exposes only its fully initialized original callback.
    if let Some(callback) = unsafe { generation.callback() } {
        callback.stop_capture();
    }
}
