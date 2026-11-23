use super::{CAPTURE_LIFETIME_TICKS, Generation};
use crate::{callbacks, inject, policy, registration, sdk, transport};
use core::{cell::UnsafeCell, num::NonZeroU32, pin::Pin, ptr::NonNull, sync::atomic::Ordering};

pub(super) struct Native {
    pub(super) transport: UnsafeCell<transport::Transport>,
    pub(super) pool: UnsafeCell<inject::Pool>,
    pub(super) registrations: UnsafeCell<registration::Registration>,
    pub(super) policy: UnsafeCell<policy::Policy>,
}

impl Native {
    pub(super) const fn new() -> Self {
        Self {
            transport: UnsafeCell::new(transport::Transport::new()),
            pool: UnsafeCell::new(inject::Pool::new()),
            registrations: UnsafeCell::new(registration::Registration::new()),
            policy: UnsafeCell::new(policy::Policy::new()),
        }
    }

    pub(super) unsafe fn prepare(
        &mut self,
        generation: &'static Generation,
        device: NonNull<sdk::DEVICE_OBJECT>,
    ) -> Result<(), sdk::NTSTATUS> {
        // SAFETY: original passive startup exclusively owns both handle slots.
        unsafe { self.transport.get_mut().open() }.map_err(|error| match error {
            transport::OpenError::Native(failure) => failure.status,
            _ => sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE,
        })?;
        // SAFETY: original pool is at its final nonpaged address before any
        // native packet can borrow it. Fixed REQUESTS equals this packet bound.
        const { assert!(callbacks::REQUESTS == 32) };
        unsafe { Pin::new_unchecked(self.pool.get_mut()).initialize(32) }.map_err(|error| {
            match error {
                inject::Error::Native { status, .. } => status,
                inject::Error::Allocation { .. } => sdk::GNUNET_WFP_STATUS_INSUFFICIENT_RESOURCES,
                _ => sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE,
            }
        })?;
        let handles = self
            .transport
            .get_mut()
            .handles()
            .ok_or(sdk::GNUNET_WFP_STATUS_INVALID_HANDLE)?;
        // SAFETY: original runtime initialization precedes entry publication;
        // handles are original live family owners, retained through native cutoff.
        let callback =
            unsafe { callbacks::State::new(generation.runtime(), handles, CAPTURE_LIFETIME_TICKS) };
        // SAFETY: callback storage is separate from mutable native-owner storage,
        // initialized once and never moved while any external entry exists.
        unsafe { (*generation.callback.get()).write(callback) };
        generation
            .callback_initialized
            .store(true, Ordering::Release);
        // SAFETY: this exact original initialized field is permanently pinned.
        let callback =
            unsafe { generation.callback() }.ok_or(sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE)?;
        // SAFETY: full original state and handles precede FWPS registration.
        unsafe { callback.publish() }.map_err(|_| sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE)?;
        generation.callback_published.store(true, Ordering::Release);
        // SAFETY: original device, callback recipient and code are prepared.
        unsafe {
            self.registrations
                .get_mut()
                .register(device, &callbacks::functions())
        }
        .map_err(|error| match error {
            registration::RegisterError::Native(failure) => failure.status,
            _ => sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE,
        })?;
        let ids = self.registrations.get_mut().ids();
        let datagrams = [ids[2], ids[3]].map(|id| id.and_then(NonZeroU32::new));
        let datagrams = [
            datagrams[0].ok_or(sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE)?,
            datagrams[1].ok_or(sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE)?,
        ];
        // SAFETY: these are this owner's actual original registration outputs.
        unsafe { callback.set_datagram_ids(datagrams) }
            .map_err(|_| sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE)?;
        // SAFETY: admission to capture is still closed, no injection exists,
        // and original registrations survive the full native policy lifetime.
        unsafe {
            self.policy
                .get_mut()
                .install(policy::Limits::default(), callback)
        }
        .map_err(|error| match error {
            policy::Error::Native(failure) => failure.status,
            _ => sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE,
        })?;
        Ok(())
    }
}
