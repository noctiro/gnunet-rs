//! One reference to the original service file's wake event.
use super::DeviceError;
use crate::{runtime::Runtime, sdk};
use core::{pin::Pin, ptr::NonNull};

pub(super) struct Event(NonNull<sdk::KEVENT>);

// SAFETY: this nonpaged kernel object has an owned reference. KeSetEvent
// serializes concurrent signals; the channel lock serializes access to the loan.
unsafe impl Send for Event {}

impl Event {
    pub(super) fn signal(&self) {
        // SAFETY: this live event accepts a no-wait signal at <= DISPATCH_LEVEL.
        unsafe { sdk::KeSetEvent(self.0.as_ptr(), 0, 0) };
    }
}

impl Drop for Event {
    fn drop(&mut self) {
        // SAFETY: release the same event reference at <= DISPATCH_LEVEL.
        unsafe { sdk::gnunet_wfp_release_event(self.0.as_ptr()) };
    }
}

impl<const F: usize, const R: usize> Runtime<F, R> {
    /// Retain one event from the authenticated file's original user process.
    /// The driver signals on newly available capture or completion records.
    ///
    /// # Safety
    /// Call at PASSIVE_LEVEL in the original IOCTL requestor context. All
    /// original objects must remain live and the handle must be an untrusted
    /// user handle. The I/O manager must retain the request through return.
    ///
    /// # Errors
    /// Refuses wrong IRQL, a stale file, a second event or native denial.
    pub unsafe fn attach_event(
        self: Pin<&Self>,
        irp: NonNull<sdk::IRP>,
        file: NonNull<sdk::FILE_OBJECT>,
        handle: u64,
    ) -> Result<(), DeviceError> {
        // SAFETY: this native SDK query is valid at any IRQL.
        if u32::from(unsafe { sdk::gnunet_wfp_current_irql() }) != sdk::PASSIVE_LEVEL {
            return Err(DeviceError::Native(
                sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_REQUEST,
            ));
        }
        // SAFETY: dispatch retains original runtime and device references.
        let _loan = unsafe { self.admission().acquire() }.map_err(DeviceError::Admission)?;
        let mut event = core::ptr::null_mut();
        let handle = core::ptr::without_provenance_mut(handle as usize);
        // SAFETY: caller retains the IRP and this checks the original user
        // requestor, access mask and object type before taking a reference.
        let status =
            unsafe { sdk::gnunet_wfp_reference_user_event(irp.as_ptr(), handle, &mut event) };
        if status != sdk::GNUNET_WFP_STATUS_SUCCESS {
            return Err(DeviceError::Native(status));
        }
        let event = Event(NonNull::new(event).ok_or(DeviceError::Stale)?);
        // SAFETY: dispatch can take the short state lock on this resident owner.
        let mut state = unsafe { self.lock() }.ok_or(DeviceError::Uninitialized)?;
        state.channel.session(file.addr().get())?;
        if state.channel.wake.is_some() {
            return Err(DeviceError::Busy);
        }
        if state.channel.captures.len() != 0 || state.channel.completions.len() != 0 {
            event.signal();
        }
        state.channel.wake = Some(event);
        Ok(())
    }
}
