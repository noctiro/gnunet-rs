//! Passive ownership of the authenticated service's original native socket handles.
use super::DeviceError;
use crate::{runtime::Runtime, sdk};
use core::{ffi::c_void, num::NonZeroU64, pin::Pin, ptr::NonNull};
use gnunet_wfp_dns::device::{self as record, Upstream};

pub(super) struct Sockets {
    leases: [Option<Lease>; record::MAX_UPSTREAM_SOCKETS],
}

impl Sockets {
    pub(super) const fn new() -> Self {
        Self {
            leases: [const { None }; record::MAX_UPSTREAM_SOCKETS],
        }
    }

    pub(super) fn excludes(&self, endpoint: NonZeroU64) -> bool {
        self.leases
            .iter()
            .flatten()
            .any(|lease| lease.original.endpoint == endpoint)
    }

    fn retain(
        &mut self,
        irp: NonNull<sdk::IRP>,
        upstreams: &record::Upstreams,
    ) -> Result<(), DeviceError> {
        for (slot, &original) in self.leases.iter_mut().zip(upstreams.as_slice()) {
            let socket = core::ptr::without_provenance_mut(original.socket.get() as usize);
            let mut raw = core::ptr::null_mut();
            // SAFETY: caller checked the original passive IRP. The wrapper
            // checks process, user access and native object type before retention.
            let status =
                unsafe { sdk::gnunet_wfp_retain_user_socket(irp.as_ptr(), socket, &mut raw) };
            if status != sdk::GNUNET_WFP_STATUS_SUCCESS {
                return Err(DeviceError::Native(status));
            }
            let owned = NonNull::new(raw)
                .ok_or(DeviceError::Native(sdk::GNUNET_WFP_STATUS_INVALID_HANDLE))?;
            *slot = Some(Lease {
                original,
                owned: Some(owned),
                close_failure: None,
            });
        }
        Ok(())
    }

    pub(super) fn close(&mut self) -> Result<(), DeviceError> {
        let mut first_failure = None;
        for lease in self.leases.iter_mut().flatten() {
            if let Err(failure) = lease.close() {
                first_failure.get_or_insert(failure);
            }
        }
        first_failure.map_or(Ok(()), Err)
    }

    pub(super) fn close_failure(&self) -> Option<sdk::NTSTATUS> {
        self.leases
            .iter()
            .flatten()
            .find_map(|lease| lease.close_failure)
    }
}

struct Lease {
    original: Upstream,
    owned: Option<NonNull<c_void>>,
    close_failure: Option<sdk::NTSTATUS>,
}

// SAFETY: the handle came from OBJ_KERNEL_HANDLE and is never transferred to
// user mode. Ownership moves under the channel lock. Close runs only at PASSIVE.
unsafe impl Send for Lease {}

impl Lease {
    fn close(&mut self) -> Result<(), DeviceError> {
        if let Some(status) = self.close_failure {
            return Err(DeviceError::Native(status));
        }
        let Some(handle) = self.owned else {
            return Ok(());
        };
        // SAFETY: release this original kernel handle once at PASSIVE_LEVEL.
        let status = unsafe { sdk::gnunet_wfp_release_socket(handle.as_ptr()) };
        if status != sdk::GNUNET_WFP_STATUS_SUCCESS {
            self.close_failure = Some(status);
            return Err(DeviceError::Native(status));
        }
        self.owned = None;
        Ok(())
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

pub(super) fn passive() -> Result<(), DeviceError> {
    // SAFETY: the WDK query is valid at any IRQL.
    if u32::from(unsafe { sdk::gnunet_wfp_current_irql() }) == sdk::PASSIVE_LEVEL {
        Ok(())
    } else {
        Err(DeviceError::Native(
            sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE,
        ))
    }
}

impl<const F: usize, const R: usize> Runtime<F, R> {
    /// Retain the original sockets, prepare native policy and arm this file.
    ///
    /// # Safety
    /// Use the original protected file's passive START IRP and its live
    /// buffered input. Only the trusted DNS service may supply the matching
    /// IFS socket and WSAIoctl-derived endpoint observations. The caller holds
    /// passive lifecycle control. `prepare` may use the runtime lock and is
    /// called only with that lock released and all original sockets retained.
    ///
    /// # Errors
    /// Refuses invalid descriptors, stale or already started ownership, and
    /// any missing native policy, wake event or original handle.
    pub unsafe fn start_file(
        self: Pin<&Self>,
        irp: NonNull<sdk::IRP>,
        file: NonNull<sdk::FILE_OBJECT>,
        upstreams: &record::Upstreams,
        prepare: impl FnOnce() -> Result<(), sdk::NTSTATUS>,
    ) -> Result<(), DeviceError> {
        passive()?;
        // SAFETY: dispatch retains the original nonpaged object through START.
        let _loan = unsafe { self.admission().acquire() }.map_err(DeviceError::Admission)?;
        let address = file.addr().get();
        {
            // SAFETY: PASSIVE dispatch can take this original initialized lock.
            let mut state = unsafe { self.lock() }.ok_or(DeviceError::Uninitialized)?;
            state.channel.session(address)?;
            if state.channel.wake.is_none() {
                return Err(DeviceError::Native(sdk::GNUNET_WFP_STATUS_DEVICE_NOT_READY));
            }
            if state.channel.started
                || state.channel.stopped
                || state.channel.socket_operation_pending
                || state.channel.failed_sockets.is_some()
            {
                return Err(DeviceError::Busy);
            }
            state.channel.socket_operation_pending = true;
        }
        let mut sockets = Sockets::new();
        let result = (|| {
            sockets.retain(irp, upstreams)?;
            {
                // SAFETY: the original START still pins the file and runtime.
                let state = unsafe { self.lock() }.ok_or(DeviceError::Uninitialized)?;
                state.channel.session(address)?;
            }
            prepare().map_err(DeviceError::Native)?;
            // SAFETY: original passive dispatch still keeps this state initialized.
            let mut state = unsafe { self.lock() }.ok_or(DeviceError::Uninitialized)?;
            state.channel.session(address)?;
            if state.channel.policy_epoch.is_none() {
                return Err(DeviceError::Native(sdk::GNUNET_WFP_STATUS_DEVICE_NOT_READY));
            }
            // Move the committed original set without triggering native release
            // while this state lock is held.
            state.channel.sockets = Some(core::mem::replace(&mut sockets, Sockets::new()));
            state.channel.started = true;
            state.channel.socket_operation_pending = false;
            Ok(())
        })();
        if result.is_err() {
            // SAFETY: this remains the one passive holder of the original
            // incomplete socket acquisition, including any rollback failures.
            let _ = unsafe { self.close_sockets(Some(sockets)) };
        }
        result
    }
}
