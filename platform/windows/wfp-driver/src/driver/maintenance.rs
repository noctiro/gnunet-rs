//! Protected, independent service control for passive driver retirement.
use super::{object_status, retire, unload};
use crate::{
    device::{
        dispatch::{self, CreateAccess},
        object::Object,
    },
    sdk,
};
use core::{
    cell::UnsafeCell,
    ptr::{self, NonNull},
    sync::atomic::{AtomicBool, AtomicPtr, Ordering},
};
use gnunet_wfp_dns::device::maintenance as record;

const FLOW_BUDGET: usize = 32;
const _: () = assert!(record::IOCTL_RETIRE == sdk::GNUNET_WFP_IOCTL_RETIRE as u32);

pub(super) struct Maintenance {
    object: UnsafeCell<Object>,
    device: AtomicPtr<sdk::DEVICE_OBJECT>,
    file: AtomicPtr<sdk::FILE_OBJECT>,
    enabled: AtomicBool,
    busy: AtomicBool,
}

impl Maintenance {
    pub(super) const fn new() -> Self {
        Self {
            object: UnsafeCell::new(Object::maintenance()),
            device: AtomicPtr::new(ptr::null_mut()),
            file: AtomicPtr::new(ptr::null_mut()),
            enabled: AtomicBool::new(false),
            busy: AtomicBool::new(false),
        }
    }

    pub(super) fn device(&self) -> Option<NonNull<sdk::DEVICE_OBJECT>> {
        NonNull::new(self.device.load(Ordering::Acquire))
    }

    pub(super) fn owns_active_request(&self, file: NonNull<sdk::FILE_OBJECT>) -> bool {
        self.busy.load(Ordering::Acquire) && self.file.load(Ordering::Acquire) == file.as_ptr()
    }

    pub(super) fn file_closed(&self) -> bool {
        self.file.load(Ordering::Acquire).is_null()
    }

    pub(super) unsafe fn prepare(
        &self,
        driver: NonNull<sdk::DRIVER_OBJECT>,
        extension_bytes: u32,
    ) -> Result<(), sdk::NTSTATUS> {
        // SAFETY: DriverEntry owns preparation before any control is enabled.
        let object = unsafe { &mut *self.object.get() };
        unsafe { object.prepare(driver, extension_bytes) }.map_err(object_status)?;
        let device = object
            .raw()
            .ok_or(sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE)?;
        self.device.store(device.as_ptr(), Ordering::Release);
        Ok(())
    }

    pub(super) unsafe fn prepare_link(&self) -> Result<(), sdk::NTSTATUS> {
        // SAFETY: DriverEntry exclusively owns the still disabled object.
        unsafe { (&mut *self.object.get()).prepare_link() }.map_err(object_status)
    }

    pub(super) unsafe fn enable(&self) {
        self.enabled.store(true, Ordering::Release);
        // SAFETY: DriverEntry finished setup before publishing file admission.
        unsafe { (&mut *self.object.get()).enable() };
    }

    pub(super) unsafe fn unpublish(&self) -> Result<(), sdk::NTSTATUS> {
        // SAFETY: the original maintenance request is the sole control writer.
        unsafe { (&mut *self.object.get()).unpublish() }
            .map(|_| ())
            .map_err(object_status)
    }

    pub(super) unsafe fn discard_unenabled(&self) -> Result<(), sdk::NTSTATUS> {
        // SAFETY: failed DriverEntry never enabled any user-mode control.
        unsafe { (&mut *self.object.get()).discard_unenabled() }.map_err(object_status)
    }

    pub(super) unsafe fn delete(&self) -> Result<(), sdk::NTSTATUS> {
        // SAFETY: DriverUnload established namespace, file and dispatch cutoff.
        unsafe { (&mut *self.object.get()).delete() }
            .map(|_| ())
            .map_err(object_status)
    }

    pub(super) unsafe fn dispatch(
        &self,
        unload: &unload::State,
        packet_device: NonNull<sdk::DEVICE_OBJECT>,
        irp: NonNull<sdk::IRP>,
        stack: &sdk::IO_STACK_LOCATION,
    ) -> sdk::NTSTATUS {
        // SAFETY: this dispatch exclusively owns the original request and completion.
        let result = unsafe { self.handle(unload, packet_device, irp, stack) };
        unsafe { dispatch::complete_irp(irp, result) }
    }

    unsafe fn handle(
        &self,
        unload: &unload::State,
        packet_device: NonNull<sdk::DEVICE_OBJECT>,
        irp: NonNull<sdk::IRP>,
        stack: &sdk::IO_STACK_LOCATION,
    ) -> Result<usize, sdk::NTSTATUS> {
        let file = NonNull::new(stack.FileObject).ok_or(sdk::GNUNET_WFP_STATUS_FILE_CLOSED)?;
        match u32::from(stack.MajorFunction) {
            sdk::IRP_MJ_CREATE => {
                if !self.enabled.load(Ordering::Acquire) {
                    return Err(sdk::GNUNET_WFP_STATUS_DEVICE_NOT_READY);
                }
                self.file
                    .compare_exchange(
                        ptr::null_mut(),
                        file.as_ptr(),
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .map_err(|_| sdk::GNUNET_WFP_STATUS_DEVICE_BUSY)?;
                // Once claimed, no previous file can publish anchor release.
                let access = if unload.released() {
                    CreateAccess::ReadOnly
                } else {
                    CreateAccess::ReadWrite
                };
                // SAFETY: CREATE belongs to this separate secure-open object.
                if let Err(status) = unsafe { dispatch::validate_root_create(stack, file, access) }
                {
                    self.file.store(ptr::null_mut(), Ordering::Release);
                    return Err(status);
                }
                // Only the original FILE_OBJECT is valid until native CLOSE.
                Ok(0)
            }
            sdk::IRP_MJ_CLEANUP => Ok(0),
            sdk::IRP_MJ_CLOSE => {
                // The I/O manager sends CLOSE after its last file reference,
                // including any maintenance IRP that survived handle cleanup.
                let _ = self.file.compare_exchange(
                    file.as_ptr(),
                    ptr::null_mut(),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                Ok(0)
            }
            sdk::IRP_MJ_READ => {
                if self.file.load(Ordering::Acquire) != file.as_ptr() {
                    return Err(sdk::GNUNET_WFP_STATUS_FILE_CLOSED);
                }
                if !unload.released() {
                    return Err(sdk::GNUNET_WFP_STATUS_DEVICE_NOT_READY);
                }
                // SAFETY: READ selects the original buffered output extent.
                let length = unsafe { stack.Parameters.Read.Length };
                if length as usize != record::PROGRESS_BYTES {
                    return Err(sdk::GNUNET_WFP_STATUS_INVALID_PARAMETER);
                }
                // SAFETY: the original buffered read owns the checked extent.
                Ok(unsafe { write_progress(system_buffer(irp)?, retired()) })
            }
            sdk::IRP_MJ_DEVICE_CONTROL => {
                // SAFETY: this major function owns the DeviceIoControl union arm.
                let control = unsafe { stack.Parameters.DeviceIoControl };
                if control.IoControlCode != record::IOCTL_RETIRE {
                    return Err(sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_REQUEST);
                }
                if control.InputBufferLength as usize != record::REQUEST_BYTES
                    || control.OutputBufferLength as usize != record::PROGRESS_BYTES
                {
                    return Err(sdk::GNUNET_WFP_STATUS_INVALID_PARAMETER);
                }
                if self.file.load(Ordering::Acquire) != file.as_ptr() {
                    return Err(sdk::GNUNET_WFP_STATUS_FILE_CLOSED);
                }
                self.busy
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .map_err(|_| sdk::GNUNET_WFP_STATUS_DEVICE_BUSY)?;
                let _busy = RequestLease(&self.busy);
                // METHOD_BUFFERED supplies one buffer sized to the larger extent.
                // SAFETY: this IRP owns both extents and the checked control code.
                let system = unsafe { system_buffer(irp) }?;
                // SAFETY: only the input bytes have been initialized by the I/O manager.
                let input =
                    unsafe { core::slice::from_raw_parts(system.as_ptr(), record::REQUEST_BYTES) };
                let request = record::Request::decode(input)
                    .ok_or(sdk::GNUNET_WFP_STATUS_INVALID_PARAMETER)?;
                let progress = if unload.released() {
                    // The original read/write owner can observe its last phase.
                    retired()
                } else {
                    // SAFETY: the active original maintenance IRP borrows both devices.
                    unsafe { advance(request, packet_device, irp, file) }?
                };
                // SAFETY: this original control owns the checked output extent.
                Ok(unsafe { write_progress(system, progress) })
            }
            _ => Err(sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_REQUEST),
        }
    }
}

unsafe fn system_buffer(irp: NonNull<sdk::IRP>) -> Result<NonNull<u8>, sdk::NTSTATUS> {
    // SAFETY: the caller selected and checked this original buffered operation.
    let system = unsafe { (*irp.as_ptr()).AssociatedIrp.SystemBuffer };
    NonNull::new(system.cast::<u8>()).ok_or(sdk::GNUNET_WFP_STATUS_INVALID_PARAMETER)
}

unsafe fn write_progress(system: NonNull<u8>, progress: record::Progress) -> usize {
    let bytes = progress.encode();
    // SAFETY: the original buffered operation owns the complete output extent.
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), system.as_ptr(), bytes.len()) };
    bytes.len()
}

fn retired() -> record::Progress {
    record::Progress {
        phase: record::Phase::NativeRetired,
        status: sdk::GNUNET_WFP_STATUS_SUCCESS,
    }
}

struct RequestLease<'a>(&'a AtomicBool);

impl Drop for RequestLease<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

unsafe fn advance(
    request: record::Request,
    device: NonNull<sdk::DEVICE_OBJECT>,
    irp: NonNull<sdk::IRP>,
    file: NonNull<sdk::FILE_OBJECT>,
) -> Result<record::Progress, sdk::NTSTATUS> {
    // SAFETY: the original maintenance IRP pins the same packet device owner.
    if let Some(status) = unsafe { unload::startup_failure(device) } {
        return Ok(failed(status));
    }
    // SAFETY: the control owner retains the exact registered packet device.
    let progress = unsafe {
        match request {
            record::Request::Poll => retire::poll(device, FLOW_BUDGET),
            record::Request::Finalize => retire::finalize(device),
        }
    }?;
    let phase = match progress.phase {
        retire::Phase::Admission => record::Phase::Admission,
        retire::Phase::FlowDeletion => record::Phase::FlowDeletion,
        retire::Phase::PreparedForNativeWait => record::Phase::PreparedForNativeWait,
        retire::Phase::Completion => record::Phase::Completion,
        retire::Phase::NativeRetired if !progress.counts.can_replace() => {
            if let Some(refused) = progress.counts.upstream_close_failure {
                return Ok(failed(refused));
            } else {
                record::Phase::Completion
            }
        }
        retire::Phase::NativeRetired => {
            // SAFETY: the original IRP and FILE_OBJECT remain live through the
            // anchor release. The original packet device just reported cutoff.
            if let Err(status) = unsafe { unload::handoff(device, irp, file) } {
                return Ok(failed(status));
            }
            return Ok(retired());
        }
        retire::Phase::Failed => {
            // SAFETY: the original control still owns passive retirement access.
            let receipts = unsafe { retire::receipts(device) }.ok();
            return Ok(failed(retire::failure_status(progress.failure, receipts)));
        }
    };
    Ok(record::Progress {
        phase,
        status: sdk::GNUNET_WFP_STATUS_SUCCESS,
    })
}

fn failed(status: sdk::NTSTATUS) -> record::Progress {
    record::Progress {
        phase: record::Phase::Failed,
        status: if status == 0 {
            sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE
        } else {
            status
        },
    }
}
