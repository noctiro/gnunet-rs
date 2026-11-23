//! Synchronous buffered I/O into the original local device channel.
use crate::{
    inject,
    runtime::{DeviceError, Runtime},
    sdk,
};
use core::{ffi::c_void, pin::Pin, ptr::NonNull, slice};
use gnunet_wfp_dns::{InjectionObservation, device as record};

const _: () = {
    assert!(record::IOCTL_COMPLETION == sdk::GNUNET_WFP_IOCTL_COMPLETION as u32);
    assert!(record::IOCTL_SET_EVENT == sdk::GNUNET_WFP_IOCTL_SET_EVENT as u32);
    assert!(record::IOCTL_START == sdk::GNUNET_WFP_IOCTL_START as u32);
    assert!(record::IOCTL_STOP == sdk::GNUNET_WFP_IOCTL_STOP as u32);
};

/// Native owners borrowed by one original IRP dispatch.
pub struct Injections<'a> {
    /// Pinned original NDIS pool.
    pub pool: Pin<&'a inject::Pool>,
    /// Original live IPv4 and IPv6 transport handles.
    pub handles: &'a [NonNull<c_void>; 2],
}

/// Complete one original IRP synchronously. An accepted WRITE reports native
/// submission only. Retrieve its actual completion with the device control.
///
/// # Safety
/// Call from the original exclusive buffered device at IRQL <= DISPATCH_LEVEL.
/// The IRP, active stack and any system buffer belong to this dispatch, and
/// there is no competing completion or private lower stack. Keep the runtime,
/// guards, original handles, pool and callback code live through native cutoff,
/// including completion after return and after original file cleanup.
pub unsafe fn dispatch<const F: usize, const R: usize>(
    runtime: Pin<&Runtime<F, R>>,
    irp: NonNull<sdk::IRP>,
    injections: Option<Injections<'_>>,
) -> sdk::NTSTATUS {
    // SAFETY: caller owns the original buffered device's active IRP.
    let result = unsafe { handle(runtime, irp, injections) };
    // SAFETY: this dispatch still owns completion of the original IRP.
    unsafe { complete_irp(irp, result) }
}

pub(crate) unsafe fn complete_irp(irp: NonNull<sdk::IRP>, result: Result) -> sdk::NTSTATUS {
    let (status, bytes) = match result {
        Ok(bytes) => (sdk::GNUNET_WFP_STATUS_SUCCESS, bytes),
        Err(status) => (status, 0),
    };
    // SAFETY: dispatch owns these original completion fields and completes
    // exactly once. The I/O manager may release the IRP during this call.
    unsafe {
        (*irp.as_ptr()).IoStatus.__bindgen_anon_1.Status = status;
        (*irp.as_ptr()).IoStatus.Information = bytes as _;
        sdk::gnunet_wfp_complete_request(irp.as_ptr(), 0);
    }
    status
}

type Result = core::result::Result<usize, sdk::NTSTATUS>;

unsafe fn handle<const F: usize, const R: usize>(
    runtime: Pin<&Runtime<F, R>>,
    irp: NonNull<sdk::IRP>,
    injections: Option<Injections<'_>>,
) -> Result {
    // SAFETY: I/O manager supplies the live current stack to this dispatch.
    let stack = unsafe { sdk::gnunet_wfp_current_irp_stack(irp.as_ptr()).as_ref() }
        .ok_or(sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_REQUEST)?;
    let file = NonNull::new(stack.FileObject).ok_or(sdk::GNUNET_WFP_STATUS_FILE_CLOSED)?;
    match u32::from(stack.MajorFunction) {
        sdk::IRP_MJ_CREATE => {
            // SAFETY: the original CREATE stack owns this original file.
            unsafe { validate_root_create(stack, file, CreateAccess::ReadWrite) }?;
            // SAFETY: original protected device supplied this CREATE file.
            unsafe { runtime.open_file(file) }.map_err(status)?;
            Ok(0)
        }
        sdk::IRP_MJ_CLEANUP => {
            // SAFETY: original I/O manager dispatch owns this file's cleanup.
            unsafe { runtime.cleanup_file(file) }.map_err(status)?;
            Ok(0)
        }
        sdk::IRP_MJ_CLOSE => Ok(0),
        sdk::IRP_MJ_READ => {
            // SAFETY: READ selects the active arm and buffered-device output.
            let output = unsafe { buffer(irp, stack.Parameters.Read.Length as usize) }?;
            // SAFETY: original file, system buffer and runtime are live.
            unsafe { runtime.dequeue(file, output) }
                .map_err(status)?
                .ok_or(sdk::GNUNET_WFP_STATUS_NO_MORE_ENTRIES)
        }
        sdk::IRP_MJ_WRITE => {
            // SAFETY: WRITE selects the active arm and buffered-device input.
            let input = unsafe { buffer(irp, stack.Parameters.Write.Length as usize) }?;
            let injections = injections.ok_or(sdk::GNUNET_WFP_STATUS_DEVICE_NOT_READY)?;
            // SAFETY: original request and all borrowed owners stay live.
            unsafe { write(runtime, file, input, injections) }
        }
        sdk::IRP_MJ_DEVICE_CONTROL => {
            // SAFETY: the DEVICE_CONTROL arm matches this original major code.
            let control = unsafe { stack.Parameters.DeviceIoControl };
            // SAFETY: both defined codes certify this original METHOD_BUFFERED IRP.
            unsafe { ioctl(runtime, irp, file, control) }
        }
        _ => Err(sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_REQUEST),
    }
}

pub(crate) unsafe fn validate_root_create(
    stack: &sdk::IO_STACK_LOCATION,
    file: NonNull<sdk::FILE_OBJECT>,
    access: CreateAccess,
) -> core::result::Result<(), sdk::NTSTATUS> {
    // SAFETY: caller supplies the active CREATE stack and its original file.
    let root_file = unsafe {
        (*file.as_ptr()).FileName.Length == 0
            && (*file.as_ptr()).RelatedFileObject.is_null()
            && stack.Parameters.Create.Options & sdk::GNUNET_WFP_FILE_DIRECTORY_FILE as u32 == 0
    };
    if !root_file {
        return Err(sdk::GNUNET_WFP_STATUS_INVALID_PARAMETER);
    }
    // SAFETY: the active CREATE arm owns the I/O manager security context.
    let desired = unsafe { stack.Parameters.Create.SecurityContext.as_ref() }
        .ok_or(sdk::GNUNET_WFP_STATUS_ACCESS_DENIED)?
        .DesiredAccess;
    let read = sdk::GNUNET_WFP_FILE_READ_DATA as u32 | sdk::GNUNET_WFP_GENERIC_READ;
    let write = sdk::GNUNET_WFP_FILE_WRITE_DATA as u32 | sdk::GNUNET_WFP_GENERIC_WRITE;
    let permitted = match access {
        CreateAccess::ReadWrite => desired & write != 0,
        CreateAccess::ReadOnly => {
            let read_only = sdk::GNUNET_WFP_FILE_GENERIC_READ as u32 | sdk::GNUNET_WFP_GENERIC_READ;
            desired & !read_only == 0
        }
    };
    if desired & read == 0 || !permitted {
        return Err(sdk::GNUNET_WFP_STATUS_ACCESS_DENIED);
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(crate) enum CreateAccess {
    ReadWrite,
    ReadOnly,
}

unsafe fn buffer<'io>(
    irp: NonNull<sdk::IRP>,
    len: usize,
) -> core::result::Result<&'io mut [u8], sdk::NTSTATUS> {
    if len == 0 {
        return Ok(&mut []);
    }
    if len > record::MAX_RECORD_BYTES {
        return Err(sdk::GNUNET_WFP_STATUS_INVALID_PARAMETER);
    }
    // SAFETY: caller selected a buffered operation with exclusive I/O custody.
    let bytes = unsafe { (*irp.as_ptr()).AssociatedIrp.SystemBuffer };
    let bytes = NonNull::new(bytes.cast::<u8>()).ok_or(sdk::GNUNET_WFP_STATUS_INVALID_PARAMETER)?;
    // SAFETY: I/O manager allocated the selected length for this original operation.
    Ok(unsafe { slice::from_raw_parts_mut(bytes.as_ptr(), len) })
}

unsafe fn write<const F: usize, const R: usize>(
    runtime: Pin<&Runtime<F, R>>,
    file: NonNull<sdk::FILE_OBJECT>,
    input: &[u8],
    injections: Injections<'_>,
) -> Result {
    // SAFETY: original dispatch pins the state and keeps this loan through
    // the whole native call, including any inline completion.
    let _loan = unsafe { runtime.admission().acquire() }
        .map_err(|_| sdk::GNUNET_WFP_STATUS_DEVICE_NOT_READY)?;
    // SAFETY: original buffered dispatch supplies exactly its own live data.
    let Some(original) = (unsafe { runtime.begin_reply(file, input) }).map_err(status)? else {
        return Ok(input.len());
    };
    let mut submission = inject::Submission::new(original);
    let recipient = NonNull::from(runtime.get_ref()).cast();
    // SAFETY: dispatch keeps this actual nonpaged callback recipient alive
    // through native retirement, independently of the original user file.
    let target = unsafe { inject::Target::new(recipient, complete::<F, R>) };
    // SAFETY: the buffered body and original native owners remain valid.
    let result = unsafe {
        submission.submit(
            injections.pool,
            injections.handles,
            &input[record::TOKEN_BYTES..],
            target,
        )
    };
    if let Err(error) = result {
        if let Some(original) = submission.into_unsubmitted() {
            // SAFETY: the failed SDK submission never accepted this context.
            unsafe { runtime.reject_reply(original) }.map_err(status)?;
        }
        return Err(match error {
            inject::Error::Native { status, .. } => status,
            inject::Error::Allocation { .. } | inject::Error::Full => {
                sdk::GNUNET_WFP_STATUS_INSUFFICIENT_RESOURCES
            }
            inject::Error::Packet(_) | inject::Error::Path => {
                sdk::GNUNET_WFP_STATUS_INVALID_PARAMETER
            }
            _ => sdk::GNUNET_WFP_STATUS_DEVICE_NOT_READY,
        });
    }
    Ok(input.len())
}

unsafe fn complete<const F: usize, const R: usize>(
    recipient: NonNull<c_void>,
    completion: inject::Completion,
) {
    // SAFETY: original native callback keeps the pinned recipient alive.
    let runtime = unsafe { Pin::new_unchecked(recipient.cast::<Runtime<F, R>>().as_ref()) };
    // SAFETY: this unique Completion comes from the actual original NBL.
    let _ = unsafe { runtime.complete_reply(completion.injection, completion.native_status) };
}

unsafe fn ioctl<const F: usize, const R: usize>(
    runtime: Pin<&Runtime<F, R>>,
    irp: NonNull<sdk::IRP>,
    file: NonNull<sdk::FILE_OBJECT>,
    control: sdk::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_17,
) -> Result {
    match control.IoControlCode {
        record::IOCTL_COMPLETION if control.InputBufferLength == 0 => {
            if (control.OutputBufferLength as usize) < record::COMPLETION_BYTES {
                return Err(sdk::GNUNET_WFP_STATUS_BUFFER_TOO_SMALL);
            }
            // SAFETY: original METHOD_BUFFERED completion output is large enough.
            let out = unsafe { buffer(irp, record::COMPLETION_BYTES) }?;
            // SAFETY: this is the original file's real completion request.
            let Some(item) = (unsafe { runtime.completion(file) }).map_err(status)? else {
                return Ok(0);
            };
            out.copy_from_slice(&record::encode_completion(
                item.request,
                item.status,
                item.observation == InjectionObservation::Authorized,
            ));
            Ok(out.len())
        }
        record::IOCTL_SET_EVENT
            if control.OutputBufferLength == 0 && control.InputBufferLength == 8 =>
        {
            // SAFETY: original METHOD_BUFFERED event input is exactly one handle.
            let input = unsafe { buffer(irp, 8) }?;
            let bytes = input
                .first_chunk::<8>()
                .ok_or(sdk::GNUNET_WFP_STATUS_INVALID_PARAMETER)?;
            // SAFETY: the runtime checks passive execution, original user context,
            // handle access rights, and the original file before retaining it.
            unsafe { runtime.attach_event(irp, file, u64::from_le_bytes(*bytes)) }
                .map_err(status)?;
            Ok(0)
        }
        record::IOCTL_STOP if control.InputBufferLength == 0 && control.OutputBufferLength == 0 => {
            // SAFETY: original passive STOP dispatch owns this live file.
            unsafe { runtime.stop_file(file) }.map_err(status)?;
            Ok(0)
        }
        _ => Err(sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_REQUEST),
    }
}

pub(crate) fn status(error: DeviceError) -> sdk::NTSTATUS {
    match error {
        DeviceError::Uninitialized | DeviceError::Admission(_) => {
            sdk::GNUNET_WFP_STATUS_DEVICE_NOT_READY
        }
        DeviceError::Stale => sdk::GNUNET_WFP_STATUS_FILE_CLOSED,
        DeviceError::Busy => sdk::GNUNET_WFP_STATUS_DEVICE_BUSY,
        DeviceError::Capacity => sdk::GNUNET_WFP_STATUS_INSUFFICIENT_RESOURCES,
        DeviceError::Buffer { .. } => sdk::GNUNET_WFP_STATUS_BUFFER_TOO_SMALL,
        DeviceError::Record(_) => sdk::GNUNET_WFP_STATUS_INVALID_PARAMETER,
        DeviceError::State(gnunet_wfp_dns::Error::Capacity) => {
            sdk::GNUNET_WFP_STATUS_INSUFFICIENT_RESOURCES
        }
        DeviceError::State(_) => sdk::GNUNET_WFP_STATUS_NOT_FOUND,
        DeviceError::Native(status) => status,
    }
}
