//! Cold WDM control-device preparation and authenticated native startup.
//!
//! The image's native entry calls this module. An independent kernel file pins
//! the driver through fallible native retirement. The original maintenance
//! request releases it after cleanup. The fixed unload routine then destroys
//! the retired devices and their storage.
use crate::{
    POOL_ALIGNMENT,
    device::{dispatch, object::Object},
    sdk,
};
use core::{
    cell::UnsafeCell,
    mem::{align_of, size_of},
    num::NonZeroU64,
    pin::Pin,
    ptr::{self, NonNull},
    slice,
    sync::atomic::{AtomicBool, AtomicPtr, Ordering},
};
use gnunet_wfp_dns::device as record;

mod bfe;
mod generation;
mod maintenance;
mod native;
mod recovery;
pub mod retire;
mod unload;
use generation::Generation;

const COLD: u8 = 0;
const STARTING: u8 = 1;
const PREPARED: u8 = 2;
const FAILED: u8 = 3;
const RETIRING: u8 = 4;
const POOL_TAG: u32 = u32::from_le_bytes(*b"GDRV");
// Give the kernel queue and scheduling time beyond the service request bound.
const CAPTURE_LIFETIME_TICKS: NonZeroU64 = match NonZeroU64::new(60 * 10_000_000) {
    Some(value) => value,
    None => unreachable!(),
};

#[repr(C)]
struct Extension {
    original: AtomicPtr<Driver>,
}

struct Driver {
    generation: AtomicPtr<Generation>,
    access: retire::Dispatches,
    bfe: bfe::State,
    object: UnsafeCell<Object>,
    maintenance: maintenance::Maintenance,
    unload: unload::State,
    packet_admitted: AtomicBool,
    retirement_busy: AtomicBool,
    stop_requested: AtomicBool,
    device: AtomicPtr<sdk::DEVICE_OBJECT>,
}

// The exact WDK alias verifies the native entry calling convention and parameters.
const _: sdk::PDRIVER_INITIALIZE = Some(entry);

const _: () = {
    // ExAllocatePool2 guarantees the original WDK's sub-page alignment.
    assert!(align_of::<Driver>() <= POOL_ALIGNMENT);
    assert!(size_of::<Extension>() <= u32::MAX as usize);
};

impl Driver {
    const fn new() -> Self {
        Self {
            generation: AtomicPtr::new(ptr::null_mut()),
            access: retire::Dispatches::new(),
            bfe: bfe::State::new(),
            object: UnsafeCell::new(Object::new()),
            maintenance: maintenance::Maintenance::new(),
            unload: unload::State::new(),
            packet_admitted: AtomicBool::new(false),
            retirement_busy: AtomicBool::new(false),
            stop_requested: AtomicBool::new(false),
            device: AtomicPtr::new(ptr::null_mut()),
        }
    }

    /// Borrow the current pinned packet generation.
    ///
    /// The original access lease or passive lifecycle control must cover all
    /// uses. Native callbacks retain the exact generation through their own
    /// separately joined registration and injection lifetimes.
    unsafe fn generation(&'static self) -> &'static Generation {
        let original = NonNull::new(self.generation.load(Ordering::Acquire))
            .expect("published driver has no packet generation");
        // SAFETY: the original caller retains the pointer through all uses.
        unsafe { original.as_ref() }
    }
}

/// Prepare the original protected WDM device without starting WFP capture.
///
/// The first authenticated passive START performs fallible native preparation.
/// Native startup failure therefore leaves a loaded owner that retains its
/// original resources, rather than returning a failed `DriverEntry` with live
/// callbacks. The fixed unload routine is installed only after the independent
/// anchor file has actually opened, before either client endpoint is enabled.
/// An uncertain open keeps maintenance available but never arms packet startup
/// or an unload routine without a proven original file pin.
///
/// # Safety
/// Supply the original WDM `DriverEntry` parameters at `PASSIVE_LEVEL`, with no
/// previous device for this driver. The integration must retain this module's
/// code and original device/state through all registered native callbacks.
/// A production export still requires native qualification of the complete
/// I/O manager and WFP lifetime contract.
pub unsafe extern "C" fn entry(
    driver: *mut sdk::DRIVER_OBJECT,
    _registry: *mut sdk::UNICODE_STRING,
) -> sdk::NTSTATUS {
    // SAFETY: the WDK wrapper only reads the current kernel IRQL.
    if u32::from(unsafe { sdk::gnunet_wfp_current_irql() }) != sdk::PASSIVE_LEVEL {
        return sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE;
    }
    let Some(driver) = NonNull::new(driver) else {
        return sdk::GNUNET_WFP_STATUS_INVALID_PARAMETER;
    };
    // SAFETY: original entry owns this live driver object's initialization.
    if !unsafe { (*driver.as_ptr()).DeviceObject }.is_null() {
        return sdk::GNUNET_WFP_STATUS_DEVICE_BUSY;
    }
    // SAFETY: allocation uses an original nonzero tag, supported nonpaged flags
    // and a nonzero, non-over-aligned complete Rust allocation size.
    let allocation = unsafe {
        sdk::ExAllocatePool2(
            sdk::GNUNET_WFP_POOL_FLAG_NON_PAGED as _,
            size_of::<Driver>() as _,
            POOL_TAG,
        )
    };
    let Some(owner) = NonNull::new(allocation.cast::<Driver>()) else {
        return sdk::GNUNET_WFP_STATUS_INSUFFICIENT_RESOURCES;
    };
    // SAFETY: this small stable owner has exclusive cold allocation custody.
    // The larger packet runtime has its own pinned nonpaged allocation.
    unsafe { owner.as_ptr().write(Driver::new()) };
    // SAFETY: exclusive cold preparation occurs before any dispatch publication.
    let prepared = unsafe { prepare_device(owner, driver) };
    if let Err(status) = prepared {
        // SAFETY: no WFP startup or client admission occurs on entry failure.
        // A possibly acquired anchor is handled as loaded maintenance-only
        // state instead of entering this cold rollback branch.
        let original = unsafe { &*owner.as_ptr() };
        // SAFETY: disabled clients and no anchor file permit exact cold deletion.
        unsafe { unload::discard_cold(original) };
        if let Some(generation) = NonNull::new(original.generation.load(Ordering::Relaxed)) {
            // SAFETY: failed driver entry never exposed this cold generation.
            unsafe { Generation::free(generation) };
        }
        // SAFETY: original clients and notification paths never opened.
        unsafe { sdk::ExFreePoolWithTag(owner.as_ptr().cast(), POOL_TAG) };
        return status;
    }
    sdk::GNUNET_WFP_STATUS_SUCCESS
}

unsafe fn prepare_device(
    owner: NonNull<Driver>,
    driver: NonNull<sdk::DRIVER_OBJECT>,
) -> Result<(), sdk::NTSTATUS> {
    // SAFETY: original DriverEntry is passive; the packet state has no users.
    let generation = unsafe { Generation::allocate() }?;
    // SAFETY: this stable original allocation is exclusively prepared.
    let original = unsafe { owner.as_ref() };
    original
        .generation
        .store(generation.as_ptr(), Ordering::Release);
    // SAFETY: DriverEntry exclusively owns the native dispatch table. No unload
    // callback is advertised before a real independent kernel file exists.
    unsafe {
        (*driver.as_ptr()).MajorFunction.fill(Some(io_dispatch));
        (*driver.as_ptr()).DriverUnload = None;
    }
    // SAFETY: this original native owner is unpublished and exclusive to entry.
    let object = unsafe { &mut *original.object.get() };
    // SAFETY: real original driver object, checked passive context and extension size.
    let extension_bytes = u32::try_from(size_of::<Extension>())
        .map_err(|_| sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE)?;
    unsafe { object.prepare(driver, extension_bytes) }.map_err(object_status)?;
    let device = object
        .raw()
        .ok_or(sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE)?;
    // SAFETY: the I/O manager allocated this original common extension, and
    // client admission remains disabled throughout cold initialization.
    unsafe { bind_extension(owner, device) }?;
    original.device.store(device.as_ptr(), Ordering::Release);
    // SAFETY: independent maintenance uses the same original extension layout.
    unsafe { original.maintenance.prepare(driver, extension_bytes) }?;
    let maintenance = original
        .maintenance
        .device()
        .ok_or(sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE)?;
    // SAFETY: both extension storage and its owning driver are still unpublished.
    unsafe { bind_extension(owner, maintenance) }?;
    // SAFETY: original anchor identity and extension precede its reentrant open.
    unsafe { original.unload.prepare(owner, driver, extension_bytes) }?;
    // Stage both fallible links before either client can create a file.
    // SAFETY: original entry exclusively owns these disabled namespaces.
    unsafe { object.prepare_link() }.map_err(object_status)?;
    unsafe { original.maintenance.prepare_link() }?;
    // This is the last fallible step. A retained uncertain result must remain
    // loaded for maintenance; a successful real open permits fixed unload.
    // SAFETY: dispatch identities and all original extension state are ready.
    let opened = unsafe { original.unload.open() }?;
    if opened {
        // SAFETY: original real anchor file prevents unload while native owners
        // can exist. This pointer is set once here and never toggled afterward.
        unsafe { (*driver.as_ptr()).DriverUnload = Some(unload::entry) };
        original.packet_admitted.store(true, Ordering::Release);
        // SAFETY: staged link, prepared dispatch, actual anchor and fixed unload.
        unsafe { object.enable() };
    }
    // SAFETY: all fallible entry work ended; maintenance may now inspect a
    // successful or uncertain original anchor without a later entry failure.
    unsafe { original.maintenance.enable() };
    Ok(())
}

unsafe fn bind_extension(
    owner: NonNull<Driver>,
    device: NonNull<sdk::DEVICE_OBJECT>,
) -> Result<(), sdk::NTSTATUS> {
    // SAFETY: each original device allocated this exact common extension size.
    let extension = NonNull::new(unsafe { (*device.as_ptr()).DeviceExtension }.cast::<Extension>())
        .ok_or(sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE)?;
    // SAFETY: exclusive cold initialization precedes any create admission.
    unsafe {
        extension.as_ptr().write(Extension {
            original: AtomicPtr::new(owner.as_ptr()),
        });
    }
    Ok(())
}

fn object_status(error: crate::device::object::Error) -> sdk::NTSTATUS {
    match error {
        crate::device::object::Error::Native { status, .. } => status,
        _ => sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE,
    }
}

unsafe extern "C" fn io_dispatch(
    device: *mut sdk::DEVICE_OBJECT,
    irp: *mut sdk::IRP,
) -> sdk::NTSTATUS {
    let Some(irp) = NonNull::new(irp) else {
        return sdk::GNUNET_WFP_STATUS_INVALID_PARAMETER;
    };
    // SAFETY: WDM supplies this driver's original device and active IRP.
    let Some(owner) = (unsafe { owner_from_device(device) }) else {
        // SAFETY: this dispatch owns the original uncompleted IRP.
        return unsafe { refuse(irp, sdk::GNUNET_WFP_STATUS_DEVICE_NOT_READY) };
    };
    // SAFETY: the I/O manager retains the original active stack until completion.
    let Some(stack) = (unsafe { sdk::gnunet_wfp_current_irp_stack(irp.as_ptr()).as_ref() }) else {
        // SAFETY: dispatch owns this original refusal and completion.
        return unsafe { refuse(irp, sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_REQUEST) };
    };
    if owner.unload.matches(device) {
        // SAFETY: exact original anchor; only its kernel lifetime operations
        // are completed, without borrowing the reentrant mutable anchor owner.
        return unsafe { owner.unload.dispatch(irp, stack) };
    }
    if owner
        .maintenance
        .device()
        .is_some_and(|original| original.as_ptr() == device)
    {
        let Some(packet) = NonNull::new(owner.device.load(Ordering::Acquire)) else {
            // SAFETY: original dispatch retains unique completion custody.
            return unsafe { refuse(irp, sdk::GNUNET_WFP_STATUS_DEVICE_NOT_READY) };
        };
        // SAFETY: exact independent protected maintenance file and original IRP.
        return unsafe {
            owner
                .maintenance
                .dispatch(&owner.unload, packet, irp, stack)
        };
    }
    if owner.device.load(Ordering::Acquire) != device {
        // SAFETY: this dispatch owns the original outstanding IRP.
        return unsafe { refuse(irp, sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_REQUEST) };
    }
    let major = u32::from(stack.MajorFunction);
    // CLOSE has no packet-generation state. CLEANUP retains access until it
    // releases the original file and any detached upstream handle owners.
    if major == sdk::IRP_MJ_CLOSE {
        // SAFETY: the I/O manager still owns the file and supplied this IRP.
        return unsafe { dispatch::complete_irp(irp, Ok(0)) };
    }
    // SAFETY: this is an original packet IRP and active stack.
    let access = unsafe { owner.packet_access(stack, major) };
    let _access = match access {
        Ok(lease) => lease,
        Err(status) => {
            // SAFETY: original dispatch retains unique completion custody.
            return unsafe { refuse(irp, status) };
        }
    };
    // SAFETY: the stable generation-access lease outlives this dispatch.
    let generation = unsafe { owner.generation() };
    if major == sdk::IRP_MJ_CLEANUP {
        // SAFETY: this passive original cleanup accesses only its exact file.
        return unsafe { dispatch::dispatch(generation.runtime(), irp, None) };
    }
    let Some(_dispatch) = generation.dispatches.enter() else {
        // SAFETY: no native packet owner was borrowed; this IRP is ours.
        return unsafe { refuse(irp, sdk::GNUNET_WFP_STATUS_DEVICE_NOT_READY) };
    };
    if major == sdk::IRP_MJ_DEVICE_CONTROL
        // SAFETY: the major function selects this original stack union member.
        && unsafe { stack.Parameters.DeviceIoControl.IoControlCode } == record::IOCTL_START
    {
        // SAFETY: original protected device and METHOD_BUFFERED START request.
        let (file, upstreams) = match unsafe { start_preflight(irp, stack) } {
            Ok(start) => start,
            Err(status) => {
                // SAFETY: dispatch retains unique completion custody.
                return unsafe { refuse(irp, status) };
            }
        };
        // Serialize the full passive START transaction with administrative
        // stop, recovery and BFE subscription retirement.
        let control = match retire::control_owner(owner) {
            Ok(control) => control,
            Err(status) => {
                // SAFETY: dispatch retains unique completion custody.
                return unsafe { refuse(irp, status) };
            }
        };
        if owner.stop_requested.load(Ordering::Acquire) {
            drop(control);
            // SAFETY: this dispatch still owns the uncompleted IRP.
            return unsafe { refuse(irp, sdk::GNUNET_WFP_STATUS_DEVICE_NOT_READY) };
        }
        // SAFETY: owner_from_device checked this original nonnull packet device.
        let packet = unsafe { NonNull::new_unchecked(device) };
        // SAFETY: the original dispatch pins the file, runtime and device.
        // start_file retains the original sockets before native preparation.
        let result = unsafe {
            generation.runtime().start_file(irp, file, &upstreams, || {
                generation
                    .start(owner, packet)
                    .map_err(retire::refusal_status)
            })
        };
        drop(control);
        // SAFETY: this START has no deferred completion path.
        return unsafe {
            dispatch::complete_irp(irp, result.map(|()| 0).map_err(dispatch::status))
        };
    }
    // SAFETY: WDM retains the original device allocation through this IRP.
    let runtime = unsafe { generation.runtime() };
    if generation.phase.load(Ordering::Acquire) == PREPARED {
        // SAFETY: PREPARED publishes completed initialization; no retirement or
        // reinitialization may mutate these owners while native users exist.
        let native = unsafe { &*generation.native.get() };
        // SAFETY: original transport slots are immutable during prepared dispatch;
        // retirement closes and joins this outer reservation before mutation.
        if let Some(handles) = unsafe { &*native.transport.get() }.handles() {
            // SAFETY: the original nonpaged pool was initialized before PREPARED.
            let pool = unsafe { Pin::new_unchecked(&*native.pool.get()) };
            // SAFETY: this original buffered IRP and every native owner remain
            // live, including completion after dispatch and file cleanup.
            return unsafe {
                dispatch::dispatch(
                    runtime,
                    irp,
                    Some(dispatch::Injections {
                        pool,
                        handles: &handles,
                    }),
                )
            };
        }
    }
    // SAFETY: cold dispatch permits real file/event/control operations, while
    // WRITE cannot claim an injection without original prepared native owners.
    unsafe { dispatch::dispatch(runtime, irp, None) }
}

unsafe fn from_device(device: *mut sdk::DEVICE_OBJECT) -> Option<&'static Driver> {
    // SAFETY: original device and common extension are retained by the caller.
    let owner = unsafe { owner_from_device(device) }?;
    (owner.device.load(Ordering::Acquire) == device).then_some(owner)
}

unsafe fn owner_from_device(device: *mut sdk::DEVICE_OBJECT) -> Option<&'static Driver> {
    let device = NonNull::new(device)?;
    // SAFETY: WDM supplies this driver's original still-live DEVICE_OBJECT.
    let extension =
        NonNull::new(unsafe { (*device.as_ptr()).DeviceExtension }.cast::<Extension>())?;
    // SAFETY: original entry initialized this extension before device publication.
    let owner = NonNull::new(
        unsafe { extension.as_ref() }
            .original
            .load(Ordering::Acquire),
    )?;
    // SAFETY: original Driver storage remains nonpaged and live through all
    // dispatch and native callbacks; fixed unload frees it only after handoff
    // and the I/O manager's actual final file/IRP cutoff.
    let owner = unsafe { owner.as_ref() };
    (owner.device.load(Ordering::Acquire) == device.as_ptr()
        || owner.unload.matches(device.as_ptr())
        || owner
            .maintenance
            .device()
            .is_some_and(|original| original == device))
    .then_some(owner)
}

unsafe fn start_preflight(
    irp: NonNull<sdk::IRP>,
    stack: &sdk::IO_STACK_LOCATION,
) -> Result<(NonNull<sdk::FILE_OBJECT>, record::Upstreams), sdk::NTSTATUS> {
    // SAFETY: the original IRP permits the native current-IRQL query.
    if u32::from(unsafe { sdk::gnunet_wfp_current_irql() }) != sdk::PASSIVE_LEVEL {
        return Err(sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE);
    }
    // SAFETY: caller checked the DEVICE_CONTROL major function and START code.
    let control = unsafe { stack.Parameters.DeviceIoControl };
    let bytes = control.InputBufferLength as usize;
    if control.OutputBufferLength != 0
        || bytes == 0
        || bytes > record::MAX_UPSTREAM_SOCKETS * record::UPSTREAM_BYTES
        || !bytes.is_multiple_of(record::UPSTREAM_BYTES)
    {
        return Err(sdk::GNUNET_WFP_STATUS_INVALID_PARAMETER);
    }
    // SAFETY: this exact START code selects METHOD_BUFFERED; I/O manager owns
    // the complete input extent, and retains it through this synchronous check.
    let input = NonNull::new(unsafe { (*irp.as_ptr()).AssociatedIrp.SystemBuffer }.cast::<u8>())
        .ok_or(sdk::GNUNET_WFP_STATUS_INVALID_PARAMETER)?;
    // SAFETY: the native I/O manager's original input buffer covers bytes.
    let input = unsafe { slice::from_raw_parts(input.as_ptr(), bytes) };
    let upstreams =
        record::Upstreams::decode(input).map_err(|_| sdk::GNUNET_WFP_STATUS_INVALID_PARAMETER)?;
    let file = NonNull::new(stack.FileObject).ok_or(sdk::GNUNET_WFP_STATUS_FILE_CLOSED)?;
    Ok((file, upstreams))
}

unsafe fn refuse(irp: NonNull<sdk::IRP>, status: sdk::NTSTATUS) -> sdk::NTSTATUS {
    // SAFETY: original dispatch owns the IRP and completes it synchronously once.
    unsafe {
        (*irp.as_ptr()).IoStatus.__bindgen_anon_1.Status = status;
        (*irp.as_ptr()).IoStatus.Information = 0;
        sdk::gnunet_wfp_complete_request(irp.as_ptr(), 0);
    }
    status
}
