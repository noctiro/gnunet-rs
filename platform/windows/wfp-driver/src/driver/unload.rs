//! Original independent anchor-file custody and one-shot WDM unload handoff.
use super::{Driver, Generation, POOL_TAG, bind_extension, from_device, owner_from_device, retire};
use crate::{
    device::{
        anchor::{Anchor, Error as AnchorError},
        dispatch,
    },
    sdk,
};
use core::{
    cell::UnsafeCell,
    ptr::{self, NonNull},
    sync::atomic::{AtomicI32, AtomicPtr, AtomicU8, Ordering},
};

const NEW: u8 = 0;
const OPENING: u8 = 1;
const HELD: u8 = 2;
const OPEN_FAILED: u8 = 3;
const HANDOFF: u8 = 4;
const CLOSE_FAILED: u8 = 5;
const RELEASED: u8 = 6;

pub(super) struct State {
    anchor: UnsafeCell<Anchor>,
    device: AtomicPtr<sdk::DEVICE_OBJECT>,
    file: AtomicPtr<sdk::FILE_OBJECT>,
    phase: AtomicU8,
    status: AtomicI32,
}

impl State {
    pub(super) const fn new() -> Self {
        Self {
            anchor: UnsafeCell::new(Anchor::new()),
            device: AtomicPtr::new(ptr::null_mut()),
            file: AtomicPtr::new(ptr::null_mut()),
            phase: AtomicU8::new(NEW),
            status: AtomicI32::new(sdk::GNUNET_WFP_STATUS_SUCCESS),
        }
    }

    pub(super) fn matches(&self, device: *mut sdk::DEVICE_OBJECT) -> bool {
        !device.is_null() && self.device.load(Ordering::Acquire) == device
    }

    pub(super) fn released(&self) -> bool {
        self.phase.load(Ordering::Acquire) == RELEASED
    }

    pub(super) unsafe fn prepare(
        &self,
        owner: NonNull<Driver>,
        driver: NonNull<sdk::DRIVER_OBJECT>,
        extension_bytes: u32,
    ) -> Result<(), sdk::NTSTATUS> {
        // SAFETY: original cold preparation has exclusive ownership; no file exists.
        let anchor = unsafe { &mut *self.anchor.get() };
        unsafe { anchor.prepare(driver, extension_bytes) }.map_err(anchor_status)?;
        let device = anchor
            .raw()
            .ok_or(sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE)?;
        // SAFETY: this real anchor allocated the exact common extension layout.
        unsafe { bind_extension(owner, device) }?;
        self.device.store(device.as_ptr(), Ordering::Release);
        Ok(())
    }

    pub(super) unsafe fn open(&self) -> Result<bool, sdk::NTSTATUS> {
        self.phase.store(OPENING, Ordering::Release);
        // SAFETY: entry published its exact identity, extension and dispatch;
        // synchronous reentrant callbacks use atomic fields, never &Anchor.
        let anchor = unsafe { &mut *self.anchor.get() };
        match unsafe { anchor.open() } {
            Ok(()) => {
                if self.file.load(Ordering::Acquire).is_null() {
                    // A handle alone cannot prove this driver's CREATE ran.
                    // Keep its custody, but never advertise a verified pin.
                    self.status.store(
                        sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE,
                        Ordering::Release,
                    );
                    self.phase.store(OPEN_FAILED, Ordering::Release);
                    return Ok(false);
                }
                self.phase.store(HELD, Ordering::Release);
                Ok(true)
            }
            Err(error) => {
                let status = anchor_status(error);
                self.status.store(status, Ordering::Release);
                self.phase.store(OPEN_FAILED, Ordering::Release);
                if anchor.has_handle() {
                    // An uncertain original cannot become failed DriverEntry:
                    // keep loaded maintenance, without arming packet or unload.
                    Ok(false)
                } else {
                    Err(control_status(status))
                }
            }
        }
    }

    pub(super) unsafe fn dispatch(
        &self,
        irp: NonNull<sdk::IRP>,
        stack: &sdk::IO_STACK_LOCATION,
    ) -> sdk::NTSTATUS {
        // SAFETY: original WDM parameters remain live through synchronous completion.
        let result = unsafe { self.handle(irp, stack) };
        unsafe { dispatch::complete_irp(irp, result) }
    }

    unsafe fn handle(
        &self,
        irp: NonNull<sdk::IRP>,
        stack: &sdk::IO_STACK_LOCATION,
    ) -> Result<usize, sdk::NTSTATUS> {
        let file = NonNull::new(stack.FileObject).ok_or(sdk::GNUNET_WFP_STATUS_FILE_CLOSED)?;
        match u32::from(stack.MajorFunction) {
            sdk::IRP_MJ_CREATE => {
                // Only the original kernel open creates this independent file.
                // Its eventual cleanup/close may run on a user-request thread;
                // those authenticate the original FILE_OBJECT instead.
                // SAFETY: this original CREATE owns its requestor tag.
                if unsafe { (*irp.as_ptr()).RequestorMode } != sdk::GNUNET_WFP_KERNEL_MODE as _ {
                    return Err(sdk::GNUNET_WFP_STATUS_ACCESS_DENIED);
                }
                if self.phase.load(Ordering::Acquire) != OPENING {
                    return Err(sdk::GNUNET_WFP_STATUS_DEVICE_NOT_READY);
                }
                // SAFETY: native CREATE owns the original file and selected union.
                let valid = unsafe {
                    (*file.as_ptr()).FileName.Length == 0
                        && (*file.as_ptr()).RelatedFileObject.is_null()
                        && stack.Parameters.Create.Options
                            & sdk::GNUNET_WFP_FILE_DIRECTORY_FILE as u32
                            == 0
                };
                if !valid {
                    return Err(sdk::GNUNET_WFP_STATUS_INVALID_PARAMETER);
                }
                self.file
                    .compare_exchange(
                        ptr::null_mut(),
                        file.as_ptr(),
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .map_err(|_| sdk::GNUNET_WFP_STATUS_DEVICE_BUSY)?;
                Ok(0)
            }
            sdk::IRP_MJ_CLEANUP if self.file.load(Ordering::Acquire) == file.as_ptr() => Ok(0),
            sdk::IRP_MJ_CLOSE => {
                self.file
                    .compare_exchange(
                        file.as_ptr(),
                        ptr::null_mut(),
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .map_err(|_| sdk::GNUNET_WFP_STATUS_FILE_CLOSED)?;
                Ok(0)
            }
            _ => Err(sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_REQUEST),
        }
    }
}

/// Inspect an uncertain original anchor startup result without native operations.
/// A nonzero result belongs in the typed maintenance payload, not a successful
/// NTSTATUS-shaped transport refusal.
///
/// # Safety
/// Supply the original packet device while its I/O-manager lifetime is retained.
/// No pointer supplied by user mode may stand in for that original object.
#[must_use]
pub(super) unsafe fn startup_failure(device: NonNull<sdk::DEVICE_OBJECT>) -> Option<sdk::NTSTATUS> {
    // SAFETY: caller retains this exact original packet device.
    let owner = unsafe { from_device(device.as_ptr()) }?;
    (owner.unload.phase.load(Ordering::Acquire) == OPEN_FAILED)
        .then(|| owner.unload.status.load(Ordering::Acquire))
}

/// Release the original kernel anchor while a genuine maintenance IRP still
/// supplies the I/O manager's file/request lifetime. No native close is retried.
///
/// # Safety
/// Use the exact protected maintenance file's current passive control IRP.
/// Keep this IRP uncompleted and its original FILE_OBJECT valid through return;
/// callers must not substitute a pointer reference for this real active request.
/// Do not call from a callback or with an arena lock or packet dispatch loan held.
///
/// # Errors
/// Preserves original namespace/anchor refusals. Busy native/file custody keeps
/// the anchor held. A successful handoff limits future maintenance opens to
/// terminal observation. Actual FILE_OBJECT CLOSE and executable unload are
/// independent.
pub(super) unsafe fn handoff(
    device: NonNull<sdk::DEVICE_OBJECT>,
    irp: NonNull<sdk::IRP>,
    file: NonNull<sdk::FILE_OBJECT>,
) -> Result<(), sdk::NTSTATUS> {
    // SAFETY: the WDK query reads current IRQL without taking a resource.
    if u32::from(unsafe { sdk::gnunet_wfp_current_irql() }) != sdk::PASSIVE_LEVEL {
        return Err(sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE);
    }
    // SAFETY: caller holds the original packet and maintenance objects.
    let owner = unsafe { from_device(device.as_ptr()) }
        .ok_or(sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE)?;
    // SAFETY: I/O manager retains the actual active stack and original file.
    let stack = unsafe { sdk::gnunet_wfp_current_irp_stack(irp.as_ptr()).as_ref() }
        .ok_or(sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_REQUEST)?;
    if stack.FileObject != file.as_ptr()
        || !owner
            .maintenance
            .device()
            .is_some_and(|original| original.as_ptr() == stack.DeviceObject)
        || u32::from(stack.MajorFunction) != sdk::IRP_MJ_DEVICE_CONTROL
        || !owner.maintenance.owns_active_request(file)
    {
        return Err(sdk::GNUNET_WFP_STATUS_ACCESS_DENIED);
    }
    match owner
        .unload
        .phase
        .compare_exchange(HELD, HANDOFF, Ordering::AcqRel, Ordering::Acquire)
    {
        Ok(_) => {}
        Err(RELEASED) => return Ok(()),
        Err(OPEN_FAILED | CLOSE_FAILED) => {
            return Err(control_status(owner.unload.status.load(Ordering::Acquire)));
        }
        Err(_) => return Err(sdk::GNUNET_WFP_STATUS_DEVICE_BUSY),
    }
    // SAFETY: original passive maintenance control retains all owners through
    // genuine retirement; this is a real result, never a deadline inference.
    let counts = match unsafe { retire::terminal_counts(device) } {
        Ok(counts) => counts,
        Err(status) => {
            owner.unload.phase.store(HELD, Ordering::Release);
            return Err(status);
        }
    };
    if !counts.can_replace() || !owner.stop_requested.load(Ordering::Acquire) {
        owner.unload.phase.store(HELD, Ordering::Release);
        return Err(sdk::GNUNET_WFP_STATUS_DEVICE_BUSY);
    }
    owner.access.stop();
    // SAFETY: permanent stop excludes generation replacement and START.
    // This passive IRP is distinct from the original notification context.
    if let Err(status) = unsafe { owner.bfe.cancel() } {
        owner.unload.phase.store(HELD, Ordering::Release);
        return Err(status);
    }
    if owner.access.outstanding() != 0 {
        owner.unload.phase.store(HELD, Ordering::Release);
        return Err(sdk::GNUNET_WFP_STATUS_DEVICE_BUSY);
    }
    // All ordinary failures happen before releasing the actual anchor. A
    // canceled client can reopen the protected native maintenance name if DOS
    // unpublication succeeded but the original close failed.
    // SAFETY: stopped packet admission and the live maintenance IRP retain state.
    if let Err(error) = unsafe { (&mut *owner.object.get()).unpublish() } {
        owner.unload.phase.store(HELD, Ordering::Release);
        return Err(super::object_status(error));
    }
    // SAFETY: current exclusive maintenance request owns its original namespace.
    if let Err(status) = unsafe { owner.maintenance.unpublish() } {
        owner.unload.phase.store(HELD, Ordering::Release);
        return Err(status);
    }
    // SAFETY: actual native retirement and active maintenance FILE/IRP prove the
    // handoff preconditions. Reentrant anchor CLOSE uses no mutable owner view.
    match unsafe { (&mut *owner.unload.anchor.get()).close_after_retirement() } {
        Ok(true) => {
            owner.packet_admitted.store(false, Ordering::Release);
            owner.unload.phase.store(RELEASED, Ordering::Release);
            Ok(())
        }
        Ok(false) => {
            let status = sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE;
            owner.unload.status.store(status, Ordering::Release);
            owner.unload.phase.store(CLOSE_FAILED, Ordering::Release);
            Err(status)
        }
        Err(error) => {
            let status = anchor_status(error);
            owner.unload.status.store(status, Ordering::Release);
            owner.unload.phase.store(CLOSE_FAILED, Ordering::Release);
            Err(control_status(status))
        }
    }
}

pub(super) unsafe fn discard_cold(owner: &Driver) {
    // SAFETY: failed entry never admitted a client and acquired no anchor file.
    let anchor = unsafe { &mut *owner.unload.anchor.get() };
    assert!(
        !anchor.has_handle(),
        "cold rollback cannot abandon an original anchor"
    );
    let _ = unsafe { owner.maintenance.discard_unenabled() };
    let _ = unsafe { (&mut *owner.object.get()).discard_unenabled() };
    assert!(
        unsafe { anchor.delete() }.is_ok(),
        "original cold anchor deletion failed"
    );
}

// Verify the exact original WDK ABI instead of hand-declaring an unload export.
const _: sdk::PDRIVER_UNLOAD = Some(entry);

pub(super) unsafe extern "C" fn entry(driver: *mut sdk::DRIVER_OBJECT) {
    let driver = NonNull::new(driver).expect("I/O manager supplied no original driver");
    // SAFETY: the I/O manager retains the original driver and its device list.
    let device = unsafe { (*driver.as_ptr()).DeviceObject };
    let owner = unsafe { owner_from_device(device) }.expect("original unload owner is absent");
    assert_eq!(
        owner.unload.phase.load(Ordering::Acquire),
        RELEASED,
        "unload preceded original handoff"
    );
    assert_eq!(
        owner.access.outstanding(),
        0,
        "packet generation still borrowed"
    );
    // SAFETY: no control request or notification remains in real WDM unload.
    let generation = unsafe { owner.generation() };
    // SAFETY: no control request or native callback exists in the actual WDM
    // unload environment; this is a pure terminal-state inspection.
    assert!(
        unsafe { &*generation.retirement.get() }.native_retired(),
        "native retirement is incomplete"
    );
    assert!(
        owner.maintenance.file_closed(),
        "original maintenance file still exists"
    );
    assert!(
        owner.unload.file.load(Ordering::Acquire).is_null(),
        "original anchor CLOSE is outstanding"
    );
    // SAFETY: terminal handoff ended all original anchor-owner mutation.
    assert!(
        unsafe { &*owner.unload.anchor.get() }.closed(),
        "original anchor handle is not closed"
    );
    // SAFETY: genuine WDM unload follows final CLOSE; inspect only local state.
    let snapshot =
        unsafe { generation.runtime().retirement_snapshot() }.expect("original runtime is absent");
    assert!(
        snapshot.flows == 0
            && snapshot.native_injections == 0
            && snapshot.queued_captures == 0
            && snapshot.capture_copies == 0
            && snapshot.completion_records == 0
            && !snapshot.file_owned
            && !snapshot.upstream_custody,
        "original runtime custody remains"
    );
    // Every fallible native/network operation finished before anchor release.
    // These original deletions can fail only if the proven lifecycle contract
    // was violated; a VOID unload cannot return an ordinary cleanup refusal.
    // SAFETY: original namespace and all file/native references have retired.
    assert!(
        unsafe { owner.maintenance.delete() }.is_ok(),
        "original maintenance device deletion failed"
    );
    assert!(
        unsafe { (&mut *owner.object.get()).delete() }.is_ok(),
        "original packet device deletion failed"
    );
    assert!(
        unsafe { (&mut *owner.unload.anchor.get()).delete() }.is_ok(),
        "original anchor device deletion failed"
    );
    let generation = NonNull::new(owner.generation.swap(ptr::null_mut(), Ordering::AcqRel))
        .expect("original generation is absent");
    // SAFETY: the original generation has no file, stable access or native borrower.
    unsafe { Generation::free(generation) };
    let original = ptr::from_ref(owner).cast_mut();
    // SAFETY: Windows guarantees no file/IRP/entry remains, native owners have
    // retired, and all original devices were deleted. Free the exact pool once.
    unsafe { sdk::ExFreePoolWithTag(original.cast(), POOL_TAG) };
}

fn anchor_status(error: AnchorError) -> sdk::NTSTATUS {
    match error {
        AnchorError::Native { status, .. } if status != 0 => status,
        AnchorError::MissingHandle => sdk::GNUNET_WFP_STATUS_INVALID_HANDLE,
        _ => sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE,
    }
}

fn control_status(status: sdk::NTSTATUS) -> sdk::NTSTATUS {
    if status < 0 {
        status
    } else {
        sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE
    }
}
