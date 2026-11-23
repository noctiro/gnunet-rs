//! One pinned packet runtime and its exact native callback owners.
use super::{COLD, Driver, FAILED, PREPARED, RETIRING, STARTING, bfe, native::Native, retire};
use crate::{POOL_ALIGNMENT, callbacks, runtime::Runtime, sdk};
use core::{
    cell::UnsafeCell,
    mem::{MaybeUninit, align_of, size_of, transmute},
    pin::Pin,
    ptr::{self, NonNull},
    sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU64, Ordering},
};

const POOL_TAG: u32 = u32::from_le_bytes(*b"GNPK");
type PacketRuntime = Runtime<{ callbacks::FLOWS }, { callbacks::REQUESTS }>;

pub(super) struct Generation {
    runtime: PacketRuntime,
    pub(super) native: UnsafeCell<Native>,
    pub(super) callback: UnsafeCell<MaybeUninit<callbacks::State>>,
    pub(super) callback_initialized: AtomicBool,
    pub(super) callback_published: AtomicBool,
    pub(super) dispatches: retire::Dispatches,
    pub(super) retirement: UnsafeCell<retire::Retirement>,
    pub(super) phase: AtomicU8,
    last_status: AtomicI32,
    pub(super) epoch: AtomicU64,
}

const _: () = assert!(align_of::<Generation>() <= POOL_ALIGNMENT);

#[repr(align(16))]
struct Template([MaybeUninit<u8>; size_of::<Generation>()]);

// SAFETY: preserves the exact cold value including uninitialized padding.
// No pointer into the state exists until its native allocation is initialized.
static COLD_TEMPLATE: Template = Template(unsafe {
    transmute::<Generation, [MaybeUninit<u8>; size_of::<Generation>()]>(Generation::new())
});

impl Generation {
    const fn new() -> Self {
        Self {
            runtime: PacketRuntime::new(),
            native: UnsafeCell::new(Native::new()),
            callback: UnsafeCell::new(MaybeUninit::uninit()),
            callback_initialized: AtomicBool::new(false),
            callback_published: AtomicBool::new(false),
            dispatches: retire::Dispatches::new(),
            retirement: UnsafeCell::new(retire::Retirement::new()),
            phase: AtomicU8::new(COLD),
            last_status: AtomicI32::new(sdk::GNUNET_WFP_STATUS_SUCCESS),
            epoch: AtomicU64::new(0),
        }
    }

    pub(super) unsafe fn allocate() -> Result<NonNull<Self>, sdk::NTSTATUS> {
        // SAFETY: requests a nonzero, naturally aligned nonpaged allocation.
        let raw = unsafe {
            sdk::ExAllocatePool2(
                sdk::GNUNET_WFP_POOL_FLAG_NON_PAGED as _,
                size_of::<Self>() as _,
                POOL_TAG,
            )
        };
        let owner = NonNull::new(raw.cast::<Self>())
            .ok_or(sdk::GNUNET_WFP_STATUS_INSUFFICIENT_RESOURCES)?;
        // SAFETY: disjoint cold bytes initialize the exact original allocation
        // without placing the large fixed packet runtime on the kernel stack.
        unsafe {
            ptr::copy_nonoverlapping(
                COLD_TEMPLATE.0.as_ptr(),
                owner.as_ptr().cast::<MaybeUninit<u8>>(),
                size_of::<Self>(),
            );
        }
        // SAFETY: this original runtime is exclusively pinned before publication.
        let mut runtime = unsafe { Pin::new_unchecked(&mut (*owner.as_ptr()).runtime) };
        // SAFETY: the caller supplies the original passive initialization.
        let ready = unsafe {
            runtime
                .as_mut()
                .initialize()
                .and_then(|()| runtime.as_ref().admission().activate())
        };
        if ready.is_err() {
            // SAFETY: this generation has no file or external native owners.
            unsafe { Self::free(owner) };
            return Err(sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE);
        }
        Ok(owner)
    }

    /// Free a never-published or completely retired generation.
    pub(super) unsafe fn free(owner: NonNull<Self>) {
        // SAFETY: caller ended all original Rust and SDK borrows and debts.
        unsafe {
            ptr::drop_in_place(owner.as_ptr());
            sdk::ExFreePoolWithTag(owner.as_ptr().cast(), POOL_TAG);
        }
    }

    pub(super) unsafe fn runtime(&self) -> Pin<&PacketRuntime> {
        // SAFETY: the original nonpaged allocation never moves while borrowed.
        unsafe { Pin::new_unchecked(&self.runtime) }
    }

    pub(super) unsafe fn callback(&self) -> Option<Pin<&callbacks::State>> {
        if !self.callback_initialized.load(Ordering::Acquire) {
            return None;
        }
        // SAFETY: startup writes it once and publishes after initialization.
        Some(unsafe { Pin::new_unchecked((*self.callback.get()).assume_init_ref()) })
    }

    pub(super) fn needs_recovery(&self, epoch: u64) -> bool {
        match self.phase.load(Ordering::Acquire) {
            PREPARED => {
                self.epoch.load(Ordering::Acquire) != epoch
                    // SAFETY: a published generation stays pinned for this borrow.
                    || !unsafe { self.callback() }.is_some_and(|state| state.policy_intact())
            }
            // A new authenticated file may retry only after the original file
            // closes and recovery retires every original native owner. The
            // same file still receives last_status from start().
            FAILED | RETIRING => true,
            _ => false,
        }
    }

    pub(super) unsafe fn start(
        &'static self,
        owner: &'static Driver,
        device: NonNull<sdk::DEVICE_OBJECT>,
    ) -> Result<(), sdk::NTSTATUS> {
        match self
            .phase
            .compare_exchange(COLD, STARTING, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {}
            Err(PREPARED) => {
                return if !self.needs_recovery(owner.bfe.epoch()) {
                    Ok(())
                } else {
                    Err(sdk::GNUNET_WFP_STATUS_DEVICE_NOT_READY)
                };
            }
            Err(FAILED) => return Err(self.last_status.load(Ordering::Acquire)),
            Err(_) => return Err(sdk::GNUNET_WFP_STATUS_DEVICE_BUSY),
        }
        // SAFETY: STARTING excludes other startup, retirement and cancellation.
        if let Err(status) = unsafe { owner.bfe.subscribe(owner) } {
            self.phase.store(COLD, Ordering::Release);
            return Err(status);
        }
        let epoch = owner.bfe.epoch();
        self.epoch.store(epoch, Ordering::Release);
        if epoch == u64::MAX || !bfe::running() {
            self.phase.store(COLD, Ordering::Release);
            return Err(sdk::GNUNET_WFP_STATUS_DEVICE_NOT_READY);
        }
        // SAFETY: STARTING is the only writer of the original packet owners.
        if let Err(status) = unsafe { (&mut *self.native.get()).prepare(self, device) } {
            if status == sdk::GNUNET_WFP_STATUS_FWP_SESSION_ABORTED
                || owner.bfe.epoch() != epoch
                || !bfe::running()
            {
                return self.obsolete(status);
            }
            return self.fail(status);
        }
        // SAFETY: native registration and the complete filter commit succeeded.
        // The new file has yet to arm its socket exclusions.
        unsafe { self.runtime().publish_policy(epoch) };
        // Recheck after publication. A loss callback racing this update either
        // invalidates this epoch here or revokes this exact generation itself.
        // SAFETY: the original initialized callback remains under our lease.
        let intact = unsafe { self.callback() }.is_some_and(|state| state.policy_intact());
        if !bfe::running() || owner.bfe.epoch() != epoch || !intact {
            // SAFETY: this bounded update revokes the original file's authority.
            unsafe { self.runtime().revoke_policy(None) };
            return self.obsolete(sdk::GNUNET_WFP_STATUS_DEVICE_NOT_READY);
        }
        self.phase.store(PREPARED, Ordering::Release);
        Ok(())
    }

    fn fail(&self, status: sdk::NTSTATUS) -> Result<(), sdk::NTSTATUS> {
        self.last_status.store(status, Ordering::Release);
        self.phase.store(FAILED, Ordering::Release);
        Err(status)
    }

    fn obsolete(&self, status: sdk::NTSTATUS) -> Result<(), sdk::NTSTATUS> {
        let _ = self.fail(status);
        Err(sdk::GNUNET_WFP_STATUS_DEVICE_NOT_READY)
    }
}
