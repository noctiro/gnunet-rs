//! Original kernel event and wait registration; signals carry no I/O receipt.
use std::{
    ffi::c_void,
    io,
    os::windows::io::{AsRawHandle, OwnedHandle},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU32, Ordering},
    },
    task::{Context, Poll, Waker},
};
use windows_sys::Win32::{
    Foundation::WAIT_OBJECT_0,
    System::Threading::{
        CloseThreadpoolWait, CreateThreadpoolWait, DisassociateCurrentThreadFromCallback,
        PTP_CALLBACK_INSTANCE, PTP_WAIT, SetThreadpoolWait, WaitForThreadpoolWaitCallbacks,
    },
};
const PENDING: u32 = u32::MAX;
#[derive(Default)]
struct WakeState {
    current: Option<Waker>,
    pending: Option<Waker>,
    notifying: bool,
}
struct Shared {
    result: AtomicU32,
    waker: Mutex<WakeState>,
}
impl Shared {
    fn waker(&self) -> MutexGuard<'_, WakeState> {
        match self.waker.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}
#[derive(Clone, Copy)]
enum Phase {
    Idle,
    Armed,
}
/// One owned kernel event and one reusable native wait object, bound to its
/// original registration. Borrowed future cancellation does not remove this owner.
/// Native callbacks retain only wake metadata, never the event/device/payload.
pub struct Wait {
    native: PTP_WAIT,
    event: OwnedHandle,
    shared: Arc<Shared>,
    phase: Phase,
}
impl Wait {
    /// Capture one uniquely owned Windows kernel event and allocate its wait.
    /// The event is never reset or signaled by this owner.
    ///
    /// # Safety
    /// The handle must be a valid Windows kernel event supported by thread-pool
    /// waits, not a mutex or arbitrary file/device handle. No external actor may
    /// close this exact handle while the owner retains it. A duplicated event
    /// handle is accepted without transferring the original handle's ownership.
    #[expect(
        unsafe_code,
        reason = "The caller certifies the owned kernel event; the stable Arc allocation remains live through native cancellation and callback detachment"
    )]
    pub unsafe fn new(event: OwnedHandle) -> io::Result<Self> {
        let shared = Arc::new(Shared {
            result: AtomicU32::new(PENDING),
            waker: Mutex::new(WakeState::default()),
        });
        // SAFETY: stable context, exact callback ABI; no wait is armed yet.
        let native = unsafe {
            CreateThreadpoolWait(
                Some(callback),
                Arc::as_ptr(&shared).cast_mut().cast(),
                std::ptr::null(),
            )
        };
        if native == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            native,
            event,
            shared,
            phase: Phase::Idle,
        })
    }
    /// Whether this original wait is armed. This is not signal or I/O readiness.
    pub const fn is_armed(&self) -> bool {
        matches!(self.phase, Phase::Armed)
    }
    /// Arm once or update the current caller's waker. A returned signal retires
    /// that native wait before another arm; original queued callbacks cannot
    /// write into a later wait generation. Native cancellation creates no signal.
    #[expect(
        unsafe_code,
        reason = "SetThreadpoolWait borrows the still-owned original event and wait object without a native timeout; callback retirement precedes reuse"
    )]
    pub fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let replace = self
            .shared
            .waker()
            .current
            .as_ref()
            .is_none_or(|old| !old.will_wake(cx.waker()));
        if replace {
            let fresh = cx.waker().clone();
            let old = self.shared.waker().current.replace(fresh);
            drop(old);
        }
        if matches!(self.phase, Phase::Idle) {
            self.shared.result.store(PENDING, Ordering::Release);
            self.phase = Phase::Armed;
            // SAFETY: original event/wait stay owned; NULL timeout is indefinite.
            unsafe { SetThreadpoolWait(self.native, self.event.as_raw_handle(), std::ptr::null()) };
        }
        let result = self.shared.result.load(Ordering::Acquire);
        if result == PENDING {
            return Poll::Pending;
        }
        self.cancel();
        Poll::Ready(if result == WAIT_OBJECT_0 {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected native event wait result",
            ))
        })
    }
    /// Stop native callbacks and finish their access to the original wait/event.
    /// The callback detaches before invoking user wake code; that code retains
    /// only an independent Arc of wake metadata. This is no packet/close receipt.
    #[expect(
        unsafe_code,
        reason = "Cancel stops new callbacks and waits for all queued/running callbacks to end or disassociate before the original event/context can be released"
    )]
    pub fn cancel(&mut self) {
        if matches!(self.phase, Phase::Armed) {
            // SAFETY: live unique wait. No Rust mutex is held while joining.
            unsafe {
                SetThreadpoolWait(self.native, std::ptr::null_mut(), std::ptr::null());
                WaitForThreadpoolWaitCallbacks(self.native, 1);
            }
            self.phase = Phase::Idle;
        }
        let discarded = {
            let mut state = self.shared.waker();
            (state.current.take(), state.pending.take())
        };
        drop(discarded);
    }
}
impl Drop for Wait {
    #[expect(
        unsafe_code,
        reason = "Native cancellation/retirement precedes exactly one wait-object close and automatic original event/context release"
    )]
    fn drop(&mut self) {
        self.cancel();
        // SAFETY: no callback can access original wait/event storage now.
        unsafe { CloseThreadpoolWait(self.native) };
    }
}
#[expect(
    unsafe_code,
    reason = "Windows supplies the exact callback ABI and context borrowed from a live Arc; an independent strong reference precedes disassociation and no native owner is used afterwards"
)]
unsafe extern "system" fn callback(
    instance: PTP_CALLBACK_INSTANCE,
    context: *mut c_void,
    _wait: PTP_WAIT,
    result: u32,
) {
    let pointer = context.cast::<Shared>().cast_const();
    // SAFETY: the registration owns the Arc until this callback ends or detaches.
    // Taking our independent reference happens before that retirement boundary.
    let shared = unsafe {
        Arc::increment_strong_count(pointer);
        Arc::from_raw(pointer)
    };
    shared.result.store(result, Ordering::Release);
    let (discarded, notify) = {
        let mut state = shared.waker();
        let current = state.current.take();
        let discarded = current.and_then(|waker| state.pending.replace(waker));
        let notify = !state.notifying && state.pending.is_some();
        if notify {
            state.notifying = true;
        }
        (discarded, notify)
    };
    // SAFETY: exact current callback instance. All later work uses only our
    // independent wake metadata; no event, wait or device owner remains borrowed.
    unsafe { DisassociateCurrentThreadFromCallback(instance) };
    drop(discarded);
    if notify {
        loop {
            let waker = {
                let mut state = shared.waker();
                match state.pending.take() {
                    Some(waker) => Some(waker),
                    None => {
                        state.notifying = false;
                        None
                    }
                }
            };
            let Some(waker) = waker else {
                break;
            };
            // One notifier and one coalesced pending wake per registration.
            // User code runs outside every mutex and the native callback fence.
            let _notification = catch_unwind(AssertUnwindSafe(|| waker.wake()));
        }
    }
}

#[cfg(test)]
mod tests;
