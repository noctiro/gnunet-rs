//! Original-process threadpool notification with independently retained callback state.
use super::launch::{Process, ProcessObject, status};
use std::{
    ffi::c_void,
    fmt, io,
    os::windows::io::AsRawHandle,
    ptr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker},
};
use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
use windows_sys::Win32::System::Threading::{
    CloseThreadpoolWait, CreateThreadpoolWait, DisassociateCurrentThreadFromCallback,
    PTP_CALLBACK_INSTANCE, PTP_WAIT, SetThreadpoolWait, WaitForThreadpoolWaitCallbacks,
};
struct CallbackState {
    result: AtomicU64,
    waker: Mutex<Option<Waker>>,
}
/// One kernel exit-notification registration for the original process object.
/// Polling never waits for process termination and never creates a per-child
/// worker or timer. Keep this owner across canceled waiting futures.
///
/// Drop cancels the native wait and synchronizes only the callback's initial Arc
/// acquisition. The callback disassociates before locking/waking caller state,
/// so teardown does not wait for the child or arbitrary caller wake code. Its
/// independent Arc retains notification state until that code returns. It owns
/// no process handle after native wait cancellation.
/// This single-waiter registration is movable between threads, not shareable.
pub struct ProcessWait {
    native: PTP_WAIT,
    raw: *const CallbackState,
    state: Arc<CallbackState>,
    process: Arc<ProcessObject>,
}
impl fmt::Debug for ProcessWait {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProcessWait")
            .field("id", &self.process.id)
            .finish_non_exhaustive()
    }
}
#[expect(
    unsafe_code,
    reason = "A threadpool wait can be canceled from another thread; callback state uses Arc, atomics and a mutex, and the original process handle is owned across moves"
)]
// SAFETY: native cancellation is thread-independent; this movable owner retains
// its process handle and shares notification state through synchronized owners.
unsafe impl Send for ProcessWait {}

#[expect(
    unsafe_code,
    reason = "Windows invokes this callback only while its registration's raw Arc is guarded; an independent Arc is acquired before native disassociation permits the registration to be destroyed"
)]
unsafe extern "system" fn complete(
    instance: PTP_CALLBACK_INSTANCE,
    context: *mut c_void,
    _wait: PTP_WAIT,
    result: u32,
) {
    let pointer = context.cast::<CallbackState>();
    // SAFETY: native cancellation waits until this callback has acquired its own
    // strong reference and disassociated, or cancels it before it starts.
    unsafe {
        Arc::increment_strong_count(pointer);
    }
    // SAFETY: this consumes exactly the independent count just acquired.
    let state = unsafe { Arc::from_raw(pointer) };
    // SAFETY: instance is this live callback instance. No wait-object state is
    // accessed afterwards; notification state remains independently owned.
    unsafe {
        DisassociateCurrentThreadFromCallback(instance);
    }
    state.result.store(u64::from(result), Ordering::Release);
    let wake = state
        .waker
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some(waker) = wake {
        // User-provided Wake code must never unwind over the system ABI.
        let _wake = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| waker.wake()));
    }
}
impl ProcessWait {
    /// Register this actual process handle for an infinite kernel wait. Native
    /// registration failure returns its Win32 error and leaves the Process owned
    /// by the caller. A notification is only a hint; poll rechecks real exit state.
    #[expect(
        unsafe_code,
        reason = "CreateThreadpoolWait receives one retained raw Arc and callback; its input process handle stays owned until cancellation/callback synchronization has finished"
    )]
    pub fn new(process: &Process) -> io::Result<Self> {
        let state = Arc::new(CallbackState {
            result: AtomicU64::new(u64::MAX),
            waker: Mutex::new(None),
        });
        let raw = Arc::into_raw(Arc::clone(&state));
        // SAFETY: raw owns an independent strong reference until cancellation;
        // no custom callback environment or transient pointer is borrowed.
        let native =
            unsafe { CreateThreadpoolWait(Some(complete), raw.cast_mut().cast(), ptr::null()) };
        if native == 0 {
            let error = io::Error::last_os_error();
            // SAFETY: registration failed, so no callback can consume this context.
            drop(unsafe { Arc::from_raw(raw) });
            return Err(error);
        }
        // SAFETY: process handle and wait remain owned together; null timeout
        // means no timer callback, not an independently sampled host deadline.
        unsafe {
            SetThreadpoolWait(native, process.0.handle.as_raw_handle(), ptr::null());
        }
        Ok(Self {
            native,
            raw,
            state,
            process: Arc::clone(&process.0),
        })
    }
    /// Poll an actual unsigned exit code. Registering/waking does not consume
    /// another child's wait authority. Repeated Ready polls observe the same
    /// original object; registry owners decide when to publish a consuming receipt.
    pub fn poll_exit(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<u32>> {
        if let Some(code) = status(&self.process)? {
            return Poll::Ready(Ok(code));
        }
        {
            let mut waker = self
                .state
                .waker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if waker.as_ref().is_none_or(|old| !old.will_wake(cx.waker())) {
                *waker = Some(cx.waker().clone());
            }
        }
        // Recheck after installing the current waker, including the exit-before-
        // registration race; no notification can be converted into a lost wake.
        if let Some(code) = status(&self.process)? {
            return Poll::Ready(Ok(code));
        }
        let result = self.state.result.load(Ordering::Acquire);
        if result == u64::MAX {
            return Poll::Pending;
        }
        if result == u64::from(WAIT_OBJECT_0) {
            if let Some(code) = status(&self.process)? {
                return Poll::Ready(Ok(code));
            }
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "process notification preceded its actual signaled state",
            )));
        }
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected native process notification",
        )))
    }
}
impl Drop for ProcessWait {
    #[expect(
        unsafe_code,
        reason = "Cancellation prevents new callbacks and joins only the pre-disassociation Arc acquisition; the raw registration reference is released after that boundary, independently of any caller wake code"
    )]
    fn drop(&mut self) {
        // SAFETY: this owner is the only canceller; a running callback first
        // acquires its own Arc, then disassociates before any user wake/lock.
        unsafe {
            SetThreadpoolWait(self.native, ptr::null_mut(), ptr::null());
            WaitForThreadpoolWaitCallbacks(self.native, 1);
            CloseThreadpoolWait(self.native);
            drop(Arc::from_raw(self.raw));
        }
    }
}
