//! Completion-owned writes to a qualified original child stdin pipe.
use super::InputWriteHandle;
use std::{
    cell::UnsafeCell,
    ffi::c_void,
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker},
};
use windows_sys::Win32::{
    Foundation::{ERROR_IO_PENDING, ERROR_NOT_FOUND, WAIT_OBJECT_0},
    Storage::FileSystem::WriteFile,
    System::{
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
        Threading::{
            CloseThreadpoolWait, CreateEventW, CreateThreadpoolWait,
            DisassociateCurrentThreadFromCallback, PTP_CALLBACK_INSTANCE, PTP_WAIT,
            SetThreadpoolWait,
        },
    },
};
const PENDING: u64 = u64::MAX;
struct Memory {
    overlapped: OVERLAPPED,
    bytes: zeroize::Zeroizing<Vec<u8>>,
}
struct Loan {
    pipe: Arc<OwnedHandle>,
    event: OwnedHandle,
    memory: UnsafeCell<Memory>,
    result: AtomicU64,
    waker: Mutex<Option<Waker>>,
}
#[expect(
    unsafe_code,
    reason = "The kernel alone borrows stable memory until the completion callback publishes retirement; no payload reference crosses threads"
)]
// SAFETY: only the unique writer accesses Memory before submission or after the
// acquire fence. The callback owns a separate Arc until GetOverlappedResult.
unsafe impl Send for Loan {}
#[expect(
    unsafe_code,
    reason = "Only synchronized result/wake metadata has concurrent Rust access; the kernel loan is inaccessible through the public API"
)]
// SAFETY: no shared reference to Memory is exposed during a pending operation.
unsafe impl Sync for Loan {}

/// Capacity-one overlapped writer. A completed count comes from the original
/// GetOverlappedResult, not local queue acceptance, flush, or child readiness.
/// Dropping requests cancellation; the native callback retains the pipe, event,
/// zeroizing payload and OVERLAPPED until actual kernel completion.
pub struct InputWriter {
    pipe: Arc<OwnedHandle>,
    pending: Option<Arc<Loan>>,
    requested: usize,
}
impl InputWriter {
    /// Consume a qualified parent handle. No I/O is submitted by construction.
    pub fn new(pipe: InputWriteHandle) -> Self {
        Self {
            pipe: Arc::new(pipe.into_handle()),
            pending: None,
            requested: 0,
        }
    }
    /// Whether the original operation still requires a completion observation.
    pub fn pending(&self) -> bool {
        self.pending.is_some()
    }
    /// Copy and submit at most 64 KiB. Another begin is refused until the original
    /// result is consumed. Every fallible allocation precedes native submission.
    #[expect(
        unsafe_code,
        reason = "Initialized event and stable callback-owned memory remain live through the exact original overlapped write"
    )]
    pub fn begin(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.pending.is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if bytes.is_empty() || bytes.len() > 65536 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut copy = zeroize::Zeroizing::new(Vec::new());
        copy.try_reserve_exact(bytes.len())
            .map_err(io::Error::other)?;
        copy.extend_from_slice(bytes);
        // SAFETY: private manual-reset event, initially unset.
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fresh original event, adopted once.
        let event = unsafe { OwnedHandle::from_raw_handle(event) };
        // SAFETY: zero initializes every SDK scalar and pointer field.
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        overlapped.hEvent = event.as_raw_handle();
        let loan = Arc::new(Loan {
            pipe: Arc::clone(&self.pipe),
            event,
            memory: UnsafeCell::new(Memory {
                overlapped,
                bytes: copy,
            }),
            result: AtomicU64::new(PENDING),
            waker: Mutex::new(None),
        });
        let raw = Arc::into_raw(Arc::clone(&loan));
        // SAFETY: independent context count exists before registration; wait is unarmed.
        let wait = unsafe {
            CreateThreadpoolWait(Some(complete), raw.cast_mut().cast(), std::ptr::null())
        };
        if wait == 0 {
            let error = io::Error::last_os_error();
            // SAFETY: no native registration or I/O can access this context.
            drop(unsafe { Arc::from_raw(raw) });
            return Err(error);
        }
        // SAFETY: unique initialized memory; no I/O or armed callback exists yet.
        let memory = unsafe { &mut *loan.memory.get() };
        // SAFETY: stable immutable payload and writable original OVERLAPPED;
        // completion byte count is obtained later, not through a stack pointer.
        let accepted = unsafe {
            WriteFile(
                loan.pipe.as_raw_handle(),
                memory.bytes.as_ptr(),
                memory.bytes.len() as u32,
                std::ptr::null_mut(),
                &mut memory.overlapped,
            )
        };
        if accepted == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
                // SAFETY: non-pending failure lent no memory; callback is unarmed.
                unsafe {
                    CloseThreadpoolWait(wait);
                    drop(Arc::from_raw(raw));
                }
                return Err(error);
            }
        }
        // SAFETY: callback's independent Arc owns all kernel loans. A synchronous
        // completion signals the same event before this arm and cannot be lost.
        unsafe {
            SetThreadpoolWait(wait, loan.event.as_raw_handle(), std::ptr::null());
        }
        self.pending = Some(loan);
        self.requested = bytes.len();
        Ok(())
    }
    /// Observe the original native result once. Cancellation of this poll leaves
    /// that request intact and never resubmits its bytes.
    pub fn poll_complete(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let Some(loan) = self.pending.as_ref() else {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        };
        let mut result = loan.result.load(Ordering::Acquire);
        if result == PENDING {
            {
                let mut wake = loan
                    .waker
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if wake.as_ref().is_none_or(|old| !old.will_wake(cx.waker())) {
                    *wake = Some(cx.waker().clone());
                }
            }
            result = loan.result.load(Ordering::Acquire);
            if result == PENDING {
                return Poll::Pending;
            }
        }
        self.pending = None;
        Poll::Ready(if result >> 32 == 0 {
            let count = result as u32 as usize;
            if count > self.requested {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "native write completion exceeds the original request",
                ))
            } else {
                Ok(count)
            }
        } else {
            Err(io::Error::from_raw_os_error((result >> 32) as u32 as i32))
        })
    }
    /// Request cancellation of the exact original write, preserving its result.
    /// Success or ERROR_NOT_FOUND establishes neither zero exposure nor closure.
    #[expect(
        unsafe_code,
        reason = "CancelIoEx borrows the same stable OVERLAPPED and original pipe retained by the completion callback"
    )]
    pub fn request_cancel(&mut self) -> io::Result<()> {
        let Some(loan) = &self.pending else {
            return Ok(());
        };
        if loan.result.load(Ordering::Acquire) != PENDING {
            return Ok(());
        }
        // SAFETY: raw pointer construction creates no aliasing reference while borrowed.
        let original = unsafe { std::ptr::addr_of_mut!((*loan.memory.get()).overlapped) };
        // SAFETY: original live handle and original stable request only.
        if unsafe { CancelIoEx(loan.pipe.as_raw_handle(), original) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_NOT_FOUND as i32) {
                return Err(error);
            }
        }
        Ok(())
    }
}
impl Drop for InputWriter {
    fn drop(&mut self) {
        let _requested = self.request_cancel();
    }
}
#[expect(
    unsafe_code,
    reason = "One-shot callback owns its independent context count and publishes only after the original kernel loan completes"
)]
unsafe extern "system" fn complete(
    instance: PTP_CALLBACK_INSTANCE,
    context: *mut c_void,
    wait: PTP_WAIT,
    reason: u32,
) {
    // SAFETY: registration's single strong reference is consumed exactly once.
    let loan = unsafe { Arc::from_raw(context.cast::<Loan>()) };
    if reason != WAIT_OBJECT_0 {
        let event = loan.event.as_raw_handle();
        let _context = Arc::into_raw(loan);
        // SAFETY: same unretired context/event, no completion has been published.
        unsafe {
            SetThreadpoolWait(wait, event, std::ptr::null());
        }
        return;
    }
    let mut count = 0;
    // SAFETY: original private event has signaled; no Rust memory reference is made.
    let original = unsafe { std::ptr::addr_of_mut!((*loan.memory.get()).overlapped) };
    // SAFETY: still-owned original handle/request; nonblocking completion query.
    let result = if unsafe {
        GetOverlappedResult(loan.pipe.as_raw_handle(), original, &mut count, 0)
    } == 0
    {
        u64::from(
            io::Error::last_os_error()
                .raw_os_error()
                .filter(|n| *n != 0)
                .unwrap_or(995) as u32,
        ) << 32
    } else {
        u64::from(count)
    };
    // SAFETY: no wait-object use follows retirement; only owned metadata remains.
    unsafe {
        DisassociateCurrentThreadFromCallback(instance);
        CloseThreadpoolWait(wait);
    }
    loan.result.store(result, Ordering::Release);
    let wake = loan
        .waker
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some(wake) = wake {
        let _notified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| wake.wake()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Read,
        task::Wake,
        time::{Duration, Instant},
    };
    struct WakeThread(std::thread::Thread);
    impl Wake for WakeThread {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    fn completion(writer: &mut InputWriter) -> io::Result<usize> {
        let hard = Instant::now() + Duration::from_secs(5);
        let wake = Waker::from(Arc::new(WakeThread(std::thread::current())));
        let mut context = Context::from_waker(&wake);
        loop {
            if let Poll::Ready(result) = writer.poll_complete(&mut context) {
                return result;
            }
            if Instant::now() >= hard {
                return Err(io::ErrorKind::TimedOut.into());
            }
            std::thread::park_timeout(Duration::from_millis(20));
        }
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions compare exact original private-pipe bytes and one-at-a-time admission independently of callback scheduling"
    )]
    fn completion_releases_only_the_original_written_prefix() -> io::Result<()> {
        let (pipe, mut child) = super::super::input_pair()?;
        let payload: Vec<_> = (0..12000).map(|n| (n % 251) as u8).collect();
        let expected = payload.clone();
        let reader = std::thread::spawn(move || -> io::Result<()> {
            let mut received = vec![0; expected.len()];
            child.read_exact(&mut received)?;
            assert_eq!(received, expected);
            Ok(())
        });
        let mut writer = InputWriter::new(pipe);
        let mut at = 0;
        while at < payload.len() {
            writer.begin(&payload[at..])?;
            assert_eq!(
                writer.begin(b"replacement").err().map(|e| e.kind()),
                Some(io::ErrorKind::WouldBlock)
            );
            let count = completion(&mut writer)?;
            assert!((1..=payload.len() - at).contains(&count));
            at += count;
        }
        assert!(!writer.pending());
        drop(writer);
        reader
            .join()
            .map_err(|_| io::Error::other("pipe reader panicked"))??;
        Ok(())
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Cancellation and reader closure may race native completion, but neither consumes or replaces its original result"
    )]
    fn cancellation_preserves_one_actual_completion() -> io::Result<()> {
        let (pipe, reader) = super::super::input_pair()?;
        let mut writer = InputWriter::new(pipe);
        writer.begin(&[7; 65536])?;
        writer.request_cancel()?;
        assert!(writer.pending());
        drop(reader);
        match completion(&mut writer) {
            Ok(count) => assert!(count <= 65536),
            Err(error) => assert!(matches!(error.raw_os_error(), Some(995 | 109 | 232))),
        }
        assert!(!writer.pending());
        let wake = Waker::noop();
        assert!(matches!(
            writer.poll_complete(&mut Context::from_waker(wake)),
            Poll::Ready(Err(_))
        ));
        Ok(())
    }
}
