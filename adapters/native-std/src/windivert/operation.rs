//! Completion-owned kernel loans; dropping a waiter requests cancellation only.
use super::{CapturedAddress, Device, abi::Address};
use std::{
    cell::UnsafeCell,
    ffi::c_void,
    fmt, io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker},
};
use windows_sys::Win32::{
    Foundation::{ERROR_IO_PENDING, ERROR_NOT_FOUND, WAIT_OBJECT_0},
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
const TAKEN: u64 = u64::MAX - 1;
#[derive(Clone, Copy)]
enum Kind {
    Receive,
    Send,
}
struct Memory {
    overlapped: OVERLAPPED,
    packet: zeroize::Zeroizing<Vec<u8>>,
    address: Address,
    address_bytes: u32,
    transferred: u32,
}
struct Loan {
    device: Arc<Device>,
    event: OwnedHandle,
    memory: UnsafeCell<Memory>,
    kind: Kind,
    result: AtomicU64,
    waker: Mutex<Option<Waker>>,
}
#[expect(
    unsafe_code,
    reason = "The kernel alone accesses the stable UnsafeCell while I/O is pending; the one completion callback publishes retirement before the unique Request owner may access its memory"
)]
// SAFETY: native completion and the result release/acquire fence separate kernel
// writes from Rust access; the private callback owns an independent strong Arc.
unsafe impl Send for Loan {}
#[expect(
    unsafe_code,
    reason = "Memory is accessed only before native submission or after completion by the unique Request owner; synchronized wake/result fields are the only concurrent Rust accesses"
)]
// SAFETY: no shared Rust memory reference is exposed during the kernel loan.
unsafe impl Sync for Loan {}
impl Drop for Loan {
    fn drop(&mut self) {
        // Final Drop is possible only before submission or after the callback
        // retired the loan. The event and provider stay owned through this point.
        if self.result.load(Ordering::Acquire) == PENDING {
            match self.kind {
                Kind::Receive => &self.device.receive,
                Kind::Send => &self.device.send,
            }
            .store(false, Ordering::Release);
        }
    }
}
/// Native injection completion violated the original whole-packet extent.
/// Exposure is unknown; the operation must never be retried as a suffix.
#[derive(Debug)]
#[non_exhaustive]
pub struct InjectionLengthError {
    /// Immutable original packet length.
    pub expected: usize,
    /// Actual native completion extent.
    pub observed: usize,
}
impl fmt::Display for InjectionLengthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "native injection extent {} differs from original {}",
            self.observed, self.expected
        )
    }
}
impl std::error::Error for InjectionLengthError {}
/// A completed original native operation. Receive data owns its allocation.
#[derive(Debug)]
#[non_exhaustive]
pub enum Completion {
    /// Complete captured packet and its original native metadata.
    Received {
        /// Exact raw IP packet.
        packet: Vec<u8>,
        /// Metadata bound to the original session, not a reused handle number.
        address: CapturedAddress,
    },
    /// Complete original packet accepted by native injection.
    Sent {
        /// Whole injected IP extent; no suffix is ever retried.
        bytes: usize,
    },
}
/// One unique receive/send owner. A canceled wait preserves this owner; Drop
/// requests cancellation while the native callback retains buffers to completion.
/// A session admits at most one pending kernel operation in each direction.
pub struct Request {
    loan: Arc<Loan>,
}
impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WinDivertRequest")
            .field(
                "pending",
                &(self.loan.result.load(Ordering::Acquire) == PENDING),
            )
            .finish_non_exhaustive()
    }
}
impl Request {
    pub(super) fn receive(device: Arc<Device>, bytes: usize) -> io::Result<Self> {
        if !(1..=65575).contains(&bytes) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut packet = Vec::new();
        packet.try_reserve_exact(bytes).map_err(io::Error::other)?;
        packet.resize(bytes, 0);
        Self::submit(
            device,
            zeroize::Zeroizing::new(packet),
            Address::default(),
            Kind::Receive,
        )
    }
    pub(super) fn send(
        device: Arc<Device>,
        packet: zeroize::Zeroizing<Vec<u8>>,
        address: Address,
    ) -> io::Result<Self> {
        if packet.is_empty() || packet.len() > 65575 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Self::submit(device, packet, address, Kind::Send)
    }
    #[expect(
        unsafe_code,
        reason = "Private initialized SDK records are pinned by a strong callback Arc before native submission, and all pointers remain live until kernel completion"
    )]
    fn submit(
        device: Arc<Device>,
        packet: zeroize::Zeroizing<Vec<u8>>,
        address: Address,
        kind: Kind,
    ) -> io::Result<Self> {
        // Prepare every fallible native resource before lending any memory.
        // SAFETY: null attributes/name; manual-reset private event starts unset.
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful constructor returned this unique event.
        let event = unsafe { OwnedHandle::from_raw_handle(event) };
        // SAFETY: OVERLAPPED is an initialized SDK scalar/pointer record.
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        overlapped.hEvent = event.as_raw_handle();
        let credit = match kind {
            Kind::Receive => &device.receive,
            Kind::Send => &device.send,
        };
        if credit.swap(true, Ordering::AcqRel) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let loan = Arc::new(Loan {
            device,
            event,
            memory: UnsafeCell::new(Memory {
                overlapped,
                packet,
                address,
                address_bytes: size_of::<Address>() as u32,
                transferred: 0,
            }),
            kind,
            result: AtomicU64::new(PENDING),
            waker: Mutex::new(None),
        });
        let raw = Arc::into_raw(Arc::clone(&loan));
        // SAFETY: the independent context Arc is live before submission; no wait
        // is armed until the native operation has actually been submitted.
        let wait = unsafe {
            CreateThreadpoolWait(Some(complete), raw.cast_mut().cast(), std::ptr::null())
        };
        if wait == 0 {
            let error = io::Error::last_os_error();
            // SAFETY: no callback registration or I/O exists; reclaim its count.
            drop(unsafe { Arc::from_raw(raw) });
            return Err(error);
        }
        let result = loan.device.call(|handle| {
            // SAFETY: native submission has not happened; no callback is armed.
            let memory = unsafe { &mut *loan.memory.get() };
            let accepted = match kind {
                Kind::Receive => {
                    // SAFETY: exact stable packet/address/count/OVERLAPPED loans.
                    unsafe {
                        (loan.device.api.recv)(
                            handle,
                            memory.packet.as_mut_ptr().cast(),
                            memory.packet.len() as u32,
                            &mut memory.transferred,
                            0,
                            &mut memory.address,
                            &mut memory.address_bytes,
                            &mut memory.overlapped,
                        )
                    }
                }
                Kind::Send => {
                    // SAFETY: immutable packet/address and stable output loans.
                    unsafe {
                        (loan.device.api.send)(
                            handle,
                            memory.packet.as_ptr().cast(),
                            memory.packet.len() as u32,
                            &mut memory.transferred,
                            0,
                            &memory.address,
                            memory.address_bytes,
                            &mut memory.overlapped,
                        )
                    }
                }
            };
            if accepted == 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
                    return Err(error);
                }
            }
            Ok(())
        });
        if let Err(error) = result {
            // SAFETY: non-pending failure means there is no kernel loan, and the
            // unarmed wait cannot invoke its callback. Release both native/count.
            unsafe {
                CloseThreadpoolWait(wait);
                drop(Arc::from_raw(raw));
            }
            return Err(error);
        }
        // SAFETY: the live one-shot registration owns its context count, event,
        // buffers and device until complete() closes the wait. Already-signaled
        // synchronous completions follow this same path without a lost wake.
        unsafe {
            SetThreadpoolWait(wait, loan.event.as_raw_handle(), std::ptr::null());
        }
        Ok(Self { loan })
    }
    /// Poll the original I/O once. Ready consumes its data/result; later polls
    /// fail instead of replaying a packet. Registration races recheck the result.
    ///
    /// # Panics
    /// Panics if the shared capture interface-observation mutex was poisoned.
    #[expect(
        unsafe_code,
        reason = "The acquire-loaded completed result proves the kernel loan retired; the unique Request owner alone may take the buffer, and the callback never accesses it after publishing"
    )]
    pub fn poll_complete(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Completion>> {
        let mut result = self.loan.result.load(Ordering::Acquire);
        if result == PENDING {
            {
                let mut wake = self
                    .loan
                    .waker
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if wake.as_ref().is_none_or(|old| !old.will_wake(cx.waker())) {
                    *wake = Some(cx.waker().clone());
                }
            }
            result = self.loan.result.load(Ordering::Acquire);
            if result == PENDING {
                return Poll::Pending;
            }
        }
        if result == TAKEN {
            return Poll::Ready(Err(io::Error::other(
                "WinDivert original result already consumed",
            )));
        }
        self.loan.result.store(TAKEN, Ordering::Release);
        if result >> 32 != 0 {
            return Poll::Ready(Err(io::Error::from_raw_os_error(
                (result >> 32) as u32 as i32,
            )));
        }
        // SAFETY: kernel completion precedes publication, and callback access to
        // Memory has ended. No other public Request can share or take this loan.
        let memory = unsafe { &mut *self.loan.memory.get() };
        let bytes = result as u32 as usize;
        if bytes > memory.packet.len() && matches!(self.loan.kind, Kind::Receive) {
            return Poll::Ready(Err(io::Error::other(
                "WinDivert completion exceeded original packet storage",
            )));
        }
        match self.loan.kind {
            Kind::Receive => {
                if memory.address_bytes != size_of::<Address>() as u32
                    || memory.address.flags & 0xffff != 0
                {
                    return Poll::Ready(Err(io::Error::other(
                        "WinDivert capture returned non-NETWORK packet metadata",
                    )));
                }
                let address = CapturedAddress::received(memory.address, &self.loan.device);
                memory.packet.truncate(bytes);
                Poll::Ready(Ok(Completion::Received {
                    packet: std::mem::take(&mut *memory.packet),
                    address,
                }))
            }
            Kind::Send if bytes == memory.packet.len() => {
                Poll::Ready(Ok(Completion::Sent { bytes }))
            }
            Kind::Send => Poll::Ready(Err(io::Error::other(InjectionLengthError {
                expected: memory.packet.len(),
                observed: bytes,
            }))),
        }
    }
    /// Request cancellation on the original handle/OVERLAPPED. Success or a
    /// not-found race does not establish completion; poll_complete still owns it.
    #[expect(
        unsafe_code,
        reason = "CancelIoEx borrows a raw pointer to the same stable original OVERLAPPED under the device close guard, without creating a Rust reference during kernel access"
    )]
    pub fn request_cancel(&mut self) -> io::Result<()> {
        if self.loan.result.load(Ordering::Acquire) != PENDING {
            return Ok(());
        }
        self.loan.device.call(|handle| {
            // SAFETY: stable loan allocation and original event/handle remain live.
            let overlapped =
                unsafe { std::ptr::addr_of_mut!((*self.loan.memory.get()).overlapped) };
            // SAFETY: exact original request; no handle/PID reconstruction occurs.
            if unsafe { CancelIoEx(handle, overlapped) } == 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(ERROR_NOT_FOUND as i32) {
                    return Err(error);
                }
            }
            Ok(())
        })
    }
}
impl Drop for Request {
    fn drop(&mut self) {
        let _canceled = self.request_cancel();
    }
}
#[expect(
    unsafe_code,
    reason = "The one-shot registration owns its raw Arc until the callback consumes it; the private event signals native completion before buffer access or release"
)]
unsafe extern "system" fn complete(
    instance: PTP_CALLBACK_INSTANCE,
    context: *mut c_void,
    wait: PTP_WAIT,
    reason: u32,
) {
    // SAFETY: exactly the registration's independent strong reference; no other
    // path reclaims it after a submitted operation is armed.
    let loan = unsafe { Arc::from_raw(context.cast::<Loan>()) };
    if reason != WAIT_OBJECT_0 {
        let event = loan.event.as_raw_handle();
        // SAFETY: restore the same registration-owned count before rearming; no
        // buffer/result has been published and native completion is unproven.
        let _context = Arc::into_raw(loan);
        // SAFETY: the original wait/context/event remain owned and unretired.
        unsafe {
            SetThreadpoolWait(wait, event, std::ptr::null());
        }
        return;
    }
    let outcome = loan.device.call(|handle| {
        let mut bytes = 0;
        // SAFETY: the private event was signaled by this completed original I/O.
        let overlapped = unsafe { std::ptr::addr_of_mut!((*loan.memory.get()).overlapped) };
        // SAFETY: original live handle and stable completed OVERLAPPED; no wait.
        if unsafe { GetOverlappedResult(handle, overlapped, &mut bytes, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(bytes)
    });
    let result = match outcome {
        Ok(bytes) => u64::from(bytes),
        Err(error) => {
            u64::from(
                error
                    .raw_os_error()
                    .filter(|code| *code != 0)
                    .unwrap_or(995) as u32,
            ) << 32
        }
    };
    // SAFETY: no wait-object state is used after close. Independent Arc ownership
    // permits native disassociation before arbitrary caller Wake code runs.
    unsafe {
        DisassociateCurrentThreadFromCallback(instance);
        CloseThreadpoolWait(wait);
    }
    match loan.kind {
        Kind::Receive => &loan.device.receive,
        Kind::Send => &loan.device.send,
    }
    .store(false, Ordering::Release);
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
