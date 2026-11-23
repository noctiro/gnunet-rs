//! One original overlapped client pipe before reactor registration.

use super::{Endpoint, is_peer_closed};
use std::{
    cell::UnsafeCell,
    ffi::c_void,
    io,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    ptr,
    sync::{Arc, Mutex, TryLockError},
    time::Instant,
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_IO_INCOMPLETE, ERROR_IO_PENDING, INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0,
        WAIT_TIMEOUT,
    },
    Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ, FILE_WRITE_DATA, OPEN_EXISTING,
        ReadFile, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    },
    System::{
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
        Threading::{
            CloseThreadpoolWait, CreateEventW, CreateThreadpoolWait,
            DisassociateCurrentThreadFromCallback, PTP_CALLBACK_INSTANCE, PTP_WAIT, ResetEvent,
            SetThreadpoolWait, WaitForSingleObject,
        },
    },
};

/// A freshly connected local pipe before any asynchronous runtime owns it.
/// The caller validates the startup protocol and the peer separately.
#[derive(Debug)]
pub struct StartupPipe(Mutex<Option<Arc<OwnedHandle>>>);

impl StartupPipe {
    /// Open the exact local byte pipe with duplex access and identification QoS.
    /// The handle remains overlapped, noninheritable and unregistered.
    ///
    /// # Errors
    /// Preserves the native open failure for the original endpoint.
    #[expect(
        unsafe_code,
        reason = "CreateFileW borrows a terminated local name and returns one original handle"
    )]
    pub fn connect(endpoint: &Endpoint) -> io::Result<Self> {
        let name: Vec<u16> = endpoint.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: name is NUL-terminated and the other inputs are scalar or null.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                FILE_GENERIC_READ | FILE_WRITE_DATA,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: CreateFileW returned a fresh handle with exactly one owner.
        let pipe = unsafe { OwnedHandle::from_raw_handle(handle) };
        Ok(Self(Mutex::new(Some(Arc::new(pipe)))))
    }

    /// Read exactly one caller-provided byte extent before the original deadline.
    /// The caller's buffer changes only after the full read completes. A failed
    /// read retires this pipe. A late native completion retains its own storage
    /// and the original handle until the kernel ends the operation.
    ///
    /// # Errors
    /// Returns `WouldBlock` for concurrent reads, `UnexpectedEof` for peer
    /// closure, `TimedOut` at the deadline, or the original native failure.
    pub fn read_exact(&self, bytes: &mut [u8], deadline: Instant) -> io::Result<()> {
        let mut access = self.0.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => io::ErrorKind::WouldBlock.into(),
            TryLockError::Poisoned(_) => io::Error::other("startup pipe read owner failed"),
        })?;
        let pipe = access.take().ok_or(io::ErrorKind::NotConnected)?;
        if !bytes.is_empty() {
            check_deadline(deadline)?;
            Read::new(Arc::clone(&pipe), bytes.len())?.complete(bytes, deadline)?;
        }
        *access = Some(pipe);
        Ok(())
    }

    /// Transfer the original settled handle for reactor registration.
    ///
    /// # Errors
    /// Refuses transfer after a failed read or while native retirement is owed.
    pub fn into_handle(self) -> io::Result<OwnedHandle> {
        let pipe = self
            .0
            .into_inner()
            .map_err(|_| io::Error::other("startup pipe read owner failed"))?
            .ok_or(io::ErrorKind::NotConnected)?;
        Arc::try_unwrap(pipe)
            .map_err(|_| io::Error::other("startup pipe still has a native reader"))
    }
}

struct Loan {
    pipe: Arc<OwnedHandle>,
    event: OwnedHandle,
    overlapped: UnsafeCell<OVERLAPPED>,
    bytes: UnsafeCell<Vec<u8>>,
}

#[expect(
    unsafe_code,
    reason = "Only the original reader touches native storage before I/O, and a detached wait owns it through completion"
)]
// SAFETY: the payload and OVERLAPPED become inaccessible to Rust while Windows owns them.
unsafe impl Send for Loan {}
#[expect(
    unsafe_code,
    reason = "The reader and the completion callback access the original native state in separate phases"
)]
// SAFETY: only the original reader uses the storage before the one-way handoff to the callback.
unsafe impl Sync for Loan {}

struct Read {
    original: Arc<Loan>,
    retirement: Option<Retirement>,
    pending: bool,
}

struct Retirement {
    wait: PTP_WAIT,
    context: *const Loan,
}

impl Read {
    #[expect(
        unsafe_code,
        reason = "Create a private event and an unarmed native wait for one stable kernel-owned allocation"
    )]
    fn new(pipe: Arc<OwnedHandle>, size: usize) -> io::Result<Self> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size).map_err(io::Error::other)?;
        bytes.resize(size, 0);
        // SAFETY: null attributes and name make this an unnamed noninheritable event.
        let event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: CreateEventW returned one new event with exactly one owner.
        let event = unsafe { OwnedHandle::from_raw_handle(event) };
        // SAFETY: all SDK OVERLAPPED storage fields permit zero initialization.
        let overlapped = unsafe { std::mem::zeroed() };
        let original = Arc::new(Loan {
            pipe,
            event,
            overlapped: UnsafeCell::new(overlapped),
            bytes: UnsafeCell::new(bytes),
        });
        let context = Arc::into_raw(Arc::clone(&original));
        // SAFETY: the context owns an independent Arc and the wait remains unarmed.
        let wait =
            unsafe { CreateThreadpoolWait(Some(drain), context.cast_mut().cast(), ptr::null()) };
        if wait == 0 {
            let error = io::Error::last_os_error();
            // SAFETY: no native owner can access this unregistered context.
            drop(unsafe { Arc::from_raw(context) });
            return Err(error);
        }
        Ok(Self {
            original,
            retirement: Some(Retirement { wait, context }),
            pending: false,
        })
    }

    #[expect(
        unsafe_code,
        reason = "The complete private payload is observed only after all kernel borrows have ended"
    )]
    fn complete(mut self, target: &mut [u8], deadline: Instant) -> io::Result<()> {
        let mut written = 0;
        while written < target.len() {
            check_deadline(deadline)?;
            let requested = (target.len() - written).min(u32::MAX as usize);
            self.submit(written, requested as u32)
                .map_err(read_failure)?;
            let received = self.wait(deadline).map_err(read_failure)?;
            if received == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            if received > requested {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "startup pipe read exceeded its original extent",
                ));
            }
            written += received;
        }
        check_deadline(deadline)?;
        // SAFETY: all I/O completed, and neither the kernel nor the unarmed wait reads the data.
        target.copy_from_slice(unsafe { &*self.original.bytes.get() });
        Ok(())
    }

    #[expect(
        unsafe_code,
        reason = "One ReadFile borrows only the original private payload extent and an initialized stable OVERLAPPED"
    )]
    fn submit(&mut self, offset: usize, count: u32) -> io::Result<()> {
        let event = self.original.event.as_raw_handle();
        // SAFETY: the previous operation has completed and this event is private.
        if unsafe { ResetEvent(event) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let overlapped = self.original.overlapped.get();
        // SAFETY: the previous kernel loan has ended and the extent was checked by the caller.
        let data = unsafe {
            *overlapped = std::mem::zeroed();
            (*overlapped).hEvent = event;
            (*self.original.bytes.get()).as_mut_ptr().add(offset)
        };
        // SAFETY: no caller-owned memory is lent. The guard keeps the handle, event,
        // buffer and exact request alive until completion even when unwinding.
        if unsafe {
            ReadFile(
                self.original.pipe.as_raw_handle(),
                data,
                count,
                ptr::null_mut(),
                overlapped,
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
                return Err(error);
            }
        }
        self.pending = true;
        Ok(())
    }

    #[expect(
        unsafe_code,
        reason = "The read guard owns the original event during finite waits"
    )]
    fn wait(&mut self, deadline: Instant) -> io::Result<usize> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let timeout = remaining.as_nanos().div_ceil(1_000_000).min(1_000) as u32;
            // SAFETY: the event is live and the timeout is finite.
            match unsafe { WaitForSingleObject(self.original.event.as_raw_handle(), timeout) } {
                WAIT_OBJECT_0 => {
                    let result = self.original.result().ok_or_else(|| {
                        io::Error::other("startup pipe signaled before native completion")
                    })?;
                    self.pending = false;
                    return result.map(|count| count as usize);
                }
                WAIT_TIMEOUT => {}
                WAIT_FAILED => return Err(io::Error::last_os_error()),
                _ => return Err(io::Error::other("unexpected startup pipe wait status")),
            }
        }
    }
}

impl Loan {
    #[expect(
        unsafe_code,
        reason = "Query the result of this exact stable native request without waiting or borrowing payload bytes"
    )]
    fn result(&self) -> Option<io::Result<u32>> {
        let mut count = 0;
        // SAFETY: the original handle, request and event stay owned until after this query.
        if unsafe {
            GetOverlappedResult(
                self.pipe.as_raw_handle(),
                self.overlapped.get(),
                &mut count,
                0,
            )
        } != 0
        {
            return Some(Ok(count));
        }
        let error = io::Error::last_os_error();
        (error.raw_os_error() != Some(ERROR_IO_INCOMPLETE as i32)).then_some(Err(error))
    }
}

impl Drop for Read {
    #[expect(
        unsafe_code,
        reason = "Retirement cancels only the original request and leaves its independent context with the native wait until completion"
    )]
    fn drop(&mut self) {
        let Some(retirement) = self.retirement.take() else {
            return;
        };
        let event = self.original.event.as_raw_handle();
        if self.pending {
            // SAFETY: no other reader can submit, and this exact native request is still owned.
            let _requested = unsafe {
                CancelIoEx(
                    self.original.pipe.as_raw_handle(),
                    self.original.overlapped.get(),
                )
            };
            // SAFETY: a zero-timeout probe observes this original private event only.
            if unsafe { WaitForSingleObject(event, 0) } != WAIT_OBJECT_0
                || self.original.result().is_none()
            {
                // SAFETY: ownership of the independent Arc and wait passes to the callback.
                unsafe { SetThreadpoolWait(retirement.wait, event, ptr::null()) };
                return;
            }
        }

        // SAFETY: the wait is still unarmed and nothing in Windows can access the context again.
        unsafe {
            CloseThreadpoolWait(retirement.wait);
            drop(Arc::from_raw(retirement.context));
        }
    }
}

#[expect(
    unsafe_code,
    reason = "An armed wait owns exactly one native context and retires it after observing completion"
)]
unsafe extern "system" fn drain(
    instance: PTP_CALLBACK_INSTANCE,
    context: *mut c_void,
    wait: PTP_WAIT,
    signal: u32,
) {
    // SAFETY: the armed one-shot wait transfers its sole context reference into this callback.
    let original = unsafe { Arc::from_raw(context.cast::<Loan>()) };
    if original.result().is_none() {
        let event = original.event.as_raw_handle();
        // SAFETY: the event remains privately owned. A second query after reset
        // detects a completion which raced with clearing the unexpected signal.
        let reset = signal != WAIT_OBJECT_0 || unsafe { ResetEvent(event) } != 0;
        if original.result().is_none() {
            // Preserve the context if Windows reports an unusable event while
            // a kernel loan is still outstanding. No client buffer is involved.
            let _context = Arc::into_raw(original);
            if reset {
                // SAFETY: the independent context remains live for the rearmed wait.
                unsafe { SetThreadpoolWait(wait, event, ptr::null()) };
                return;
            }
        }
    }
    // SAFETY: the wait is no longer armed and the callback will never use it again.
    unsafe {
        DisassociateCurrentThreadFromCallback(instance);
        CloseThreadpoolWait(wait);
    }
}

fn check_deadline(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        return Err(io::ErrorKind::TimedOut.into());
    }
    Ok(())
}

fn read_failure(error: io::Error) -> io::Error {
    if is_peer_closed(&error) {
        io::Error::new(io::ErrorKind::UnexpectedEof, error)
    } else {
        error
    }
}
