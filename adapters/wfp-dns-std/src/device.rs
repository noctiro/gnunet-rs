//! Exclusive buffered access to the installed local DNS capture device.
//!
//! Opening starts no driver, service or policy. One unnamed auto-reset event
//! wakes the caller for either queued queries or actual injection completions.
//! Signals coalesce: drain both queues before waiting again. A write acknowledges
//! only its original command; native completion and receive authorization arrive
//! independently. Dropping the owner closes the original device session.
mod maintenance;
use super::{NativeFailure, upstream};
use gnunet_wfp_dns::{RequestId, device as record};
pub use maintenance::{Maintenance, MaintenanceError, Released};
use std::{
    fmt, io,
    num::NonZeroU64,
    os::windows::io::{
        AsHandle, AsRawHandle, AsRawSocket, BorrowedHandle, BorrowedSocket, FromRawHandle,
        IntoRawHandle, OwnedHandle,
    },
    ptr,
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_BUSY, ERROR_NO_MORE_ITEMS, ERROR_NOT_READY, ERROR_SHARING_VIOLATION,
        GENERIC_READ, GENERIC_WRITE, GetLastError, INVALID_HANDLE_VALUE, WAIT_FAILED,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING, ReadFile, WriteFile},
    System::{
        IO::DeviceIoControl,
        Threading::{CreateEventW, WaitForSingleObject},
    },
};

/// Original native failure or invalid local device record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Exact Win32 error from the original failing operation.
    Native(NativeFailure),
    /// A complete local record did not satisfy the shared device codec.
    Record(record::Error),
    /// The original upstream socket failed native identity or IFS validation.
    Upstream(upstream::Error),
    /// START did not supply one through the fixed maximum original sockets.
    UpstreamCount {
        /// Original socket count.
        actual: usize,
    },
    /// START repeated an original socket or observed endpoint identity.
    DuplicateUpstream,
    /// Query storage cannot hold every ordinary UDP DNS record.
    Buffer {
        /// Required complete-record capacity.
        required: usize,
        /// Supplied capacity.
        actual: usize,
    },
    /// A successful original operation returned an unexpected byte count.
    Transfer {
        /// Original synchronous native operation.
        operation: &'static str,
        /// Complete expected record or command extent.
        expected: usize,
        /// Native transferred-byte observation.
        actual: usize,
    },
}
impl Error {
    /// The original query/completion read observed unavailable packet policy.
    /// Invalid records and errors from writes, events or closes never qualify.
    #[must_use]
    pub fn is_policy_loss(&self) -> bool {
        matches!(
            self,
            Self::Native(NativeFailure {
                operation: "ReadFile" | "DeviceIoControl(IOCTL_COMPLETION)",
                code: ERROR_NOT_READY,
            })
        )
    }

    /// A reply write observed that the original packet device became unavailable.
    /// The failed command is never replayed on a replacement file.
    #[must_use]
    pub fn is_write_not_ready(&self) -> bool {
        matches!(
            self,
            Self::Native(NativeFailure {
                operation: "WriteFile",
                code: ERROR_NOT_READY,
            })
        )
    }

    /// The original device open or START observed expected native unavailability.
    /// An exclusive open's sharing conflict is also pending. This does not
    /// authorize retrying the same uncertain START command; close
    /// that original file before attempting a new session. Event publication,
    /// access, record and other native failures remain terminal.
    #[must_use]
    pub fn is_start_pending(&self) -> bool {
        matches!(
            self,
            Self::Native(NativeFailure {
                operation: "CreateFileW" | "DeviceIoControl(IOCTL_START)",
                code: ERROR_NOT_READY | ERROR_BUSY,
            }) | Self::Native(NativeFailure {
                operation: "CreateFileW",
                code: ERROR_SHARING_VIOLATION,
            })
        )
    }
}
impl From<record::Error> for Error {
    fn from(error: record::Error) -> Self {
        Self::Record(error)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Native(error) => error.fmt(output),
            Self::Record(error) => write!(output, "invalid local DNS device record: {error:?}"),
            Self::Upstream(error) => error.fmt(output),
            Self::UpstreamCount { actual } => write!(
                output,
                "DNS capture needs 1..={} original upstream sockets, received {actual}",
                record::MAX_UPSTREAM_SOCKETS
            ),
            Self::DuplicateUpstream => {
                output.write_str("DNS capture repeats an upstream socket or endpoint")
            }
            Self::Buffer { required, actual } => write!(
                output,
                "DNS query record needs {required} bytes of storage, received {actual}"
            ),
            Self::Transfer {
                operation,
                expected,
                actual,
            } => {
                write!(
                    output,
                    "{operation} transferred {actual} bytes, expected {expected}"
                )
            }
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Native(error) => Some(error),
            Self::Upstream(error) => Some(error),
            _ => None,
        }
    }
}

/// Complete dequeued query borrowing the caller's original record storage.
#[derive(Clone, Copy)]
pub struct Query<'buffer> {
    /// Opaque token valid only for this original open driver session.
    pub request: RequestId,
    /// Complete DNS query; application-level DNS validation remains the caller's.
    pub dns: &'buffer [u8],
}
impl fmt::Debug for Query<'_> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("Query")
            .field("request", &self.request)
            .field("bytes", &self.dns.len())
            .finish()
    }
}

/// One exclusive synchronous device session and its original wake event.
/// Calls borrow the owner mutably, preventing concurrent record operations.
/// Device cleanup does not prove that native injection callbacks have drained.
#[derive(Debug)]
#[must_use = "retain the original device session through its query/reply work"]
pub struct Device {
    channel: OwnedHandle,
    wake: OwnedHandle,
}

/// Original START refusal retaining its same open device for explicit cleanup.
/// No failed/uncertain command is automatically retried.
#[derive(Debug)]
#[must_use = "retain or close the original device after failed START"]
pub struct StartFailure {
    /// Original validation, Winsock, codec or native START failure.
    pub original: Error,
    /// Same original device; dropping it closes that session.
    pub device: Device,
}
impl fmt::Display for StartFailure {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "starting DNS capture: {}", self.original)
    }
}
impl std::error::Error for StartFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}

/// Original device whose native START actually returned complete success.
/// Keep the caller's real socket reservations through successful STOP. Endpoint
/// observations do not replace those owners or prove native callback retirement.
#[derive(Debug)]
#[must_use = "stop original capture and drain its actual native completions"]
pub struct Started {
    device: Device,
    upstreams: record::Upstreams,
    stopped: Option<Result<(), Error>>,
}

impl Started {
    /// Close this original packet file once, retaining its event through close.
    /// The native file cleanup ends this session; it is not an injection,
    /// `FILE_OBJECT` destruction or driver-unload receipt. No STOP is repeated.
    ///
    /// # Errors
    /// Preserves the original close failure. Its handle custody is then
    /// uncertain and terminal; no retry or Drop closes that identifier again.
    pub fn close(self) -> Result<(), Error> {
        self.device.close()
    }

    /// Immutable original START inputs, without socket custody or a fresh query.
    #[must_use]
    pub fn upstreams(&self) -> &[record::Upstream] {
        self.upstreams.as_slice()
    }

    /// Borrow this original device's wake event for one consuming wait worker.
    #[must_use]
    pub fn wake_event(&self) -> BorrowedHandle<'_> {
        self.device.wake_event()
    }

    /// Create a native wait retaining a duplicate of the original wake event.
    ///
    /// # Errors
    /// Preserves event duplication or native wait-allocation failure.
    pub fn event_wait(&self) -> io::Result<gnunet_native::event_wait::Wait> {
        self.device.event_wait()
    }

    /// Wait on the original capture/completion hint from a blocking I/O worker.
    /// Use a single consuming wait per file. A signal is not an I/O receipt.
    ///
    /// # Errors
    /// Preserves the original Windows wait failure.
    #[expect(
        unsafe_code,
        reason = "WaitForSingleObject borrows the original event until a finite native wait returns"
    )]
    pub fn wait_for_wake(&self, remaining: Duration) -> io::Result<bool> {
        // Round up fractional milliseconds and never pass the INFINITE value.
        let millis = remaining
            .as_nanos()
            .div_ceil(1_000_000)
            .min(u128::from(u32::MAX - 1)) as u32;
        // SAFETY: the started file owns this original auto-reset event.
        match unsafe { WaitForSingleObject(self.wake_event().as_raw_handle(), millis) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            WAIT_FAILED => Err(io::Error::last_os_error()),
            _ => Err(io::Error::other("unexpected WFP retirement wait result")),
        }
    }

    /// Dequeue one complete query using full-capacity caller storage.
    ///
    /// # Errors
    /// Preserves the original device read, buffer or shared record error.
    pub fn read_query<'buffer>(
        &mut self,
        buffer: &'buffer mut [u8],
    ) -> Result<Option<Query<'buffer>>, Error> {
        self.device.read_query(buffer)
    }

    /// Submit one original discard or reply; acceptance is not completion.
    /// A token-only discard can revoke a pending reply without settling native
    /// completion debt. Kernel rejection and already-authorized state remain real.
    ///
    /// # Errors
    /// Preserves the original validation, write or short-transfer error.
    pub fn write(&mut self, command: record::Reply<'_>, buffer: &mut [u8]) -> Result<(), Error> {
        self.device.write(command, buffer)
    }

    /// Dequeue actual original injection completion, including after STOP.
    ///
    /// # Errors
    /// Preserves native control, extent or shared completion-record errors.
    pub fn read_completion(&mut self) -> Result<Option<record::Completion>, Error> {
        self.device.read_completion()
    }

    /// Revoke original capture and release driver-side upstream handle owners.
    /// Only complete native success acknowledges STOP. The same file remains
    /// open for outstanding actual injection completions. One attempt is cached;
    /// neither success nor failure is retried, and Drop closes the original file.
    ///
    /// # Errors
    /// Preserves the original native STOP or unexpected output-length error.
    pub fn stop(&mut self) -> Result<(), Error> {
        if let Some(result) = self.stopped {
            return result;
        }
        let result = self
            .device
            .control(record::IOCTL_STOP, &[], "DeviceIoControl(IOCTL_STOP)");
        self.stopped = Some(result);
        result
    }

    /// Whether this original device actually acknowledged complete STOP.
    /// This is not a native completion/callback cutoff proof.
    #[must_use]
    pub const fn is_stopped(&self) -> bool {
        matches!(self.stopped, Some(Ok(())))
    }
}

impl Device {
    /// Consume this original packet file with one actual native close attempt.
    /// Keep its original wake event alive through the synchronous close. Success
    /// observes only handle release, without proving native callback retirement
    /// or final I/O-manager file destruction.
    ///
    /// # Errors
    /// Preserves the original `CloseHandle` failure. Custody remains uncertain;
    /// the consumed handle is never closed again by retry or Drop.
    #[expect(
        unsafe_code,
        reason = "The original packet handle leaves OwnedHandle before its single explicit CloseHandle; the wake owner remains live through native return"
    )]
    pub fn close(self) -> Result<(), Error> {
        let Self { channel, wake } = self;
        let raw = channel.into_raw_handle();
        // SAFETY: exclusive original channel ownership was consumed before this
        // sole close attempt, and no device operation retains a borrow of it.
        let accepted = unsafe { CloseHandle(raw) };
        let result = if accepted == 0 {
            Err(Error::Native(last_error("CloseHandle(packet device)")))
        } else {
            Ok(())
        };
        drop(wake);
        result
    }

    /// Open the existing protected device and attach an unnamed auto-reset event.
    /// Requests read/write access, no sharing, no inheritance and no overlapped I/O.
    /// The calling token must already satisfy the device's access checks.
    ///
    /// # Errors
    /// Preserves the original CreateFileW, CreateEventW or event-publication error.
    /// No installation, privilege adjustment or elevation is attempted.
    #[expect(
        unsafe_code,
        reason = "Win32 borrows fixed path/record storage and transfers each successful checked native handle to exactly one OwnedHandle"
    )]
    pub fn open() -> Result<Self, Error> {
        let path: Vec<u16> = record::PATH.encode_utf16().chain(Some(0)).collect();
        // SAFETY: terminated fixed device path, null security/template handles,
        // explicit exclusive synchronous access and no ownership to borrow.
        let channel = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };
        if channel == INVALID_HANDLE_VALUE {
            return Err(Error::Native(last_error("CreateFileW")));
        }
        // SAFETY: successful CreateFileW transfers this unique real handle.
        let channel = unsafe { OwnedHandle::from_raw_handle(channel) };
        // SAFETY: null attributes forbid inheritance, false manual/initial
        // state creates an unnamed unsignaled auto-reset event.
        let wake = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
        if wake.is_null() {
            return Err(Error::Native(last_error("CreateEventW")));
        }
        // SAFETY: successful CreateEventW transfers this unique event handle.
        let wake = unsafe { OwnedHandle::from_raw_handle(wake) };
        let event = (wake.as_raw_handle() as usize as u64).to_le_bytes();
        let mut returned = 0;
        // SAFETY: exact original synchronous device, fixed eight-byte local
        // process handle, no output buffer or pending/overlapped operation.
        let accepted = unsafe {
            DeviceIoControl(
                channel.as_raw_handle(),
                record::IOCTL_SET_EVENT,
                event.as_ptr().cast(),
                event.len() as u32,
                ptr::null_mut(),
                0,
                &mut returned,
                ptr::null_mut(),
            )
        };
        if accepted == 0 {
            return Err(Error::Native(last_error(
                "DeviceIoControl(IOCTL_SET_EVENT)",
            )));
        }
        exact("DeviceIoControl(IOCTL_SET_EVENT)", 0, returned)?;
        Ok(Self { channel, wake })
    }

    /// Query original IFS UDP sockets and submit their complete native START.
    /// No numeric identity can construct Started without actual device success.
    /// Keep the original socket reservation owners until successful STOP; this
    /// method only borrows them through synchronous query and START publication.
    ///
    /// # Errors
    /// Preserves original socket validation/query and native START errors with
    /// this same device. Empty, oversized or duplicate lists fail before START.
    pub fn start(mut self, sockets: &[BorrowedSocket<'_>]) -> Result<Started, StartFailure> {
        let result = (|| {
            let first = sockets.first().ok_or(Error::UpstreamCount { actual: 0 })?;
            if sockets.len() > record::MAX_UPSTREAM_SOCKETS {
                return Err(Error::UpstreamCount {
                    actual: sockets.len(),
                });
            }
            let mut upstreams = record::Upstreams::new(descriptor(first)?);
            for socket in &sockets[1..] {
                upstreams
                    .push(descriptor(socket)?)
                    .map_err(|_| Error::DuplicateUpstream)?;
            }
            let mut input = [0; record::MAX_UPSTREAM_SOCKETS * record::UPSTREAM_BYTES];
            for (upstream, output) in upstreams
                .as_slice()
                .iter()
                .zip(input.as_chunks_mut::<{ record::UPSTREAM_BYTES }>().0)
            {
                output.copy_from_slice(&upstream.encode());
            }
            self.control(
                record::IOCTL_START,
                &input[..sockets.len() * record::UPSTREAM_BYTES],
                "DeviceIoControl(IOCTL_START)",
            )?;
            Ok(upstreams)
        })();
        match result {
            Ok(upstreams) => Ok(Started {
                device: self,
                upstreams,
                stopped: None,
            }),
            Err(original) => Err(StartFailure {
                original,
                device: self,
            }),
        }
    }

    /// Borrow the original auto-reset event for the caller's own wait worker.
    /// Do not reset, signal or close it. One signal is a wake hint; drain both
    /// query and completion queues before waiting again. Use one consuming waiter.
    #[must_use]
    pub fn wake_event(&self) -> BorrowedHandle<'_> {
        self.wake.as_handle()
    }

    /// Create a native event wait over a duplicate of this original wake event.
    /// Keep one consuming waiter and drain both device queues before rearming.
    /// This retains only the event; it grants no device-session or driver lease.
    ///
    /// # Errors
    /// Preserves event duplication or native wait-allocation failure.
    #[expect(
        unsafe_code,
        reason = "Only the original internally created auto-reset event is duplicated into the native wait's uniquely owned handle"
    )]
    pub fn event_wait(&self) -> io::Result<gnunet_native::event_wait::Wait> {
        let event = self.wake.try_clone()?;
        // SAFETY: this is a real auto-reset kernel event duplicated from our
        // live owner, and the wait receives exclusive ownership of its handle.
        unsafe { gnunet_native::event_wait::Wait::new(event) }
    }

    /// Dequeue one complete query without waiting for a future capture.
    /// Storage must cover MAX_RECORD_BYTES; larger storage is bounded to that
    /// extent before native entry. An empty queue returns None.
    ///
    /// # Errors
    /// Refuses insufficient storage before reading and preserves native errors
    /// or invalid complete records. A malformed dequeued record is not retried.
    #[expect(
        unsafe_code,
        reason = "Synchronous ReadFile borrows the original owned device and bounded exclusive caller buffer without retaining either after return"
    )]
    pub fn read_query<'buffer>(
        &mut self,
        buffer: &'buffer mut [u8],
    ) -> Result<Option<Query<'buffer>>, Error> {
        let actual = buffer.len();
        let buffer = buffer
            .get_mut(..record::MAX_RECORD_BYTES)
            .ok_or(Error::Buffer {
                required: record::MAX_RECORD_BYTES,
                actual,
            })?;
        let mut returned = 0;
        // SAFETY: synchronous handle and initialized exclusive output storage;
        // the fixed maximum fits DWORD and no overlapped state is retained.
        let accepted = unsafe {
            ReadFile(
                self.channel.as_raw_handle(),
                buffer.as_mut_ptr(),
                record::MAX_RECORD_BYTES as u32,
                &mut returned,
                ptr::null_mut(),
            )
        };
        if accepted == 0 {
            let error = last_error("ReadFile");
            return if error.code == ERROR_NO_MORE_ITEMS {
                Ok(None)
            } else {
                Err(Error::Native(error))
            };
        }
        let bytes = buffer.get(..returned as usize).ok_or(Error::Transfer {
            operation: "ReadFile",
            expected: record::MAX_RECORD_BYTES,
            actual: returned as usize,
        })?;
        let (request, dns) = record::query(bytes)?;
        Ok(Some(Query { request, dns }))
    }

    /// Send one complete discard or reply command using reusable record storage.
    /// Success acknowledges this command, not native completion or delivery.
    /// A discard creates no new injection; a previously accepted reply retains
    /// its actual completion. Observe replies with read_completion separately.
    /// No command is automatically repeated.
    ///
    /// # Errors
    /// Refuses invalid replies/capacity before WriteFile. Preserves the original
    /// native failure or short-write observation. Do not retry an attempted write
    /// on this original token: a failure does not grant a new reservation.
    #[expect(
        unsafe_code,
        reason = "Synchronous WriteFile borrows exactly one codec-validated complete command from caller storage and is never retried"
    )]
    pub fn write(&mut self, command: record::Reply<'_>, buffer: &mut [u8]) -> Result<(), Error> {
        let (request, dns) = match command {
            record::Reply::Discard(request) => (request, &[][..]),
            record::Reply::Datagram(request, dns) => {
                if dns.is_empty() {
                    return Err(record::Error::Length.into());
                }
                (request, dns)
            }
        };
        let bytes = record::encode(request, dns, buffer)?;
        let input = &buffer[..bytes];
        record::reply(input)?;
        let mut returned = 0;
        // SAFETY: the codec validated this complete bounded command; the
        // original synchronous handle retains no pointer after native return.
        let accepted = unsafe {
            WriteFile(
                self.channel.as_raw_handle(),
                input.as_ptr(),
                bytes as u32,
                &mut returned,
                ptr::null_mut(),
            )
        };
        if accepted == 0 {
            return Err(Error::Native(last_error("WriteFile")));
        }
        exact("WriteFile", bytes, returned)
    }

    /// Dequeue one actual injection completion independently of write acceptance.
    /// Preserves the original native status and independent receive-gate verdict.
    /// Neither is proof that an application consumed the response.
    ///
    /// # Errors
    /// Preserves native control errors, unexpected record extents or codec errors.
    #[expect(
        unsafe_code,
        reason = "Synchronous DeviceIoControl writes one fixed shared completion record to exclusive initialized stack storage"
    )]
    pub fn read_completion(&mut self) -> Result<Option<record::Completion>, Error> {
        let mut record = [0; record::COMPLETION_BYTES];
        let mut returned = 0;
        // SAFETY: original synchronous device, no input, exact fixed output
        // record and no overlapped operation or retained stack pointers.
        let accepted = unsafe {
            DeviceIoControl(
                self.channel.as_raw_handle(),
                record::IOCTL_COMPLETION,
                ptr::null(),
                0,
                record.as_mut_ptr().cast(),
                record.len() as u32,
                &mut returned,
                ptr::null_mut(),
            )
        };
        if accepted == 0 {
            return Err(Error::Native(last_error(
                "DeviceIoControl(IOCTL_COMPLETION)",
            )));
        }
        if returned == 0 {
            return Ok(None);
        }
        exact("DeviceIoControl(IOCTL_COMPLETION)", record.len(), returned)?;
        Ok(Some(record::decode_completion(&record)?))
    }

    #[expect(
        unsafe_code,
        reason = "One synchronous bounded START/STOP control borrows complete caller storage and returns no output or retained buffer pointers"
    )]
    fn control(&mut self, code: u32, input: &[u8], operation: &'static str) -> Result<(), Error> {
        let mut returned = 0;
        // SAFETY: original owned synchronous device and bounded fixed local
        // START/STOP record, no output, overlapped operation or retained pointer.
        let accepted = unsafe {
            DeviceIoControl(
                self.channel.as_raw_handle(),
                code,
                if input.is_empty() {
                    ptr::null()
                } else {
                    input.as_ptr().cast()
                },
                input.len() as u32,
                ptr::null_mut(),
                0,
                &mut returned,
                ptr::null_mut(),
            )
        };
        if accepted == 0 {
            return Err(Error::Native(last_error(operation)));
        }
        exact(operation, 0, returned)
    }
}

fn descriptor(socket: &BorrowedSocket<'_>) -> Result<record::Upstream, Error> {
    let endpoint = upstream::query(socket).map_err(Error::Upstream)?;
    let socket = NonZeroU64::new(socket.as_raw_socket()).ok_or(record::Error::Upstream)?;
    // query refuses a zero successful native endpoint.
    let endpoint = NonZeroU64::new(endpoint.get()).ok_or(record::Error::Upstream)?;
    Ok(record::Upstream { socket, endpoint })
}

fn exact(operation: &'static str, expected: usize, actual: u32) -> Result<(), Error> {
    let actual = actual as usize;
    if actual == expected {
        Ok(())
    } else {
        Err(Error::Transfer {
            operation,
            expected,
            actual,
        })
    }
}

#[expect(
    unsafe_code,
    reason = "GetLastError reads the unchanged calling-thread status immediately after the original failing native operation"
)]
fn last_error(operation: &'static str) -> NativeFailure {
    // SAFETY: GetLastError accepts no pointers and reads thread-local native state.
    let code = unsafe { GetLastError() };
    NativeFailure { operation, code }
}

#[cfg(test)]
mod tests;
