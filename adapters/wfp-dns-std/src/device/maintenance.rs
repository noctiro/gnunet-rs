//! Explicit staged retirement through the protected maintenance device.
//!
//! Stop the data service independently. This channel neither starts a driver
//! nor invokes SCM. Its final receipt requires both native anchor retirement
//! and actual release of this original maintenance handle.
use super::last_error;
use crate::NativeFailure;
use gnunet_wfp_dns::device::maintenance as record;
use std::{
    fmt,
    os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, GENERIC_READ, GENERIC_WRITE,
        HANDLE, INVALID_HANDLE_VALUE,
    },
    Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING, ReadFile},
    System::IO::DeviceIoControl,
};

/// Original maintenance transport failure or an unverified retirement boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceError {
    /// Exact original Win32 failure, without a retry.
    Native(NativeFailure),
    /// Both names of the same protected device failed to open.
    Open {
        /// Original absent DOS-path observation that permitted native lookup.
        canonical: NativeFailure,
        /// Original native-device lookup failure.
        native: NativeFailure,
    },
    /// This original channel has already completed its close attempt.
    Closed,
    /// No successful native anchor-release observation permits a close receipt.
    NotRetired {
        /// Most recent successfully decoded original response, if any.
        progress: Option<record::Progress>,
    },
    /// A successful transport returned an unexpected complete-record extent.
    Extent {
        /// Original control operation.
        operation: &'static str,
        /// Actual native returned-byte count.
        returned: u32,
    },
    /// An exact native response violated the shared phase/status contract.
    Record {
        /// Original control operation.
        operation: &'static str,
        /// Unchanged original response bytes.
        bytes: [u8; record::PROGRESS_BYTES],
    },
}
impl fmt::Display for MaintenanceError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Native(error) => error.fmt(output),
            Self::Open { canonical, native } => {
                write!(output, "{native}; original DOS lookup: {canonical}")
            }
            Self::Closed => {
                output.write_str("original maintenance handle has completed its close attempt")
            }
            Self::NotRetired { progress } => {
                write!(
                    output,
                    "native driver retirement is unconfirmed: {progress:?}"
                )
            }
            Self::Extent {
                operation,
                returned,
            } => write!(
                output,
                "{operation} returned {returned} bytes, expected {}",
                record::PROGRESS_BYTES
            ),
            Self::Record { operation, bytes } => {
                write!(
                    output,
                    "{operation} returned an invalid retirement record: {bytes:02x?}"
                )
            }
        }
    }
}
impl std::error::Error for MaintenanceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Native(error) => Some(error),
            Self::Open { native, .. } => Some(native),
            _ => None,
        }
    }
}

/// Actual maintenance-handle close after native anchor retirement.
/// This is neither an SCM result nor proof of final FILE_OBJECT destruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Released {
    progress: record::Progress,
}
impl Released {
    /// Original terminal native acknowledgement observed before handle close.
    #[must_use]
    pub const fn progress(self) -> record::Progress {
        self.progress
    }
}

/// One original protected maintenance file and its explicit native observations.
/// Each request performs one synchronous control; no loop, deadline-derived
/// success or automatic retry advances retirement. Early Drop closes an open
/// handle without producing a release receipt. Failed explicit close retains
/// an uncertain original-handle record and is never retried, including on Drop.
#[must_use = "observe native retirement and explicitly close before a separate SCM operation"]
pub struct Maintenance {
    channel: Option<OwnedHandle>,
    progress: Option<record::Progress>,
    close_result: Option<Result<Released, MaintenanceError>>,
    uncertain_handle: Option<usize>,
}
impl fmt::Debug for Maintenance {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("Maintenance")
            .field("open", &self.channel.is_some())
            .field("progress", &self.progress)
            .field("close_result", &self.close_result)
            .field("has_uncertain_original", &self.uncertain_handle.is_some())
            .finish()
    }
}
impl Maintenance {
    /// Open the installed maintenance device with exclusive read/write access.
    /// Uses the caller's existing access rights, OPEN_EXISTING and synchronous
    /// I/O. An absent DOS name permits lookup of the same secured native device.
    /// Access-denied and in-use errors never trigger that fallback. No wake event,
    /// data START, privilege adjustment or SCM call occurs.
    ///
    /// # Errors
    /// Preserves original CreateFileW failures from every attempted name.
    pub fn open() -> Result<Self, MaintenanceError> {
        let access = GENERIC_READ | GENERIC_WRITE;
        let channel = match open_path(record::PATH, access, "CreateFileW(maintenance)") {
            Ok(channel) => channel,
            Err(canonical)
                if matches!(canonical.code, ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) =>
            {
                open_path(
                    record::NATIVE_PATH,
                    access,
                    "CreateFileW(maintenance native name)",
                )
                .map_err(|native| MaintenanceError::Open { canonical, native })?
            }
            Err(error) => return Err(MaintenanceError::Native(error)),
        };
        Ok(Self {
            channel: Some(channel),
            progress: None,
            close_result: None,
            uncertain_handle: None,
        })
    }

    /// Observe completed native retirement on the original, still-loaded
    /// driver's protected read-only device and close that observation handle.
    /// Use after interruption between handoff and the SCM stop request.
    ///
    /// # Errors
    /// Preserves original open, read, decode and close failures. The native
    /// handle stays exclusive through the complete read. Only successful
    /// close after a verified terminal response produces a receipt.
    #[expect(
        unsafe_code,
        reason = "Read one exact initialized fixed response through the original synchronous read-only native file"
    )]
    pub fn recover_release() -> Result<Released, MaintenanceError> {
        let channel = open_path(
            record::NATIVE_PATH,
            GENERIC_READ,
            "CreateFileW(retirement observation)",
        )
        .map_err(MaintenanceError::Native)?;
        let mut output = [0; record::PROGRESS_BYTES];
        let mut returned = 0;
        // SAFETY: the original synchronous handle and writable fixed extent
        // remain live through this call; no overlapped request is issued.
        let accepted = unsafe {
            ReadFile(
                channel.as_raw_handle(),
                output.as_mut_ptr(),
                output.len() as u32,
                &mut returned,
                ptr::null_mut(),
            )
        };
        let operation = "ReadFile(retirement observation)";
        if accepted == 0 {
            return Err(MaintenanceError::Native(last_error(operation)));
        }
        let progress = decode_progress(operation, returned, output)?;
        let progress = terminal(Some(progress))?;
        close_channel(channel).map_err(|(error, _)| MaintenanceError::Native(error))?;
        Ok(Released { progress })
    }

    /// Advance one bounded preparation stage without a hidden wait/retry loop.
    /// Kernel slot work is bounded; documented SDK-call latency is independent.
    ///
    /// # Errors
    /// Preserves original transport, returned-extent and phase/status errors.
    pub fn poll(&mut self) -> Result<record::Progress, MaintenanceError> {
        self.request(record::Request::Poll)
    }

    /// Explicitly enter or observe native finalization after preparation.
    /// This synchronous request can perform the native handle-destruction wait;
    /// use the caller's blocking maintenance context. Pending stages remain
    /// pending and never become successful retirement through elapsed time.
    ///
    /// # Errors
    /// Preserves original transport, returned-extent and phase/status errors.
    pub fn finalize(&mut self) -> Result<record::Progress, MaintenanceError> {
        self.request(record::Request::Finalize)
    }

    /// Most recent actual decoded response, independent of later transport errors.
    #[must_use]
    pub const fn last_progress(&self) -> Option<record::Progress> {
        self.progress
    }

    /// Close the original handle after verified NativeRetired with zero status.
    /// Only actual CloseHandle success produces Released. Repeated calls return
    /// the same original close observation without another native attempt.
    ///
    /// # Errors
    /// Refuses unconfirmed native retirement before touching the handle, or
    /// retains the original CloseHandle failure and disables further I/O.
    pub fn close(&mut self) -> Result<Released, MaintenanceError> {
        if let Some(result) = self.close_result {
            return result;
        }
        let progress = terminal(self.progress)?;
        let channel = self.channel.take().ok_or(MaintenanceError::Closed)?;
        let result = match close_channel(channel) {
            Ok(()) => Ok(Released { progress }),
            Err((error, raw)) => {
                self.uncertain_handle = Some(raw);
                Err(MaintenanceError::Native(error))
            }
        };
        self.close_result = Some(result);
        result
    }

    fn raw(&self) -> Result<HANDLE, MaintenanceError> {
        if let Some(result) = self.close_result {
            return Err(result.err().unwrap_or(MaintenanceError::Closed));
        }
        self.channel
            .as_ref()
            .map(AsRawHandle::as_raw_handle)
            .ok_or(MaintenanceError::Closed)
    }

    #[expect(
        unsafe_code,
        reason = "Synchronous DeviceIoControl borrows one exact shared request and initialized fixed output record through native return without retaining pointers"
    )]
    fn request(&mut self, request: record::Request) -> Result<record::Progress, MaintenanceError> {
        let channel = self.raw()?;
        let input = request.encode();
        let mut output = [0; record::PROGRESS_BYTES];
        let mut returned = 0;
        let operation = match request {
            record::Request::Poll => "DeviceIoControl(IOCTL_RETIRE/POLL)",
            record::Request::Finalize => "DeviceIoControl(IOCTL_RETIRE/FINALIZE)",
        };
        // SAFETY: original synchronous device and exact initialized resident
        // buffers, no overlapped operation, output or ownership retained later.
        let accepted = unsafe {
            DeviceIoControl(
                channel,
                record::IOCTL_RETIRE,
                input.as_ptr().cast(),
                record::REQUEST_BYTES as u32,
                output.as_mut_ptr().cast(),
                record::PROGRESS_BYTES as u32,
                &mut returned,
                ptr::null_mut(),
            )
        };
        if accepted == 0 {
            return Err(MaintenanceError::Native(last_error(operation)));
        }
        let progress = decode_progress(operation, returned, output)?;
        self.progress = Some(progress);
        Ok(progress)
    }
}

fn decode_progress(
    operation: &'static str,
    returned: u32,
    bytes: [u8; record::PROGRESS_BYTES],
) -> Result<record::Progress, MaintenanceError> {
    if returned as usize != record::PROGRESS_BYTES {
        return Err(MaintenanceError::Extent {
            operation,
            returned,
        });
    }
    record::Progress::decode(&bytes).ok_or(MaintenanceError::Record { operation, bytes })
}

fn terminal(progress: Option<record::Progress>) -> Result<record::Progress, MaintenanceError> {
    progress
        .filter(|progress| progress.phase == record::Phase::NativeRetired && progress.status == 0)
        .ok_or(MaintenanceError::NotRetired { progress })
}

#[expect(
    unsafe_code,
    reason = "Consume the original handle before the single explicit close attempt"
)]
fn close_channel(channel: OwnedHandle) -> Result<(), (NativeFailure, usize)> {
    let raw = channel.into_raw_handle();
    // SAFETY: ownership left OwnedHandle and all synchronous I/O has returned.
    if unsafe { CloseHandle(raw) } == 0 {
        Err((last_error("CloseHandle(maintenance)"), raw as usize))
    } else {
        Ok(())
    }
}

#[expect(
    unsafe_code,
    reason = "CreateFileW borrows one fixed terminated device path and transfers its checked successful real handle into exactly one OwnedHandle"
)]
fn open_path(
    path: &str,
    access: u32,
    operation: &'static str,
) -> Result<OwnedHandle, NativeFailure> {
    let path: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    // SAFETY: fixed terminated path, exclusive synchronous access, null
    // security attributes forbid inheritance and no template is borrowed.
    let channel = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            0,
            ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if channel == INVALID_HANDLE_VALUE {
        return Err(last_error(operation));
    }
    // SAFETY: successful CreateFileW transfers this original unique handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(channel) })
}
