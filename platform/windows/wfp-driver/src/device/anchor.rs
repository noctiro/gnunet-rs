//! Independent kernel file ownership that gates the legacy driver's unload.
//!
//! This device has no DOS link and never retains the service's control file.
//! Its real open handle keeps the I/O manager's device-file lifetime active
//! until explicit passive retirement succeeds. No destructor closes or deletes
//! native resources, and an uncertain close retains its original custody.
use crate::sdk;
use core::{ffi::c_void, fmt, mem::size_of, ptr::NonNull};

const DEVICE_NAME: &[u16; 35] = &wide(b"\\Device\\GNUnetDnsInterceptLifetime\0");
const SYSTEM_ONLY: &[u16; 16] = &wide(b"D:P(A;;GA;;;SY)\0");
const DEVICE_CLASS: sdk::GUID = sdk::GUID {
    Data1: 0x2ac5_2d64,
    Data2: 0xa8c7,
    Data3: 0x4509,
    Data4: [0xb7, 0xcb, 0xd3, 0x90, 0xe9, 0xe3, 0x69, 0xaf],
};

/// Refusal of an original anchor transition or native operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// The original device has already been created.
    AlreadyCreated,
    /// The original device is absent or has already been deleted.
    NotPrepared,
    /// A real open was already attempted and cannot be issued again.
    AlreadyOpened,
    /// An original or uncertain file handle still prevents deletion.
    HandleHeld,
    /// Secure creation returned no original device.
    MissingDevice,
    /// Native open returned success without a usable original handle.
    MissingHandle,
    /// Device-class overrides changed required native properties.
    IncompatibleDevice,
    /// The actual caller is not at passive IRQL.
    Irql {
        /// Actual processor IRQL.
        current: u8,
    },
    /// A file open requires special kernel APCs to be enabled.
    ApcsDisabled,
    /// Original native refusal, without replacing its NTSTATUS.
    Native {
        /// Actual WDK routine that produced the outcome.
        operation: &'static str,
        /// Unmodified native result.
        status: sdk::NTSTATUS,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyCreated => output.write_str("original lifetime device already exists"),
            Self::NotPrepared => output.write_str("original lifetime device is not prepared"),
            Self::AlreadyOpened => {
                output.write_str("original lifetime file open was already attempted")
            }
            Self::HandleHeld => output.write_str("original lifetime file custody remains"),
            Self::MissingDevice => output.write_str("secure creation returned no lifetime device"),
            Self::MissingHandle => output.write_str("native open returned no lifetime file handle"),
            Self::IncompatibleDevice => {
                output.write_str("native lifetime device properties differ")
            }
            Self::Irql { current } => write!(
                output,
                "lifetime device requires passive IRQL, got {current}"
            ),
            Self::ApcsDisabled => {
                output.write_str("lifetime file open requires special kernel APCs")
            }
            Self::Native { operation, status } => {
                write!(output, "{operation} failed with NTSTATUS {status:#010x}")
            }
        }
    }
}
impl core::error::Error for Error {}

enum Device {
    Empty,
    Prepared(NonNull<sdk::DEVICE_OBJECT>),
    Published(NonNull<sdk::DEVICE_OBJECT>),
    Incompatible(NonNull<sdk::DEVICE_OBJECT>),
    DeleteIssued,
}

enum File {
    Unopened,
    Open(NonNull<c_void>),
    OpenRefused(Error),
    Uncertain {
        original: Option<NonNull<c_void>>,
        error: Error,
    },
    CloseRefused {
        original: NonNull<c_void>,
        error: Error,
    },
    Closed,
}

/// One protected anchor device and its independent original kernel file open.
#[must_use]
pub struct Anchor {
    device: Device,
    file: File,
}

impl Anchor {
    /// Construct an empty owner without native effects.
    pub const fn new() -> Self {
        Self {
            device: Device::Empty,
            file: File::Unopened,
        }
    }

    /// Observe the original device without taking an additional reference.
    #[must_use]
    pub const fn raw(&self) -> Option<NonNull<sdk::DEVICE_OBJECT>> {
        match self.device {
            Device::Prepared(device) | Device::Published(device) | Device::Incompatible(device) => {
                Some(device)
            }
            Device::Empty | Device::DeleteIssued => None,
        }
    }

    /// Whether an original handle or unresolved native file custody remains.
    #[must_use]
    pub const fn has_handle(&self) -> bool {
        matches!(
            self.file,
            File::Open(_) | File::Uncertain { .. } | File::CloseRefused { .. }
        )
    }

    /// Whether no original file handle remains, including an unopened owner.
    #[must_use]
    pub const fn closed(&self) -> bool {
        !self.has_handle()
    }

    /// Create a separate System-only device without releasing initialization.
    ///
    /// Class overrides may change its ACL through the documented WDK mechanism;
    /// the dispatch must independently accept only its own kernel-mode file
    /// lifetime operations. A name collision is refused and never adopted.
    ///
    /// # Errors
    /// Refuses reuse, non-passive use, native failure or incompatible properties.
    /// A successfully created original remains owned on a later refusal.
    ///
    /// # Safety
    /// Supply the original live legacy driver at PASSIVE_LEVEL. Retain this
    /// owner on every partial failure and control its original native name.
    /// Initialize the requested nonpaged extension and actual dispatch routing
    /// before calling [`Self::open`]. No other component may attach a device or
    /// replace this name during its owned lifetime.
    pub unsafe fn prepare(
        &mut self,
        driver: NonNull<sdk::DRIVER_OBJECT>,
        extension_bytes: u32,
    ) -> Result<(), Error> {
        passive()?;
        if !matches!(self.device, Device::Empty) {
            return Err(Error::AlreadyCreated);
        }
        let mut name = counted(DEVICE_NAME);
        let security = counted(SYSTEM_ONLY);
        let mut original = core::ptr::null_mut();
        // SAFETY: original live driver and synchronous counted strings; the
        // native allocator owns the requested nonpaged extension allocation.
        let status = unsafe {
            sdk::WdmlibIoCreateDeviceSecure(
                driver.as_ptr(),
                extension_bytes,
                &raw mut name,
                sdk::FILE_DEVICE_UNKNOWN,
                sdk::FILE_DEVICE_SECURE_OPEN,
                1,
                &raw const security,
                &DEVICE_CLASS,
                &raw mut original,
            )
        };
        native("WdmlibIoCreateDeviceSecure", status)?;
        let original = NonNull::new(original).ok_or(Error::MissingDevice)?;
        self.device = Device::Incompatible(original);
        // SAFETY: this original remains unpublished with exclusive preparation
        // custody; no reference covers the I/O manager's entire mutable object.
        let (kind, characteristics, flags) = unsafe {
            (
                (*original.as_ptr()).DeviceType,
                (*original.as_ptr()).Characteristics,
                (*original.as_ptr()).Flags,
            )
        };
        if kind != sdk::FILE_DEVICE_UNKNOWN
            || characteristics & sdk::FILE_DEVICE_SECURE_OPEN == 0
            || flags & sdk::DO_EXCLUSIVE == 0
            || flags & sdk::DO_DEVICE_INITIALIZING == 0
        {
            return Err(Error::IncompatibleDevice);
        }
        self.device = Device::Prepared(original);
        Ok(())
    }

    /// Release initialization and open the actual independent kernel file once.
    ///
    /// # Errors
    /// Refuses an invalid transition, disabled special APCs or native failure.
    /// A native refusal is retained rather than automatically reopening a name.
    ///
    /// # Safety
    /// The original device extension and identity must already be published to
    /// the driver's dispatch table. Its CREATE/CLEANUP/CLOSE handlers must
    /// synchronously complete only kernel-mode, empty-name lifetime operations,
    /// without borrowing this mutable owner, forwarding or pending the CREATE.
    /// Retain original device/state/code for that reentrant dispatch and until
    /// the file is closed. Call at PASSIVE_LEVEL with special kernel APCs enabled.
    pub unsafe fn open(&mut self) -> Result<(), Error> {
        passive()?;
        // SAFETY: this WDK routine only observes the current thread APC state.
        if unsafe { sdk::KeAreAllApcsDisabled() } != 0 {
            return Err(Error::ApcsDisabled);
        }
        match self.file {
            File::Unopened => {}
            File::OpenRefused(error)
            | File::Uncertain { error, .. }
            | File::CloseRefused { error, .. } => return Err(error),
            File::Open(_) | File::Closed => return Err(Error::AlreadyOpened),
        }
        let Device::Prepared(device) = self.device else {
            return Err(Error::NotPrepared);
        };
        let mut name = counted(DEVICE_NAME);
        let mut attributes = sdk::OBJECT_ATTRIBUTES {
            Length: u32::try_from(size_of::<sdk::OBJECT_ATTRIBUTES>())
                .map_err(|_| Error::IncompatibleDevice)?,
            RootDirectory: core::ptr::null_mut(),
            ObjectName: &raw mut name,
            Attributes: (sdk::GNUNET_WFP_OBJ_KERNEL_HANDLE | sdk::GNUNET_WFP_OBJ_CASE_INSENSITIVE)
                .cast_unsigned(),
            SecurityDescriptor: core::ptr::null_mut(),
            SecurityQualityOfService: core::ptr::null_mut(),
        };
        // SAFETY: zero is a valid initial output representation; the SDK writes
        // this status block before the original synchronous create returns.
        let mut io: sdk::IO_STATUS_BLOCK = unsafe { core::mem::zeroed() };
        let mut original = core::ptr::null_mut();
        self.device = Device::Published(device);
        // SAFETY: actual identity/extension/dispatch publication precedes this
        // release, allowing the immediate self-open to reach only ready state.
        unsafe { (*device.as_ptr()).Flags &= !sdk::DO_DEVICE_INITIALIZING };
        // SAFETY: this private original name targets our synchronous CREATE;
        // counted inputs and outputs live until return, with special APCs enabled.
        let status = unsafe {
            sdk::ZwCreateFile(
                &raw mut original,
                (sdk::GNUNET_WFP_FILE_READ_DATA | sdk::GNUNET_WFP_SYNCHRONIZE).cast_unsigned(),
                &raw mut attributes,
                &raw mut io,
                core::ptr::null_mut(),
                0,
                0,
                sdk::GNUNET_WFP_FILE_OPEN.cast_unsigned(),
                (sdk::GNUNET_WFP_FILE_NON_DIRECTORY_FILE
                    | sdk::GNUNET_WFP_FILE_SYNCHRONOUS_IO_NONALERT)
                    .cast_unsigned(),
                core::ptr::null_mut(),
                0,
            )
        };
        if status != sdk::GNUNET_WFP_STATUS_SUCCESS {
            let error = Error::Native {
                operation: "ZwCreateFile",
                status,
            };
            self.file = if status < 0 {
                File::OpenRefused(error)
            } else {
                File::Uncertain {
                    original: NonNull::new(original),
                    error,
                }
            };
            return Err(error);
        }
        let Some(original) = NonNull::new(original) else {
            self.file = File::Uncertain {
                original: None,
                error: Error::MissingHandle,
            };
            return Err(Error::MissingHandle);
        };
        self.file = File::Open(original);
        Ok(())
    }

    /// Close only the original handle after successful independent retirement.
    ///
    /// # Errors
    /// Returns the original native refusal. Failed close custody is retained,
    /// and subsequent calls return its cached outcome without reusing the handle.
    ///
    /// # Safety
    /// All fallible WFP/native retirement must have succeeded. Keep a separate
    /// live maintenance file/IRP or equivalent real I/O-manager lifetime through
    /// this call and its return; closing this handle may remove the unload gate.
    /// The original kernel handle must not be closed by another component.
    /// Retain dispatch/state through synchronous anchor CLEANUP/CLOSE.
    pub unsafe fn close_after_retirement(&mut self) -> Result<bool, Error> {
        passive()?;
        let original = match self.file {
            File::Open(original) => original,
            File::CloseRefused { original, error } => {
                // Preserve the exact original value without issuing a second close.
                let _ = original;
                return Err(error);
            }
            File::Uncertain { original, error } => {
                // The native outcome did not prove this value usable or closed.
                let _ = original;
                return Err(error);
            }
            File::Unopened | File::OpenRefused(_) | File::Closed => return Ok(false),
        };
        let mode = sdk::GNUNET_WFP_KERNEL_MODE
            .try_into()
            .map_err(|_| Error::IncompatibleDevice)?;
        // SAFETY: this is our original OBJ_KERNEL_HANDLE and the explicit mode
        // is the SDK's KernelMode, independent of the maintenance IRP requestor.
        // Caller retains independent I/O lifetime and reentrant close dispatch.
        let status = unsafe { sdk::ObCloseHandle(original.as_ptr(), mode) };
        if status != sdk::GNUNET_WFP_STATUS_SUCCESS {
            let error = Error::Native {
                operation: "ObCloseHandle",
                status,
            };
            self.file = File::CloseRefused { original, error };
            return Err(error);
        }
        self.file = File::Closed;
        Ok(true)
    }

    /// Issue deletion once after the anchor's real file custody has ended.
    ///
    /// # Errors
    /// Refuses non-passive use or any retained/uncertain original file owner.
    ///
    /// # Safety
    /// All original file/IRP entries and extension borrowers have actually
    /// drained, normally in the I/O manager's unload environment or unpublished
    /// entry rollback. No subsequent dispatch may discover this original device.
    /// The bool records `IoDeleteDevice` issuance, not final object destruction.
    pub unsafe fn delete(&mut self) -> Result<bool, Error> {
        passive()?;
        if self.has_handle() {
            return Err(Error::HandleHeld);
        }
        let Some(original) = self.raw() else {
            return Ok(false);
        };
        // SAFETY: caller supplies actual original file/entry drain; the native
        // deletion operation is issued once and may defer object destruction.
        unsafe { sdk::IoDeleteDevice(original.as_ptr()) };
        self.device = Device::DeleteIssued;
        Ok(true)
    }
}

impl Default for Anchor {
    fn default() -> Self {
        Self::new()
    }
}

fn passive() -> Result<(), Error> {
    // SAFETY: the wrapper reads the current kernel IRQL at any IRQL.
    let current = unsafe { sdk::gnunet_wfp_current_irql() };
    if u32::from(current) == sdk::PASSIVE_LEVEL {
        Ok(())
    } else {
        Err(Error::Irql { current })
    }
}

fn native(operation: &'static str, status: sdk::NTSTATUS) -> Result<(), Error> {
    if status >= 0 {
        Ok(())
    } else {
        Err(Error::Native { operation, status })
    }
}

const fn wide<const N: usize>(bytes: &[u8; N]) -> [u16; N] {
    let mut output = [0; N];
    let mut index = 0;
    while index < N {
        output[index] = bytes[index] as u16;
        index += 1;
    }
    output
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "const input bounds both UNICODE_STRING byte lengths"
)]
fn counted<const N: usize>(buffer: &[u16; N]) -> sdk::UNICODE_STRING {
    const { assert!(N > 0 && N <= 32_767) };
    sdk::UNICODE_STRING {
        Length: ((N - 1) * 2) as u16,
        MaximumLength: (N * 2) as u16,
        Buffer: buffer.as_ptr().cast_mut(),
    }
}
