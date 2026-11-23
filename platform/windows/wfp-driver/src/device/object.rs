//! Original legacy control-device ownership, separate from file dispatch.
//!
//! The I/O manager allocates the device and its nonpaged extension. The secure
//! creation routine requires the WDK's `Wdmsec.lib`; it is not an undocumented
//! kernel export. No device is published until its caller installs the actual
//! dispatch table and prepares every state allocation those entries can reach.
use crate::sdk;
use core::{fmt, ptr::NonNull};

const DEVICE_NAME: &[u16; 27] = &wide(b"\\Device\\GNUnetDnsIntercept\0");
// Explicit Global avoids binding the service endpoint to a caller's local
// DOS-device namespace. Ordinary Win32 lookup resolves this global link.
const SYMBOLIC_NAME: &[u16; 38] = &wide(b"\\DosDevices\\Global\\GNUnetDnsIntercept\0");
const MAINTENANCE_NAME: &[u16; 29] = &wide(b"\\Device\\GNUnetDnsMaintenance\0");
const MAINTENANCE_LINK: &[u16; 40] = &wide(b"\\DosDevices\\Global\\GNUnetDnsMaintenance\0");
const SYSTEM_ONLY: &[u16; 16] = &wide(b"D:P(A;;GA;;;SY)\0");

// A dedicated setup class lets administrators override this device's default
// security without changing an unrelated class. No existing class is reused.
const DEVICE_CLASS: sdk::GUID = sdk::GUID {
    Data1: 0x3508_7504,
    Data2: 0x4498,
    Data3: 0x44ec,
    Data4: [0x88, 0x8b, 0x84, 0x9b, 0xda, 0x68, 0xb2, 0x31],
};
const MAINTENANCE_CLASS: sdk::GUID = sdk::GUID {
    Data1: 0x1f5c_67d1,
    Data2: 0x2f89,
    Data3: 0x4518,
    Data4: [0x98, 0xec, 0x15, 0x26, 0x7e, 0x1e, 0x15, 0x1b],
};

/// Native failure or an invalid transition of this original device owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// This owner has already attempted a successful original creation.
    AlreadyCreated,
    /// Publication requires a newly prepared original device.
    NotPrepared,
    /// Remove the original symbolic link before issuing device deletion.
    StillPublished,
    /// Actual native refusal; earlier acquired resources remain owned.
    Native {
        /// WDK routine that returned the status.
        operation: &'static str,
        /// Unmodified native NTSTATUS.
        status: sdk::NTSTATUS,
    },
    /// Secure creation returned success without its original device pointer.
    MissingDevice,
    /// Registry overrides supplied a device outside this control protocol's
    /// required native type, exclusive access or secure-open characteristics.
    IncompatibleDevice,
    /// The actual caller is not at `PASSIVE_LEVEL`.
    Irql {
        /// IRQL returned by the kernel.
        current: u8,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyCreated => output.write_str("original control device was already created"),
            Self::NotPrepared => output.write_str("control device is not prepared for publication"),
            Self::StillPublished => {
                output.write_str("control device symbolic link remains published")
            }
            Self::Native { operation, status } => {
                write!(output, "{operation} failed with NTSTATUS {status:#010x}")
            }
            Self::MissingDevice => output.write_str("secure creation returned no device object"),
            Self::IncompatibleDevice => {
                output.write_str("native control device properties do not match the protocol")
            }
            Self::Irql { current } => write!(
                output,
                "control device operation requires passive IRQL, got {current}"
            ),
        }
    }
}
impl core::error::Error for Error {}

enum State {
    Empty,
    Prepared(NonNull<sdk::DEVICE_OBJECT>),
    Linked(NonNull<sdk::DEVICE_OBJECT>),
    Published(NonNull<sdk::DEVICE_OBJECT>),
    Unpublished(NonNull<sdk::DEVICE_OBJECT>),
    DeleteIssued,
}

#[derive(Clone, Copy)]
enum Endpoint {
    Packet,
    Maintenance,
}

impl Endpoint {
    fn device(self) -> sdk::UNICODE_STRING {
        match self {
            Self::Packet => counted(DEVICE_NAME),
            Self::Maintenance => counted(MAINTENANCE_NAME),
        }
    }

    fn link(self) -> sdk::UNICODE_STRING {
        match self {
            Self::Packet => counted(SYMBOLIC_NAME),
            Self::Maintenance => counted(MAINTENANCE_LINK),
        }
    }

    fn class(self) -> &'static sdk::GUID {
        match self {
            Self::Packet => &DEVICE_CLASS,
            Self::Maintenance => &MAINTENANCE_CLASS,
        }
    }
}

/// One original exclusive, buffered, secure control device and its DOS link.
///
/// Native failures preserve ownership. No Drop implementation waits, deletes a
/// link or issues deletion. In particular, issuing `IoDeleteDevice` does not
/// establish that existing file objects, callbacks or the allocation are gone.
#[must_use]
pub struct Object {
    state: State,
    endpoint: Endpoint,
}

impl Object {
    /// Construct an owner without native effects.
    pub const fn new() -> Self {
        Self {
            state: State::Empty,
            endpoint: Endpoint::Packet,
        }
    }

    pub(crate) const fn maintenance() -> Self {
        Self {
            state: State::Empty,
            endpoint: Endpoint::Maintenance,
        }
    }

    /// Borrow the original pointer for extension setup and WFP registration.
    /// This observation grants no reference or independent lifetime.
    #[must_use]
    pub const fn raw(&self) -> Option<NonNull<sdk::DEVICE_OBJECT>> {
        match self.state {
            State::Prepared(device)
            | State::Linked(device)
            | State::Published(device)
            | State::Unpublished(device) => Some(device),
            State::Empty | State::DeleteIssued => None,
        }
    }

    /// Create the original named device with a System-only default ACL.
    ///
    /// The dedicated device class permits explicit administrator security
    /// overrides through the documented WDK mechanism. Actual exclusive access,
    /// secure-open characteristics and device type must still match this
    /// protocol. A name collision never adopts an existing device. The I/O
    /// manager supplies a zeroed nonpaged extension of `extension_bytes`; no
    /// Rust value has yet been initialized there. Buffered I/O is selected
    /// before publication.
    ///
    /// # Safety
    /// Call at `PASSIVE_LEVEL` from exclusive driver preparation with the
    /// original live driver object. This is a legacy control device, not an FDO
    /// or a filter attached to a plug-and-play stack. Its driver and original
    /// dispatch code must remain live until all external entries have drained.
    /// This driver must control the original native and DOS names exclusively;
    /// another component must not remove or replace them while owned. Keep this
    /// owner on every partial failure. Initialize extension storage with its
    /// actual layout and alignment before publishing it.
    ///
    /// # Errors
    /// Refuses reuse, incorrect IRQL, a native creation error or a missing
    /// output or incompatible native properties. A successfully created device
    /// with incompatible properties remains owned for deletion and cannot be
    /// published. No DOS symbolic link is created by this operation.
    pub unsafe fn prepare(
        &mut self,
        driver: NonNull<sdk::DRIVER_OBJECT>,
        extension_bytes: u32,
    ) -> Result<(), Error> {
        passive()?;
        if !matches!(self.state, State::Empty) {
            return Err(Error::AlreadyCreated);
        }
        let mut name = self.endpoint.device();
        let security = counted(SYSTEM_ONLY);
        let mut device = core::ptr::null_mut();
        // SAFETY: original driver, passive caller and synchronous counted
        // strings meet WDK requirements. The SDK owns the returned allocation.
        let status = unsafe {
            sdk::WdmlibIoCreateDeviceSecure(
                driver.as_ptr(),
                extension_bytes,
                &raw mut name,
                sdk::FILE_DEVICE_UNKNOWN,
                sdk::FILE_DEVICE_SECURE_OPEN,
                1,
                &raw const security,
                self.endpoint.class(),
                &raw mut device,
            )
        };
        check("WdmlibIoCreateDeviceSecure", status)?;
        let device = NonNull::new(device).ok_or(Error::MissingDevice)?;
        // Retain the original allocation even when class registry overrides
        // violate this protocol. Such an owner permits deletion, not publication.
        self.state = State::Unpublished(device);
        // SAFETY: this original device remains unpublished with its I/O-manager
        // initialization flag set. Preparation exclusively owns these flags.
        let (device_type, characteristics, flags) = unsafe {
            (
                (*device.as_ptr()).DeviceType,
                (*device.as_ptr()).Characteristics,
                (*device.as_ptr()).Flags,
            )
        };
        if device_type != sdk::FILE_DEVICE_UNKNOWN
            || characteristics & sdk::FILE_DEVICE_SECURE_OPEN == 0
            || flags & sdk::DO_EXCLUSIVE == 0
            || flags & sdk::DO_DEVICE_INITIALIZING == 0
            || flags & sdk::DO_DIRECT_IO != 0
        {
            return Err(Error::IncompatibleDevice);
        }
        // SAFETY: only the caller's unpublished preparation writes Flags;
        // there is no Rust reference covering the I/O manager's whole object.
        unsafe { (*device.as_ptr()).Flags = flags | sdk::DO_BUFFERED_IO };
        self.state = State::Prepared(device);
        Ok(())
    }

    /// Install the DOS link while the I/O manager still rejects device opens.
    ///
    /// # Safety
    /// Call at `PASSIVE_LEVEL` during exclusive preparation of the device.
    ///
    /// # Errors
    /// Refuses incorrect IRQL, invalid phase or a native link creation error.
    pub unsafe fn prepare_link(&mut self) -> Result<(), Error> {
        passive()?;
        let State::Prepared(device) = self.state else {
            return Err(Error::NotPrepared);
        };
        let mut symbolic = self.endpoint.link();
        let mut target = self.endpoint.device();
        // SAFETY: the original prepared device and both strings are live; the
        // caller has prepared every dispatch entry for publication.
        check("IoCreateSymbolicLink", unsafe {
            sdk::IoCreateSymbolicLink(&raw mut symbolic, &raw mut target)
        })?;
        self.state = State::Linked(device);
        Ok(())
    }

    /// Enable dispatch after the final fallible operation in driver entry.
    ///
    /// # Safety
    /// The original link and every reachable dispatch owner must be ready.
    /// The caller must handle immediate opens and retain native owners
    /// through actual retirement.
    pub unsafe fn enable(&mut self) {
        let State::Linked(device) = self.state else {
            return;
        };
        self.state = State::Published(device);
        // SAFETY: exclusive final preparation ends only after the original
        // global link exists and all real dispatch state is already prepared.
        unsafe { (*device.as_ptr()).Flags &= !sdk::DO_DEVICE_INITIALIZING };
    }

    /// Remove only this owner's original DOS link, preserving native failures.
    /// Existing files and direct native-name entries have independent lifetimes.
    ///
    /// # Safety
    /// Call exclusively at `PASSIVE_LEVEL` after closing create admission in
    /// the real dispatch state. Exclude external deletion or replacement of
    /// this original global DOS name until return; deletion is by name. Keep
    /// the original device, extension, dispatch
    /// code and all native resources live through their independent drains.
    /// Removing the link neither closes a file nor cancels or completes an IRP.
    ///
    /// # Errors
    /// Returns incorrect IRQL or the original native deletion refusal. A failed
    /// link remains owned, and this operation may be retried before deletion.
    pub unsafe fn unpublish(&mut self) -> Result<bool, Error> {
        passive()?;
        let device = match self.state {
            State::Linked(device) | State::Published(device) => device,
            _ => return Ok(false),
        };
        let mut symbolic = self.endpoint.link();
        // SAFETY: this owner created and still owns this exact original link.
        check("IoDeleteSymbolicLink", unsafe {
            sdk::IoDeleteSymbolicLink(&raw mut symbolic)
        })?;
        self.state = State::Unpublished(device);
        Ok(true)
    }

    /// Roll back cold driver entry even if deleting its DOS link was refused.
    ///
    /// # Safety
    /// The caller owns preparation at `PASSIVE_LEVEL`. This original device
    /// has never admitted any file, dispatch or native borrower.
    ///
    /// # Errors
    /// Returns the original link deletion error. A stale link can remain in
    /// the namespace after the inaccessible device has been deleted.
    pub unsafe fn discard_unenabled(&mut self) -> Result<(), Error> {
        passive()?;
        if matches!(self.state, State::Published(_)) {
            return Err(Error::StillPublished);
        }
        // SAFETY: cold rollback owns the original prepared namespace.
        let removed = unsafe { self.unpublish() };
        if let Some(device) = self.raw() {
            // SAFETY: initialization never exposed this pointer to callers.
            unsafe { sdk::IoDeleteDevice(device.as_ptr()) };
            self.state = State::DeleteIssued;
        }
        removed.map(|_| ())
    }

    /// Issue `IoDeleteDevice` once for the original unpublished device.
    /// The bool records issuance, not native destruction or callback completion.
    ///
    /// # Safety
    /// Call exclusively at `PASSIVE_LEVEL`. The original link must be removed,
    /// create admission closed, and every callback, dispatch, native registration
    /// and resource borrowing the extension independently drained. Release all
    /// resources the driver placed in its extension before this call. Do not
    /// unload callback code while original file objects can still invoke it.
    /// The I/O manager may defer destruction until outstanding references end.
    ///
    /// # Errors
    /// Refuses incorrect IRQL or a still-published link. The native deletion
    /// routine returns no status; this owner never invents a success receipt for
    /// final object destruction and never retries its original pointer.
    pub unsafe fn delete(&mut self) -> Result<bool, Error> {
        passive()?;
        let device = match self.state {
            State::Linked(_) | State::Published(_) => return Err(Error::StillPublished),
            State::Prepared(device) | State::Unpublished(device) => device,
            State::Empty | State::DeleteIssued => return Ok(false),
        };
        // SAFETY: the caller proved retirement of every original extension
        // borrower. The I/O manager accepts this exact original pointer once.
        unsafe { sdk::IoDeleteDevice(device.as_ptr()) };
        self.state = State::DeleteIssued;
        Ok(true)
    }
}

impl Default for Object {
    fn default() -> Self {
        Self::new()
    }
}

fn passive() -> Result<(), Error> {
    // SAFETY: the WDK wrapper reads the current processor's kernel IRQL.
    let current = unsafe { sdk::gnunet_wfp_current_irql() };
    if u32::from(current) == sdk::PASSIVE_LEVEL {
        Ok(())
    } else {
        Err(Error::Irql { current })
    }
}

fn check(operation: &'static str, status: sdk::NTSTATUS) -> Result<(), Error> {
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
    reason = "the const assertion bounds both byte lengths to UNICODE_STRING's u16 fields"
)]
fn counted<const N: usize>(buffer: &[u16; N]) -> sdk::UNICODE_STRING {
    const { assert!(N > 0 && N <= 32_767) };
    // The three private constants are null-terminated; their maximum byte
    // lengths are checked at monomorphization without a kernel panic path.
    sdk::UNICODE_STRING {
        Length: ((N - 1) * 2) as u16,
        MaximumLength: (N * 2) as u16,
        Buffer: buffer.as_ptr().cast_mut(),
    }
}
