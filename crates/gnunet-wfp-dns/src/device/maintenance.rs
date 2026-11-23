//! Local buffered controls for retiring an installed Windows DNS driver.

/// Canonical path of the separate protected maintenance device.
pub const PATH: &str = r"\\.\GNUnetDnsMaintenance";
/// Exact protected device name used after normal namespace retirement. After
/// completed handoff, a read-only file returns one fixed terminal progress
/// record while the driver remains loaded.
pub const NATIVE_PATH: &str = r"\\?\GLOBALROOT\Device\GNUnetDnsMaintenance";
/// Buffered retirement control requiring read and write access.
pub const IOCTL_RETIRE: u32 = 0x0022_e010;
/// Size of the fixed little-endian operation selector.
pub const REQUEST_BYTES: usize = 4;
/// Size of the fixed phase and signed NTSTATUS response.
pub const PROGRESS_BYTES: usize = 8;

/// Independent passive operations on the original driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Request {
    /// Advance bounded preparation or observe the current phase.
    Poll = 0,
    /// Continue native finalization once its passive preconditions hold.
    Finalize = 1,
}

impl Request {
    /// Encode one exact local request.
    pub const fn encode(self) -> [u8; REQUEST_BYTES] {
        (self as u32).to_le_bytes()
    }

    /// Decode an exact extent and a supported operation.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        match u32::from_le_bytes(bytes.try_into().ok()?) {
            0 => Some(Self::Poll),
            1 => Some(Self::Finalize),
            _ => None,
        }
    }
}

/// Driver retirement boundaries observable through the original control file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Phase {
    /// Existing packet dispatches and runtime admissions are draining.
    Admission = 0,
    /// Original flow deletion callbacks remain outstanding.
    FlowDeletion = 1,
    /// A caller can explicitly enter the passive native wait.
    PreparedForNativeWait = 2,
    /// Native handles retired and completion accounting remains.
    Completion = 3,
    /// Original native resources and the unload anchor have retired.
    /// The maintenance file still has to close before Windows can unload.
    NativeRetired = 4,
    /// An original retirement operation was refused.
    Failed = 5,
}

/// Exact response to a successful maintenance control transport operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Progress {
    /// Current verified retirement boundary.
    pub phase: Phase,
    /// Nonzero NTSTATUS for a failed retirement, or zero otherwise.
    pub status: i32,
}

impl Progress {
    /// Encode the phase and native status in little-endian order.
    pub fn encode(self) -> [u8; PROGRESS_BYTES] {
        let mut bytes = [0; PROGRESS_BYTES];
        bytes[..4].copy_from_slice(&(self.phase as u32).to_le_bytes());
        bytes[4..].copy_from_slice(&self.status.to_le_bytes());
        bytes
    }

    /// Decode an exact response, requiring consistency between phase and status.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (phase, status) = bytes.split_first_chunk::<4>()?;
        let phase = match u32::from_le_bytes(*phase) {
            0 => Phase::Admission,
            1 => Phase::FlowDeletion,
            2 => Phase::PreparedForNativeWait,
            3 => Phase::Completion,
            4 => Phase::NativeRetired,
            5 => Phase::Failed,
            _ => return None,
        };
        let status = i32::from_le_bytes(status.try_into().ok()?);
        match phase {
            Phase::Failed if status != 0 => Some(Self { phase, status }),
            Phase::Failed => None,
            _ if status == 0 => Some(Self { phase, status }),
            _ => None,
        }
    }
}
