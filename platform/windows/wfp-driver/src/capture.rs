//! One owned nonpaged copy of an original outbound WFP UDP DNS body.
use crate::{path, sdk};
use core::{fmt, ptr::NonNull, slice};
use gnunet_wfp_dns::Path;

const UDP_HEADER_BYTES: usize = 8;
const DNS_HEADER_BYTES: usize = 12;
const POOL_TAG: u32 = u32::from_le_bytes(*b"GnDC");

/// Why an original indication could not supply one owned DNS query copy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// Fixed values or metadata do not describe a supported outbound UDP path.
    Path,
    /// The callback supplied no packet list.
    MissingPacket,
    /// The indication contains more than one packet list.
    ChainedPacket,
    /// The packet list supplied no network buffer.
    MissingBuffer,
    /// The packet list contains more than one network buffer.
    ChainedBuffer,
    /// A nonempty network buffer has no valid current MDL.
    MissingMdl,
    /// The UDP extent is too short or not representable.
    Extent,
    /// The original nonpaged copy could not be allocated.
    Allocation,
    /// NDIS could not provide a contiguous view of the original bytes.
    Mapping,
    /// The UDP length does not equal the original native datagram extent.
    Length,
    /// UDP header ports disagree with the original path or DNS destination.
    Ports,
    /// The DNS header identifies a response.
    Response,
}

impl fmt::Display for Refusal {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "DNS capture refused: {self:?}")
    }
}

impl core::error::Error for Refusal {}

/// Exact original UDP bytes in nonpaged storage. The original NBL is no
/// longer borrowed. The I/O owner must drop this value at IRQL <= DISPATCH_LEVEL.
#[must_use]
pub struct Captured {
    path: Path,
    bytes: PoolCopy,
}

impl Captured {
    /// Original local and remote WFP path observations.
    pub const fn path(&self) -> Path {
        self.path
    }

    /// Exact DNS body without a transport header.
    pub fn payload(&self) -> &[u8] {
        &self.bytes.as_slice()[UDP_HEADER_BYTES..]
    }
}

struct PoolCopy {
    bytes: NonNull<u8>,
    len: usize,
}

// SAFETY: PoolCopy uniquely owns a nonpaged kernel allocation. Read-only
// access follows the Rust loan and retirement at DISPATCH_LEVEL or below.
unsafe impl Send for PoolCopy {}

impl PoolCopy {
    fn new(len: usize) -> Result<Self, Refusal> {
        // SAFETY: private bounded allocation, zeroed NX nonpaged pool; caller
        // is the original callback at DISPATCH_LEVEL or below.
        let bytes = unsafe {
            sdk::ExAllocatePool2(
                sdk::GNUNET_WFP_POOL_FLAG_NON_PAGED as _,
                len as sdk::SIZE_T,
                POOL_TAG,
            )
        };
        let bytes = NonNull::new(bytes.cast()).ok_or(Refusal::Allocation)?;
        Ok(Self { bytes, len })
    }

    fn as_slice(&self) -> &[u8] {
        // SAFETY: this owner retains its original initialized len-byte allocation.
        unsafe { slice::from_raw_parts(self.bytes.as_ptr(), self.len) }
    }
}

impl Drop for PoolCopy {
    fn drop(&mut self) {
        // SAFETY: original tagged nonpaged allocation; the retained IRQL
        // contract permits release on the owning callback or device worker.
        unsafe { sdk::ExFreePoolWithTag(self.bytes.as_ptr().cast(), POOL_TAG) };
    }
}

/// Copy one original UDP DNS body without retaining native buffers. A split
/// MDL chain is gathered directly into the owned allocation by NDIS. A
/// contiguous native view is copied once after checking the UDP/DNS envelope.
///
/// # Errors
/// Refuses unsupported paths or buffers, allocation failure, invalid UDP
/// length/ports, response frames and unavailable NDIS mappings.
///
/// # Safety
/// Call only in the original outbound DATAGRAM_DATA callback at IRQL no higher
/// than DISPATCH_LEVEL. All arguments and the NBL/NB/MDL chain must belong to
/// that callback and remain stable and live through this call. Drop the result
/// at IRQL <= DISPATCH_LEVEL after any Rust borrows have retired.
pub unsafe fn copy(
    packet: *const sdk::NET_BUFFER_LIST,
    fixed: &sdk::FWPS_INCOMING_VALUES0,
    metadata: Option<&sdk::FWPS_INCOMING_METADATA_VALUES0>,
) -> Result<Captured, Refusal> {
    // SAFETY: these are the original callback's still-live observations.
    let path = unsafe { path::outbound(fixed, metadata) }.ok_or(Refusal::Path)?;
    if packet.is_null() || !packet.is_aligned() {
        return Err(Refusal::MissingPacket);
    }
    // SAFETY: the caller retains the original native list and buffer links.
    let buffer = unsafe {
        if !sdk::gnunet_wfp_nbl_next(packet).is_null() {
            return Err(Refusal::ChainedPacket);
        }
        sdk::gnunet_wfp_nbl_first_nb(packet)
    };
    if buffer.is_null() || !buffer.is_aligned() {
        return Err(Refusal::MissingBuffer);
    }
    // SAFETY: the original NB and MDL chain are live through synchronous access.
    let extent = unsafe {
        if !sdk::gnunet_wfp_nb_next(buffer).is_null() {
            return Err(Refusal::ChainedBuffer);
        }
        let mdl = sdk::gnunet_wfp_nb_current_mdl(buffer);
        if mdl.is_null() || !mdl.is_aligned() {
            return Err(Refusal::MissingMdl);
        }
        sdk::gnunet_wfp_nb_data_length(buffer)
    };
    let len = usize::try_from(extent).map_err(|_| Refusal::Extent)?;
    if !(UDP_HEADER_BYTES + DNS_HEADER_BYTES..=usize::from(u16::MAX)).contains(&len) {
        return Err(Refusal::Extent);
    }
    let bytes = PoolCopy::new(len)?;
    // Outbound DATAGRAM_DATA starts at the transport header. NDIS returns a
    // bounded direct view or copies into this driver's resident allocation.
    // SAFETY: original extent is stable, with len writable disjoint pool bytes.
    let view = unsafe { sdk::NdisGetDataBuffer(buffer, extent, bytes.bytes.as_ptr().cast(), 1, 0) };
    let view = NonNull::new(view.cast::<u8>()).ok_or(Refusal::Mapping)?;
    // SAFETY: this is an original contiguous view of the requested len bytes.
    let datagram = unsafe { slice::from_raw_parts(view.as_ptr(), len) };
    validate(datagram, path)?;
    if view != bytes.bytes {
        // SAFETY: the native view and newly allocated driver pool are disjoint.
        // The shared view is no longer used and the pool still has len bytes.
        unsafe { core::ptr::copy_nonoverlapping(view.as_ptr(), bytes.bytes.as_ptr(), len) };
    }
    Ok(Captured { path, bytes })
}

fn validate(datagram: &[u8], path: Path) -> Result<(), Refusal> {
    if usize::from(u16::from_be_bytes([datagram[4], datagram[5]])) != datagram.len() {
        return Err(Refusal::Length);
    }
    let ports = [
        u16::from_be_bytes([datagram[0], datagram[1]]),
        u16::from_be_bytes([datagram[2], datagram[3]]),
    ];
    if ports != path.ports() || ports[0] == 0 || ports[1] != 53 {
        return Err(Refusal::Ports);
    }
    if datagram[UDP_HEADER_BYTES + 2] & 0x80 != 0 {
        return Err(Refusal::Response);
    }
    Ok(())
}
