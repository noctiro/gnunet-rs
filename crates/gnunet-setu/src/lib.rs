//! Official SETU algorithms and original union operation ownership.
//! Default algorithms use caller storage. Set snapshots/service operations use
//! explicit bounded `alloc`; no thread, network, clock or persistence is hidden.
#![no_std]
#![forbid(unsafe_code)]
#[cfg(feature = "alloc")]
extern crate alloc;
/// Official IBF key/checksum/index/peeling and serialized bucket slices.
pub mod ibf;
/// Official multi-strata insert/remove, raw serialization and difference estimate.
pub mod strata;
/// Borrowed active official IPC/P2P codecs, including explicit source ABI.
pub use gnunet_wire::official::setu as wire;
/// Bounded complete-member zlib port. Implementations must reject trailing input
/// and return actual output length, never manufacture estimator bytes.
pub trait Codec {
    /// Compress exact raw strata into the supplied bounded output.
    fn compress(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, gnunet_types::Error>;
    /// Inflate exact zlib member into supplied bounded output, requiring EOF/checksum.
    fn decompress(&mut self, input: &[u8], output: &mut [u8])
    -> Result<usize, gnunet_types::Error>;
}
/// Set/listener/incoming/evaluate/accept/cancel service composition ports.
#[cfg(feature = "alloc")]
pub mod service;
/// Immutable typed elements, bounded mutable sets and operation snapshots.
#[cfg(feature = "alloc")]
pub mod set;
/// Differential/full union protocol, original output leases and result events.
#[cfg(feature = "alloc")]
pub mod union;
/// Fixed-state pure Rust actual zlib capability; construction explicitly allocates.
#[cfg(feature = "zlib")]
pub mod zlib;
