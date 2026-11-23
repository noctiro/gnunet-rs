//! Official SETU algorithms and original union operation ownership.
//! Default algorithms use caller storage. Set snapshots/service operations use
//! explicit bounded `alloc`; no thread, network, clock or persistence is hidden.
#![no_std]
#![forbid(unsafe_code)]
#[cfg(feature = "alloc")]
extern crate alloc;
/// Bounded original SETU full-set and differential peer operations.
pub mod fixed;
/// Official IBF key/checksum/index/peeling and serialized bucket slices.
pub mod ibf;
mod mode;
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

    /// Visit bounded decompressed bytes in wire order. Callers must treat the
    /// visit as provisional until the entire zlib member has passed validation.
    /// The default uses a complete output buffer. A streaming codec can reuse
    /// just one DEFLATE history window regardless of the expected extent.
    fn visit_decompressed(
        &mut self,
        input: &[u8],
        workspace: &mut [u8],
        limit: usize,
        visit: &mut dyn FnMut(&[u8]) -> Result<(), gnunet_types::Error>,
    ) -> Result<usize, gnunet_types::Error> {
        let output = workspace
            .get_mut(..limit)
            .ok_or(gnunet_types::Error::Capacity)?;
        let written = self.decompress(input, output)?;
        visit(
            output
                .get(..written)
                .ok_or(gnunet_types::Error::Malformed)?,
        )?;
        Ok(written)
    }
}

/// Allocation-free zlib member codec for the bounded SETU profile.
#[cfg(feature = "fixed-zlib")]
pub use gnunet_compression::FixedZlib;

#[cfg(feature = "fixed-zlib")]
impl Codec for FixedZlib {
    fn compress(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, gnunet_types::Error> {
        Self::compress(self, input, output)
    }

    fn decompress(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, gnunet_types::Error> {
        Self::decompress(self, input, output)
    }

    fn visit_decompressed(
        &mut self,
        input: &[u8],
        workspace: &mut [u8],
        limit: usize,
        visit: &mut dyn FnMut(&[u8]) -> Result<(), gnunet_types::Error>,
    ) -> Result<usize, gnunet_types::Error> {
        Self::visit_decompressed(self, input, workspace, limit, visit)
    }
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

fn element_hash(
    element: wire::Element<'_>,
    abi: wire::Abi,
) -> Result<[u8; 64], gnunet_types::Error> {
    if element.data.len() > usize::from(u16::MAX) - 8 {
        return Err(gnunet_types::Error::TooLarge);
    }
    let size = u16::try_from(element.data.len()).map_err(|_| gnunet_types::Error::TooLarge)?;
    Ok(gnunet_crypto::hash512_parts(&[
        &abi.order.u16(size),
        &abi.order.u16(element.kind),
        element.data,
    ]))
}
