//! Explicit fallible original entropy and bounded zlib ports.
use alloc::vec::Vec;
use gnunet_types::Error;
/// Actual live caller entropy. A failure is not a deterministic fallback seed.
pub trait Random {
    /// Fill every byte with actual entropy or return the original classification.
    /// Native owners retain the first actual provider failure and erase partial output.
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error>;
}
/// One complete bounded zlib member, independent of any particular SET wire ABI.
pub trait Compression {
    /// Compress exactly this raw input, refusing output exceeding the given bound.
    fn compress(&mut self, input: &[u8], limit: usize) -> Result<Vec<u8>, Error>;
    /// Decompress one complete member with checksum/EOF and no trailing input,
    /// requiring precisely expected bytes and expected no larger than limit.
    fn decompress_exact(
        &mut self,
        input: &[u8],
        expected: usize,
        limit: usize,
    ) -> Result<Vec<u8>, Error>;
}
/// Original algorithm ports; a caller implementation owns their actual failures.
pub trait Ports: Random + Compression {}
impl<T: Random + Compression> Ports for T {}
