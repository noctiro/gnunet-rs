//! Shared bounded complete-member zlib, adapted to the existing SETU port.
use crate::Codec;
use gnunet_types::Error;
/// Caller-owned reusable state implementing the SETU-specific compression port.
/// The shared primitive owns no SETU or generic SET protocol state.
pub struct Zlib(gnunet_compression::Zlib);
impl Zlib {
    /// Allocate the same fixed compression state once, without native IO.
    #[must_use]
    pub fn new() -> Self {
        Self(gnunet_compression::Zlib::new())
    }
}
impl Default for Zlib {
    fn default() -> Self {
        Self::new()
    }
}
impl Codec for Zlib {
    fn compress(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        self.0.compress(input, output)
    }
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        self.0.decompress(input, output)
    }
}
