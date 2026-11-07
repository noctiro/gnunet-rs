//! Explicit entropy and bounded shared complete-member zlib for generic SET.
use gnunet_compression::Zlib;
use gnunet_set::{Compression, Random};
use gnunet_types::Error;

/// Actual foreground providers. Their state belongs to this caller, not a peer
/// or a hidden worker. The original first entropy-provider failure is retained.
pub struct NativePorts {
    codec: Zlib,
    entropy_failure: Option<getrandom::Error>,
}
impl NativePorts {
    /// Create one reusable compressor/inflater; this performs no entropy or IO.
    #[must_use]
    pub fn new() -> Self {
        Self {
            codec: Zlib::new(),
            entropy_failure: None,
        }
    }
    /// Consume the actual first native entropy error independently from the
    /// pure protocol's error classification. No replacement entropy is used.
    pub fn take_error(&mut self) -> Option<getrandom::Error> {
        self.entropy_failure.take()
    }
}
impl Default for NativePorts {
    fn default() -> Self {
        Self::new()
    }
}
impl Random for NativePorts {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(output).map_err(|error| {
            output.fill(0);
            if self.entropy_failure.is_none() {
                self.entropy_failure = Some(error);
            }
            Error::Entropy
        })
    }
}
fn storage(len: usize) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    output.try_reserve_exact(len).map_err(|_| Error::Capacity)?;
    output.resize(len, 0);
    Ok(output)
}
impl Compression for NativePorts {
    fn compress(&mut self, input: &[u8], limit: usize) -> Result<Vec<u8>, Error> {
        let mut output = storage(limit)?;
        let used = self.codec.compress(input, &mut output)?;
        output.truncate(used);
        Ok(output)
    }
    fn decompress_exact(
        &mut self,
        input: &[u8],
        expected: usize,
        limit: usize,
    ) -> Result<Vec<u8>, Error> {
        if expected > limit {
            return Err(Error::Capacity);
        }
        let mut output = storage(expected)?;
        if self.codec.decompress(input, &mut output)? != expected {
            return Err(Error::Malformed);
        }
        Ok(output)
    }
}
