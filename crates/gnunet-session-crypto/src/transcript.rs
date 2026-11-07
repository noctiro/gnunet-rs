//! Official incremental SHA512 transcript and HMAC-SHA512, with no framing.
use sha2::{Digest, Sha512};
/// Fixed-storage SHA512 context with source-equivalent public checkpoint copying.
/// Aborting is ordinary drop; SHA2's zeroize feature erases its state/buffers.
#[derive(Clone, Default)]
pub struct Hash512State(Sha512);
impl Hash512State {
    /// Begin an empty standard SHA512 context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Append the next exact source bytes.
    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
    /// Consume the context and return its standard64-byte digest.
    #[must_use]
    pub fn finish(self) -> [u8; 64] {
        self.0.finalize().into()
    }
}
/// Standard source HMAC-SHA512 over concatenated parts, with erased key pads.
/// The key is caller owned; no implicit tag truncation or wire fields are added.
#[must_use]
pub fn hmac512(key: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    *crate::kdf::hmac512(key, parts)
}
