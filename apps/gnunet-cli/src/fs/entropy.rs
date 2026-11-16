//! Protocol entropy adapter using the native system CSPRNG on every host.
use gnunet::{crypto::Entropy, types::Error};
pub(super) struct OsEntropy;
impl Entropy for OsEntropy {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        gnunet_native::entropy::fill(bytes).map_err(|_| Error::Entropy)
    }
}
