//! Actual native cryptographic entropy and opaque IDENTITY signing ownership.
//! Creating these types does not read any private-key file or invoke a tool.
use gnunet_messenger_core::{PublicKey, crypto};
use gnunet_types::Error as Fault;
use std::fmt;
/// Actual operating-system entropy port. The original OS error is retained,
/// separately from the common crypto trait's bounded failure classification.
#[derive(Default)]
pub struct OsEntropy {
    last: Option<getrandom::Error>,
}
impl OsEntropy {
    /// Create no RNG request, native task or file access.
    pub const fn new() -> Self {
        Self { last: None }
    }
    /// Original first unconsumed OS entropy failure, without key/RNG contents.
    pub const fn last_error(&self) -> Option<&getrandom::Error> {
        self.last.as_ref()
    }
    /// Consume the original first OS failure after recording it externally.
    pub fn take_error(&mut self) -> Option<getrandom::Error> {
        self.last.take()
    }
}
impl fmt::Debug for OsEntropy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OsEntropy([REDACTED])")
    }
}
impl crypto::Entropy for OsEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Fault> {
        match getrandom::fill(output) {
            Ok(()) => Ok(()),
            Err(error) => {
                if self.last.is_none() {
                    self.last = Some(error);
                }
                Err(Fault::EntropyUnavailable)
            }
        }
    }
}
/// Opaque generation of an explicitly supplied local identity. It is neither a
/// public-key hash nor a wire ego ID and cannot adopt another high-level owner.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Identity {
    pub(crate) owner: u64,
    pub(crate) generation: u64,
}
impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}
pub(crate) struct Signer {
    pub id: Identity,
    pub public: PublicKey,
    pub secret: gnunet_identity::SecretKey,
}
impl fmt::Debug for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IdentitySigner([REDACTED])")
    }
}
