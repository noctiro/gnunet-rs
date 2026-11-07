//! Actual official Messenger cryptography. These operations establish exactly
//! the documented cryptographic check, never room/member/epoch authorization.
//! Callers own key selection, trust, nonce lifecycle, storage and native effects.
use core::fmt;
pub use gnunet_crypto::Entropy;
pub use gnunet_session_crypto::exchange::{EcdhePublic, EcdheSecret};
use gnunet_types::Error as Fault;
use zeroize::{Zeroize, Zeroizing};
/// Official epoch/group HMAC and shared-key ACCESS operations.
pub mod group;
/// Official PRIVATE, SECRET and TRANSCRIPT encrypted/inner message operations.
pub mod message;
/// Actual private epoch/encryption record AEAD and secret ownership.
pub mod records;
/// Actual member/peer signature and short-message hash paths.
pub mod signature;
/// Protocol/crypto failure. No missing official authorization MAC is invented.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Actual bounded codec, entropy or cryptographic failure.
    Protocol(Fault),
    /// The active192-byte AUTHORIZATION transmission omits the separate MAC16
    /// required by its HMAC/decryptor. Official received bytes cannot supply it.
    AuthorizationMacOmitted,
}
impl From<Fault> for Error {
    fn from(error: Fault) -> Self {
        Self::Protocol(error)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "Messenger crypto: {error:?}"),
            Self::AuthorizationMacOmitted => {
                f.write_str("official AUTHORIZATION omits its required MAC")
            }
        }
    }
}
impl core::error::Error for Error {}
/// Exclusively owned official AEAD/shared key32. No Clone, Hash, raw public
/// getter or serialization trait exists; every temporary/key is erased on drop.
/// This owner is a cryptographic capability, not proof of room/epoch authority.
pub struct AeadKey(Zeroizing<[u8; 32]>);
impl fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AeadKey([REDACTED])")
    }
}
impl AeadKey {
    /// Import a caller-owned official raw shared key and erase this input copy.
    /// Caller remains responsible for erasure and authorization of other copies.
    pub fn from_bytes(mut bytes: [u8; 32]) -> Self {
        let result = Self(Zeroizing::new(bytes));
        bytes.zeroize();
        result
    }
    /// Draw exactly32 bytes from an explicit real entropy owner. Partial output
    /// is erased on failure; no default/mock/randomness source is substituted.
    pub fn generate(entropy: &mut impl Entropy) -> Result<Self, Error> {
        let mut bytes = Zeroizing::new([0; 32]);
        entropy.fill(bytes.as_mut()).map_err(|_| Fault::Entropy)?;
        Ok(Self(bytes))
    }
    /// Derive the official epoch/group successor key. This is cryptography,
    /// not authorization: the state owner must first prove the previous group
    /// complete and every previous participant belongs to the new epoch.
    /// The reference uses sizeof salts (including NUL), epoch64 then identifier32.
    pub fn derive_epoch(
        &self,
        epoch: &[u8; 64],
        identifier: &[u8; 32],
        group: bool,
    ) -> Result<Self, Error> {
        let mut output = Zeroizing::new([0; 32]);
        let salt = if group {
            group::GROUP_SALT
        } else {
            group::EPOCH_SALT
        };
        gnunet_crypto::hkdf_gnunet(salt, self.0.as_ref(), &[epoch, identifier], output.as_mut())?;
        Ok(Self(output))
    }
    /// Explicit capability equality, with no secret export or hash identifier.
    pub fn constant_time_eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        bool::from(self.0[..].ct_eq(&other.0[..]))
    }
    /// Consume and erase an old shared-key capability.
    pub fn clear(self) {
        drop(self);
    }
}
