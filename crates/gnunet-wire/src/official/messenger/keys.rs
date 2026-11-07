//! Structural public HPKE key and encrypted one-shot packet views. No private
//! key parsing, scalar conversion, encapsulation, authentication or crypto runs.
use super::{SensitiveBytes, array};
use core::fmt;
use gnunet_types::Error;
/// Active X25519 HPKE public serialization: BE32 tag0 plus32 public bytes.
pub const HPKE_PUBLIC_LEN: usize = 36;
/// Actual one-shot encapsulation32 plus authentication tag16.
pub const HPKE_OVERHEAD: usize = 48;
/// Borrowed exact active HPKE public-key serialization.
#[derive(Clone, Copy)]
pub struct HpkePublicKey<'a>(&'a [u8; 36]);
impl<'a> HpkePublicKey<'a> {
    /// Validate length and the only active tag0, without point validation.
    pub fn new(bytes: &'a [u8]) -> Result<Self, Error> {
        let raw: &[u8; 36] = bytes.try_into().map_err(|_| Error::Malformed)?;
        if u32::from_be_bytes(*array(raw, 0)?) != 0 {
            return Err(Error::Unsupported);
        }
        Ok(Self(raw))
    }
    /// Exact serialized public bytes.
    pub const fn as_bytes(self) -> &'a [u8; 36] {
        self.0
    }
    /// Original32-byte X25519 public representation.
    pub fn public_bytes(self) -> &'a [u8] {
        &self.0[4..]
    }
}
impl fmt::Debug for HpkePublicKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HpkePublicKey(X25519, unverified)")
    }
}
/// Actual HPKE one-shot packet: public encapsulation32, encrypted bytes and a
/// final16-byte tag. Valid framing is not successful decapsulation/decryption.
#[derive(Clone, Copy)]
pub struct HpkeCiphertext<'a>(SensitiveBytes<'a>);
impl<'a> HpkeCiphertext<'a> {
    /// Validate the complete minimum framing without asserting authentication.
    pub fn new(bytes: SensitiveBytes<'a>) -> Result<Self, Error> {
        if bytes.len() < HPKE_OVERHEAD {
            return Err(Error::Truncated);
        }
        Ok(Self(bytes))
    }
    /// Exact original packet bytes, potentially sensitive private-room data.
    pub const fn expose(self) -> SensitiveBytes<'a> {
        self.0
    }
    /// Exact32-byte public encapsulation.
    pub fn encapsulation(self) -> Result<&'a [u8; 32], Error> {
        array(self.0.expose(), 0)
    }
    /// Original ciphertext and final AEAD tag, as passed to HPKE open.
    pub fn ciphertext_and_tag(self) -> SensitiveBytes<'a> {
        SensitiveBytes::new(&self.0.expose()[32..])
    }
    /// Ciphertext without the final16-byte authentication tag.
    pub fn ciphertext(self) -> SensitiveBytes<'a> {
        SensitiveBytes::new(&self.0.expose()[32..self.0.len() - 16])
    }
    /// Carried16-byte tag, not a verification result.
    pub fn tag(self) -> Result<&'a [u8; 16], Error> {
        array(self.0.expose(), self.0.len() - 16)
    }
}
impl fmt::Debug for HpkeCiphertext<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("HpkeCiphertext(unverified)")
            .field(&self.0.len())
            .finish()
    }
}
