//! Official UDP communicator payload encryption and explicit public prefixes.
//!
//! Source GCM uses empty AAD. KID/enc prefixes are outside GCM and must never be
//! silently added to AAD. Key-cache selection/credit/replay and the initial
//! Elligator KEM plus identity confirmation remain the protocol owner's duties.
use crate::{Prk, gcm::Aes256Gcm, session};
use gnunet_types::Error;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// UDPBox/InitialKX common prefix width: selector32 then tag16.
pub const PREFIX_BYTES: usize = 48;
/// Encrypted UDPConfirmation width in the current standard byte-field profile:
/// peer32, signature64 and monotonic-timeBE64. It is not a signature check.
pub const CONFIRMATION_BYTES: usize = 104;

/// One derived datagram key/nonce, not a sequence/ACK admission capability.
/// No Clone/Debug or secret exporter is provided. Reusing the same serial under
/// the same master is the caller's protocol error, not hidden state here.
pub struct DatagramKey {
    cipher: Aes256Gcm,
    nonce: [u8; 12],
    kid: [u8; 32],
    serial: u32,
}
impl DatagramKey {
    /// Exact original get_iv_key/get_kid, with serialBE32 and nonce12. Serial0
    /// is the initial KX payload; acknowledged BOX serials start at1.
    pub fn derive(master: &Prk, serial: u32) -> Result<Self, Error> {
        let mut key = Zeroizing::new([0; 32]);
        let mut nonce = [0; 12];
        session::udp_key_iv(master, serial, &mut key, &mut nonce)?;
        let cipher = Aes256Gcm::from_bytes(*key);
        Ok(Self {
            cipher,
            nonce,
            kid: session::udp_key_id(master, serial)?,
            serial,
        })
    }
    /// Public key-cache selector. It is outside GCM's authenticated data.
    #[must_use]
    pub const fn kid(&self) -> &[u8; 32] {
        &self.kid
    }
    /// Public derived nonce; it is12 bytes in the pinned source.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }
    /// Serial used for derivation. It is not carried directly in the datagram.
    #[must_use]
    pub const fn serial(&self) -> u32 {
        self.serial
    }
    /// Encrypt the entire explicit confirmation/rekey/message/padding body.
    /// The caller supplies exactly the plaintext bytes and source-empty AAD is
    /// selected here. No random padding or application message is synthesized.
    pub fn seal_body(&self, bytes: &mut [u8]) -> Result<[u8; 16], Error> {
        self.cipher.seal(&self.nonce, &[], bytes)
    }
    /// Check the complete encrypted body before releasing plaintext. This does
    /// not authenticate a peer/enc/KID or commit any replay/ACK window.
    pub fn open_body(&self, bytes: &mut [u8], tag: &[u8; 16]) -> Result<(), Error> {
        self.cipher.open(&self.nonce, &[], bytes, tag)
    }
    /// Emit the official KID32||tag16||ciphertext BOX layout. Nonzero serial and
    /// nonempty body are required; the full UDP receive path only classifies
    /// lengths greater than48 as BOX candidates. ACK credit is caller authority.
    pub fn seal_box(&self, plaintext: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if self.serial == 0 || plaintext.is_empty() {
            return Err(Error::InvalidInput);
        }
        let needed = PREFIX_BYTES
            .checked_add(plaintext.len())
            .ok_or(Error::Overflow)?;
        if out.len() < needed {
            return Err(Error::Capacity);
        }
        crate::gcm::validate_lengths(
            u64::try_from(plaintext.len()).map_err(|_| Error::Overflow)?,
            0,
        )?;
        out[PREFIX_BYTES..needed].copy_from_slice(plaintext);
        let tag = self.seal_body(&mut out[PREFIX_BYTES..needed])?;
        out[..32].copy_from_slice(&self.kid);
        out[32..PREFIX_BYTES].copy_from_slice(&tag);
        Ok(needed)
    }
    /// Open a BOX only after matching this exact expected key-cache selector.
    /// This separate selector check models cache routing, not invented GCM AAD.
    /// A mismatched KID or tag erases the plaintext range; basic refusal is atomic.
    pub fn open_box(&self, packet: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if self.serial == 0 {
            return Err(Error::InvalidInput);
        }
        let view = BoxView::parse(packet)?;
        let n = view.ciphertext.len();
        if out.len() < n {
            return Err(Error::Capacity);
        }
        crate::gcm::validate_lengths(u64::try_from(n).map_err(|_| Error::Overflow)?, 0)?;
        if !bool::from(view.kid.ct_eq(&self.kid)) {
            out[..n].zeroize();
            return Err(Error::Authentication);
        }
        out[..n].copy_from_slice(view.ciphertext);
        self.open_body(&mut out[..n], view.tag)?;
        Ok(n)
    }
    /// Emit initial enc32||tag16||ciphertext using serial0. This only protects an
    /// already prepared opaque confirmation/payload/padding body. The caller
    /// must obtain the real Elligator shared secret and valid sender signature;
    /// successful encryption alone is not a complete authenticated handshake.
    pub fn seal_initial_payload(
        &self,
        enc: &[u8; 32],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if self.serial != 0 || plaintext.len() < CONFIRMATION_BYTES {
            return Err(Error::InvalidInput);
        }
        let needed = PREFIX_BYTES
            .checked_add(plaintext.len())
            .ok_or(Error::Overflow)?;
        if out.len() < needed {
            return Err(Error::Capacity);
        }
        crate::gcm::validate_lengths(
            u64::try_from(plaintext.len()).map_err(|_| Error::Overflow)?,
            0,
        )?;
        out[PREFIX_BYTES..needed].copy_from_slice(plaintext);
        let tag = self.seal_body(&mut out[PREFIX_BYTES..needed])?;
        out[..32].copy_from_slice(enc);
        out[32..PREFIX_BYTES].copy_from_slice(&tag);
        Ok(needed)
    }
    /// Open an initial encrypted payload using an explicitly selected master.
    /// The returned public enc is still unauthenticated by GCM. Source derives
    /// the master from that enc first, then separately verifies purpose-signed
    /// sender/receiver/enc/time. Neither operation is faked by this function.
    pub fn open_initial_payload<'a>(
        &self,
        packet: &'a [u8],
        out: &mut [u8],
    ) -> Result<(&'a [u8; 32], usize), Error> {
        if self.serial != 0 {
            return Err(Error::InvalidInput);
        }
        let view = InitialView::parse(packet)?;
        let n = view.ciphertext.len();
        if out.len() < n {
            return Err(Error::Capacity);
        }
        crate::gcm::validate_lengths(u64::try_from(n).map_err(|_| Error::Overflow)?, 0)?;
        out[..n].copy_from_slice(view.ciphertext);
        self.open_body(&mut out[..n], view.tag)?;
        Ok((view.enc, n))
    }
}
/// Borrowed UDPBox prefix; successful parsing is not KID/AEAD admission.
pub struct BoxView<'a> {
    /// Public external key-cache selector32.
    pub kid: &'a [u8; 32],
    /// Detached GCM tag16.
    pub tag: &'a [u8; 16],
    /// Entire encrypted body, including any encrypted padding/rekey.
    pub ciphertext: &'a [u8],
}
impl<'a> BoxView<'a> {
    /// Mirror the source BOX candidate width (>48); routing still belongs to
    /// the caller because KX uses the same prefix width with different meaning.
    pub fn parse(packet: &'a [u8]) -> Result<Self, Error> {
        if packet.len() <= PREFIX_BYTES {
            return Err(Error::Truncated);
        }
        Ok(Self {
            kid: packet[..32].try_into().map_err(|_| Error::Truncated)?,
            tag: packet[32..PREFIX_BYTES]
                .try_into()
                .map_err(|_| Error::Truncated)?,
            ciphertext: &packet[PREFIX_BYTES..],
        })
    }
}
/// Borrowed initial KX prefix; this does not decode Elligator or verify identity.
pub struct InitialView<'a> {
    /// Public Elligator encapsulation whose interpretation belongs to KEM.
    pub enc: &'a [u8; 32],
    /// Detached GCM tag16.
    pub tag: &'a [u8; 16],
    /// Encrypted confirmation and following message/padding bytes.
    pub ciphertext: &'a [u8],
}
impl<'a> InitialView<'a> {
    /// Require the exact source minimum:48-byte prefix plus104 confirmation.
    pub fn parse(packet: &'a [u8]) -> Result<Self, Error> {
        if packet.len() < PREFIX_BYTES + CONFIRMATION_BYTES {
            return Err(Error::Truncated);
        }
        Ok(Self {
            enc: packet[..32].try_into().map_err(|_| Error::Truncated)?,
            tag: packet[32..PREFIX_BYTES]
                .try_into()
                .map_err(|_| Error::Truncated)?,
            ciphertext: &packet[PREFIX_BYTES..],
        })
    }
}
