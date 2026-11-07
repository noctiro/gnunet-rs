//! Actual encrypted epoch/HPKE-private record operations. GNS record signature,
//! zone ownership, room/epoch validity and storage commit are caller state gates.
use super::{AeadKey, EcdheSecret, Entropy, Error};
use crate::wire::records::Record;
use core::fmt;
use gnunet_crypto::hkdf_gnunet;
use gnunet_session_crypto::aead;
use gnunet_types::Error as Fault;
use zeroize::{Zeroize, Zeroizing};
/// Actual record derivation uses strlen(salt), excluding the final NUL. Message
/// group HMAC salts independently use sizeof(string), including their NUL.
pub const RECORD_SALT: &[u8] = b"gnunet-messenger-secret-key-}xJ(eTuk[+xu{S";
/// Original optional Messenger handle secret is a HashCode64, not an AEAD key32.
/// Explicit ownership prevents accidental key-width conversion/default-zero use.
pub struct RecordSecret(Zeroizing<[u8; 64]>);
impl fmt::Debug for RecordSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecordSecret([REDACTED])")
    }
}
impl RecordSecret {
    /// Import an explicitly caller-selected original handle secret64 and erase
    /// the by-value local copy. No file, IDENTITY key or default is read.
    pub fn from_bytes(mut bytes: [u8; 64]) -> Self {
        let result = Self(Zeroizing::new(bytes));
        bytes.zeroize();
        result
    }
    /// Provision a fresh original handle secret from explicit real entropy.
    pub fn generate(entropy: &mut impl Entropy) -> Result<Self, Error> {
        let mut bytes = Zeroizing::new([0; 64]);
        entropy.fill(bytes.as_mut()).map_err(|_| Fault::Entropy)?;
        Ok(Self(bytes))
    }
    fn derive(&self, info: &[&[u8]]) -> Result<AeadKey, Error> {
        let mut key = Zeroizing::new([0; 32]);
        hkdf_gnunet(RECORD_SALT, self.0.as_ref(), info, key.as_mut())?;
        Ok(AeadKey::from_bytes(*key))
    }
}
/// Real236-byte epoch record ciphertext fields. Private key material is held
/// only in a separate AeadKey owner and erased derivation scratch.
pub struct EpochRecord {
    room: [u8; 64],
    epoch: [u8; 64],
    identifier: [u8; 32],
    nonce: [u8; 24],
    mac: [u8; 16],
    ciphertext: [u8; 32],
    flags: u32,
}
impl fmt::Debug for EpochRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EpochRecord([REDACTED])")
    }
}
impl EpochRecord {
    /// Derive the actual record key from handle-secret64 and ordered
    /// room64/epoch64/identifier32, then encrypt key32 with a fresh nonce24.
    pub fn seal(
        root: &RecordSecret,
        room: &[u8; 64],
        epoch: &[u8; 64],
        identifier: &[u8; 32],
        flags: u32,
        shared: &AeadKey,
        entropy: &mut impl Entropy,
    ) -> Result<Self, Error> {
        let key = root.derive(&[room, epoch, identifier])?;
        let mut nonce = [0; 24];
        entropy.fill(&mut nonce).map_err(|_| Fault::Entropy)?;
        let mut plaintext = Zeroizing::new(*shared.0);
        let mac = aead::xchacha20poly1305_seal(&key.0, &nonce, &[], plaintext.as_mut())?;
        Ok(Self {
            room: *room,
            epoch: *epoch,
            identifier: *identifier,
            nonce,
            mac,
            ciphertext: *plaintext,
            flags,
        })
    }
    /// Exact existing wire record view. Flags retain the caller-selected native
    /// profile at encoding; no NAMESTORE commit or GNS validation is implied.
    pub fn record(&self) -> Record<'_> {
        Record::EpochKey {
            room_key: &self.room,
            epoch: &self.epoch,
            identifier: &self.identifier,
            nonce: &self.nonce,
            mac: &self.mac,
            encrypted_shared_key: &self.ciphertext,
            flags: self.flags,
        }
    }
}
/// Authenticate/decrypt key32 before releasing an owned shared-key capability.
/// Caller binds original record signature, zone, room, epoch and validity flags
/// before installing the result; raw flags are not an authorization proof.
pub fn open_epoch_record(root: &RecordSecret, record: Record<'_>) -> Result<AeadKey, Error> {
    let Record::EpochKey {
        room_key,
        epoch,
        identifier,
        nonce,
        mac,
        encrypted_shared_key,
        ..
    } = record
    else {
        return Err(Fault::InvalidInput.into());
    };
    let key = root.derive(&[room_key, epoch, identifier])?;
    let mut plaintext = Zeroizing::new(*encrypted_shared_key);
    aead::xchacha20poly1305_open(&key.0, nonce, &[], plaintext.as_mut(), mac)?;
    Ok(AeadKey::from_bytes(*plaintext))
}
/// Actual624-byte encryption record, retaining ciphertext of all516 private
/// serialization/random suffix bytes. No secret serialization is publicly held.
pub struct EncryptionRecord {
    room: [u8; 64],
    nonce: [u8; 24],
    mac: [u8; 16],
    key_len: u32,
    ciphertext: [u8; 516],
}
impl fmt::Debug for EncryptionRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EncryptionRecord([REDACTED])")
    }
}
impl EncryptionRecord {
    /// Serialize the real owned HPKE private key into erased516-byte scratch,
    /// fill its actual random suffix, derive from secret64/room64 and AEAD-seal
    /// the complete array. The private serialization never leaves this function.
    pub fn seal(
        root: &RecordSecret,
        room: &[u8; 64],
        hpke_key: &EcdheSecret,
        entropy: &mut impl Entropy,
    ) -> Result<Self, Error> {
        let mut plaintext = Zeroizing::new([0; 516]);
        let n = hpke_key.encode_hpke_private(plaintext.as_mut())?;
        let key_len = u32::try_from(n).map_err(|_| Fault::Overflow)?;
        entropy
            .fill(&mut plaintext[n..])
            .map_err(|_| Fault::Entropy)?;
        let key = root.derive(&[room])?;
        let mut nonce = [0; 24];
        entropy.fill(&mut nonce).map_err(|_| Fault::Entropy)?;
        let mac = aead::xchacha20poly1305_seal(&key.0, &nonce, &[], plaintext.as_mut())?;
        Ok(Self {
            room: *room,
            nonce,
            mac,
            key_len,
            ciphertext: *plaintext,
        })
    }
    /// Exact existing packed record fields; native encrypted_key_length is
    /// encoded by the explicit wire profile. This is not persistence evidence.
    pub fn record(&self) -> Record<'_> {
        Record::EncryptionKey {
            room_key: &self.room,
            nonce: &self.nonce,
            mac: &self.mac,
            encrypted_key_length: self.key_len,
            encrypted_private_data: &self.ciphertext,
        }
    }
}
/// Actually authenticate all516 ciphertext bytes before private-key parsing.
/// The active exact36-byte HPKE serialization and consumed length are checked;
/// malformed lengths/private tags never produce a successful key capability.
pub fn open_encryption_record(
    root: &RecordSecret,
    record: Record<'_>,
) -> Result<EcdheSecret, Error> {
    let Record::EncryptionKey {
        room_key,
        nonce,
        mac,
        encrypted_key_length,
        encrypted_private_data,
    } = record
    else {
        return Err(Fault::InvalidInput.into());
    };
    let n = usize::try_from(encrypted_key_length).map_err(|_| Fault::TooLarge)?;
    if n > 516 {
        return Err(Fault::Malformed.into());
    }
    let key = root.derive(&[room_key])?;
    let mut plaintext = Zeroizing::new(*encrypted_private_data);
    aead::xchacha20poly1305_open(&key.0, nonce, &[], plaintext.as_mut(), mac)?;
    let (owned, consumed) = EcdheSecret::decode_hpke_private(&plaintext[..n])?;
    if consumed != n {
        return Err(Fault::Malformed.into());
    }
    Ok(owned)
}
