//! Standard IDENTITY CLI HPKE envelopes, composed from the existing primitives.
//! This module performs no IO, lookup, identity-key generation or implicit RNG;
//! the existing one-shot sender uses only its explicit ephemeral entropy input.
use gnunet::{
    clients::identity::{KeyType, SecretKey},
    crypto::Entropy,
    gnsrecord::{ZoneKey, base32_encoded_len, decode_base32, encode_base32},
    session_crypto::{exchange, hpke},
    types::Error as Fault,
};
use std::{collections::TryReserveError, error::Error, fmt};
use zeroize::Zeroizing;

/// Explicit local resource bound, independent of the public HPKE wire format.
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_ENVELOPE_BYTES: usize = MAX_MESSAGE_BYTES + 1 + hpke::ONESHOT_OVERHEAD;
const MAX_ENCODED_BYTES: usize = (MAX_ENVELOPE_BYTES * 8).div_ceil(5);

/// Typed causes contain no message bytes, public-key text or private material.
#[derive(Debug)]
pub(super) enum Failure {
    /// Local bounded preparation refused this message length.
    MessageTooLarge,
    /// A CLI argument cannot contain a C-string interior terminator.
    InteriorNul,
    /// The supplied public envelope does not fit the standard CLI framing.
    Envelope,
    /// Authenticated data was not one complete standard CLI C-string message.
    Plaintext,
    /// Actual existing parser, key-conversion or HPKE primitive refusal.
    Primitive(Fault),
    /// Actual fallible bounded allocation failure.
    Allocation(TryReserveError),
}
impl From<Fault> for Failure {
    fn from(cause: Fault) -> Self {
        Self::Primitive(cause)
    }
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IDENTITY message: {self:?}")
    }
}
impl Error for Failure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Primitive(cause) => Some(cause),
            Self::Allocation(cause) => Some(cause),
            _ => None,
        }
    }
}
fn buffer(length: usize) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(length)
        .map_err(Failure::Allocation)?;
    bytes.resize(length, 0);
    Ok(bytes)
}
fn recipient_key(secret: &SecretKey) -> Result<exchange::EcdheSecret, Failure> {
    let view = secret.view()?;
    let mut raw = Zeroizing::new([0; 32]);
    raw.copy_from_slice(&view.expose_serialized()[4..]);
    Ok(match view.key_type() {
        // crypto_hpke.c copies the original PKEY scalar without hashing it.
        KeyType::Ecdsa => exchange::EcdheSecret::from_bytes(*raw),
        // libsodium's Ed25519 conversion hashes the original seed, then clamps.
        KeyType::Eddsa => exchange::EcdheSecret::from_eddsa_seed(*raw),
    })
}
/// Encrypt the original argument bytes plus their required terminal NUL.
/// Result is canonical Base32GNS without LF; the caller owns the once-only IO.
/// Both typed identity public-key families use the existing Edwards conversion.
/// The caller guard checks the same original stop/deadline at synchronous
/// capability boundaries. It cannot interrupt an in-progress primitive call.
pub(super) fn encrypt(
    recipient: &ZoneKey,
    message: &[u8],
    entropy: &mut impl Entropy,
    guard: &mut impl FnMut() -> Result<(), Fault>,
) -> Result<Zeroizing<Vec<u8>>, Failure> {
    guard()?;
    if message.len() > MAX_MESSAGE_BYTES {
        return Err(Failure::MessageTooLarge);
    }
    if message.contains(&0) {
        return Err(Failure::InteriorNul);
    }
    let plain_len = message
        .len()
        .checked_add(1)
        .ok_or(Failure::MessageTooLarge)?;
    let wire_len = plain_len
        .checked_add(hpke::ONESHOT_OVERHEAD)
        .ok_or(Failure::MessageTooLarge)?;
    let encoded_len = base32_encoded_len(wire_len)?;
    // Complete bounded output preparation precedes key conversion and entropy.
    let mut plaintext = buffer(plain_len)?;
    let mut wire = buffer(wire_len)?;
    let mut encoded = buffer(encoded_len)?;
    plaintext[..message.len()].copy_from_slice(message);
    guard()?;
    let public = exchange::EcdhePublic::from_edwards(recipient.key())?;
    guard()?;
    let written = hpke::seal_oneshot(public, &[], &[], &plaintext, &mut wire, entropy)?;
    // C's optional ct_len_p excludes enc32. Its CLI serializes the whole
    // enc32 || ciphertext || tag16 envelope, as total_written does here.
    if written.total_written != wire_len {
        return Err(Failure::Envelope);
    }
    guard()?;
    let used = encode_base32(&wire, &mut encoded)?;
    encoded.truncate(used);
    guard()?;
    Ok(encoded)
}
/// Decode and authenticate one standard Base32GNS CLI envelope using the actual
/// looked-up ego secret. Returns original argument bytes without the final NUL.
/// Bytes need not be UTF-8. No error formats or echoes plaintext/private data.
/// Guard checks use the caller's original stop/deadline, without constructing
/// another budget. They cannot preempt an existing synchronous crypto call.
pub(super) fn decrypt(
    secret: &SecretKey,
    encoded: &[u8],
    guard: &mut impl FnMut() -> Result<(), Fault>,
) -> Result<Zeroizing<Vec<u8>>, Failure> {
    guard()?;
    if encoded.len() > MAX_ENCODED_BYTES {
        return Err(Failure::MessageTooLarge);
    }
    let wire_len = encoded.len().checked_mul(5).ok_or(Failure::Envelope)? / 8;
    let plain_len = wire_len
        .checked_sub(hpke::ONESHOT_OVERHEAD)
        .filter(|length| *length != 0)
        .ok_or(Failure::Envelope)?;
    if plain_len > MAX_MESSAGE_BYTES + 1 {
        return Err(Failure::MessageTooLarge);
    }
    let mut wire = buffer(wire_len)?;
    let used = decode_base32(encoded, &mut wire)?;
    if used != wire_len {
        return Err(Failure::Envelope);
    }
    let mut plaintext = buffer(plain_len)?;
    guard()?;
    let recipient = recipient_key(secret)?;
    guard()?;
    let opened = hpke::open_oneshot(&recipient, &[], &[], &wire, &mut plaintext)?;
    guard()?;
    if opened != plain_len || plaintext.last() != Some(&0) {
        return Err(Failure::Plaintext);
    }
    if plaintext[..plain_len - 1].contains(&0) {
        return Err(Failure::Plaintext);
    }
    plaintext.truncate(plain_len - 1);
    guard()?;
    Ok(plaintext)
}
