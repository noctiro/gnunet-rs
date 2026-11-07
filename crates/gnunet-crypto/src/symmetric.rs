//! GNS AES-256-CTR and NaCl XSalsa20-Poly1305, with caller-owned storage.
use aes::cipher::{KeyIvInit, StreamCipher};
use gnunet_types::Error;
use poly1305::{Poly1305, universal_hash::KeyInit};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Encrypt or decrypt a complete AES-256-CTR message with a big-endian counter.
pub fn aes256ctr(key: &[u8; 32], iv: &[u8; 16], bytes: &mut [u8]) -> Result<(), Error> {
    let mut cipher = ctr::Ctr128BE::<aes::Aes256>::new(key.into(), iv.into());
    cipher.try_apply_keystream(bytes).map_err(|_| {
        bytes.zeroize();
        Error::TooLarge
    })
}

/// NaCl's tag-first secretbox layout, with no additional data or length padding.
/// The output must be exactly plaintext length plus 16 bytes.
pub fn xsalsa20poly1305_seal(
    key: &[u8; 32],
    nonce: &[u8; 24],
    plaintext: &[u8],
    output: &mut [u8],
) -> Result<(), Error> {
    if output.len() != plaintext.len().checked_add(16).ok_or(Error::Overflow)? {
        return Err(Error::Capacity);
    }
    let mut cipher = salsa20::XSalsa20::new(key.into(), nonce.into());
    let mut poly_key = Zeroizing::new([0; 32]);
    cipher
        .try_apply_keystream(poly_key.as_mut())
        .map_err(|_| Error::TooLarge)?;
    output[16..].copy_from_slice(plaintext);
    if cipher.try_apply_keystream(&mut output[16..]).is_err() {
        output.zeroize();
        return Err(Error::TooLarge);
    }
    let tag = Poly1305::new((&*poly_key).into()).compute_unpadded(&output[16..]);
    output[..16].copy_from_slice(&tag);
    Ok(())
}

/// Authenticate the tag before releasing any plaintext. Output is erased on a
/// bad tag; malformed lengths and capacity refusal do not touch the output.
pub fn xsalsa20poly1305_open(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
    output: &mut [u8],
) -> Result<(), Error> {
    if ciphertext.len() < 16 {
        return Err(Error::Truncated);
    }
    if output.len() != ciphertext.len() - 16 {
        return Err(Error::Capacity);
    }
    let mut cipher = salsa20::XSalsa20::new(key.into(), nonce.into());
    let mut poly_key = Zeroizing::new([0; 32]);
    cipher
        .try_apply_keystream(poly_key.as_mut())
        .map_err(|_| Error::TooLarge)?;
    let tag = Poly1305::new((&*poly_key).into()).compute_unpadded(&ciphertext[16..]);
    if !bool::from(tag.as_slice().ct_eq(&ciphertext[..16])) {
        output.zeroize();
        return Err(Error::Authentication);
    }
    output.copy_from_slice(&ciphertext[16..]);
    cipher.try_apply_keystream(output).map_err(|_| {
        output.zeroize();
        Error::TooLarge
    })
}
