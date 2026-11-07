//! Official detached IETF ChaCha20Poly1305 and XChaCha20Poly1305 layouts.
//! HChaCha state/subkey and counter0 one-time key are explicitly erased owners.
use chacha20::{ChaChaCore, R20, variants::Ietf};
use cipher::{KeyIvInit, StreamCipherCore};
use gnunet_types::Error;
use poly1305::{
    Poly1305,
    universal_hash::{KeyInit, UniversalHash},
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};
type Core = ChaChaCore<R20, Ietf>;
/// Maximum official IETF payload: counters1 through2^32-1,64 bytes each.
pub const MAX_PLAINTEXT_BYTES: u64 = (u32::MAX as u64) * 64;
pub(crate) fn preflight(len: usize, aad: usize) -> Result<(), Error> {
    if u64::try_from(len).map_err(|_| Error::Overflow)? > MAX_PLAINTEXT_BYTES {
        return Err(Error::TooLarge);
    }
    u64::try_from(aad).map_err(|_| Error::Overflow)?;
    Ok(())
}
fn quarter(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}
pub(crate) fn hchacha(key: &[u8; 32], nonce: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    let mut s = Zeroizing::new([0_u32; 16]);
    s[..4].copy_from_slice(&[0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
    for (i, p) in key.as_chunks::<4>().0.iter().enumerate() {
        s[4 + i] = u32::from_le_bytes(*p);
    }
    for (i, p) in nonce.as_chunks::<4>().0.iter().enumerate() {
        s[12 + i] = u32::from_le_bytes(*p);
    }
    for _ in 0..10 {
        quarter(&mut s, 0, 4, 8, 12);
        quarter(&mut s, 1, 5, 9, 13);
        quarter(&mut s, 2, 6, 10, 14);
        quarter(&mut s, 3, 7, 11, 15);
        quarter(&mut s, 0, 5, 10, 15);
        quarter(&mut s, 1, 6, 11, 12);
        quarter(&mut s, 2, 7, 8, 13);
        quarter(&mut s, 3, 4, 9, 14);
    }
    let mut out = Zeroizing::new([0; 32]);
    for (chunk, index) in out
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .zip([0, 1, 2, 3, 12, 13, 14, 15])
    {
        let mut word = s[index].to_le_bytes();
        chunk.copy_from_slice(&word);
        word.zeroize();
    }
    out
}
fn initial(key: &[u8; 32], nonce: &[u8; 12]) -> (Core, Zeroizing<[u8; 32]>) {
    let mut core = Core::new(key.into(), nonce.into());
    let mut block = Zeroizing::new([0; 64]);
    // Counter0 is the Poly1305 one-time key only; consume the whole64-byte block.
    core.write_keystream_block((&mut *block).into());
    let mut poly = Zeroizing::new([0; 32]);
    poly.copy_from_slice(&block[..32]);
    (core, poly)
}
fn apply(core: &mut Core, bytes: &mut [u8]) {
    let mut block = Zeroizing::new([0; 64]);
    // Preflight guarantees no call after the final u32 counter wraps. Direct
    // one-block API includes the legal final counter, unlike a reused wrapper.
    for chunk in bytes.chunks_mut(64) {
        core.write_keystream_block((&mut *block).into());
        for (byte, key) in chunk.iter_mut().zip(block.iter()) {
            *byte ^= *key;
        }
    }
}
fn tag(key: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut poly = Poly1305::new(key.into());
    poly.update_padded(aad);
    poly.update_padded(ciphertext);
    let mut lengths = [0_u8; 16];
    lengths[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lengths[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    poly.update(&[lengths.into()]);
    poly.finalize().into()
}
/// Encrypt in place with IETF nonce12 and return detached tag16. AAD is exact
/// caller bytes; no protocol header, private domain or padding is inserted.
pub fn chacha20poly1305_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    bytes: &mut [u8],
) -> Result<[u8; 16], Error> {
    preflight(bytes.len(), aad.len())?;
    let (mut core, poly) = initial(key, nonce);
    apply(&mut core, bytes);
    Ok(tag(&poly, aad, bytes))
}
/// Check the tag before decryption; bad authentication erases the output range.
/// Resource refusal leaves the complete input/output unchanged.
pub fn chacha20poly1305_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    bytes: &mut [u8],
    expected: &[u8; 16],
) -> Result<(), Error> {
    preflight(bytes.len(), aad.len())?;
    let (mut core, poly) = initial(key, nonce);
    let computed = tag(&poly, aad, bytes);
    if !bool::from(computed.ct_eq(expected)) {
        bytes.zeroize();
        return Err(Error::Authentication);
    }
    apply(&mut core, bytes);
    Ok(())
}
fn subkey_nonce(key: &[u8; 32], nonce: &[u8; 24]) -> (Zeroizing<[u8; 32]>, [u8; 12]) {
    let mut prefix = [0; 16];
    prefix.copy_from_slice(&nonce[..16]);
    let subkey = hchacha(key, &prefix);
    let mut iv = [0; 12];
    iv[4..].copy_from_slice(&nonce[16..]);
    (subkey, iv)
}
/// Official XChaCha IETF nonce24, detached tag16. This is distinct from the
/// existing GNS XSalsa20 secretbox tag-first layout.
pub fn xchacha20poly1305_seal(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    bytes: &mut [u8],
) -> Result<[u8; 16], Error> {
    preflight(bytes.len(), aad.len())?;
    let (subkey, iv) = subkey_nonce(key, nonce);
    chacha20poly1305_seal(&subkey, &iv, aad, bytes)
}
/// Authenticate exact AAD/tag before releasing any XChaCha plaintext.
pub fn xchacha20poly1305_open(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    bytes: &mut [u8],
    tag: &[u8; 16],
) -> Result<(), Error> {
    preflight(bytes.len(), aad.len())?;
    let (subkey, iv) = subkey_nonce(key, nonce);
    chacha20poly1305_open(&subkey, &iv, aad, bytes, tag)
}
