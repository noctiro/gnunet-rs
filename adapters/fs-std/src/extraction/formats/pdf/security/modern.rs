//! Standard PDF AES-256 authentication for documents that open with no password.

use aes::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit, consts::U16};
use aes::{Aes128, Aes256};
use sha2::{Digest, Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const BLOCK_BYTES: usize = 16;
const MIN_ROUNDS: usize = 64;
// A round's last byte is at most 255 and the end threshold is rounds - 32.
const MAX_ROUNDS: usize = u8::MAX as usize + 32;
const REPETITIONS: usize = 64;
const ZERO_IV: [u8; BLOCK_BYTES] = [0; BLOCK_BYTES];

#[derive(Clone, Copy)]
pub(super) enum Revision {
    R5,
    R6,
}

pub(super) struct AuthInput<'a> {
    pub(super) revision: Revision,
    pub(super) owner: &'a [u8; 48],
    pub(super) user: &'a [u8; 48],
    pub(super) owner_key: &'a [u8; 32],
    pub(super) user_key: &'a [u8; 32],
    pub(super) validation: &'a [u8; BLOCK_BYTES],
    pub(super) permissions: i32,
    pub(super) encrypt_metadata: bool,
}

pub(super) fn open(input: AuthInput<'_>) -> Option<Zeroizing<[u8; 32]>> {
    let recipients = [
        (input.owner, input.owner_key, Some(input.user)),
        (input.user, input.user_key, None),
    ];
    for (entry, wrapped, user) in recipients {
        let validation = password_hash(input.revision, &entry[32..40], user)?;
        if !bool::from(validation.as_slice().ct_eq(&entry[..32])) {
            continue;
        }

        let wrapping_key = password_hash(input.revision, &entry[40..], user)?;
        let mut file_key = Zeroizing::new(*wrapped);
        decrypt256(&mut *file_key, &wrapping_key, &ZERO_IV)?;
        return permissions_match(&input, &file_key).then_some(file_key);
    }
    None
}

fn permissions_match(input: &AuthInput<'_>, key: &[u8; 32]) -> bool {
    let cipher = Aes256::new(key.into());
    let mut permissions = Zeroizing::new(*input.validation);
    cipher.decrypt_block((&mut *permissions).into());
    let mut expected = *b"\0\0\0\0\xff\xff\xff\xffTadb";
    expected[..4].copy_from_slice(&input.permissions.to_le_bytes());
    if !input.encrypt_metadata {
        expected[8] = b'F';
    }
    bool::from(permissions[..expected.len()].ct_eq(&expected))
}

fn password_hash(
    revision: Revision,
    salt: &[u8],
    user: Option<&[u8; 48]>,
) -> Option<Zeroizing<[u8; 32]>> {
    // The opening password is empty. Owner validation includes the whole U field.
    let user = user.map_or([].as_slice(), <[_; 48]>::as_slice);
    let mut initial = Sha256::new();
    initial.update(salt);
    initial.update(user);
    let initial = Zeroizing::new(initial.finalize());
    if matches!(revision, Revision::R5) {
        return Some(Zeroizing::new(*initial.first_chunk()?));
    }
    hardened_hash(&initial, user)
}

fn hardened_hash(initial: &[u8], user: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    let mut hash = Zeroizing::new([0; 64]);
    let mut hash_len = initial.len();
    hash[..hash_len].copy_from_slice(initial);
    let mut scratch = Zeroizing::new([0; REPETITIONS * (64 + 48)]);
    for round in 1..=MAX_ROUNDS {
        let sequence_len = hash_len + user.len();
        let encrypted = scratch.get_mut(..REPETITIONS * sequence_len)?;
        for sequence in encrypted.chunks_exact_mut(sequence_len) {
            let (key_bytes, user_bytes) = sequence.split_at_mut(hash_len);
            key_bytes.copy_from_slice(&hash[..hash_len]);
            user_bytes.copy_from_slice(user);
        }
        let (key, iv) = hash[..32].split_at(16);
        encrypt128(encrypted, key.try_into().ok()?, iv.try_into().ok()?)?;

        // An unsigned big-endian integer is congruent to the sum of its bytes modulo 3.
        let hash_choice = encrypted[..16]
            .iter()
            .map(|&byte| u16::from(byte))
            .sum::<u16>()
            % 3;
        hash_len = match hash_choice {
            0 => replace_hash(&mut hash, &Zeroizing::new(Sha256::digest(&*encrypted))[..]),
            1 => replace_hash(&mut hash, &Zeroizing::new(Sha384::digest(&*encrypted))[..]),
            _ => replace_hash(&mut hash, &Zeroizing::new(Sha512::digest(&*encrypted))[..]),
        };
        if round >= MIN_ROUNDS && usize::from(*encrypted.last()?) <= round - 32 {
            return Some(Zeroizing::new(*hash.first_chunk()?));
        }
    }
    None
}

fn replace_hash(hash: &mut [u8; 64], next: &[u8]) -> usize {
    hash[..next.len()].copy_from_slice(next);
    next.len()
}

fn encrypt128(data: &mut [u8], key: &[u8; BLOCK_BYTES], iv: &[u8; BLOCK_BYTES]) -> Option<()> {
    let (blocks, remainder) = data.as_chunks_mut::<BLOCK_BYTES>();
    if !remainder.is_empty() {
        return None;
    }
    let cipher = Aes128::new(key.into());
    let mut chain = Zeroizing::new(Array::from(*iv));
    for block in blocks {
        for (byte, &input) in chain.iter_mut().zip(block.iter()) {
            *byte ^= input;
        }
        cipher.encrypt_block(&mut chain);
        block.copy_from_slice(&chain[..]);
    }
    Some(())
}

pub(super) fn decrypt128(
    data: &mut [u8],
    key: &[u8; BLOCK_BYTES],
    iv: &[u8; BLOCK_BYTES],
) -> Option<()> {
    decrypt_cbc(data, &Aes128::new(key.into()), iv)
}

pub(super) fn decrypt256(data: &mut [u8], key: &[u8; 32], iv: &[u8; BLOCK_BYTES]) -> Option<()> {
    decrypt_cbc(data, &Aes256::new(key.into()), iv)
}

fn decrypt_cbc(
    data: &mut [u8],
    cipher: &impl BlockCipherDecrypt<BlockSize = U16>,
    iv: &[u8; BLOCK_BYTES],
) -> Option<()> {
    let (blocks, remainder) = data.as_chunks_mut::<BLOCK_BYTES>();
    if !remainder.is_empty() {
        return None;
    }
    let mut previous = *iv;
    for block in blocks {
        let ciphertext = *block;
        cipher.decrypt_block((&mut *block).into());
        for (byte, previous) in block.iter_mut().zip(previous) {
            *byte ^= previous;
        }
        previous = ciphertext;
    }
    Some(())
}
