//! RFC 3211 password-recipient key unwrapping.

use std::borrow::Cow;

use aes::{
    Aes128, Aes192, Aes256,
    cipher::{BlockCipherDecrypt, KeyInit},
};
use des::{Des, TdesEde3};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::super::{Item, OCTETS, algorithm};

const PWRI_KEK: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x03\x09";
const AES_CIPHER_ARC: &[u8] = b"\x60\x86\x48\x01\x65\x03\x04\x01";
const DES_CBC: &[u8] = b"\x2b\x0e\x03\x02\x07";
const TDES_CBC: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x03\x07";

const MAX_BLOCK_SIZE: usize = 16;
const MAX_KEY_SIZE: usize = u8::MAX as usize;
const HEADER_BYTES: usize = 4;
const MAX_WRAPPED_BYTES: usize = (MAX_KEY_SIZE + HEADER_BYTES).next_multiple_of(MAX_BLOCK_SIZE);

pub(super) struct Key<'a> {
    wrapping: Wrapping,
    iv: Cow<'a, [u8]>,
    ciphertext: Cow<'a, [u8]>,
}

impl<'a> Key<'a> {
    pub(super) fn parse(identifier: Item<'a>, ciphertext: Item<'a>) -> Option<Self> {
        let (oid, parameters) = algorithm(identifier)?;
        if oid != PWRI_KEK {
            return None;
        }
        let (oid, parameters) = algorithm(parameters?)?;
        let wrapping = Wrapping::parse(oid)?;
        let width = wrapping.block_size();
        let iv = parameters?.octets(OCTETS, width)?;
        let ciphertext = ciphertext.octets(OCTETS, MAX_WRAPPED_BYTES)?;
        if iv.len() != width
            || ciphertext.len() < 2 * width
            || !ciphertext.len().is_multiple_of(width)
        {
            return None;
        }
        Some(Self {
            wrapping,
            iv,
            ciphertext,
        })
    }

    pub(super) fn key_size(&self) -> usize {
        self.wrapping.key_size()
    }

    pub(super) fn open(self, key: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        match self.wrapping {
            Wrapping::Aes128 => self.open_with::<Aes128>(key),
            Wrapping::Aes192 => self.open_with::<Aes192>(key),
            Wrapping::Aes256 => self.open_with::<Aes256>(key),
            Wrapping::Des => self.open_with::<Des>(key),
            Wrapping::TripleDes => self.open_with::<TdesEde3>(key),
        }
    }

    fn open_with<C: BlockCipherDecrypt + KeyInit>(self, key: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let cipher = C::new_from_slice(key).ok()?;
        let width = self.wrapping.block_size();
        let ciphertext = &*self.ciphertext;
        let last_at = ciphertext.len().checked_sub(width)?;
        let penultimate_at = last_at.checked_sub(width)?;
        let mut plaintext = Zeroizing::new([0; MAX_WRAPPED_BYTES]);
        let output = plaintext.get_mut(..ciphertext.len())?;

        // The inner layer's last ciphertext block was the outer layer's IV.
        // Recover it using the outer layer's last two ciphertext blocks.
        let (prefix, last) = output.split_at_mut(last_at);
        decrypt_block(
            &cipher,
            &ciphertext[last_at..],
            &ciphertext[penultimate_at..last_at],
            last,
        )?;

        let mut iv = &*last;
        for (encrypted, decrypted) in ciphertext[..last_at]
            .chunks_exact(width)
            .zip(prefix.chunks_exact_mut(width))
        {
            decrypt_block(&cipher, encrypted, iv, decrypted)?;
            iv = encrypted;
        }

        // Decrypt the recovered inner layer in place using the admitted IV.
        let mut previous = Zeroizing::new([0; MAX_BLOCK_SIZE]);
        let mut next = Zeroizing::new([0; MAX_BLOCK_SIZE]);
        let previous = previous.get_mut(..width)?;
        let next = next.get_mut(..width)?;
        previous.copy_from_slice(&self.iv);
        for block in output.chunks_exact_mut(width) {
            next.copy_from_slice(block);
            decrypt_block(&cipher, next, previous, block)?;
            previous.copy_from_slice(next);
        }

        let (&[length, a, b, c], rest) = output.split_first_chunk::<HEADER_BYTES>()?;
        let (&[x, y, z], _) = rest.split_first_chunk::<3>()?;
        let intact = [a, b, c].ct_eq(&[!x, !y, !z]);
        let length = usize::from(length);
        if length < 5 || !bool::from(intact) {
            return None;
        }
        Some(Zeroizing::new(rest.get(..length)?.to_vec()))
    }
}

fn decrypt_block<C: BlockCipherDecrypt>(
    cipher: &C,
    ciphertext: &[u8],
    iv: &[u8],
    output: &mut [u8],
) -> Option<()> {
    cipher.decrypt_block_b2b(ciphertext.try_into().ok()?, (&mut *output).try_into().ok()?);
    for (byte, previous) in output.iter_mut().zip(iv) {
        *byte ^= *previous;
    }
    Some(())
}

#[derive(Clone, Copy)]
enum Wrapping {
    Aes128,
    Aes192,
    Aes256,
    Des,
    TripleDes,
}

impl Wrapping {
    fn parse(oid: &[u8]) -> Option<Self> {
        match oid {
            DES_CBC => Some(Self::Des),
            TDES_CBC => Some(Self::TripleDes),
            _ => match oid.strip_prefix(AES_CIPHER_ARC)? {
                [2] => Some(Self::Aes128),
                [22] => Some(Self::Aes192),
                [42] => Some(Self::Aes256),
                _ => None,
            },
        }
    }

    const fn block_size(self) -> usize {
        match self {
            Self::Aes128 | Self::Aes192 | Self::Aes256 => 16,
            Self::Des | Self::TripleDes => 8,
        }
    }

    const fn key_size(self) -> usize {
        match self {
            Self::Des => 8,
            Self::Aes128 => 16,
            Self::Aes192 | Self::TripleDes => 24,
            Self::Aes256 => 32,
        }
    }
}
