//! CMS symmetric content-key wrapping shared by recipient mechanisms.

mod rc2;

use aes::{
    Aes128, Aes192, Aes256,
    cipher::{BlockCipherDecrypt, KeyInit},
};
use des::TdesEde3;
use sha1::{Digest, Sha1};
use std::borrow::Cow;
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, Zeroizing};

use super::{Item, OCTETS, algorithm};

const AES128_WRAP_OID: &[u8] = b"\x60\x86\x48\x01\x65\x03\x04\x01\x05";
const AES192_WRAP_OID: &[u8] = b"\x60\x86\x48\x01\x65\x03\x04\x01\x19";
const AES256_WRAP_OID: &[u8] = b"\x60\x86\x48\x01\x65\x03\x04\x01\x2d";
pub(super) const CMS3DES_WRAP_OID: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x03\x06";
pub(super) const RC2_WRAP_OID: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x03\x07";
pub(super) const MAX_WRAPPED_BYTES: usize = 136;

const AES_REGISTER_BYTES: usize = 8;
const AES_WRAP_ROUNDS: usize = 6;
const TDES_KEY_BYTES: usize = 24;
const TDES_WRAPPED_BYTES: usize = 16 + TDES_KEY_BYTES;
const CBC_INITIAL_IV: [u8; 8] = [0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05];

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Algorithm {
    Aes128,
    Aes192,
    Aes256,
    TripleDes,
    Rc2(Rc2Version),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Rc2Version {
    Bits40,
    Bits64,
    Bits128,
}

impl Rc2Version {
    fn parse(parameter: Item<'_>) -> Option<Self> {
        match parameter.uint()? {
            160 => Some(Self::Bits40),
            120 => Some(Self::Bits64),
            58 => Some(Self::Bits128),
            _ => None,
        }
    }

    const fn effective_bits(self) -> usize {
        match self {
            Self::Bits40 => 40,
            Self::Bits64 => 64,
            Self::Bits128 => 128,
        }
    }
}

impl Algorithm {
    pub(super) fn parse(identifier: Item<'_>) -> Option<Self> {
        let (oid, parameters) = algorithm(identifier)?;
        match oid {
            AES128_WRAP_OID if parameters.is_none() => Some(Self::Aes128),
            AES192_WRAP_OID if parameters.is_none() => Some(Self::Aes192),
            AES256_WRAP_OID if parameters.is_none() => Some(Self::Aes256),
            CMS3DES_WRAP_OID => {
                let null = parameters?;
                (null.tag == 0x05 && null.data.is_empty()).then_some(Self::TripleDes)
            }
            RC2_WRAP_OID => Some(Self::Rc2(Rc2Version::parse(parameters?)?)),
            _ => None,
        }
    }

    fn admits_wrapped_bytes(self, length: usize) -> bool {
        match self {
            Self::TripleDes => length == TDES_WRAPPED_BYTES,
            Self::Rc2(_) => rc2::admits_wrapped_bytes(length),
            Self::Aes128 | Self::Aes192 | Self::Aes256 => {
                (3 * AES_REGISTER_BYTES..=MAX_WRAPPED_BYTES).contains(&length)
                    && length.is_multiple_of(AES_REGISTER_BYTES)
            }
        }
    }

    pub(super) const fn is_aes(self) -> bool {
        matches!(self, Self::Aes128 | Self::Aes192 | Self::Aes256)
    }

    pub(super) const fn oid(self) -> &'static [u8] {
        match self {
            Self::Aes128 => AES128_WRAP_OID,
            Self::Aes192 => AES192_WRAP_OID,
            Self::Aes256 => AES256_WRAP_OID,
            Self::TripleDes => CMS3DES_WRAP_OID,
            Self::Rc2(_) => RC2_WRAP_OID,
        }
    }

    pub(super) const fn key_bytes(self) -> u8 {
        match self {
            Self::Aes128 | Self::Rc2(_) => 16,
            Self::Aes192 | Self::TripleDes => 24,
            Self::Aes256 => 32,
        }
    }

    pub(super) const fn key_info(self) -> &'static [u8] {
        // KDF inputs use DER. AES parameters are absent. CMS Triple-DES
        // and RC2 use NULL and INTEGER parameters, respectively.
        match self {
            Self::Aes128 => b"\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x05",
            Self::Aes192 => b"\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x19",
            Self::Aes256 => b"\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x2d",
            Self::TripleDes => {
                b"\x30\x0f\x06\x0b\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x03\x06\x05\x00"
            }
            Self::Rc2(Rc2Version::Bits40) => {
                b"\x30\x11\x06\x0b\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x03\x07\x02\x02\x00\xa0"
            }
            Self::Rc2(Rc2Version::Bits64) => {
                b"\x30\x10\x06\x0b\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x03\x07\x02\x01\x78"
            }
            Self::Rc2(Rc2Version::Bits128) => {
                b"\x30\x10\x06\x0b\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x03\x07\x02\x01\x3a"
            }
        }
    }
}

pub(super) struct WrappedKey<'a> {
    algorithm: Algorithm,
    bytes: Cow<'a, [u8]>,
}

impl<'a> WrappedKey<'a> {
    pub(super) fn parse(identifier: Item<'_>, bytes: Cow<'a, [u8]>) -> Option<Self> {
        Self::validated(Algorithm::parse(identifier)?, bytes)
    }

    pub(super) fn read(identifier: Item<'_>, encrypted: Item<'a>) -> Option<Self> {
        let algorithm = Algorithm::parse(identifier)?;
        let limit = match algorithm {
            Algorithm::Rc2(_) => rc2::MAX_WRAPPED_BYTES,
            _ => MAX_WRAPPED_BYTES,
        };
        let bytes = encrypted.octets(OCTETS, limit)?;
        Self::validated(algorithm, bytes)
    }

    fn validated(algorithm: Algorithm, bytes: Cow<'a, [u8]>) -> Option<Self> {
        algorithm
            .admits_wrapped_bytes(bytes.len())
            .then_some(Self { algorithm, bytes })
    }

    pub(super) const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    pub(super) fn wrapped_bytes(&self) -> usize {
        self.bytes.len()
    }

    pub(super) fn open(self, kek: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        if kek.len() != usize::from(self.algorithm.key_bytes()) {
            return None;
        }
        match self.algorithm {
            Algorithm::Aes128 => unwrap_aes::<Aes128>(kek, &self.bytes),
            Algorithm::Aes192 => unwrap_aes::<Aes192>(kek, &self.bytes),
            Algorithm::Aes256 => unwrap_aes::<Aes256>(kek, &self.bytes),
            Algorithm::TripleDes => unwrap_tdes(kek, &self.bytes),
            Algorithm::Rc2(version) => rc2::unwrap(kek.try_into().ok()?, version, &self.bytes),
        }
    }
}

fn unwrap_aes<C: BlockCipherDecrypt + KeyInit>(
    key: &[u8],
    wrapped: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    let cipher = C::new_from_slice(key).ok()?;
    let (initial, registers) = wrapped.split_first_chunk::<AES_REGISTER_BYTES>()?;
    let mut integrity = Zeroizing::new(*initial);
    let mut output = Zeroizing::new(registers.to_vec());
    let (registers, []) = output.as_chunks_mut::<AES_REGISTER_BYTES>() else {
        return None;
    };
    let count = registers.len();
    let mut block = Zeroizing::new([0; 2 * AES_REGISTER_BYTES]);
    // RFC 3394 §2.2.2 iterates backwards through the rounds and registers.
    for round in (0..AES_WRAP_ROUNDS).rev() {
        for (number, register) in registers.iter_mut().enumerate().rev() {
            let counter = u64::try_from(count * round + number + 1).ok()?;
            let (left, right) = block.split_at_mut(AES_REGISTER_BYTES);
            for (byte, (value, step)) in left
                .iter_mut()
                .zip(integrity.iter().zip(counter.to_be_bytes()))
            {
                *byte = value ^ step;
            }
            right.copy_from_slice(register);
            cipher.decrypt_block(block.as_mut_slice().try_into().ok()?);
            integrity.copy_from_slice(&block[..AES_REGISTER_BYTES]);
            register.copy_from_slice(&block[AES_REGISTER_BYTES..]);
        }
    }
    bool::from(integrity.ct_eq(&[0xa6; AES_REGISTER_BYTES])).then_some(output)
}

fn unwrap_tdes(key: &[u8], wrapped: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let cipher = TdesEde3::new_from_slice(key).ok()?;
    let mut bytes = Zeroizing::new(<[u8; TDES_WRAPPED_BYTES]>::try_from(wrapped).ok()?);
    let (content, checksum) = cbc_unwrap(&cipher, bytes.as_mut_slice())?.split_last_chunk::<8>()?;
    let check = checksum_matches(content, checksum);
    let parity_failures = content
        .iter()
        .fold(0, |acc, byte| acc | ((byte.count_ones() & 1) ^ 1));
    if bool::from(check & parity_failures.ct_eq(&0)) {
        Some(Zeroizing::new(content.to_vec()))
    } else {
        None
    }
}

fn checksum_matches(content: &[u8], checksum: &[u8; 8]) -> Choice {
    let mut digest = Sha1::digest(content);
    let check = digest[..8].ct_eq(checksum);
    digest.as_mut_slice().zeroize();
    check
}

fn cbc_unwrap<'a, C: BlockCipherDecrypt>(cipher: &C, bytes: &'a mut [u8]) -> Option<&'a [u8]> {
    // RFC 3217 uses two CBC passes separated by octet reversal.
    cbc_decrypt(cipher, &CBC_INITIAL_IV, bytes)?;
    bytes.reverse();
    let (iv, encrypted) = bytes.split_first_chunk_mut::<8>()?;
    cbc_decrypt(cipher, iv, encrypted)?;
    Some(encrypted)
}

fn cbc_decrypt<C: BlockCipherDecrypt>(cipher: &C, iv: &[u8; 8], bytes: &mut [u8]) -> Option<()> {
    let (blocks, []) = bytes.as_chunks_mut::<8>() else {
        return None;
    };
    let mut previous = Zeroizing::new(*iv);
    for block in blocks {
        let next = Zeroizing::new(*block);
        cipher.decrypt_block(block.as_mut_slice().try_into().ok()?);
        for (byte, preceding) in block.iter_mut().zip(previous.iter()) {
            *byte ^= preceding;
        }
        *previous = *next;
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cms_3des_key_unwrap_checks_both_encryption_layers() {
        // RFC 3217 §3.4 reference vector.
        let key = b"\x25\x5e\x0d\x1c\x07\xb6\x46\xdf\xb3\x13\x4c\xc8\x43\xba\x8a\xa7\x1f\x02\x5b\x7c\x08\x38\x25\x1f";
        let mut wrapped = *b"\x69\x01\x07\x61\x8e\xf0\x92\xb3\xb4\x8c\xa1\x79\x6b\x23\x4a\xe9\xfa\x33\xeb\xb4\x15\x96\x04\x03\x7d\xb5\xd6\xa8\x4e\xb3\xaa\xc2\x76\x8c\x63\x27\x75\xa4\x67\xd4";
        let expected = b"\x29\x23\xbf\x85\xe0\x6d\xd6\xae\x52\x91\x49\xf1\xf1\xba\xe9\xea\xb3\xa7\xda\x3d\x86\x0d\x3e\x98";
        let actual = unwrap_tdes(key, &wrapped);
        assert_eq!(
            actual.as_deref().map(Vec::as_slice),
            Some(expected.as_slice())
        );
        wrapped[17] ^= 1;
        assert!(unwrap_tdes(key, &wrapped).is_none());
        assert!(unwrap_tdes(key, &wrapped[..32]).is_none());
    }
}
