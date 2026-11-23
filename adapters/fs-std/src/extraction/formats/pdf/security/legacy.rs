//! Authentication and object keys for PDF Standard security revisions 2–4.

use md5::{Digest, Md5};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::super::syntax::ObjectId;
use crate::extraction::pdf_rc4;

const PADDING: [u8; 32] = [
    0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41, 0x64, 0x00, 0x4e, 0x56, 0xff, 0xfa, 0x01, 0x08,
    0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80, 0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a,
];

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Revision {
    R2,
    R3,
    R4,
}

pub(super) struct AuthInput<'a> {
    pub(super) revision: Revision,
    pub(super) key_bytes: usize,
    pub(super) owner: &'a [u8; 32],
    pub(super) user: &'a [u8; 32],
    pub(super) permissions: i32,
    pub(super) id: &'a [u8],
    pub(super) encrypt_metadata: bool,
}

pub(super) struct Key {
    bytes: Zeroizing<[u8; 16]>,
    len: usize,
}

impl Key {
    pub(super) fn from_digest(bytes: Zeroizing<[u8; 16]>, len: usize) -> Option<Self> {
        (5..=16).contains(&len).then_some(Self { bytes, len })
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Check the implicit empty user and owner credentials used for publication.
pub(super) fn open(input: AuthInput<'_>) -> Option<Key> {
    match input.revision {
        Revision::R2 if input.key_bytes == 5 => {}
        Revision::R3 | Revision::R4 if (5..=16).contains(&input.key_bytes) => {}
        _ => return None,
    }

    if let Some(key) = authenticate_user(&input, &PADDING) {
        return Some(key);
    }
    if let Some(key) = authenticate_owner(&input, input.key_bytes) {
        return Some(key);
    }
    // Algorithm 3 describes rehashing the full digest. Poppler and QPDF
    // rehash only the key width, which differs for keys shorter than 128 bits.
    if input.revision != Revision::R2 && input.key_bytes != 16 {
        return authenticate_owner(&input, 16);
    }
    None
}

fn authenticate_user(input: &AuthInput<'_>, password: &[u8; 32]) -> Option<Key> {
    // Algorithm 2 (PDF 32000-1, 7.6.3.3).
    let mut hash = Md5::new();
    hash.update(password);
    hash.update(input.owner);
    hash.update(input.permissions.to_le_bytes());
    hash.update(input.id);
    if input.revision == Revision::R4 && !input.encrypt_metadata {
        hash.update([0xff; 4]);
    }
    let key = Key {
        bytes: rehash(hash, input.revision, input.key_bytes),
        len: input.key_bytes,
    };
    let matches = if input.revision == Revision::R2 {
        let mut check = Zeroizing::new(PADDING);
        crypt_rc4(check.as_mut(), &key);
        check.as_ref().ct_eq(input.user)
    } else {
        let mut hash = Md5::new();
        hash.update(PADDING);
        hash.update(input.id);
        let mut check: Zeroizing<[u8; 16]> = Zeroizing::new(hash.finalize().into());
        crypt_passes(check.as_mut(), &key, 0..20);
        check.as_ref().ct_eq(&input.user[..16])
    };
    bool::from(matches).then_some(key)
}

fn authenticate_owner(input: &AuthInput<'_>, hash_width: usize) -> Option<Key> {
    // Algorithm 7 reverses the owner entry cipher to validate the user entry.
    let mut hash = Md5::new();
    hash.update(PADDING);
    let key = Key {
        bytes: rehash(hash, input.revision, hash_width),
        len: input.key_bytes,
    };
    let mut padded_user = Zeroizing::new(*input.owner);
    let passes = if input.revision == Revision::R2 {
        1
    } else {
        20
    };
    crypt_passes(padded_user.as_mut(), &key, (0..passes).rev());
    authenticate_user(input, &padded_user)
}

fn rehash(hash: Md5, revision: Revision, width: usize) -> Zeroizing<[u8; 16]> {
    let mut digest: Zeroizing<[u8; 16]> = Zeroizing::new(hash.finalize().into());
    if revision != Revision::R2 {
        for _ in 0..50 {
            *digest = Md5::digest(&digest[..width]).into();
        }
    }
    digest
}

/// Algorithm 1 key for an RC4 or AESV2 string or stream.
pub(super) fn object_key(file_key: &Key, id: ObjectId, aes: bool) -> Option<Key> {
    if id.number == 0 || aes && file_key.len != 16 {
        return None;
    }
    let mut hash = Md5::new();
    hash.update(file_key.as_bytes());
    hash.update(&id.number.to_le_bytes()[..3]);
    hash.update(id.generation.to_le_bytes());
    if aes {
        hash.update(b"sAlT");
    }
    Some(Key {
        bytes: Zeroizing::new(hash.finalize().into()),
        len: (file_key.len + 5).min(16),
    })
}

pub(super) fn crypt_rc4(data: &mut [u8], key: &Key) {
    pdf_rc4::apply(data, key.as_bytes());
}

fn crypt_passes(data: &mut [u8], key: &Key, passes: impl Iterator<Item = u8>) {
    let mut round_key = Zeroizing::new([0; 16]);
    for pass in passes {
        for (target, byte) in round_key.iter_mut().zip(key.as_bytes()) {
            *target = byte ^ pass;
        }
        pdf_rc4::apply(data, &round_key[..key.len]);
    }
}
