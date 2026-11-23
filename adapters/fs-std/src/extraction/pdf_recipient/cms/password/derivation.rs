//! Bounded PBKDF2 derivation for the CMS password recipient.

use std::{borrow::Cow, cell::Cell, num::NonZeroUsize};

use hmac::{Hmac, KeyInit, Mac, digest::Output};
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use zeroize::{Zeroize, Zeroizing};

use super::super::{Ber, INTEGER, Item, OCTETS, OID, SEQUENCE, algorithm};

const PBKDF2: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x05\x0c";
const RSADSI_DIGESTS: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x02";
const MAX_SALT_BYTES: usize = 1024;
pub(super) const MAX_HMAC_CALLS: usize = 1_000_000;

pub(super) struct Pbkdf2<'a> {
    prf: Prf,
    iterations: NonZeroUsize,
    salt: Cow<'a, [u8]>,
}

impl<'a> Pbkdf2<'a> {
    pub(super) fn parse(input: Item<'a>, key_size: usize) -> Option<Self> {
        // PWRI implicitly tags its AlgorithmIdentifier with [0].
        let mut algorithm_fields = Ber(input.data);
        if algorithm_fields.take(OID)?.data != PBKDF2 {
            return None;
        }
        let mut fields = Ber(algorithm_fields.take(SEQUENCE)?.data);
        algorithm_fields.finish()?;

        // RFC 8018 reserves the algorithm-identified salt for future use.
        let salt = fields.read()?.octets(OCTETS, MAX_SALT_BYTES)?;
        let iterations = NonZeroUsize::new(usize::try_from(fields.take(INTEGER)?.uint()?).ok()?)?;
        if let Some(length) = fields.optional(INTEGER)?
            && length.uint()? != u64::try_from(key_size).ok()?
        {
            return None;
        }
        let prf = match fields.optional(SEQUENCE)? {
            Some(identifier) => Prf::parse(identifier)?,
            None => Prf::Sha1,
        };
        fields.finish()?;
        Some(Self {
            prf,
            iterations,
            salt,
        })
    }

    pub(super) fn derive(
        &self,
        password: &[u8],
        remaining_work: &Cell<usize>,
        output: &mut [u8],
    ) -> Option<()> {
        let output_blocks = output.len().div_ceil(self.prf.tag_size());
        let cost = self.iterations.get().checked_mul(output_blocks)?;
        remaining_work.set(remaining_work.get().checked_sub(cost)?);
        match self.prf {
            Prf::Sha1 => self.derive_with::<Hmac<Sha1>>(password, output),
            Prf::Sha224 => self.derive_with::<Hmac<Sha224>>(password, output),
            Prf::Sha256 => self.derive_with::<Hmac<Sha256>>(password, output),
            Prf::Sha384 => self.derive_with::<Hmac<Sha384>>(password, output),
            Prf::Sha512 => self.derive_with::<Hmac<Sha512>>(password, output),
            Prf::Sha512_224 => self.derive_with::<Hmac<Sha512_224>>(password, output),
            Prf::Sha512_256 => self.derive_with::<Hmac<Sha512_256>>(password, output),
        }
    }

    fn derive_with<M: Mac + KeyInit + Clone>(
        &self,
        password: &[u8],
        output: &mut [u8],
    ) -> Option<()> {
        let mac = M::new_from_slice(password).ok()?;
        let tag_size = Output::<M>::default().len();
        for (counter, chunk) in (1_u32..).zip(output.chunks_mut(tag_size)) {
            // RFC 8018 §5.2 computes U1 from salt and a one-based block index.
            let mut first = mac.clone();
            first.update(&self.salt);
            first.update(&counter.to_be_bytes());
            let mut tag = Zeroizing::new(first.finalize().into_bytes());
            chunk.copy_from_slice(&tag[..chunk.len()]);

            for _ in 1..self.iterations.get() {
                let mut next = mac.clone();
                next.update(tag.as_slice());
                let mut digest = next.finalize().into_bytes();
                tag.copy_from_slice(&digest);
                digest.as_mut_slice().zeroize();
                for (byte, tag_byte) in chunk.iter_mut().zip(tag.iter()) {
                    *byte ^= *tag_byte;
                }
            }
        }
        Some(())
    }
}

#[derive(Clone, Copy)]
enum Prf {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512_224,
    Sha512_256,
}

impl Prf {
    fn parse(identifier: Item<'_>) -> Option<Self> {
        let (oid, parameters) = algorithm(identifier)?;
        if parameters.is_some_and(|p| p.tag != 0x05 || !p.data.is_empty()) {
            return None;
        }
        match oid.strip_prefix(RSADSI_DIGESTS)? {
            [7] => Some(Self::Sha1),
            [8] => Some(Self::Sha224),
            [9] => Some(Self::Sha256),
            [10] => Some(Self::Sha384),
            [11] => Some(Self::Sha512),
            [12] => Some(Self::Sha512_224),
            [13] => Some(Self::Sha512_256),
            _ => None,
        }
    }

    const fn tag_size(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha224 | Self::Sha512_224 => 28,
            Self::Sha256 | Self::Sha512_256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}
