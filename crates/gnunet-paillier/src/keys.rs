use crate::{
    CIPHERTEXT_BYTES, DecryptJob, EncryptJob, EncryptWithWitnessJob, Error, PRIME_ROUNDS, U2048,
    U4096,
};
use crypto_bigint::{
    Odd,
    modular::{FixedMontyForm, FixedMontyParams},
    nlimbs,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Explicit finite primitive work policy; no memory or entropy is reserved from
/// a global source. One unit is one exponent bit or fixed-size arithmetic step.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Total candidate1024-bit draws across both factors, maximum2^20.
    pub candidates: u32,
    /// Consecutive base/nonce sampling refusals before a real capacity failure.
    pub rejections: u32,
    /// Maximum work units accepted by any one advance call,1..64.
    pub units_per_turn: u16,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            candidates: 1 << 20,
            rejections: 4096,
            units_per_turn: 8,
        }
    }
}
impl Limits {
    /// Reject an unbounded or unusable profile before secret state is created.
    pub fn validate(self) -> Result<(), Error> {
        if self.candidates < 2
            || self.candidates > 1 << 20
            || self.rejections == 0
            || self.rejections > 1 << 20
            || self.units_per_turn == 0
            || self.units_per_turn > 64
        {
            return Err(Error::Capacity);
        }
        Ok(())
    }
    pub(crate) fn units(self, units: u16) -> Result<usize, Error> {
        if units == 0 || units > self.units_per_turn {
            return Err(Error::Capacity);
        }
        Ok(usize::from(units))
    }
}
/// Original unsigned plaintext residue. Never cloned, formatted or implicitly
/// exposed. Signed offset/range interpretation belongs to the scalar protocol.
pub struct Plaintext(pub(crate) Zeroizing<U2048>);
impl Plaintext {
    /// Copy into a zeroizing fixed-width BE buffer owned by the caller.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<[u8; 256]> {
        let encoded = Zeroizing::new(self.0.to_be_bytes());
        let mut bytes = Zeroizing::new([0; 256]);
        bytes.copy_from_slice(encoded.as_ref());
        bytes
    }
}
/// The exact original public ciphertext fields. Wire decoding preserves the
/// signed count; every arithmetic entry validates integer/unit/key membership.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Ciphertext {
    pub(crate) remaining: i32,
    pub(crate) bits: [u8; 512],
}
impl Ciphertext {
    /// Preserve all516 official bytes without granting mathematical validity.
    #[must_use]
    pub fn from_wire(wire: [u8; CIPHERTEXT_BYTES]) -> Self {
        let remaining = i32::from_be_bytes([wire[0], wire[1], wire[2], wire[3]]);
        let mut bits = [0; 512];
        bits.copy_from_slice(&wire[4..]);
        Self { remaining, bits }
    }
    /// Encode the exact signed BE32 count followed by the512-byte BE integer.
    #[must_use]
    pub fn to_wire(&self) -> [u8; CIPHERTEXT_BYTES] {
        let mut bytes = [0; CIPHERTEXT_BYTES];
        bytes[..4].copy_from_slice(&self.remaining.to_be_bytes());
        bytes[4..].copy_from_slice(&self.bits);
        bytes
    }
    /// Exact signed original guarantee field. It is not an authentication proof;
    /// homomorphic addition rejects counters outside the valid positive range.
    /// Decryption does not confuse this metadata with mathematical validity.
    #[must_use]
    pub const fn remaining_ops(&self) -> i32 {
        self.remaining
    }
    pub(crate) fn integer(&self) -> U4096 {
        U4096::from_be_slice(&self.bits)
    }
    pub(crate) fn from_integer(value: &U4096, remaining: i32) -> Self {
        let mut bits = [0; 512];
        bits.copy_from_slice(value.to_be_bytes().as_ref());
        Self { remaining, bits }
    }
}
/// Actual original public modulus and its reusable Montgomery parameters.
/// Shape validation is not a proof that an untrusted remote modulus has a
/// particular factorization or a trusted identity.
#[derive(Clone)]
pub struct PublicKey {
    pub(crate) n: U2048,
    pub(crate) square: U4096,
    pub(crate) params: FixedMontyParams<{ nlimbs(4096) }>,
}
impl PublicKey {
    /// Admit an odd2047/2048-bit original modulus, including normal C products.
    pub fn from_bytes(bytes: &[u8; 256]) -> Result<Self, Error> {
        Self::from_integer(U2048::from_be_slice(bytes))
    }
    pub(crate) fn from_integer(n: U2048) -> Result<Self, Error> {
        if !(2047..=2048).contains(&n.bits()) || !n.bit_vartime(0) {
            return Err(Error::InvalidKey);
        }
        let square: U4096 = n.concatenating_square();
        let odd = Odd::new(square).into_option().ok_or(Error::InvalidKey)?;
        let params = FixedMontyParams::new(odd);
        Ok(Self { n, square, params })
    }
    /// Exact original256-byte big-endian public modulus.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 256] {
        let mut bytes = [0; 256];
        bytes.copy_from_slice(self.n.to_be_bytes().as_ref());
        bytes
    }
    /// Admit a nonnegative magnitude strictly below this actual modulus.
    pub fn plaintext(&self, bytes: &[u8]) -> Result<Plaintext, Error> {
        if bytes.len() > 256 {
            return Err(Error::Range);
        }
        let mut padded = Zeroizing::new([0; 256]);
        padded[256 - bytes.len()..].copy_from_slice(bytes);
        let value = Zeroizing::new(U2048::from_be_slice(padded.as_ref()));
        if *value >= self.n {
            return Err(Error::Range);
        }
        Ok(Plaintext(value))
    }
    /// Convert a signed magnitude into its real Zn residue. The scalar profile
    /// normally adds its standard positive offset before using this primitive.
    pub fn signed_plaintext(&self, negative: bool, magnitude: &[u8]) -> Result<Plaintext, Error> {
        let mut value = self.plaintext(magnitude)?;
        if negative && *value.0 != U2048::ZERO {
            *value.0 = self.n.wrapping_sub(&value.0);
        }
        Ok(value)
    }
    pub(crate) fn validate_cipher(&self, cipher: &Ciphertext) -> Result<U4096, Error> {
        let c = cipher.integer();
        if c == U4096::ZERO || c >= self.square || c.gcd(&self.square) != U4096::ONE {
            return Err(Error::InvalidCipher);
        }
        Ok(c)
    }
    pub(crate) fn operations(&self, m: &U2048, desired: u32) -> Result<i32, Error> {
        if desired > i32::MAX as u32 || *m >= self.n {
            return Err(Error::Range);
        }
        let mut possible = 2047u32.saturating_sub(m.bits());
        // The fixed C formula assumes its2048-bit n. Preserve its normal count,
        // but never overstate a guarantee for an admitted2047-bit remote modulus.
        if *m != U2048::ZERO && possible > 0 {
            let doubled = Zeroizing::new(m.shl(possible));
            if *doubled >= self.n {
                possible -= 1;
            }
        }
        i32::try_from(possible.min(desired)).map_err(|_| Error::Range)
    }
    /// Start actual randomized encryption. No ciphertext exists until the
    /// explicit-entropy job has sampled a unit and completed real exponentiation.
    pub fn encrypt(
        &self,
        plaintext: Plaintext,
        desired_ops: u32,
        limits: Limits,
    ) -> Result<EncryptJob, Error> {
        EncryptJob::new(self, plaintext, desired_ops, limits)
    }
    /// Start the same encryption while retaining its actual secret randomizer
    /// for a caller-owned proof. The explicit witness job erases that unit on
    /// failure/cancel/drop; ordinary encrypt() retains no separate witness.
    pub fn encrypt_with_witness(
        &self,
        plaintext: Plaintext,
        desired_ops: u32,
        limits: Limits,
    ) -> Result<EncryptWithWitnessJob, Error> {
        EncryptWithWitnessJob::new(self, plaintext, desired_ops, limits)
    }
    /// Actual homomorphic addition under this same public modulus. Both original
    /// counters must be positive; result guarantee is exactly min(input)-1.
    pub fn homomorphic_add(&self, lhs: &Ciphertext, rhs: &Ciphertext) -> Result<Ciphertext, Error> {
        if !(1..=2047).contains(&lhs.remaining) || !(1..=2047).contains(&rhs.remaining) {
            return Err(Error::Range);
        }
        let a = Zeroizing::new(self.validate_cipher(lhs)?);
        let b = Zeroizing::new(self.validate_cipher(rhs)?);
        let a = Zeroizing::new(FixedMontyForm::new(&a, &self.params));
        let b = Zeroizing::new(FixedMontyForm::new(&b, &self.params));
        let result = Zeroizing::new(a.mul(&b));
        let value = Zeroizing::new(result.retrieve());
        Ok(Ciphertext::from_integer(
            &value,
            lhs.remaining.min(rhs.remaining) - 1,
        ))
    }
}
/// Original generated secret components. No Clone/Debug/Display or unvalidated
/// import can silently substitute factors or a different modulus.
pub struct PrivateKey {
    pub(crate) n: U2048,
    pub(crate) lambda: Zeroizing<U2048>,
    pub(crate) mu: Zeroizing<U2048>,
}
impl PrivateKey {
    /// Copy secret lambda||mu into an explicitly zeroizing caller-owned buffer.
    #[must_use]
    pub fn to_secret_bytes(&self) -> Zeroizing<[u8; 512]> {
        let lambda = Zeroizing::new(self.lambda.to_be_bytes());
        let mu = Zeroizing::new(self.mu.to_be_bytes());
        let mut out = Zeroizing::new([0; 512]);
        out[..256].copy_from_slice(lambda.as_ref());
        out[256..].copy_from_slice(mu.as_ref());
        out
    }
    /// Start actual decryption only under this key's original public modulus.
    pub fn decrypt(
        &self,
        public: &PublicKey,
        ciphertext: &Ciphertext,
        limits: Limits,
    ) -> Result<DecryptJob, Error> {
        DecryptJob::new(self, public, ciphertext, limits)
    }
}
/// One real generated public/private pair; both factors passed the configured
/// fixed80 independent strong probable-prime rounds and were distinct.
pub struct KeyPair {
    pub(crate) public: PublicKey,
    pub(crate) private: PrivateKey,
}
impl KeyPair {
    /// Original public key, without secret ownership transfer.
    #[must_use]
    pub const fn public_key(&self) -> &PublicKey {
        &self.public
    }
    /// Original nonclone zeroizing private key.
    #[must_use]
    pub const fn private_key(&self) -> &PrivateKey {
        &self.private
    }
}
// Keep prime assurance an actual fixed production constant, not a bypassable
// user-selected zero-round or deterministic-base profile.
const _: () = assert!(PRIME_ROUNDS >= 80);
