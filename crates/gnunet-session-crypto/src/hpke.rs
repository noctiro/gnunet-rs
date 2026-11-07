//! Official v0.29.1 HPKE context: X25519 or Elligator/HKDF-SHA256/ChaCha20Poly1305.
//!
//! Only Base and PSK modes are implemented by the pinned C source. Auth and
//! AuthPsk are declared there but rejected. Elligator0x0022 has distinct typed
//! setup operations; the context schedule retains GNUnet's fixed0x0020 suite. The stored exporter secret is borrowable as an opaque PRK, matching
//! the public C context field. No absent RFC Export operation is invented.
use crate::{Prk, aead, elligator, exchange, hkdf_extract};
use gnunet_crypto::Entropy;
use gnunet_types::Error;
use zeroize::{Zeroize, Zeroizing};

/// Official authenticated-encryption tag length.
pub const TAG_BYTES: usize = 16;
/// Official ephemeral public encapsulation length.
pub const ENCAPSULATION_BYTES: usize = 32;
/// Full one-shot wire overhead (encapsulation plus tag).
pub const ONESHOT_OVERHEAD: usize = ENCAPSULATION_BYTES + TAG_BYTES;
const SUITE: &[u8] = b"HPKE\x00\x20\x00\x01\x00\x03";

/// Official declared mode values; only Base/PSK are implemented upstream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Mode {
    /// No preshared key or sender authentication.
    Base = 0,
    /// Preshared key and nonempty key identifier.
    Psk = 1,
    /// Declared but unsupported by v0.29.1 setup2.
    Auth = 2,
    /// Declared but unsupported by v0.29.1 setup2.
    AuthPsk = 3,
}
impl TryFrom<u8> for Mode {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Error> {
        match value {
            0 => Ok(Self::Base),
            1 => Ok(Self::Psk),
            2 => Ok(Self::Auth),
            3 => Ok(Self::AuthPsk),
            _ => Err(Error::Unsupported),
        }
    }
}
/// Official KEM values, never negotiated by a private extension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Kem {
    /// DHKEM(X25519,HKDF-SHA256), implemented.
    X25519 = 0x0020,
    /// Official Elligator variant, through the distinct representative setup API.
    X25519Elligator = 0x0022,
}
impl TryFrom<u16> for Kem {
    type Error = Error;
    fn try_from(value: u16) -> Result<Self, Error> {
        match value {
            0x0020 => Ok(Self::X25519),
            0x0022 => Ok(Self::X25519Elligator),
            _ => Err(Error::Unsupported),
        }
    }
}
/// Official context role; seal/open check it before writing output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Role {
    /// Receiver, official numeric value0.
    Receiver = 0,
    /// Sender, official numeric value1.
    Sender = 1,
}
/// Borrowed setup inputs. PSK bytes remain caller-owned and are never formatted.
pub struct Parameters<'a> {
    /// Declared key encapsulation mechanism.
    pub kem: Kem,
    /// Declared mode.
    pub mode: Mode,
    /// Exact context info, including any embedded zero bytes.
    pub info: &'a [u8],
    /// Preshared secret; nonempty exactly in PSK mode.
    pub psk: &'a [u8],
    /// Preshared key identifier; nonempty exactly when PSK is nonempty.
    pub psk_id: &'a [u8],
}
impl<'a> Parameters<'a> {
    /// Official default X25519 Base setup inputs.
    #[must_use]
    pub const fn base(info: &'a [u8]) -> Self {
        Self {
            kem: Kem::X25519,
            mode: Mode::Base,
            info,
            psk: &[],
            psk_id: &[],
        }
    }
    fn check(&self) -> Result<(), Error> {
        if self.mode != Mode::Base && self.mode != Mode::Psk {
            return Err(Error::Unsupported);
        }
        if self.psk.is_empty() != self.psk_id.is_empty()
            || (self.mode == Mode::Base && !self.psk.is_empty())
            || (self.mode == Mode::Psk && self.psk.is_empty())
        {
            return Err(Error::InvalidInput);
        }
        extract_preflight(b"psk_id_hash", self.psk_id.len())?;
        extract_preflight(b"info_hash", self.info.len())?;
        extract_preflight(b"secret", self.psk.len())?;
        for (label, length) in [
            (b"key".as_slice(), 32),
            (b"base_nonce".as_slice(), 12),
            (b"exp".as_slice(), 32),
        ] {
            expand_preflight(label, 65, length)?;
        }
        Ok(())
    }
    fn check_kem(&self, expected: Kem) -> Result<(), Error> {
        self.check()?;
        if self.kem != expected {
            return Err(Error::Unsupported);
        }
        Ok(())
    }
    /// Official Elligator0x0022 Base inputs, for the representative setup API.
    #[must_use]
    pub const fn base_elligator(info: &'a [u8]) -> Self {
        Self {
            kem: Kem::X25519Elligator,
            ..Self::base(info)
        }
    }
}
/// Exclusively owned session state. Key/exporter bytes erase on drop.
///
/// Sequence is stored as a host integer and serialized as BE64 only for nonce
/// derivation, matching C's network-order `ctx.seq` memory bytes. No state clone,
/// key dump, nonce rollback or implicit entropy source is exposed.
pub struct Context {
    role: Role,
    key: Zeroizing<[u8; 32]>,
    base_nonce: [u8; 12],
    sequence: u64,
    exporter: Prk,
}
fn extract_preflight(label: &[u8], value_len: usize) -> Result<(), Error> {
    7_usize
        .checked_add(SUITE.len())
        .and_then(|n| n.checked_add(label.len()))
        .and_then(|n| n.checked_add(value_len))
        .ok_or(Error::Overflow)?;
    Ok(())
}
fn expand_preflight(label: &[u8], info_len: usize, out_len: usize) -> Result<[u8; 2], Error> {
    let length = u16::try_from(out_len)
        .map_err(|_| Error::TooLarge)?
        .to_be_bytes();
    if out_len > 255 * 32 {
        return Err(Error::InvalidInput);
    }
    2_usize
        .checked_add(7)
        .and_then(|n| n.checked_add(SUITE.len()))
        .and_then(|n| n.checked_add(label.len()))
        .and_then(|n| n.checked_add(info_len))
        // The existing HKDF expand also admits its previous digest + counter.
        .and_then(|n| n.checked_add(32 + 1))
        .ok_or(Error::Overflow)?;
    Ok(length)
}
fn labeled_extract(salt: &[u8], label: &[u8], value: &[u8]) -> Result<Prk, Error> {
    extract_preflight(label, value.len())?;
    Ok(hkdf_extract(salt, &[b"HPKE-v1", SUITE, label, value]))
}
fn labeled_expand(prk: &Prk, label: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), Error> {
    let length = expand_preflight(label, info.len(), out.len())?;
    prk.expand(&[&length, b"HPKE-v1", SUITE, label, info], out)
}
fn schedule(role: Role, shared: &Prk, parameters: &Parameters<'_>) -> Result<Context, Error> {
    parameters.check()?;
    let psk_id_hash = labeled_extract(&[], b"psk_id_hash", parameters.psk_id)?;
    let info_hash = labeled_extract(&[], b"info_hash", parameters.info)?;
    let mut context = Zeroizing::new([0; 65]);
    context[0] = parameters.mode as u8;
    context[1..33].copy_from_slice(psk_id_hash.0.as_ref());
    context[33..].copy_from_slice(info_hash.0.as_ref());
    let secret = labeled_extract(shared.0.as_ref(), b"secret", parameters.psk)?;
    let mut key = Zeroizing::new([0; 32]);
    let mut base_nonce = [0; 12];
    let mut exporter = Zeroizing::new([0; 32]);
    labeled_expand(&secret, b"key", context.as_ref(), key.as_mut())?;
    labeled_expand(&secret, b"base_nonce", context.as_ref(), &mut base_nonce)?;
    labeled_expand(&secret, b"exp", context.as_ref(), exporter.as_mut())?;
    Ok(Context {
        role,
        key,
        base_nonce,
        sequence: 0,
        exporter: Prk(exporter),
    })
}
/// Deterministic official setup2 for Base/PSK. `sender_auth` is ignored by C in
/// these modes; Auth variants fail instead of silently becoming Base.
pub fn sender_setup2(
    ephemeral: &exchange::EcdheSecret,
    _sender_auth: Option<&exchange::EcdheSecret>,
    recipient: exchange::EcdhePublic,
    parameters: &Parameters<'_>,
) -> Result<(exchange::EcdhePublic, Context), Error> {
    parameters.check_kem(Kem::X25519)?;
    let (enc, shared) = exchange::kem_encapsulate(recipient, ephemeral)?;
    Ok((enc, schedule(Role::Sender, &shared, parameters)?))
}
/// Official default Base sender setup, drawing exactly32 explicit entropy bytes.
pub fn sender_setup(
    recipient: exchange::EcdhePublic,
    info: &[u8],
    entropy: &mut impl Entropy,
) -> Result<(exchange::EcdhePublic, Context), Error> {
    let parameters = Parameters::base(info);
    parameters.check_kem(Kem::X25519)?;
    let ephemeral = exchange::EcdheSecret::generate(entropy)?;
    sender_setup2(&ephemeral, None, recipient, &parameters)
}
/// Official receiver setup2 for Base/PSK. `sender_auth` is ignored in these modes.
pub fn receiver_setup2(
    encapsulation: exchange::EcdhePublic,
    recipient: &exchange::EcdheSecret,
    _sender_auth: Option<exchange::EcdhePublic>,
    parameters: &Parameters<'_>,
) -> Result<Context, Error> {
    parameters.check_kem(Kem::X25519)?;
    let shared = exchange::kem_decapsulate(recipient, encapsulation)?;
    schedule(Role::Receiver, &shared, parameters)
}
/// Official default Base receiver setup.
pub fn receiver_setup(
    encapsulation: exchange::EcdhePublic,
    recipient: &exchange::EcdheSecret,
    info: &[u8],
) -> Result<Context, Error> {
    receiver_setup2(encapsulation, recipient, None, &Parameters::base(info))
}
/// Official0x0022 setup2 using the actual special scalar and explicit tweak.
/// Base/PSK and all schedule lengths are checked before KEM work. The returned
/// encapsulation is a Representative, never an ordinary X25519 public-key alias.
/// GNUnet uses KEM0022 labels but retains HPKE0020 for the context schedule.
/// Auth modes remain unsupported; no raw shared-secret/context import is exposed.
pub fn sender_setup2_elligator(
    ephemeral: &elligator::Secret,
    tweak: u8,
    recipient: exchange::EcdhePublic,
    parameters: &Parameters<'_>,
) -> Result<(elligator::Representative, Context), Error> {
    parameters.check_kem(Kem::X25519Elligator)?;
    let (enc, shared) = elligator::encapsulate(recipient, ephemeral, tweak)?;
    Ok((enc, schedule(Role::Sender, &shared, parameters)?))
}
/// Explicit-entropy0x0022 Base/PSK setup with bounded rejection attempts.
/// Parameter/length refusal precedes every entropy call. The existing KEM owns
/// the exact tweak/scalar draw order, representability checks and secret erasure.
pub fn sender_setup2_elligator_random(
    recipient: exchange::EcdhePublic,
    parameters: &Parameters<'_>,
    entropy: &mut impl Entropy,
    attempts: core::num::NonZeroUsize,
) -> Result<(elligator::Representative, Context), Error> {
    parameters.check_kem(Kem::X25519Elligator)?;
    let (enc, shared) = elligator::encapsulate_random(recipient, entropy, attempts)?;
    Ok((enc, schedule(Role::Sender, &shared, parameters)?))
}
/// Official0x0022 receiver setup2 for an original representative and recipient.
/// Base/PSK and schedule lengths are checked before actual KEM decoding/DH.
/// The same GNUnet HPKE0020 context schedule is used; low-order DH fails through
/// the existing KEM without manufacturing a context or changing caller storage.
pub fn receiver_setup2_elligator(
    encapsulation: elligator::Representative,
    recipient: &exchange::EcdheSecret,
    parameters: &Parameters<'_>,
) -> Result<Context, Error> {
    parameters.check_kem(Kem::X25519Elligator)?;
    let shared = elligator::decapsulate(recipient, encapsulation)?;
    schedule(Role::Receiver, &shared, parameters)
}

impl Context {
    /// Official operation role.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }
    /// Sequence of the next attempted message, interpreted as a host integer.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Exact C `ctx.seq` memory bytes, in network order.
    #[must_use]
    pub const fn sequence_be(&self) -> [u8; 8] {
        self.sequence.to_be_bytes()
    }
    /// Current source nonce: base nonce XOR sequence BE64 in the last8 bytes.
    #[must_use]
    pub fn nonce(&self) -> [u8; 12] {
        let mut nonce = self.base_nonce;
        for (byte, seq) in nonce[4..].iter_mut().zip(self.sequence_be()) {
            *byte ^= seq;
        }
        nonce
    }
    /// Borrow the stored official context field as an opaque erased PRK.
    /// This is not an RFC Export function, which v0.29.1 does not expose.
    #[must_use]
    pub const fn exporter_secret(&self) -> &Prk {
        &self.exporter
    }
    /// Seal into separate caller storage, appending tag16. Capacity/role refusal
    /// is atomic; exhaustion erases the would-be ciphertext range and does not
    /// advance. Successful return is the actual ciphertext length.
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if self.role != Role::Sender {
            return Err(Error::InvalidInput);
        }
        let needed = seal_length(plaintext.len())?;
        if out.len() < needed {
            return Err(Error::Capacity);
        }
        if self.sequence == u64::MAX {
            out[..needed].zeroize();
            return Err(Error::TooLarge);
        }
        aead::preflight(plaintext.len(), aad.len())?;
        out[..plaintext.len()].copy_from_slice(plaintext);
        self.seal_in_place(aad, &mut out[..needed], plaintext.len())
    }
    /// Seal an existing plaintext prefix in place; remaining tag capacity must
    /// be present. Tail capacity after the returned length remains untouched.
    pub fn seal_in_place(
        &mut self,
        aad: &[u8],
        bytes: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize, Error> {
        if self.role != Role::Sender {
            return Err(Error::InvalidInput);
        }
        let needed = seal_length(plaintext_len)?;
        if bytes.len() < needed {
            return Err(Error::Capacity);
        }
        if self.sequence == u64::MAX {
            bytes[..needed].zeroize();
            return Err(Error::TooLarge);
        }
        let tag = aead::chacha20poly1305_seal(
            &self.key,
            &self.nonce(),
            aad,
            &mut bytes[..plaintext_len],
        )?;
        bytes[plaintext_len..needed].copy_from_slice(&tag);
        self.sequence += 1;
        Ok(needed)
    }
    /// Open separate ciphertext+tag into caller storage. A bad tag or exhausted
    /// sequence erases the plaintext range and never advances the sequence.
    /// Role, framing and capacity refusal leave the complete output unchanged.
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if self.role != Role::Receiver {
            return Err(Error::InvalidInput);
        }
        let length = open_length(ciphertext.len())?;
        if out.len() < length {
            return Err(Error::Capacity);
        }
        aead::preflight(length, aad.len())?;
        let tag = ciphertext[length..]
            .try_into()
            .map_err(|_| Error::Truncated)?;
        out[..length].copy_from_slice(&ciphertext[..length]);
        let result =
            aead::chacha20poly1305_open(&self.key, &self.nonce(), aad, &mut out[..length], tag);
        result?;
        if self.sequence == u64::MAX {
            out[..length].zeroize();
            return Err(Error::TooLarge);
        }
        self.sequence += 1;
        Ok(length)
    }
    /// Open one in-place ciphertext prefix; authenticated plaintext remains in
    /// its initial bytes. The trailing public tag and unused capacity stay put.
    pub fn open_in_place(
        &mut self,
        aad: &[u8],
        bytes: &mut [u8],
        ciphertext_len: usize,
    ) -> Result<usize, Error> {
        if self.role != Role::Receiver {
            return Err(Error::InvalidInput);
        }
        if bytes.len() < ciphertext_len {
            return Err(Error::Capacity);
        }
        let length = open_length(ciphertext_len)?;
        let mut tag = [0; TAG_BYTES];
        tag.copy_from_slice(&bytes[length..ciphertext_len]);
        aead::chacha20poly1305_open(&self.key, &self.nonce(), aad, &mut bytes[..length], &tag)?;
        if self.sequence == u64::MAX {
            bytes[..length].zeroize();
            return Err(Error::TooLarge);
        }
        self.sequence += 1;
        Ok(length)
    }
}
/// Checked ciphertext length, including the appended official tag.
pub fn seal_length(plaintext_len: usize) -> Result<usize, Error> {
    plaintext_len.checked_add(TAG_BYTES).ok_or(Error::Overflow)
}
/// Checked plaintext length; a complete tag must be present.
pub fn open_length(ciphertext_len: usize) -> Result<usize, Error> {
    ciphertext_len
        .checked_sub(TAG_BYTES)
        .ok_or(Error::Truncated)
}
/// Explicit distinction between full one-shot wire bytes and upstream's
/// ciphertext-only `ct_len_p` result, which excludes its preceding enc32.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OneshotLengths {
    /// Actual enc32+ciphertext+tag bytes written to caller storage.
    pub total_written: usize,
    /// Exactly the length the C one-shot seal reports (ciphertext+tag only).
    pub c_reported_ciphertext_len: usize,
}
/// Deterministic Base one-shot composition using an explicit ephemeral owner.
/// C exposes the same composition through setup2 plus seal.
pub fn seal_oneshot_with_ephemeral(
    recipient: exchange::EcdhePublic,
    ephemeral: &exchange::EcdheSecret,
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<OneshotLengths, Error> {
    let cipher_len = seal_length(plaintext.len())?;
    let total = cipher_len
        .checked_add(ENCAPSULATION_BYTES)
        .ok_or(Error::Overflow)?;
    if out.len() < total {
        return Err(Error::Capacity);
    }
    aead::preflight(plaintext.len(), aad.len())?;
    let (enc, mut context) = sender_setup2(ephemeral, None, recipient, &Parameters::base(info))?;
    let written = context.seal(aad, plaintext, &mut out[ENCAPSULATION_BYTES..total])?;
    out[..ENCAPSULATION_BYTES].copy_from_slice(enc.as_bytes());
    Ok(OneshotLengths {
        total_written: total,
        c_reported_ciphertext_len: written,
    })
}
/// Official Base one-shot seal with exactly32 bytes from explicit entropy.
pub fn seal_oneshot(
    recipient: exchange::EcdhePublic,
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
    entropy: &mut impl Entropy,
) -> Result<OneshotLengths, Error> {
    let total = seal_length(plaintext.len())?
        .checked_add(ENCAPSULATION_BYTES)
        .ok_or(Error::Overflow)?;
    if out.len() < total {
        return Err(Error::Capacity);
    }
    let ephemeral = exchange::EcdheSecret::generate(entropy)?;
    seal_oneshot_with_ephemeral(recipient, &ephemeral, info, aad, plaintext, out)
}
/// Official one-shot open, with explicit refusal of short enc/tag framing
/// before any access. C's underflowing short-input path is not exercised.
pub fn open_oneshot(
    recipient: &exchange::EcdheSecret,
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    if ciphertext.len() < ONESHOT_OVERHEAD {
        return Err(Error::Truncated);
    }
    let enc = exchange::EcdhePublic::from_bytes(
        ciphertext[..ENCAPSULATION_BYTES]
            .try_into()
            .map_err(|_| Error::Truncated)?,
    );
    let mut context = receiver_setup(enc, recipient, info)?;
    context.open(aad, &ciphertext[ENCAPSULATION_BYTES..], out)
}

#[cfg(test)]
mod tests;
