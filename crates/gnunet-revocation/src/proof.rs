use gnunet_gnsrecord::ZoneKey;
use gnunet_types::Error;
/// Number of distinct increasing nonces required by the current protocol.
pub const NONCES: usize = 32;
/// Current typed public-key encoding length, including its type word.
pub const KEY_BYTES: usize = 36;
/// Current signature length for both official blindable key families.
pub const SIGNATURE_BYTES: usize = 64;
/// Fields: timestamp (8), informational TTL (8), nonce set (256), typed public key (36), signature (64).
pub const PROOF_BYTES: usize = 372;
/// Exact public signature-purpose region length; TTL/nonces are not signed.
pub const SIGNING_BYTES: usize = 52;
pub(crate) fn word(input: &[u8], at: usize) -> Result<u64, Error> {
    Ok(u64::from_be_bytes(
        input
            .get(at..at + 8)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Truncated)?,
    ))
}
/// An immutable structural certificate view, with no authenticity assertion.
#[derive(Clone, Copy)]
pub struct Proof<'a>(&'a [u8; PROOF_BYTES]);
impl core::fmt::Debug for Proof<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RevocationProof(structural, unverified)")
    }
}
impl<'a> Proof<'a> {
    /// Decode one complete current certificate. Ignores no suffix and performs
    /// no signature, key derivation, PoW, clock, entropy, file or service work.
    pub fn parse(input: &'a [u8]) -> Result<Self, Error> {
        let bytes: &[u8; PROOF_BYTES] = input.try_into().map_err(|_| Error::Malformed)?;
        ZoneKey::from_wire(&bytes[272..308])?;
        Ok(Self(bytes))
    }
    /// The exact original public certificate bytes.
    #[must_use]
    pub const fn bytes(self) -> &'a [u8; PROOF_BYTES] {
        self.0
    }
    /// Original absolute microsecond timestamp.
    pub fn timestamp(self) -> u64 {
        u64::from_be_bytes(self.0.as_chunks::<8>().0[0])
    }
    /// Informational TTL; acceptance uses the work score and configured epochs.
    pub fn ttl(self) -> u64 {
        u64::from_be_bytes(self.0.as_chunks::<8>().0[1])
    }
    /// Original typed public zone. The point is not authenticated by decoding.
    pub fn public(self) -> Result<ZoneKey, Error> {
        ZoneKey::from_wire(&self.0[272..308])
    }
    /// One original nonce; no work hash is performed.
    pub fn nonce(self, index: usize) -> Result<u64, Error> {
        if index >= NONCES {
            return Err(Error::InvalidInput);
        }
        word(self.0, 16 + index * 8)
    }
    /// Actual strictly increasing nonce encoding, without asserting work quality.
    pub fn ordered(self) -> bool {
        self.0[16..272]
            .as_chunks::<8>()
            .0
            .iter()
            .zip(self.0[24..272].as_chunks::<8>().0.iter())
            .all(|(a, b)| a < b)
    }
    /// Exact original signature-purpose region for an external actual signer.
    /// Contains size52/purpose3/timestamp8/typed public key36 and no private data.
    pub fn signing_message(self) -> [u8; SIGNING_BYTES] {
        let mut key = [0; KEY_BYTES];
        key.copy_from_slice(&self.0[272..308]);
        gnunet_block::revocation::signing_message(self.timestamp(), &key)
    }
    /// Authenticate only the signature with the shared existing Rust primitive.
    /// A true result does not validate PoW, lifetime, publication or revocation.
    pub fn signature_valid(self) -> Result<bool, Error> {
        gnunet_block::revocation::signature_valid(self.0)
    }
    /// Begin real signature+ordered-set checking, then caller-scheduled hashes.
    pub fn verification(
        self,
        policy: crate::RevocationConfig,
    ) -> Result<Option<crate::Verification<'a>>, Error> {
        crate::Verification::new(self.0, policy)
    }
}
/// Fixed owned public certificate bytes. No secret signing key is retained.
#[derive(Clone)]
pub struct Certificate(pub(crate) [u8; PROOF_BYTES]);
impl core::fmt::Debug for Certificate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RevocationCertificate(unverified)")
    }
}
impl Certificate {
    /// Assemble actual externally supplied public fields and signature. This
    /// creates no signature or PoW and does not imply a valid certificate.
    pub fn from_parts(
        public: ZoneKey,
        timestamp: u64,
        ttl: u64,
        nonces: &[u64; NONCES],
        signature: &[u8; SIGNATURE_BYTES],
    ) -> Self {
        let mut bytes = [0; PROOF_BYTES];
        bytes[..8].copy_from_slice(&timestamp.to_be_bytes());
        bytes[8..16].copy_from_slice(&ttl.to_be_bytes());
        for (slot, nonce) in bytes[16..272].as_chunks_mut::<8>().0.iter_mut().zip(nonces) {
            slot.copy_from_slice(&nonce.to_be_bytes());
        }
        bytes[272..308].copy_from_slice(&public.to_wire());
        bytes[308..].copy_from_slice(signature);
        Self(bytes)
    }
    /// Copy one structurally checked public certificate, without cryptography.
    #[must_use]
    pub fn copy(proof: Proof<'_>) -> Self {
        Self(*proof.bytes())
    }
    /// Borrow the exact fixed public bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8; PROOF_BYTES] {
        &self.0
    }
    /// Original fixed typed public-key encoding, with no decoding or authenticity
    /// assertion. Borrowing it permits indices without another key allocation.
    #[must_use]
    pub fn public_encoding(&self) -> &[u8] {
        &self.0[272..308]
    }
    /// Borrow the original structural view; no signature/PoW is asserted.
    pub fn proof(&self) -> Result<Proof<'_>, Error> {
        Proof::parse(&self.0)
    }
}
