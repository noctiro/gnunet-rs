//! Official REGEX_ACCEPT type 23 artifact, without allocation or native services.
//!
//! GNUnet v0.29.1 `src/include/block_regex.h` and
//! `src/plugin/regex/plugin_block_regex.c`: the signed region is the first 80
//! bytes (purpose header, expiry and state key). The peer is the public key used
//! to verify that signature; it is not a separately signed field. The block's
//! DHT key is its embedded state key, not a hash of the complete block.
//!
//! Encoding or retaining bytes grants no authenticity. Only actual signature
//! verification constructs [`Authenticated`](crate::accept::Authenticated); expiry is a separate caller-clock
//! check. Even [`Verified`](crate::accept::Verified) establishes neither DHT provenance, a path signature,
//! original-operation correlation, peer reachability nor admission to a service.

use crate::Hash;
use gnunet_crypto::{EddsaPrivateKey, EddsaPublicKey, EddsaSignature};
use gnunet_types::Error;

/// Exact packed official accepting-block byte length.
pub const ACCEPT_BLOCK_BYTES: usize = 176;
/// Exact purpose-prefixed EdDSA input length: header 8 + expiry 8 + state key 64.
pub const ACCEPT_SIGNED_BYTES: usize = 80;
/// Official `GNUNET_SIGNATURE_PURPOSE_REGEX_ACCEPT`.
pub const ACCEPT_PURPOSE: u32 = 18;

/// Canonical public signing material. No peer, signature or secret key is held.
/// This may be retained by an original caller-owned asynchronous signing job;
/// the caller binds that job's source, peer, operation and lifetime separately.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptMaterial {
    bytes: [u8; ACCEPT_SIGNED_BYTES],
}
impl AcceptMaterial {
    /// Build the exact public 80-byte purpose 18 input with absolute microseconds.
    /// Any expiry is representable; this constructor does not read a clock or
    /// assert that the supplied expiry is current.
    #[must_use]
    pub fn new(key: Hash, expires: u64) -> Self {
        let mut bytes = [0; ACCEPT_SIGNED_BYTES];
        bytes[..4].copy_from_slice(&(ACCEPT_SIGNED_BYTES as u32).to_be_bytes());
        bytes[4..8].copy_from_slice(&ACCEPT_PURPOSE.to_be_bytes());
        bytes[8..16].copy_from_slice(&expires.to_be_bytes());
        bytes[16..80].copy_from_slice(&key);
        Self { bytes }
    }
    /// Original immutable signed bytes, including the exact purpose header.
    #[must_use]
    pub fn view(&self) -> &[u8; ACCEPT_SIGNED_BYTES] {
        &self.bytes
    }
    /// Exact embedded state key; no additional hashing or namespace transform.
    #[must_use]
    pub fn key(&self) -> Hash {
        let mut key = [0; 64];
        key.copy_from_slice(&self.bytes[16..80]);
        key
    }
    /// Advertised absolute expiration in GNUnet microseconds.
    #[must_use]
    pub fn expires(&self) -> u64 {
        u64::from_be_bytes([
            self.bytes[8],
            self.bytes[9],
            self.bytes[10],
            self.bytes[11],
            self.bytes[12],
            self.bytes[13],
            self.bytes[14],
            self.bytes[15],
        ])
    }
    /// Serialize exact peer/signature bytes returned by a caller's provider.
    /// This does not validate that provider or create an authentication proof.
    /// An asynchronous owner must correlate the original peer/material/job and
    /// actually verify the result before treating it as a signed publication.
    #[must_use]
    pub fn finish(&self, peer: [u8; 32], signature: [u8; 64]) -> [u8; ACCEPT_BLOCK_BYTES] {
        let mut block = [0; ACCEPT_BLOCK_BYTES];
        block[..80].copy_from_slice(&self.bytes);
        block[80..112].copy_from_slice(&peer);
        block[112..176].copy_from_slice(&signature);
        block
    }
    /// Actually sign with an explicit caller-owned Ed25519 key and serialize
    /// its actual public identity. The protocol owner must authorize this
    /// purpose 18 operation. No key is cloned/exported and no entropy, storage,
    /// PILS/OS service, task or implicit clock is used here.
    pub fn sign(&self, key: &EddsaPrivateKey) -> Result<[u8; ACCEPT_BLOCK_BYTES], Error> {
        let signature = key.sign(ACCEPT_PURPOSE, self.view())?;
        Ok(self.finish(*key.public_key().as_bytes(), *signature.as_bytes()))
    }
}

/// Exact borrowed structural view. Construction checks size and purpose header,
/// and leaves peer/key/signature bytes untrusted until actual verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptBlock<'a> {
    bytes: &'a [u8; ACCEPT_BLOCK_BYTES],
}
impl<'a> AcceptBlock<'a> {
    /// Decode exactly 176 bytes; a truncated prefix, trailing bytes, signed-size
    /// mismatch or wrong purpose is rejected. No signature/hash/key operation
    /// occurs in this structural decoder.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        if input.len() < ACCEPT_BLOCK_BYTES {
            return Err(Error::Truncated);
        }
        let bytes: &'a [u8; ACCEPT_BLOCK_BYTES] = input.try_into().map_err(|_| Error::Malformed)?;
        if u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
            != ACCEPT_SIGNED_BYTES as u32
            || u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) != ACCEPT_PURPOSE
        {
            return Err(Error::Malformed);
        }
        Ok(Self { bytes })
    }
    /// Exact borrowed artifact, without any authenticity elevation.
    #[must_use]
    pub fn as_bytes(self) -> &'a [u8; ACCEPT_BLOCK_BYTES] {
        self.bytes
    }
    /// Copy the exact original artifact; capacity failure leaves output intact.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        if output.len() < ACCEPT_BLOCK_BYTES {
            return Err(Error::Capacity);
        }
        output[..ACCEPT_BLOCK_BYTES].copy_from_slice(self.bytes);
        Ok(ACCEPT_BLOCK_BYTES)
    }
    /// Borrow the original 80-byte signed prefix, including purpose and size.
    #[must_use]
    pub fn material(self) -> &'a [u8] {
        &self.bytes[..ACCEPT_SIGNED_BYTES]
    }
    /// Exact DHT state key embedded by the producer, still untrusted.
    #[must_use]
    pub fn key(self) -> Hash {
        let mut key = [0; 64];
        key.copy_from_slice(&self.bytes[16..80]);
        key
    }
    /// Exact claimed signing peer. This accessor alone does not verify it.
    #[must_use]
    pub fn peer(self) -> [u8; 32] {
        let mut peer = [0; 32];
        peer.copy_from_slice(&self.bytes[80..112]);
        peer
    }
    /// Exact unverified Ed25519 signature bytes.
    #[must_use]
    pub fn signature(self) -> [u8; 64] {
        let mut signature = [0; 64];
        signature.copy_from_slice(&self.bytes[112..176]);
        signature
    }
    /// Advertised absolute expiration in GNUnet microseconds.
    #[must_use]
    pub fn expires(self) -> u64 {
        u64::from_be_bytes([
            self.bytes[8],
            self.bytes[9],
            self.bytes[10],
            self.bytes[11],
            self.bytes[12],
            self.bytes[13],
            self.bytes[14],
            self.bytes[15],
        ])
    }
    /// Independent time predicate matching `GNUNET_TIME_absolute_is_past`:
    /// expiry < now is past; equality remains current. This establishes no
    /// signature validity. The caller supplies its actual time domain/sample.
    #[must_use]
    pub fn is_expired(self, now: u64) -> bool {
        self.expires() < now
    }
    /// Check expiry independently of cryptographic authenticity.
    pub fn check_expiration(self, now: u64) -> Result<(), Error> {
        if self.is_expired(now) {
            Err(Error::Timeout)
        } else {
            Ok(())
        }
    }
    /// Verify the expected original query key and actual peer-public-key EdDSA
    /// signature over the exact 80-byte purpose 18 input. Does not check expiry.
    /// A caller must still bind the actual provider operation/source and use
    /// [`Authenticated::at`] before using an authenticated current result.
    pub fn verify_signature(self, expected_key: &Hash) -> Result<Authenticated<'a>, Error> {
        if &self.key() != expected_key {
            return Err(Error::Authentication);
        }
        EddsaPublicKey::from_bytes(self.peer()).verify(
            ACCEPT_PURPOSE,
            self.material(),
            &EddsaSignature::from_bytes(self.signature()),
        )?;
        Ok(Authenticated { block: self })
    }
    /// Actual expected-key/signature verification plus the explicit expiry
    /// check at now. Expired bytes are rejected before expensive verification;
    /// this function creates no remote/provider receipt or service grant.
    pub fn verify(self, now: u64, expected_key: &Hash) -> Result<Verified<'a>, Error> {
        self.check_expiration(now)?;
        self.verify_signature(expected_key)?.at(now)
    }
}

/// Private-constructor evidence of an actual successful purpose 18 verification
/// against this exact immutable block and expected key. Expiry is not implied.
#[derive(Debug)]
pub struct Authenticated<'a> {
    block: AcceptBlock<'a>,
}
impl<'a> Authenticated<'a> {
    /// Check the independent expiry at the caller's actual time sample. A new
    /// time check creates no new network/provider operation or signature.
    pub fn at(self, now: u64) -> Result<Verified<'a>, Error> {
        self.block.check_expiration(now)?;
        Ok(Verified {
            block: self.block,
            checked_at: now,
        })
    }
    /// Actual signature's public peer, without reachability/path authority.
    #[must_use]
    pub fn peer(&self) -> [u8; 32] {
        self.block.peer()
    }
    /// Expected key bound by the completed signature verification.
    #[must_use]
    pub fn key(&self) -> Hash {
        self.block.key()
    }
    /// Signed expiration; validity at any time still needs a separate check.
    #[must_use]
    pub fn expires(&self) -> u64 {
        self.block.expires()
    }
}

/// Actual signature/key verification and a successful expiry check at one
/// explicit sample. This is not a continuing clock/source/deadline lease.
/// Correlate original DHT/IPC jobs separately and recheck expiry before later use.
#[derive(Debug)]
pub struct Verified<'a> {
    block: AcceptBlock<'a>,
    checked_at: u64,
}
impl Verified<'_> {
    /// Actual signing peer, not a route or connectivity proof.
    #[must_use]
    pub fn peer(&self) -> [u8; 32] {
        self.block.peer()
    }
    /// Exact state key checked against the original expected query key.
    #[must_use]
    pub fn key(&self) -> Hash {
        self.block.key()
    }
    /// Actual signed absolute expiration.
    #[must_use]
    pub fn expires(&self) -> u64 {
        self.block.expires()
    }
    /// Caller time sample at which the independent expiry check succeeded.
    #[must_use]
    pub fn checked_at(&self) -> u64 {
        self.checked_at
    }
    /// Recheck this immutable signature's expiry without repeating cryptography.
    /// Caller still owns its original operation/source and cannot extend them
    /// by supplying a different or rolled-back clock value here.
    pub fn check_expiration(&self, now: u64) -> Result<(), Error> {
        self.block.check_expiration(now)
    }
}
