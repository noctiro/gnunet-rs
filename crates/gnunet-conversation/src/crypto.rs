//! Exact typed purpose20 ringing signatures; no native key or identity lookup.
use crate::{Peer, Port, wire};
use gnunet_crypto::{EddsaPrivateKey, EddsaPublicKey, EddsaSignature, gns::PkeySecret};
use gnunet_identity::{KeyType, SecretKey};
use gnunet_types::Error;
use zeroize::Zeroizing;

/// Actual signed caller introduction. This contains public material only, and
/// proves neither a live CADET source nor that the target accepted the call.
pub struct SignedRing {
    public: [u8; 36],
    signature: [u8; 68],
    expiration: u64,
}
impl SignedRing {
    /// Sign the official port/target/expiration purpose112 region with the
    /// original caller ego. Temporary secret copies are erased on every path.
    pub fn sign(
        key: &SecretKey,
        port: &Port,
        target: &Peer,
        expiration: u64,
    ) -> Result<Self, Error> {
        if expiration == 0 || expiration == u64::MAX {
            return Err(Error::InvalidInput);
        }
        let region = payload(port, target, expiration)?;
        let mut raw = Zeroizing::new([0; 32]);
        raw.copy_from_slice(&key.expose_serialized()[4..]);
        let sig = match key.key_type() {
            KeyType::Ecdsa => PkeySecret::from_bytes(*raw)?.sign(wire::RING_PURPOSE, &[&region])?,
            KeyType::Eddsa => *EddsaPrivateKey::from_seed(*raw)
                .sign(wire::RING_PURPOSE, &region)?
                .as_bytes(),
        };
        let mut signature = [0; 68];
        signature[..4].copy_from_slice(&key.key_type().value().to_be_bytes());
        signature[4..].copy_from_slice(&sig);
        Ok(Self {
            public: key.public_key()?,
            signature,
            expiration,
        })
    }
    /// Exact complete typed public caller key36.
    pub const fn public_key(&self) -> &[u8; 36] {
        &self.public
    }
    /// Exact complete typed signature68.
    pub const fn signature(&self) -> &[u8; 68] {
        &self.signature
    }
    /// Original finite absolute UTC expiration in microseconds.
    pub const fn expiration(&self) -> u64 {
        self.expiration
    }
}

/// Sealed result of verifying the original caller's exact RingInfo. The caller
/// must additionally bind the original channel, Line port and local identity.
pub struct VerifiedRing {
    public: [u8; 36],
    expiration: u64,
}
impl VerifiedRing {
    /// Original verified typed public key, suitable for Ring735.
    pub const fn public_key(&self) -> &[u8; 36] {
        &self.public
    }
    /// Original verified absolute UTC expiration.
    pub const fn expiration(&self) -> u64 {
        self.expiration
    }
}
/// Verify supported key/signature tags and exact signed context. Expired or
/// nonfinite invitations never become local Ring notifications. This proves
/// caller-key possession, not equality with the remote network peer identity.
pub fn verify(
    public: &[u8],
    signature: &[u8],
    port: &Port,
    target: &Peer,
    expiration: u64,
    utc: u64,
) -> Result<VerifiedRing, Error> {
    if utc == u64::MAX || expiration == u64::MAX {
        return Err(Error::TimeUncertain);
    }
    if expiration <= utc {
        return Err(Error::Timeout);
    }
    let public: &[u8; 36] = public.try_into().map_err(|_| Error::Malformed)?;
    let signature: &[u8; 68] = signature.try_into().map_err(|_| Error::Malformed)?;
    let kind = KeyType::from_value(u32::from_be_bytes(
        public[..4].try_into().map_err(|_| Error::Malformed)?,
    ))?;
    if signature[..4] != public[..4] {
        return Err(Error::Authentication);
    }
    let p: &[u8; 32] = public[4..].try_into().map_err(|_| Error::Malformed)?;
    let s: &[u8; 64] = signature[4..].try_into().map_err(|_| Error::Malformed)?;
    let region = payload(port, target, expiration)?;
    match kind {
        KeyType::Ecdsa => gnunet_crypto::gns::verify_pkey(p, wire::RING_PURPOSE, &[&region], s)?,
        KeyType::Eddsa => EddsaPublicKey::from_bytes(*p).verify(
            wire::RING_PURPOSE,
            &region,
            &EddsaSignature::from_bytes(*s),
        )?,
    }
    Ok(VerifiedRing {
        public: *public,
        expiration,
    })
}
fn payload(
    port: &Port,
    target: &Peer,
    expiration: u64,
) -> Result<[u8; wire::RING_INFO_BYTES], Error> {
    let mut region = [0; wire::RING_INFO_BYTES];
    wire::RingInfo {
        port,
        target,
        expiration,
    }
    .encode(&mut region)?;
    Ok(region)
}
