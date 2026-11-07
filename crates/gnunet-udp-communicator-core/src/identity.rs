use crate::PeerId;
use gnunet_crypto::{EddsaPrivateKey, EddsaPublicKey, EddsaSignature};
use gnunet_session_crypto::{
    Prk,
    elligator::{self, Representative},
    exchange::{self, EcdhePublic, EcdheSecret},
};
use gnunet_types::Error;
use zeroize::Zeroize;
/// Current local signing/exchange identity. No Clone, Debug or secret exporter.
/// Native initialization derives this from verified current PILS seed under its
/// existing writer/key-generation owner; no master identity material is required.
pub struct Identity {
    signing: EddsaPrivateKey,
    exchange: EcdheSecret,
}
impl Identity {
    /// Consume one current Ed25519 seed and erase this local copy.
    #[must_use]
    pub fn from_seed(mut seed: [u8; 32]) -> Self {
        let signing = EddsaPrivateKey::from_seed(seed);
        let exchange = EcdheSecret::from_eddsa_seed(seed);
        seed.zeroize();
        Self { signing, exchange }
    }
    /// Current public identity, without endpoint authority.
    #[must_use]
    pub fn peer(&self) -> PeerId {
        *self.signing.public_key().as_bytes()
    }
    pub(crate) fn sign(&self, purpose: u32, region: &[u8]) -> Result<[u8; 64], Error> {
        Ok(*self.signing.sign(purpose, region)?.as_bytes())
    }
    pub(crate) fn initial(&self, enc: Representative) -> Result<Prk, Error> {
        elligator::decapsulate(&self.exchange, enc)
    }
    /// Decapsulate a rekey only after the containing BOX was authenticated.
    /// This transfers secret material, not replay/window admission.
    pub fn decapsulate_rekey(&self, enc: [u8; 32]) -> Result<Prk, Error> {
        exchange::kem_decapsulate(&self.exchange, EcdhePublic::from_bytes(enc))
    }
}
pub(crate) fn verify(
    peer: PeerId,
    purpose: u32,
    region: &[u8],
    signature: [u8; 64],
) -> Result<(), Error> {
    EddsaPublicKey::from_bytes(peer).verify(purpose, region, &EddsaSignature::from_bytes(signature))
}
impl Identity {
    /// Sign only the official clear LAN discovery purpose34 region. The native
    /// host supplies the actual source sockaddr hash with port zero; this does
    /// not authorize an endpoint or replenish any session's packet credit.
    pub fn broadcast(&self, address_hash: &[u8; 64]) -> Result<crate::wire::Broadcast, Error> {
        let sender = self.peer();
        let region = crate::wire::broadcast_region(sender, address_hash);
        Ok(crate::wire::Broadcast {
            sender,
            signature: self.sign(34, &region)?,
        })
    }
}
impl crate::wire::Broadcast {
    /// Verify the original purpose34 signature for one explicitly supplied
    /// source sockaddr hash. A successful check is an address hint, not a
    /// session handshake, replay receipt or TRANSPORT validation result.
    pub fn verify(&self, address_hash: &[u8; 64]) -> Result<(), Error> {
        let region = crate::wire::broadcast_region(self.sender, address_hash);
        verify(self.sender, 34, &region, self.signature)
    }
}
