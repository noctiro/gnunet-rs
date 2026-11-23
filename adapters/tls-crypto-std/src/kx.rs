//! RustCrypto key agreement over the TLS named-group encodings.
use getrandom::SysRng;
use ml_kem::{
    B32, Ciphertext, Decapsulate, DecapsulationKey768, DecapsulationKey1024, EncapsulationKey768,
    EncapsulationKey1024, Generate, KeyExport, MlKem768, TryKeyInit, kem::SharedKey,
};
use p256::elliptic_curve::sec1::ToSec1Point;
use rustls::{
    Error, NamedGroup, PeerMisbehaved, ProtocolVersion,
    crypto::{
        ActiveKeyExchange, CompletedKeyExchange, GetRandomFailed, SharedSecret, SupportedKxGroup,
    },
    ffdhe_groups::FfdheGroup,
};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::Zeroizing;

const INVALID_SHARE: Error = Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);
const X25519_SHARE: usize = 32;
const P256_SHARE: usize = 65;
const P384_SHARE: usize = 97;
const MLKEM768_CLIENT_SHARE: usize = 1184;
const MLKEM768_SERVER_SHARE: usize = 1088;

pub(super) static DEFAULT_KX_GROUPS: &[&dyn SupportedKxGroup] =
    &[&Curve::X25519, &Curve::P256, &Curve::P384, &Hybrid::X25519];

pub(super) static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    &Curve::X25519,
    &Curve::P256,
    &Curve::P384,
    &Hybrid::X25519,
    &Hybrid::P256,
    &MlKem::Kem768,
    &MlKem::Kem1024,
];

#[derive(Clone, Copy, Debug)]
enum Curve {
    X25519,
    P256,
    P384,
}

impl Curve {
    fn exchange(self) -> Result<Ecdh, Error> {
        match self {
            Self::X25519 => {
                let mut seed = Zeroizing::new([0; X25519_SHARE]);
                getrandom::fill(seed.as_mut()).map_err(|_| GetRandomFailed)?;
                let secret = X25519Secret::from(*seed);
                let share = X25519Public::from(&secret).to_bytes();
                Ok(Ecdh::X25519 { secret, share })
            }
            Self::P256 => {
                let secret = p256::ecdh::EphemeralSecret::try_generate_from_rng(&mut SysRng)
                    .map_err(|_| GetRandomFailed)?;
                let share = secret.public_key().to_sec1_point(false);
                Ok(Ecdh::P256 { secret, share })
            }
            Self::P384 => {
                let secret = p384::ecdh::EphemeralSecret::try_generate_from_rng(&mut SysRng)
                    .map_err(|_| GetRandomFailed)?;
                let share = secret.public_key().to_sec1_point(false);
                Ok(Ecdh::P384 { secret, share })
            }
        }
    }
}

impl SupportedKxGroup for Curve {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        Ok(Box::new(self.exchange()?))
    }

    fn start_and_complete(&self, peer: &[u8]) -> Result<CompletedKeyExchange, Error> {
        self.exchange()?.agree_with(peer, |share, secret| {
            Ok(CompletedKeyExchange {
                group: self.name(),
                pub_key: share.to_vec(),
                secret: SharedSecret::from(secret),
            })
        })
    }

    fn name(&self) -> NamedGroup {
        match self {
            Self::X25519 => NamedGroup::X25519,
            Self::P256 => NamedGroup::secp256r1,
            Self::P384 => NamedGroup::secp384r1,
        }
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }
}

enum Ecdh {
    X25519 {
        secret: X25519Secret,
        share: [u8; X25519_SHARE],
    },
    P256 {
        secret: p256::ecdh::EphemeralSecret,
        share: p256::Sec1Point,
    },
    P384 {
        secret: p384::ecdh::EphemeralSecret,
        share: p384::Sec1Point,
    },
}

impl Ecdh {
    fn agree(self, peer: &[u8]) -> Result<SharedSecret, Error> {
        self.agree_with(peer, |_, secret| Ok(SharedSecret::from(secret)))
    }

    // Keep each curve's zeroizing secret in its original storage until the
    // caller copies it into the final Rustls shared secret.
    fn agree_with<T>(
        self,
        peer: &[u8],
        finish: impl FnOnce(&[u8], &[u8]) -> Result<T, Error>,
    ) -> Result<T, Error> {
        match self {
            Self::X25519 { secret, share } => {
                let peer: [u8; X25519_SHARE] = peer.try_into().map_err(|_| INVALID_SHARE)?;
                let shared = secret.diffie_hellman(&X25519Public::from(peer));
                if !shared.was_contributory() {
                    return Err(INVALID_SHARE);
                }
                finish(&share, shared.as_ref())
            }
            Self::P256 { secret, share } => {
                uncompressed(peer, P256_SHARE)?;
                let peer = p256::PublicKey::from_sec1_bytes(peer).map_err(|_| INVALID_SHARE)?;
                let shared = secret.diffie_hellman(&peer);
                finish(share.as_bytes(), shared.raw_secret_bytes().as_slice())
            }
            Self::P384 { secret, share } => {
                uncompressed(peer, P384_SHARE)?;
                let peer = p384::PublicKey::from_sec1_bytes(peer).map_err(|_| INVALID_SHARE)?;
                let shared = secret.diffie_hellman(&peer);
                finish(share.as_bytes(), shared.raw_secret_bytes().as_slice())
            }
        }
    }
}

impl ActiveKeyExchange for Ecdh {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        self.agree(peer)
    }

    fn pub_key(&self) -> &[u8] {
        match self {
            Self::X25519 { share, .. } => share,
            Self::P256 { share, .. } => share.as_bytes(),
            Self::P384 { share, .. } => share.as_bytes(),
        }
    }

    fn group(&self) -> NamedGroup {
        match self {
            Self::X25519 { .. } => Curve::X25519.name(),
            Self::P256 { .. } => Curve::P256.name(),
            Self::P384 { .. } => Curve::P384.name(),
        }
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }
}

fn uncompressed(peer: &[u8], length: usize) -> Result<(), Error> {
    if peer.len() != length || peer.first() != Some(&4) {
        return Err(INVALID_SHARE);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum MlKem {
    Kem768,
    Kem1024,
}

impl SupportedKxGroup for MlKem {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        match self {
            Self::Kem768 => Ok(Box::new(KemClient::<DecapsulationKey768>::new(
                self.name(),
            )?)),
            Self::Kem1024 => Ok(Box::new(KemClient::<DecapsulationKey1024>::new(
                self.name(),
            )?)),
        }
    }

    fn start_and_complete(&self, peer: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let (pub_key, secret) = match self {
            Self::Kem768 => {
                let (ciphertext, secret) = encapsulate_768(peer)?;
                (ciphertext.to_vec(), secret)
            }
            Self::Kem1024 => {
                let key = EncapsulationKey1024::new_from_slice(peer).map_err(|_| INVALID_SHARE)?;
                let (ciphertext, secret) =
                    key.encapsulate_deterministic(&*encapsulation_randomness()?);
                (ciphertext.to_vec(), Zeroizing::new(secret))
            }
        };
        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key,
            secret: SharedSecret::from(secret.as_slice()),
        })
    }

    fn name(&self) -> NamedGroup {
        match self {
            Self::Kem768 => NamedGroup::MLKEM768,
            Self::Kem1024 => NamedGroup::MLKEM1024,
        }
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }
}

fn encapsulation_randomness() -> Result<Zeroizing<B32>, Error> {
    let mut random = Zeroizing::new(B32::default());
    getrandom::fill(random.as_mut_slice()).map_err(|_| GetRandomFailed)?;
    Ok(random)
}

fn encapsulate_768(peer: &[u8]) -> Result<(Ciphertext<MlKem768>, Zeroizing<B32>), Error> {
    let key = EncapsulationKey768::new_from_slice(peer).map_err(|_| INVALID_SHARE)?;
    let (ciphertext, secret) = key.encapsulate_deterministic(&*encapsulation_randomness()?);
    Ok((ciphertext, Zeroizing::new(secret)))
}

fn decapsulate<D: Decapsulate>(
    key: &D,
    peer: &[u8],
) -> Result<Zeroizing<SharedKey<D::Kem>>, Error> {
    key.decapsulate_slice(peer)
        .map(Zeroizing::new)
        .map_err(|_| INVALID_SHARE)
}

struct KemClient<D> {
    secret: D,
    share: Vec<u8>,
    group: NamedGroup,
}

impl<D: Decapsulate + Generate> KemClient<D> {
    fn new(group: NamedGroup) -> Result<Self, Error> {
        let secret = D::try_generate_from_rng(&mut SysRng).map_err(|_| GetRandomFailed)?;
        let share = secret.encapsulation_key().to_bytes().to_vec();
        Ok(Self {
            secret,
            share,
            group,
        })
    }
}

impl<D: Decapsulate + Send + Sync> ActiveKeyExchange for KemClient<D> {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let secret = decapsulate(&self.secret, peer)?;
        Ok(SharedSecret::from(secret.as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.share
    }

    fn group(&self) -> NamedGroup {
        self.group
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }
}

#[derive(Clone, Copy, Debug)]
enum Hybrid {
    X25519,
    P256,
}

impl Hybrid {
    fn curve(self) -> Curve {
        match self {
            Self::X25519 => Curve::X25519,
            Self::P256 => Curve::P256,
        }
    }

    // The hybrid groups specify different orders for both shares and secrets.
    fn join(self, classical: &[u8], kem: &[u8]) -> Vec<u8> {
        match self {
            Self::X25519 => [kem, classical].concat(),
            Self::P256 => [classical, kem].concat(),
        }
    }

    fn split(self, peer: &[u8], kem_length: usize) -> Result<(&[u8], &[u8]), Error> {
        let classical_length = match self {
            Self::X25519 => X25519_SHARE,
            Self::P256 => P256_SHARE,
        };
        if peer.len() != classical_length + kem_length {
            return Err(INVALID_SHARE);
        }
        Ok(match self {
            Self::X25519 => {
                let (kem, classical) = peer.split_at(kem_length);
                (classical, kem)
            }
            Self::P256 => peer.split_at(classical_length),
        })
    }
}

impl SupportedKxGroup for Hybrid {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let classical = self.curve().exchange()?;
        let kem =
            DecapsulationKey768::try_generate_from_rng(&mut SysRng).map_err(|_| GetRandomFailed)?;
        let share = self.join(
            classical.pub_key(),
            kem.encapsulation_key().to_bytes().as_slice(),
        );
        Ok(Box::new(HybridClient {
            group: *self,
            classical,
            kem,
            share,
        }))
    }

    fn start_and_complete(&self, peer: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let (peer_classical, peer_kem) = self.split(peer, MLKEM768_CLIENT_SHARE)?;
        self.curve()
            .exchange()?
            .agree_with(peer_classical, |share, classical| {
                let (ciphertext, kem) = encapsulate_768(peer_kem)?;
                Ok(CompletedKeyExchange {
                    group: self.name(),
                    pub_key: self.join(share, ciphertext.as_slice()),
                    secret: SharedSecret::from(self.join(classical, kem.as_slice())),
                })
            })
    }

    fn name(&self) -> NamedGroup {
        match self {
            Self::X25519 => NamedGroup::X25519MLKEM768,
            Self::P256 => NamedGroup::secp256r1MLKEM768,
        }
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }
}

struct HybridClient {
    group: Hybrid,
    classical: Ecdh,
    kem: DecapsulationKey768,
    share: Vec<u8>,
}

impl ActiveKeyExchange for HybridClient {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let group = self.group;
        let kem_key = &self.kem;
        let (peer_classical, peer_kem) = group.split(peer, MLKEM768_SERVER_SHARE)?;
        self.classical.agree_with(peer_classical, |_, classical| {
            let kem = decapsulate(kem_key, peer_kem)?;
            Ok(SharedSecret::from(group.join(classical, kem.as_slice())))
        })
    }

    fn pub_key(&self) -> &[u8] {
        &self.share
    }

    fn group(&self) -> NamedGroup {
        self.group.name()
    }

    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((self.classical.group(), self.classical.pub_key()))
    }

    fn complete_hybrid_component(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        self.classical.agree(peer)
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_offer_can_complete_the_classical_fallback() -> Result<(), Error> {
        for (hybrid, classical, offset) in [
            (Hybrid::X25519, Curve::X25519, MLKEM768_CLIENT_SHARE),
            (Hybrid::P256, Curve::P256, 0),
        ] {
            let client = hybrid.start()?;
            let (group, fallback) = client.hybrid_component().ok_or(INVALID_SHARE)?;
            if group != classical.name()
                || client.pub_key().get(offset..offset + fallback.len()) != Some(fallback)
            {
                return Err(Error::General(format!(
                    "invalid classical component for {:?}",
                    hybrid.name()
                )));
            }
            let server = classical.start_and_complete(fallback)?;
            let secret = client.complete_hybrid_component(&server.pub_key)?;
            if secret.secret_bytes() != server.secret.secret_bytes() {
                return Err(Error::General(format!(
                    "classical fallback mismatch for {:?}",
                    hybrid.name()
                )));
            }
        }
        Ok(())
    }

    #[test]
    fn named_groups_agree_on_the_same_secret() -> Result<(), Error> {
        for group in ALL_KX_GROUPS {
            let client = group.start()?;
            let server = group.start_and_complete(client.pub_key())?;
            let secret = client.complete(&server.pub_key)?;
            if server.group != group.name() || secret.secret_bytes() != server.secret.secret_bytes()
            {
                return Err(Error::General(format!(
                    "key exchange mismatch for {:?}",
                    group.name()
                )));
            }
        }
        for group in [&Curve::X25519, &Curve::P256, &Curve::P384] {
            let client = group.start()?;
            let invalid_peer = vec![0; client.pub_key().len()];
            if !matches!(
                client.complete(&invalid_peer),
                Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))
            ) {
                return Err(Error::General(format!(
                    "accepted invalid share for {:?}",
                    group.name()
                )));
            }
        }
        Ok(())
    }
}
