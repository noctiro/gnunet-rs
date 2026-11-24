//! Private-key loading and rustls signature selection.
mod ml_dsa;
mod rsa;
mod verify;

pub(crate) use verify::ALGORITHMS;

use ::rsa::{
    pkcs1,
    pkcs8::{AssociatedOid, PrivateKeyInfoRef, der::Decode},
};
use getrandom::SysRng;
use p256::ecdsa::signature::{RandomizedSigner, Signer as _};
use rustls::{
    Error, SignatureAlgorithm, SignatureScheme,
    crypto::KeyProvider,
    pki_types::{PrivateKeyDer, SubjectPublicKeyInfoDer, alg_id},
    sign::{Signer, SigningKey, public_key_to_spki},
};
use std::{fmt, sync::Arc};
use zeroize::Zeroizing;

pub(crate) static KEY_PROVIDER: &dyn KeyProvider = &RustKeyProvider;

#[derive(Debug)]
struct RustKeyProvider;

impl KeyProvider for RustKeyProvider {
    fn load_private_key(&self, der: PrivateKeyDer<'static>) -> Result<Arc<dyn SigningKey>, Error> {
        let der = Zeroizing::new(der);
        let (key, public) = Key::parse(&der)?;
        Ok(signing_key(key, public))
    }
}

pub(super) fn p256_signing_key(
    key: p256::ecdsa::SigningKey,
    public: p256::Sec1Point,
) -> Arc<dyn SigningKey> {
    signing_key(
        Key::P256(key),
        public_key_to_spki(&alg_id::ECDSA_P256, public),
    )
}

fn signing_key(key: Key, public: SubjectPublicKeyInfoDer<'static>) -> Arc<dyn SigningKey> {
    Arc::new(PrivateKey {
        // rustls lets a selected signer outlive the SigningKey handle.
        key: Arc::new(key),
        public,
    })
}

enum Key {
    Rsa(Box<::rsa::PrivateKey>),
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    P521(p521::ecdsa::SigningKey),
    Ed25519(ed25519_dalek::SigningKey),
    MlDsa(ml_dsa::SigningKey),
}

macro_rules! ec_key {
    ($curve:ident, $variant:ident, $algorithm:ident, $secret:expr) => {
        $secret.ok().map(|key| {
            let key: $curve::ecdsa::SigningKey = key.into();
            let public = public_key_to_spki(
                &alg_id::$algorithm,
                key.verifying_key().to_sec1_point(false),
            );
            (Key::$variant(key), public)
        })
    };
}

impl Key {
    fn parse(der: &PrivateKeyDer<'_>) -> Result<(Self, SubjectPublicKeyInfoDer<'static>), Error> {
        match der {
            PrivateKeyDer::Pkcs1(der) => Self::rsa(rsa::load_pkcs1(der.secret_pkcs1_der())),
            PrivateKeyDer::Sec1(der) => {
                let der = der.secret_sec1_der();
                ec_key!(p256, P256, ECDSA_P256, p256::SecretKey::from_sec1_der(der))
                    .or_else(|| {
                        ec_key!(p384, P384, ECDSA_P384, p384::SecretKey::from_sec1_der(der))
                    })
                    .or_else(|| {
                        ec_key!(p521, P521, ECDSA_P521, p521::SecretKey::from_sec1_der(der))
                    })
                    .ok_or_else(invalid_key)
            }
            PrivateKeyDer::Pkcs8(der) => {
                let info = PrivateKeyInfoRef::from_der(der.secret_pkcs8_der())
                    .map_err(|_| invalid_key())?;
                Self::from_pkcs8(info)
            }
            _ => Err(invalid_key()),
        }
    }

    fn from_pkcs8(
        info: PrivateKeyInfoRef<'_>,
    ) -> Result<(Self, SubjectPublicKeyInfoDer<'static>), Error> {
        match info.algorithm.oid {
            pkcs1::ALGORITHM_OID => Self::rsa(rsa::load_pkcs8(info)),
            p256::elliptic_curve::ALGORITHM_OID => {
                match info.algorithm.parameters_oid().map_err(|_| invalid_key())? {
                    p256::NistP256::OID => {
                        ec_key!(p256, P256, ECDSA_P256, p256::SecretKey::try_from(info))
                    }
                    p384::NistP384::OID => {
                        ec_key!(p384, P384, ECDSA_P384, p384::SecretKey::try_from(info))
                    }
                    p521::NistP521::OID => {
                        ec_key!(p521, P521, ECDSA_P521, p521::SecretKey::try_from(info))
                    }
                    _ => None,
                }
                .ok_or_else(invalid_key)
            }
            ed25519_dalek::pkcs8::ALGORITHM_OID => {
                let key = ed25519_dalek::SigningKey::try_from(info).map_err(|_| invalid_key())?;
                let public = public_key_to_spki(&alg_id::ED25519, key.verifying_key().as_bytes());
                Ok((Self::Ed25519(key), public))
            }
            _ => ml_dsa::SigningKey::from_pkcs8(info)
                .map(|(key, public)| (Self::MlDsa(key), public))
                .ok_or_else(invalid_key),
        }
    }

    fn rsa(
        key: Option<::rsa::PrivateKey>,
    ) -> Result<(Self, SubjectPublicKeyInfoDer<'static>), Error> {
        let key = key.ok_or_else(invalid_key)?;
        let public = rsa::public(&key)?;
        Ok((Self::Rsa(Box::new(key)), public))
    }

    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<SignatureScheme> {
        let scheme = match self {
            Self::Rsa(_) => {
                return rsa::SCHEMES
                    .iter()
                    .copied()
                    .find(|scheme| offered.contains(scheme));
            }
            Self::P256(_) => SignatureScheme::ECDSA_NISTP256_SHA256,
            Self::P384(_) => SignatureScheme::ECDSA_NISTP384_SHA384,
            Self::P521(_) => SignatureScheme::ECDSA_NISTP521_SHA512,
            Self::Ed25519(_) => SignatureScheme::ED25519,
            Self::MlDsa(key) => key.scheme(),
        };
        offered.contains(&scheme).then_some(scheme)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        match self {
            Self::Rsa(_) => SignatureAlgorithm::RSA,
            Self::P256(_) | Self::P384(_) | Self::P521(_) => SignatureAlgorithm::ECDSA,
            Self::Ed25519(_) => SignatureAlgorithm::ED25519,
            Self::MlDsa(_) => SignatureAlgorithm::Unknown(0),
        }
    }
}

struct PrivateKey {
    key: Arc<Key>,
    public: SubjectPublicKeyInfoDer<'static>,
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("RustCryptoSigningKey")
            .field("algorithm", &self.algorithm())
            .finish_non_exhaustive()
    }
}

impl SigningKey for PrivateKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let scheme = self.key.choose_scheme(offered)?;
        Some(Box::new(Selected {
            key: Arc::clone(&self.key),
            scheme,
        }))
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(self.public.as_ref()))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.key.algorithm()
    }
}

struct Selected {
    key: Arc<Key>,
    scheme: SignatureScheme,
}

impl fmt::Debug for Selected {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("RustCryptoSigner")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}

macro_rules! ec_sign {
    ($curve:ident, $key:expr, $message:expr) => {{
        let signature: $curve::ecdsa::Signature = $key
            .try_sign_with_rng(&mut SysRng, $message)
            .map_err(|_| signing_failed())?;
        signature.to_der().as_bytes().to_vec()
    }};
}

impl Signer for Selected {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(match self.key.as_ref() {
            Key::Rsa(key) => rsa::sign(key, self.scheme, message)?,
            Key::P256(key) => ec_sign!(p256, key, message),
            Key::P384(key) => ec_sign!(p384, key, message),
            Key::P521(key) => ec_sign!(p521, key, message),
            Key::Ed25519(key) => key
                .try_sign(message)
                .map_err(|_| signing_failed())?
                .to_bytes()
                .to_vec(),
            Key::MlDsa(key) => key.sign(message).ok_or_else(signing_failed)?,
        })
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

fn invalid_key() -> Error {
    Error::General("invalid or unsupported TLS private key".into())
}

fn signing_failed() -> Error {
    Error::General("TLS signing failed".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::rsa::pkcs8::{
        AlgorithmIdentifierRef, EncodePrivateKey,
        der::{
            Encode, SecretDocument,
            asn1::{Null, OctetStringRef},
        },
    };
    use p256::elliptic_curve::sec1::ToSec1Point;
    use rustls::pki_types::{PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};
    use std::io;

    fn spki(
        der: impl Into<PrivateKeyDer<'static>>,
        scheme: SignatureScheme,
    ) -> Result<SubjectPublicKeyInfoDer<'static>, Box<dyn std::error::Error>> {
        let key = KEY_PROVIDER.load_private_key(der.into())?;
        let signer = key
            .choose_scheme(&[scheme])
            .ok_or_else(|| io::Error::other("scheme rejected"))?;
        if signer.scheme() != scheme {
            return Err(io::Error::other("unexpected signer scheme").into());
        }
        let spki = key
            .public_key()
            .ok_or_else(|| io::Error::other("missing public key"))?;
        Ok(SubjectPublicKeyInfoDer::from(spki.as_ref().to_vec()))
    }

    #[test]
    fn classic_key_formats_select_the_expected_tls_scheme() -> Result<(), Box<dyn std::error::Error>>
    {
        macro_rules! check_curve {
            ($curve:ident, $algorithm:ident, $scheme:ident) => {{
                let secret = $curve::SecretKey::from_slice(&[7; 32])?;
                let public = public_key_to_spki(
                    &alg_id::$algorithm,
                    secret.public_key().to_sec1_point(false),
                );
                let pkcs8 = secret.to_pkcs8_der()?;
                let sec1 = secret.to_sec1_der()?;
                let scheme = SignatureScheme::$scheme;
                if spki(PrivatePkcs8KeyDer::from(pkcs8.as_bytes().to_vec()), scheme)? != public {
                    return Err(io::Error::other(concat!(
                        stringify!($curve),
                        " PKCS#8 SPKI mismatch"
                    ))
                    .into());
                }
                if spki(PrivateSec1KeyDer::from(sec1.to_vec()), scheme)? != public {
                    return Err(io::Error::other(concat!(
                        stringify!($curve),
                        " SEC1 SPKI mismatch"
                    ))
                    .into());
                }
            }};
        }
        check_curve!(p256, ECDSA_P256, ECDSA_NISTP256_SHA256);
        check_curve!(p384, ECDSA_P384, ECDSA_NISTP384_SHA384);
        check_curve!(p521, ECDSA_P521, ECDSA_NISTP521_SHA512);

        let seed = [7; 32];
        let secret = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public = public_key_to_spki(&alg_id::ED25519, secret.verifying_key().as_bytes());
        let private = OctetStringRef::new(&seed)?.to_der()?;
        let info = PrivateKeyInfoRef::new(
            AlgorithmIdentifierRef {
                oid: ed25519_dalek::pkcs8::ALGORITHM_OID,
                parameters: None,
            },
            OctetStringRef::new(&private)?,
        );
        let der = SecretDocument::encode_msg(&info)?;
        if spki(
            PrivatePkcs8KeyDer::from(der.as_bytes().to_vec()),
            SignatureScheme::ED25519,
        )? != public
        {
            return Err(io::Error::other("Ed25519 PKCS#8 SPKI mismatch").into());
        }
        Ok(())
    }

    #[test]
    fn rsa_accepts_pkcs1_and_pkcs8_with_absent_or_null_parameters()
    -> Result<(), Box<dyn std::error::Error>> {
        let der = include_bytes!("sign/fixtures/rsa-test-key.der");
        let info = PrivateKeyInfoRef::from_der(der)?;
        let scheme = SignatureScheme::RSA_PSS_SHA256;
        let public = spki(
            PrivatePkcs1KeyDer::from(info.private_key.as_bytes().to_vec()),
            scheme,
        )?;
        for parameters in [None, Some(Null.into())] {
            let algorithm = AlgorithmIdentifierRef {
                oid: pkcs1::ALGORITHM_OID,
                parameters,
            };
            let wrapped =
                SecretDocument::encode_msg(&PrivateKeyInfoRef::new(algorithm, info.private_key))?;
            if spki(
                PrivatePkcs8KeyDer::from(wrapped.as_bytes().to_vec()),
                scheme,
            )? != public
            {
                return Err(io::Error::other("RSA PKCS#1 and PKCS#8 SPKI mismatch").into());
            }
        }
        let algorithm = AlgorithmIdentifierRef {
            oid: pkcs1::ALGORITHM_OID,
            parameters: Some((&info.algorithm.oid).into()),
        };
        let invalid =
            SecretDocument::encode_msg(&PrivateKeyInfoRef::new(algorithm, info.private_key))?;
        if KEY_PROVIDER
            .load_private_key(PrivatePkcs8KeyDer::from(invalid.as_bytes().to_vec()).into())
            .is_ok()
        {
            return Err(io::Error::other("RSA accepted unsupported PKCS#8 parameters").into());
        }
        Ok(())
    }
}
