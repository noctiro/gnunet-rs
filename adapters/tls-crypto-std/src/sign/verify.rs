//! WebPKI certificate and handshake signature verification.
use super::{ml_dsa::Profile, rsa};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use rustls::{
    SignatureScheme,
    crypto::WebPkiSupportedAlgorithms,
    pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id},
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::fmt;

#[derive(Clone, Copy, Debug)]
enum Curve {
    P256,
    P384,
    P521,
}

#[derive(Clone, Copy, Debug)]
enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Clone, Copy, Debug)]
enum Method {
    Ecdsa(Curve, Hash),
    Ed25519,
    Rsa(SignatureScheme),
    MlDsa(Profile),
}

struct Algorithm {
    method: Method,
    public_key: AlgorithmIdentifier,
    signature: AlgorithmIdentifier,
}

impl Algorithm {
    const fn new(
        method: Method,
        public_key: AlgorithmIdentifier,
        signature: AlgorithmIdentifier,
    ) -> Self {
        Self {
            method,
            public_key,
            signature,
        }
    }

    const fn ecdsa(curve: Curve, hash: Hash) -> Self {
        let public_key = match curve {
            Curve::P256 => alg_id::ECDSA_P256,
            Curve::P384 => alg_id::ECDSA_P384,
            Curve::P521 => alg_id::ECDSA_P521,
        };
        let signature = match hash {
            Hash::Sha256 => alg_id::ECDSA_SHA256,
            Hash::Sha384 => alg_id::ECDSA_SHA384,
            Hash::Sha512 => alg_id::ECDSA_SHA512,
        };
        Self::new(Method::Ecdsa(curve, hash), public_key, signature)
    }

    const fn rsa(scheme: SignatureScheme, signature: AlgorithmIdentifier) -> Self {
        Self::new(Method::Rsa(scheme), alg_id::RSA_ENCRYPTION, signature)
    }

    const fn ml_dsa(profile: Profile) -> Self {
        let algorithm = profile.algorithm();
        Self::new(Method::MlDsa(profile), algorithm, algorithm)
    }
}

impl fmt::Debug for Algorithm {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_tuple("RustCrypto")
            .field(&self.method)
            .finish()
    }
}

impl SignatureVerificationAlgorithm for Algorithm {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        match self.method {
            Method::Ecdsa(curve, hash) => verify_ecdsa(curve, hash, public_key, message, signature),
            Method::Ed25519 => verify_ed25519(public_key, message, signature),
            Method::Rsa(scheme) => rsa::verify(scheme, public_key, message, signature),
            Method::MlDsa(profile) => profile.verify(public_key, message, signature),
        }
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature
    }
}

fn verify_ecdsa(
    curve: Curve,
    hash: Hash,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), InvalidSignature> {
    // Accept SEC1 compressed/uncompressed public keys and ASN.1 DER signatures.
    // RustCrypto applies the curve's digest truncation for cross-curve TLS 1.2.
    let digest256;
    let digest384;
    let digest512;
    let digest: &[u8] = match hash {
        Hash::Sha256 => {
            digest256 = Sha256::digest(message);
            &digest256
        }
        Hash::Sha384 => {
            digest384 = Sha384::digest(message);
            &digest384
        }
        Hash::Sha512 => {
            digest512 = Sha512::digest(message);
            &digest512
        }
    };

    macro_rules! verify {
        ($curve:ident) => {{
            let key = $curve::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|_| InvalidSignature)?;
            let signature =
                $curve::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
            key.verify_prehash(digest, &signature)
                .map_err(|_| InvalidSignature)
        }};
    }

    match curve {
        Curve::P256 => verify!(p256),
        Curve::P384 => verify!(p384),
        Curve::P521 => verify!(p521),
    }
}

fn verify_ed25519(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), InvalidSignature> {
    let bytes = public_key.try_into().map_err(|_| InvalidSignature)?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(bytes).map_err(|_| InvalidSignature)?;
    let signature =
        ed25519_dalek::Signature::from_slice(signature).map_err(|_| InvalidSignature)?;
    key.verify_strict(message, &signature)
        .map_err(|_| InvalidSignature)
}

static P256_SHA256: Algorithm = Algorithm::ecdsa(Curve::P256, Hash::Sha256);
static P256_SHA384: Algorithm = Algorithm::ecdsa(Curve::P256, Hash::Sha384);
static P256_SHA512: Algorithm = Algorithm::ecdsa(Curve::P256, Hash::Sha512);
static P384_SHA256: Algorithm = Algorithm::ecdsa(Curve::P384, Hash::Sha256);
static P384_SHA384: Algorithm = Algorithm::ecdsa(Curve::P384, Hash::Sha384);
static P384_SHA512: Algorithm = Algorithm::ecdsa(Curve::P384, Hash::Sha512);
static P521_SHA256: Algorithm = Algorithm::ecdsa(Curve::P521, Hash::Sha256);
static P521_SHA384: Algorithm = Algorithm::ecdsa(Curve::P521, Hash::Sha384);
static P521_SHA512: Algorithm = Algorithm::ecdsa(Curve::P521, Hash::Sha512);
static ED25519: Algorithm = Algorithm::new(Method::Ed25519, alg_id::ED25519, alg_id::ED25519);

static RSA_PSS_SHA256: Algorithm =
    Algorithm::rsa(SignatureScheme::RSA_PSS_SHA256, alg_id::RSA_PSS_SHA256);
static RSA_PSS_SHA384: Algorithm =
    Algorithm::rsa(SignatureScheme::RSA_PSS_SHA384, alg_id::RSA_PSS_SHA384);
static RSA_PSS_SHA512: Algorithm =
    Algorithm::rsa(SignatureScheme::RSA_PSS_SHA512, alg_id::RSA_PSS_SHA512);
static RSA_PKCS1_SHA256: Algorithm =
    Algorithm::rsa(SignatureScheme::RSA_PKCS1_SHA256, alg_id::RSA_PKCS1_SHA256);
static RSA_PKCS1_SHA384: Algorithm =
    Algorithm::rsa(SignatureScheme::RSA_PKCS1_SHA384, alg_id::RSA_PKCS1_SHA384);
static RSA_PKCS1_SHA512: Algorithm =
    Algorithm::rsa(SignatureScheme::RSA_PKCS1_SHA512, alg_id::RSA_PKCS1_SHA512);

// RFC 4055 requires verifiers to accept absent signature identifier parameters as well as NULL.
static RSA_PKCS1_SHA256_ABSENT: Algorithm = Algorithm::rsa(
    SignatureScheme::RSA_PKCS1_SHA256,
    AlgorithmIdentifier::from_slice(b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b"),
);
static RSA_PKCS1_SHA384_ABSENT: Algorithm = Algorithm::rsa(
    SignatureScheme::RSA_PKCS1_SHA384,
    AlgorithmIdentifier::from_slice(b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0c"),
);
static RSA_PKCS1_SHA512_ABSENT: Algorithm = Algorithm::rsa(
    SignatureScheme::RSA_PKCS1_SHA512,
    AlgorithmIdentifier::from_slice(b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0d"),
);

static ML_DSA_44: Algorithm = Algorithm::ml_dsa(Profile::MlDsa44);
static ML_DSA_65: Algorithm = Algorithm::ml_dsa(Profile::MlDsa65);
static ML_DSA_87: Algorithm = Algorithm::ml_dsa(Profile::MlDsa87);

pub(crate) const ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        &P256_SHA256,
        &P256_SHA384,
        &P256_SHA512,
        &P384_SHA256,
        &P384_SHA384,
        &P384_SHA512,
        &P521_SHA256,
        &P521_SHA384,
        &P521_SHA512,
        &ED25519,
        &RSA_PSS_SHA256,
        &RSA_PSS_SHA384,
        &RSA_PSS_SHA512,
        &RSA_PKCS1_SHA256,
        &RSA_PKCS1_SHA384,
        &RSA_PKCS1_SHA512,
        &RSA_PKCS1_SHA256_ABSENT,
        &RSA_PKCS1_SHA384_ABSENT,
        &RSA_PKCS1_SHA512_ABSENT,
        &ML_DSA_44,
        &ML_DSA_65,
        &ML_DSA_87,
    ],
    mapping: &[
        // TLS 1.3 uses the first verifier only. TLS 1.2 selects by hash and certificate curve.
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[&P384_SHA384, &P256_SHA384, &P521_SHA384],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[&P256_SHA256, &P384_SHA256, &P521_SHA256],
        ),
        (
            SignatureScheme::ECDSA_NISTP521_SHA512,
            &[&P521_SHA512, &P384_SHA512, &P256_SHA512],
        ),
        (SignatureScheme::ED25519, &[&ED25519]),
        (SignatureScheme::RSA_PSS_SHA512, &[&RSA_PSS_SHA512]),
        (SignatureScheme::RSA_PSS_SHA384, &[&RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA256, &[&RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PKCS1_SHA512, &[&RSA_PKCS1_SHA512]),
        (SignatureScheme::RSA_PKCS1_SHA384, &[&RSA_PKCS1_SHA384]),
        (SignatureScheme::RSA_PKCS1_SHA256, &[&RSA_PKCS1_SHA256]),
        (Profile::MlDsa44.scheme(), &[&ML_DSA_44]),
        (Profile::MlDsa65.scheme(), &[&ML_DSA_65]),
        (Profile::MlDsa87.scheme(), &[&ML_DSA_87]),
    ],
};
