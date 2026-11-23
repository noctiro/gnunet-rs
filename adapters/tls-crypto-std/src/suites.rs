//! Cipher suite definitions shared by TLS and QUIC.
use crate::{aead, schedule};
use rustls::{
    CipherSuite, SignatureScheme, SupportedCipherSuite, Tls12CipherSuite, Tls13CipherSuite,
    crypto::{
        CipherSuiteCommon, KeyExchangeAlgorithm,
        cipher::{Tls12AeadAlgorithm, Tls13AeadAlgorithm},
        hash::Hash,
        tls12::Prf,
        tls13::Hkdf,
    },
    quic,
};

const ECDSA_SIGNATURES: &[SignatureScheme] = &[
    SignatureScheme::ED25519,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP256_SHA256,
];
const RSA_SIGNATURES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

const AES128: CipherPrimitives = CipherPrimitives::new(
    &aead::AES128_GCM,
    &schedule::SHA256,
    &schedule::PRF_SHA256,
    &schedule::HKDF_SHA256,
    1 << 24,
);
const AES256: CipherPrimitives = CipherPrimitives::new(
    &aead::AES256_GCM,
    &schedule::SHA384,
    &schedule::PRF_SHA384,
    &schedule::HKDF_SHA384,
    1 << 24,
);
const CHACHA: CipherPrimitives = CipherPrimitives::new(
    &aead::CHACHA20_POLY1305,
    &schedule::SHA256,
    &schedule::PRF_SHA256,
    &schedule::HKDF_SHA256,
    u64::MAX,
);

static TLS13_AES128: Tls13CipherSuite = AES128.tls13(CipherSuite::TLS13_AES_128_GCM_SHA256);

pub(super) const DEFAULT_SUITES: &[SupportedCipherSuite] = &[
    SupportedCipherSuite::Tls13(&AES256.tls13(CipherSuite::TLS13_AES_256_GCM_SHA384)),
    SupportedCipherSuite::Tls13(&TLS13_AES128),
    SupportedCipherSuite::Tls13(&CHACHA.tls13(CipherSuite::TLS13_CHACHA20_POLY1305_SHA256)),
    SupportedCipherSuite::Tls12(&AES256.tls12(
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        ECDSA_SIGNATURES,
    )),
    SupportedCipherSuite::Tls12(&AES128.tls12(
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        ECDSA_SIGNATURES,
    )),
    SupportedCipherSuite::Tls12(&CHACHA.tls12(
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        ECDSA_SIGNATURES,
    )),
    SupportedCipherSuite::Tls12(&AES256.tls12(
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        RSA_SIGNATURES,
    )),
    SupportedCipherSuite::Tls12(&AES128.tls12(
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        RSA_SIGNATURES,
    )),
    SupportedCipherSuite::Tls12(&CHACHA.tls12(
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        RSA_SIGNATURES,
    )),
];

struct CipherPrimitives {
    tls12: &'static dyn Tls12AeadAlgorithm,
    tls13: &'static dyn Tls13AeadAlgorithm,
    quic: &'static dyn quic::Algorithm,
    hash: &'static dyn Hash,
    prf: &'static dyn Prf,
    hkdf: &'static dyn Hkdf,
    record_limit: u64,
}

impl CipherPrimitives {
    const fn new<A: Tls12AeadAlgorithm + Tls13AeadAlgorithm + quic::Algorithm>(
        aead: &'static A,
        hash: &'static dyn Hash,
        prf: &'static dyn Prf,
        hkdf: &'static dyn Hkdf,
        record_limit: u64,
    ) -> Self {
        Self {
            tls12: aead,
            tls13: aead,
            quic: aead,
            hash,
            prf,
            hkdf,
            record_limit,
        }
    }

    const fn common(&self, suite: CipherSuite) -> CipherSuiteCommon {
        CipherSuiteCommon {
            suite,
            hash_provider: self.hash,
            confidentiality_limit: self.record_limit,
        }
    }

    const fn tls13(&self, suite: CipherSuite) -> Tls13CipherSuite {
        Tls13CipherSuite {
            common: self.common(suite),
            hkdf_provider: self.hkdf,
            aead_alg: self.tls13,
            quic: Some(self.quic),
        }
    }

    const fn tls12(
        &self,
        suite: CipherSuite,
        signatures: &'static [SignatureScheme],
    ) -> Tls12CipherSuite {
        Tls12CipherSuite {
            common: self.common(suite),
            prf_provider: self.prf,
            kx: KeyExchangeAlgorithm::ECDHE,
            sign: signatures,
            aead_alg: self.tls12,
        }
    }
}
