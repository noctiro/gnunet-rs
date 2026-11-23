//! RustCrypto algorithms for rustls TLS 1.2, TLS 1.3 and QUIC.
#![forbid(unsafe_code)]

mod aead;
/// Generate and issue certificates using Rust signing keys.
pub mod certificate;
mod kx;
mod schedule;
mod sign;
mod suites;

use rustls::crypto::{CryptoProvider, GetRandomFailed, SecureRandom};
use std::sync::{Arc, OnceLock};

/// Borrow the shared provider for an explicitly configured TLS endpoint.
/// Constructing this provider leaves the process-wide rustls default alone.
pub fn provider() -> Arc<CryptoProvider> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    Arc::clone(PROVIDER.get_or_init(|| {
        Arc::new(CryptoProvider {
            cipher_suites: suites::DEFAULT_SUITES.to_vec(),
            kx_groups: kx::DEFAULT_KX_GROUPS.to_vec(),
            signature_verification_algorithms: sign::ALGORITHMS,
            secure_random: &OsRandom,
            key_provider: sign::KEY_PROVIDER,
        })
    }))
}

/// All implemented groups for callers that set their own negotiation policy.
pub fn supported_key_exchange_groups() -> &'static [&'static dyn rustls::crypto::SupportedKxGroup] {
    kx::ALL_KX_GROUPS
}

#[derive(Debug)]
struct OsRandom;

impl SecureRandom for OsRandom {
    fn fill(&self, output: &mut [u8]) -> Result<(), GetRandomFailed> {
        getrandom::fill(output).map_err(|_| GetRandomFailed)
    }
}
