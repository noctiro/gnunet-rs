//! Real Quinn/Rustls TLS configuration. Caller owns trust and certificate input;
//! neither TLS completion nor a raw32 PID proposal becomes GNUnet authentication.
pub use crate::tls::Profile;
use gnunet_types::Error;
use std::sync::Arc;
/// Real configured Quinn endpoint TLS, with no raw key getter/secret Debug.
pub struct Tls {
    pub(crate) client: quinn::ClientConfig,
    pub(crate) server: quinn::ServerConfig,
    profile: Profile,
}
impl std::fmt::Debug for Tls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicTls")
            .field("profile", &self.profile)
            .field("credentials", &"[REDACTED]")
            .finish()
    }
}
/// Actual configuration failure; never a synthetic successful TLS witness.
#[derive(Debug)]
pub enum Failure {
    /// Invalid profile/resource option.
    Protocol(Error),
    /// Operating-system entropy for the QUIC handshake token key was unavailable.
    Entropy(std::io::Error),
    /// Actual fresh certificate generation failed.
    #[cfg(feature = "fresh-tls")]
    Certificate(rcgen::Error),
    /// Actual Rustls certificate/key installation failed.
    Rustls(rustls::Error),
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QUIC TLS configuration: {self:?}")
    }
}
impl std::error::Error for Failure {}
impl Tls {
    /// Adopt actual caller-owned TLS configurations. Their key/trust policy must
    /// already be selected explicitly; no file is opened and no handshake runs.
    /// ALPN and disabled early-data policy are fixed for the original profile.
    pub fn from_configs(
        mut client: rustls::ClientConfig,
        mut server: rustls::ServerConfig,
        profile: Profile,
    ) -> Result<Self, Failure> {
        let alpn: Vec<Vec<u8>> = match profile {
            Profile::Raw => gnunet_transport_quic::raw::ALPNS
                .iter()
                .map(|v| v.to_vec())
                .collect(),
            Profile::Http3 => vec![b"h3".to_vec()],
        };
        client.alpn_protocols = alpn.clone();
        client.enable_early_data = false;
        client.resumption = rustls::client::Resumption::disabled();
        server.alpn_protocols = alpn;
        server.max_early_data_size = 0;
        server.send_tls13_tickets = 0;
        let client = crate::quic_tls::Client::new(client).map_err(Failure::Rustls)?;
        let server = crate::quic_tls::Server::new(server).map_err(Failure::Rustls)?;
        let token_key = crate::local_keys::handshake_token_key().map_err(Failure::Entropy)?;
        Ok(Self {
            client: quinn::ClientConfig::new(Arc::new(client)),
            server: quinn::ServerConfig::new(Arc::new(server), token_key),
            profile,
        })
    }
    /// Exact configured original application protocol. This is not evidence of
    /// a connection handshake, certificate/PID binding or packet processing.
    pub const fn profile(&self) -> Profile {
        self.profile
    }
    /// Generate a fresh P-256 server certificate in memory and configure the
    /// shared Rust TLS provider. Profile policy governs client verification.
    #[cfg(feature = "fresh-tls")]
    pub fn fresh(profile: Profile, names: Vec<String>) -> Result<Self, Failure> {
        use gnunet_tls_crypto_host::certificate::P256Key;
        if names.is_empty() || names.len() > 16 || names.iter().any(|n| n.len() > 253) {
            return Err(Failure::Protocol(Error::InvalidInput));
        }
        let key = P256Key::generate().map_err(Failure::Certificate)?;
        let certificate = key.self_signed(names).map_err(Failure::Certificate)?;
        Self::from_generated(profile, certificate.into(), key)
    }

    #[cfg(feature = "fresh-tls")]
    pub(super) fn from_generated(
        profile: Profile,
        certificate: rustls::pki_types::CertificateDer<'static>,
        key: gnunet_tls_crypto_host::certificate::P256Key,
    ) -> Result<Self, Failure> {
        let provider = gnunet_tls_crypto_host::provider();
        let client = crate::tls::client(Arc::clone(&provider), profile).map_err(Failure::Rustls)?;
        let server = crate::tls::server_with_generated_key(provider, certificate, key, profile)
            .map_err(Failure::Rustls)?;
        Self::from_configs(client, server, profile)
    }
}
