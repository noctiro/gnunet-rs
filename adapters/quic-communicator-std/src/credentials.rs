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
    /// Existing Rustls/TLS configuration invalid for QUIC1RTT.
    Quinn(quinn::crypto::rustls::NoInitialCipherSuite),
    /// Invalid profile/resource option.
    Protocol(Error),
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
        let client =
            quinn::crypto::rustls::QuicClientConfig::try_from(client).map_err(Failure::Quinn)?;
        let server =
            quinn::crypto::rustls::QuicServerConfig::try_from(server).map_err(Failure::Quinn)?;
        Ok(Self {
            client: quinn::ClientConfig::new(Arc::new(client)),
            server: quinn::ServerConfig::with_crypto(Arc::new(server)),
            profile,
        })
    }
    /// Exact configured original application protocol. This is not evidence of
    /// a connection handshake, certificate/PID binding or packet processing.
    pub const fn profile(&self) -> Profile {
        self.profile
    }
    /// Actual optional fresh in-memory TLS server certificate using existing
    /// AWS-LC backend. No PILS secret, existing key/certificate file or static
    /// private key is read. The caller still supplies actual client trust policy.
    #[cfg(feature = "fresh-tls")]
    pub fn fresh(profile: Profile, names: Vec<String>) -> Result<Self, Failure> {
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use zeroize::Zeroizing;
        if names.is_empty() || names.len() > 16 || names.iter().any(|n| n.len() > 253) {
            return Err(Failure::Protocol(Error::InvalidInput));
        }
        let key = zeroize::Zeroizing::new(
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
                .map_err(Failure::Certificate)?,
        );
        let params = rcgen::CertificateParams::new(names).map_err(Failure::Certificate)?;
        let certificate = params.self_signed(&*key).map_err(Failure::Certificate)?;
        let mut serialized = Zeroizing::new(key.serialize_der());
        let private =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(core::mem::take(&mut *serialized)));
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let client = crate::tls::client(provider.clone(), profile).map_err(Failure::Rustls)?;
        let server =
            crate::tls::server(provider, vec![certificate.der().clone()], private, profile)
                .map_err(Failure::Rustls)?;
        Self::from_configs(client, server, profile)
    }
}
