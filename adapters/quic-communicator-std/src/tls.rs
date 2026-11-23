//! Explicit TLS configuration for GNUnet's untrusted QUIC transport profiles.
//!
//! The pinned communicators accept transport certificates without WebPKI trust.
//! Rustls still verifies the actual TLS handshake signature with that certificate
//! before completing its handshake. The raw public peer proposal remains a claim;
//! this configuration cannot authenticate a GNUnet peer. HOSTLIST HTTPS uses its
//! own hostname/CA policy and does not consume this module.
use gnunet_transport_quic::{h3, raw};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error, ServerConfig, SignatureScheme,
    client::{
        Resumption,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    server::{NoServerSessionStorage, ParsedCertificate},
    sign::{CertifiedKey, SingleCertAndKey},
};
use std::{fmt, sync::Arc};

/// Distinct application ALPN selection; raw QUIC and HTTP3 are separate profiles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    /// Original raw32 initiator identity and GNUnet frames on stream4.
    Raw,
    /// HTTP3 identity/message POST and GET long-poll profile.
    Http3,
}
impl Profile {
    /// Official configuration section and NAT registration section name.
    #[must_use]
    pub const fn section(self) -> &'static [u8] {
        match self {
            Self::Raw => b"communicator-quic",
            Self::Http3 => b"communicator-http3",
        }
    }

    fn protocols(self) -> Vec<Vec<u8>> {
        match self {
            Self::Raw => raw::ALPNS
                .iter()
                .map(|protocol| protocol.to_vec())
                .collect(),
            Self::Http3 => vec![h3::ALPN.to_vec()],
        }
    }
}

struct UntrustedTransportCertificate {
    provider: Arc<CryptoProvider>,
}
impl fmt::Debug for UntrustedTransportCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GNUnetTransportCertificatePolicy")
            .finish_non_exhaustive()
    }
}
impl ServerCertVerifier for UntrustedTransportCertificate {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // Certificate-chain acceptance is the explicit GNUnet transport policy.
        // Parse the leaf here; the separate signature callbacks below verify
        // real possession of its TLS key. No CA, hostname, validity, PILS or
        // GNUnet identity authentication follows from this policy acceptance.
        ParsedCertificate::try_from(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // Required by the Rustls trait; these configurations select TLS1.3 only.
        verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build a TLS1.3 client using the explicit GNUnet untrusted-certificate policy
/// and this caller's actual crypto provider. No process-global provider or trust
/// store is installed. Session resumption and 0RTT are disabled so a fresh source
/// cannot inherit an earlier source's TLS/application admission or early data.
pub fn client(provider: Arc<CryptoProvider>, profile: Profile) -> Result<ClientConfig, Error> {
    let verifier = Arc::new(UntrustedTransportCertificate {
        provider: Arc::clone(&provider),
    });
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = profile.protocols();
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    Ok(config)
}

/// Build a TLS1.3 server from an explicitly owned certificate chain/private key.
/// Rustls checks actual key loading and certificate/key correspondence; failures
/// propagate without a successful configuration. This function does not read a
/// key file, generate credentials, use PILS secrets or emit credential bytes.
/// No client certificate, resumption cache, tickets or 0RTT are requested.
pub fn server(
    provider: Arc<CryptoProvider>,
    certificates: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    profile: Profile,
) -> Result<ServerConfig, Error> {
    server_with(provider, profile, |provider| {
        CertifiedKey::from_der(certificates, key, provider)
    })
}

#[cfg(feature = "fresh-tls")]
pub(super) fn server_with_generated_key(
    provider: Arc<CryptoProvider>,
    certificate: CertificateDer<'static>,
    key: gnunet_tls_crypto_host::certificate::P256Key,
    profile: Profile,
) -> Result<ServerConfig, Error> {
    server_with(provider, profile, |_| {
        let certified = CertifiedKey::new(vec![certificate], key.into_tls_signing_key());
        certified.keys_match()?;
        Ok(certified)
    })
}

fn server_with(
    provider: Arc<CryptoProvider>,
    profile: Profile,
    certify: impl FnOnce(&CryptoProvider) -> Result<CertifiedKey, Error>,
) -> Result<ServerConfig, Error> {
    let builder = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth();
    let certified = certify(builder.crypto_provider())?;
    let mut config = builder.with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
    config.alpn_protocols = profile.protocols();
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    Ok(config)
}
