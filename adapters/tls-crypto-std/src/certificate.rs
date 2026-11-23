//! RustCrypto signing keys for generated local TLS certificates.
use crate::sign::{KEY_PROVIDER, p256_signing_key};
use getrandom::SysRng;
use p256::{
    Sec1Point,
    ecdsa::{Signature, SigningKey, signature::RandomizedSigner},
    elliptic_curve::Generate,
    pkcs8::{EncodePrivateKey, SecretDocument},
};
use rcgen::{Certificate, CertificateParams, KeyIdMethod, PublicKeyData, SerialNumber};
use rustls::{
    SignatureScheme,
    pki_types::{AlgorithmIdentifier, CertificateDer, DnsName, PrivateKeyDer, alg_id},
    sign::{Signer, public_key_to_spki},
};
use sha2::{Digest, Sha256};
use std::{fmt, net::IpAddr, sync::Arc};
use time::OffsetDateTime;
use x509_parser::{extensions::ParsedExtension, parse_x509_certificate};
use yasna::{
    DERWriter, Tag,
    models::{GeneralizedTime, ObjectIdentifier, UTCTime},
};

/// An owned P-256 certificate key generated with the operating-system RNG.
pub struct P256Key {
    signing: SigningKey,
    public: Sec1Point,
}

impl fmt::Debug for P256Key {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.debug_struct("P256Key").finish_non_exhaustive()
    }
}

impl P256Key {
    /// Generate an independent P-256 key.
    pub fn generate() -> Result<Self, rcgen::Error> {
        let signing = SigningKey::try_generate_from_rng(&mut SysRng)
            .map_err(|_| rcgen::Error::RemoteKeyError)?;
        let public = signing.verifying_key().to_sec1_point(false);
        Ok(Self { signing, public })
    }

    /// Transfer the generated key to rustls without serializing the private scalar.
    #[must_use]
    pub fn into_tls_signing_key(self) -> Arc<dyn rustls::sign::SigningKey> {
        p256_signing_key(self.signing, self.public)
    }

    /// Export the original key in a zeroizing PKCS#8 document.
    pub fn pkcs8(&self) -> Result<SecretDocument, rcgen::Error> {
        self.signing
            .to_pkcs8_der()
            .map_err(|_| rcgen::Error::CouldNotParseKeyPair)
    }

    /// Issue a self-signed certificate using the normal rcgen validity and SAN defaults.
    pub fn self_signed(&self, names: Vec<String>) -> Result<Certificate, rcgen::Error> {
        self.self_signed_with(CertificateParams::new(names)?)
    }

    /// Issue a self-signed certificate under the supplied profile with a serial
    /// and subject key identifier derived from this key.
    pub fn self_signed_with(
        &self,
        mut params: CertificateParams,
    ) -> Result<Certificate, rcgen::Error> {
        params.serial_number = Some(SerialNumber::from_slice(&serial(self.public.as_bytes())));
        params.key_identifier_method =
            KeyIdMethod::PreSpecified(key_id(self.subject_public_key_info().as_slice()).to_vec());
        params.self_signed(self)
    }
}

impl PublicKeyData for P256Key {
    fn der_bytes(&self) -> &[u8] {
        self.public.as_bytes()
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for P256Key {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let signature: Signature = self
            .signing
            .try_sign_with_rng(&mut SysRng, message)
            .map_err(|_| rcgen::Error::RemoteKeyError)?;
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

/// An original CA signer and the certificate's exact issuer identity.
pub struct ServerIssuer {
    signing: Box<dyn Signer>,
    signature: AlgorithmIdentifier,
    name: Vec<u8>,
    key_id: Vec<u8>,
}

impl fmt::Debug for ServerIssuer {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("ServerIssuer")
            .field("scheme", &self.signing.scheme())
            .finish_non_exhaustive()
    }
}

/// CA matching and local leaf issuance failures.
#[derive(Debug)]
#[non_exhaustive]
pub enum IssuanceError {
    /// The CA certificate is malformed.
    Certificate,
    /// The CA key could not be decoded or validated.
    Key(rustls::Error),
    /// The exact certificate subject public key does not match the private key.
    KeyMismatch,
    /// No supported certificate signing algorithm applies to the key.
    UnsupportedAlgorithm,
    /// The requested server name or validity range is invalid.
    Leaf,
    /// The original CA signer failed.
    Signature(rustls::Error),
}

impl fmt::Display for IssuanceError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Certificate => output.write_str("invalid CA certificate"),
            Self::Key(error) => write!(output, "invalid CA private key: {error}"),
            Self::KeyMismatch => output.write_str("CA private key does not match the certificate"),
            Self::UnsupportedAlgorithm => output.write_str("unsupported CA signature algorithm"),
            Self::Leaf => output.write_str("invalid server certificate name or validity"),
            Self::Signature(error) => write!(output, "CA signing failed: {error}"),
        }
    }
}

impl std::error::Error for IssuanceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Key(error) | Self::Signature(error) => Some(error),
            _ => None,
        }
    }
}

impl ServerIssuer {
    /// Validate and match a private key to the exact CA certificate public key.
    /// The caller independently authorizes the certificate to issue server leaves.
    pub fn load(
        ca: &CertificateDer<'_>,
        private_key: PrivateKeyDer<'static>,
    ) -> Result<Self, IssuanceError> {
        let key = KEY_PROVIDER
            .load_private_key(private_key)
            .map_err(IssuanceError::Key)?;
        let (remaining, certificate) =
            parse_x509_certificate(ca.as_ref()).map_err(|_| IssuanceError::Certificate)?;
        if !remaining.is_empty() {
            return Err(IssuanceError::Certificate);
        }
        let expected = key.public_key().ok_or(IssuanceError::KeyMismatch)?;
        let ca_public = certificate.public_key().raw;
        if expected.as_ref() != ca_public {
            return Err(IssuanceError::KeyMismatch);
        }
        // rcgen's existing CA importer selected these signature schemes for each key type.
        let (signing, signature) = [
            (SignatureScheme::ECDSA_NISTP256_SHA256, alg_id::ECDSA_SHA256),
            (SignatureScheme::ECDSA_NISTP384_SHA384, alg_id::ECDSA_SHA384),
            (SignatureScheme::ECDSA_NISTP521_SHA512, alg_id::ECDSA_SHA512),
            (SignatureScheme::ED25519, alg_id::ED25519),
            (SignatureScheme::RSA_PKCS1_SHA256, alg_id::RSA_PKCS1_SHA256),
        ]
        .into_iter()
        .find_map(|(scheme, id)| key.choose_scheme(&[scheme]).map(|signer| (signer, id)))
        .ok_or(IssuanceError::UnsupportedAlgorithm)?;
        let key_id = certificate
            .extensions()
            .iter()
            .find_map(|extension| match extension.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(identifier) => Some(identifier.0.to_vec()),
                _ => None,
            })
            .unwrap_or_else(|| key_id(ca_public).to_vec());
        Ok(Self {
            signing,
            signature,
            name: certificate.subject().as_raw().to_vec(),
            key_id,
        })
    }

    /// Issue a server-auth leaf for a single DNS or numeric IP name with the given
    /// UTC validity. The signed certificate keeps the exact issuer Name and key ID.
    pub fn issue(
        &self,
        subject: &str,
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
        key: &P256Key,
    ) -> Result<CertificateDer<'static>, IssuanceError> {
        let name = match subject.parse::<IpAddr>() {
            Ok(address) => Name::Ip(address),
            Err(_) => Name::Dns(DnsName::try_from(subject).map_err(|_| IssuanceError::Leaf)?),
        };
        let not_before = OffsetDateTime::from_unix_timestamp(not_before.unix_timestamp())
            .map_err(|_| IssuanceError::Leaf)?;
        let not_after = OffsetDateTime::from_unix_timestamp(not_after.unix_timestamp())
            .map_err(|_| IssuanceError::Leaf)?;
        if not_before >= not_after || not_before.year() < 0 || not_after.year() > 9999 {
            return Err(IssuanceError::Leaf);
        }
        let public_key = public_key_to_spki(&alg_id::ECDSA_P256, key.public.as_bytes());
        let tbs = yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer
                    .next()
                    .write_tagged(Tag::context(0), |writer| writer.write_u8(2));
                writer
                    .next()
                    .write_bigint_bytes(&serial(key.public.as_bytes()), true);
                algorithm(writer.next(), self.signature);
                writer.next().write_der(&self.name);
                writer.next().write_sequence(|writer| {
                    time(writer.next(), not_before);
                    time(writer.next(), not_after);
                });
                common_name(writer.next(), subject);
                writer.next().write_der(public_key.as_ref());
                extensions(writer.next(), &self.key_id, &name);
            });
        });
        let signature = self.signing.sign(&tbs).map_err(IssuanceError::Signature)?;
        Ok(yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_der(&tbs);
                algorithm(writer.next(), self.signature);
                writer
                    .next()
                    .write_bitvec_bytes(&signature, signature.len() * 8);
            });
        })
        .into())
    }
}

enum Name<'a> {
    Dns(DnsName<'a>),
    Ip(IpAddr),
}

fn key_id(input: &[u8]) -> [u8; 20] {
    let mut bytes = [0; 20];
    bytes.copy_from_slice(&Sha256::digest(input)[..20]);
    bytes
}

fn serial(public_key: &[u8]) -> [u8; 20] {
    let mut bytes = key_id(public_key);
    bytes[0] &= 0x7f;
    if bytes == [0; 20] {
        bytes[19] = 1;
    }
    bytes
}

fn algorithm(writer: DERWriter<'_>, signature: AlgorithmIdentifier) {
    writer.write_sequence(|writer| writer.next().write_der(signature.as_ref()));
}

fn time(writer: DERWriter<'_>, value: OffsetDateTime) {
    if (1950..2050).contains(&value.year()) {
        writer.write_utctime(&UTCTime::from_datetime(value));
    } else {
        writer.write_generalized_time(&GeneralizedTime::from_datetime(value));
    }
}

fn common_name(writer: DERWriter<'_>, name: &str) {
    writer.write_sequence(|writer| {
        writer.next().write_set(|writer| {
            writer.next().write_sequence(|writer| {
                writer
                    .next()
                    .write_oid(&ObjectIdentifier::from_slice(&[2, 5, 4, 3]));
                writer.next().write_utf8_string(name);
            });
        });
    });
}

fn extensions(writer: DERWriter<'_>, authority_key_id: &[u8], name: &Name<'_>) {
    writer.write_tagged(Tag::context(3), |writer| {
        writer.write_sequence(|writer| {
            extension(writer.next(), &[2, 5, 29, 35], false, |writer| {
                writer.write_sequence(|writer| {
                    writer
                        .next()
                        .write_tagged_implicit(Tag::context(0), |writer| {
                            writer.write_bytes(authority_key_id)
                        });
                });
            });
            extension(writer.next(), &[2, 5, 29, 17], false, |writer| {
                writer.write_sequence(|writer| {
                    let writer = writer.next();
                    match name {
                        Name::Dns(name) => writer
                            .write_tagged_implicit(Tag::context(2), |writer| {
                                writer.write_bytes(name.as_ref().as_bytes())
                            }),
                        Name::Ip(IpAddr::V4(address)) => writer
                            .write_tagged_implicit(Tag::context(7), |writer| {
                                writer.write_bytes(&address.octets())
                            }),
                        Name::Ip(IpAddr::V6(address)) => writer
                            .write_tagged_implicit(Tag::context(7), |writer| {
                                writer.write_bytes(&address.octets())
                            }),
                    }
                });
            });
            extension(writer.next(), &[2, 5, 29, 15], true, |writer| {
                writer.write_bitvec_bytes(&[0x80], 1)
            });
            extension(writer.next(), &[2, 5, 29, 37], false, |writer| {
                writer.write_sequence(|writer| {
                    writer
                        .next()
                        .write_oid(&ObjectIdentifier::from_slice(&[1, 3, 6, 1, 5, 5, 7, 3, 1]));
                });
            });
        });
    });
}

fn extension(
    writer: DERWriter<'_>,
    oid: &[u64],
    critical: bool,
    value: impl FnOnce(DERWriter<'_>),
) {
    writer.write_sequence(|writer| {
        writer.next().write_oid(&ObjectIdentifier::from_slice(oid));
        if critical {
            writer.next().write_bool(true);
        }
        writer.next().write_bytes(&yasna::construct_der(value));
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, DnType, IsCa, KeyUsagePurpose};
    use rustls::{
        RootCertStore,
        client::{WebPkiServerVerifier, danger::ServerCertVerifier},
        pki_types::{PrivatePkcs8KeyDer, ServerName, UnixTime},
    };
    use std::{sync::Arc, time::Duration};

    #[test]
    fn issued_server_leaf_verifies_under_the_loaded_ca() -> Result<(), Box<dyn std::error::Error>> {
        let ca_key = P256Key::generate()?;
        let mut ca = CertificateParams::default();
        ca.distinguished_name.push(DnType::CommonName, "Test CA");
        ca.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca = ca_key.self_signed_with(ca)?;
        let private = ca_key.pkcs8()?;
        let issuer = ServerIssuer::load(
            ca.der(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private.as_bytes().to_vec())),
        )?;

        let leaf_key = P256Key::generate()?;
        let domain = "service.example";
        let not_before = OffsetDateTime::from_unix_timestamp(1_700_000_000)?;
        let not_after = OffsetDateTime::from_unix_timestamp(1_700_003_600)?;
        let leaf = issuer.issue(domain, not_before, not_after, &leaf_key)?;

        let mut roots = RootCertStore::empty();
        roots.add(ca.der().clone())?;
        let verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), crate::provider())
                .build()?;
        let now = UnixTime::since_unix_epoch(Duration::from_secs(1_700_000_060));
        verifier.verify_server_cert(&leaf, &[], &ServerName::try_from(domain)?, &[], now)?;
        Ok(())
    }
}
