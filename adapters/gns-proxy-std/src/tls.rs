//! TLS credentials for the local browser connection and authenticated upstream TLS.
//!
//! The caller supplies authenticated GNS TLSA records for the selected TCP service,
//! an explicit CA PEM path, and the *same* cancellation/deadline guard used by the
//! surrounding session. No operating-system trust settings are changed here.
//!
//! Guards bracket synchronous I/O, parsing, key generation, signing and verification.
//! They detect expiry after an operation; they cannot preempt synchronous provider
//! code or filesystem I/O. The host must also guard and deadline-bound its native
//! accept/connect futures. An UpstreamTls is intended for one handshake only.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::digest;
use rcgen::{CertificateParams, DistinguishedName, DnType, Issuer, KeyPair, PublicKeyData};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, TrustAnchor, UnixTime,
};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, ServerConfig};
use rustls::{Error as RustlsError, SignatureScheme};
use time::OffsetDateTime;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::{FromDer, X509Certificate};
use zeroize::Zeroizing;

const MAX_CA_PEM_BYTES: usize = 1024 * 1024;
const MAX_CACHE_ENTRIES: usize = 4096;
const MAX_LEAF_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_NAME_BYTES: usize = 253;
const MAX_TLSA_RECORDS: usize = 32;
const MAX_ASSOCIATION_BYTES: usize = 128 * 1024;
const MAX_TLSA_BYTES: usize = 256 * 1024;
const MAX_CERT_BYTES: usize = 128 * 1024;
const MAX_CHAIN_CERTS: usize = 16;
const MAX_CHAIN_BYTES: usize = 512 * 1024;
const MAX_OCSP_BYTES: usize = 64 * 1024;
const MAX_SIGNATURE_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_SIGNATURE_BYTES: usize = 16 * 1024;
const MAX_PUBLIC_ROOT_PEM_BYTES: usize = 8 * 1024 * 1024;
const MAX_PUBLIC_ROOT_CERTIFICATES: usize = 512;
const MAX_MOZILLA_ROOTS: usize = 1024;

/// Capture the original session deadline, stop flag and runtime clock in this
/// closure. Do not create a new relative deadline when making a TLS configuration.
pub type Guard = Arc<dyn Fn() -> Result<(), TlsError> + Send + Sync>;

/// No error contains PEM contents, keys, certificate bytes or filesystem paths.
#[derive(Clone, Debug)]
pub enum TlsError {
    /// The original session stop flag requested cancellation.
    Cancelled,
    /// The original session deadline has elapsed.
    Deadline,
    /// A required clock read or checked time conversion failed.
    Clock,
    /// A supplied name, PEM profile or association has invalid syntax.
    InvalidInput(
        /// Bounded diagnostic describing the invalid input.
        &'static str,
    ),
    /// A configured or hard resource bound was exceeded.
    Limit(
        /// Bounded diagnostic identifying the exceeded resource.
        &'static str,
    ),
    /// Reading an explicit credential or public-root file failed.
    Io(
        /// Original I/O cause, also available through Error::source.
        Arc<std::io::Error>,
    ),
    /// Certificate encoding or required certificate constraints were invalid.
    Certificate(
        /// Bounded diagnostic describing the failed certificate check.
        &'static str,
    ),
    /// The standard signing or verification provider rejected an operation.
    Crypto(
        /// Bounded diagnostic identifying the provider operation.
        &'static str,
    ),
    /// A TLS or credential configuration could not be constructed.
    Configuration(
        /// Bounded diagnostic identifying the configuration problem.
        &'static str,
    ),
    /// A required credential or authenticated GNS-data time window is closed.
    Expired,
    /// Credential or handshake state could not be locked without blocking.
    Busy,
    /// The chosen service, browser SNI or handshake certificate did not agree.
    Binding,
    /// Ordinary PKIX certificate and hostname authentication failed.
    Pkix,
    /// At least one TLSA association was usable, but none authenticated the peer.
    Dane,
    /// An internal association operation received unsupported TLSA parameters.
    UnsupportedTlsa {
        /// Unsupported certificate-usage value.
        usage: u8,
        /// Unsupported certificate-selector value.
        selector: u8,
        /// Unsupported association matching-type value.
        matching: u8,
    },
    /// A completed handshake with a provider-verified peer signature is unavailable.
    IncompleteHandshake,
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str("TLS session cancelled"),
            Self::Deadline => f.write_str("TLS session deadline reached"),
            Self::Clock => f.write_str("TLS clock unavailable or out of range"),
            Self::InvalidInput(reason) => write!(f, "invalid TLS input: {reason}"),
            Self::Limit(reason) => write!(f, "TLS input limit: {reason}"),
            Self::Io(error) => write!(f, "TLS credential I/O failed: {:?}", error.kind()),
            Self::Certificate(reason) => write!(f, "invalid certificate: {reason}"),
            Self::Crypto(reason) => write!(f, "TLS provider failed: {reason}"),
            Self::Configuration(reason) => write!(f, "invalid TLS configuration: {reason}"),
            Self::Expired => f.write_str("TLS credential or authenticated GNS data expired"),
            Self::Busy => f.write_str("TLS credential state is busy"),
            Self::Binding => f.write_str("TLS service or handshake binding mismatch"),
            Self::Pkix => f.write_str("upstream PKIX authentication failed"),
            Self::Dane => f.write_str("authenticated TLSA records did not authenticate upstream"),
            Self::UnsupportedTlsa {
                usage,
                selector,
                matching,
            } => {
                write!(f, "unsupported TLSA profile {usage}/{selector}/{matching}")
            }
            Self::IncompleteHandshake => f.write_str("TLS handshake authentication is incomplete"),
        }
    }
}

impl std::error::Error for TlsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

fn guarded<T>(
    guard: &Guard,
    operation: impl FnOnce() -> Result<T, TlsError>,
) -> Result<T, TlsError> {
    guard()?;
    let result = operation();
    guard()?;
    result
}

fn rustls_error(error: TlsError) -> RustlsError {
    RustlsError::General(error.to_string())
}

fn wall_now(guard: &Guard) -> Result<SystemTime, TlsError> {
    guarded(guard, || Ok(SystemTime::now()))
}

fn from_seconds(seconds: i64) -> Result<SystemTime, TlsError> {
    if seconds >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(seconds as u64))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(seconds.unsigned_abs()))
    }
    .ok_or(TlsError::Clock)
}

fn to_seconds(time: SystemTime) -> Result<i64, TlsError> {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TlsError::Clock)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| TlsError::Clock)
}

fn unix_time(time: SystemTime) -> Result<UnixTime, TlsError> {
    Ok(UnixTime::since_unix_epoch(
        time.duration_since(UNIX_EPOCH)
            .map_err(|_| TlsError::Clock)?,
    ))
}

fn host_name(name: &str, guard: &Guard) -> Result<ServerName<'static>, TlsError> {
    if name.is_empty() || name.len() > MAX_NAME_BYTES || !name.is_ascii() {
        return Err(TlsError::InvalidInput(
            "host must be an ASCII A-label name or IP literal",
        ));
    }
    // SOCKS IPv6 addresses are supplied without URL square brackets.
    if name.parse::<IpAddr>().is_err() {
        let dns = name.strip_suffix('.').unwrap_or(name);
        if dns.is_empty()
            || dns.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return Err(TlsError::InvalidInput("invalid DNS A-label host"));
        }
    }
    guarded(guard, || {
        ServerName::try_from(name.to_owned())
            .map_err(|_| TlsError::InvalidInput("invalid TLS server name"))
    })
}

fn parse_certificate<'a>(der: &'a [u8]) -> Result<X509Certificate<'a>, TlsError> {
    let (rest, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|_| TlsError::Certificate("DER decoding"))?;
    if !rest.is_empty() {
        return Err(TlsError::Certificate("trailing DER data"));
    }
    cert.extensions_map()
        .map_err(|_| TlsError::Certificate("duplicate extensions"))?;
    Ok(cert)
}

#[derive(Clone, Copy)]
struct Validity {
    not_before: SystemTime,
    not_after: SystemTime,
}

struct CaValidity {
    validity: Validity,
    path_len_constraint: Option<u32>,
}

fn validity(der: &[u8], guard: &Guard) -> Result<Validity, TlsError> {
    guarded(guard, || {
        let cert = parse_certificate(der)?;
        Ok(Validity {
            not_before: from_seconds(cert.validity().not_before.timestamp())?,
            not_after: from_seconds(cert.validity().not_after.timestamp())?,
        })
    })
}

/// Validate authority semantics ourselves: rcgen's Issuer constructor deliberately
/// assumes them, and webpki trust-anchor extraction deliberately does not check them.
fn ca_validity(der: &[u8], now: SystemTime, guard: &Guard) -> Result<CaValidity, TlsError> {
    guarded(guard, || {
        let cert = parse_certificate(der)?;
        let bc = cert
            .basic_constraints()
            .map_err(|_| TlsError::Certificate("CA constraints"))?
            .ok_or(TlsError::Certificate("CA BasicConstraints missing"))?;
        if !bc.critical || !bc.value.ca {
            return Err(TlsError::Certificate("certificate is not an explicit CA"));
        }
        let ku = cert
            .key_usage()
            .map_err(|_| TlsError::Certificate("CA KeyUsage"))?
            .ok_or(TlsError::Certificate("CA KeyUsage missing"))?;
        if !ku.value.key_cert_sign() {
            return Err(TlsError::Certificate("CA cannot sign certificates"));
        }
        if let Some(eku) = cert
            .extended_key_usage()
            .map_err(|_| TlsError::Certificate("CA extended key usage"))?
            && !eku.value.any
            && !eku.value.server_auth
        {
            return Err(TlsError::Certificate("CA excludes server authentication"));
        }
        for extension in cert.extensions() {
            if matches!(
                extension.parsed_extension(),
                ParsedExtension::ParseError { .. }
            ) {
                return Err(TlsError::Certificate("malformed CA extension"));
            }
            if extension.critical
                && !matches!(
                    extension.parsed_extension(),
                    ParsedExtension::BasicConstraints(_)
                        | ParsedExtension::KeyUsage(_)
                        | ParsedExtension::ExtendedKeyUsage(_)
                        | ParsedExtension::NameConstraints(_)
                )
            {
                return Err(TlsError::Certificate("unsupported critical CA extension"));
            }
        }
        let result = Validity {
            not_before: from_seconds(cert.validity().not_before.timestamp())?,
            not_after: from_seconds(cert.validity().not_after.timestamp())?,
        };
        if result.not_before > now || result.not_after <= now {
            return Err(TlsError::Expired);
        }
        Ok(CaValidity {
            validity: result,
            path_len_constraint: bc.value.path_len_constraint,
        })
    })
}

struct CachedLeaf {
    domain: String,
    expires_at: SystemTime,
    key: Arc<CertifiedKey>,
}

/// An explicitly configured signing authority. The combined PEM file must contain
/// exactly one CA certificate and exactly one unencrypted PKCS#8, SEC1 or PKCS#1 key.
/// The file is read only by load(), never from a default path or a trust-store API.
pub struct Authority {
    issuer: Mutex<Issuer<'static, KeyPair>>,
    ca: CertificateDer<'static>,
    ca_validity: Validity,
    provider: Arc<CryptoProvider>,
    cache: Mutex<VecDeque<CachedLeaf>>,
    cache_capacity: usize,
    max_leaf_ttl: Duration,
}

impl fmt::Debug for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authority")
            .field("cache_capacity", &self.cache_capacity)
            .finish_non_exhaustive()
    }
}

impl Authority {
    /// Load and validate the single signing CA and matching private key from the
    /// explicit combined PEM file, with a bounded leaf cache and maximum lifetime.
    /// The guard brackets every synchronous credential-loading capability.
    pub fn load(
        ca_pem: &Path,
        cache_capacity: usize,
        max_leaf_ttl: Duration,
        guard: &Guard,
    ) -> Result<Arc<Self>, TlsError> {
        guard()?;
        if ca_pem.as_os_str().as_encoded_bytes().len() > 4096 {
            return Err(TlsError::Limit("CA PEM path"));
        }
        if cache_capacity == 0
            || cache_capacity > MAX_CACHE_ENTRIES
            || max_leaf_ttl.is_zero()
            || max_leaf_ttl > MAX_LEAF_TTL
        {
            return Err(TlsError::Configuration(
                "invalid CA cache capacity or leaf lifetime",
            ));
        }
        let mut file = guarded(guard, || {
            File::open(ca_pem).map_err(|e| TlsError::Io(Arc::new(e)))
        })?;
        let metadata = guarded(guard, || {
            file.metadata().map_err(|e| TlsError::Io(Arc::new(e)))
        })?;
        if !metadata.is_file() || metadata.len() > MAX_CA_PEM_BYTES as u64 {
            return Err(TlsError::Limit("CA PEM must be a bounded regular file"));
        }
        let mut pem = Zeroizing::new(Vec::new());
        let mut chunk = Zeroizing::new([0_u8; 8192]);
        loop {
            let count = guarded(guard, || {
                file.read(&mut chunk[..])
                    .map_err(|e| TlsError::Io(Arc::new(e)))
            })?;
            if count == 0 {
                break;
            }
            if pem
                .len()
                .checked_add(count)
                .ok_or(TlsError::Limit("CA PEM"))?
                > MAX_CA_PEM_BYTES
            {
                return Err(TlsError::Limit("CA PEM"));
            }
            pem.extend_from_slice(&chunk[..count]);
        }
        let (ca, key) = guarded(guard, || {
            let mut certs = CertificateDer::pem_slice_iter(&pem);
            let ca = certs
                .next()
                .ok_or(TlsError::Certificate("CA PEM certificate missing"))?
                .map_err(|_| TlsError::Certificate("CA PEM certificate encoding"))?;
            if certs.next().is_some() || ca.len() > MAX_CERT_BYTES {
                return Err(TlsError::Limit(
                    "exactly one bounded CA certificate required",
                ));
            }
            let mut keys = PrivateKeyDer::pem_slice_iter(&pem);
            let key = keys
                .next()
                .ok_or(TlsError::Crypto("CA PEM private key missing"))?
                .map_err(|_| TlsError::Crypto("CA PEM private key encoding"))?;
            if keys.next().is_some() {
                return Err(TlsError::Configuration(
                    "exactly one CA private key required",
                ));
            }
            Ok((ca, Zeroizing::new(key)))
        })?;
        let now = wall_now(guard)?;
        let ca_validity = ca_validity(ca.as_ref(), now, guard)?.validity;
        let provider = guarded(guard, || {
            Ok(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        })?;
        let ca_signing_key = guarded(guard, || {
            rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
                .map_err(|_| TlsError::Crypto("CA private key decoding"))
        })?;
        let certified = CertifiedKey::new(vec![ca.clone()], ca_signing_key);
        guarded(guard, || {
            certified
                .keys_match()
                .map_err(|_| TlsError::Crypto("CA key match is not proven"))
        })?;
        let key_pair = guarded(guard, || {
            KeyPair::try_from(&*key).map_err(|_| TlsError::Crypto("CA signing key unsupported"))
        })?;
        guarded(guard, || {
            let cert = parse_certificate(ca.as_ref())?;
            if key_pair.subject_public_key_info() != cert.public_key().raw {
                return Err(TlsError::Crypto("CA public key mismatch"));
            }
            Ok(())
        })?;
        let issuer = guarded(guard, || {
            Issuer::from_ca_cert_der(&ca, key_pair)
                .map_err(|_| TlsError::Certificate("CA issuer import"))
        })?;
        if wall_now(guard)? >= ca_validity.not_after {
            return Err(TlsError::Expired);
        }
        guard()?;
        Ok(Arc::new(Self {
            issuer: Mutex::new(issuer),
            ca,
            ca_validity,
            provider,
            cache: Mutex::new(VecDeque::new()),
            cache_capacity,
            max_leaf_ttl,
        }))
    }

    /// expires_at is the authenticated GNS-data expiry (or the caller's explicit
    /// bounded policy for an ordinary numeric/DNS destination), never a fresh TTL.
    /// DNS names and numeric IPv4/IPv6 names receive the matching SAN type.
    /// DNS connections require matching original-domain SNI; IP connections omit SNI.
    pub fn server_config(
        &self,
        browser_domain: &str,
        expires_at: SystemTime,
        guard: &Guard,
    ) -> Result<Arc<ServerConfig>, TlsError> {
        let name = host_name(browser_domain, guard)?;
        let now = wall_now(guard)?;
        if now < self.ca_validity.not_before || now >= self.ca_validity.not_after {
            return Err(TlsError::Expired);
        }
        let max_expiry = now.checked_add(self.max_leaf_ttl).ok_or(TlsError::Clock)?;
        let expiry = expires_at.min(max_expiry).min(self.ca_validity.not_after);
        // DER certificate dates have second precision: round down, never beyond GNS expiry.
        let expiry = from_seconds(to_seconds(expiry)?)?;
        if expiry <= now {
            return Err(TlsError::Expired);
        }
        let cached = guarded(guard, || {
            let mut cache = self.cache.try_lock().map_err(|_| TlsError::Busy)?;
            cache.retain(|entry| entry.expires_at > now);
            Ok(cache
                .iter()
                .find(|entry| entry.domain == browser_domain && entry.expires_at <= expiry)
                .map(|entry| (entry.key.clone(), entry.expires_at)))
        })?;
        let (key, expiry) = match cached {
            Some(cached) => cached,
            None => {
                let mut params = guarded(guard, || {
                    CertificateParams::new(vec![browser_domain.to_owned()])
                        .map_err(|_| TlsError::InvalidInput("certificate SAN"))
                })?;
                params.distinguished_name = DistinguishedName::new();
                params
                    .distinguished_name
                    .push(DnType::CommonName, browser_domain);
                let not_before = now
                    .checked_sub(Duration::from_secs(60))
                    .unwrap_or(UNIX_EPOCH)
                    .max(self.ca_validity.not_before);
                params.not_before = OffsetDateTime::from_unix_timestamp(to_seconds(not_before)?)
                    .map_err(|_| TlsError::Clock)?;
                params.not_after = OffsetDateTime::from_unix_timestamp(to_seconds(expiry)?)
                    .map_err(|_| TlsError::Clock)?;
                params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
                params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
                params.use_authority_key_identifier_extension = true;
                let leaf_key = guarded(guard, || {
                    KeyPair::generate().map_err(|_| TlsError::Crypto("leaf key generation"))
                })?;
                let leaf = guarded(guard, || {
                    let issuer = self.issuer.try_lock().map_err(|_| TlsError::Busy)?;
                    params
                        .signed_by(&leaf_key, &*issuer)
                        .map_err(|_| TlsError::Crypto("leaf signing"))
                })?;
                if leaf.der().len() > MAX_CERT_BYTES {
                    return Err(TlsError::Limit("generated leaf"));
                }
                // This also enforces any name constraints in the configured CA.
                guarded(guard, || {
                    let anchor = webpki::anchor_from_trusted_cert(&self.ca)
                        .map_err(|_| TlsError::Certificate("CA trust anchor"))?;
                    let anchors = [anchor];
                    let cert = webpki::EndEntityCert::try_from(leaf.der())
                        .map_err(|_| TlsError::Certificate("generated leaf encoding"))?;
                    cert.verify_for_usage(
                        self.provider.signature_verification_algorithms.all,
                        &anchors,
                        &[],
                        unix_time(now)?,
                        webpki::KeyUsage::server_auth(),
                        None,
                        None,
                    )
                    .map_err(|_| TlsError::Certificate("generated leaf violates CA constraints"))?;
                    guard()?;
                    cert.verify_is_valid_for_subject_name(&name)
                        .map_err(|_| TlsError::Certificate("generated leaf hostname"))?;
                    Ok(())
                })?;
                let der_key = guarded(guard, || {
                    Ok(Zeroizing::new(PrivateKeyDer::Pkcs8(
                        PrivatePkcs8KeyDer::from(leaf_key.serialize_der()),
                    )))
                })?;
                let signing_key = guarded(guard, || {
                    rustls::crypto::aws_lc_rs::sign::any_supported_type(&der_key)
                        .map_err(|_| TlsError::Crypto("leaf key import"))
                })?;
                let certified =
                    CertifiedKey::new(vec![leaf.der().clone(), self.ca.clone()], signing_key);
                guarded(guard, || {
                    certified
                        .keys_match()
                        .map_err(|_| TlsError::Crypto("leaf key match is not proven"))
                })?;
                let key = Arc::new(certified);
                guarded(guard, || {
                    let mut cache = self.cache.try_lock().map_err(|_| TlsError::Busy)?;
                    cache.retain(|entry| entry.expires_at > now && entry.domain != browser_domain);
                    while cache.len() >= self.cache_capacity {
                        cache.pop_front();
                    }
                    cache.push_back(CachedLeaf {
                        domain: browser_domain.to_owned(),
                        expires_at: expiry,
                        key: key.clone(),
                    });
                    Ok(())
                })?;
                (key, expiry)
            }
        };
        let config = guarded(guard, || {
            let resolver = LocalCertificate {
                key,
                expires_at: expiry,
                guard: guard.clone(),
                dns_name: match name {
                    ServerName::DnsName(_) => Some(browser_domain.to_owned()),
                    _ => None,
                },
            };
            let mut config = ServerConfig::builder_with_provider(self.provider.clone())
                .with_safe_default_protocol_versions()
                .map_err(|_| TlsError::Configuration("TLS protocol versions"))?
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(resolver));
            config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
            config.send_tls13_tickets = 0;
            config.max_early_data_size = 0;
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            Ok(Arc::new(config))
        })?;
        if wall_now(guard)? >= expiry {
            return Err(TlsError::Expired);
        }
        guard()?;
        Ok(config)
    }
}

struct LocalCertificate {
    key: Arc<CertifiedKey>,
    expires_at: SystemTime,
    dns_name: Option<String>,
    guard: Guard,
}

impl fmt::Debug for LocalCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalCertificate")
    }
}

impl ResolvesServerCert for LocalCertificate {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        guarded(&self.guard, || {
            if SystemTime::now() >= self.expires_at {
                return Err(TlsError::Expired);
            }
            match (hello.server_name(), &self.dns_name) {
                (Some(actual), Some(expected))
                    if actual
                        .trim_end_matches('.')
                        .eq_ignore_ascii_case(expected.trim_end_matches('.')) => {}
                (None, None) => {}
                _ => return Err(TlsError::Binding),
            }
            Ok(self.key.clone())
        })
        .ok()
    }
}

/// Public root-file limits. Configured values must also fit the hard caps of
/// 8 MiB PEM, 512 certificates and 128 KiB for each decoded DER certificate.
#[derive(Clone, Copy, Debug)]
pub struct TrustRootLimits {
    /// Maximum input PEM bytes, bounded above by the module's 8 MiB hard limit.
    pub max_pem_bytes: usize,
    /// Maximum explicit root certificates, bounded above by the hard limit of 512.
    pub max_certificates: usize,
}

impl Default for TrustRootLimits {
    fn default() -> Self {
        Self {
            max_pem_bytes: 4 * 1024 * 1024,
            max_certificates: 256,
        }
    }
}

struct FullDerRoot {
    certificate: CertificateDer<'static>,
    anchor: TrustAnchor<'static>,
}

/// Shared PKIX roots. Mozilla provides complete default PKIX trust anchors; its
/// compact data does not retain the full certificate DER. Configuring a public
/// root PEM adds actual PKIX roots and retains their full DER for TLSA usage 0.
/// Thus a certificate-hash association for an omitted root requires that root's
/// full DER in the configured public PEM. This never changes OS trust settings.
pub struct TrustRoots {
    store: Arc<RootCertStore>,
    full_der: Vec<FullDerRoot>,
}

impl fmt::Debug for TrustRoots {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustRoots")
            .field("anchors", &self.store.len())
            .field("full_der_certificates", &self.full_der.len())
            .finish()
    }
}

impl TrustRoots {
    /// Use the bundled Mozilla PKIX trust anchors without loading any root file.
    /// Full root-certificate DER is unavailable in this compact default store.
    pub fn mozilla(guard: &Guard) -> Result<Arc<Self>, TlsError> {
        guarded(guard, || {
            if webpki_roots::TLS_SERVER_ROOTS.len() > MAX_MOZILLA_ROOTS {
                return Err(TlsError::Limit("Mozilla PKIX root count"));
            }
            Ok(Arc::new(Self {
                store: Arc::new(RootCertStore {
                    roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
                }),
                full_der: Vec::new(),
            }))
        })
    }

    /// Load once under the host's startup guard, then share the returned Arc.
    /// The explicit file must consist solely of CERTIFICATE PEM sections and
    /// ASCII whitespace. Private keys, unknown sections, preambles, nested or
    /// unmatched sections and duplicate DER certificates are rejected. Supplied
    /// roots must be currently valid CAs permitted to sign TLS server chains;
    /// no private-key parser or signing operation is used by this method.
    pub fn from_pem(
        public_roots_pem: &Path,
        limits: TrustRootLimits,
        guard: &Guard,
    ) -> Result<Arc<Self>, TlsError> {
        guard()?;
        if public_roots_pem.as_os_str().as_encoded_bytes().len() > 4096 {
            return Err(TlsError::Limit("public root PEM path"));
        }
        if limits.max_pem_bytes == 0
            || limits.max_pem_bytes > MAX_PUBLIC_ROOT_PEM_BYTES
            || limits.max_certificates == 0
            || limits.max_certificates > MAX_PUBLIC_ROOT_CERTIFICATES
        {
            return Err(TlsError::Configuration("invalid public root PEM limits"));
        }
        let mut file = guarded(guard, || {
            File::open(public_roots_pem).map_err(|error| TlsError::Io(Arc::new(error)))
        })?;
        let metadata = guarded(guard, || {
            file.metadata()
                .map_err(|error| TlsError::Io(Arc::new(error)))
        })?;
        if !metadata.is_file() || metadata.len() > limits.max_pem_bytes as u64 {
            return Err(TlsError::Limit(
                "public root PEM must be a bounded regular file",
            ));
        }
        // Also erase the input if a misconfigured file unexpectedly contains a key.
        let mut pem = Zeroizing::new(Vec::new());
        let mut chunk = Zeroizing::new([0_u8; 8192]);
        loop {
            let count = guarded(guard, || {
                file.read(&mut chunk[..])
                    .map_err(|error| TlsError::Io(Arc::new(error)))
            })?;
            if count == 0 {
                break;
            }
            if pem
                .len()
                .checked_add(count)
                .ok_or(TlsError::Limit("public root PEM bytes"))?
                > limits.max_pem_bytes
            {
                return Err(TlsError::Limit("public root PEM bytes"));
            }
            pem.extend_from_slice(&chunk[..count]);
        }
        // PemObject's standard decoder intentionally ignores unrelated section
        // labels. First constrain framing so keys/unknown blocks cannot be ignored.
        let expected_count = guarded(guard, || {
            certificate_only_pem(&pem, limits.max_certificates)
        })?;
        let mozilla = Self::mozilla(guard)?;
        let mut store = (*mozilla.store).clone();
        let mut full_der: Vec<FullDerRoot> = Vec::new();
        let now = wall_now(guard)?;
        let mut sections = CertificateDer::pem_slice_iter(&pem);
        while let Some(section) = guarded(guard, || Ok(sections.next()))? {
            let certificate =
                section.map_err(|_| TlsError::Certificate("public root PEM encoding"))?;
            if certificate.is_empty() || certificate.len() > MAX_CERT_BYTES {
                return Err(TlsError::Limit("public root DER bytes"));
            }
            if full_der.len() >= limits.max_certificates {
                return Err(TlsError::Limit("public root certificate count"));
            }
            if full_der
                .iter()
                .any(|root| root.certificate.as_ref() == certificate.as_ref())
            {
                return Err(TlsError::InvalidInput("duplicate public root certificate"));
            }
            ca_validity(certificate.as_ref(), now, guard)?;
            let anchor = guarded(guard, || {
                webpki::anchor_from_trusted_cert(&certificate)
                    .map(|anchor| anchor.to_owned())
                    .map_err(|_| TlsError::Certificate("public root anchor"))
            })?;
            // RootCertStore::add performs real webpki trust-anchor extraction.
            // This same store is passed to the ordinary PKIX server verifier.
            guarded(guard, || {
                store
                    .add(certificate.clone())
                    .map_err(|_| TlsError::Certificate("public PKIX root import"))
            })?;
            full_der.push(FullDerRoot {
                certificate,
                anchor,
            });
        }
        if full_der.len() != expected_count {
            return Err(TlsError::Certificate(
                "public root PEM section count mismatch",
            ));
        }
        guard()?;
        Ok(Arc::new(Self {
            store: Arc::new(store),
            full_der,
        }))
    }
}

/// Strict framing only; base64/DER decoding is performed by rustls' PemObject.
fn certificate_only_pem(pem: &[u8], max_certificates: usize) -> Result<usize, TlsError> {
    if !pem.is_ascii() {
        return Err(TlsError::InvalidInput("public root PEM must be ASCII"));
    }
    let text =
        std::str::from_utf8(pem).map_err(|_| TlsError::InvalidInput("public root PEM encoding"))?;
    let mut inside = false;
    let mut certificates = 0_usize;
    for line in text.lines() {
        let line = line.trim_matches(|character: char| character.is_ascii_whitespace());
        if !inside {
            if line.is_empty() {
                continue;
            }
            if line != "-----BEGIN CERTIFICATE-----" {
                return Err(TlsError::InvalidInput(
                    "only public CERTIFICATE PEM sections are accepted",
                ));
            }
            inside = true;
        } else if line == "-----END CERTIFICATE-----" {
            inside = false;
            certificates = certificates
                .checked_add(1)
                .ok_or(TlsError::Limit("public root certificate count"))?;
            if certificates > max_certificates {
                return Err(TlsError::Limit("public root certificate count"));
            }
        } else if !line
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        {
            return Err(TlsError::InvalidInput(
                "invalid or ambiguous public root PEM section",
            ));
        }
    }
    if inside || certificates == 0 {
        return Err(TlsError::InvalidInput(
            "missing or unterminated public root certificate",
        ));
    }
    Ok(certificates)
}

/// Raw TLSA fields from an authenticated GNS answer, after exact TCP/port BOX selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsaRecord {
    /// RFC 6698 certificate usage: PKIX-TA, PKIX-EE, DANE-TA or DANE-EE (0..=3).
    pub usage: u8,
    /// Select the entire certificate (0) or its SubjectPublicKeyInfo (1).
    pub selector: u8,
    /// Compare exact bytes (0), SHA-256 (1) or SHA-512 (2).
    pub matching: u8,
    /// Original authenticated association bytes; all bytes count toward input limits.
    pub association: Vec<u8>,
}

/// Construction is a trusted host boundary: DNS resolver results are not sufficient.
/// hostname and port must be the same selected upstream hostname/SNI and TCP port.
/// The caller retains the original authenticated answer and exact BOX provenance.
#[derive(Clone, Debug)]
pub struct AuthenticatedTlsa {
    /// Exact selected upstream hostname used by the TLS factory and SNI policy.
    pub hostname: String,
    /// Exact TCP port selected from the authenticated service records.
    pub port: u16,
    /// Original authenticated GNS-data expiry, converted with checked arithmetic.
    pub expires_at: SystemTime,
    /// Original TLSA records in their authenticated answer order.
    pub records: Vec<TlsaRecord>,
}

/// Why RFC 6698 association processing ignored an individual authenticated record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsaUnusableReason {
    /// The usage, selector or matching-type value is not supported.
    UnsupportedParameters,
    /// Comparison data is empty, has the wrong digest length or invalid exact DER.
    MalformedAssociation,
}

/// Original RRset indices and parameters are retained even when RFC 6698
/// requires a record to be ignored during certificate association processing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkippedTlsaRecord {
    /// Zero-based position in the original authenticated TLSA record vector.
    pub record_index: usize,
    /// Original certificate-usage value.
    pub usage: u8,
    /// Original selector value.
    pub selector: u8,
    /// Original matching-type value.
    pub matching: u8,
    /// Reason this record was excluded from the usable associations.
    pub reason: TlsaUnusableReason,
}

fn tlsa_unusable_reason(
    record: &TlsaRecord,
    guard: &Guard,
) -> Result<Option<TlsaUnusableReason>, TlsError> {
    guard()?;
    if record.usage > 3 || record.selector > 1 || record.matching > 2 {
        return Ok(Some(TlsaUnusableReason::UnsupportedParameters));
    }
    let length = record.association.len();
    if length == 0
        || (record.matching == 1 && length != 32)
        || (record.matching == 2 && length != 64)
    {
        return Ok(Some(TlsaUnusableReason::MalformedAssociation));
    }
    if record.matching == 0 {
        let well_formed = guarded(guard, || {
            Ok(match record.selector {
                0 => parse_certificate(&record.association).is_ok(),
                1 => x509_parser::x509::SubjectPublicKeyInfo::from_der(&record.association)
                    .is_ok_and(|(rest, _)| rest.is_empty()),
                _ => false,
            })
        })?;
        if !well_formed {
            return Ok(Some(TlsaUnusableReason::MalformedAssociation));
        }
    }
    guard()?;
    Ok(None)
}

/// Certificate policy that authenticated the peer before handshake proof reporting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthenticationMethod {
    /// Ordinary PKIX, including the case where every authenticated TLSA is unusable.
    Pkix,
    /// A valid PKIX chain and hostname also matched a usage 0 or usage 1 record.
    PkixTlsa {
        /// Zero-based position of the matching original authenticated TLSA record.
        record_index: usize,
        /// Accepted PKIX-TA (0) or PKIX-EE (1) usage.
        usage: u8,
        /// Accepted certificate or SubjectPublicKeyInfo selector.
        selector: u8,
        /// Accepted exact-byte, SHA-256 or SHA-512 comparison type.
        matching: u8,
    },
    /// A verified server chain and hostname reached the authenticated usage 2 CA.
    DaneTrustAnchor {
        /// Zero-based position of the matching original authenticated TLSA record.
        record_index: usize,
        /// Accepted certificate or SubjectPublicKeyInfo selector.
        selector: u8,
        /// Accepted exact-byte, SHA-256 or SHA-512 comparison type.
        matching: u8,
    },
    /// A usage 3 association matched the peer whose handshake signature was checked.
    DaneEndEntity {
        /// Zero-based position of the matching original authenticated TLSA record.
        record_index: usize,
        /// Accepted certificate or SubjectPublicKeyInfo selector.
        selector: u8,
        /// Accepted exact-byte, SHA-256 or SHA-512 comparison type.
        matching: u8,
    },
}

/// Available only after certificate policy, provider signature verification and
/// the caller's completed rustls handshake agree on the same peer certificate.
#[derive(Clone, Debug)]
pub struct Authentication {
    /// Selected upstream hostname whose connection was authenticated.
    pub hostname: String,
    /// Selected upstream TCP port bound to the authenticated records.
    pub port: u16,
    /// Actual successful certificate-authentication policy.
    pub method: AuthenticationMethod,
    /// Original authenticated TLSA-set expiry, including when every record was skipped.
    pub tlsa_expires_at: Option<SystemTime>,
    /// Ignored TLSA records with their original indices, parameters and reasons.
    pub skipped_tlsa_records: Vec<SkippedTlsaRecord>,
    /// Peer certificate notAfter value; usage 3 does not require PKIX time validity.
    pub certificate_not_after: SystemTime,
    /// Leaf/data expiry ceiling; DANE-EE uses TLSA expiry without PKIX time rules.
    pub authenticated_until: SystemTime,
}

struct Proof {
    leaf: Vec<u8>,
    authentication: Authentication,
    signature_verified: bool,
}

/// Build once per native upstream handshake and discard afterward. Do not pool or
/// reuse config across sessions: its verifier holds the original session guard.
pub struct UpstreamTls {
    /// Configuration for this single upstream handshake and its original session guard.
    pub config: Arc<ClientConfig>,
    /// Server name to pass to the native rustls connector for this configuration.
    pub server_name: ServerName<'static>,
    proof: Arc<Mutex<Option<Proof>>>,
    guard: Guard,
}

impl UpstreamTls {
    /// The host calls this immediately after TlsConnector::connect succeeds, using
    /// stream.get_ref().1, and before forwarding application data to the browser.
    pub fn authentication(
        &self,
        connection: &ClientConnection,
    ) -> Result<Authentication, TlsError> {
        guarded(&self.guard, || {
            if connection.is_handshaking() {
                return Err(TlsError::IncompleteHandshake);
            }
            let proof = self.proof.try_lock().map_err(|_| TlsError::Busy)?;
            let proof = proof.as_ref().ok_or(TlsError::IncompleteHandshake)?;
            if !proof.signature_verified {
                return Err(TlsError::IncompleteHandshake);
            }
            let leaf = connection
                .peer_certificates()
                .and_then(|chain| chain.first())
                .ok_or(TlsError::IncompleteHandshake)?;
            if leaf.as_ref() != proof.leaf.as_slice() {
                return Err(TlsError::Binding);
            }
            if SystemTime::now() >= proof.authentication.authenticated_until {
                return Err(TlsError::Expired);
            }
            Ok(proof.authentication.clone())
        })
    }
}

/// Construct one upstream handshake policy for the exact hostname and TCP port.
/// Authenticated TLSA records retain their original indices and expiry. Zero usable
/// associations use ordinary PKIX; any usable association set must authenticate the
/// peer without falling back after a mismatch. The caller owns the native handshake.
pub fn upstream_config(
    hostname: &str,
    port: u16,
    tlsa: Option<AuthenticatedTlsa>,
    roots: Arc<TrustRoots>,
    guard: Guard,
) -> Result<UpstreamTls, TlsError> {
    let server_name = host_name(hostname, &guard)?;
    if port == 0 {
        return Err(TlsError::InvalidInput("zero upstream TCP port"));
    }
    let tlsa_expiry = tlsa.as_ref().map(|set| set.expires_at);
    let mut usable_tlsa = Vec::new();
    let mut skipped_tlsa_records = Vec::new();
    if let Some(records) = &tlsa {
        host_name(&records.hostname, &guard)?;
        if records.hostname != hostname || records.port != port {
            return Err(TlsError::Binding);
        }
        if records.expires_at <= wall_now(&guard)? {
            return Err(TlsError::Expired);
        }
        if records.records.len() > MAX_TLSA_RECORDS {
            return Err(TlsError::Limit("authenticated TLSA record count"));
        }
        let mut bytes = 0_usize;
        for (record_index, record) in records.records.iter().enumerate() {
            guard()?;
            let length = record.association.len();
            if length > MAX_ASSOCIATION_BYTES {
                return Err(TlsError::Limit("TLSA association length"));
            }
            bytes = bytes
                .checked_add(length)
                .ok_or(TlsError::Limit("TLSA association bytes"))?;
            if bytes > MAX_TLSA_BYTES {
                return Err(TlsError::Limit("TLSA association bytes"));
            }
            if let Some(reason) = tlsa_unusable_reason(record, &guard)? {
                skipped_tlsa_records.push(SkippedTlsaRecord {
                    record_index,
                    usage: record.usage,
                    selector: record.selector,
                    matching: record.matching,
                    reason,
                });
            } else {
                usable_tlsa.push(record_index);
            }
        }
    }
    let (config, proof) = guarded(&guard, || {
        let provider = guarded(&guard, || {
            Ok(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        })?;
        let pkix = guarded(&guard, || {
            WebPkiServerVerifier::builder_with_provider(roots.store.clone(), provider.clone())
                .build()
                .map_err(|_| TlsError::Configuration("PKIX roots"))
        })?;
        let proof = Arc::new(Mutex::new(None));
        let verifier = UpstreamVerifier {
            hostname: hostname.to_owned(),
            port,
            server_name: server_name.clone(),
            tlsa,
            usable_tlsa,
            skipped_tlsa_records,
            roots,
            pkix,
            provider: provider.clone(),
            guard: guard.clone(),
            proof: proof.clone(),
        };
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| TlsError::Configuration("TLS protocol versions"))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        config.resumption = rustls::client::Resumption::disabled();
        config.enable_early_data = false;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok((Arc::new(config), proof))
    })?;
    if let Some(expiry) = tlsa_expiry
        && wall_now(&guard)? >= expiry
    {
        return Err(TlsError::Expired);
    }
    guard()?;
    Ok(UpstreamTls {
        config,
        server_name,
        proof,
        guard,
    })
}

struct UpstreamVerifier {
    hostname: String,
    port: u16,
    server_name: ServerName<'static>,
    tlsa: Option<AuthenticatedTlsa>,
    usable_tlsa: Vec<usize>,
    skipped_tlsa_records: Vec<SkippedTlsaRecord>,
    roots: Arc<TrustRoots>,
    pkix: Arc<WebPkiServerVerifier>,
    provider: Arc<CryptoProvider>,
    guard: Guard,
    proof: Arc<Mutex<Option<Proof>>>,
}

impl fmt::Debug for UpstreamVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GnsUpstreamVerifier")
    }
}

fn bounded_chain(leaf: &CertificateDer<'_>, chain: &[CertificateDer<'_>]) -> Result<(), TlsError> {
    if chain.len() >= MAX_CHAIN_CERTS || leaf.len() > MAX_CERT_BYTES {
        return Err(TlsError::Limit("upstream certificate chain"));
    }
    let mut total = leaf.len();
    for cert in chain {
        if cert.len() > MAX_CERT_BYTES {
            return Err(TlsError::Limit("upstream certificate"));
        }
        total = total
            .checked_add(cert.len())
            .ok_or(TlsError::Limit("upstream certificate bytes"))?;
        if total > MAX_CHAIN_BYTES {
            return Err(TlsError::Limit("upstream certificate bytes"));
        }
    }
    Ok(())
}

fn matches_bytes(record: &TlsaRecord, bytes: &[u8], guard: &Guard) -> Result<bool, TlsError> {
    guarded(guard, || {
        Ok(match record.matching {
            0 => bytes == record.association.as_slice(),
            1 => digest::digest(&digest::SHA256, bytes).as_ref() == record.association.as_slice(),
            2 => digest::digest(&digest::SHA512, bytes).as_ref() == record.association.as_slice(),
            _ => {
                return Err(TlsError::UnsupportedTlsa {
                    usage: record.usage,
                    selector: record.selector,
                    matching: record.matching,
                });
            }
        })
    })
}

fn matches_certificate(
    record: &TlsaRecord,
    cert: &CertificateDer<'_>,
    guard: &Guard,
) -> Result<bool, TlsError> {
    match record.selector {
        0 => matches_bytes(record, cert.as_ref(), guard),
        1 => {
            let spki = guarded(guard, || {
                Ok(parse_certificate(cert.as_ref())?.public_key().raw.to_vec())
            })?;
            matches_bytes(record, &spki, guard)
        }
        _ => Err(TlsError::UnsupportedTlsa {
            usage: record.usage,
            selector: record.selector,
            matching: record.matching,
        }),
    }
}

fn dane_path_len_allows(
    path: &webpki::VerifiedPath<'_>,
    limit: u32,
    guard: &Guard,
) -> Result<bool, TlsError> {
    guarded(guard, || {
        let mut intermediate_count = 0_usize;
        let mut non_self_issued_cas = 0_u32;
        // VerifiedPath contains only verified CA intermediates here; its leaf
        // and selected trust anchor are separate and must not consume pathLen.
        for certificate in path.intermediate_certificates() {
            let self_issued = guarded(guard, || {
                intermediate_count += 1;
                if intermediate_count >= MAX_CHAIN_CERTS || certificate.der().len() > MAX_CERT_BYTES
                {
                    return Err(TlsError::Limit("verified DANE intermediate certificates"));
                }
                // Use the same DER name representation exposed by webpki for
                // both sides, rather than a display-string or CN comparison.
                Ok(certificate.subject() == certificate.issuer())
            })?;
            if !self_issued {
                non_self_issued_cas = non_self_issued_cas
                    .checked_add(1)
                    .ok_or(TlsError::Limit("verified DANE CA depth"))?;
                if non_self_issued_cas > limit {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    })
}

impl UpstreamVerifier {
    fn pkix_ca_association(
        &self,
        record: &TlsaRecord,
        leaf: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<bool, TlsError> {
        let mut matched_certificates = Vec::new();
        let mut matched_anchors = Vec::new();
        for root in &self.roots.full_der {
            if matches_certificate(record, &root.certificate, &self.guard)? {
                // Imported into this exact PKIX store; the callback below also
                // requires this retained certificate's actual selected anchor.
                matched_anchors.push(root.anchor.clone());
            }
        }
        if record.selector == 0 && record.matching == 0 {
            // An exact full-DER association itself supplies the root certificate
            // omitted by many peers. It still has to identify the anchor of a
            // PKIX-valid path to this configured store; it establishes no new trust.
            let der = CertificateDer::from(record.association.as_slice());
            let candidate = guarded(&self.guard, || {
                webpki::anchor_from_trusted_cert(&der)
                    .map(|anchor| anchor.to_owned())
                    .map_err(|_| TlsError::Certificate("TLSA exact CA certificate"))
            });
            match candidate {
                Ok(anchor) => matched_anchors.push(anchor),
                Err(TlsError::Certificate(_)) => {}
                Err(error) => return Err(error),
            }
        }
        for certificate in chain {
            if matches_certificate(record, certificate, &self.guard)? {
                matched_certificates.push(certificate.as_ref());
                let anchor = guarded(&self.guard, || {
                    webpki::anchor_from_trusted_cert(certificate)
                        .map(|anchor| anchor.to_owned())
                        .map_err(|_| TlsError::Certificate("presented CA anchor"))
                });
                match anchor {
                    Ok(anchor) => matched_anchors.push(anchor),
                    Err(TlsError::Certificate(_)) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        if record.selector == 1 {
            // Mozilla roots retain the SPKI SEQUENCE contents, rather than full
            // certificate DER. A standard DER encoder restores the SPKI wrapper.
            // Omitted root certificate hashes need retained configured full DER;
            // all anchors additionally support SPKI associations here.
            for anchor in &self.roots.store.roots {
                let spki = guarded(&self.guard, || {
                    Ok(yasna::construct_der(|writer| {
                        writer.write_sequence(|sequence| {
                            sequence
                                .next()
                                .write_der(anchor.subject_public_key_info.as_ref())
                        });
                    }))
                })?;
                if matches_bytes(record, &spki, &self.guard)? {
                    matched_anchors.push(anchor.clone());
                }
            }
        }
        if matched_certificates.is_empty() && matched_anchors.is_empty() {
            return Ok(false);
        }
        guarded(&self.guard, || {
            let cert = webpki::EndEntityCert::try_from(leaf)
                .map_err(|_| TlsError::Certificate("upstream leaf"))?;
            let require_association = |path: &webpki::VerifiedPath<'_>| {
                if matched_anchors.iter().any(|anchor| anchor == path.anchor())
                    || path.intermediate_certificates().any(|cert| {
                        matched_certificates
                            .iter()
                            .any(|der| *der == cert.der().as_ref())
                    })
                {
                    Ok(())
                } else {
                    Err(webpki::Error::UnknownIssuer)
                }
            };
            Ok(cert
                .verify_for_usage(
                    self.provider.signature_verification_algorithms.all,
                    &self.roots.store.roots,
                    chain,
                    now,
                    webpki::KeyUsage::server_auth(),
                    None,
                    Some(&require_association),
                )
                .is_ok())
        })
    }

    fn dane_trust_anchor(
        &self,
        record: &TlsaRecord,
        leaf: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<bool, TlsError> {
        let now_wall = UNIX_EPOCH
            .checked_add(Duration::from_secs(now.as_secs()))
            .ok_or(TlsError::Clock)?;
        // RFC 7671 section 5.2.2: a 2/0/0 association supplies the complete
        // authenticated trust-anchor certificate even when the server omits it.
        // A certificate/public-key digest cannot supply a missing certificate.
        let association_ca = if record.selector == 0 && record.matching == 0 {
            Some(CertificateDer::from(record.association.as_slice()))
        } else {
            None
        };
        for candidate in association_ca.iter().chain(chain.iter()) {
            (self.guard)()?;
            if !matches_certificate(record, candidate, &self.guard)? {
                continue;
            }
            // The CA must be supplied by the authenticated exact association or
            // explicitly presented. It must also satisfy actual CA constraints,
            // a verified certificate path and the selected upstream hostname.
            let constraints = match ca_validity(candidate.as_ref(), now_wall, &self.guard) {
                Ok(constraints) => constraints,
                Err(TlsError::Certificate(_) | TlsError::Expired) => continue,
                Err(error) => return Err(error),
            };
            let valid = guarded(&self.guard, || {
                let anchor = webpki::anchor_from_trusted_cert(candidate)
                    .map_err(|_| TlsError::Certificate("DANE trust anchor"))?;
                let anchors = [anchor];
                let cert = webpki::EndEntityCert::try_from(leaf)
                    .map_err(|_| TlsError::Certificate("upstream leaf"))?;
                // Trust-anchor extraction drops BasicConstraints.pathLenConstraint.
                // Apply it to each actual selected path, allowing webpki to try a
                // different valid path when one path contains too many CA hops.
                let callback_error = RefCell::new(None);
                let check_path = |path: &webpki::VerifiedPath<'_>| {
                    let allowed = match constraints.path_len_constraint {
                        Some(limit) => dane_path_len_allows(path, limit, &self.guard),
                        None => Ok(true),
                    };
                    match allowed {
                        Ok(true) => Ok(()),
                        Ok(false) => Err(webpki::Error::UnknownIssuer),
                        Err(error) => {
                            let mut first_error = callback_error.borrow_mut();
                            if first_error.is_none() {
                                *first_error = Some(error);
                            }
                            Err(webpki::Error::UnknownIssuer)
                        }
                    }
                };
                let verified = cert.verify_for_usage(
                    self.provider.signature_verification_algorithms.all,
                    &anchors,
                    chain,
                    now,
                    webpki::KeyUsage::server_auth(),
                    None,
                    Some(&check_path),
                );
                if let Some(error) = callback_error.into_inner() {
                    return Err(error);
                }
                if verified.is_err() {
                    return Ok(false);
                }
                (self.guard)()?;
                Ok(cert
                    .verify_is_valid_for_subject_name(&self.server_name)
                    .is_ok())
            })?;
            if valid {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn verify_policy(
        &self,
        leaf: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<Authentication, TlsError> {
        guarded(&self.guard, || bounded_chain(leaf, chain))?;
        if ocsp.len() > MAX_OCSP_BYTES {
            return Err(TlsError::Limit("upstream OCSP response"));
        }
        if name != &self.server_name {
            return Err(TlsError::Binding);
        }
        let dates = validity(leaf.as_ref(), &self.guard)?;
        let tlsa_expiry = self.tlsa.as_ref().map(|set| set.expires_at);
        let now_wall = UNIX_EPOCH
            .checked_add(Duration::from_secs(now.as_secs()))
            .ok_or(TlsError::Clock)?;
        if tlsa_expiry.is_some_and(|expiry| expiry <= now_wall) {
            return Err(TlsError::Expired);
        }
        // RFC 6698 section 4.1: with zero usable associations perform ordinary
        // TLS/PKIX. Once any association is usable, failure to match aborts TLS.
        let pkix_needed = self.usable_tlsa.is_empty()
            || self.tlsa.as_ref().is_some_and(|set| {
                self.usable_tlsa.iter().any(|&index| {
                    set.records
                        .get(index)
                        .is_some_and(|record| record.usage <= 1)
                })
            });
        let pkix_valid = if pkix_needed {
            guarded(&self.guard, || {
                Ok(self
                    .pkix
                    .verify_server_cert(leaf, chain, name, ocsp, now)
                    .is_ok())
            })?
        } else {
            false
        };
        let method = if let Some(set) = self.tlsa.as_ref().filter(|_| !self.usable_tlsa.is_empty())
        {
            let mut method = None;
            for &record_index in &self.usable_tlsa {
                (self.guard)()?;
                let record = set.records.get(record_index).ok_or(TlsError::Binding)?;
                let accepted = match record.usage {
                    0 if pkix_valid => self.pkix_ca_association(record, leaf, chain, now)?,
                    1 if pkix_valid => matches_certificate(record, leaf, &self.guard)?,
                    0 | 1 => false,
                    2 => self.dane_trust_anchor(record, leaf, chain, now)?,
                    3 => matches_certificate(record, leaf, &self.guard)?,
                    _ => {
                        return Err(TlsError::UnsupportedTlsa {
                            usage: record.usage,
                            selector: record.selector,
                            matching: record.matching,
                        });
                    }
                };
                if accepted {
                    method = Some(match record.usage {
                        0 | 1 => AuthenticationMethod::PkixTlsa {
                            record_index,
                            usage: record.usage,
                            selector: record.selector,
                            matching: record.matching,
                        },
                        2 => AuthenticationMethod::DaneTrustAnchor {
                            record_index,
                            selector: record.selector,
                            matching: record.matching,
                        },
                        3 => AuthenticationMethod::DaneEndEntity {
                            record_index,
                            selector: record.selector,
                            matching: record.matching,
                        },
                        _ => {
                            return Err(TlsError::UnsupportedTlsa {
                                usage: record.usage,
                                selector: record.selector,
                                matching: record.matching,
                            });
                        }
                    });
                    break;
                }
            }
            method.ok_or(TlsError::Dane)?
        } else {
            if !pkix_valid {
                return Err(TlsError::Pkix);
            }
            AuthenticationMethod::Pkix
        };
        let authenticated_until = if matches!(method, AuthenticationMethod::DaneEndEntity { .. }) {
            tlsa_expiry.ok_or(TlsError::Dane)?
        } else {
            tlsa_expiry.map_or(dates.not_after, |expiry| expiry.min(dates.not_after))
        };
        (self.guard)()?;
        Ok(Authentication {
            hostname: self.hostname.clone(),
            port: self.port,
            method,
            tlsa_expires_at: tlsa_expiry,
            skipped_tlsa_records: self.skipped_tlsa_records.clone(),
            certificate_not_after: dates.not_after,
            authenticated_until,
        })
    }

    fn record_signature(&self, cert: &CertificateDer<'_>) -> Result<(), RustlsError> {
        guarded(&self.guard, || {
            let mut proof = self.proof.try_lock().map_err(|_| TlsError::Busy)?;
            let proof = proof.as_mut().ok_or(TlsError::IncompleteHandshake)?;
            if proof.leaf.as_slice() != cert.as_ref() {
                return Err(TlsError::Binding);
            }
            proof.signature_verified = true;
            Ok(())
        })
        .map_err(rustls_error)
    }
}

impl ServerCertVerifier for UpstreamVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        guarded(&self.guard, || {
            *self.proof.try_lock().map_err(|_| TlsError::Busy)? = None;
            Ok(())
        })
        .map_err(rustls_error)?;
        let authentication = self
            .verify_policy(end_entity, intermediates, server_name, ocsp_response, now)
            .map_err(rustls_error)?;
        guarded(&self.guard, || {
            *self.proof.try_lock().map_err(|_| TlsError::Busy)? = Some(Proof {
                leaf: end_entity.as_ref().to_vec(),
                authentication,
                signature_verified: false,
            });
            Ok(ServerCertVerified::assertion())
        })
        .map_err(rustls_error)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        (self.guard)().map_err(rustls_error)?;
        if message.len() > MAX_SIGNATURE_MESSAGE_BYTES
            || cert.len() > MAX_CERT_BYTES
            || dss.signature().len() > MAX_SIGNATURE_BYTES
        {
            return Err(rustls_error(TlsError::Limit(
                "TLS handshake signature input",
            )));
        }
        let result = verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        );
        (self.guard)().map_err(rustls_error)?;
        let valid = result?;
        self.record_signature(cert)?;
        Ok(valid)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        (self.guard)().map_err(rustls_error)?;
        if message.len() > MAX_SIGNATURE_MESSAGE_BYTES
            || cert.len() > MAX_CERT_BYTES
            || dss.signature().len() > MAX_SIGNATURE_BYTES
        {
            return Err(rustls_error(TlsError::Limit(
                "TLS handshake signature input",
            )));
        }
        let result = verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        );
        (self.guard)().map_err(rustls_error)?;
        let valid = result?;
        self.record_signature(cert)?;
        Ok(valid)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        if (self.guard)().is_err() {
            return Vec::new();
        }
        let schemes = self
            .provider
            .signature_verification_algorithms
            .supported_schemes();
        if (self.guard)().is_err() {
            return Vec::new();
        }
        schemes
    }
}
