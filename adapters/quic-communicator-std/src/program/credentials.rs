//! Bounded configured PEM/DER pair ownership. All IO runs after USER.
//! Missing pairs are generated with the existing Rust TLS backend, never a C
//! subprocess. Partial pairs are refused rather than overwriting an existing key.
use super::{Failure, settings::Pair};
use crate::{credentials::Tls, tls::Profile};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;
const KEY_BYTES: usize = 64 * 1024;
const CERT_BYTES: usize = 1024 * 1024;
const CHAIN: usize = 16;
fn invalid(text: &'static str) -> Failure {
    io::Error::new(io::ErrorKind::InvalidData, text).into()
}
fn present(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_file() => Ok(true),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "credential path is not a regular file",
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}
fn read(path: &Path, limit: usize, private: bool) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > u64::try_from(limit)? {
        return Err(invalid("credential exceeds its regular-file byte bound"));
    }
    if private && metadata.mode() & 0o077 != 0 {
        return Err(invalid("private TLS key must not grant group/other access"));
    }
    let maximum = limit.checked_add(1).ok_or("credential size overflow")?;
    let mut body = Zeroizing::new(Vec::new());
    body.try_reserve_exact(maximum)?;
    file.take(u64::try_from(maximum)?).read_to_end(&mut body)?;
    if body.len() > limit || body.is_empty() {
        return Err(invalid("credential is empty or exceeds byte bound"));
    }
    Ok(body)
}
fn pem(bytes: &[u8]) -> bool {
    bytes
        .windows(b"-----BEGIN ".len())
        .any(|v| v == b"-----BEGIN ")
}
fn install(
    profile: Profile,
    certificates: Vec<CertificateDer<'static>>,
    key: Zeroizing<PrivateKeyDer<'static>>,
) -> Result<Tls, Failure> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let client = crate::tls::client(provider.clone(), profile)?;
    // Rustls consumes the original owned installation input and performs actual
    // key/certificate consistency checking. The retained parser copy is zeroized.
    let server = crate::tls::server(provider, certificates, key.clone_key(), profile)?;
    Ok(Tls::from_configs(client, server, profile)?)
}
fn load(profile: Profile, pair: &Pair) -> Result<Tls, Failure> {
    let key_body = read(&pair.key, KEY_BYTES, true)?;
    let key = if pem(&key_body) {
        PrivateKeyDer::from_pem_slice(&key_body)
            .map_err(|_| invalid("invalid PEM private TLS key"))?
    } else {
        // Parse by borrowing first, so invalid DER is never moved into an ordinary
        // unzeroized Vec on the library's error path.
        PrivateKeyDer::try_from(&key_body[..])
            .map_err(|_| invalid("invalid DER private TLS key"))?
            .clone_key()
    };
    let key = Zeroizing::new(key);
    let certificate_body = read(&pair.certificate, CERT_BYTES, false)?;
    let mut certificates = Vec::new();
    certificates.try_reserve_exact(CHAIN)?;
    if pem(&certificate_body) {
        for c in CertificateDer::pem_slice_iter(&certificate_body) {
            if certificates.len() == CHAIN {
                return Err(invalid("certificate chain exceeds entry bound"));
            }
            certificates.push(c.map_err(|_| invalid("invalid PEM TLS certificate"))?);
        }
    } else {
        certificates.push(CertificateDer::from(certificate_body.to_vec()))
    }
    if certificates.is_empty() {
        return Err(invalid("empty certificate chain"));
    }
    install(profile, certificates, key)
}
struct NewFile {
    path: PathBuf,
    file: File,
    device: u64,
    inode: u64,
    keep: bool,
}
impl NewFile {
    fn create(path: &Path) -> Result<Self, Failure> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let m = match file.metadata() {
            Ok(metadata) => metadata,
            Err(original) => {
                return Err(Box::new(CreationFailure {
                    original: original.into(),
                    cleanup: [
                        Some(io::Error::other(
                            "new empty credential inode could not be observed; path left untouched",
                        )),
                        None,
                    ],
                }));
            }
        };
        Ok(Self {
            path: path.to_path_buf(),
            file,
            device: m.dev(),
            inode: m.ino(),
            keep: false,
        })
    }
    fn remove(&mut self) -> io::Result<()> {
        if self.keep {
            return Ok(());
        }
        match fs::symlink_metadata(&self.path) {
            Ok(m) if m.dev() == self.device && m.ino() == self.inode => fs::remove_file(&self.path),
            Ok(_) => Err(io::Error::other(
                "created credential path changed; replacement left untouched",
            )),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}
impl Drop for NewFile {
    fn drop(&mut self) {
        match self.remove() {
            Ok(()) | Err(_) => {}
        }
    }
}
#[derive(Debug)]
struct CreationFailure {
    original: Failure,
    cleanup: [Option<io::Error>; 2],
}
impl std::fmt::Display for CreationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TLS pair creation failed: {}; independent cleanup: {:?}",
            self.original, self.cleanup
        )
    }
}
impl std::error::Error for CreationFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.original.as_ref())
    }
}
fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}
fn create(profile: Profile, pair: &Pair) -> Result<Tls, Failure> {
    let key = Zeroizing::new(rcgen::KeyPair::generate_for(
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )?);
    let certificate =
        rcgen::CertificateParams::new(vec!["localhost".to_string()])?.self_signed(&*key)?;
    let serialized = Zeroizing::new(key.serialize_der());
    if serialized.len() > KEY_BYTES || certificate.der().as_ref().len() > CERT_BYTES {
        return Err(invalid("generated credential exceeds byte bound"));
    }
    // Install/validate before creating any persistent file. These are DER, accepted
    // by the same bounded load path on a subsequent process invocation.
    let private = Zeroizing::new(
        PrivateKeyDer::try_from(&serialized[..])
            .map_err(|_| invalid("backend returned invalid private DER"))?
            .clone_key(),
    );
    let tls = install(profile, vec![certificate.der().clone()], private)?;
    gnunet_service_runtime::private_parents(&pair.key)?;
    gnunet_service_runtime::private_parents(&pair.certificate)?;
    let mut key_file = NewFile::create(&pair.key)?;
    let mut cert_file = match NewFile::create(&pair.certificate) {
        Ok(f) => f,
        Err(original) => {
            let cleanup = key_file.remove().err();
            return Err(Box::new(CreationFailure {
                original,
                cleanup: [cleanup, None],
            }));
        }
    };
    let written = (|| -> Result<(), Failure> {
        key_file.file.write_all(&serialized)?;
        cert_file.file.write_all(certificate.der().as_ref())?;
        key_file.file.sync_all()?;
        cert_file.file.sync_all()?;
        File::open(parent(&pair.key))?.sync_all()?;
        if parent(&pair.key) != parent(&pair.certificate) {
            File::open(parent(&pair.certificate))?.sync_all()?
        }
        Ok(())
    })();
    if let Err(original) = written {
        return Err(Box::new(CreationFailure {
            original,
            cleanup: [key_file.remove().err(), cert_file.remove().err()],
        }));
    }
    key_file.keep = true;
    cert_file.keep = true;
    Ok(tls)
}
pub(super) fn prepare(profile: Profile, pair: Option<&Pair>) -> Result<Tls, Failure> {
    let Some(pair) = pair else {
        return Ok(Tls::fresh(profile, vec!["localhost".to_string()])?);
    };
    match (present(&pair.key)?, present(&pair.certificate)?) {
        (true, true) => load(profile, pair),
        (false, false) => create(profile, pair),
        _ => Err(invalid(
            "partial configured TLS pair; existing credential left untouched",
        )),
    }
}
