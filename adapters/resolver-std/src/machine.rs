//! Owned startup inputs, separate from Resolver state and native socket drivers.
use std::{
    fmt,
    io::{self, Read},
    net::SocketAddr,
    path::{Path, PathBuf},
};

/// Exact origin of a machine input failure, independent of protocol authority.
#[derive(Debug)]
pub enum MachineSource {
    /// An actual selected file path, including its original native encoding.
    File(PathBuf),
    /// Windows Internet database location discovery before selecting hosts.
    DatabaseDirectory,
    /// Native Windows DNS adapter configuration.
    DnsConfiguration,
    /// Native primary or operational-interface DNS search domain.
    DnsDomain,
}
impl fmt::Display for MachineSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(path) => path.display().fmt(f),
            Self::DatabaseDirectory => f.write_str("Windows Internet database directory"),
            Self::DnsConfiguration => f.write_str("Windows DNS configuration"),
            Self::DnsDomain => f.write_str("Windows DNS search domain"),
        }
    }
}
/// An input that failed to load, never a successful empty-source receipt.
#[derive(Debug)]
pub struct MachineDiagnostic {
    /// Original selected source.
    pub source: MachineSource,
    /// Original native read/query or explicit resource error.
    pub error: io::Error,
}
/// Owned machine inputs sampled once before service readiness. Empty fixture
/// inputs are explicit; Default does not read the host or start native work.
#[derive(Default)]
pub struct MachineInputs {
    /// Hosts-file bytes, or explicitly supplied embedding fixture bytes.
    pub hosts: Vec<u8>,
    /// Unix resolver-file bytes retaining their exact line syntax.
    pub resolv: Vec<u8>,
    /// Native IP/port/scope tuples, first-attempt order. Never serialized through
    /// a resolver-file IP token, which would lose a scoped IPv6 address.
    pub dns_endpoints: Vec<SocketAddr>,
    /// Explicit native/embedding single search domain, overriding a file suffix.
    /// None leaves the resolver file's domain unchanged. No private config key
    /// or DNS request is used to discover this observation.
    pub search_domain: Option<Vec<u8>>,
    /// Actual failed sources. Startup may continue with their inputs empty.
    pub diagnostics: Vec<MachineDiagnostic>,
}
impl MachineInputs {
    /// Sample production inputs with a byte ceiling for each file. Unix uses
    /// literal /etc/hosts and /etc/resolv.conf. Windows uses the configured native
    /// Internet database directory's hosts and bounded DNS adapter configuration.
    /// An absent registry location selects native system-directory discovery. Read,
    /// query and capacity failures become diagnostics and leave that source empty.
    /// The primary DNS domain precedes an operational-interface suffix. Search
    /// lists, devolution and NRPT are not synthesized from adapter server data.
    pub fn production(maximum_file_bytes: usize) -> Self {
        let mut inputs = Self::default();
        #[cfg(unix)]
        {
            inputs.hosts = inputs.load(PathBuf::from("/etc/hosts"), maximum_file_bytes);
            inputs.resolv = inputs.load(PathBuf::from("/etc/resolv.conf"), maximum_file_bytes);
        }
        #[cfg(windows)]
        {
            match gnunet_native::paths::internet_database_directory() {
                Ok(directory) => {
                    inputs.hosts = inputs.load(directory.join("hosts"), maximum_file_bytes)
                }
                Err(error) => inputs.diagnostics.push(MachineDiagnostic {
                    source: MachineSource::DatabaseDirectory,
                    error,
                }),
            }
            match gnunet_native::dns::configuration(Default::default()) {
                Ok(config) => {
                    match config.servers {
                        Ok(endpoints) => inputs.dns_endpoints = endpoints,
                        Err(error) => inputs.diagnostics.push(MachineDiagnostic {
                            source: MachineSource::DnsConfiguration,
                            error,
                        }),
                    }
                    match config.domain {
                        Ok(domain) => {
                            inputs.search_domain = domain.map(|domain| domain.name.into_bytes())
                        }
                        Err(error) => inputs.diagnostics.push(MachineDiagnostic {
                            source: MachineSource::DnsDomain,
                            error,
                        }),
                    }
                }
                Err(error) => inputs.diagnostics.push(MachineDiagnostic {
                    source: MachineSource::DnsConfiguration,
                    error,
                }),
            }
        }
        inputs
    }
    fn load(&mut self, path: PathBuf, maximum: usize) -> Vec<u8> {
        match read(&path, maximum) {
            Ok(bytes) => bytes,
            Err(error) => {
                self.diagnostics.push(MachineDiagnostic {
                    source: MachineSource::File(path),
                    error,
                });
                Vec::new()
            }
        }
    }
}
fn read(path: &Path, maximum: usize) -> io::Result<Vec<u8>> {
    let mut file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    let mut block = [0u8; 8192];
    loop {
        let count = file.read(&mut block)?;
        if count == 0 {
            return Ok(bytes);
        }
        if count > maximum.saturating_sub(bytes.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "machine file exceeds explicit host byte capacity",
            ));
        }
        let required = bytes.len() + count;
        if required > bytes.capacity() {
            let capacity = bytes
                .capacity()
                .saturating_mul(2)
                .max(block.len())
                .max(required)
                .min(maximum);
            bytes
                .try_reserve_exact(capacity - bytes.len())
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::OutOfMemory,
                        "machine-file allocation capacity",
                    )
                })?;
        }
        bytes.extend_from_slice(&block[..count]);
    }
}
