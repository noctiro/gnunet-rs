use crate::*;
/// Explicit utility resources, independent from configured service runtime pools.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Distinct configuration attempts per original native system.
    pub configurations: usize,
    /// Maximum newly allocated ports for one configuration.
    pub ports_per_configuration: usize,
    /// Maximum configurations/sections/ACL planning input bytes.
    pub configuration_bytes: usize,
    /// Maximum path bytes and UNIXPATH output bytes.
    pub path_bytes: usize,
    /// Native temporary directory name attempts, without entropy or a hidden loop.
    pub directory_attempts: u32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            configurations: 4096,
            ports_per_configuration: 256,
            configuration_bytes: 4 * 1024 * 1024,
            path_bytes: 4096,
            directory_attempts: 4096,
        }
    }
}
impl Limits {
    pub(crate) fn validate(self) -> Result<(), Failure> {
        if self.configurations == 0
            || self.ports_per_configuration == 0
            || self.configuration_bytes == 0
            || self.path_bytes == 0
            || self.directory_attempts == 0
        {
            Err(Cause::Protocol(Fault::InvalidInput).into())
        } else {
            Ok(())
        }
    }
}
/// Explicit address families for real bind probes. Every enabled supported
/// family is checked for BOTH TCP and UDP; at least one must actually support it.
#[derive(Clone, Copy, Debug)]
pub struct Families {
    /// Check IPv4 wildcard endpoints.
    pub ipv4: bool,
    /// Check IPv6 wildcard endpoints, v6-only to keep both families distinct.
    pub ipv6: bool,
}
impl Default for Families {
    fn default() -> Self {
        Self {
            ipv4: true,
            ipv6: true,
        }
    }
}
/// Explicit creation, root trust and public network policy.
pub struct Options {
    /// Exact GNUNET_TESTBED_PREFIX override, or None for a fresh owned temp child.
    pub prefix: Option<PathBuf>,
    /// Existing parent for fresh named children, defaults to /tmp to leave room for actual Unix socket names.
    pub temporary_parent: PathBuf,
    /// One safe basename, not a path. Used only when prefix is absent.
    pub label: OsString,
    /// Exact trusted IP/CIDR appended to service ACCEPT_FROM/ACCEPT_FROM6.
    pub trusted_ip: Option<String>,
    /// Configured real host name; None selects official localhost.
    pub hostname: Option<Vec<u8>>,
    /// Inclusive source range low.
    pub low_port: u16,
    /// Exclusive source range high.
    pub high_port: u16,
    /// Actual selected probe families.
    pub families: Families,
    /// Explicit finite utility limits.
    pub limits: Limits,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            prefix: None,
            temporary_parent: PathBuf::from("/tmp"),
            label: "testing".into(),
            trusted_ip: None,
            hostname: None,
            low_port: core::DEFAULT_LOW_PORT,
            high_port: core::DEFAULT_HIGH_PORT,
            families: Families::default(),
            limits: Limits::default(),
        }
    }
}
/// Actual failed effect stage; no false durable/store/process result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Exposure {
    /// No target installation was attempted.
    Unchanged,
    /// A private temporary file may exist; final target not installed.
    Staged,
    /// Rename/link actually installed original bytes; later fsync may be unknown.
    Installed,
}
/// Original typed failure. Configuration values are never included in messages.
#[derive(Debug)]
pub enum Cause {
    /// Resource, original-token or input failure.
    Protocol(Fault),
    /// Shared official configuration backend's actual error.
    Configuration(gnunet_config::Error),
    /// Actual native error and exact operation path.
    Io {
        /// Native stage name, not a configuration value.
        operation: &'static str,
        /// Actual attempted path.
        path: PathBuf,
        /// Original OS error.
        error: io::Error,
    },
    /// Existing directory is not this utility's marked Rust namespace.
    ForeignDirectory,
    /// Namespace inode/marker/counter changed, or a prior unknown fenced admission.
    Changed,
    /// Active C declares but does not implement this per-host-sharding policy.
    SharedServiceSharding,
}
/// First original failure plus first independent cleanup cause and total count.
/// Utility cleanup always attempts every original reservation before returning.
#[derive(Debug)]
pub struct Failure {
    /// Original operation cause.
    pub cause: Cause,
    /// Actual installation exposure, never converted to success.
    pub exposure: Exposure,
    /// First independent cleanup cause, if any.
    pub cleanup: Option<Cause>,
    /// Total independent cleanup failures (bounded attempts).
    pub cleanup_count: usize,
}
impl Failure {
    pub(crate) fn io(operation: &'static str, path: impl Into<PathBuf>, error: io::Error) -> Self {
        Cause::Io {
            operation,
            path: path.into(),
            error,
        }
        .into()
    }
    pub(crate) fn add(&mut self, cause: Cause) {
        self.cleanup_count = self.cleanup_count.saturating_add(1);
        if self.cleanup.is_none() {
            self.cleanup = Some(cause)
        }
    }
}
impl From<Cause> for Failure {
    fn from(cause: Cause) -> Self {
        Self {
            cause,
            exposure: Exposure::Unchanged,
            cleanup: None,
            cleanup_count: 0,
        }
    }
}
impl From<Fault> for Failure {
    fn from(error: Fault) -> Self {
        Cause::Protocol(error).into()
    }
}
impl From<gnunet_config::Error> for Failure {
    fn from(error: gnunet_config::Error) -> Self {
        Cause::Configuration(error).into()
    }
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.cause {
            Cause::Protocol(e) => write!(f, "TESTBED resource/input failure: {e:?}"),
            Cause::Configuration(e) => write!(f, "TESTBED configuration failure: {e}"),
            Cause::Io {
                operation,
                path,
                error,
            } => write!(f, "TESTBED {operation} at {}: {error}", path.display()),
            Cause::ForeignDirectory => {
                f.write_str("TESTBED refuses an unmarked/nonempty directory")
            }
            Cause::Changed => f.write_str("TESTBED owned namespace changed or outcome is fenced"),
            Cause::SharedServiceSharding => f.write_str(
                "TESTBED active per-host service sharding has no implemented official semantics",
            ),
        }
    }
}
impl std::error::Error for Failure {}
/// Successful complete local configuration publication, only minted after real
/// final file and parent fsync. It implies no service/peer readiness.
#[derive(Debug)]
pub struct Published {
    pub(crate) path: PathBuf,
    pub(crate) bytes: usize,
}
impl Published {
    /// Actual output path.
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// Actual immutable serialized byte count.
    pub const fn bytes(&self) -> usize {
        self.bytes
    }
}
/// Real explicit destruction result. Keeping paths does not claim removal.
#[derive(Debug)]
pub enum Removal {
    /// Logical resources released; marked path deliberately retained.
    Kept(PathBuf),
    /// Native remove_dir_all of the original marked directory succeeded.
    Removed(PathBuf),
}
/// Explicit target publication policy; no implicit unknown-write replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Replace {
    /// Atomic no-replace installation; existing files are refused.
    NewOnly,
    /// Exact caller-selected configuration target may be atomically replaced.
    Allowed,
}

impl Options {
    /// Explicit capture of only the official GNUNET_TESTBED_PREFIX input.
    /// No other environment, directory, key file or native source is consulted.
    pub fn from_environment() -> Self {
        Self {
            prefix: std::env::var_os("GNUNET_TESTBED_PREFIX").map(PathBuf::from),
            ..Self::default()
        }
    }
}
