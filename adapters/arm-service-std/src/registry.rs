//! Official ARM setup_service/run/start_process configuration decisions.
use gnunet_arm_service_core::ServiceSpec;
use gnunet_config::{BinaryPathCache, Configuration, Environment, ProjectData};
use std::{
    ffi::OsString,
    fmt, fs,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::PathBuf,
};
/// Explicit bounds on the std registry; refusal never omits a service as success.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum registered non-ARM services, including those without listeners.
    pub services: usize,
    /// Maximum composed native command/options bytes per service.
    pub command_bytes: usize,
    /// Maximum recursive {} substitutions in GLOBAL_POSTFIX.
    pub substitutions: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            services: 256,
            command_bytes: 65535,
            substitutions: 65535,
        }
    }
}
/// Registry preparation failures, before any native process or listener is created.
#[derive(Debug)]
pub enum Error {
    /// Exact typed configuration failure.
    Configuration(gnunet_config::Error),
    /// Caller finite storage/expansion limit refused the complete registry.
    Capacity,
    /// ARM service category switches are invalid or select neither category.
    Categories,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(e) => write!(f, "ARM configuration: {e}"),
            Self::Capacity => f.write_str("ARM registry capacity"),
            Self::Categories => f.write_str("ARM service categories are invalid or empty"),
        }
    }
}
impl std::error::Error for Error {}
impl From<gnunet_config::Error> for Error {
    fn from(e: gnunet_config::Error) -> Self {
        Self::Configuration(e)
    }
}
/// Source command forms differ in executable filename versus argv0 semantics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Recipe {
    /// Raw official textual command; later native port must use official parser.
    Gnunet(Vec<u8>),
    /// Source run_command_va(filename=prefix,argv0=binary,argv1=whole-options).
    Simple {
        /// Executable name, possibly empty (which later genuinely fails precheck).
        filename: OsString,
        /// First argument, independent from filename.
        argv0: OsString,
        /// Exactly one whole argument, even when it contains spaces.
        options: OsString,
    },
}
impl Recipe {
    /// Borrow the core's opaque source-plan bytes; full enum stays in the host.
    pub fn core_bytes(&self) -> &[u8] {
        match self {
            Self::Gnunet(command) => command,
            Self::Simple { filename, .. } => filename.as_bytes(),
        }
    }
}
/// One complete registered service, in official running-list order.
#[derive(Clone, Debug)]
pub struct Service {
    /// Original section spelling; an empty official section is retained.
    pub name: Vec<u8>,
    /// Original configured BINARY bytes, as shown by LIST.
    pub binary: Vec<u8>,
    /// Service CONFIG/default filename only if actual stat succeeded.
    pub configuration: Option<PathBuf>,
    /// Initial source force_start.
    pub immediate: bool,
    /// Source branch chooses creation of managed listeners.
    pub bind: bool,
    /// Exactly YES enables the native signal pipe.
    pub pipe_control: bool,
    /// Actual source-native command plan, never a claim of execution.
    pub recipe: Recipe,
}
/// Nonfatal source diagnostics retained independently from a successful registry.
#[derive(Clone, Debug)]
pub struct Diagnostic {
    /// Original service name.
    pub service: Vec<u8>,
    /// Actual failed stat filename; source then omits -c.
    pub config_path: PathBuf,
    /// OS error category, without secret configuration values.
    pub error: std::io::ErrorKind,
}
/// Owned registry; SourceSpec views borrow it without self-reference or cloning keys.
#[derive(Debug)]
pub struct Registry {
    services: Vec<Service>,
    diagnostics: Vec<Diagnostic>,
}
fn yes(config: &Configuration, section: &[u8], key: &[u8]) -> bool {
    matches!(config.get_yesno(section, key), Ok(true))
}
fn category(config: &Configuration, key: &[u8]) -> Result<Option<bool>, Error> {
    if !config.have_value(b"arm", key) {
        return Ok(None);
    }
    config
        .get_yesno(b"arm", key)
        .map(Some)
        .map_err(|_| Error::Categories)
}
fn expanded(
    config: &Configuration,
    section: &[u8],
    key: &[u8],
    env: &impl Environment,
) -> Result<Vec<u8>, Error> {
    config.get(section, key).map_or(Ok(Vec::new()), |v| {
        config.expand_dollar(v, env).map_err(Error::from)
    })
}
fn join(out: &mut Vec<u8>, part: &[u8], limit: usize) -> Result<(), Error> {
    if out.len().checked_add(part.len()).is_none_or(|n| n > limit) {
        return Err(Error::Capacity);
    }
    out.try_reserve(part.len()).map_err(|_| Error::Capacity)?;
    out.extend_from_slice(part);
    Ok(())
}
fn replace_name(mut text: Vec<u8>, name: &[u8], limits: Limits) -> Result<Vec<u8>, Error> {
    for _ in 0..limits.substitutions {
        let Some(at) = text.windows(2).position(|v| v == b"{}") else {
            return Ok(text);
        };
        let mut next = Vec::new();
        join(&mut next, &text[..at], limits.command_bytes)?;
        join(&mut next, name, limits.command_bytes)?;
        join(&mut next, &text[at + 2..], limits.command_bytes)?;
        text = next;
    }
    if text.windows(2).any(|v| v == b"{}") {
        Err(Error::Capacity)
    } else {
        Ok(text)
    }
}
impl Registry {
    /// Snapshot exact service selection and source command composition, without I/O
    /// beyond source stat/project discovery. Caller environment is read-only.
    pub fn from_config(
        config: &Configuration,
        env: &impl Environment,
        project: &ProjectData,
        cache: &mut BinaryPathCache,
        limits: Limits,
    ) -> Result<Self, Error> {
        let (system, user) = match (
            category(config, b"START_SYSTEM_SERVICES")?,
            category(config, b"START_USER_SERVICES")?,
        ) {
            (None, None) => (true, true),
            (a, b) => (a == Some(true), b == Some(true)),
        };
        if !system && !user {
            return Err(Error::Categories);
        }
        let prefix = expanded(config, b"arm", b"GLOBAL_PREFIX", env)?;
        let postfix = expanded(config, b"arm", b"GLOBAL_POSTFIX", env)?;
        let mut services = Vec::new();
        let mut diagnostics = Vec::new();
        let sections = config.sections().collect::<Vec<_>>();
        for section in sections {
            let name = section.name();
            if name.eq_ignore_ascii_case(b"arm") {
                continue;
            }
            let Some(binary) = config.get(name, b"BINARY") else {
                continue;
            };
            if if yes(config, name, b"RUN_PER_USER") {
                !user
            } else {
                !system
            } {
                continue;
            }
            if services.len() == limits.services {
                return Err(Error::Capacity);
            }
            let configuration = match config.get_filename(name, b"CONFIG", env) {
                Ok(path) => Some(path),
                Err(
                    gnunet_config::Error::Capacity
                    | gnunet_config::Error::Cycle
                    | gnunet_config::Error::Overflow,
                ) => return Err(Error::Capacity),
                Err(_) => match config.get_filename(b"PATHS", b"DEFAULTCONFIG", env) {
                    Ok(path) => Some(path),
                    Err(
                        gnunet_config::Error::Capacity
                        | gnunet_config::Error::Cycle
                        | gnunet_config::Error::Overflow,
                    ) => return Err(Error::Capacity),
                    Err(_) => None,
                },
            };
            let configuration = if let Some(path) = configuration {
                match fs::metadata(&path) {
                    Ok(_) => Some(path),
                    Err(error) => {
                        diagnostics.push(Diagnostic {
                            service: name.to_vec(),
                            config_path: path,
                            error: error.kind(),
                        });
                        None
                    }
                }
            } else {
                None
            };
            let local_prefix = if config.have_value(name, b"PREFIX") {
                expanded(config, name, b"PREFIX", env)?
            } else {
                prefix.clone()
            };
            let mut options = replace_name(postfix.clone(), name, limits)?;
            if config.have_value(name, b"OPTIONS") {
                join(&mut options, b" ", limits.command_bytes)?;
                join(
                    &mut options,
                    &expanded(config, name, b"OPTIONS", env)?,
                    limits.command_bytes,
                )?;
            }
            let options = config.expand_dollar(&options, env)?;
            if options.len() > limits.command_bytes {
                return Err(Error::Capacity);
            }
            let simple = config
                .get_choice(name, b"TYPE", &[b"GNUNET", b"SIMPLE"])
                .is_ok_and(|v| v == b"SIMPLE");
            let recipe = if simple {
                let executable = config.expand_dollar(binary, env)?;
                Recipe::Simple {
                    filename: OsString::from_vec(local_prefix),
                    argv0: OsString::from_vec(executable),
                    options: OsString::from_vec(options),
                }
            } else {
                let path = project.libexec_binary_path_with(binary, env, cache)?;
                let mut command = Vec::new();
                join(&mut command, &local_prefix, limits.command_bytes)?;
                if !local_prefix.is_empty() {
                    join(&mut command, b" ", limits.command_bytes)?;
                }
                join(
                    &mut command,
                    path.as_os_str().as_bytes(),
                    limits.command_bytes,
                )?;
                let debug = match config.get_yesno(name, b"DEBUG") {
                    Ok(v) => v,
                    Err(gnunet_config::Error::Missing) => false,
                    Err(_) => true,
                };
                if debug {
                    join(&mut command, b" -L DEBUG", limits.command_bytes)?;
                }
                if let Some(path) = &configuration {
                    join(&mut command, b" -c ", limits.command_bytes)?;
                    join(
                        &mut command,
                        path.as_os_str().as_bytes(),
                        limits.command_bytes,
                    )?;
                }
                if !options.is_empty() {
                    join(&mut command, b" ", limits.command_bytes)?;
                    join(&mut command, &options, limits.command_bytes)?;
                }
                Recipe::Gnunet(command)
            };
            let immediate = yes(config, name, b"IMMEDIATE_START");
            let bind = if immediate {
                !yes(config, name, b"NOARMBIND")
            } else {
                yes(config, name, b"START_ON_DEMAND")
            };
            services.try_reserve(1).map_err(|_| Error::Capacity)?;
            services.push(Service {
                name: name.to_vec(),
                binary: binary.to_vec(),
                configuration,
                immediate,
                bind,
                pipe_control: yes(config, name, b"PIPECONTROL"),
                recipe,
            });
        }
        services.reverse();
        Ok(Self {
            services,
            diagnostics,
        })
    }
    /// Registered order, already reflecting C head insertion.
    pub fn services(&self) -> &[Service] {
        &self.services
    }
    /// Nonfatal actual stat failures, which do not remove service entries.
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }
    /// Borrow source-shaped immutable core specs. Hold this vector and registry
    /// independently for the pure owner's lifetime; no unsafe self-reference.
    pub fn specs(&self) -> Vec<ServiceSpec<'_>> {
        self.services
            .iter()
            .map(|s| ServiceSpec {
                name: &s.name,
                binary: &s.binary,
                command: s.recipe.core_bytes(),
                immediate: s.immediate,
                pipe_control: s.pipe_control,
            })
            .collect()
    }
}
