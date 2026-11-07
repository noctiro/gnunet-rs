//! Official GNUnet host configuration semantics, pinned to v0.29.1.
//!
//! This host adapter preserves opaque byte names/values, official list order,
//! parsing, includes and typed value conventions. It has no private node format.
#![forbid(unsafe_code)]

mod accounts;
mod command;
mod configuration;
pub mod diagnostic;
mod expansion;
mod glob;
mod project;
mod tool;
mod values;

pub use accounts::{NativeNss, NssResolver};
pub use command::{
    ConfigCommandLogging, ConfigCommandPreparation, PreparedConfigCommand,
    prepare_config_command_with_program, run_config_command, run_config_command_with_program,
};
pub use configuration::{
    CleanRemoval, Configuration, Definition, DirectoryLoad, Dirty, Entry, FileSource, Limits,
    Section,
};
pub use expansion::{Environment, ProcessEnvironment};
pub use gnunet_native::locale::{CaseContext, CaseSnapshot, LocaleSnapshot, ThreadLocale};
pub use project::{
    BinaryPathCache, BuildProfile, Installation, InstallationOrigin, OFFICIAL_BUILD_PROFILE,
    PathKind, ProjectData, UTIL_VERSION, default_filename,
};
pub use tool::{ConfigSettings, ToolOutput, ToolReport};
pub use values::{parse_number, parse_relative_time, parse_relative_time_checked, parse_size};

use std::{fmt, io, path::PathBuf};

/// A classified configuration failure. Secret values are never in diagnostics.
#[derive(Debug)]
pub enum Error {
    /// I/O failed for the named source or target.
    Io {
        /// Path involved in the failure.
        path: PathBuf,
        /// Original OS failure.
        error: io::Error,
    },
    /// A source line does not follow the pinned configuration grammar.
    Syntax {
        /// Source file, if supplied.
        source: Option<PathBuf>,
        /// One-based physical line.
        line: usize,
    },
    /// A finite caller-selected resource bound was exceeded.
    Capacity,
    /// Input contains a NUL or otherwise cannot represent a C configuration value.
    InvalidInput,
    /// A required setting is absent or was removed.
    Missing,
    /// A value is present but not a valid value of the requested type.
    InvalidValue,
    /// Numeric input cannot be represented by the requested type.
    Overflow,
    /// Include ancestry or dollar references are recursive.
    Cycle,
    /// A selected host capability or OS representation is unsupported.
    Unsupported,
    /// An expected source changed before a conditional rewrite.
    Changed,
    /// A filename iterator's callback stopped the traversal.
    IterationAborted,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, error } => {
                write!(f, "configuration I/O at {}: {error}", path.display())
            }
            Self::Syntax { source, line } => write!(
                f,
                "configuration syntax at {}:{line}",
                source
                    .as_ref()
                    .map_or_else(|| "<input>".into(), |p| p.display().to_string())
            ),
            Self::Capacity => f.write_str("configuration capacity exhausted"),
            Self::InvalidInput => f.write_str("invalid configuration input"),
            Self::Missing => f.write_str("configuration value is absent"),
            Self::InvalidValue => f.write_str("invalid typed configuration value"),
            Self::Overflow => f.write_str("configuration numeric overflow"),
            Self::Cycle => f.write_str("recursive configuration input"),
            Self::Unsupported => f.write_str("configuration host capability is unsupported"),
            Self::Changed => f.write_str("configuration source changed"),
            Self::IterationAborted => f.write_str("configuration filename traversal aborted"),
        }
    }
}
impl std::error::Error for Error {}

pub(crate) fn io_error(path: impl Into<PathBuf>, error: io::Error) -> Error {
    Error::Io {
        path: path.into(),
        error,
    }
}

#[cfg(unix)]
pub(crate) fn path_bytes(path: &std::path::Path) -> Result<&[u8], Error> {
    use std::os::unix::ffi::OsStrExt;
    Ok(path.as_os_str().as_bytes())
}
#[cfg(not(unix))]
pub(crate) fn path_bytes(path: &std::path::Path) -> Result<&[u8], Error> {
    path.to_str().map(str::as_bytes).ok_or(Error::Unsupported)
}
pub(crate) fn bytes_path(bytes: &[u8]) -> Result<PathBuf, Error> {
    if bytes.contains(&0) {
        return Err(Error::InvalidInput);
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(std::ffi::OsStr::from_bytes(bytes).into())
    }
    #[cfg(not(unix))]
    {
        Ok(std::str::from_utf8(bytes)
            .map_err(|_| Error::Unsupported)?
            .into())
    }
}
