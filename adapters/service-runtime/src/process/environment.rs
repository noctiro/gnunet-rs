//! Immutable Windows process environment and working directory.
use gnunet_native::process::{Environment, LaunchLimits};
use std::{
    ffi::{OsStr, OsString},
    io,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
};

/// Explicit native child context. Construction never changes global environment
/// or working directory; lookups retain native comparison errors.
#[derive(Clone, Debug)]
pub struct EnvironmentSnapshot {
    environment: Environment,
    cwd: PathBuf,
}
impl EnvironmentSnapshot {
    /// Capture this process using the default finite native environment profile.
    pub fn system() -> io::Result<Self> {
        Self::from_values(
            std::env::vars_os(),
            std::env::current_dir()?,
            LaunchLimits::default(),
        )
    }
    /// Retain an explicit environment/cwd under the caller's native bounds.
    pub fn from_values(
        values: impl IntoIterator<Item = (OsString, OsString)>,
        cwd: PathBuf,
        limits: LaunchLimits,
    ) -> io::Result<Self> {
        if !cwd.is_absolute() || cwd.as_os_str().encode_wide().any(|unit| unit == 0) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut owned = Vec::new();
        for value in values {
            if owned.len() == limits.environment_entries {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            owned
                .try_reserve(1)
                .map_err(|_| io::ErrorKind::OutOfMemory)?;
            owned.push(value);
        }
        Ok(Self {
            environment: Environment::new(owned, limits)?,
            cwd,
        })
    }
    /// Native lookup with last-input-wins ordinal name comparison.
    pub fn variable_os(&self, name: &OsStr) -> io::Result<Option<&OsStr>> {
        self.environment.value(name)
    }
    /// Original explicit working directory.
    pub fn current_dir(&self) -> &Path {
        &self.cwd
    }
    /// Resolve a path using this snapshot's cwd and explicit per-drive entries.
    /// This performs no filesystem access or ambient process-state lookup.
    pub fn absolute_path(&self, path: &Path) -> io::Result<PathBuf> {
        super::executable::absolute(path, self)
    }
    /// Original environment entries, without process-global lookup.
    pub fn values(&self) -> &[(OsString, OsString)] {
        self.environment.values()
    }
}
