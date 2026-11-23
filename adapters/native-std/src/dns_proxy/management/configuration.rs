//! Bounded preference values and explicit ownership policy.
use std::{
    io,
    path::{Path, PathBuf},
};

/// Validated provider identity and absolute GNUnet configuration path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Configuration {
    pub(super) identifier: String,
    pub(super) file: PathBuf,
}
impl Configuration {
    /// Validates strings without opening files or changing system preferences.
    pub fn new(provider_bundle_id: &str, configuration_file: &Path) -> io::Result<Self> {
        identifier(provider_bundle_id)?;
        path(configuration_file)?;
        Ok(Self {
            identifier: provider_bundle_id.to_owned(),
            file: configuration_file.to_owned(),
        })
    }
    /// Validated target system-extension bundle identifier.
    pub fn provider_bundle_identifier(&self) -> &str {
        &self.identifier
    }
    /// Validated absolute GNUnet configuration path.
    pub fn configuration_file(&self) -> &Path {
        &self.file
    }
}

/// Persisted enablement requested by an explicit apply operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Saving enables this proxy and can disable other applications' proxies.
    Enabled,
    /// Saves this configuration without enabling its proxy.
    Disabled,
}

/// Original asynchronous preference operation that completed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    /// Loads the caller's current preferences.
    Load,
    /// Saves the supplied provider configuration.
    Apply,
    /// Disables the original loaded configuration without replacing its protocol.
    Disable,
    /// Removes the original loaded configuration.
    Remove,
}

/// Observed preference values, independent of provider running state or health.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub(super) present: bool,
    pub(super) enabled: bool,
    pub(super) identifier: Option<String>,
    pub(super) file: Option<PathBuf>,
    pub(super) file_error: Option<String>,
}
impl Snapshot {
    /// Whether the loaded manager contains a provider protocol configuration.
    pub fn has_configuration(&self) -> bool {
        self.present
    }
    /// Configured enablement; this is not evidence of provider readiness.
    pub fn enabled(&self) -> bool {
        self.enabled
    }
    /// Original configured extension identifier, when present.
    pub fn provider_bundle_identifier(&self) -> Option<&str> {
        self.identifier.as_deref()
    }
    /// Original configured absolute GNUnet file path, when present.
    pub fn configuration_file(&self) -> Option<&Path> {
        self.file.as_deref()
    }
    /// Invalid vendor path observation; ownership and explicit recovery remain available.
    pub fn configuration_error(&self) -> Option<&str> {
        self.file_error.as_deref()
    }

    pub(super) fn owned(&self, expected: &str, create: bool) -> io::Result<()> {
        if !self.present {
            return if create {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "DNS proxy configuration is absent",
                ))
            };
        }
        if self.identifier.as_deref() != Some(expected) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "DNS proxy configuration belongs to another provider",
            ));
        }
        Ok(())
    }
}

pub(super) fn identifier(value: &str) -> io::Result<()> {
    if value.len() > 255
        || !value.contains('.')
        || value.split('.').any(|part| {
            part.is_empty() || !part.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "provider bundle identifier is not a bounded reverse-DNS identifier",
        ));
    }
    Ok(())
}
pub(super) fn path(value: &Path) -> io::Result<&str> {
    let text = value.to_str().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "GNUNET_CONFIG must be UTF-8")
    })?;
    if !value.is_absolute() || text.len() > 4096 || text.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "GNUNET_CONFIG must be a bounded absolute path",
        ));
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn foreign_or_missing_identity_cannot_be_mutated() {
        let mut snapshot = Snapshot {
            present: true,
            enabled: true,
            identifier: Some("org.other.proxy".into()),
            file: None,
            file_error: None,
        };
        assert!(
            matches!(snapshot.owned("org.gnunet.proxy", true), Err(error) if error.kind() == io::ErrorKind::PermissionDenied)
        );
        snapshot.identifier = None;
        assert!(snapshot.owned("org.gnunet.proxy", false).is_err());
        snapshot.identifier = Some("org.gnunet.proxy".into());
        snapshot.file_error = Some("loaded GNUNET_CONFIG is not a string".into());
        assert!(snapshot.configuration_file().is_none());
        assert!(snapshot.configuration_error().is_some());
        assert!(
            snapshot.owned("org.gnunet.proxy", false).is_ok(),
            "invalid vendor data must not prevent exact-owned recovery"
        );
        snapshot.present = false;
        assert!(snapshot.owned("org.gnunet.proxy", true).is_ok());
        assert!(
            matches!(snapshot.owned("org.gnunet.proxy", false), Err(error) if error.kind() == io::ErrorKind::NotFound)
        );
    }
    #[test]
    fn configuration_refuses_unbounded_or_relative_values() {
        for file in ["relative.conf", "/valid\0suffix"] {
            assert!(Configuration::new("org.gnunet.proxy", Path::new(file)).is_err());
        }
        assert!(Configuration::new("org..proxy", Path::new("/config")).is_err());
        assert!(
            Configuration::new(
                "org.gnunet.proxy",
                Path::new(&format!("/{}", "a".repeat(4096)))
            )
            .is_err()
        );
        assert!(Configuration::new("org.gnunet.proxy", Path::new("/config")).is_ok());
    }
}
