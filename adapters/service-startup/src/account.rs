//! Shared official configuration selection; OS account identity stays native.
use gnunet_config::{Configuration, Environment, ProcessEnvironment};
use std::ffi::OsString;

/// Read the platform account name. Missing means keep the current identity.
pub fn configured_user(
    config: &Configuration,
    section: &[u8],
) -> Result<Option<OsString>, gnunet_config::Error> {
    configured_user_with(config, section, &ProcessEnvironment)
}

/// Read the platform account name using the caller's configuration environment.
pub fn configured_user_with(
    config: &Configuration,
    section: &[u8],
    environment: &impl Environment,
) -> Result<Option<OsString>, gnunet_config::Error> {
    let Some(value) = config.get(section, b"USERNAME") else {
        return Ok(None);
    };
    #[cfg(windows)]
    {
        let name = config.expand_dollar(value, environment)?;
        if name.is_empty() || name.contains(&0) {
            return Err(gnunet_config::Error::InvalidValue);
        }
        gnunet_native::os_bytes::decode_owned(name)
            .map(Some)
            .map_err(|_| gnunet_config::Error::InvalidValue)
    }
    #[cfg(not(windows))]
    {
        let _ = value;
        config
            .get_filename(section, b"USERNAME", environment)
            .map(|path| Some(path.into_os_string()))
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn windows_account_names_are_not_paths() {
        let mut config = Configuration::new(gnunet_config::Limits::default());
        for name in [r"WORKSTATION\service", r".\service", "service@domain.test"] {
            assert!(
                config
                    .set_value(b"service", b"USERNAME", Some(name.as_bytes()))
                    .is_ok()
            );
            assert_eq!(
                configured_user(&config, b"service")
                    .ok()
                    .flatten()
                    .as_deref(),
                Some(OsStr::new(name))
            );
        }
    }
}
