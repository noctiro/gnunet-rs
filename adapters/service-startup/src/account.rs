//! Shared official configuration selection; OS account identity stays native.
use gnunet_config::{Configuration, ProcessEnvironment};
use std::ffi::OsString;

/// Preserve USERNAME's original filename/dollar expansion. Missing means keep
/// identity; invalid present configuration is an explicit fail-closed error.
pub fn configured_user(
    config: &Configuration,
    section: &[u8],
) -> Result<Option<OsString>, gnunet_config::Error> {
    config
        .get(section, b"USERNAME")
        .map(|_| {
            config
                .get_filename(section, b"USERNAME", &ProcessEnvironment)
                .map(|p| p.into_os_string())
        })
        .transpose()
}
