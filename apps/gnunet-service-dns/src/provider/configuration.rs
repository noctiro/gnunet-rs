//! Explicit bundle defaults and configuration, shared by provider and control.
use crate::Failure;
use gnunet_config::{Configuration, Installation, ProjectData};
use std::{path::Path, sync::Arc};

pub(crate) fn load(
    filename: &Path,
    resources: &Path,
    binaries: &Path,
) -> Result<Configuration, Failure> {
    let project = Arc::new(ProjectData::default());
    let installation = Installation::from_locations(&project, resources, Some(binaries))?;
    let mut config = Configuration::with_installation(project, installation, Default::default())?;
    config.load_explicit(
        Some(&resources.join("share/gnunet/config.d")),
        Some(filename),
    )?;
    if gnunet_service_startup::configured_user(&config, b"dns")?.is_some() {
        return Err("the operating system supplies DNS provider identity; dns.USER is unsupported in this provider profile".into());
    }
    Ok(config)
}
