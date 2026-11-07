//! Own snapshot or explicit caller-shared configuration across MQ reconnects.
use gnunet_client_host::{ConnectError as IpcError, Endpoint, LiveConfiguration};
use gnunet_config::Configuration;
use std::path::PathBuf;
pub(crate) enum Source {
    Unix(PathBuf),
    Live {
        config: LiveConfiguration,
        resolution: gnunet_client_host::resolution::SharedResolution,
        service: &'static [u8],
    },
    Configuration {
        config: Box<Configuration>,
        resolution: gnunet_client_host::resolution::SharedResolution,
        service: &'static [u8],
    },
}
impl Source {
    pub(crate) fn launch_configuration(&self) -> Result<Option<Configuration>, IpcError> {
        match self {
            Self::Live { config, .. } => config.snapshot().map(Some),
            _ => Ok(None),
        }
    }
    pub fn resolve(&self) -> Result<Endpoint, IpcError> {
        match self {
            Self::Unix(path) => Endpoint::unix(path.clone()),
            Self::Live {
                config,
                resolution,
                service,
            } => Endpoint::configuration_live(config.clone(), service, resolution.clone()),
            Self::Configuration {
                config,
                service,
                resolution,
            } => Endpoint::configuration(config.duplicate()?, service, resolution.clone()),
        }
    }
}
