//! Explicit caller-owned live configuration, separate from connection authority.
use crate::ConnectError;
use gnunet_config::Configuration;
use std::{
    io,
    sync::{Arc, Mutex},
};
/// A shared configuration object corresponding to a caller-retained native cfg.
/// Replacing it performs no I/O, wake, reconnect, cancellation or callback. Each
/// documented service effect samples it independently; active attempts and
/// streams keep the parameters they already sampled. Locks never cross await.
#[derive(Clone)]
pub struct LiveConfiguration(Arc<Mutex<Configuration>>);
impl LiveConfiguration {
    pub(crate) fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    /// Own a configuration and expose explicitly shared read/update authority.
    pub fn new(configuration: Configuration) -> Self {
        Self(Arc::new(Mutex::new(configuration)))
    }
    /// Copy one coherent current configuration without opening any socket.
    pub fn snapshot(&self) -> Result<Configuration, ConnectError> {
        let configuration = self
            .0
            .lock()
            .map_err(|_| io::Error::other("live configuration lock poisoned"))?;
        Ok(configuration.duplicate()?)
    }
    /// Replace the configuration as one synchronous action. This does not change
    /// cached MQ fields or wake a pending drive/connection future by itself.
    pub fn replace(&self, configuration: Configuration) -> Result<(), ConnectError> {
        let mut current = self
            .0
            .lock()
            .map_err(|_| io::Error::other("live configuration lock poisoned"))?;
        *current = configuration;
        Ok(())
    }
}
