//! Configuration-only normal startup; parsing never opens a key or state file.
use gnunet_config::{Configuration, ProcessEnvironment};
use gnunet_tcp_communicator_runtime::startup::LocalKeyCapability;
use std::{error::Error, path::PathBuf};

pub(super) struct Settings {
    pub(super) directory: PathBuf,
    pub(super) key: LocalKeyCapability,
}
impl Settings {
    pub(super) fn parse(config: &Configuration) -> Result<Self, Box<dyn Error>> {
        let section = b"communicator-tcp-rust";
        match config.get(section, b"KEY_PROVIDER") {
            None | Some(b"existing-local") => {}
            Some(_) => {
                return Err(
                    "unsupported communicator-tcp-rust KEY_PROVIDER; expected existing-local"
                        .into(),
                );
            }
        }
        let directory = if config.get(section, b"STATE_DIRECTORY").is_some() {
            config.get_filename(section, b"STATE_DIRECTORY", &ProcessEnvironment)?
        } else {
            // Same actual PATHS/dollar expansion used by the TRANSPORT owner;
            // the final directory and frontier format are independently owned.
            let raw = b"$GNUNET_DATA_HOME/tcp-rust-state";
            let expanded = config.expand_dollar(raw, &ProcessEnvironment)?;
            if expanded == raw {
                return Err("set GNUNET_DATA_HOME or [communicator-tcp-rust] STATE_DIRECTORY to an independent Rust-owned directory".into());
            }
            config.expand_filename(&expanded, &ProcessEnvironment)?
        };
        if !directory.is_absolute() || directory.file_name().is_none() {
            return Err("STATE_DIRECTORY must name an absolute final Rust-owned directory".into());
        }
        // This resolves only configured path bytes. The existing provider is
        // called later under the target identity, after a real PILS identity.
        let ikm_file = config.get_filename(b"peer", b"PRIVATE_KEY", &ProcessEnvironment)?;
        if directory == ikm_file || directory.starts_with(&ikm_file) {
            return Err("Rust state directory must be separate from the peer key file".into());
        }
        Ok(Self {
            directory,
            key: LocalKeyCapability { ikm_file },
        })
    }
}
