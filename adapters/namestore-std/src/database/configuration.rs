//! The shared service and offline database selection.
use crate::{backend, snapshot};
use gnunet_config::{Configuration, ProcessEnvironment};
use gnunet_namestore::Limits;
use gnunet_types::Error;
use std::path::PathBuf;

const SECTION: &[u8] = b"namestore-rust";
type Failure = Box<dyn std::error::Error>;

/// Validated storage path, inventory limits and on-disk body bound.
pub struct Options {
    pub(super) directory: PathBuf,
    pub(super) limits: Limits,
    pub(super) backend: backend::Limits,
}

impl Options {
    /// Bind the storage bounds to an absolute native path.
    pub fn new(directory: PathBuf, limits: Limits, body_bytes: usize) -> Result<Self, Error> {
        limits.validate()?;
        if !directory.is_absolute() {
            return Err(Error::InvalidInput);
        }
        if limits.rows > 16384
            || limits.retained_bytes > 256 * 1024 * 1024
            || body_bytes < limits.image_bytes.max(snapshot::EMPTY_BYTES)
            || body_bytes > 64 * 1024 * 1024
        {
            return Err(Error::Capacity);
        }
        Ok(Self {
            directory,
            limits,
            backend: backend::Limits { body_bytes },
        })
    }

    /// Read the same storage profile for the offline tool and the live service.
    pub fn read(config: &Configuration) -> Result<Self, Failure> {
        let directory = if config.get(SECTION, b"DIRECTORY").is_some() {
            config.get_filename(SECTION, b"DIRECTORY", &ProcessEnvironment)?
        } else {
            let raw = b"${GNUNET_DATA_HOME}/namestore-rust-v1";
            let expanded = config.expand_dollar(raw, &ProcessEnvironment)?;
            if expanded == raw {
                return Err("set [namestore-rust] DIRECTORY or GNUNET_DATA_HOME".into());
            }
            config.expand_filename(&expanded, &ProcessEnvironment)?
        };
        let d = Limits::default();
        let limits = Limits {
            rows: value(config, b"MAX_LABELS", d.rows, Configuration::get_number)?,
            zones: value(config, b"MAX_ZONES", d.zones, Configuration::get_number)?,
            label_bytes: size(config, b"LABEL_BYTES", d.label_bytes)?,
            label_input_bytes: size(config, b"LABEL_INPUT_BYTES", d.label_input_bytes)?,
            hint_bytes: size(config, b"HINT_BYTES", d.hint_bytes)?,
            records_per_set: value(
                config,
                b"RECORDS_PER_SET",
                d.records_per_set,
                Configuration::get_number,
            )?,
            record_bytes: size(config, b"RECORD_BYTES", d.record_bytes)?,
            batch: value(config, b"BATCH_SETS", d.batch, Configuration::get_number)?,
            image_bytes: size(config, b"IMAGE_BYTES", d.image_bytes)?,
            retained_bytes: size(config, b"RETAINED_BYTES", d.retained_bytes)?,
        };
        let body_bytes = size(config, b"STORE_BODY_BYTES", snapshot::DEFAULT_BODY_BYTES)?;
        Ok(Self::new(directory, limits, body_bytes)?)
    }

    /// Maximum canonical body for the service's snapshot encoder.
    #[must_use]
    pub const fn body_bytes(&self) -> usize {
        self.backend.body_bytes
    }
}

fn size(config: &Configuration, key: &[u8], default: usize) -> Result<usize, Failure> {
    value(config, key, default, Configuration::get_size)
}

fn value(
    config: &Configuration,
    key: &[u8],
    default: usize,
    read: impl FnOnce(&Configuration, &[u8], &[u8]) -> Result<u64, gnunet_config::Error>,
) -> Result<usize, Failure> {
    if config.get(SECTION, key).is_some() {
        Ok(usize::try_from(read(config, SECTION, key)?)?)
    } else {
        Ok(default)
    }
}
