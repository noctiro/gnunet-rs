use crate::Failure;
use gnunet_config::Configuration;
use gnunet_fs::directory;
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Target},
};
use std::{ffi::OsString, os::unix::ffi::OsStringExt, path::PathBuf, time::Duration};

pub(super) struct Arguments {
    timeout: Target<u64>,
}
impl Arguments {
    pub fn new() -> Self {
        Self {
            timeout: Target::new(0),
        }
    }
    pub fn options(&self) -> Options<'static> {
        let mut o = Options::new();
        o.add(helpers::relative_time(
            0,
            b"timeout",
            b"DURATION",
            b"Optional fixed whole operation timeout; zero/FOREVER is unbounded",
            self.timeout.clone(),
        ));
        o
    }
    pub fn select(&self, config: &Configuration, args: &[Vec<u8>]) -> Result<Settings, Failure> {
        if args.is_empty() {
            return Err("specify at least one local GNUnet directory file".into());
        }
        let mut files = Vec::new();
        files.try_reserve_exact(args.len())?;
        for name in args {
            if name.is_empty() || name.contains(&0) {
                return Err("invalid directory input filename".into());
            }
            files.push(PathBuf::from(OsString::from_vec(name.clone())));
        }
        let number = |key: &[u8], default: usize| -> Result<usize, Failure> {
            let value = config
                .get(b"directory-rust", key)
                .map(|_| config.get_number(b"directory-rust", key))
                .transpose()?
                .unwrap_or(u64::try_from(default)?);
            Ok(usize::try_from(value)?)
        };
        // The streamed file itself and total entry count do not require memory
        // proportional to their extent. Only each original record is retained.
        let mut limits = directory::Limits {
            max_extent: u64::MAX,
            max_entries: usize::MAX,
            max_work: u64::MAX,
            ..directory::Limits::default()
        };
        limits.max_record_bytes = number(b"RECORD_BYTES", limits.max_record_bytes)?;
        limits.metadata.max_coded_bytes =
            number(b"CODED_METADATA_BYTES", limits.metadata.max_coded_bytes)?;
        limits.metadata.max_plain_bytes =
            number(b"PLAIN_METADATA_BYTES", limits.metadata.max_plain_bytes)?;
        limits.metadata.max_entries = number(b"METADATA_ITEMS", limits.metadata.max_entries)?;
        limits.uri.max_input_bytes = number(b"URI_BYTES", limits.uri.max_input_bytes)?;
        limits.uri.max_identifier_bytes = limits.uri.max_input_bytes;
        if limits.max_record_bytes < 12
            || limits.metadata.max_coded_bytes < 12
            || limits.metadata.max_plain_bytes == 0
            || limits.metadata.max_entries == 0
            || limits.uri.max_input_bytes == 0
        {
            return Err("invalid directory-rust record/metadata/URI resource profile".into());
        }
        for value in [
            limits.metadata.max_coded_bytes,
            limits.metadata.max_plain_bytes,
            limits.metadata.max_entries,
        ] {
            u32::try_from(value)
                .map_err(|_| "metadata resource bound exceeds its u32 representation")?;
        }
        let timeout = self.timeout.get()?;
        let timeout = if timeout == 0 {
            config
                .get(b"directory-rust", b"TOTAL_TIMEOUT")
                .map(|_| config.get_time(b"directory-rust", b"TOTAL_TIMEOUT"))
                .transpose()?
                .unwrap_or(0)
        } else {
            timeout
        };
        let lifetime =
            (timeout != 0 && timeout != u64::MAX).then_some(Duration::from_micros(timeout));
        Ok(Settings {
            files,
            limits,
            lifetime,
        })
    }
}
pub(super) struct Settings {
    pub files: Vec<PathBuf>,
    pub limits: directory::Limits,
    pub lifetime: Option<Duration>,
}
