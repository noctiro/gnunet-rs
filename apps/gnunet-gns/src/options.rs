//! Standard public GNS lookup options; no DNS fallback is implied by --dns.
use crate::Cause;
use gnunet_gnsrecord_text::{RecordType, typename_to_number};
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Target},
    reporting::Reporter,
};
use std::{error::Error, fmt};

pub(super) struct Settings {
    pub name: Vec<u8>,
    pub record_type: RecordType,
    pub type_name: Vec<u8>,
    pub timeout: u64,
    pub raw: bool,
    pub maximum_output_bytes: usize,
}
pub(super) struct Selection {
    lookup: Target<Option<Vec<u8>>>,
    kind: Target<Option<Vec<u8>>>,
    timeout: Target<u64>,
    raw: Target<i32>,
    dns: Target<i32>,
}
#[derive(Debug)]
pub(super) enum NameFailure {
    Dns(gnunet_types::Error),
    Idna(gnunet_idna::Error),
}
impl NameFailure {
    pub(super) fn code(&self) -> u8 {
        match self {
            Self::Dns(_) => 3,
            Self::Idna(_) => 4,
        }
    }
}
impl fmt::Display for NameFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(error) => write!(f, "DNS compatibility name check: {error}"),
            Self::Idna(error) => write!(f, "DNS compatibility IDNA conversion: {error:?}"),
        }
    }
}
impl Error for NameFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Dns(error) => Some(error),
            Self::Idna(_) => None,
        }
    }
}
impl Selection {
    pub(super) fn new() -> Self {
        Self {
            lookup: Target::new(None),
            kind: Target::new(None),
            timeout: Target::new(u64::MAX),
            raw: Target::new(0),
            dns: Target::new(0),
        }
    }
    pub(super) fn options(&self) -> Options<'static> {
        let mut options = Options::new();
        options.add(helpers::string(
            b'u',
            b"lookup",
            b"NAME",
            b"Lookup a record for the given name",
            self.lookup.clone(),
        ));
        options.add(helpers::string(
            b't',
            b"type",
            b"TYPE",
            b"Specify the record type (default A)",
            self.kind.clone(),
        ));
        options.add(helpers::relative_time(
            b'T',
            b"timeout",
            b"TIMEOUT",
            b"Original total lookup timeout (default forever)",
            self.timeout.clone(),
        ));
        options.add(helpers::flag(
            b'r',
            b"raw",
            b"Print only formatted record values",
            self.raw.clone(),
        ));
        options.add(helpers::flag(
            b'd',
            b"dns",
            b"Validate DNS format and convert IDNA name to UTF-8",
            self.dns.clone(),
        ));
        options
    }
    pub(super) fn finish(
        self,
        config: &gnunet_config::Configuration,
        args: &[Vec<u8>],
        reporter: &Reporter,
    ) -> Result<Settings, Cause> {
        if !args.is_empty() {
            return Err("gnunet-gns accepts -u/--lookup NAME and no positional arguments".into());
        }
        let mut name = self.lookup.get()?.ok_or("-u/--lookup NAME is required")?;
        if let Some(colon) = name.iter().position(|b| *b == b':') {
            name.truncate(colon);
        }
        if name.is_empty() || name.len() > 1024 || name.contains(&0) {
            return Err("empty, oversized or NUL-containing lookup name".into());
        }
        if self.dns.get()? != 0 {
            let mut scratch = gnunet_idna::Workspace::new();
            let mut work = [0u8; 1020];
            {
                let idna = gnunet_idna::Backend::new(
                    &mut scratch,
                    gnunet_idna::Limits::GNUNET,
                    gnunet_idna::NativeProfile::Libunistring1_5Unicode18_0,
                );
                gnunet_dns::check_name(&name, &idna, &mut work, gnunet_dns::Limits::DNS)
                    .map_err(NameFailure::Dns)?;
            }
            let n = gnunet_idna::to_unicode(
                &name,
                &mut work,
                &mut scratch,
                gnunet_idna::Limits::GNUNET,
            )
            .map_err(NameFailure::Idna)?;
            name.clear();
            name.extend_from_slice(&work[..n]);
        }
        let type_name = self.kind.get()?.unwrap_or_else(|| b"A".to_vec());
        if type_name.len() > 64 || type_name.contains(&0) {
            return Err("oversized or NUL-containing typename".into());
        }
        let kind = std::str::from_utf8(&type_name)
            .ok()
            .and_then(typename_to_number);
        let record_type = kind.unwrap_or_else(|| {
            reporter.warning(
                "gns.type.unknown",
                format_args!("Invalid typename specified, assuming ANY"),
            );
            RecordType::ANY
        });
        let maximum_output_bytes = match config.get(b"gns-cli", b"MAX_OUTPUT_BYTES") {
            None => 16 * 1024 * 1024,
            Some(value) => {
                let value = std::str::from_utf8(value)?.parse::<usize>()?;
                if !(1..=64 * 1024 * 1024).contains(&value) {
                    return Err("out of range [gns-cli] MAX_OUTPUT_BYTES".into());
                }
                value
            }
        };
        Ok(Settings {
            name,
            record_type,
            type_name,
            timeout: self.timeout.get()?,
            raw: self.raw.get()? != 0,
            maximum_output_bytes,
        })
    }
}
