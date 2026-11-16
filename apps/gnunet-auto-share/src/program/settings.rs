//! Finite resource policy; these keys do not introduce a wire protocol.
use super::Failure;
use gnunet_config::Configuration;
use gnunet_fs_host::{auto_share::Limits, extraction::MetadataSettings};
use std::time::Duration;
pub(super) struct Settings {
    pub limits: Limits,
    pub resolver: gnunet_resolver_broker::Limits,
    pub metadata: MetadataSettings,
}
const SECTION: &[u8] = b"auto-share-rust";
fn number(c: &Configuration, key: &[u8], default: usize) -> Result<usize, Failure> {
    Ok(c.get(SECTION, key)
        .map(|_| c.get_number(SECTION, key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}
fn duration(c: &Configuration, key: &[u8], default: Duration) -> Result<Duration, Failure> {
    let us = c
        .get(SECTION, key)
        .map(|_| c.get_time(SECTION, key))
        .transpose()?
        .unwrap_or(u64::try_from(default.as_micros())?);
    if us == 0 || us == u64::MAX {
        return Err("automatic sharing bounds must be finite and positive".into());
    }
    Ok(Duration::from_micros(us))
}
impl Settings {
    pub fn read(
        c: &Configuration,
        disabled: bool,
        extractors: Option<&[u8]>,
        library: Option<&[u8]>,
    ) -> Result<Self, Failure> {
        let configured = extractors.or_else(|| c.get(b"FS", b"EXTRACTORS"));
        let library = if disabled || configured == Some(b"-".as_slice()) {
            None
        } else {
            match library {
                Some(path) => {
                    if path.len() > 4096 || path.contains(&0) {
                        return Err(
                            "extractor library path exceeds4096 bytes or contains NUL".into()
                        );
                    }
                    Some(gnunet_program_host::program::native_path(path)?.into_owned())
                }
                None if c.get(b"fs-rust", b"EXTRACTOR_LIBRARY").is_some() => {
                    Some(c.get_path("fs-rust", "EXTRACTOR_LIBRARY")?)
                }
                None => None,
            }
        };
        // Admit the explicit native-code selection without loading it. Provider
        // ownership starts on the file worker after PROGRAM/privilege admission.
        let metadata = authorize_selected(MetadataSettings::new(disabled, configured, library)?)?;
        let mut l = Limits::default();
        l.entries = number(c, b"ENTRIES", l.entries)?;
        l.versions = number(c, b"VERSIONS", l.versions)?;
        l.failures = number(c, b"FAILURES", l.failures)?;
        l.scan.objects = u64::try_from(number(
            c,
            b"SCAN_OBJECTS",
            usize::try_from(l.scan.objects)?,
        )?)?;
        l.scan.children = number(c, b"SCAN_CHILDREN", l.scan.children)?;
        l.scan.depth = number(c, b"SCAN_DEPTH", l.scan.depth)?;
        l.scan.name_bytes = number(c, b"NAME_BYTES", l.scan.name_bytes)?;
        l.scan.names_bytes = number(c, b"SCAN_NAME_BYTES", l.scan.names_bytes)?;
        l.stability = duration(c, b"STABILITY", l.stability)?;
        l.minimum_scan = duration(c, b"MIN_SCAN", l.minimum_scan)?;
        l.maximum_scan = duration(c, b"MAX_SCAN", l.maximum_scan)?;
        l.retry = duration(c, b"RETRY", l.retry)?;
        l.operation = duration(c, b"OPERATION_TIMEOUT", l.operation)?;
        l.lifetime = duration(c, b"SOURCE_LIFETIME", l.lifetime)?;
        l.retained_bytes = u64::try_from(number(
            c,
            b"RETAINED_BYTES",
            usize::try_from(l.retained_bytes)?,
        )?)?;
        l.version_reservation = u64::try_from(number(
            c,
            b"VERSION_RESERVATION",
            usize::try_from(l.version_reservation)?,
        )?)?;
        l.preparation.metadata.max_probe_bytes = number(
            c,
            b"EXTRACT_PROBE_BYTES",
            l.preparation.metadata.max_probe_bytes,
        )?;
        l.preparation.metadata.max_metadata_items = number(
            c,
            b"METADATA_ITEMS",
            l.preparation.metadata.max_metadata_items,
        )?;
        l.preparation.metadata.max_metadata_bytes = number(
            c,
            b"METADATA_BYTES",
            l.preparation.metadata.max_metadata_bytes,
        )?;
        l.preparation.metadata.max_keywords =
            number(c, b"KEYWORDS", l.preparation.metadata.max_keywords)?;
        l.preparation.metadata.max_keyword_bytes = number(
            c,
            b"KEYWORD_BYTES",
            l.preparation.metadata.max_keyword_bytes,
        )?;
        l.preparation.max_keyword_tasks =
            number(c, b"KEYWORD_TASKS", l.preparation.max_keyword_tasks)?;
        l.preparation.max_group_plan_bytes =
            number(c, b"GROUP_PLAN_BYTES", l.preparation.max_group_plan_bytes)?;
        Ok(Self {
            limits: l,
            metadata,
            resolver: gnunet_resolver_broker::Limits::default(),
        })
    }
}

/// The application treats its explicit metadata-library/plugin configuration as
/// a trusted native-code selection. Restored task bytes do not enter this path.
#[expect(
    unsafe_code,
    reason = "The application explicitly admits the user's selected GNU libextractor dependency/plugins; library APIs require this unforgeable execution capability"
)]
fn authorize_selected(settings: MetadataSettings) -> Result<MetadataSettings, Failure> {
    let Some(configuration) = settings.native_configuration() else {
        return Ok(settings);
    };
    // SAFETY: this application defines the explicit user/config-file native
    // extension choice as trusted code with the standard GNU ABI and plugin
    // lifetimes. The assertion includes selected dependencies and loader state.
    let authorization = unsafe {
        gnunet_fs_host::extraction::NativeMetadataAuthorization::new(configuration.clone())
    };
    Ok(settings.with_native_authorization(&authorization)?)
}
