//! Owned extraction selection for explicit FS commands. No native
//! provider or worker is constructed by configuration parsing.
use gnunet::fs_host::extraction::{ManualMetadata, MetadataSettings};
use gnunet_config::Configuration;
use std::{error::Error, ffi::OsStr, path::PathBuf, sync::Arc};

#[derive(Default)]
pub(crate) struct Arguments {
    config: Option<PathBuf>,
    extractors: Option<Vec<u8>>,
    library: Option<PathBuf>,
    pub disabled: bool,
    manual: ManualMetadata,
}
impl Arguments {
    /// Consume one original extraction option and its complete following value.
    /// The caller handles `--` before calling this helper. Unindex does not
    /// accept manual publication annotations as reconstructed historical data.
    pub fn consume<T: AsRef<OsStr>>(
        &mut self,
        args: &[T],
        at: &mut usize,
        manual: bool,
    ) -> Result<bool, Box<dyn Error>> {
        let name = args.get(*at).ok_or("missing metadata option")?.as_ref();
        match name.as_encoded_bytes() {
            b"-D" | b"--disable-extractor" => {
                self.disabled = true;
                *at += 1;
                Ok(true)
            }
            b"-m" | b"--meta" if !manual => {
                Err("unindex does not accept manual -m/--meta annotations".into())
            }
            b"-c" | b"--config" | b"--extractors" | b"--extractor-library" | b"-m" | b"--meta" => {
                let value = args
                    .get(*at + 1)
                    .ok_or("metadata option requires a value")?
                    .as_ref();
                self.option(name, value)?;
                *at += 2;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    pub fn option(&mut self, name: &OsStr, value: &OsStr) -> Result<(), Box<dyn Error>> {
        let bytes = value.as_encoded_bytes();
        if matches!(name.as_encoded_bytes(), b"-m" | b"--meta") {
            self.manual.push(crate::argument::wire_bytes(value)?)?;
            return Ok(());
        }
        if bytes.len() > 4096 || bytes.contains(&0) {
            return Err("metadata option exceeds4096 bytes or contains NUL".into());
        }
        match name.as_encoded_bytes() {
            b"-c" | b"--config" => {
                if self.config.is_some() || bytes.is_empty() {
                    return Err("--config requires one nonempty filename".into());
                }
                self.config = Some(PathBuf::from(value));
            }
            b"--extractor-library" => {
                if self.library.is_some() || bytes.is_empty() {
                    return Err("--extractor-library requires one absolute filename".into());
                }
                self.library = Some(PathBuf::from(value));
            }
            b"--extractors" => {
                let bytes = crate::argument::wire_bytes(value)?;
                if self.extractors.is_some() {
                    return Err("--extractors may be specified only once".into());
                }
                let mut owned = Vec::new();
                owned.try_reserve_exact(bytes.len())?;
                owned.extend_from_slice(bytes);
                self.extractors = Some(owned);
            }
            _ => return Err("invalid metadata option".into()),
        }
        Ok(())
    }
    pub fn select(self) -> Result<MetadataSettings, Box<dyn Error>> {
        let mut c = Configuration::create(
            Arc::new(gnunet_config::ProjectData::default()),
            Default::default(),
        )?;
        if let Some(path) = self.config.as_deref() {
            // These commands have no global PROGRAM. Only the named main
            // file and its official include
            // semantics are requested; do not add ambient user/default files.
            c.load_explicit(None, Some(path))?;
        }
        self.select_configured(&c)
    }

    pub(super) fn select_configured(
        self,
        c: &Configuration,
    ) -> Result<MetadataSettings, Box<dyn Error>> {
        let configured = self
            .extractors
            .as_deref()
            .or_else(|| c.get(b"FS", b"EXTRACTORS"));
        let library = if self.disabled || configured == Some(b"-".as_slice()) {
            None
        } else {
            match self.library {
                Some(path) => Some(path),
                None if c.get(b"fs-rust", b"EXTRACTOR_LIBRARY").is_some() => {
                    Some(c.get_path("fs-rust", "EXTRACTOR_LIBRARY")?)
                }
                None => None,
            }
        };
        let settings =
            MetadataSettings::new(self.disabled, configured, library)?.with_manual(self.manual);
        authorize_selected(settings)
    }
}

/// The application treats its explicit metadata-library/plugin configuration as
/// a trusted native-code selection. Restored task bytes do not enter this path.
#[expect(
    unsafe_code,
    reason = "The application explicitly admits the user's selected GNU libextractor dependency/plugins; library APIs require this unforgeable execution capability"
)]
fn authorize_selected(settings: MetadataSettings) -> Result<MetadataSettings, Box<dyn Error>> {
    let Some(configuration) = settings.native_configuration() else {
        return Ok(settings);
    };
    // SAFETY: this application defines the explicit user/config-file native
    // extension choice as trusted code with the standard GNU ABI and plugin
    // lifetimes. The assertion includes selected dependencies and loader state.
    let authorization = unsafe {
        gnunet::fs_host::extraction::NativeMetadataAuthorization::new(configuration.clone())
    };
    Ok(settings.with_native_authorization(&authorization)?)
}
