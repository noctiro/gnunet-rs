//! Owned extraction selection crosses the existing worker boundary; native
//! handles are created, used and explicitly closed only inside that worker.
use super::{Context, Error, ManualMetadata, Policy};
use gnunet_extractor_host::{Provider, Selection};
use std::{os::unix::ffi::OsStrExt, path::PathBuf, sync::Arc};

/// Optional provider's explicit resource policy; not an FS protocol constant.
pub use gnunet_extractor_host::Limits as NativeMetadataLimits;

#[derive(Clone)]
enum SelectionData {
    Builtin,
    Disabled,
    FilenameOnly,
    Native(Arc<NativeConfig>),
}
struct NativeConfig {
    library: PathBuf,
    extractors: Option<Vec<u8>>,
    limits: NativeMetadataLimits,
}
/// One owned, cheaply cloned metadata configuration snapshot. Contains no
/// provider, file, clock, task or native handle and is safe to send to the
/// original worker. Its Debug output does not disclose plugin option contents.
#[derive(Clone)]
pub struct MetadataSettings {
    selection: SelectionData,
    manual: Option<Arc<ManualMetadata>>,
}
impl std::fmt::Debug for MetadataSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match &self.selection {
            SelectionData::Builtin => "MetadataSettings(Builtin)",
            SelectionData::Disabled => "MetadataSettings(Disabled)",
            SelectionData::FilenameOnly => "MetadataSettings(FilenameOnly)",
            SelectionData::Native(_) => "MetadataSettings(Native)",
        })
    }
}
impl Default for MetadataSettings {
    fn default() -> Self {
        Self::selected(SelectionData::Builtin)
    }
}
impl MetadataSettings {
    fn selected(selection: SelectionData) -> Self {
        Self {
            selection,
            manual: None,
        }
    }
    /// Adopt bounded explicit user annotations. This never loads a provider or
    /// changes automatic keyword selection; it survives CLI-D unchanged.
    #[must_use]
    pub fn with_manual(mut self, manual: ManualMetadata) -> Self {
        self.manual = (!manual.is_empty()).then(|| Arc::new(manual));
        self
    }
    /// Number of distinct explicit annotations, not an extraction receipt.
    #[must_use]
    pub fn manual_items(&self) -> usize {
        self.manual.as_ref().map_or(0, |m| m.len())
    }
    pub(crate) fn manual(&self) -> Option<Arc<ManualMetadata>> {
        self.manual.clone()
    }
    /// Validate/copy exact selected FS.EXTRACTORS bytes without loading code.
    /// Explicit disablement wins; absent config/library selects builtins.
    /// Any explicit non-`-` config without a native library is a real refusal.
    pub fn new(
        disabled: bool,
        configured: Option<&[u8]>,
        library: Option<PathBuf>,
    ) -> Result<Self, Error> {
        Self::new_with_limits(
            disabled,
            configured,
            library,
            NativeMetadataLimits::default(),
        )
    }
    /// Same pure owned configuration with explicit native limits. Actual
    /// per-operation content/metadata/group bounds further restrict these.
    pub fn new_with_limits(
        disabled: bool,
        configured: Option<&[u8]>,
        library: Option<PathBuf>,
        limits: NativeMetadataLimits,
    ) -> Result<Self, Error> {
        if disabled {
            return Ok(Self::selected(SelectionData::Disabled));
        }
        if configured == Some(b"-".as_slice()) {
            return Ok(Self::selected(SelectionData::FilenameOnly));
        }
        let Some(library) = library else {
            return if configured.is_none() {
                Ok(Self::default())
            } else {
                Err(Error::MetadataSettings(
                    gnunet_extractor_host::NativeError::Invalid(
                        "explicit FS.EXTRACTORS requires a selected native library",
                    ),
                ))
            };
        };
        limits.validate().map_err(Error::MetadataSettings)?;
        if !library.is_absolute()
            || library.as_os_str().as_bytes().len() > limits.config_bytes
            || library.as_os_str().as_bytes().contains(&0)
            || configured.is_some_and(|b| b.len() > limits.config_bytes || b.contains(&0))
        {
            return Err(Error::MetadataSettings(
                gnunet_extractor_host::NativeError::Invalid(
                    "absolute bounded metadata provider path/config",
                ),
            ));
        }
        let extractors = configured.map(super::copy).transpose()?;
        Ok(Self::selected(SelectionData::Native(Arc::new(
            NativeConfig {
                library,
                extractors,
                limits,
            },
        ))))
    }
    /// Freeze the exact automatic extraction selection and native limits for a
    /// private durable owner. No provider/configuration file is opened here.
    /// Manual publication annotations are outside automatic keyword recovery
    /// and are explicitly refused rather than silently omitted.
    pub fn snapshot(&self) -> Result<Vec<u8>, Error> {
        snapshot::encode(self)
    }
    /// Restore the same bounded automatic selection without re-reading live
    /// configuration or loading a provider. This is private task data, not a
    /// GNUnet message, provider-identity certificate or extraction receipt.
    pub fn from_snapshot(bytes: &[u8]) -> Result<Self, Error> {
        snapshot::decode(bytes)
    }
    /// Whether automatic metadata-derived KSKs are permitted. CLI-D disables
    /// them, while configured `-` retains the safe filename/date path, matching
    /// fixed C's valid serialized empty-header/scanner path.
    #[must_use]
    pub fn automatic_keywords_enabled(&self) -> bool {
        !matches!(&self.selection, SelectionData::Disabled)
    }
    /// Whether actual builtin/native format probes are selected. Configured `-`
    /// disables these without discarding the safe filename/date or KSK intent.
    #[must_use]
    pub fn format_extraction_enabled(&self) -> bool {
        matches!(
            &self.selection,
            SelectionData::Builtin | SelectionData::Native(_)
        )
    }
    /// Retained shared settings payload, including native option/path capacities.
    /// Clones share these allocations; an enclosing owner charges them once.
    /// This excludes the enclosing handle and native provider allocations.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        let native = if let SelectionData::Native(c) = &self.selection {
            std::mem::size_of::<NativeConfig>()
                .checked_add(2 * std::mem::size_of::<usize>())
                .and_then(|n| n.checked_add(c.library.capacity()))
                .and_then(|n| n.checked_add(c.extractors.as_ref().map_or(0, Vec::capacity)))
                .ok_or(Error::Limit)?
        } else {
            0
        };
        let manual = if let Some(m) = &self.manual {
            m.retained_bytes()?
                .checked_add(2 * std::mem::size_of::<usize>())
                .ok_or(Error::Limit)?
        } else {
            0
        };
        native.checked_add(manual).ok_or(Error::Limit)
    }
    pub(crate) fn open<C: FnMut(crate::Progress) -> crate::Control>(
        &self,
        context: &Context<C>,
        policy: Policy,
        content_file_bytes: u64,
    ) -> Result<Option<Provider>, Error> {
        if !policy.extract {
            return Ok(None);
        }
        let SelectionData::Native(c) = &self.selection else {
            return Ok(None);
        };
        let mut limits = c.limits;
        limits.source_bytes = limits.source_bytes.min(content_file_bytes);
        limits.memory_input_bytes = limits
            .memory_input_bytes
            .min(usize::try_from(limits.source_bytes).unwrap_or(usize::MAX));
        limits.items = limits.items.min(policy.max_metadata_items);
        limits.callbacks = limits.callbacks.min(policy.max_metadata_items);
        limits.value_bytes = limits.value_bytes.min(policy.max_metadata_bytes);
        limits.name_bytes = limits
            .name_bytes
            .min(policy.max_metadata_bytes.saturating_sub(1));
        limits.output_bytes = limits.output_bytes.min(policy.max_metadata_bytes);
        let remaining = {
            let budget = context.budget.borrow();
            budget.limit.checked_sub(budget.used).ok_or(Error::Limit)?
        };
        limits.output_bytes = limits.output_bytes.min(remaining);
        limits.items = limits
            .items
            .min(limits.output_bytes / std::mem::size_of::<gnunet_extractor_host::Item>());
        if limits.items == 0 {
            return Err(Error::Limit);
        }
        context.check()?;
        let provider = Provider::open(
            &c.library,
            Selection::from_fs(false, c.extractors.as_deref()),
            limits,
            || context.check(),
        )
        .map_err(Error::from)?;
        Ok(provider)
    }
}

/// Close the real provider on every ordinary result path; do not hide an
/// original preparation failure if physical provider close also fails.
pub(super) fn finish<T>(provider: Option<Provider>, result: Result<T, Error>) -> Result<T, Error> {
    let close = provider.map(Provider::close).transpose();
    match (result, close) {
        (Ok(value), Ok(_)) => Ok(value),
        (Err(error), Ok(_)) => Err(error),
        (Ok(_), Err(cleanup)) => Err(Error::ExtractorCleanup {
            original: None,
            cleanup,
        }),
        (Err(original), Err(cleanup)) => Err(Error::ExtractorCleanup {
            original: Some(Box::new(original)),
            cleanup,
        }),
    }
}

mod snapshot;
