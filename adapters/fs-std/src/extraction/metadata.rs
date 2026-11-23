//! Owned extraction selection crosses the existing worker boundary; native
//! handles are created, used and explicitly closed only inside that worker.
use super::{
    Context, Error, ManualMetadata, PdfExternalStreams, PdfRecipientAuthorization, Policy,
};
pub use gnunet_extractor_host::{
    Authorization as NativeMetadataAuthorization, Configuration as NativeMetadataConfiguration,
};
use gnunet_extractor_host::{Provider, Selection};
use std::{path::PathBuf, sync::Arc};

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
    provider: NativeMetadataConfiguration,
    limits: NativeMetadataLimits,
}
#[derive(Clone, Default)]
enum PdfRecipientAccess {
    #[default]
    Unselected,
    Required([u8; 32]),
    Authorized(PdfRecipientAuthorization),
}
/// Owned extraction configuration with optional runtime-only execution authority.
/// Clones share configuration/capability payloads. Native handles stay on the
/// worker; Debug does not disclose plugin options.
#[derive(Clone)]
pub struct MetadataSettings {
    selection: SelectionData,
    manual: Option<Arc<ManualMetadata>>,
    pdf_streams: Option<Arc<PdfExternalStreams>>,
    pdf_recipient: PdfRecipientAccess,
    authorization: Option<NativeMetadataAuthorization>,
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
            pdf_streams: None,
            pdf_recipient: PdfRecipientAccess::Unselected,
            authorization: None,
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
    /// Attach caller-supplied PDF stream data bound to original document versions.
    #[must_use]
    pub fn with_pdf_external_streams(mut self, streams: PdfExternalStreams) -> Self {
        self.pdf_streams = (!streams.is_empty()).then(|| Arc::new(streams));
        self
    }
    pub(super) fn pdf_streams(&self) -> Option<&PdfExternalStreams> {
        self.pdf_streams.as_deref()
    }
    /// Select live PDF recipient authority. A restored selection requires
    /// the same public credential identity.
    ///
    /// # Errors
    ///
    /// Returns a binding error if the selected identity differs.
    pub fn with_pdf_recipient(
        mut self,
        authorization: &PdfRecipientAuthorization,
    ) -> Result<Self, Error> {
        if self
            .pdf_recipient_id()
            .is_some_and(|id| id != *authorization.identity())
        {
            return Err(Error::Binding);
        }
        self.pdf_recipient = PdfRecipientAccess::Authorized(authorization.clone());
        Ok(self)
    }

    pub(super) fn pdf_recipient(&self) -> Result<Option<&PdfRecipientAuthorization>, Error> {
        match &self.pdf_recipient {
            PdfRecipientAccess::Unselected => Ok(None),
            PdfRecipientAccess::Required(_) => Err(Error::PdfRecipientRequired),
            PdfRecipientAccess::Authorized(authority) => Ok(Some(authority)),
        }
    }

    fn pdf_recipient_id(&self) -> Option<[u8; 32]> {
        match &self.pdf_recipient {
            PdfRecipientAccess::Unselected => None,
            PdfRecipientAccess::Required(id) => Some(*id),
            PdfRecipientAccess::Authorized(authority) => Some(*authority.identity()),
        }
    }
    /// Validate/copy exact selected FS.EXTRACTORS bytes without loading code.
    /// Explicit disablement wins; absent config/library selects builtins.
    /// Any explicit non-`-` config without a native library is a real refusal.
    /// Native selections remain unapproved until a matching capability is attached.
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
        let provider = NativeMetadataConfiguration::new(
            library,
            Selection::from_fs(false, configured),
            limits.config_bytes,
        )
        .map_err(Error::MetadataSettings)?;
        Ok(Self::selected(SelectionData::Native(Arc::new(
            NativeConfig { provider, limits },
        ))))
    }
    /// Pure native configuration, if selected. Inspecting or cloning this value
    /// grants no authority to execute the library or any plugin.
    #[must_use]
    pub fn native_configuration(&self) -> Option<&NativeMetadataConfiguration> {
        match &self.selection {
            SelectionData::Native(c) => Some(&c.provider),
            _ => None,
        }
    }
    /// Whether an in-memory matching native execution capability is attached.
    /// Snapshots never retain this fact or recreate the capability.
    #[must_use]
    pub fn is_native_authorized(&self) -> bool {
        self.authorization.is_some()
    }
    /// Attach an explicit matching execution capability. The capability shares
    /// this settings allocation; no native code is loaded here.
    pub fn with_native_authorization(
        mut self,
        authorization: &NativeMetadataAuthorization,
    ) -> Result<Self, Error> {
        let configuration = self.native_configuration().ok_or_else(|| {
            Error::MetadataSettings(gnunet_extractor_host::NativeError::AuthorizationMismatch)
        })?;
        self.authorization = Some(
            authorization
                .for_configuration(configuration)
                .map_err(Error::MetadataSettings)?,
        );
        Ok(self)
    }
    /// Reattach matching native provider and PDF recipient authority to
    /// restored selections. A held capability stays valid when the current
    /// settings omit it. Extraction fails before opening a provider or source
    /// when a recorded selection still requires authorization.
    pub fn with_authorization_from(self, current: &Self) -> Result<Self, Error> {
        let restored = match (self.native_configuration(), &current.authorization) {
            (Some(_), Some(authority)) => self.with_native_authorization(authority)?,
            _ => self,
        };
        match (restored.pdf_recipient_id(), &current.pdf_recipient) {
            (Some(_), PdfRecipientAccess::Authorized(authority)) => {
                restored.with_pdf_recipient(authority)
            }
            _ => Ok(restored),
        }
    }
    /// Freeze the automatic extraction selection, native limits and bound PDF
    /// data for a private durable owner. Reads each held bound PDF to identify
    /// its exact contents. Manual publication annotations are refused.
    pub fn snapshot(&self) -> Result<Vec<u8>, Error> {
        snapshot::encode(self, None)
    }
    #[cfg(feature = "network")]
    pub(crate) fn snapshot_for_document(&self, file: &std::fs::File) -> Result<Vec<u8>, Error> {
        snapshot::encode(self, Some(super::pdf_streams::observe(file)?))
    }
    #[cfg(feature = "network")]
    pub(crate) fn check_bound_document(&self, file: &std::fs::File) -> Result<(), Error> {
        if let Some(streams) = self.pdf_streams()
            && let observed = super::pdf_streams::observe(file)?
            && !streams
                .documents()
                .iter()
                .any(|doc| doc.observed == observed)
        {
            return Err(Error::SourceChanged);
        }
        Ok(())
    }
    #[cfg(feature = "network")]
    pub(crate) fn agrees_with_bound_digest(&self, digest: [u8; 64]) -> bool {
        self.pdf_streams().is_none_or(|streams| {
            streams
                .documents()
                .iter()
                .all(|doc| doc.matches_frozen_digest(digest))
        })
    }
    /// Restore private automatic extraction settings. PDF bindings require
    /// matching document identity, version and content before use. Native
    /// provider execution and selected PDF recipient keys require their live
    /// runtime authorizations.
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
    /// This excludes the enclosing handle, native provider allocations and
    /// independently owned runtime credentials.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        let native = if let SelectionData::Native(c) = &self.selection {
            std::mem::size_of::<NativeConfig>()
                .checked_add(2 * std::mem::size_of::<usize>())
                .and_then(|n| n.checked_add(c.provider.retained_bytes().ok()?))
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
        let external = self.pdf_streams.as_deref().map_or(0, |streams| {
            streams.retained_bytes() + 2 * std::mem::size_of::<usize>()
        });
        native
            .checked_add(manual)
            .and_then(|size| size.checked_add(external))
            .ok_or(Error::Limit)
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
        let authorization = self.authorization.as_ref().ok_or_else(|| {
            Error::MetadataSettings(gnunet_extractor_host::NativeError::AuthorizationRequired)
        })?;
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
        let provider =
            Provider::open(authorization, limits, || context.check()).map_err(Error::from)?;
        Ok(Some(provider))
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
