use std::{any::Any, error::Error, fmt, io};

/// Exact GNUnet FS extraction selection, without interpreting plugin contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Selection<'a> {
    /// Explicit `-D` or the exact configured `-`: do not load any provider.
    Disabled,
    /// Use libextractor's installed/default selection.
    Defaults,
    /// Load defaults, then apply the original colon-separated plugin config.
    DefaultsWith(&'a [u8]),
}
impl<'a> Selection<'a> {
    /// Preserve fixed GNUnet's exact `-` sentinel and optional EXTRACTORS value.
    #[must_use]
    pub fn from_fs(disabled: bool, configured: Option<&'a [u8]>) -> Self {
        if disabled || configured == Some(b"-".as_slice()) {
            Self::Disabled
        } else {
            configured.map_or(Self::Defaults, Self::DefaultsWith)
        }
    }
}

/// Finite Rust input/callback retention policy. Native plugin allocation and
/// execution time are separate provider limitations, not measured by this cap.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum actual regular-file extent admitted to the descriptor profile.
    pub source_bytes: u64,
    /// Maximum separately selected in-memory input extent; no automatic fallback.
    pub memory_input_bytes: usize,
    /// Maximum original plugin config or absolute library-path length.
    pub config_bytes: usize,
    /// Maximum callbacks, including duplicate metadata values.
    pub callbacks: usize,
    /// Maximum retained metadata records.
    pub items: usize,
    /// Maximum raw data extent in one callback, before text termination.
    pub value_bytes: usize,
    /// Maximum plugin/MIME C-string length excluding NUL.
    pub name_bytes: usize,
    /// Maximum actual Rust output Vec capacities, including record metadata.
    pub output_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            source_bytes: 64 * 1024 * 1024 * 1024,
            memory_input_bytes: 64 * 1024 * 1024,
            config_bytes: 4096,
            callbacks: 4096,
            items: 256,
            value_bytes: 1024 * 1024,
            name_bytes: 1024,
            output_bytes: 4 * 1024 * 1024,
        }
    }
}
impl Limits {
    /// Check arithmetic and nonzero policy before native provider admission.
    pub fn validate(self) -> Result<(), NativeError> {
        if self.source_bytes == 0
            || self.source_bytes > i64::MAX as u64
            || self.memory_input_bytes == 0
            || self.memory_input_bytes as u64 > self.source_bytes
            || self.config_bytes == 0
            || self.callbacks == 0
            || self.items == 0
            || self.items > self.callbacks
            || self.value_bytes == 0
            || self.name_bytes == 0
            || self.config_bytes >= isize::MAX as usize
            || self.value_bytes >= isize::MAX as usize
            || self.name_bytes >= isize::MAX as usize
            || self.output_bytes >= isize::MAX as usize
            || self
                .items
                .checked_mul(std::mem::size_of::<Item>())
                .is_none_or(|bytes| bytes > self.output_bytes)
        {
            return Err(NativeError::Invalid("extractor resource policy"));
        }
        Ok(())
    }
}

/// Public libextractor metadata format, numerically identical to GNUnet v2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Format {
    /// UTF8-labelled original bytes, with a final NUL; no unchecked Rust str.
    Utf8 = 1,
    /// Arbitrary bytes, including zero bytes or an empty value.
    Binary = 2,
    /// Original unknown-encoding C-string bytes with a final NUL.
    CString = 3,
}

/// One original callback record; names and text retain their wire terminators.
/// Debug reports extents, avoiding implicit logging of extracted contents.
pub struct Item {
    /// Open, nonnegative native metadata type number.
    pub kind: u32,
    /// Original supported metadata format.
    pub format: Format,
    /// Original plugin name including NUL, or the original NULL.
    pub plugin: Option<Vec<u8>>,
    /// Original metadata MIME name including NUL, or the original NULL.
    pub mime: Option<Vec<u8>>,
    /// Original data; text lacking its final NUL is terminated as in fixed C.
    pub data: Vec<u8>,
}
impl fmt::Debug for Item {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Item")
            .field("kind", &self.kind)
            .field("format", &self.format)
            .field("plugin_bytes", &self.plugin.as_ref().map(Vec::len))
            .field("mime_bytes", &self.mime.as_ref().map(Vec::len))
            .field("data_bytes", &self.data.len())
            .finish()
    }
}
impl Item {
    pub(crate) fn retained(&self) -> Option<usize> {
        self.data
            .capacity()
            .checked_add(self.plugin.as_ref().map_or(0, Vec::capacity))?
            .checked_add(self.mime.as_ref().map_or(0, Vec::capacity))
    }
}

/// What the public void-returning native API actually exposed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Observation {
    /// No callback was observed. Unsupported format and internal plugin failure
    /// cannot be distinguished by this API; this is not failure-free validation.
    EmptyUnknown,
    /// Actual bounded callback records were observed, not metadata acceptance,
    /// CHK binding, KSK completion or whole-plugin success evidence.
    Records,
}

/// Complete return from one synchronous extraction attempt. Own/guard failures
/// return Failure instead; they never turn into EmptyUnknown or basic fallback.
#[derive(Debug)]
pub struct Extraction {
    pub(crate) items: Vec<Item>,
    pub(crate) callbacks: usize,
    pub(crate) retained: usize,
}
impl Extraction {
    /// Actual retained original metadata records.
    #[must_use]
    pub fn items(&self) -> &[Item] {
        &self.items
    }
    /// Number of actual callbacks observed during this attempt.
    #[must_use]
    pub fn callbacks(&self) -> usize {
        self.callbacks
    }
    /// Actual retained Rust heap capacity of the returned record container/data.
    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        self.retained
    }
    /// Keep native empty/unknown distinct from observed metadata records.
    #[must_use]
    pub fn observation(&self) -> Observation {
        if self.items.is_empty() {
            Observation::EmptyUnknown
        } else {
            Observation::Records
        }
    }
    /// Move original metadata to the caller without a second payload copy.
    #[must_use]
    pub fn into_items(self) -> Vec<Item> {
        self.items
    }
}

/// Original panic captured inside the C callback instead of unwinding over C.
pub struct PanicPayload(pub(crate) Box<dyn Any + Send>);
impl fmt::Debug for PanicPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PanicPayload(<original callback panic>)")
    }
}
impl PanicPayload {
    /// Recover the exact original payload for the outer worker's panic policy.
    #[must_use]
    pub fn into_inner(self) -> Box<dyn Any + Send> {
        self.0
    }
}

/// Original native/provider refusal; no error is converted into empty metadata.
#[derive(Debug)]
pub enum NativeError {
    /// Invalid explicit selection, input descriptor or callback field.
    Invalid(&'static str),
    /// Finite resource admission/allocation failed.
    Limit(&'static str),
    /// Actual native I/O failure and errno.
    Io {
        /// Original operation.
        operation: &'static str,
        /// Original native error, not formatted into another error.
        source: io::Error,
    },
    /// Actual POSIX dynamic loader failure with an immediate bounded diagnostic.
    Loader {
        /// Original loader operation.
        operation: &'static str,
        /// Original diagnostic bytes; may be empty if allocation also failed.
        diagnostic: Vec<u8>,
        /// Native diagnostic was longer or its copy could not be retained.
        truncated: bool,
    },
    /// Provider was already physically closed.
    Closed,
    /// Original descriptor/namespace identity or extent/stamp changed.
    SourceChanged,
    /// Original caught callback panic, with its payload retained.
    CallbackPanicked(PanicPayload),
    /// Descriptor namespace is not implemented for this platform.
    DescriptorProfileUnavailable,
}
impl fmt::Display for NativeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(s) => write!(f, "invalid {s}"),
            Self::Limit(s) => write!(f, "extractor limit: {s}"),
            Self::Io { operation, source } => write!(f, "{operation}: {source}"),
            Self::Loader { operation, .. } => write!(f, "native loader failed: {operation}"),
            Self::Closed => f.write_str("libextractor provider is closed"),
            Self::SourceChanged => f.write_str("original extraction source changed"),
            Self::CallbackPanicked(_) => f.write_str("original extractor callback panicked"),
            Self::DescriptorProfileUnavailable => {
                f.write_str("descriptor extraction profile unavailable")
            }
        }
    }
}
impl Error for NativeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Primary provider cause or the caller's unchanged original hard/stop cause.
#[derive(Debug)]
pub enum Cause<E> {
    /// Native provider/resource/source failure.
    Native(NativeError),
    /// Exact original caller cause; no replacement clock/deadline is sampled.
    Caller(E),
}
/// Failed original attempt with independent cleanup/seek restoration failures.
#[derive(Debug)]
pub struct Failure<E> {
    /// Primary original cause.
    pub cause: Cause<E>,
    /// Independent provider cleanup failure, if physical close was attempted.
    pub cleanup: Option<NativeError>,
    /// Independent original file-position restoration failure.
    pub restore: Option<io::Error>,
}
impl<E> Failure<E> {
    pub(crate) fn native(error: NativeError) -> Self {
        Self {
            cause: Cause::Native(error),
            cleanup: None,
            restore: None,
        }
    }
    pub(crate) fn caller(error: E) -> Self {
        Self {
            cause: Cause::Caller(error),
            cleanup: None,
            restore: None,
        }
    }
}
impl<E: fmt::Display> fmt::Display for Failure<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.cause {
            Cause::Native(e) => e.fmt(f),
            Cause::Caller(e) => e.fmt(f),
        }
    }
}
impl<E: Error + 'static> Error for Failure<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(match &self.cause {
            Cause::Native(e) => e,
            Cause::Caller(e) => e,
        })
    }
}

/// Exact cleanup calls observed, not proof of native plugin internals/children.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cleanup {
    /// The original opaque list's void release function was called once.
    pub plugin_release_called: bool,
    /// dlclose returned zero for the original library handle.
    pub library_close_returned_zero: bool,
}
