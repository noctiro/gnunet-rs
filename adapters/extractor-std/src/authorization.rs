//! Explicit authority for executing one exact caller-trusted native selection.
use crate::{Configuration, NativeError};
/// Permission to execute the exact selected GNU libextractor dependency and
/// plugins. It contains no native handle and can cross worker boundaries. It
/// cannot be parsed or reconstructed from configuration/snapshot bytes.
#[derive(Clone, Debug)]
pub struct Authorization {
    configuration: Configuration,
}
impl Authorization {
    /// Authorize future loads/providers for this exact immutable selection.
    /// This only creates a capability; it executes no native code itself.
    ///
    /// # Safety
    /// For every future use of this value, its clones and resulting providers,
    /// the caller must trust the selected library's initialization, destruction,
    /// dependencies, configured/default plugins and loader environment. They
    /// must implement the public GNU libextractor C ABI, valid pointer extents,
    /// synchronous callback lifetimes and callback-stop semantics. Native code
    /// must not unwind through C or invalidate Rust-owned memory/resources.
    /// Independent providers may run on different threads; ensure the selected
    /// plugins/dependencies support that use or arrange required global exclusion.
    /// The assertion covers later path replacement and environment changes too.
    ///
    /// Configuration data cannot grant execution through a safe call:
    /// ```compile_fail
    /// use gnunet_extractor_host::{Authorization, Configuration, Selection};
    /// let config = Configuration::new(std::path::PathBuf::from("/selected/provider"), Selection::Defaults, 4096).unwrap();
    /// let authority = Authorization::new(config);
    /// ```
    #[expect(
        unsafe_code,
        reason = "The caller explicitly certifies native code/ABI trust; pure configuration cannot establish this authority"
    )]
    #[must_use]
    pub unsafe fn new(configuration: Configuration) -> Self {
        Self { configuration }
    }
    /// Exact admitted selection, still without any loaded native resources.
    #[must_use]
    pub fn configuration(&self) -> &Configuration {
        &self.configuration
    }
    /// Share this authority with an equal configuration allocation. Matching is
    /// exact native spelling and exact option bytes, including None versus empty.
    /// Other paths or plugin selections require a new explicit trust decision.
    pub fn for_configuration(&self, configuration: &Configuration) -> Result<Self, NativeError> {
        if !self.configuration.same_selection(configuration) {
            return Err(NativeError::AuthorizationMismatch);
        }
        Ok(Self {
            configuration: configuration.clone(),
        })
    }
}
