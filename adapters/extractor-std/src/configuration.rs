//! Immutable bounded provider selection; constructing this value executes no code.
use crate::{NativeError, Selection};
use std::{
    ffi::{CStr, CString},
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
};
struct Data {
    library: PathBuf,
    configured: Option<CString>,
}
/// Pure owned provider selection. Clones share bounded native path/config data;
/// parsing, restoring or cloning it grants no native execution authority.
#[derive(Clone)]
pub struct Configuration(Arc<Data>);
impl fmt::Debug for Configuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Configuration")
            .field("configured_bytes", &self.configured().map(<[u8]>::len))
            .finish_non_exhaustive()
    }
}
impl Configuration {
    /// Validate one absolute native path and exact default/plugin configuration.
    /// Disabled selection has no provider configuration. No filesystem or loader
    /// operation is performed. `maximum` bounds each original path/config value.
    pub fn new(
        library: PathBuf,
        selection: Selection<'_>,
        maximum: usize,
    ) -> Result<Self, NativeError> {
        if maximum == 0
            || maximum >= isize::MAX as usize
            || !library.is_absolute()
            || library.as_os_str().as_encoded_bytes().len() > maximum
            || library.as_os_str().as_encoded_bytes().contains(&0)
        {
            return Err(NativeError::Invalid(
                "absolute bounded provider library path",
            ));
        }
        let configured = match selection {
            Selection::Disabled => {
                return Err(NativeError::Invalid("disabled provider configuration"));
            }
            Selection::Defaults => None,
            Selection::DefaultsWith(bytes) => {
                if bytes.len() > maximum || bytes.contains(&0) {
                    return Err(NativeError::Invalid("bounded provider configuration"));
                }
                let mut owned = Vec::new();
                owned
                    .try_reserve_exact(
                        bytes
                            .len()
                            .checked_add(1)
                            .ok_or(NativeError::Limit("provider C-string extent"))?,
                    )
                    .map_err(|_| NativeError::Limit("provider configuration allocation"))?;
                owned.extend_from_slice(bytes);
                owned.push(0);
                Some(
                    CString::from_vec_with_nul(owned)
                        .map_err(|_| NativeError::Invalid("provider configuration C-string"))?,
                )
            }
        };
        Ok(Self(Arc::new(Data {
            library,
            configured,
        })))
    }
    /// Exact native library spelling, without canonicalization or path resolution.
    #[must_use]
    pub fn library(&self) -> &Path {
        &self.0.library
    }
    /// Exact plugin bytes; absent and present-empty selections remain distinct.
    #[must_use]
    pub fn configured(&self) -> Option<&[u8]> {
        self.0.configured.as_deref().map(CStr::to_bytes)
    }
    pub(crate) fn configured_cstr(&self) -> Option<&CStr> {
        self.0.configured.as_deref()
    }
    /// Borrow the provider's original non-disabled selection.
    #[must_use]
    pub fn selection(&self) -> Selection<'_> {
        self.configured()
            .map_or(Selection::Defaults, Selection::DefaultsWith)
    }
    /// Actual retained shared payload, excluding this enclosing Arc handle.
    pub fn retained_bytes(&self) -> Result<usize, NativeError> {
        std::mem::size_of::<Data>()
            .checked_add(2 * std::mem::size_of::<usize>())
            .and_then(|n| n.checked_add(self.0.library.capacity()))
            .and_then(|n| {
                n.checked_add(
                    self.0
                        .configured
                        .as_ref()
                        .map_or(0, |s| s.as_bytes_with_nul().len()),
                )
            })
            .ok_or(NativeError::Limit("provider configuration capacity"))
    }
    pub(crate) fn same_selection(&self, other: &Self) -> bool {
        self.library().as_os_str() == other.library().as_os_str()
            && self.configured() == other.configured()
    }
}
