//! Worker-local library/list ownership and public GNU libextractor ABI calls.
//! The callback bridge owns bounded output conversion and panic containment.
mod callback;
use crate::{Authorization, Cleanup, Extraction, Failure, Limits, NativeError};
use callback::Collector;
use gnunet_native::library::Library;
use std::{
    ffi::{c_char, c_int, c_void},
    marker::PhantomData,
    ptr,
    rc::Rc,
};

type Defaults = unsafe extern "C" fn(c_int) -> *mut c_void;
type Config = unsafe extern "C" fn(*mut c_void, *const c_char, c_int) -> *mut c_void;
type Release = unsafe extern "C" fn(*mut c_void);
type Callback = unsafe extern "C" fn(
    *mut c_void,
    *const c_char,
    c_int,
    c_int,
    *const c_char,
    *const c_char,
    usize,
) -> c_int;
type Extract =
    unsafe extern "C" fn(*mut c_void, *const c_char, *const c_void, usize, Callback, *mut c_void);
#[derive(Clone, Copy)]
struct Api {
    defaults: Defaults,
    config: Config,
    release: Release,
    extract: Extract,
}
macro_rules! bind {
    ($library:expr, $name:literal, $ty:ty, $guard:expr) => {{
        $guard().map_err(Failure::caller)?;
        let raw = $library.symbol($name).map_err(|source| {
            Failure::native(NativeError::Loader {
                operation: "lookup libextractor symbol",
                source,
            })
        })?;
        // SAFETY: named public libextractor symbol and its exact extractor.h C
        // signature on this target. The library owner remains live through every call.
        unsafe { std::mem::transmute::<*mut c_void, $ty>(raw) }
    }};
}

/// One original libextractor list and library, created/used on its caller's
/// existing worker. Not Send/Sync; this leaf starts no thread or child task.
/// IN_PROCESS suppresses libextractor's framework isolation workers. Arbitrary
/// plugin code can still allocate or start its own native work; that is not a
/// resource/process guarantee made by this leaf. Native plugins remain trusted.
pub struct Provider {
    library: Library,
    api: Api,
    plugins: *mut c_void,
    limits: Limits,
    _local: PhantomData<Rc<()>>,
}
impl std::fmt::Debug for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Provider")
            .field("open", &self.library.is_open())
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}
impl Provider {
    /// Open exactly the already authorized native library/plugin selection.
    /// Configuration or restored bytes alone cannot call this entry point.
    /// Every native admission uses the caller's original hard/stop guard.
    ///
    /// Pure configuration cannot substitute for an execution capability:
    /// ```compile_fail
    /// use gnunet_extractor_host::{Configuration, Limits, Provider, Selection};
    /// let config = Configuration::new(std::path::PathBuf::from("/selected/provider"), Selection::Defaults, 4096).unwrap();
    /// let provider = Provider::open(&config, Limits::default(), || Ok::<(), ()>(()));
    /// ```
    pub fn open<E>(
        authorization: &Authorization,
        limits: Limits,
        mut guard: impl FnMut() -> Result<(), E>,
    ) -> Result<Self, Failure<E>> {
        let configuration = authorization.configuration();
        let path = configuration.library();
        limits.validate().map_err(Failure::native)?;
        if path.as_os_str().as_encoded_bytes().len() > limits.config_bytes {
            return Err(Failure::native(NativeError::Limit("native library path")));
        }
        if configuration
            .configured()
            .is_some_and(|bytes| bytes.len() > limits.config_bytes)
        {
            return Err(Failure::native(NativeError::Limit(
                "native provider configuration",
            )));
        }
        let config = configuration.configured_cstr();
        guard().map_err(Failure::caller)?;
        // SAFETY: the unforgeable authorization certifies this exact native
        // dependency, plugin selection, environment and public GNU ABI.
        // Its reference remains owned until every plugin and callback is done.
        let mut library = unsafe { Library::load(path) }.map_err(|source| {
            Failure::native(NativeError::Loader {
                operation: "load libextractor",
                source,
            })
        })?;
        let loaded: Result<Api, Failure<E>> = (|| {
            Ok(Api {
                defaults: bind!(library, c"EXTRACTOR_plugin_add_defaults", Defaults, guard),
                config: bind!(library, c"EXTRACTOR_plugin_add_config", Config, guard),
                release: bind!(library, c"EXTRACTOR_plugin_remove_all", Release, guard),
                extract: bind!(library, c"EXTRACTOR_extract", Extract, guard),
            })
        })();
        let api = match loaded {
            Ok(api) => api,
            Err(mut error) => {
                error.cleanup = library.close().err().map(|source| NativeError::Loader {
                    operation: "close libextractor",
                    source,
                });
                return Err(error);
            }
        };
        let mut provider = Self {
            library,
            api,
            plugins: ptr::null_mut(),
            limits,
            _local: PhantomData,
        };
        let configured: Result<(), Failure<E>> = (|| {
            guard().map_err(Failure::caller)?;
            // SAFETY: original standard defaults function, explicit IN_PROCESS=2.
            provider.plugins = unsafe { (api.defaults)(2) };
            if let Some(config) = config {
                guard().map_err(Failure::caller)?;
                // SAFETY: public list updater owns its previous list; config is
                // original terminated bytes, not a shell or alternate protocol.
                provider.plugins = unsafe { (api.config)(provider.plugins, config.as_ptr(), 2) };
            }
            guard().map_err(Failure::caller)?;
            Ok(())
        })();
        match configured {
            Ok(()) => Ok(provider),
            Err(mut error) => {
                error.cleanup = provider.close_inner().err();
                Err(error)
            }
        }
    }

    /// Separately selected bounded complete in-memory input; borrowed bytes are
    /// not copied. This is never an automatic fallback for descriptor failures.
    pub fn extract_bytes<E>(
        &mut self,
        bytes: &[u8],
        mut guard: impl FnMut() -> Result<(), E>,
    ) -> Result<Extraction, Failure<E>> {
        if bytes.len() > self.limits.memory_input_bytes {
            return Err(Failure::native(NativeError::Limit(
                "complete in-memory input",
            )));
        }
        self.run(ptr::null(), bytes.as_ptr().cast(), bytes.len(), &mut guard)
    }

    #[cfg(unix)]
    pub(crate) fn extract_filename<E>(
        &mut self,
        name: &std::ffi::CStr,
        guard: &mut impl FnMut() -> Result<(), E>,
    ) -> Result<Extraction, Failure<E>> {
        self.run(name.as_ptr(), ptr::null(), 0, guard)
    }

    #[cfg(windows)]
    pub(crate) fn extract_mapping<E>(
        &mut self,
        mapping: &gnunet_native::filesystem::ReadMapping,
        guard: &mut impl FnMut() -> Result<(), E>,
    ) -> Result<Extraction, Failure<E>> {
        let address = mapping.as_ptr().map_err(|source| {
            Failure::native(NativeError::Io {
                operation: "borrow original file mapping",
                source,
            })
        })?;
        self.run(ptr::null(), address, mapping.len(), guard)
    }

    fn run<E, G: FnMut() -> Result<(), E>>(
        &mut self,
        filename: *const c_char,
        data: *const c_void,
        size: usize,
        guard: &mut G,
    ) -> Result<Extraction, Failure<E>> {
        if !self.library.is_open() {
            return Err(Failure::native(NativeError::Closed));
        }
        guard().map_err(Failure::caller)?;
        let mut collected = Collector::new(self.limits, guard).map_err(Failure::native)?;
        collected.check()?;
        // SAFETY: synchronous standard API; either the original held descriptor
        // name or complete borrowed memory is valid for the whole call. The
        // stack collector lives until every callback has returned. Its callback
        // contains Rust panic unwinding and does not retain native pointers.
        unsafe {
            (self.api.extract)(
                self.plugins,
                filename,
                data,
                size,
                callback::receive::<G, E>,
                (&mut collected as *mut Collector<'_, G, E>).cast(),
            );
        }
        collected.finish()
    }

    /// Original explicit resource policy.
    #[must_use]
    pub fn limits(&self) -> Limits {
        self.limits
    }

    fn close_inner(&mut self) -> Result<Cleanup, NativeError> {
        let released = !self.plugins.is_null();
        let plugins = std::mem::replace(&mut self.plugins, ptr::null_mut());
        if released {
            // SAFETY: original opaque list is released once before its library.
            unsafe {
                (self.api.release)(plugins);
            }
        }
        let closed = self.library.close().map_err(|source| NativeError::Loader {
            operation: "close libextractor",
            source,
        })?;
        Ok(Cleanup {
            plugin_release_called: released,
            library_close_succeeded: closed,
        })
    }
    /// Clock-free original cleanup. The void plugin release is a called fact;
    /// Native close errors remain errors; loader release does not prove physical unloading.
    pub fn close(mut self) -> Result<Cleanup, NativeError> {
        self.close_inner()
    }
}
impl Drop for Provider {
    fn drop(&mut self) {
        let _unobserved_cleanup = self.close_inner();
    }
}
