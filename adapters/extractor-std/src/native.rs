//! Sole POSIX/libextractor ABI boundary. Only standard public provider symbols
//! are used; no libgnunet ABI or plugin-private object layout is accessed.
use crate::{
    Cleanup, Extraction, Failure, Format, Item, Limits, NativeError, PanicPayload, Selection,
};
use libc::{c_char, c_int, c_void};
use std::{
    ffi::{CStr, CString},
    fs::File,
    marker::PhantomData,
    os::{fd::AsRawFd, unix::ffi::OsStrExt},
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
    ptr::{self, NonNull},
    rc::Rc,
};

#[cfg(any(target_os = "linux", target_os = "android"))]
#[link(name = "dl")]
unsafe extern "C" {}

struct Library(Option<NonNull<c_void>>);
fn loader_error(operation: &'static str) -> NativeError {
    // SAFETY: the POSIX thread-local diagnostic is consumed before another
    // loader operation. strnlen stops at its NUL or this fixed bound.
    let raw = unsafe { libc::dlerror() };
    if raw.is_null() {
        return NativeError::Loader {
            operation,
            diagnostic: Vec::new(),
            truncated: false,
        };
    }
    // SAFETY: dlerror returns a live NUL-terminated diagnostic.
    let n = unsafe { libc::strnlen(raw, 1025) };
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(n.min(1024)).is_err() {
        return NativeError::Loader {
            operation,
            diagnostic: bytes,
            truncated: true,
        };
    }
    // SAFETY: the bounded prefix is within the original diagnostic's extent.
    bytes.extend_from_slice(unsafe { std::slice::from_raw_parts(raw.cast(), n.min(1024)) });
    NativeError::Loader {
        operation,
        diagnostic: bytes,
        truncated: n > 1024,
    }
}
fn terminated(bytes: &[u8], maximum: usize) -> Result<CString, NativeError> {
    if bytes.len() > maximum || bytes.contains(&0) {
        return Err(NativeError::Invalid("provider path/config C-string"));
    }
    let size = bytes
        .len()
        .checked_add(1)
        .ok_or(NativeError::Limit("C-string extent"))?;
    let mut value = Vec::new();
    value
        .try_reserve_exact(size)
        .map_err(|_| NativeError::Limit("C-string allocation"))?;
    value.extend_from_slice(bytes);
    value.push(0);
    CString::from_vec_with_nul(value).map_err(|_| NativeError::Invalid("provider C-string"))
}
impl Library {
    fn open(path: &CStr) -> Result<Self, NativeError> {
        // SAFETY: original owned terminated path and standard POSIX loader flags.
        let raw = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        NonNull::new(raw)
            .map(|p| Self(Some(p)))
            .ok_or_else(|| loader_error("dlopen libextractor"))
    }
    fn symbol(&self, name: &CStr) -> Result<*mut c_void, NativeError> {
        let handle = self.0.ok_or(NativeError::Closed)?;
        // SAFETY: original still-live handle and a static public symbol name.
        let raw = unsafe {
            let _old = libc::dlerror();
            libc::dlsym(handle.as_ptr(), name.as_ptr())
        };
        // SAFETY: immediately consume dlsym's own thread-local diagnostic.
        let error = unsafe { libc::dlerror() };
        if !error.is_null() || raw.is_null() {
            // Preserve this diagnostic before a different loader call.
            let mut bytes = Vec::new();
            let mut truncated = false;
            if !error.is_null() {
                // SAFETY: original diagnostic is NUL-terminated by POSIX.
                let n = unsafe { libc::strnlen(error, 1025) };
                if bytes.try_reserve_exact(n.min(1024)).is_ok() {
                    // SAFETY: prefix is bounded by its original live extent.
                    bytes.extend_from_slice(unsafe {
                        std::slice::from_raw_parts(error.cast(), n.min(1024))
                    });
                    truncated = n > 1024;
                } else {
                    truncated = true;
                }
            }
            return Err(NativeError::Loader {
                operation: "dlsym libextractor",
                diagnostic: bytes,
                truncated,
            });
        }
        Ok(raw)
    }
    fn close(&mut self) -> Result<bool, NativeError> {
        let Some(handle) = self.0.take() else {
            return Ok(false);
        };
        // SAFETY: take original ownership before the single close attempt; no
        // function/object can be used again through this now-closed owner.
        let code = unsafe { libc::dlclose(handle.as_ptr()) };
        if code == 0 {
            Ok(true)
        } else {
            Err(loader_error("dlclose libextractor"))
        }
    }
}
impl Drop for Library {
    fn drop(&mut self) {
        let _unobserved_cleanup = self.close();
    }
}

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
        let raw = $library.symbol($name).map_err(Failure::native)?;
        // SAFETY: named public libextractor symbol and its exact extractor.h C
        // signature. POSIX dlsym function pointers use this native ABI.
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
impl Provider {
    /// Open one explicit absolute native library and apply default plus original
    /// FS plugin configuration. None means only explicit extraction disablement.
    /// Every native admission uses the caller's same original hard/stop guard.
    pub fn open<E>(
        path: &Path,
        selection: Selection<'_>,
        limits: Limits,
        mut guard: impl FnMut() -> Result<(), E>,
    ) -> Result<Option<Self>, Failure<E>> {
        if selection == Selection::Disabled {
            return Ok(None);
        }
        limits.validate().map_err(Failure::native)?;
        if !path.is_absolute() {
            return Err(Failure::native(NativeError::Invalid(
                "absolute libextractor path",
            )));
        }
        let library_path = terminated(path.as_os_str().as_bytes(), limits.config_bytes)
            .map_err(Failure::native)?;
        let config = match selection {
            Selection::DefaultsWith(bytes) => {
                Some(terminated(bytes, limits.config_bytes).map_err(Failure::native)?)
            }
            _ => None,
        };
        guard().map_err(Failure::caller)?;
        let mut library = Library::open(&library_path).map_err(Failure::native)?;
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
                error.cleanup = library.close().err();
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
            Ok(()) => Ok(Some(provider)),
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

    pub(crate) fn extract_filename<E>(
        &mut self,
        name: &CStr,
        guard: &mut impl FnMut() -> Result<(), E>,
    ) -> Result<Extraction, Failure<E>> {
        self.run(name.as_ptr(), ptr::null(), 0, guard)
    }

    fn run<E, G: FnMut() -> Result<(), E>>(
        &mut self,
        filename: *const c_char,
        data: *const c_void,
        size: usize,
        guard: &mut G,
    ) -> Result<Extraction, Failure<E>> {
        if self.library.0.is_none() {
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
                callback::<G, E>,
                (&mut collected as *mut Collector<'_, G, E>).cast(),
            );
        }
        if let Some(error) = collected.failure.take() {
            return Err(error);
        }
        collected.check()?;
        Ok(Extraction {
            items: collected.items,
            callbacks: collected.callbacks,
            retained: collected.retained,
        })
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
        let closed = self.library.close()?;
        Ok(Cleanup {
            plugin_release_called: released,
            library_close_returned_zero: closed,
        })
    }
    /// Clock-free original cleanup. The void plugin release is a called fact;
    /// dlclose errors are retained and not called successful physical cleanup.
    pub fn close(mut self) -> Result<Cleanup, NativeError> {
        self.close_inner()
    }
}
impl Drop for Provider {
    fn drop(&mut self) {
        let _unobserved_cleanup = self.close_inner();
    }
}

pub(crate) fn readonly(file: &File) -> Result<(), NativeError> {
    // SAFETY: original borrowed File keeps this descriptor live throughout fcntl.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(NativeError::Io {
            operation: "read extraction source flags",
            source: std::io::Error::last_os_error(),
        });
    }
    if flags & libc::O_ACCMODE != libc::O_RDONLY {
        return Err(NativeError::Invalid("read-only extraction descriptor"));
    }
    Ok(())
}

struct Collector<'a, G, E> {
    guard: &'a mut G,
    limits: Limits,
    items: Vec<Item>,
    callbacks: usize,
    retained: usize,
    failure: Option<Failure<E>>,
}
impl<'a, G: FnMut() -> Result<(), E>, E> Collector<'a, G, E> {
    fn new(limits: Limits, guard: &'a mut G) -> Result<Self, NativeError> {
        let mut items = Vec::new();
        items
            .try_reserve_exact(limits.items)
            .map_err(|_| NativeError::Limit("metadata record allocation"))?;
        let retained = items
            .capacity()
            .checked_mul(std::mem::size_of::<Item>())
            .filter(|n| *n <= limits.output_bytes)
            .ok_or(NativeError::Limit("metadata record actual capacity"))?;
        Ok(Self {
            guard,
            limits,
            items,
            callbacks: 0,
            retained,
            failure: None,
        })
    }
    fn check(&mut self) -> Result<(), Failure<E>> {
        (self.guard)().map_err(Failure::caller)
    }
    fn push(
        &mut self,
        kind: c_int,
        format: c_int,
        plugin: Option<&[u8]>,
        mime: Option<&[u8]>,
        data: &[u8],
    ) -> Result<(), NativeError> {
        self.callbacks = self
            .callbacks
            .checked_add(1)
            .filter(|n| *n <= self.limits.callbacks)
            .ok_or(NativeError::Limit("metadata callbacks"))?;
        if self.items.len() >= self.limits.items || data.len() > self.limits.value_bytes {
            return Err(NativeError::Limit("metadata item/data extent"));
        }
        let kind =
            u32::try_from(kind).map_err(|_| NativeError::Invalid("negative metadata type"))?;
        let format = match format {
            1 => Format::Utf8,
            2 => Format::Binary,
            3 => Format::CString,
            _ => return Err(NativeError::Invalid("metadata format")),
        };
        let append = format != Format::Binary && data.last() != Some(&0);
        let item = Item {
            kind,
            format,
            plugin: plugin.map(|p| copy(p, false)).transpose()?,
            mime: mime.map(|m| copy(m, false)).transpose()?,
            data: copy(data, append)?,
        };
        let retained = self
            .retained
            .checked_add(
                item.retained()
                    .ok_or(NativeError::Limit("metadata arithmetic"))?,
            )
            .filter(|n| *n <= self.limits.output_bytes)
            .ok_or(NativeError::Limit("metadata actual retained capacity"))?;
        self.items.push(item);
        self.retained = retained;
        Ok(())
    }
}
fn copy(bytes: &[u8], append: bool) -> Result<Vec<u8>, NativeError> {
    let n = bytes
        .len()
        .checked_add(usize::from(append))
        .ok_or(NativeError::Limit("metadata copy extent"))?;
    let mut out = Vec::new();
    out.try_reserve_exact(n)
        .map_err(|_| NativeError::Limit("metadata payload allocation"))?;
    out.extend_from_slice(bytes);
    if append {
        out.push(0);
    }
    Ok(out)
}
unsafe fn name<'a>(raw: *const c_char, bound: usize) -> Result<Option<&'a [u8]>, NativeError> {
    if raw.is_null() {
        return Ok(None);
    }
    // SAFETY: libextractor's callback ABI supplies a valid NUL-terminated name.
    // The scan stops at that NUL and no unbounded CStr scan is used.
    let n = unsafe { libc::strnlen(raw, bound + 1) };
    if n > bound {
        return Err(NativeError::Limit("metadata name"));
    }
    // SAFETY: n bytes and its NUL are within the original callback string.
    Ok(Some(unsafe {
        std::slice::from_raw_parts(raw.cast(), n + 1)
    }))
}
unsafe extern "C" fn callback<G: FnMut() -> Result<(), E>, E>(
    cls: *mut c_void,
    plugin: *const c_char,
    kind: c_int,
    format: c_int,
    mime: *const c_char,
    data: *const c_char,
    len: usize,
) -> c_int {
    // SAFETY: run passes this exact live stack collector for one synchronous
    // IN_PROCESS extraction. Native pointers are borrowed only inside this call.
    let state = unsafe { &mut *cls.cast::<Collector<'_, G, E>>() };
    if state.failure.is_some() {
        return 1;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        state.check()?;
        if len > state.limits.value_bytes {
            return Err(Failure::native(NativeError::Limit(
                "metadata callback data extent",
            )));
        }
        if data.is_null() && len != 0 {
            return Err(Failure::native(NativeError::Invalid(
                "metadata callback data extent",
            )));
        }
        // SAFETY: native ABI guarantees exactly len readable original bytes;
        // policy checks precede constructing a slice. NULL/zero is handled.
        let data = if len == 0 {
            &[]
        } else {
            // SAFETY: the checked non-null ABI pointer has len readable bytes.
            unsafe { std::slice::from_raw_parts(data.cast(), len) }
        };
        // SAFETY: original callback names are live terminated ABI strings.
        let plugin = unsafe { name(plugin, state.limits.name_bytes) }.map_err(Failure::native)?;
        // SAFETY: same callback ABI, with NULL preserving an absent MIME.
        let mime = unsafe { name(mime, state.limits.name_bytes) }.map_err(Failure::native)?;
        state
            .push(kind, format, plugin, mime, data)
            .map_err(Failure::native)?;
        state.check()
    }));
    match result {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => {
            state.failure = Some(error);
            1
        }
        Err(payload) => {
            state.failure = Some(Failure::native(NativeError::CallbackPanicked(
                PanicPayload(payload),
            )));
            1
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Unexecuted pure callback-format/resource assertions return native setup failures directly"
)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    #[test]
    fn native_record_formats_keep_binary_zero_and_terminate_text() -> Result<(), NativeError> {
        let mut guard = || Ok::<(), Infallible>(());
        let mut records = Collector::new(Limits::default(), &mut guard)?;
        // These are extractor.h's actual public values, not renamed private
        // format IDs. Empty binary is valid; empty text still needs its NUL.
        records.push(4, 1, Some(b"title\0"), Some(b"text/plain\0"), b"title")?;
        records.push(45, 2, None, None, b"")?;
        records.push(13, 3, Some(b"legacy\0"), None, b"")?;
        assert_eq!(records.items[0].data, b"title\0");
        assert_eq!(records.items[1].format, Format::Binary);
        assert!(records.items[1].data.is_empty());
        assert_eq!(records.items[2].data, b"\0");
        assert_eq!(
            records.items[0].plugin.as_deref(),
            Some(b"title\0".as_slice())
        );
        assert_eq!(
            records.items[0].mime.as_deref(),
            Some(b"text/plain\0".as_slice())
        );
        Ok(())
    }

    #[test]
    fn own_limit_or_original_stop_never_returns_empty_observation() -> Result<(), NativeError> {
        let mut guard = || Err::<(), _>(17u32);
        let limits = Limits {
            items: 2,
            value_bytes: 4,
            ..Limits::default()
        };
        let mut records = Collector::new(limits, &mut guard)?;
        assert!(matches!(
            records.check(),
            Err(Failure {
                cause: crate::Cause::Caller(17),
                ..
            })
        ));
        records.push(4, 1, None, None, b"abc")?;
        let retained = records.retained;
        assert!(matches!(
            records.push(1, 2, None, None, b"too long"),
            Err(NativeError::Limit(_))
        ));
        assert_eq!(records.items.len(), 1);
        assert_eq!(records.retained, retained);
        assert!(matches!(
            Selection::from_fs(false, Some(b"-")),
            Selection::Disabled
        ));
        assert!(matches!(
            Selection::from_fs(false, Some(b"-mime:png")),
            Selection::DefaultsWith(b"-mime:png")
        ));
        Ok(())
    }
}
