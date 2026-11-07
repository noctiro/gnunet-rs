//! Sole standard POSIX loader/libpng1.6/libzbar ABI boundary.
use crate::{Cleanup, Error, Limits, ProviderFailure, Symbol};
use gnunet_types::Error as Fault;
use libc::{c_char, c_int, c_uint, c_ulong, c_void};
use std::{
    cell::Cell,
    ffi::{CStr, CString},
    ptr::{self, NonNull},
    rc::Rc,
};
#[cfg(any(target_os = "linux", target_os = "android"))]
#[link(name = "dl")]
unsafe extern "C" {}
struct Library {
    handle: NonNull<c_void>,
}
fn diagnostic(operation: &'static str, raw: *const c_char) -> Error {
    let bytes = if raw.is_null() {
        b"native loader supplied no diagnostic".as_slice()
    } else {
        // SAFETY: dlerror's original NUL-terminated thread-local diagnostic is
        // copied immediately before the next loader operation.
        unsafe { CStr::from_ptr(raw) }.to_bytes()
    };
    let n = bytes.len().min(1024);
    let mut detail = String::new();
    if detail.try_reserve_exact(n).is_err() {
        return Fault::Capacity.into();
    }
    for b in &bytes[..n] {
        detail.push(if b.is_ascii_graphic() || *b == b' ' {
            char::from(*b)
        } else {
            '?'
        });
    }
    Error::Loader {
        operation,
        detail,
        truncated: bytes.len() > n,
    }
}
impl Library {
    fn open(
        names: &[&CStr],
        operation: &'static str,
        before_native: &mut impl FnMut() -> Result<(), Error>,
    ) -> Result<Rc<Self>, Error> {
        let mut failure = None;
        for name in names {
            before_native()?;
            // SAFETY: fixed NUL-terminated standard provider name and POSIX flags.
            let raw = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
            if let Some(handle) = NonNull::new(raw) {
                return Ok(Rc::new(Self { handle }));
            }
            // SAFETY: read the actual current loader diagnostic before next call.
            failure = Some(diagnostic(operation, unsafe { libc::dlerror() }));
        }
        Err(failure.unwrap_or_else(|| Fault::Unavailable.into()))
    }
    fn symbol(
        &self,
        name: &CStr,
        before_native: &mut impl FnMut() -> Result<(), Error>,
    ) -> Result<*mut c_void, Error> {
        before_native()?;
        // SAFETY: same live library and a fixed NUL-terminated exported name.
        let (raw, error) = unsafe {
            let _old = libc::dlerror();
            let p = libc::dlsym(self.handle.as_ptr(), name.as_ptr());
            (p, libc::dlerror())
        };
        if raw.is_null() || !error.is_null() {
            Err(diagnostic("resolve standard QR provider symbol", error))
        } else {
            Ok(raw)
        }
    }
}
impl Drop for Library {
    fn drop(&mut self) {
        // SAFETY: final Rc follows every original native object/function use.
        let _actual = unsafe { libc::dlclose(self.handle.as_ptr()) };
    }
}
fn provider(name: &'static str, operation: &'static str, code: i32) -> Error {
    Error::Provider(ProviderFailure {
        provider: name,
        operation,
        code,
        detail: None,
    })
}
// Exact public libpng1.6 png_image ABI, version1, not an opaque private decoder.
#[repr(C)]
struct PngImage {
    opaque: *mut c_void,
    version: u32,
    width: u32,
    height: u32,
    format: u32,
    flags: u32,
    colormap: u32,
    warning: u32,
    message: [c_char; 64],
}
#[repr(C)]
struct PngColor {
    red: u8,
    green: u8,
    blue: u8,
}
type PngBegin = unsafe extern "C" fn(*mut PngImage, *const c_void, usize) -> c_int;
type PngFinish =
    unsafe extern "C" fn(*mut PngImage, *const PngColor, *mut c_void, i32, *mut c_void) -> c_int;
type PngFree = unsafe extern "C" fn(*mut PngImage);
struct PngApi {
    _library: Rc<Library>,
    begin: PngBegin,
    finish: PngFinish,
    free: PngFree,
}
macro_rules! bind {
    ($l:expr,$name:literal,$ty:ty,$guard:expr) => {{
        // SAFETY: each invocation binds the exact declared standard public C ABI;
        // original Rc library remains held by the API and all its native objects.
        unsafe { std::mem::transmute::<*mut c_void, $ty>($l.symbol($name, $guard)?) }
    }};
}
impl PngApi {
    fn load(before_native: &mut impl FnMut() -> Result<(), Error>) -> Result<Rc<Self>, Error> {
        #[cfg(target_os = "macos")]
        let names = [c"libpng16.16.dylib", c"libpng16.dylib", c"libpng.dylib"];
        #[cfg(not(target_os = "macos"))]
        let names = [c"libpng16.so.16", c"libpng16.so", c"libpng.so"];
        let l = Library::open(&names, "open standard libpng", before_native)?;
        Ok(Rc::new(Self {
            begin: bind!(
                l,
                c"png_image_begin_read_from_memory",
                PngBegin,
                before_native
            ),
            finish: bind!(l, c"png_image_finish_read", PngFinish, before_native),
            free: bind!(l, c"png_image_free", PngFree, before_native),
            _library: l,
        }))
    }
}
struct PngState {
    image: PngImage,
    api: Rc<PngApi>,
}
impl PngState {
    fn failure(&self, operation: &'static str) -> Error {
        let n = self
            .image
            .message
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(64);
        let mut detail = String::new();
        if detail.try_reserve_exact(n).is_err() {
            return Fault::Capacity.into();
        }
        for b in &self.image.message[..n] {
            let b = *b as u8;
            detail.push(if b.is_ascii_graphic() || b == b' ' {
                char::from(b)
            } else {
                '?'
            });
        }
        Error::Provider(ProviderFailure {
            provider: "libpng1.6",
            operation,
            code: self.image.warning as i32,
            detail: Some(detail),
        })
    }
}
impl Drop for PngState {
    fn drop(&mut self) {
        // SAFETY: initialized version1 image, including failed/finished reads;
        // the public function accepts NULL opaque and releases its own allocation.
        unsafe { (self.api.free)(&mut self.image) };
    }
}
type Create = unsafe extern "C" fn() -> *mut c_void;
type Destroy = unsafe extern "C" fn(*mut c_void);
type ScannerConfig = unsafe extern "C" fn(*mut c_void, c_int, c_int, c_int) -> c_int;
type Scan = unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int;
type ImageFormat = unsafe extern "C" fn(*mut c_void, c_ulong);
type ImageSize = unsafe extern "C" fn(*mut c_void, c_uint, c_uint);
type ImageData = unsafe extern "C" fn(
    *mut c_void,
    *const c_void,
    c_ulong,
    Option<unsafe extern "C" fn(*mut c_void)>,
);
type FirstSymbol = unsafe extern "C" fn(*const c_void) -> *const c_void;
type SymbolData = unsafe extern "C" fn(*const c_void) -> *const c_char;
type SymbolLength = unsafe extern "C" fn(*const c_void) -> c_uint;
type SymbolType = unsafe extern "C" fn(*const c_void) -> c_int;
type ProcessorCreate = unsafe extern "C" fn(c_int) -> *mut c_void;
type ProcessorInit = unsafe extern "C" fn(*mut c_void, *const c_char, c_int) -> c_int;
type ProcessorSize = unsafe extern "C" fn(*mut c_void, c_uint, c_uint) -> c_int;
type ProcessorFlag = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
type ProcessOne = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
type Results = unsafe extern "C" fn(*const c_void) -> *const c_void;
type ResultsRef = unsafe extern "C" fn(*const c_void, c_int);
type Dimension = unsafe extern "C" fn(*const c_void) -> c_uint;
type Handler = unsafe extern "C" fn(*mut c_void, *const c_void);
type SetHandler =
    unsafe extern "C" fn(*mut c_void, Option<Handler>, *const c_void) -> Option<Handler>;
struct ZbarApi {
    _library: Rc<Library>,
    scanner_create: Create,
    scanner_destroy: Destroy,
    scanner_config: ScannerConfig,
    scan: Scan,
    image_create: Create,
    image_destroy: Destroy,
    image_format: ImageFormat,
    image_size: ImageSize,
    image_data: ImageData,
    image_first: FirstSymbol,
    symbol_data: SymbolData,
    symbol_length: SymbolLength,
    symbol_type: SymbolType,
    processor_create: ProcessorCreate,
    processor_destroy: Destroy,
    processor_init: ProcessorInit,
    processor_size: ProcessorSize,
    processor_config: ScannerConfig,
    processor_visible: ProcessorFlag,
    processor_active: ProcessorFlag,
    process_one: ProcessOne,
    results: Results,
    results_first: FirstSymbol,
    results_ref: ResultsRef,
    image_width: Dimension,
    image_height: Dimension,
    set_handler: SetHandler,
}
impl ZbarApi {
    fn load(before_native: &mut impl FnMut() -> Result<(), Error>) -> Result<Rc<Self>, Error> {
        #[cfg(target_os = "macos")]
        let names = [c"libzbar.0.dylib", c"libzbar.dylib"];
        #[cfg(not(target_os = "macos"))]
        let names = [c"libzbar.so.0", c"libzbar.so"];
        let l = Library::open(&names, "open standard libzbar", before_native)?;
        Ok(Rc::new(Self {
            scanner_create: bind!(l, c"zbar_image_scanner_create", Create, before_native),
            scanner_destroy: bind!(l, c"zbar_image_scanner_destroy", Destroy, before_native),
            scanner_config: bind!(
                l,
                c"zbar_image_scanner_set_config",
                ScannerConfig,
                before_native
            ),
            scan: bind!(l, c"zbar_scan_image", Scan, before_native),
            image_create: bind!(l, c"zbar_image_create", Create, before_native),
            image_destroy: bind!(l, c"zbar_image_destroy", Destroy, before_native),
            image_format: bind!(l, c"zbar_image_set_format", ImageFormat, before_native),
            image_size: bind!(l, c"zbar_image_set_size", ImageSize, before_native),
            image_data: bind!(l, c"zbar_image_set_data", ImageData, before_native),
            image_first: bind!(l, c"zbar_image_first_symbol", FirstSymbol, before_native),
            symbol_data: bind!(l, c"zbar_symbol_get_data", SymbolData, before_native),
            symbol_length: bind!(
                l,
                c"zbar_symbol_get_data_length",
                SymbolLength,
                before_native
            ),
            symbol_type: bind!(l, c"zbar_symbol_get_type", SymbolType, before_native),
            processor_create: bind!(l, c"zbar_processor_create", ProcessorCreate, before_native),
            processor_destroy: bind!(l, c"zbar_processor_destroy", Destroy, before_native),
            processor_init: bind!(l, c"zbar_processor_init", ProcessorInit, before_native),
            processor_size: bind!(
                l,
                c"zbar_processor_request_size",
                ProcessorSize,
                before_native
            ),
            processor_config: bind!(
                l,
                c"zbar_processor_set_config",
                ScannerConfig,
                before_native
            ),
            processor_visible: bind!(
                l,
                c"zbar_processor_set_visible",
                ProcessorFlag,
                before_native
            ),
            processor_active: bind!(
                l,
                c"zbar_processor_set_active",
                ProcessorFlag,
                before_native
            ),
            process_one: bind!(l, c"zbar_process_one", ProcessOne, before_native),
            results: bind!(l, c"zbar_processor_get_results", Results, before_native),
            results_first: bind!(
                l,
                c"zbar_symbol_set_first_symbol",
                FirstSymbol,
                before_native
            ),
            results_ref: bind!(l, c"zbar_symbol_set_ref", ResultsRef, before_native),
            image_width: bind!(l, c"zbar_image_get_width", Dimension, before_native),
            image_height: bind!(l, c"zbar_image_get_height", Dimension, before_native),
            set_handler: bind!(
                l,
                c"zbar_processor_set_data_handler",
                SetHandler,
                before_native
            ),
            _library: l,
        }))
    }
    fn symbol(&self, raw: *const c_void, limits: Limits) -> Result<Symbol, Error> {
        if raw.is_null() {
            return Err(Error::NoSymbol);
        }
        // SAFETY: raw is the first result borrowed from the still-owned image or
        // incremented result set. No scan/recycle occurs until this copy finishes.
        let (length, data, kind) = unsafe {
            (
                (self.symbol_length)(raw),
                (self.symbol_data)(raw),
                (self.symbol_type)(raw),
            )
        };
        let length = usize::try_from(length).map_err(|_| Fault::Overflow)?;
        if length == 0 || length > limits.symbol_bytes {
            return Err(Fault::TooLarge.into());
        }
        if data.is_null() {
            return Err(Fault::Malformed.into());
        }
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(length)
            .map_err(|_| Fault::Capacity)?;
        if owned.capacity() > limits.symbol_bytes {
            return Err(Fault::Capacity.into());
        }
        // SAFETY: the public length excludes terminator and covers this original
        // provider-owned result. Library owner remains alive throughout copying.
        owned.extend_from_slice(unsafe { std::slice::from_raw_parts(data.cast::<u8>(), length) });
        Ok(Symbol { data: owned, kind })
    }
}
struct ZObject {
    raw: NonNull<c_void>,
    destroy: Destroy,
    _api: Rc<ZbarApi>,
}
impl Drop for ZObject {
    fn drop(&mut self) {
        // SAFETY: each handle came from its matching public constructor and is
        // destroyed exactly once while the function/library owner remains held.
        unsafe { (self.destroy)(self.raw.as_ptr()) };
    }
}
/// Decode an actual complete PNG to bounded grayscale then scan it with ZBar.
/// No fabricated symbol, GNUnet C call, background decoder or device is used.
pub fn scan_png(
    input: &[u8],
    limits: Limits,
    before_native: &mut impl FnMut() -> Result<(), Error>,
) -> Result<Symbol, Error> {
    limits.validate()?;
    if input.is_empty() || input.len() > limits.encoded_bytes {
        return Err(Fault::TooLarge.into());
    }
    before_native()?;
    let png = PngApi::load(before_native)?;
    before_native()?;
    let mut state = PngState {
        api: png,
        image: PngImage {
            opaque: ptr::null_mut(),
            version: 1,
            width: 0,
            height: 0,
            format: 0,
            flags: 0,
            colormap: 0,
            warning: 0,
            message: [0; 64],
        },
    };
    // SAFETY: version1 initialized image and original input slice remain alive
    // until finish/free; the length matches the readable borrowed storage.
    let began = unsafe { (state.api.begin)(&mut state.image, input.as_ptr().cast(), input.len()) };
    if began == 0 {
        return Err(state.failure("begin_read_from_memory"));
    }
    before_native()?;
    let length = limits.image(state.image.width, state.image.height)?;
    // Ask the public simplified API for grayscale+alpha, then strip alpha in
    // place like C's png_set_strip_alpha. Compositing transparent code pixels
    // onto a new background would change which actual symbol can be decoded.
    let storage = length.checked_mul(2).ok_or(Fault::Overflow)?;
    let storage_limit = limits.pixels.checked_mul(2).ok_or(Fault::Overflow)?;
    let mut pixels = Vec::new();
    pixels
        .try_reserve_exact(storage)
        .map_err(|_| Fault::Capacity)?;
    if pixels.capacity() > storage_limit {
        return Err(Fault::Capacity.into());
    }
    pixels.resize(storage, 0);
    state.image.format = 1; // PNG_FORMAT_GA; background is ignored with alpha kept.
    let white = PngColor {
        red: 255,
        green: 255,
        blue: 255,
    };
    before_native()?;
    // SAFETY: public GA byte output has two bytes per checked pixel.
    // Row stride0 selects tightly packed rows, no colormap output is requested.
    let finished = unsafe {
        (state.api.finish)(
            &mut state.image,
            &white,
            pixels.as_mut_ptr().cast(),
            0,
            ptr::null_mut(),
        )
    };
    if finished == 0 {
        return Err(state.failure("finish_read grayscale"));
    }
    before_native()?;
    for i in 0..length {
        if i % 4096 == 0 {
            before_native()?;
        }
        pixels[i] = pixels[i * 2];
    }
    pixels.truncate(length);
    before_native()?;
    let api = ZbarApi::load(before_native)?;
    before_native()?;
    // SAFETY: standard no-argument native constructors; NULL is an actual refusal.
    let scanner_raw = unsafe { (api.scanner_create)() };
    let scanner = ZObject {
        raw: NonNull::new(scanner_raw)
            .ok_or_else(|| provider("ZBar", "image_scanner_create", 0))?,
        destroy: api.scanner_destroy,
        _api: api.clone(),
    };
    before_native()?;
    // SAFETY: enable all actual supported public symbologies with CFG_ENABLE0.
    let configured = unsafe { (api.scanner_config)(scanner.raw.as_ptr(), 0, 0, 1) };
    if configured != 0 {
        return Err(provider(
            "ZBar",
            "image_scanner_set_config enable",
            configured,
        ));
    }
    before_native()?;
    // SAFETY: the standard constructor returns a separately owned image.
    let image_raw = unsafe { (api.image_create)() };
    let image = ZObject {
        raw: NonNull::new(image_raw).ok_or_else(|| provider("ZBar", "image_create", 0))?,
        destroy: api.image_destroy,
        _api: api.clone(),
    };
    // SAFETY: Y800 is the standard fourcc, checked dimensions match the original
    // grayscale slice. NULL cleanup keeps Rust's pixels owned until both native
    // image and scanner are destroyed below (also on any early return).
    unsafe {
        (api.image_format)(image.raw.as_ptr(), 0x3030_3859);
        (api.image_size)(image.raw.as_ptr(), state.image.width, state.image.height);
        (api.image_data)(
            image.raw.as_ptr(),
            pixels.as_ptr().cast(),
            c_ulong::try_from(length).map_err(|_| Fault::Overflow)?,
            None,
        );
    }
    before_native()?;
    // SAFETY: scanner/image/pixels are all original live owners, no native worker.
    let found = unsafe { (api.scan)(scanner.raw.as_ptr(), image.raw.as_ptr()) };
    if found < 0 {
        return Err(provider("ZBar", "scan_image", found));
    }
    before_native()?;
    if found == 0 {
        return Err(Error::NoSymbol);
    }
    // SAFETY: borrow first symbol only until its owned copy below is complete.
    let first = unsafe { (api.image_first)(image.raw.as_ptr()) };
    let result = api.symbol(first, limits);
    drop(image);
    drop(scanner);
    drop(pixels);
    result
}
struct Observation {
    limits: Limits,
    width: Cell<u32>,
    height: Cell<u32>,
    too_large: Cell<bool>,
    get_width: Dimension,
    get_height: Dimension,
}
unsafe extern "C" fn observe_image(image: *mut c_void, user: *const c_void) {
    if image.is_null() || user.is_null() {
        return;
    }
    // SAFETY: the original stable Box is registered only on a nonthreaded0
    // processor; callback is unregistered before the Box or its API can drop.
    let observation = unsafe { &*user.cast::<Observation>() };
    // SAFETY: ZBar invokes this callback with its actual still-owned image.
    let (width, height) = unsafe {
        (
            (observation.get_width)(image),
            (observation.get_height)(image),
        )
    };
    observation.width.set(width);
    observation.height.set(height);
    if observation.limits.image(width, height).is_err() {
        observation.too_large.set(true);
    }
}
struct ResultSet {
    raw: NonNull<c_void>,
    api: Rc<ZbarApi>,
}
impl Drop for ResultSet {
    fn drop(&mut self) {
        // SAFETY: processor_get_results increments exactly this result reference;
        // this owner's only release decrements it after copying/failed admission.
        unsafe { (self.api.results_ref)(self.raw.as_ptr(), -1) };
    }
}
/// Actual explicitly selected native camera. Threading is disabled; each step
/// calls the standard finite-time processor on this caller's thread only.
#[must_use = "explicitly close and inspect native deactivation/display failures"]
pub struct Camera {
    api: Rc<ZbarApi>,
    raw: Option<NonNull<c_void>>,
    observation: Box<Observation>,
    limits: Limits,
    display: bool,
}
impl Camera {
    /// Open the actual selected device and optional display; provider absence or
    /// unavailable platform/device is an original error, never simulated input.
    pub fn open(
        device: &CStr,
        display: bool,
        limits: Limits,
        before_native: &mut impl FnMut() -> Result<(), Error>,
    ) -> Result<Self, Error> {
        limits.validate()?;
        before_native()?;
        let api = ZbarApi::load(before_native)?;
        before_native()?;
        // SAFETY: threaded0 disables provider background processing.
        let raw = unsafe { (api.processor_create)(0) };
        let raw = NonNull::new(raw).ok_or_else(|| provider("ZBar", "processor_create", 0))?;
        let observation = Box::new(Observation {
            limits,
            width: Cell::new(0),
            height: Cell::new(0),
            too_large: Cell::new(false),
            get_width: api.image_width,
            get_height: api.image_height,
        });
        let mut camera = Self {
            api,
            raw: Some(raw),
            observation,
            limits,
            display,
        };
        let result = (|| {
            before_native()?;
            // SAFETY: supported ENABLE control, actual original processor.
            let configured = unsafe { (camera.api.processor_config)(raw.as_ptr(), 0, 0, 1) };
            if configured != 0 {
                return Err(provider("ZBar", "processor_set_config enable", configured));
            }
            before_native()?;
            // SAFETY: public preferred-size request before initialization.
            let sized = unsafe {
                (camera.api.processor_size)(raw.as_ptr(), limits.camera_width, limits.camera_height)
            };
            if sized != 0 {
                return Err(provider("ZBar", "processor_request_size", sized));
            }
            before_native()?;
            // SAFETY: actual CStr device name; caller explicitly chose display.
            let initialized = unsafe {
                (camera.api.processor_init)(raw.as_ptr(), device.as_ptr(), c_int::from(display))
            };
            if initialized != 0 {
                return Err(provider(
                    "ZBar",
                    "processor_init device/display",
                    initialized,
                ));
            }
            before_native()?;
            // SAFETY: stable Box outlives all callbacks, nonthreaded processor;
            // callback performs only checked observations, no allocation/panic.
            let _old = unsafe {
                (camera.api.set_handler)(
                    raw.as_ptr(),
                    Some(observe_image),
                    (&*camera.observation as *const Observation).cast(),
                )
            };
            if display {
                before_native()?;
                // SAFETY: standard visible flag on this actual initialized owner.
                let visible = unsafe { (camera.api.processor_visible)(raw.as_ptr(), 1) };
                if visible != 0 {
                    return Err(provider("ZBar", "processor_set_visible", visible));
                }
            }
            before_native()?;
            // SAFETY: actual initialized original video processor.
            let active = unsafe { (camera.api.processor_active)(raw.as_ptr(), 1) };
            if active != 0 {
                return Err(provider("ZBar", "processor_set_active", active));
            }
            before_native()?;
            Ok(())
        })();
        if let Err(error) = result {
            let cleanup = camera.close();
            if !cleanup.is_clean() {
                return Err(Error::Acquisition {
                    original: Box::new(error),
                    cleanup: Box::new(cleanup),
                });
            }
            return Err(error);
        }
        Ok(camera)
    }
    /// Scan one finite provider interval. Timeout is None, not a negative lookup
    /// or successful URI. Returned original result bytes are bounded and copied.
    pub fn step(
        &mut self,
        before_native: &mut impl FnMut() -> Result<(), Error>,
    ) -> Result<Option<Symbol>, Error> {
        let raw = self.raw.ok_or(Fault::Closed)?;
        before_native()?;
        // SAFETY: actual original nonthreaded processor and finite1..100ms timeout.
        let code =
            unsafe { (self.api.process_one)(raw.as_ptr(), self.limits.camera_poll_ms as c_int) };
        if code < 0 {
            return Err(provider("ZBar", "process_one camera", code));
        }
        before_native()?;
        if self.observation.too_large.get() {
            return Err(Fault::TooLarge.into());
        }
        if code == 0 {
            return Ok(None);
        }
        self.limits
            .image(self.observation.width.get(), self.observation.height.get())?;
        // SAFETY: this public getter returns one incremented result-set reference.
        let results = unsafe { (self.api.results)(raw.as_ptr()) };
        let Some(raw) = NonNull::new(results.cast_mut()) else {
            return Err(Fault::Malformed.into());
        };
        let result = ResultSet {
            raw,
            api: self.api.clone(),
        };
        // SAFETY: first symbol remains borrowed from this owned result set.
        let first = unsafe { (self.api.results_first)(result.raw.as_ptr()) };
        let symbol = self.api.symbol(first, self.limits)?;
        before_native()?;
        Ok(Some(symbol))
    }
    /// Clock-free native deactivation/display close/destroy of this exact camera.
    /// Library destruction has no status and does not prove device hardware exit.
    pub fn close(&mut self) -> Cleanup {
        let Some(raw) = self.raw.take() else {
            return Cleanup::default();
        };
        // SAFETY: retire callback before its Box, then actual original processor;
        // cleanup is allowed after any business clock/signal failure.
        let (deactivate, display) = unsafe {
            let _old = (self.api.set_handler)(raw.as_ptr(), None, ptr::null());
            let a = (self.api.processor_active)(raw.as_ptr(), 0);
            let b = if self.display {
                (self.api.processor_visible)(raw.as_ptr(), 0)
            } else {
                0
            };
            (self.api.processor_destroy)(raw.as_ptr());
            (a, b)
        };
        Cleanup {
            deactivate: (deactivate != 0).then_some(ProviderFailure {
                provider: "ZBar",
                operation: "processor_set_active close",
                code: deactivate,
                detail: None,
            }),
            display: (display != 0).then_some(ProviderFailure {
                provider: "ZBar",
                operation: "processor_set_visible close",
                code: display,
                detail: None,
            }),
        }
    }
    /// Copy a native device name with an explicit no-NUL, finite byte contract.
    pub fn device(bytes: &[u8]) -> Result<CString, Error> {
        if bytes.is_empty() || bytes.len() > 4096 {
            return Err(Fault::TooLarge.into());
        }
        CString::new(bytes).map_err(|_| Fault::InvalidInput.into())
    }
}
impl Drop for Camera {
    fn drop(&mut self) {
        let _actual = self.close();
    }
}
