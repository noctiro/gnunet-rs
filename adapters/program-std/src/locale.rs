//! Exact, explicitly selected standard gettext platform boundary.
//! No GNUnet implementation/library is loaded. Catalog parsing, locale aliases
//! and charset conversion are delegated to the actual selected gettext backend;
//! Rust retains ownership, copies native strings and formats arguments safely.
use crate::program::{Failure, LocaleSetup};
use gnunet_config::{Installation, PathKind, ProcessEnvironment, ProjectData};
use std::{
    ffi::{CStr, CString},
    io,
    marker::PhantomData,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
};
/// Explicit standard backend ABI. Choosing names cannot validate an arbitrary
/// binary: load's unsafe contract requires the actual trusted implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbiProfile {
    /// GNU libintl exported libintl_* symbols, including its setlocale wrapper.
    Libintl,
    /// Standard unprefixed gettext symbols and native setlocale, e.g. glibc.
    Libc,
}
/// Owned translation port, shared by explicit Rc clones within this process
/// context. No returned byte view can outlive a library handle.
pub trait Translations {
    /// None uses current textdomain; Some selects dgettext's explicit domain.
    fn gettext(&self, domain: Option<&[u8]>, message: &[u8]) -> io::Result<Vec<u8>>;
    /// Exact ngettext/dngettext operation. Count must fit native unsigned long.
    fn ngettext(
        &self,
        domain: Option<&[u8]>,
        singular: &[u8],
        plural: &[u8],
        count: u64,
    ) -> io::Result<Vec<u8>>;
}
struct Disabled;
impl Translations for Disabled {
    fn gettext(&self, _: Option<&[u8]>, message: &[u8]) -> io::Result<Vec<u8>> {
        Ok(prefix(message).to_vec())
    }
    fn ngettext(
        &self,
        _: Option<&[u8]>,
        singular: &[u8],
        plural: &[u8],
        count: u64,
    ) -> io::Result<Vec<u8>> {
        Ok(prefix(if count == 1 { singular } else { plural }).to_vec())
    }
}
/// Explicit ENABLE_NLS=0 translation profile; no native locale call or fallback
/// from an enabled backend error is performed by this operation.
#[must_use]
pub fn disabled() -> Rc<dyn Translations> {
    Rc::new(Disabled)
}
fn prefix(value: &[u8]) -> &[u8] {
    &value[..value.iter().position(|&b| b == 0).unwrap_or(value.len())]
}
fn cstring(value: &[u8]) -> io::Result<CString> {
    CString::new(prefix(value)).map_err(io::Error::other)
}
type SetLocale = unsafe extern "C" fn(libc::c_int, *const libc::c_char) -> *mut libc::c_char;
type Domain = unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_char;
type Bind = unsafe extern "C" fn(*const libc::c_char, *const libc::c_char) -> *mut libc::c_char;
type Get = unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_char;
type DGet = unsafe extern "C" fn(*const libc::c_char, *const libc::c_char) -> *mut libc::c_char;
type NGet = unsafe extern "C" fn(
    *const libc::c_char,
    *const libc::c_char,
    libc::c_ulong,
) -> *mut libc::c_char;
type DNGet = unsafe extern "C" fn(
    *const libc::c_char,
    *const libc::c_char,
    *const libc::c_char,
    libc::c_ulong,
) -> *mut libc::c_char;
static CLAIMED: AtomicBool = AtomicBool::new(false);
struct Lease;
impl Drop for Lease {
    fn drop(&mut self) {
        CLAIMED.store(false, Ordering::Release);
    }
}
struct Library(*mut libc::c_void);
impl Library {
    fn open(path: &Path) -> io::Result<Self> {
        let path = CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)?;
        #[expect(
            unsafe_code,
            reason = "Unsafe outer constructor requires a trusted standard backend and exclusive early native initialization"
        )]
        // SAFETY: C path is live, flags are valid and selected binary trust is a caller precondition.
        let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if handle.is_null() {
            return Err(io::Error::other(
                "selected gettext library could not be loaded",
            ));
        }
        Ok(Self(handle))
    }
    fn symbol(&self, name: &CStr) -> io::Result<*mut libc::c_void> {
        #[expect(
            unsafe_code,
            reason = "Live loaded handle and static NUL-terminated symbol name, with no retained borrowed name"
        )]
        // SAFETY: this Library keeps its successful dlopen handle live through the call.
        let ptr = unsafe { libc::dlsym(self.0, name.as_ptr()) };
        if ptr.is_null() {
            return Err(io::Error::other(format!(
                "selected gettext ABI is missing {}",
                name.to_string_lossy()
            )));
        }
        Ok(ptr)
    }
}
impl Drop for Library {
    fn drop(&mut self) {
        #[expect(
            unsafe_code,
            reason = "Library is the unique owner of one successful dlopen reference and all copied symbols drop before this release"
        )]
        // SAFETY: this exact successful dlopen reference has not previously been closed.
        let status = unsafe { libc::dlclose(self.0) };
        if status != 0 { /* Drop cannot report loader failure. */ }
    }
}
struct Backend {
    setlocale: SetLocale,
    textdomain: Domain,
    bindtextdomain: Bind,
    gettext: Get,
    dgettext: DGet,
    ngettext: NGet,
    dngettext: DNGet,
    // Every function/string operation borrows Backend, retaining this handle.
    _library: Library,
    _lease: Lease,
    _thread: PhantomData<Rc<()>>,
}
fn copy_native(ptr: *const libc::c_char) -> io::Result<Vec<u8>> {
    if ptr.is_null() {
        return Err(io::Error::other("gettext backend returned NULL"));
    }
    #[expect(
        unsafe_code,
        reason = "Only a trusted standard gettext ABI supplies this nonnull NUL-terminated string; each caller retains Backend through its immediate copy"
    )]
    // SAFETY: the selected native API promises a live C string for the duration of this synchronous call.
    Ok(unsafe { CStr::from_ptr(ptr) }.to_bytes().to_vec())
}
impl Translations for Backend {
    fn gettext(&self, domain: Option<&[u8]>, message: &[u8]) -> io::Result<Vec<u8>> {
        let message = cstring(message)?;
        #[expect(
            unsafe_code,
            reason = "Explicit standard ABI, live input C strings and retained owning backend; no pointer escapes the immediate copy"
        )]
        // SAFETY: function signatures are validated by the unsafe trusted-library contract.
        let ptr = unsafe {
            match domain {
                None => (self.gettext)(message.as_ptr()),
                Some(domain) => {
                    let domain = cstring(domain)?;
                    (self.dgettext)(domain.as_ptr(), message.as_ptr())
                }
            }
        };
        copy_native(ptr)
    }
    fn ngettext(
        &self,
        domain: Option<&[u8]>,
        singular: &[u8],
        plural: &[u8],
        count: u64,
    ) -> io::Result<Vec<u8>> {
        let singular = cstring(singular)?;
        let plural = cstring(plural)?;
        let count = libc::c_ulong::try_from(count).map_err(io::Error::other)?;
        #[expect(
            unsafe_code,
            reason = "Trusted standard ngettext ABI with native-width count, live inputs and retained backend library"
        )]
        // SAFETY: no callback or native pointer is retained; returned storage is copied synchronously.
        let ptr = unsafe {
            match domain {
                None => (self.ngettext)(singular.as_ptr(), plural.as_ptr(), count),
                Some(domain) => {
                    let domain = cstring(domain)?;
                    (self.dngettext)(domain.as_ptr(), singular.as_ptr(), plural.as_ptr(), count)
                }
            }
        };
        copy_native(ptr)
    }
}
/// Actual enabled locale installation observations. A rejected environment
/// retains the prior locale as in C; this is observable rather than fake English.
#[derive(Clone, Debug)]
pub struct InstallationResult {
    /// Actual setlocale(LC_ALL,"") outcome.
    pub environment_selected: bool,
    /// Native LC_MESSAGES after the attempt.
    pub messages_locale: Vec<u8>,
    /// Actual textdomain result after selecting the project's domain.
    pub domain: Vec<u8>,
    /// Path actually bound, or None when the source skips bindtextdomain.
    pub bound_directory: Option<PathBuf>,
}
/// Early/exclusive locale capability. Rc translation clones retain the native
/// handle AND this capability's gate even after ProcessLocale itself is dropped.
pub struct ProcessLocale {
    backend: Rc<Backend>,
    path: PathBuf,
    profile: AbiProfile,
    result: Option<InstallationResult>,
    cases: gnunet_config::CaseContext,
    native_thread: gnunet_config::ThreadLocale,
}
impl ProcessLocale {
    /// Load one caller-selected trusted standard gettext backend.
    ///
    /// # Safety
    /// If path can be loaded, the caller must ensure it is a trusted native
    /// implementation exporting the exact selected standard ABI (including
    /// function-pointer calling conventions), compatible with this process/libc.
    /// A definitely absent path may be supplied to observe the ordinary loader
    /// error; no native object or function can be used on that failed path. During load's native backend setup and every configure, all unrelated
    /// thread, foreign locale/gettext user and environment mutator must be quiescent.
    /// No other code may unload this backend or invalidate its returned strings.
    /// Translation string obligations last until all translation Rc clones are
    /// dropped. Native locale read/effect exclusion additionally lasts until all
    /// retained CaseContext/configuration clones are dropped, including use on
    /// other threads: do not mutate global locale concurrently with those calls.
    /// Sequential explicit changes under exclusive authority are allowed. The
    /// gate cannot establish whole-process exclusivity or binary trust.
    #[expect(
        unsafe_code,
        reason = "Dynamic standard platform ABI and process-global locale authority require explicit caller trust/exclusivity"
    )]
    pub unsafe fn load(path: PathBuf, profile: AbiProfile) -> io::Result<Self> {
        CLAIMED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| io::Error::other("locale capability already held"))?;
        let lease = Lease;
        let library = Library::open(&path)?;
        let names = match profile {
            AbiProfile::Libintl => [
                c"libintl_setlocale",
                c"libintl_textdomain",
                c"libintl_bindtextdomain",
                c"libintl_gettext",
                c"libintl_dgettext",
                c"libintl_ngettext",
                c"libintl_dngettext",
            ],
            AbiProfile::Libc => [
                c"setlocale",
                c"textdomain",
                c"bindtextdomain",
                c"gettext",
                c"dgettext",
                c"ngettext",
                c"dngettext",
            ],
        };
        let mut symbols = [std::ptr::null_mut(); 7];
        for (i, name) in names.into_iter().enumerate() {
            symbols[i] = library.symbol(name)?;
        }
        #[expect(
            unsafe_code,
            reason = "POSIX dlsym function-address conversion is used only under the explicit trusted ABI profile precondition"
        )]
        // SAFETY: the caller certifies these exact signatures; Library remains owned by Backend.
        let backend = unsafe {
            Backend {
                setlocale: std::mem::transmute::<*mut libc::c_void, SetLocale>(symbols[0]),
                textdomain: std::mem::transmute::<*mut libc::c_void, Domain>(symbols[1]),
                bindtextdomain: std::mem::transmute::<*mut libc::c_void, Bind>(symbols[2]),
                gettext: std::mem::transmute::<*mut libc::c_void, Get>(symbols[3]),
                dgettext: std::mem::transmute::<*mut libc::c_void, DGet>(symbols[4]),
                ngettext: std::mem::transmute::<*mut libc::c_void, NGet>(symbols[5]),
                dngettext: std::mem::transmute::<*mut libc::c_void, DNGet>(symbols[6]),
                _library: library,
                _lease: lease,
                _thread: PhantomData,
            }
        };
        // SAFETY: load's caller guarantees the synchronous native read/effect
        // contract, including every retained configuration/context clone.
        let native_thread = unsafe { gnunet_config::ThreadLocale::acquire()? };
        let cases = gnunet_config::CaseContext::current_thread(native_thread.clone());
        Ok(Self {
            backend: Rc::new(backend),
            cases,
            native_thread,
            path,
            profile,
            result: None,
        })
    }
    /// Caller-selected shared comparison context. Attach configurations before
    /// cloning them when they must all follow later configure publications.
    #[must_use]
    pub fn case_context(&self) -> gnunet_config::CaseContext {
        self.cases.clone()
    }
    /// Use one existing caller-owned context for later native locale selections.
    /// Existing cfg/duplicate values sharing it are compared in place.
    pub fn bind_case_context(&mut self, context: gnunet_config::CaseContext) {
        let current = self.cases.snapshot();
        drop(context.replace(current));
        self.cases = context;
    }
    /// Last actual enabled installation record.
    #[must_use]
    pub fn result(&self) -> Option<&InstallationResult> {
        self.result.as_ref()
    }
    /// Selected trusted library identity, to bind separately in deployment/proofs.
    #[must_use]
    pub fn library(&self) -> (&Path, AbiProfile) {
        (&self.path, self.profile)
    }
    /// Actual gettext operations retain the backend even if the installer drops.
    #[must_use]
    pub fn translations(&self) -> Rc<dyn Translations> {
        self.backend.clone()
    }
}
impl LocaleSetup for ProcessLocale {
    fn case_context(&self) -> Option<gnunet_config::CaseContext> {
        Some(self.cases.clone())
    }
    fn configure(&mut self, project: &ProjectData) -> Result<(), Failure> {
        let Some(domain) = project.gettext_domain.as_deref() else {
            return Ok(());
        };
        #[expect(
            unsafe_code,
            reason = "Exclusive early capability and trusted backend; empty static C string requests native environment locale"
        )]
        // SAFETY: this call obeys ProcessLocale::load's continuing exclusive-native contract.
        let selected = unsafe { !(self.backend.setlocale)(libc::LC_ALL, c"".as_ptr()).is_null() };
        // Publish the actual current-thread capability. A prior source CONFIG
        // float failure can leave a mixed thread locale installed, so a global
        // setlocale alone must not falsely replace it with a snapshot of global.
        drop(
            self.cases
                .replace(gnunet_config::CaseSnapshot::CurrentThread(
                    self.native_thread.clone(),
                )),
        );

        #[expect(
            unsafe_code,
            reason = "The live backend and exclusive capability keep query results valid through their immediate copy"
        )]
        // SAFETY: null second argument queries this native category rather than changing it.
        let messages_locale =
            copy_native(unsafe { (self.backend.setlocale)(libc::LC_MESSAGES, std::ptr::null()) })?;
        let directory = if let Some(path) = &project.gettext_path {
            Some(path.clone())
        } else {
            Installation::discover(project, &ProcessEnvironment)?
                .path(PathKind::Localedir)
                .map(Path::to_path_buf)
        };
        let domain = cstring(domain)?;
        if let Some(path) = &directory {
            let path = CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)?;
            #[expect(
                unsafe_code,
                reason = "Trusted bindtextdomain ABI receives live domain/path strings, copied/retained by the actual native backend"
            )]
            // SAFETY: native bindtextdomain does not borrow either input after returning.
            copy_native(unsafe { (self.backend.bindtextdomain)(domain.as_ptr(), path.as_ptr()) })?;
        }
        #[expect(
            unsafe_code,
            reason = "Live domain C string and trusted textdomain ABI; copy completes while Backend is retained"
        )]
        // SAFETY: textdomain retains its own copy, and the returned storage is copied immediately.
        let selected_domain = copy_native(unsafe { (self.backend.textdomain)(domain.as_ptr()) })?;
        self.result = Some(InstallationResult {
            environment_selected: selected,
            messages_locale,
            domain: selected_domain,
            bound_directory: directory,
        });
        Ok(())
    }
    fn translations(&self) -> Rc<dyn Translations> {
        ProcessLocale::translations(self)
    }
}
