//! Owned POSIX locale primitives. This module never installs a locale, changes
//! process/thread environment, or calls any GNUnet implementation. Snapshot
//! capture is an explicit unsafe read of caller-controlled native state.
use std::{
    ffi::CString,
    io,
    ptr::NonNull,
    sync::{Arc, RwLock},
};
#[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
#[expect(
    unsafe_code,
    reason = "Exact POSIX/Darwin declarations missing from the pinned libc crate; SDK headers and native comparison proof bind this ABI"
)]
unsafe extern "C" {
    fn strncasecmp_l(
        first: *const libc::c_char,
        second: *const libc::c_char,
        n: libc::size_t,
        locale: libc::locale_t,
    ) -> libc::c_int;
    fn isspace_l(value: libc::c_int, locale: libc::locale_t) -> libc::c_int;
    fn strtof_l(
        value: *const libc::c_char,
        end: *mut *mut libc::c_char,
        locale: libc::locale_t,
    ) -> libc::c_float;
    fn strtoull_l(
        value: *const libc::c_char,
        end: *mut *mut libc::c_char,
        base: libc::c_int,
        locale: libc::locale_t,
    ) -> libc::c_ulonglong;
}
#[cfg_attr(
    not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))),
    expect(
        dead_code,
        reason = "Unvalidated native ABI constructors return Unsupported, so private locale ownership cannot be created or read"
    )
)]
struct Handle(NonNull<libc::c_void>);
#[expect(
    unsafe_code,
    reason = "The private locale is immutable, never passed as a mutable newlocale base, and remains Arc/TLS-owned throughout every native read or installation"
)]
// SAFETY: POSIX *_l readers may share an immutable locale. No raw handle escapes,
// so no thread can mutate/free it; final Arc alone invokes Drop after TLS detaches any private installation.
unsafe impl Send for Handle {}
#[expect(
    unsafe_code,
    reason = "Immutable POSIX locale readers share this handle; final Arc Drop occurs only after every borrowed comparison/scan ends"
)]
// SAFETY: all public operations only read the locale; independent duplicated
// ownership prevents changes to the original global/thread locale from aliasing it.
unsafe impl Sync for Handle {}
impl Drop for Handle {
    fn drop(&mut self) {
        #[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
        #[expect(
            unsafe_code,
            reason = "One successful newlocale/duplocale result is uniquely owned by the final Arc; no pointer/function use remains live"
        )]
        // SAFETY: this is the exact private allocation returned by libc, never a
        // global/C sentinel; private TLS installation is detached before its owner releases the final Arc.
        unsafe {
            libc::freelocale(self.0.as_ptr());
        }
    }
}
/// Independent immutable native locale; Clone shares one owned allocation and
/// never duplicates/free-aliases a raw locale_t. No native pointer is exposed.
#[derive(Clone)]
pub struct LocaleSnapshot {
    #[cfg_attr(
        not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))),
        expect(
            dead_code,
            reason = "Native ownership is unreachable on unvalidated ABI targets, while pure C-byte contexts stay available"
        )
    )]
    handle: Arc<Handle>,
}
impl LocaleSnapshot {
    /// Load a named locale into an independent object. This may read native
    /// locale data. Empty names (implicit environment selection) and embedded NUL
    /// are explicit errors; use capture_current_thread for actual selected state.
    pub fn named(name: &[u8]) -> io::Result<Self> {
        if name.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "explicit locale name required",
            ));
        }
        let name = CString::new(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "locale name contains NUL"))?;
        #[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
        {
            #[expect(
                unsafe_code,
                reason = "LC_ALL_MASK and a live C-string name are valid; NULL base requests a fresh allocation and never mutates an existing locale"
            )]
            // SAFETY: libc copies/loads the supplied name synchronously and
            // returns new ownership; no process/thread locale is changed.
            let raw =
                unsafe { libc::newlocale(libc::LC_ALL_MASK, name.as_ptr(), std::ptr::null_mut()) };
            Self::owned(raw)
        }
        #[cfg(not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))))]
        {
            drop(name);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native locale ABI requires ordinary Darwin libc or glibc",
            ))
        }
    }
    /// Duplicate the calling thread's effective locale (which may select the
    /// process-global locale) into independent immutable ownership.
    ///
    /// # Safety
    /// During this call, the caller must keep every native mutator/free of the
    /// active thread/global locale quiescent. This API cannot establish that
    /// process-wide precondition. After success the owned snapshot needs no
    /// continuing borrow/quiescence of the original locale.
    #[expect(
        unsafe_code,
        reason = "Capturing native process/thread locale requires explicit external quiescence; successful duplocale creates independent ownership"
    )]
    pub unsafe fn capture_current_thread() -> io::Result<Self> {
        #[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
        {
            // SAFETY: NULL queries rather than changes the current thread's
            // locale. The caller keeps its selected/global native owner stable.
            let current = unsafe { libc::uselocale(std::ptr::null_mut()) };
            // SAFETY: current is the just-queried live locale or libc's valid
            // global sentinel; caller quiescence covers duplication.
            let raw = unsafe { libc::duplocale(current) };
            Self::owned(raw)
        }
        #[cfg(not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native locale ABI requires ordinary Darwin libc or glibc",
            ))
        }
    }
    #[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
    fn owned(raw: libc::locale_t) -> io::Result<Self> {
        let pointer = NonNull::new(raw).ok_or_else(io::Error::last_os_error)?;
        // POSIX global sentinel is never new owned storage; reject a violated
        // constructor contract instead of ever freeing process-global state.
        if pointer.as_ptr().addr() == usize::MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native locale constructor returned a global sentinel",
            ));
        }
        Ok(Self {
            handle: Arc::new(Handle(pointer)),
        })
    }
    /// Compare the C-string prefixes of bounded byte spans. Embedded NUL ends a
    /// prefix; unequal lengths cannot be equal after per-byte case translation.
    /// Empty spans are handled without any C call or NULL/dangling dereference.
    #[must_use]
    pub fn equals(&self, first: &[u8], second: &[u8]) -> bool {
        let first = prefix(first);
        let second = prefix(second);
        if first.len() != second.len() {
            return false;
        }
        if first.is_empty() {
            return true;
        }
        #[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
        {
            #[expect(
                unsafe_code,
                reason = "Both spans contain at least n live bytes, n is their checked equal prefix length, and the immutable private locale remains Arc-owned"
            )]
            // SAFETY: strncasecmp_l reads at most n bytes, retaining no pointer.
            // A terminating NUL beyond n is unnecessary for a bounded compare.
            unsafe {
                strncasecmp_l(
                    first.as_ptr().cast(),
                    second.as_ptr().cast(),
                    first.len(),
                    self.handle.0.as_ptr(),
                ) == 0
            }
        }
        #[cfg(not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))))]
        {
            false
        }
    }
    /// Exact native unsigned-byte isspace classification in this snapshot.
    #[must_use]
    pub fn is_space(&self, value: u8) -> bool {
        #[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
        {
            #[expect(
                unsafe_code,
                reason = "Every u8 converts to a valid unsigned-char ctype input; private immutable locale is live"
            )]
            // SAFETY: no signed negative char/invalid ctype domain is passed.
            unsafe {
                isspace_l(i32::from(value), self.handle.0.as_ptr()) != 0
            }
        }
        #[cfg(not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))))]
        {
            let _value = value;
            false
        }
    }
    /// Defined strtof_l conversion with exact consumption and ERANGE, unlike an
    /// unchecked scanf conversion whose mathematical result may not fit float.
    pub fn scan_float(&self, input: &[u8]) -> io::Result<FloatScan> {
        let source = c_string(input)?;
        #[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
        {
            let mut end = std::ptr::null_mut();
            let errno = Errno::clear();
            #[expect(
                unsafe_code,
                reason = "Live NUL-terminated input, valid end-pointer out slot and retained immutable locale; strtof_l defines overflow/underflow as ERANGE"
            )]
            // SAFETY: native conversion cannot write the input and retains no
            // input/end/locale pointer after this synchronous call.
            let value = unsafe { strtof_l(source.as_ptr(), &mut end, self.handle.0.as_ptr()) };
            let range_error = last_errno() == libc::ERANGE;
            drop(errno);
            Ok(FloatScan {
                value,
                consumed: consumed(&source, end)?,
                range_error,
            })
        }
        #[cfg(not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))))]
        {
            drop(source);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native locale ABI requires ordinary Darwin libc or glibc",
            ))
        }
    }
    /// Defined decimal strtoull_l conversion, preserving native whitespace/sign
    /// consumption while returning ERANGE separately from a representable value.
    pub fn scan_number(&self, input: &[u8]) -> io::Result<NumberScan> {
        let source = c_string(input)?;
        #[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
        {
            let mut end = std::ptr::null_mut();
            let errno = Errno::clear();
            #[expect(
                unsafe_code,
                reason = "Live C input/end slot and retained locale; base10 is valid and strtoull_l defines range failure"
            )]
            // SAFETY: the standard conversion owns no passed pointer.
            let value =
                unsafe { strtoull_l(source.as_ptr(), &mut end, 10, self.handle.0.as_ptr()) };
            let range_error = last_errno() == libc::ERANGE;
            drop(errno);
            Ok(NumberScan {
                value,
                consumed: consumed(&source, end)?,
                range_error,
            })
        }
        #[cfg(not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))))]
        {
            drop(source);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native locale ABI requires ordinary Darwin libc or glibc",
            ))
        }
    }
}
/// Standard conversion result; callers decide whether trailing data is allowed.
pub struct FloatScan {
    /// Native float value, including supported inf/NaN spellings.
    pub value: f32,
    /// Consumed byte count within the C-string prefix.
    pub consumed: usize,
    /// Native ERANGE; never permission to run an overflowing scanf oracle.
    pub range_error: bool,
}
/// Defined decimal unsigned conversion result.
pub struct NumberScan {
    /// Native converted unsigned long long value.
    pub value: u64,
    /// Consumed byte count within the C-string prefix.
    pub consumed: usize,
    /// Native ERANGE, distinct from no conversion or trailing data.
    pub range_error: bool,
}
fn prefix(input: &[u8]) -> &[u8] {
    &input[..input.iter().position(|&b| b == 0).unwrap_or(input.len())]
}
fn c_string(input: &[u8]) -> io::Result<CString> {
    let input = prefix(input);
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(
            input
                .len()
                .checked_add(1)
                .ok_or(io::ErrorKind::OutOfMemory)?,
        )
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    bytes.extend_from_slice(input);
    bytes.push(0);
    CString::from_vec_with_nul(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid owned C string"))
}
fn consumed(source: &CString, end: *mut libc::c_char) -> io::Result<usize> {
    let start = source.as_ptr().addr();
    let end = end.addr();
    let maximum = start
        .checked_add(source.as_bytes().len())
        .ok_or(io::ErrorKind::InvalidData)?;
    if end < start || end > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native end pointer outside input",
        ));
    }
    Ok(end - start)
}
#[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
struct Errno(i32);
#[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
fn last_errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}
#[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
fn set_errno(value: i32) {
    #[expect(
        unsafe_code,
        reason = "libc returns the current thread's live errno slot; only this synchronous native operation writes it"
    )]
    // SAFETY: the pointer is libc's thread-local errno storage.
    unsafe {
        #[cfg(target_os = "macos")]
        {
            *libc::__error() = value;
        }
        #[cfg(target_os = "linux")]
        {
            *libc::__errno_location() = value;
        }
    }
}
#[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
impl Errno {
    fn clear() -> Self {
        let old = Self(last_errno());
        set_errno(0);
        old
    }
}
#[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
impl Drop for Errno {
    fn drop(&mut self) {
        set_errno(self.0);
    }
}
/// Caller-selected immutable comparison profile. C is a pure, exact byte profile;
/// Native owns a real locale object rather than guessing Unicode folding rules.
#[derive(Clone)]
pub enum CaseSnapshot {
    /// C/POSIX case and whitespace rules, with no hidden locale/OS call.
    C,
    /// Exact selected native locale.
    Native(LocaleSnapshot),
    /// Explicit capability that reads this calling thread's actual native locale.
    CurrentThread(ThreadLocale),
}
impl CaseSnapshot {
    /// Compare bounded C-string prefixes under this one immutable selection.
    #[must_use]
    pub fn equals(&self, a: &[u8], b: &[u8]) -> bool {
        match self {
            Self::C => prefix(a).eq_ignore_ascii_case(prefix(b)),
            Self::Native(locale) => locale.equals(a, b),
            Self::CurrentThread(locale) => locale.equals(a, b),
        }
    }
    /// Exact unsigned-byte space classification; C includes vertical tab.
    #[must_use]
    pub fn is_space(&self, value: u8) -> bool {
        match self {
            Self::C => matches!(value, b' ' | b'\t'..=b'\r'),
            Self::Native(locale) => locale.is_space(value),
            Self::CurrentThread(locale) => locale.is_space(value),
        }
    }
    /// Trim according to this retained selection, without retaining input bytes.
    #[must_use]
    pub fn trim<'a>(&self, input: &'a [u8]) -> &'a [u8] {
        let start = input
            .iter()
            .position(|&v| !self.is_space(v))
            .unwrap_or(input.len());
        let end = input
            .iter()
            .rposition(|&v| !self.is_space(v))
            .map_or(start, |n| n + 1);
        &input[start..end]
    }
}
/// Explicit replaceable locale selection shared by caller-chosen configurations.
/// It does not automatically follow arbitrary external process/thread changes.
#[derive(Clone)]
pub struct CaseContext(Arc<RwLock<CaseSnapshot>>);
impl CaseContext {
    /// Independent pure C selection. This constructor performs no native IO.
    #[must_use]
    pub fn c() -> Self {
        Self(Arc::new(RwLock::new(CaseSnapshot::C)))
    }
    /// Share one actual immutable native selection.
    #[must_use]
    pub fn native(locale: LocaleSnapshot) -> Self {
        Self(Arc::new(RwLock::new(CaseSnapshot::Native(locale))))
    }
    /// Share one explicit native current-thread reader/effect capability. Its
    /// unsafe acquisition obligations remain live until all context clones drop.
    #[must_use]
    pub fn current_thread(locale: ThreadLocale) -> Self {
        Self(Arc::new(RwLock::new(CaseSnapshot::CurrentThread(locale))))
    }
    /// Retain a selection for an entire comparison/scan operation. Recovery from
    /// poisoning is valid: writers only atomically swap a fully valid enum and
    /// never execute user/native Drop code while holding the lock.
    #[must_use]
    pub fn snapshot(&self) -> CaseSnapshot {
        match self.0.read() {
            Ok(value) => value.clone(),
            Err(poison) => poison.into_inner().clone(),
        }
    }
    /// Publish a whole valid selection; old locale Drop occurs outside the lock.
    /// Returning the previous snapshot grants no acknowledgement beyond local
    /// selection replacement and never mutates process/thread locale state.
    pub fn replace(&self, next: CaseSnapshot) -> CaseSnapshot {
        {
            let mut state = match self.0.write() {
                Ok(value) => value,
                Err(poison) => poison.into_inner(),
            };
            std::mem::replace(&mut *state, next)
        }
    }
    /// Load first, publish only on success. A missing locale cannot silently fall
    /// back to C or destroy the previous selection.
    pub fn replace_named(&self, name: &[u8]) -> io::Result<CaseSnapshot> {
        let next = LocaleSnapshot::named(name)?;
        Ok(self.replace(CaseSnapshot::Native(next)))
    }
}

/// Explicit native current-thread locale capability. It is a reader/effect port,
/// not an immutable snapshot and not an automatic process-global lock.
#[derive(Clone)]
pub struct ThreadLocale {
    _private: (),
}
impl ThreadLocale {
    /// Enable actual native current-thread reads and the source CONFIG float
    /// failure effect. Construction does not change any native locale.
    ///
    /// # Safety
    /// Until every clone and containing CaseContext is dropped, the caller must
    /// exclude concurrent process-global locale mutations from all operations on
    /// this capability. Every externally installed thread locale must stay valid
    /// throughout each synchronous call. Foreign code must not retain or free a
    /// private thread-locale pointer installed by this capability. The supported
    /// libc must be an ordinary initialized Darwin/glibc process profile, not
    /// Apple's loader-only VARIANT_DYLD or an unvalidated replacement libc. Sequential
    /// explicit setlocale/uselocale changes under the same exclusive authority
    /// are allowed; subsequent calls intentionally observe them.
    #[expect(
        unsafe_code,
        reason = "Current global/thread native state requires an explicit lifetime-long external mutation and ownership contract"
    )]
    pub unsafe fn acquire() -> io::Result<Self> {
        #[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
        {
            Ok(Self { _private: () })
        }
        #[cfg(not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "current-thread locale ABI requires ordinary Darwin libc or glibc",
            ))
        }
    }
    /// Duplicate this calling thread's actual selection into independent native
    /// ownership. The unsafe acquisition contract covers synchronous capture.
    pub fn snapshot(&self) -> io::Result<LocaleSnapshot> {
        #[expect(
            unsafe_code,
            reason = "ThreadLocale acquisition guarantees native mutation/lifetime exclusion throughout this synchronous snapshot"
        )]
        // SAFETY: all external validity and quiescence obligations were accepted
        // by the capability constructor and persist across its clones.
        unsafe {
            LocaleSnapshot::capture_current_thread()
        }
    }
    /// Bounded native case comparison of C-string prefixes, observing this
    /// calling thread's actual locale. Empty prefixes never call C.
    #[must_use]
    pub fn equals(&self, a: &[u8], b: &[u8]) -> bool {
        let a = prefix(a);
        let b = prefix(b);
        if a.len() != b.len() {
            return false;
        }
        if a.is_empty() {
            return true;
        }
        #[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
        {
            #[expect(
                unsafe_code,
                reason = "The capability's native mutation/lifetime contract protects current locale; both spans have exactly n readable prefix bytes"
            )]
            // SAFETY: strncasecmp reads at most equal prefix length, no NUL
            // beyond those spans is needed, and no pointer is retained.
            unsafe {
                libc::strncasecmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) == 0
            }
        }
        #[cfg(not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))))]
        {
            false
        }
    }
    /// Native unsigned-byte space classification for the calling thread.
    #[must_use]
    pub fn is_space(&self, byte: u8) -> bool {
        #[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
        {
            #[expect(
                unsafe_code,
                reason = "Unsigned char ctype domain and the capability's valid current-locale contract"
            )]
            // SAFETY: all u8 values are valid ctype inputs; no negative char.
            unsafe {
                libc::isspace(i32::from(byte)) != 0
            }
        }
        #[cfg(not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))))]
        {
            let _byte = byte;
            false
        }
    }
    /// Defined strtoull conversion under the calling thread's current locale.
    pub fn scan_number(&self, input: &[u8]) -> io::Result<NumberScan> {
        let input = c_string(input)?;
        #[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
        {
            let mut end = std::ptr::null_mut();
            let errno = Errno::clear();
            #[expect(
                unsafe_code,
                reason = "Live NUL input and end slot, fixed base10, current-locale lifetime/mutation capability; overflow has defined ERANGE behavior"
            )]
            // SAFETY: this synchronous libc conversion retains no pointers.
            let value = unsafe { libc::strtoull(input.as_ptr(), &mut end, 10) };
            let range_error = last_errno() == libc::ERANGE;
            drop(errno);
            Ok(NumberScan {
                value,
                consumed: consumed(&input, end)?,
                range_error,
            })
        }
        #[cfg(not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))))]
        {
            drop(input);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "current-thread conversion ABI is not validated",
            ))
        }
    }
    /// Source CONFIG float setter formatting in a temporary numeric-C locale,
    /// restoring the original thread selection before returning owned bytes.
    pub fn format_configuration_float(&self, value: f32) -> io::Result<Vec<u8>> {
        #[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
        {
            #[expect(
                unsafe_code,
                reason = "Explicit native capability excludes global locale mutations while newlocale creates private numeric-C ownership"
            )]
            // SAFETY: fixed numeric mask and name, NULL base allocates; result
            // is privately owned and never used as a mutable shared base.
            let locale = LocaleSnapshot::owned(unsafe {
                libc::newlocale(libc::LC_NUMERIC_MASK, c"C".as_ptr(), std::ptr::null_mut())
            })?;
            let _installed = InstalledLocale::new(locale)?;
            let mut output = [0u8; 64];
            #[expect(
                unsafe_code,
                reason = "Literal %f expects promoted double; every finite f32 plus six fractional digits fits the source 64-byte bound, and NaN/Inf are defined printf inputs"
            )]
            // SAFETY: the initialized writable array is exactly the supplied
            // size, and f64::from(value) is C's actual default float promotion.
            let used = unsafe {
                libc::snprintf(
                    output.as_mut_ptr().cast(),
                    output.len(),
                    c"%f".as_ptr(),
                    f64::from(value),
                )
            };
            let used = usize::try_from(used)
                .map_err(|_| io::Error::other("native float formatting failed"))?;
            if used >= output.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "native float formatting exceeded source width",
                ));
            }
            let mut owned = Vec::new();
            owned
                .try_reserve_exact(used)
                .map_err(|_| io::ErrorKind::OutOfMemory)?;
            owned.extend_from_slice(&output[..used]);
            Ok(owned)
        }
        #[cfg(not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))))]
        {
            let _value = value;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native CONFIG float formatting ABI is not validated",
            ))
        }
    }
    /// Actual source CONFIG `%f%1s` operation using its native numeric-C locale.
    /// A defined strtof_l ERANGE preflight rejects out-of-range inputs before
    /// scanf; those inputs receive no native scanf-equivalence claim. A lexical
    /// or trailing-item failure retains the source's private mixed locale in this
    /// thread until a later explicit change or thread exit. Success restores the
    /// original locale. Neither path changes other threads' selected locale.
    pub fn configuration_float(&self, input: &[u8]) -> io::Result<ConfigurationFloat> {
        #[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
        {
            #[expect(
                unsafe_code,
                reason = "Explicit current-locale capability excludes concurrent global mutation while native newlocale copies its unspecified categories"
            )]
            // SAFETY: NULL base creates fresh ownership. Numeric is C; other
            // category semantics are the native ABI's actual source behavior.
            let locale = LocaleSnapshot::owned(unsafe {
                libc::newlocale(libc::LC_NUMERIC_MASK, c"C".as_ptr(), std::ptr::null_mut())
            })?;
            let scan = locale.scan_float(input)?;
            if scan.range_error {
                return Ok(ConfigurationFloat {
                    value: scan.value,
                    matched: false,
                    range_error: true,
                });
            }
            let text = c_string(input)?;
            let mut installed = InstalledLocale::new(locale)?;
            let mut value = 0.0f32;
            let mut dummy = [0 as libc::c_char; 2];
            #[expect(
                unsafe_code,
                reason = "The literal format has exactly one float* and a width1 char[2]*; preflight rejected undefined out-of-range scanf conversions, native current locale is privately retained"
            )]
            // SAFETY: writable correctly typed/aligned outputs match the fixed
            // format. The input is NUL terminated and all owners remain live.
            let matched = unsafe {
                libc::sscanf(
                    text.as_ptr(),
                    c"%f%1s".as_ptr(),
                    &mut value as *mut f32,
                    dummy.as_mut_ptr(),
                )
            } == 1;
            if !matched {
                installed.retain_failure()?;
            }
            Ok(ConfigurationFloat {
                value,
                matched,
                range_error: false,
            })
        }
        #[cfg(not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))))]
        {
            let _input = input;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native CONFIG float ABI is not validated",
            ))
        }
    }
}
/// Exact typed native CONFIG float result; out-of-range preflight is separately
/// classified and never represented as a successful or executed scanf call.
#[derive(Clone, Copy, Debug)]
pub struct ConfigurationFloat {
    /// Native float output; valid as a CONFIG value only when matched is true.
    pub value: f32,
    /// True exactly when the defined native scanf converted one item.
    pub matched: bool,
    /// A defined strtof_l range error rejected before any scanf/effect.
    pub range_error: bool,
}
#[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
struct RetainedThreadLocale {
    locale: LocaleSnapshot,
}
#[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
impl Drop for RetainedThreadLocale {
    fn drop(&mut self) {
        #[expect(
            unsafe_code,
            reason = "The TLS owner retains its private immutable locale; query current first, and detach only if that exact private locale remains installed before final Arc can free it"
        )]
        // SAFETY: NULL queries. Global sentinel is a valid uselocale selector,
        // The reviewed Darwin/POSIX SDK defines it as (locale_t)-1; it is
        // never dereferenced, passed to a *_l reader or freed. Foreign retained pointers are
        // excluded by the explicit ThreadLocale capability contract.
        unsafe {
            if libc::uselocale(std::ptr::null_mut()) == self.locale.handle.0.as_ptr() {
                let _previous =
                    libc::uselocale(std::ptr::without_provenance_mut::<libc::c_void>(usize::MAX));
            }
        }
    }
}
#[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
std::thread_local! {
    static RETAINED_THREAD_LOCALE:std::cell::RefCell<Option<RetainedThreadLocale>>=const{std::cell::RefCell::new(None)};
}
#[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
struct InstalledLocale {
    locale: LocaleSnapshot,
    previous: libc::locale_t,
    restore: bool,
}
#[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
impl InstalledLocale {
    fn new(locale: LocaleSnapshot) -> io::Result<Self> {
        #[expect(
            unsafe_code,
            reason = "Private immutable locale remains owned in this guard throughout installation; capability protects the previous effective native locale"
        )]
        // SAFETY: valid freshly allocated locale. uselocale returns the original
        // live selection/sentinel, which guard restoration never frees.
        let previous = unsafe { libc::uselocale(locale.handle.0.as_ptr()) };
        if previous.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            locale,
            previous,
            restore: true,
        })
    }
    fn retain_failure(&mut self) -> io::Result<()> {
        // Create ownership before disabling restoration. On TLS access/borrow
        // failure the guard still restores the original selection before Drop.
        let next = RetainedThreadLocale {
            locale: self.locale.clone(),
        };
        let old = RETAINED_THREAD_LOCALE
            .try_with(|slot| {
                let mut slot = slot
                    .try_borrow_mut()
                    .map_err(|_| io::Error::other("native locale effect reentered TLS owner"))?;
                Ok::<_, io::Error>(slot.replace(next))
            })
            .map_err(|_| io::Error::other("native locale owner is being destroyed"))??;
        self.restore = false;
        drop(old);
        Ok(())
    }
}
#[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
impl Drop for InstalledLocale {
    fn drop(&mut self) {
        if self.restore {
            #[expect(
                unsafe_code,
                reason = "Original selection is retained by the native capability contract; restoration happens before this guard's private locale Arc is dropped"
            )]
            // SAFETY: previous is exactly the successful uselocale return value;
            // no object is freed or raw pointer exposed by restoration.
            unsafe {
                let _replaced = libc::uselocale(self.previous);
            }
        }
    }
}
