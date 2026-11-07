//! UCRT locale objects and explicit-locale conversion; no locale installation.
use super::{ConfigurationFloat, FloatScan, NumberScan, c_string, consumed, prefix};
use std::{
    ffi::{CString, c_char, c_int, c_void},
    io,
    ptr::NonNull,
    sync::Arc,
};

type RawLocale = *mut c_void;
#[expect(
    unsafe_code,
    reason = "UCRT locale.h, ctype.h, string.h and stdlib.h declare these opaque-handle C ABIs; all ownership stays in this module"
)]
unsafe extern "C" {
    fn _create_locale(category: c_int, name: *const c_char) -> RawLocale;
    fn _get_current_locale() -> RawLocale;
    fn _free_locale(locale: RawLocale);
    fn _strnicmp_l(a: *const c_char, b: *const c_char, n: usize, locale: RawLocale) -> c_int;
    fn _strnicmp(a: *const c_char, b: *const c_char, n: usize) -> c_int;
    fn _isspace_l(value: c_int, locale: RawLocale) -> c_int;
    fn _strtof_l(input: *const c_char, end: *mut *mut c_char, locale: RawLocale) -> f32;
    fn _strtoui64_l(
        input: *const c_char,
        end: *mut *mut c_char,
        base: c_int,
        locale: RawLocale,
    ) -> u64;
    fn _strtoui64(input: *const c_char, end: *mut *mut c_char, base: c_int) -> u64;
    fn _errno() -> *mut c_int;
}
#[cfg_attr(target_env = "msvc", link(name = "legacy_stdio_definitions"))]
#[expect(
    unsafe_code,
    reason = "UCRT stdio.h declares this explicit-locale bounded formatter; the MSVC out-of-line ABI is provided by its standard legacy_stdio_definitions library"
)]
unsafe extern "C" {
    fn _snprintf_l(
        output: *mut c_char,
        size: usize,
        format: *const c_char,
        locale: RawLocale,
        ...
    ) -> c_int;
}

struct Handle(NonNull<c_void>);
#[expect(
    unsafe_code,
    reason = "The opaque UCRT locale is immutable and never installed or passed to a native mutator; an Arc retains it through all synchronous readers"
)]
// SAFETY: only immutable *_l reads can borrow this independently owned handle.
unsafe impl Send for Handle {}
#[expect(
    unsafe_code,
    reason = "Readers share only an immutable opaque locale; final Arc Drop frees it after all borrows end"
)]
// SAFETY: no raw pointer escapes and no native locale installation aliases ownership.
unsafe impl Sync for Handle {}
impl Drop for Handle {
    #[expect(
        unsafe_code,
        reason = "This is exactly one successful _create_locale/_get_current_locale allocation, freed once after its last Arc reader"
    )]
    fn drop(&mut self) {
        // SAFETY: UCRT transfers the original opaque allocation to this owner.
        unsafe {
            _free_locale(self.0.as_ptr());
        }
    }
}

#[expect(
    unsafe_code,
    reason = "UCRT _errno returns the calling thread's initialized CRT errno slot, not Win32 GetLastError storage"
)]
fn errno() -> c_int {
    // SAFETY: this initialized UCRT thread owns the live errno cell.
    unsafe { *_errno() }
}
#[expect(
    unsafe_code,
    reason = "Only the current thread's CRT errno cell is updated during synchronous native calls"
)]
fn set_errno(value: c_int) {
    // SAFETY: _errno points to this UCRT thread's writable errno cell.
    unsafe {
        *_errno() = value;
    }
}
struct Errno(c_int);
impl Errno {
    fn clear() -> Self {
        let old = Self(errno());
        set_errno(0);
        old
    }
}
impl Drop for Errno {
    fn drop(&mut self) {
        set_errno(self.0);
    }
}
fn crt_error(operation: &'static str) -> io::Error {
    let code = errno();
    let kind = match code {
        libc::ENOMEM => io::ErrorKind::OutOfMemory,
        libc::EINVAL => io::ErrorKind::InvalidInput,
        _ => io::ErrorKind::Other,
    };
    // CRT errno and Win32 error numbers are separate namespaces.
    io::Error::new(kind, format!("{operation} failed (CRT errno {code})"))
}

/// An independent immutable UCRT locale. Clones share one owned allocation;
/// comparisons and conversions never change a process or thread selection.
#[derive(Clone)]
pub struct LocaleSnapshot {
    handle: Arc<Handle>,
}
impl LocaleSnapshot {
    fn owned(raw: RawLocale, operation: &'static str) -> io::Result<Self> {
        let pointer = NonNull::new(raw).ok_or_else(|| crt_error(operation))?;
        Ok(Self {
            handle: Arc::new(Handle(pointer)),
        })
    }
    /// Create an explicit named UCRT locale, without installing it. Empty names,
    /// NUL and names above 32767 bytes are refused; a missing locale is an error.
    #[expect(
        unsafe_code,
        reason = "A fixed valid LC_ALL category and live bounded C name request one new UCRT locale allocation"
    )]
    pub fn named(name: &[u8]) -> io::Result<Self> {
        if name.is_empty() || name.len() > 32767 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let name = CString::new(name).map_err(|_| io::ErrorKind::InvalidInput)?;
        let _errno = Errno::clear();
        // SAFETY: UCRT copies the live name; no process locale is selected.
        Self::owned(
            unsafe { _create_locale(libc::LC_ALL, name.as_ptr()) },
            "_create_locale",
        )
    }
    /// Capture the calling thread's effective UCRT locale in independent ownership.
    ///
    /// # Safety
    /// Exclude concurrent global locale mutation during capture. Any external
    /// thread locale must remain valid throughout this synchronous call.
    #[expect(
        unsafe_code,
        reason = "Explicit caller quiescence protects current UCRT state while _get_current_locale returns independent owned storage"
    )]
    pub unsafe fn capture_current_thread() -> io::Result<Self> {
        let _errno = Errno::clear();
        // SAFETY: external state validity and mutation exclusion are caller obligations.
        Self::owned(unsafe { _get_current_locale() }, "_get_current_locale")
    }
    /// Compare bounded C-string prefixes using this retained native locale.
    #[must_use]
    #[expect(
        unsafe_code,
        reason = "Both equal-length prefixes contain n readable bytes and the immutable locale remains Arc-owned through _strnicmp_l"
    )]
    pub fn equals(&self, a: &[u8], b: &[u8]) -> bool {
        let (a, b) = (prefix(a), prefix(b));
        if a.len() != b.len() {
            return false;
        }
        if a.is_empty() {
            return true;
        }
        // SAFETY: comparison is bounded to both spans, requiring no extra NUL.
        unsafe {
            _strnicmp_l(
                a.as_ptr().cast(),
                b.as_ptr().cast(),
                a.len(),
                self.handle.0.as_ptr(),
            ) == 0
        }
    }
    /// Classify one unsigned byte under this immutable locale.
    #[must_use]
    #[expect(
        unsafe_code,
        reason = "Every u8 is in the native ctype domain; the opaque locale remains live and immutable"
    )]
    pub fn is_space(&self, value: u8) -> bool {
        // SAFETY: no negative signed-char value or invalid locale is supplied.
        unsafe { _isspace_l(c_int::from(value), self.handle.0.as_ptr()) != 0 }
    }
    /// Defined native float conversion with checked consumption and CRT ERANGE.
    #[expect(
        unsafe_code,
        reason = "NUL input, end-pointer output and owned opaque locale are live for one defined _strtof_l call"
    )]
    pub fn scan_float(&self, input: &[u8]) -> io::Result<FloatScan> {
        let input = c_string(input)?;
        let mut end = std::ptr::null_mut();
        let _errno = Errno::clear();
        // SAFETY: all storage is live and no pointer is retained by UCRT.
        let value = unsafe { _strtof_l(input.as_ptr(), &mut end, self.handle.0.as_ptr()) };
        let range_error = errno() == libc::ERANGE;
        Ok(FloatScan {
            value,
            consumed: consumed(&input, end)?,
            range_error,
        })
    }
    /// Decimal unsigned conversion with native sign/whitespace and CRT ERANGE.
    #[expect(
        unsafe_code,
        reason = "One bounded C input and checked end output use valid base10 and one retained native locale"
    )]
    pub fn scan_number(&self, input: &[u8]) -> io::Result<NumberScan> {
        let input = c_string(input)?;
        let mut end = std::ptr::null_mut();
        let _errno = Errno::clear();
        // SAFETY: UCRT retains none of these live borrowed pointers.
        let value = unsafe { _strtoui64_l(input.as_ptr(), &mut end, 10, self.handle.0.as_ptr()) };
        let range_error = errno() == libc::ERANGE;
        Ok(NumberScan {
            value,
            consumed: consumed(&input, end)?,
            range_error,
        })
    }
}

/// Explicit reader of the calling thread's effective UCRT locale. Configuration
/// float conversion/formatting uses a private C locale without installing it.
#[derive(Clone)]
pub struct ThreadLocale {
    _private: (),
}
impl ThreadLocale {
    /// Acquire current-thread observation authority without changing any locale.
    ///
    /// # Safety
    /// Until all clones are dropped, exclude concurrent global locale mutations
    /// during operations and keep external thread locales valid during each call.
    #[expect(
        unsafe_code,
        reason = "This capability requires external locale mutation/lifetime exclusion across every clone and synchronous operation"
    )]
    pub unsafe fn acquire() -> io::Result<Self> {
        Ok(Self { _private: () })
    }
    /// Retain the current effective locale independently of the originating thread.
    #[expect(
        unsafe_code,
        reason = "The capability's acquisition contract protects native capture for the duration of this synchronous call"
    )]
    pub fn snapshot(&self) -> io::Result<LocaleSnapshot> {
        // SAFETY: accepted mutation and lifetime obligations remain in force.
        unsafe { LocaleSnapshot::capture_current_thread() }
    }
    /// Compare bounded prefixes using the calling thread's native locale.
    #[must_use]
    #[expect(
        unsafe_code,
        reason = "The reader capability protects current locale; both live byte spans contain the supplied comparison bound"
    )]
    pub fn equals(&self, a: &[u8], b: &[u8]) -> bool {
        let (a, b) = (prefix(a), prefix(b));
        if a.len() != b.len() {
            return false;
        }
        if a.is_empty() {
            return true;
        }
        // SAFETY: _strnicmp is bounded to two valid equal-length spans.
        unsafe { _strnicmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) == 0 }
    }
    /// Native unsigned-byte classification under the calling thread's selection.
    #[must_use]
    #[expect(
        unsafe_code,
        reason = "The current-locale capability and unsigned-char domain satisfy native isspace preconditions"
    )]
    pub fn is_space(&self, byte: u8) -> bool {
        // SAFETY: unsigned input and externally protected native locale.
        unsafe { libc::isspace(c_int::from(byte)) != 0 }
    }
    /// Defined decimal conversion under the calling thread's current selection.
    #[expect(
        unsafe_code,
        reason = "Native current locale is protected by the capability; input/end storage is live and base10 has defined range behavior"
    )]
    pub fn scan_number(&self, input: &[u8]) -> io::Result<NumberScan> {
        let input = c_string(input)?;
        let mut end = std::ptr::null_mut();
        let _errno = Errno::clear();
        // SAFETY: all pointers remain live for this single conversion.
        let value = unsafe { _strtoui64(input.as_ptr(), &mut end, 10) };
        let range_error = errno() == libc::ERANGE;
        Ok(NumberScan {
            value,
            consumed: consumed(&input, end)?,
            range_error,
        })
    }
    /// Format the promoted float with native `%f` in a private numeric-C locale.
    /// Success and failure leave the calling thread's locale unchanged.
    #[expect(
        unsafe_code,
        reason = "The fixed %f format accepts one promoted double; exact writable storage and a retained C locale bound the native formatter"
    )]
    pub fn format_configuration_float(&self, value: f32) -> io::Result<Vec<u8>> {
        let locale = LocaleSnapshot::named(b"C")?;
        let mut output = [0_u8; 64];
        let _errno = Errno::clear();
        // SAFETY: f64 is the actual C float promotion and format/storage are fixed.
        let used = unsafe {
            _snprintf_l(
                output.as_mut_ptr().cast(),
                output.len(),
                c"%f".as_ptr(),
                locale.handle.0.as_ptr(),
                f64::from(value),
            )
        };
        let used = usize::try_from(used).map_err(|_| crt_error("_snprintf_l"))?;
        if used >= output.len() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(used)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        bytes.extend_from_slice(&output[..used]);
        Ok(bytes)
    }
    /// CONFIG numeric-C conversion with one value and only trailing whitespace.
    /// Defined strtof consumption/range checks avoid overflowing scanf. UCRT's
    /// explicit locale parameter needs no TLS installation or failure retention.
    pub fn configuration_float(&self, input: &[u8]) -> io::Result<ConfigurationFloat> {
        let locale = LocaleSnapshot::named(b"C")?;
        let scan = locale.scan_float(input)?;
        let input = prefix(input);
        let matched = !scan.range_error
            && scan.consumed != 0
            && input[scan.consumed..]
                .iter()
                .all(|&byte| locale.is_space(byte));
        Ok(ConfigurationFloat {
            value: scan.value,
            matched,
            range_error: scan.range_error,
        })
    }
}
