//! Owned native locale readers with shared comparison selection and conversion results.
//! Platform backends retain their own handles and error/state contracts. No
//! GNUnet library is loaded and named snapshots never change process locale.
use std::{
    ffi::CString,
    io,
    sync::{Arc, RwLock},
};
#[cfg(not(windows))]
#[path = "locale/posix.rs"]
mod backend;
#[cfg(windows)]
#[path = "locale/windows.rs"]
mod backend;
pub use backend::{LocaleSnapshot, ThreadLocale};
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
#[cfg(any(
    windows,
    target_os = "macos",
    target_os = "freebsd",
    all(target_os = "linux", target_env = "gnu")
))]
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

/// Typed native CONFIG float result; out-of-range conversion is separately
/// classified. POSIX uses preflight plus scanf; UCRT uses explicit-locale
/// conversion and trailing-whitespace validation without locale installation.
#[derive(Clone, Copy, Debug)]
pub struct ConfigurationFloat {
    /// Native float output; valid as a CONFIG value only when matched is true.
    pub value: f32,
    /// One complete value with only allowed trailing whitespace was accepted.
    pub matched: bool,
    /// A defined strtof_l range error rejected before any scanf/effect.
    pub range_error: bool,
}
