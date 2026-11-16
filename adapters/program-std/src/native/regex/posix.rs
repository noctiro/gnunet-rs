//! Owned POSIX BRE allocations and exact compile-locale selection.
use crate::native::cstring;
use std::{io, mem::MaybeUninit};
// The native POSIX regex contract requires execution in the compile locale.
// Keep one private duplicate, not a borrowed global/thread selector. Neither
// this handle nor the compiled regex is exposed to a foreign mutator.
struct RegexLocale(std::ptr::NonNull<libc::c_void>);
impl RegexLocale {
    fn capture() -> io::Result<Self> {
        if !cfg!(any(
            target_os = "macos",
            target_os = "freebsd",
            all(target_os = "linux", target_env = "gnu")
        )) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "owned native regex locale requires Darwin, FreeBSD libc or glibc",
            ));
        }
        #[expect(
            unsafe_code,
            reason = "PROGRAM's native-locale capability excludes concurrent mutations; NULL queries current thread and duplocale creates independent ownership"
        )]
        // SAFETY: current is a valid selected locale or global sentinel. The
        // duplicate is independent; no foreign raw pointer escapes this module.
        let raw = unsafe { libc::duplocale(libc::uselocale(std::ptr::null_mut())) };
        let raw = std::ptr::NonNull::new(raw).ok_or_else(io::Error::last_os_error)?;
        if raw.as_ptr().addr() == usize::MAX {
            return Err(io::Error::other("duplocale returned global sentinel"));
        }
        Ok(Self(raw))
    }
}
impl Drop for RegexLocale {
    fn drop(&mut self) {
        #[expect(
            unsafe_code,
            reason = "The private duplicate is freed once, only after every short use guard and regex allocation was released"
        )]
        // SAFETY: this is a successful private duplocale result, never a global
        // sentinel or a locale still installed by one of our guards.
        unsafe {
            libc::freelocale(self.0.as_ptr());
        }
    }
}
struct RegexLocaleUse<'a> {
    _locale: &'a RegexLocale,
    previous: libc::locale_t,
}
impl<'a> RegexLocaleUse<'a> {
    fn enter(locale: &'a RegexLocale) -> io::Result<Self> {
        #[expect(
            unsafe_code,
            reason = "Privately owned immutable duplicate stays borrowed throughout the guard; no callbacks or foreign ownership changes occur in the guarded native regex call"
        )]
        // SAFETY: locale is valid and live. The previous selection stays live
        // under the same native-locale capability contract as PROGRAM setup.
        let previous = unsafe { libc::uselocale(locale.0.as_ptr()) };
        if previous.is_null() {
            return Err(io::Error::last_os_error());
        }
        let guard = Self {
            _locale: locale,
            previous,
        };
        #[expect(
            unsafe_code,
            reason = "NULL only queries actual current thread selection; private owned selector is retained by the guard"
        )]
        // SAFETY: querying changes no locale or ownership and cannot retain data.
        let selected = unsafe { libc::uselocale(std::ptr::null_mut()) };
        if selected != locale.0.as_ptr() {
            return Err(io::Error::other(
                "native regex locale selection did not commit",
            ));
        }
        Ok(guard)
    }
}
impl Drop for RegexLocaleUse<'_> {
    fn drop(&mut self) {
        #[expect(
            unsafe_code,
            reason = "Restore exactly the original live selector before releasing the privately installed duplicate"
        )]
        // SAFETY: no user callback runs inside this short guard. No owned
        // object is freed here; previous may be libc's valid global sentinel.
        let restored = unsafe { libc::uselocale(self.previous) };
        if restored.is_null() {
            // A valid private/original selector cannot fail under the reviewed
            // libc ABI. Never proceed to free a still-installed object after an
            // ownership/ABI invariant breach. This branch is not an IO retry or
            // a fake non-match, and is never exercised as a native C experiment.
            std::process::abort();
        }
    }
}
pub(crate) enum RegexCompileFailure {
    InvalidPattern,
    Boundary(io::Error),
}
impl From<io::Error> for RegexCompileFailure {
    fn from(value: io::Error) -> Self {
        Self::Boundary(value)
    }
}
pub(crate) struct Regex {
    data: libc::regex_t,
    locale: RegexLocale,
}
fn regex_result(status: libc::c_int) -> io::Result<bool> {
    if status == 0 {
        Ok(true)
    } else if status == libc::REG_NOMATCH {
        Ok(false)
    } else {
        Err(io::Error::new(
            if status == libc::REG_ESPACE {
                io::ErrorKind::OutOfMemory
            } else {
                io::ErrorKind::Other
            },
            format!("POSIX BRE match error {status}"),
        ))
    }
}
impl Regex {
    pub(crate) fn new(pattern: &[u8]) -> Result<Self, RegexCompileFailure> {
        let pattern = cstring(pattern)?;
        let locale = RegexLocale::capture()?;
        let mut storage = MaybeUninit::uninit();
        let guard = RegexLocaleUse::enter(&locale)?;
        #[expect(
            unsafe_code,
            reason = "Correctly aligned owned regex_t output and NUL pattern stay live; private compile locale is installed for exactly this call"
        )]
        // SAFETY: this native call retains no borrowed pattern/guard pointer;
        // only successful regcomp initializes a releasable regex_t.
        let status =
            unsafe { libc::regcomp(storage.as_mut_ptr(), pattern.as_ptr(), libc::REG_NOSUB) };
        drop(guard);
        if status == libc::REG_ESPACE {
            return Err(RegexCompileFailure::Boundary(io::Error::new(
                io::ErrorKind::OutOfMemory,
                format!("POSIX BRE compile error {status}"),
            )));
        }
        if status != 0 {
            return Err(RegexCompileFailure::InvalidPattern);
        }
        #[expect(
            unsafe_code,
            reason = "Successful regcomp initialized this exclusively owned regex_t"
        )]
        // SAFETY: exact successful native output; all selected supported libc
        // profiles store allocated regex guts, not self-relative stack storage.
        let data = unsafe { storage.assume_init() };
        Ok(Self { data, locale })
    }
    pub(crate) fn matches(&self, value: &[u8]) -> io::Result<bool> {
        let value = cstring(value)?;
        let _guard = RegexLocaleUse::enter(&self.locale)?;
        #[expect(
            unsafe_code,
            reason = "Owned successful regex, NUL string, REG_NOSUB/no match outputs and the exact compile locale satisfy native regexec preconditions"
        )]
        // SAFETY: all inputs remain borrowed through this synchronous call and
        // locale restoration occurs before returning to caller/user callbacks.
        let status =
            unsafe { libc::regexec(&self.data, value.as_ptr(), 0, std::ptr::null_mut(), 0) };
        regex_result(status)
    }
}
impl Drop for Regex {
    fn drop(&mut self) {
        let guard = match RegexLocaleUse::enter(&self.locale) {
            Ok(guard) => guard,
            Err(_) => {
                // EINVAL for a privately owned live locale indicates an internal ABI
                // or ownership breach. Do not regfree under a mismatched locale or
                // silently orphan an unbounded native allocation.
                std::process::abort();
            }
        };
        #[expect(
            unsafe_code,
            reason = "Unique successful regex is released once in its exact owned compile locale, which remains alive until this Drop returns"
        )]
        // SAFETY: no further regex access remains, and locale is not freed until
        // after regfree and the guard's original-thread-locale restoration.
        unsafe {
            libc::regfree(&mut self.data);
        }
        drop(guard);
    }
}
#[cfg(test)]
mod regex_tests {
    use super::regex_result;
    #[test]
    fn native_match_status_never_treats_resource_or_unknown_failure_as_nomatch() {
        assert!(matches!(regex_result(0), Ok(true)));
        assert!(matches!(regex_result(libc::REG_NOMATCH), Ok(false)));
        assert!(
            matches!(regex_result(libc::REG_ESPACE),Err(error) if error.kind()==std::io::ErrorKind::OutOfMemory)
        );
        assert!(regex_result(-313).is_err());
    }
}

#[cfg(all(test, target_os = "macos"))]
mod regex_locale_tests {
    use super::{Regex, RegexCompileFailure, RegexLocale, RegexLocaleUse};
    fn named(name: &std::ffi::CStr) -> std::io::Result<RegexLocale> {
        #[expect(
            unsafe_code,
            reason = "Literal known Darwin locale name/all-category mask creates new private ownership; no global locale mutation"
        )]
        // SAFETY: live static C string, NULL base/fresh immutable ownership.
        let raw =
            unsafe { libc::newlocale(libc::LC_ALL_MASK, name.as_ptr(), std::ptr::null_mut()) };
        Ok(RegexLocale(
            std::ptr::NonNull::new(raw).ok_or_else(std::io::Error::last_os_error)?,
        ))
    }
    fn current() -> libc::locale_t {
        #[expect(
            unsafe_code,
            reason = "NULL only queries current thread locale and retains no reference"
        )]
        // SAFETY: no memory is changed or pointer dereferenced by this query.
        unsafe {
            libc::uselocale(std::ptr::null_mut())
        }
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Only the repaired wrapper is exercised: each native call uses its compile locale; ambient locale changes are thread-private and not an undefined C comparator"
    )]
    fn owned_regex_keeps_compile_locale_and_restores_ambient_after_match_and_drop()
    -> std::io::Result<()> {
        let original = current();
        let latin = named(c"en_US.ISO8859-1")?;
        let c = named(c"C")?;
        let latin_guard = RegexLocaleUse::enter(&latin)?;
        let regex = Regex::new(b"^[[:alpha:]]$").map_err(|error| match error {
            RegexCompileFailure::Boundary(error) => error,
            RegexCompileFailure::InvalidPattern => std::io::Error::other("literal regex rejected"),
        })?;
        assert!(regex.matches(b"\xe9")?);
        assert_eq!(current(), latin.0.as_ptr());
        drop(latin_guard);
        assert_eq!(current(), original);
        let c_guard = RegexLocaleUse::enter(&c)?;
        assert_eq!(current(), c.0.as_ptr());
        assert!(regex.matches(b"\xe9")?);
        assert_eq!(current(), c.0.as_ptr());
        assert!(!regex.matches(b"1")?);
        assert_eq!(current(), c.0.as_ptr());
        drop(regex);
        assert_eq!(current(), c.0.as_ptr());
        drop(c_guard);
        assert_eq!(current(), original);
        Ok(())
    }
}
