//! Narrow POSIX adapters for ordinary initialized Darwin libc / glibc hosts.
//! The owned regex locale contract is bound to native-contracts/sources.json.
//! Unknown libc and Apple's loader-only VARIANT_DYLD are outside this profile;
//! these APIs do not claim to validate a caller's arbitrary replacement libc.
use std::{
    ffi::{CStr, CString},
    io,
    mem::MaybeUninit,
};
fn cstring(bytes: &[u8]) -> io::Result<CString> {
    CString::new(&bytes[..bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len())])
        .map_err(io::Error::other)
}
// The native POSIX regex contract requires execution in the compile locale.
// Keep one private duplicate, not a borrowed global/thread selector. Neither
// this handle nor the compiled regex is exposed to a foreign mutator.
struct RegexLocale(std::ptr::NonNull<libc::c_void>);
impl RegexLocale {
    fn capture() -> io::Result<Self> {
        if !cfg!(any(
            target_os = "macos",
            all(target_os = "linux", target_env = "gnu")
        )) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "owned native regex locale requires ordinary Darwin libc or glibc profile",
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
    InvalidPattern(libc::c_int),
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
            return Err(RegexCompileFailure::InvalidPattern(status));
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
/// Widen the platform signed microsecond type without changing prior native narrowing.
pub(crate) fn wide_micros(value: impl Into<i64>) -> i64 {
    value.into()
}

/// Native wall timeval plus its native calendar representation.
pub(crate) struct Calendar {
    pub(crate) seconds: i64,
    pub(crate) micros: i64,
    local: Option<libc::tm>,
}
impl Calendar {
    pub(crate) fn wall() -> io::Result<Self> {
        let mut time = MaybeUninit::uninit();
        #[expect(
            unsafe_code,
            reason = "OS writes exactly one timeval to valid caller storage; timezone argument is unused"
        )]
        // SAFETY: output is aligned and writable; gettimeofday does not retain it.
        let status = unsafe { libc::gettimeofday(time.as_mut_ptr(), std::ptr::null_mut()) };
        if status != 0 {
            return Err(io::Error::last_os_error());
        }
        #[expect(
            unsafe_code,
            reason = "gettimeofday success initialized the exact timeval output"
        )]
        // SAFETY: the preceding successful call filled the output.
        let time = unsafe { time.assume_init() };
        Self::new(time.tv_sec, wide_micros(time.tv_usec), false)
    }
    pub(crate) fn new(seconds: i64, micros: i64, utc: bool) -> io::Result<Self> {
        let value: libc::time_t = seconds;
        let mut out = MaybeUninit::uninit();
        #[expect(
            unsafe_code,
            reason = "Reentrant native calendar conversion with valid borrowed input and unique output"
        )]
        // SAFETY: pointers refer to valid time_t and writable tm; null means range failure.
        let result = unsafe {
            if utc {
                libc::gmtime_r(&value, out.as_mut_ptr())
            } else {
                libc::localtime_r(&value, out.as_mut_ptr())
            }
        };
        let local = if result.is_null() {
            None
        } else {
            #[expect(
                unsafe_code,
                reason = "Non-null reentrant calendar result initialized this output tm"
            )]
            // SAFETY: localtime_r/gmtime_r returned our initialized output pointer.
            Some(unsafe { out.assume_init() })
        };
        Ok(Self {
            seconds,
            micros,
            local,
        })
    }
    pub(crate) fn format(&self, pattern: &[u8], capacity: usize) -> io::Result<Vec<u8>> {
        let Some(local) = &self.local else {
            return Err(io::Error::other("localtime error"));
        };
        let pattern = cstring(pattern)?;
        let mut output = vec![0; capacity];
        #[expect(
            unsafe_code,
            reason = "Native strftime receives initialized tm and C format, bounded writable byte buffer"
        )]
        // SAFETY: output length is exactly the provided capacity and all inputs outlive the call.
        let count = unsafe {
            libc::strftime(
                output.as_mut_ptr().cast(),
                output.len(),
                pattern.as_ptr(),
                local,
            )
        };
        if count == 0 {
            return Err(io::Error::other("strftime returned zero"));
        }
        output.truncate(count);
        Ok(output)
    }
    pub(crate) fn date(&self) -> Vec<u8> {
        let Ok(pattern) = self.format(b"%Y-%m-%dT%H:%M:%S.@%z", 64) else {
            return b"localtime error".to_vec();
        };
        let Some(split) = pattern.iter().position(|&b| b == b'@') else {
            return b"localtime error".to_vec();
        };
        let mut date = pattern[..split].to_vec();
        date.extend_from_slice(format!("{:06}", self.micros as u32).as_bytes());
        date.extend_from_slice(&pattern[split + 1..]);
        date
    }
}
#[cfg(target_os = "macos")]
fn errno_ptr() -> *mut libc::c_int {
    #[expect(
        unsafe_code,
        reason = "Darwin provides a live thread-local errno pointer"
    )]
    // SAFETY: __error has no input and returns this thread's errno address.
    unsafe {
        libc::__error()
    }
}
#[cfg(target_os = "linux")]
fn errno_ptr() -> *mut libc::c_int {
    #[expect(
        unsafe_code,
        reason = "Linux provides a live thread-local errno pointer"
    )]
    // SAFETY: __errno_location has no input and returns this thread's errno address.
    unsafe {
        libc::__errno_location()
    }
}
pub(crate) struct ErrnoGuard(libc::c_int);
impl ErrnoGuard {
    pub(crate) fn new() -> Self {
        #[expect(unsafe_code, reason = "Read only current thread's valid errno cell")]
        // SAFETY: errno_ptr points to this thread's initialized errno cell.
        Self(unsafe { *errno_ptr() })
    }
}
impl Drop for ErrnoGuard {
    fn drop(&mut self) {
        #[expect(unsafe_code, reason = "Restore only this thread's errno after logging")]
        // SAFETY: errno_ptr points to this thread's writable errno cell.
        unsafe {
            *errno_ptr() = self.0;
        }
    }
}
pub(crate) fn strerror(number: i32) -> Vec<u8> {
    #[expect(
        unsafe_code,
        reason = "Native strerror returns process-owned C text, copied immediately without mutation"
    )]
    // SAFETY: strerror permits every integer errno; a null fallback is handled.
    let text = unsafe { libc::strerror(number) };
    if text.is_null() {
        return b"unknown error".to_vec();
    }
    #[expect(
        unsafe_code,
        reason = "Non-null native strerror text is NUL terminated and copied before another call"
    )]
    // SAFETY: native strerror returned a valid C string for this call.
    unsafe {
        CStr::from_ptr(text).to_bytes().to_vec()
    }
}

pub(crate) fn upper(byte: u8) -> i32 {
    #[expect(
        unsafe_code,
        reason = "POSIX toupper accepts every unsigned-char value; preserves native LC_CTYPE sorting semantics"
    )]
    // SAFETY: u8 promoted to int is in the required unsigned-char domain.
    unsafe {
        libc::toupper(i32::from(byte))
    }
}
pub(crate) fn whitespace(byte: u8) -> bool {
    #[expect(
        unsafe_code,
        reason = "POSIX isspace accepts every unsigned-char value; native locale is installed separately"
    )]
    // SAFETY: u8 promoted to int is in the required unsigned-char domain.
    unsafe {
        libc::isspace(i32::from(byte)) != 0
    }
}
pub(crate) fn absolute_calendar(input: &[u8]) -> io::Result<u64> {
    let input = cstring(input)?;
    #[expect(
        unsafe_code,
        reason = "All integer and raw-pointer fields of native tm admit zero, matching source memset"
    )]
    // SAFETY: libc tm contains only C integers and nullable raw pointers.
    let mut calendar: libc::tm = unsafe { std::mem::zeroed() };
    let end = input.as_bytes().len();
    let mut complete = false;
    for pattern in [
        c"%a %b %d %H:%M:%S %Y",
        c"%c",
        c"%Ec",
        c"%Y-%m-%d %H:%M:%S",
        c"%Y-%m-%d %H:%M",
        c"%x",
        c"%Ex",
        c"%Y-%m-%d",
        c"%Y-%m",
        c"%Y",
    ] {
        #[expect(
            unsafe_code,
            reason = "Valid C input/format and uniquely borrowed tm; partial fields intentionally survive failed formats as in source"
        )]
        // SAFETY: pointers remain live; strptime mutates only this initialized tm.
        let result = unsafe { libc::strptime(input.as_ptr(), pattern.as_ptr(), &mut calendar) };
        if !result.is_null() && result.addr() == input.as_ptr().addr() + end {
            complete = true;
            break;
        }
    }
    if !complete {
        return Err(io::Error::other("invalid absolute time"));
    }
    #[expect(
        unsafe_code,
        reason = "Native mktime receives initialized caller-owned tm and normalizes it in place"
    )]
    // SAFETY: calendar is live, initialized and uniquely borrowed.
    let seconds = unsafe { libc::mktime(&mut calendar) };
    if seconds == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok((seconds as u64).saturating_mul(1_000_000))
}

pub(crate) fn errno() -> i32 {
    #[expect(
        unsafe_code,
        reason = "Read only the calling thread's initialized native errno cell"
    )]
    // SAFETY: errno_ptr returns the live thread-local cell.
    unsafe {
        *errno_ptr()
    }
}
pub(crate) fn path_access(path: &[u8], mode: i32) -> io::Result<()> {
    let path = cstring(path)?;
    #[expect(
        unsafe_code,
        reason = "Live NUL-terminated native path and POSIX access mode, with no retained pointer"
    )]
    // SAFETY: access reads this C string only during the call.
    let status = unsafe { libc::access(path.as_ptr(), mode) };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
pub(crate) fn path_is_directory(path: &[u8]) -> io::Result<bool> {
    let path = cstring(path)?;
    let mut value = MaybeUninit::uninit();
    #[expect(
        unsafe_code,
        reason = "stat receives live native path and exclusive aligned output storage"
    )]
    // SAFETY: pointers remain valid through stat, which does not retain them.
    let status = unsafe { libc::stat(path.as_ptr(), value.as_mut_ptr()) };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    #[expect(
        unsafe_code,
        reason = "Successful native stat initialized the complete output structure"
    )]
    // SAFETY: this exact stat call returned success for this output storage.
    let value = unsafe { value.assume_init() };
    Ok(value.st_mode & libc::S_IFMT == libc::S_IFDIR)
}
pub(crate) fn path_mkdir(path: &[u8]) -> io::Result<()> {
    let path = cstring(path)?;
    #[expect(
        unsafe_code,
        reason = "Caller explicitly selected the log destination; mkdir receives only a live C path and official 0755 mode"
    )]
    // SAFETY: mkdir reads the path during this call and creates no retained borrow.
    let status = unsafe { libc::mkdir(path.as_ptr(), 0o755) };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[expect(
    unsafe_code,
    reason = "Exact POSIX inet_ntop ABI uses executing libc family/socklen_t and caller-owned aligned native structures"
)]
unsafe extern "C" {
    fn inet_ntop(
        family: libc::c_int,
        source: *const libc::c_void,
        destination: *mut libc::c_char,
        size: libc::socklen_t,
    ) -> *const libc::c_char;
}
/// Format without DNS or any socket operation, exactly as source GNUNET_a2s.
pub(crate) fn ipv6_text(address: [u8; 16]) -> io::Result<Vec<u8>> {
    let source = libc::in6_addr { s6_addr: address };
    let mut destination = [0 as libc::c_char; 46];
    #[expect(
        unsafe_code,
        reason = "Aligned initialized in6_addr input and 46-byte writable destination cover the exact POSIX IPv6 conversion contract"
    )]
    // SAFETY: both native objects are live and nonoverlapping; inet_ntop neither retains pointers nor exceeds the supplied capacity.
    let result = unsafe {
        inet_ntop(
            libc::AF_INET6,
            (&source as *const libc::in6_addr).cast(),
            destination.as_mut_ptr(),
            46,
        )
    };
    if result.is_null() {
        return Err(io::Error::last_os_error());
    }
    let length = destination
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| io::Error::other("native IPv6 formatter omitted terminator"))?;
    Ok(destination[..length].iter().map(|&b| b as u8).collect())
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
            RegexCompileFailure::InvalidPattern(code) => {
                std::io::Error::other(format!("literal regex rejected {code}"))
            }
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
