//! Public Windows NLS resolution of UCRT category names; no CRT-layout access.
use crate::windows_crt::{Errno, crt_error};
use std::{ffi::c_int, io};
use windows_sys::Win32::Foundation::{ERROR_INVALID_PARAMETER, GetLastError};
use windows_sys::Win32::Globalization::{
    CSTR_EQUAL, CompareStringOrdinal, ConvertDefaultLocale, EnumSystemLocalesEx, GetLocaleInfoEx,
    LOCALE_INEUTRAL, LOCALE_RETURN_NUMBER, LOCALE_SABBREVCTRYNAME, LOCALE_SABBREVLANGNAME,
    LOCALE_SENGLISHCOUNTRYNAME, LOCALE_SENGLISHLANGUAGENAME, LOCALE_SISO639LANGNAME,
    LOCALE_SISO3166CTRYNAME, LOCALE_SPECIFICDATA, LocaleNameToLCID, ResolveLocaleName,
};
#[derive(Clone, Copy)]
pub(crate) enum Category {
    Time,
    Collate,
}
impl Category {
    fn value(self) -> c_int {
        match self {
            Self::Time => libc::LC_TIME,
            Self::Collate => libc::LC_COLLATE,
        }
    }
    fn operation(self) -> &'static str {
        match self {
            Self::Time => "_wsetlocale(LC_TIME,NULL)",
            Self::Collate => "_wsetlocale(LC_COLLATE,NULL)",
        }
    }
}
pub(crate) fn is_classic(name: &[u16]) -> bool {
    without_codepage(name) == [u16::from(b'C')]
}
const MAX_NAME: usize = 32767;
const METADATA_UNITS: usize = 512;
const INVARIANT: u32 = 0x007f; // Windows LOCALE_INVARIANT.
const NLS_NAME_UNITS: usize = 85; // LOCALE_NAME_MAX_LENGTH, including NUL.
#[derive(Clone)]
pub(crate) struct Name(Vec<u16>);
impl Name {
    pub(crate) fn units(&self) -> &[u16] {
        &self.0[..self.0.len() - 1]
    }
    pub(crate) fn as_ptr(&self) -> *const u16 {
        self.0.as_ptr()
    }
    fn from_buffer(buffer: &[u16], count: i32) -> io::Result<Self> {
        let count = usize::try_from(count).map_err(|_| io::ErrorKind::InvalidData)?;
        let value = buffer
            .get(..count)
            .filter(|value| value.last() == Some(&0))
            .filter(|value| !value[..value.len() - 1].contains(&0))
            .ok_or(io::ErrorKind::InvalidData)?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(count)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        owned.extend_from_slice(value);
        Ok(Self(owned))
    }
}
fn named(wide: &[u16]) -> io::Result<Option<Name>> {
    let mut neutral = 0u32;
    #[expect(
        unsafe_code,
        reason = "The owned terminated name and aligned exclusive DWORD output satisfy the documented LOCALE_RETURN_NUMBER two-wide-unit contract"
    )]
    // SAFETY: wide came from a bounded terminated copy; output holds two u16 units.
    let count = unsafe {
        GetLocaleInfoEx(
            wide.as_ptr(),
            LOCALE_INEUTRAL | LOCALE_RETURN_NUMBER,
            (&mut neutral as *mut u32).cast(),
            2,
        )
    };
    if count == 0 {
        #[expect(
            unsafe_code,
            reason = "Immediately capture the preceding NLS failure before another native operation"
        )]
        // SAFETY: GetLastError has no input or pointer ownership.
        let error = unsafe { GetLastError() };
        return if error == ERROR_INVALID_PARAMETER {
            Ok(None)
        } else {
            Err(io::Error::from_raw_os_error(error as i32))
        };
    }
    if count != 2 || neutral > 1 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    if neutral == 0 {
        // Retain the validated selected name, including alternate-sort suffixes.
        // General locale properties need not preserve that complete identity.
        let count = i32::try_from(wide.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
        return Name::from_buffer(wide, count).map(Some);
    }
    let mut buffer = [0; NLS_NAME_UNITS];
    #[expect(
        unsafe_code,
        reason = "Only a validated neutral NLS name is resolved to its documented language-default region; no unknown name fallback occurs"
    )]
    // SAFETY: owned input/output remain live and native locale selection is unchanged.
    let count =
        unsafe { ResolveLocaleName(wide.as_ptr(), buffer.as_mut_ptr(), buffer.len() as i32) };
    if count == 0 {
        return Err(io::Error::last_os_error());
    }
    Name::from_buffer(&buffer, count).map(Some)
}
#[expect(
    unsafe_code,
    reason = "UCRT locale.h declares this wide query ABI; only a typed valid category and a null locale argument are passed"
)]
unsafe extern "C" {
    fn _wsetlocale(category: c_int, locale: *const u16) -> *const u16;
}

/// Caller must exclude concurrent UCRT locale mutation until the borrowed query
/// string has been copied. No locale selection is changed by this function.
#[expect(
    unsafe_code,
    reason = "The enclosing native locale capability protects UCRT query storage until its bounded NUL-terminated UTF-16 copy completes"
)]
pub(crate) unsafe fn current_name(category: Category) -> io::Result<Vec<u16>> {
    let _errno = Errno::clear();
    // SAFETY: the typed category is valid; null requests a read-only name query.
    let value = unsafe { _wsetlocale(category.value(), std::ptr::null()) };
    if value.is_null() {
        return Err(crt_error(category.operation()));
    }
    let mut name = Vec::new();
    for at in 0..=MAX_NAME {
        // SAFETY: the native API returns a live NUL-terminated wide string; the
        // caller excludes invalidating writes until we finish copying it.
        let unit = unsafe { value.add(at).read() };
        if unit == 0 {
            if name.is_empty() {
                return Err(io::ErrorKind::InvalidData.into());
            }
            return Ok(name);
        }
        name.try_reserve(1)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        name.push(unit);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "native locale name exceeds bound",
    ))
}
fn without_codepage(name: &[u16]) -> &[u16] {
    if let Some(at) = name.iter().rposition(|unit| *unit == u16::from(b'.')) {
        let suffix = &name[at + 1..];
        if !suffix.is_empty() && suffix.iter().all(|unit| (48..=57).contains(unit)) {
            return &name[..at];
        }
        for codepage in ["UTF8", "UTF-8", "ACP", "OCP"] {
            if suffix
                .iter()
                .map(|&unit| {
                    if unit <= 127 {
                        u16::from((unit as u8).to_ascii_uppercase())
                    } else {
                        unit
                    }
                })
                .eq(codepage.encode_utf16())
            {
                return &name[..at];
            }
        }
    }
    name
}
fn nul(name: &[u16]) -> io::Result<Vec<u16>> {
    let mut out = Vec::new();
    out.try_reserve_exact(name.len() + 1)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    out.extend_from_slice(name);
    out.push(0);
    Ok(out)
}
fn equal(a: &[u16], b: &[u16]) -> io::Result<bool> {
    #[expect(
        unsafe_code,
        reason = "Both initialized UTF-16 spans have validated native-int lengths and stay borrowed through a bounded ordinal comparison"
    )]
    // SAFETY: lengths are bounded by MAX_NAME or fixed NLS metadata storage.
    let result =
        unsafe { CompareStringOrdinal(a.as_ptr(), a.len() as i32, b.as_ptr(), b.len() as i32, 1) };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(result == CSTR_EQUAL)
}
fn specific(id: u32) -> io::Result<u32> {
    #[expect(
        unsafe_code,
        reason = "ConvertDefaultLocale accepts a scalar LCID and changes no selection"
    )]
    // SAFETY: id came from successful native name resolution.
    let resolved = unsafe { ConvertDefaultLocale(id) };
    // OLE accepts only LCIDs, so unspecified/custom placeholders cannot retain
    // an exact named culture. Refuse instead of silently using the user default.
    if matches!(resolved, 0x0c00 | 0x1000 | 0x1400) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native LCID cannot retain this named custom locale",
        ));
    }
    Ok(resolved)
}
struct Search<'name> {
    language: &'name [u16],
    country: Option<&'name [u16]>,
    found: Option<Name>,
    failure: Option<io::Error>,
}
impl Search<'_> {
    fn field_matches(&self, name: *const u16, keys: &[u32], value: &[u16]) -> io::Result<bool> {
        let mut buffer = [0u16; METADATA_UNITS];
        for key in keys {
            #[expect(
                unsafe_code,
                reason = "EnumSystemLocalesEx supplies a valid callback-scoped locale name; fixed writable UTF-16 metadata storage has the declared capacity"
            )]
            // SAFETY: name remains live for this native callback and no pointer escapes.
            let count =
                unsafe { GetLocaleInfoEx(name, *key, buffer.as_mut_ptr(), buffer.len() as i32) };
            if count == 0 {
                return Err(io::Error::last_os_error());
            }
            let count = usize::try_from(count).map_err(|_| io::ErrorKind::InvalidData)?;
            let data = buffer
                .get(..count)
                .filter(|data| data.last() == Some(&0))
                .ok_or(io::ErrorKind::InvalidData)?;
            if equal(value, &data[..data.len() - 1])? {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn visit(&mut self, name: *const u16) -> io::Result<bool> {
        if !self.field_matches(
            name,
            &[
                LOCALE_SENGLISHLANGUAGENAME,
                LOCALE_SISO639LANGNAME,
                LOCALE_SABBREVLANGNAME,
            ],
            self.language,
        )? {
            return Ok(true);
        }
        if let Some(country) = self.country
            && !self.field_matches(
                name,
                &[
                    LOCALE_SENGLISHCOUNTRYNAME,
                    LOCALE_SISO3166CTRYNAME,
                    LOCALE_SABBREVCTRYNAME,
                ],
                country,
            )?
        {
            return Ok(true);
        }
        if self.country.is_none() {
            #[expect(
                unsafe_code,
                reason = "The callback's specific name supplies a scalar language ID used only to select the native default country for a language-only alias"
            )]
            // SAFETY: no raw locale handle is borrowed, changed or retained.
            let id = unsafe { LocaleNameToLCID(name, 0) };
            if id == 0 {
                return Err(io::Error::last_os_error());
            }
            #[expect(
                unsafe_code,
                reason = "A successful scalar LCID supplies the language-neutral default lookup; no locale is installed"
            )]
            // SAFETY: both inputs and output are scalar IDs, with no pointer ownership.
            let preferred = unsafe { ConvertDefaultLocale(id & 0x03ff) };
            if matches!(id, 0x0c00 | 0x1000 | 0x1400) || id != preferred {
                return Ok(true);
            }
        }
        let mut buffer = [0; NLS_NAME_UNITS];
        for (at, slot) in buffer.iter_mut().enumerate() {
            #[expect(
                unsafe_code,
                reason = "EnumSystemLocalesEx guarantees a live terminated locale name of at most LOCALE_NAME_MAX_LENGTH units during its synchronous callback"
            )]
            // SAFETY: the input remains callback-scoped and copying stops at NUL.
            let unit = unsafe { name.add(at).read() };
            *slot = unit;
            if *slot == 0 {
                self.found = Some(Name::from_buffer(&buffer, (at + 1) as i32)?);
                return Ok(false);
            }
        }
        Err(io::ErrorKind::InvalidData.into())
    }
}
#[expect(
    unsafe_code,
    reason = "EnumSystemLocalesEx synchronously calls this private trampoline with its exact live Search pointer; Rust panics are stopped at the FFI boundary"
)]
unsafe extern "system" fn visit(name: *const u16, _: u32, context: isize) -> i32 {
    if context == 0 || name.is_null() {
        return 0;
    }
    // SAFETY: resolve retains exclusive Search storage for the entire synchronous
    // enumeration. The callback is not retained or invoked concurrently.
    let search = unsafe { &mut *(context as *mut Search<'_>) };
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| search.visit(name))) {
        Ok(Ok(keep_going)) => i32::from(keep_going),
        Ok(Err(error)) => {
            search.failure = Some(error);
            0
        }
        Err(_) => {
            search.failure = Some(io::Error::other("native locale callback panicked"));
            0
        }
    }
}
/// Resolve only at the Automation boundary; named NLS operations retain Name.
pub(crate) fn automation_id(name: &Name) -> io::Result<u32> {
    if name.0 == [0] {
        return Ok(INVARIANT);
    }
    #[expect(
        unsafe_code,
        reason = "An owned validated specific NLS name remains live through its read-only LCID conversion"
    )]
    // SAFETY: a null user-default name is never passed.
    let id = unsafe { LocaleNameToLCID(name.as_ptr(), 0) };
    if id == 0 {
        return Err(io::Error::last_os_error());
    }
    specific(id)
}
pub(crate) fn resolve_name(name: &[u16]) -> io::Result<Name> {
    if name.len() > MAX_NAME {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let name = without_codepage(name);
    if name == [u16::from(b'C')] {
        return Ok(Name(nul(&[])?));
    }
    let wide = nul(name)?;
    if let Some(name) = named(&wide)? {
        return Ok(name);
    }
    let (language, country) = match name.iter().position(|unit| *unit == u16::from(b'_')) {
        Some(at) => (&name[..at], Some(&name[at + 1..])),
        None => (name, None),
    };
    if language.is_empty() || country.is_some_and(<[u16]>::is_empty) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut search = Search {
        language,
        country,
        found: None,
        failure: None,
    };
    #[expect(
        unsafe_code,
        reason = "A private non-escaping callback receives exclusive live Search storage; enumeration is synchronous and uses only public NLS APIs"
    )]
    // SAFETY: callback/data ABI match, reserved is null, and Search remains live.
    let result = unsafe {
        EnumSystemLocalesEx(
            Some(visit),
            LOCALE_SPECIFICDATA,
            (&mut search as *mut Search<'_>) as isize,
            std::ptr::null(),
        )
    };
    if let Some(error) = search.failure {
        return Err(error);
    }
    if let Some(id) = search.found {
        return Ok(id);
    }
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "current UCRT locale has no matching NLS locale",
    ))
}
