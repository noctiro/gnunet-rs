//! Owned Windows ICU collation and its actual contraction inventory.
mod api;
mod names;
mod provider;
use super::{Strength, nls};
use api::Api;
use std::{
    cmp::Ordering,
    ffi::{CStr, c_void},
    fmt, io,
    ptr::NonNull,
    rc::Rc,
};
const MAX_ITEMS: i32 = 16384;
const MAX_ELEMENT_UNITS: usize = 128;
const MAX_ELEMENT_SYMBOLS: usize = 64;
#[derive(Debug)]
struct NativeError {
    operation: &'static str,
    code: i32,
}
impl fmt::Display for NativeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ICU status {}", self.operation, self.code)
    }
}
impl std::error::Error for NativeError {}
fn check(operation: &'static str, code: i32) -> io::Result<()> {
    if code > 0 {
        return Err(io::Error::other(NativeError { operation, code }));
    }
    Ok(())
}
fn language_script(name: &CStr) -> (&[u8], &[u8]) {
    let mut fields = name.to_bytes().split(|unit| matches!(*unit, b'_' | b'@'));
    let language = fields.next().unwrap_or_default();
    let script = fields
        .next()
        .filter(|value| value.len() == 4)
        .unwrap_or_default();
    (language, script)
}
struct Collator {
    raw: NonNull<c_void>,
    api: Rc<Api>,
}
impl Collator {
    #[expect(
        unsafe_code,
        reason = "The exact stable ICU C ABI returns one owned collator; all name and status storage remains live and ownership precedes fallible setup"
    )]
    fn open(api: Rc<Api>, locale: &CStr, strength: i32) -> io::Result<Self> {
        let mut status = 0;
        // SAFETY: validated terminated locale and writable status; no borrowed output.
        let raw = unsafe { (api.open)(locale.as_ptr(), &mut status) };
        let raw = NonNull::new(raw).ok_or_else(|| {
            io::Error::other(NativeError {
                operation: "ucol_open",
                code: status,
            })
        })?;
        let result = Self { raw, api };
        check("ucol_open", status)?;
        // SAFETY: this unique collator has not been published; strength is PRIMARY0
        // or IDENTICAL15. Normalization ON17 is selected for attribute4.
        unsafe {
            (result.api.strength)(result.raw.as_ptr(), strength);
        }
        status = 0;
        // SAFETY: initialized exclusive object and documented attribute values.
        unsafe {
            (result.api.attribute)(result.raw.as_ptr(), 4, 17, &mut status);
        }
        check("ucol_setAttribute(normalization)", status)?;
        status = 0;
        // SAFETY: the collator owns the returned, terminated valid-locale name.
        let valid = unsafe { (result.api.locale)(result.raw.as_ptr(), 1, &mut status) };
        check("ucol_getLocaleByType(valid)", status)?;
        if valid.is_null() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        // SAFETY: this successful ICU return is terminated and remains live.
        let valid = unsafe { CStr::from_ptr(valid) };
        let requested_identity = result.api.expanded(locale)?;
        let valid_identity = result.api.expanded(valid)?;
        if language_script(&valid_identity) != language_script(&requested_identity) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ICU did not retain the selected collation language/script",
            ));
        }
        let requested = result.api.sort_keyword(locale)?;
        if !requested.is_empty() {
            status = 0;
            // SAFETY: the provider returns borrowed terminated locale storage valid
            // while this collator remains owned; no pointer escapes this function.
            let actual = unsafe { (result.api.locale)(result.raw.as_ptr(), 0, &mut status) };
            check("ucol_getLocaleByType", status)?;
            if actual.is_null() {
                return Err(io::ErrorKind::InvalidData.into());
            }
            // SAFETY: successful ICU output is a valid terminated C string.
            let actual = unsafe { CStr::from_ptr(actual) };
            if result.api.sort_keyword(actual)? != requested {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "ICU did not retain the selected alternate sort",
                ));
            }
        }
        Ok(result)
    }
}
impl Drop for Collator {
    #[expect(
        unsafe_code,
        reason = "One original collator is synchronously closed while its exact provider remains owned"
    )]
    fn drop(&mut self) {
        // SAFETY: unique live collator, no outstanding calls or borrowed outputs.
        unsafe {
            (self.api.close)(self.raw.as_ptr());
        }
    }
}
struct Set {
    raw: NonNull<c_void>,
    api: Rc<Api>,
}
impl Set {
    #[expect(
        unsafe_code,
        reason = "The stable ICU constructor returns one owned Unicode set; null denotes allocation failure"
    )]
    fn new(api: Rc<Api>) -> io::Result<Self> {
        // SAFETY: no arguments or retained input pointers.
        let raw = unsafe { (api.set_open)() };
        Ok(Self {
            raw: NonNull::new(raw).ok_or(io::ErrorKind::OutOfMemory)?,
            api,
        })
    }
}
impl Drop for Set {
    #[expect(
        unsafe_code,
        reason = "The original Unicode set is exclusively owned and its ICU provider outlives close"
    )]
    fn drop(&mut self) {
        // SAFETY: unique live set, with no outstanding native call.
        unsafe {
            (self.api.set_close)(self.raw.as_ptr());
        }
    }
}
pub(super) struct Collation {
    ordering: Collator,
    primary: Collator,
    contractions: Set,
    width: usize,
    prefixes: Box<[(u32, usize)]>,
}
impl Collation {
    #[expect(
        unsafe_code,
        reason = "Owned ICU collators/set remain live through synchronous calls; fixed initialized buffers and explicit limits bound native inventory output"
    )]
    pub fn open(name: &nls::Name) -> io::Result<Self> {
        let api = Rc::new(Api::load()?);
        let locale = api.locale_id(name)?;
        let ordering = Collator::open(Rc::clone(&api), &locale, 15)?;
        let primary = Collator::open(Rc::clone(&api), &locale, 0)?;
        let contractions = Set::new(Rc::clone(&api))?;
        let mut status = 0;
        // SAFETY: immutable collator, unique output set, no expansions/prefixes.
        unsafe {
            (api.contractions)(
                ordering.raw.as_ptr(),
                contractions.raw.as_ptr(),
                std::ptr::null_mut(),
                0,
                &mut status,
            );
        }
        check("ucol_getContractionsAndExpansions", status)?;
        // SAFETY: immutable live set with no concurrent mutations.
        let count = unsafe { (api.count)(contractions.raw.as_ptr()) };
        if !(0..=MAX_ITEMS).contains(&count) {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "ICU contraction inventory exceeds bound",
            ));
        }
        let mut width = 1;
        let mut prefixes = Vec::new();
        prefixes
            .try_reserve_exact(count as usize)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        for index in 0..count {
            let (mut start, mut end, mut status) = (0, 0, 0);
            let mut output = [0; MAX_ELEMENT_UNITS];
            // SAFETY: valid item index, original set and complete exclusive outputs.
            let size = unsafe {
                (api.item)(
                    contractions.raw.as_ptr(),
                    index,
                    &mut start,
                    &mut end,
                    output.as_mut_ptr(),
                    output.len() as i32,
                    &mut status,
                )
            };
            check("uset_getItem", status)?;
            let size = usize::try_from(size).map_err(|_| io::ErrorKind::InvalidData)?;
            let text = output.get(..size).ok_or(io::ErrorKind::InvalidData)?;
            let mut symbols = 0;
            let mut first = None;
            for value in char::decode_utf16(text.iter().copied()) {
                let value = value.map_err(|_| io::ErrorKind::InvalidData)?;
                first.get_or_insert(u32::from(value));
                symbols += 1;
            }
            if symbols > MAX_ELEMENT_SYMBOLS {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "ICU collating element exceeds symbol bound",
                ));
            }
            width = width.max(symbols);
            if symbols > 1
                && let Some(first) = first
            {
                prefixes.push((first, symbols));
            }
        }
        prefixes.sort_unstable_by_key(|entry| entry.0);
        prefixes.dedup_by(|later, earlier| {
            if later.0 == earlier.0 {
                earlier.1 = earlier.1.max(later.1);
                true
            } else {
                false
            }
        });
        Ok(Self {
            ordering,
            primary,
            contractions,
            width,
            prefixes: prefixes.into_boxed_slice(),
        })
    }
    pub fn width(&self) -> usize {
        self.width
    }
    pub fn width_for(&self, first: char) -> usize {
        self.prefixes
            .binary_search_by_key(&u32::from(first), |entry| entry.0)
            .map_or(1, |index| self.prefixes[index].1)
    }
    #[expect(
        unsafe_code,
        reason = "The immutable contraction set and validated bounded UTF-16 input remain live for this synchronous membership query"
    )]
    pub fn contains(&self, value: &[u16]) -> bool {
        // SAFETY: the caller validated the complete nonempty span and native length.
        unsafe {
            (self.contractions.api.contains)(
                self.contractions.raw.as_ptr(),
                value.as_ptr(),
                value.len() as i32,
            ) != 0
        }
    }
    #[expect(
        unsafe_code,
        reason = "Both validated bounded spans and the immutable original strength-specific collator remain live through comparison"
    )]
    pub fn compare(&self, left: &[u16], right: &[u16], strength: Strength) -> io::Result<Ordering> {
        let collator = match strength {
            Strength::Ordering => &self.ordering,
            Strength::Primary => &self.primary,
        };
        // SAFETY: no pointer escapes, and this collator is immutable after setup.
        match unsafe {
            (collator.api.compare)(
                collator.raw.as_ptr(),
                left.as_ptr(),
                left.len() as i32,
                right.as_ptr(),
                right.len() as i32,
            )
        } {
            -1 => Ok(Ordering::Less),
            0 => Ok(Ordering::Equal),
            1 => Ok(Ordering::Greater),
            _ => Err(io::ErrorKind::InvalidData.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Api, Collator};
    use std::{io, rc::Rc};
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Read-only native ICU identity checks distinguish normal English root-data inheritance from substitution of an unknown language"
    )]
    fn root_data_inheritance_does_not_substitute_unknown_language() -> io::Result<()> {
        let api = Rc::new(Api::load()?);
        let _english = Collator::open(Rc::clone(&api), c"en_US", 15)?;
        let error = Collator::open(api, c"zz_ZZ", 15)
            .err()
            .ok_or_else(|| io::Error::other("unknown collation language was accepted"))?;
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        Ok(())
    }
}
