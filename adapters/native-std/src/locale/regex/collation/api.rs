//! System ICU C exports. No C++ ABI, locale installation or provider search.
use super::provider::{Part, Provider};
use std::{
    ffi::{c_char, c_void},
    io,
};

type Open = unsafe extern "C" fn(*const c_char, *mut i32) -> *mut c_void;
type Close = unsafe extern "C" fn(*mut c_void);
type Strength = unsafe extern "C" fn(*mut c_void, i32);
type Attribute = unsafe extern "C" fn(*mut c_void, i32, i32, *mut i32);
type Compare = unsafe extern "C" fn(*const c_void, *const u16, i32, *const u16, i32) -> i32;
type Contractions = unsafe extern "C" fn(*const c_void, *mut c_void, *mut c_void, i8, *mut i32);
type SetOpen = unsafe extern "C" fn() -> *mut c_void;
type Contains = unsafe extern "C" fn(*const c_void, *const u16, i32) -> i8;
type Count = unsafe extern "C" fn(*const c_void) -> i32;
type Item =
    unsafe extern "C" fn(*const c_void, i32, *mut i32, *mut i32, *mut u16, i32, *mut i32) -> i32;
type Language = unsafe extern "C" fn(*const c_char, *mut c_char, i32, *mut i32, *mut i32) -> i32;
type WindowsLocale = unsafe extern "C" fn(u32, *mut c_char, i32, *mut i32) -> i32;
type Likely = unsafe extern "C" fn(*const c_char, *mut c_char, i32, *mut i32) -> i32;
type Keyword =
    unsafe extern "C" fn(*const c_char, *const c_char, *mut c_char, i32, *mut i32) -> i32;
type Locale = unsafe extern "C" fn(*const c_void, i32, *mut i32) -> *const c_char;
pub(super) struct Api {
    provider: Provider,
    pub open: Open,
    pub close: Close,
    pub strength: Strength,
    pub attribute: Attribute,
    pub compare: Compare,
    pub contractions: Contractions,
    pub set_open: SetOpen,
    pub set_close: Close,
    pub contains: Contains,
    pub count: Count,
    pub item: Item,
    pub language: Language,
    pub windows_locale: WindowsLocale,
    pub canonical: Likely,
    pub likely: Likely,
    pub keyword: Keyword,
    pub locale: Locale,
}
impl Api {
    #[expect(
        unsafe_code,
        reason = "Typed stable ICU C exports are resolved from the selected original system provider references before any native object is constructed"
    )]
    pub fn load() -> io::Result<Self> {
        let provider = Provider::load()?;
        macro_rules! export {
            ($name:literal, $ty:ty, $part:ident) => {{
                let symbol = provider.symbol($name, Part::$part)?;
                // SAFETY: exact documented ICU C export, resolved on this provider.
                unsafe { std::mem::transmute::<*mut c_void, $ty>(symbol) }
            }};
        }
        let api = Self {
            open: export!(c"ucol_open", Open, Collation),
            close: export!(c"ucol_close", Close, Collation),
            strength: export!(c"ucol_setStrength", Strength, Collation),
            attribute: export!(c"ucol_setAttribute", Attribute, Collation),
            compare: export!(c"ucol_strcoll", Compare, Collation),
            contractions: export!(
                c"ucol_getContractionsAndExpansions",
                Contractions,
                Collation
            ),
            set_open: export!(c"uset_openEmpty", SetOpen, Common),
            set_close: export!(c"uset_close", Close, Common),
            contains: export!(c"uset_containsString", Contains, Common),
            count: export!(c"uset_getItemCount", Count, Common),
            item: export!(c"uset_getItem", Item, Common),
            language: export!(c"uloc_forLanguageTag", Language, Common),
            windows_locale: export!(c"uloc_getLocaleForLCID", WindowsLocale, Common),
            canonical: export!(c"uloc_canonicalize", Likely, Common),
            likely: export!(c"uloc_addLikelySubtags", Likely, Common),
            keyword: export!(c"uloc_getKeywordValue", Keyword, Common),
            locale: export!(c"ucol_getLocaleByType", Locale, Collation),
            provider,
        };
        // ICU may retain process/TLS caches beyond individual collator close.
        // Global u_cleanup would invalidate other users, so retain module code.
        api.provider.pin()?;
        Ok(api)
    }
}
