//! Native character properties and collation; no regex syntax or matching policy.
use super::{CharacterClass, LocaleSnapshot, nls};
use std::{cmp::Ordering, fmt, io};
mod collation;
use collation::Collation;
use windows_sys::Win32::Globalization::{CT_CTYPE1, GetStringTypeW};

#[expect(
    unsafe_code,
    reason = "UCRT wctype.h declares this immutable explicit-locale wide-character classifier"
)]
unsafe extern "C" {
    fn _iswctype_l(value: u16, mask: u16, locale: *mut std::ffi::c_void) -> i32;
}

/// The native collation strength selected for a range or equivalence class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strength {
    /// Full locale ordering, including case and secondary distinctions.
    Ordering,
    /// Primary equivalence, ignoring case, diacritics, width and kana distinctions.
    /// C collation retains ordinal equality.
    Primary,
}
/// Independently owned CRT classification locale and resolved LC_COLLATE identity.
pub struct Locale {
    snapshot: LocaleSnapshot,
    collation: Option<Collation>,
}
impl fmt::Debug for Locale {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("Locale")
            .field("classic", &self.collation.is_none())
            .finish_non_exhaustive()
    }
}
impl Locale {
    /// Capture the calling thread's current classification and collation.
    ///
    /// # Errors
    /// Retains CRT/NLS capture, system ICU loading and collation errors. Named
    /// cultures preserve language/script and selected alternate sort; unsupported
    /// mappings are refused instead of selecting user-default collation.
    ///
    /// # Safety
    /// Exclude native locale mutation until all bounded observations finish.
    #[expect(
        unsafe_code,
        reason = "Caller exclusion protects the queried name and independent owned CRT snapshot capture"
    )]
    pub unsafe fn capture_current_thread() -> io::Result<Self> {
        // SAFETY: both operations share the caller's locale-mutation exclusion.
        let (name, snapshot) = unsafe {
            (
                nls::current_name(nls::Category::Collate)?,
                LocaleSnapshot::capture_current_thread()?,
            )
        };
        let collation = if nls::is_classic(&name) {
            None
        } else {
            Some(Collation::open(&nls::resolve_name(&name)?)?)
        };
        Ok(Self {
            collation,
            snapshot,
        })
    }
    /// Whether this retained collation is the C locale's ordinal ordering.
    #[must_use]
    pub fn is_classic_collation(&self) -> bool {
        self.collation.is_none()
    }
    /// Classify one Unicode scalar. BMP properties use the retained CRT locale;
    /// supplementary properties use the operating system's NLS character data.
    ///
    /// # Errors
    /// Returns the original Win32 error if supplementary classification fails.
    pub fn classify(&self, value: char, class: CharacterClass) -> io::Result<bool> {
        if class == CharacterClass::Blank && value == '\t' {
            return Ok(true);
        }
        let mask = match class {
            CharacterClass::Alpha => 0x0103,
            CharacterClass::Alnum => 0x0107,
            CharacterClass::Blank => 0x0040,
            CharacterClass::Control => 0x0020,
            CharacterClass::Digit => 0x0004,
            CharacterClass::Graph => 0x0117,
            CharacterClass::Lower => 0x0002,
            CharacterClass::Print => 0x0157,
            CharacterClass::Punct => 0x0010,
            CharacterClass::Space => 0x0008,
            CharacterClass::Upper => 0x0001,
            CharacterClass::Hex => 0x0080,
        };
        if let Ok(value) = u16::try_from(u32::from(value)) {
            #[expect(
                unsafe_code,
                reason = "A Unicode BMP scalar is a valid wint_t; the documented mask and immutable owned locale stay live through the call"
            )]
            // SAFETY: no raw selector or mutable locale ownership is exposed.
            return Ok(unsafe { _iswctype_l(value, mask, self.snapshot.as_raw()) } != 0);
        }
        let mut wide = [0; 2];
        let wide = value.encode_utf16(&mut wide);
        let mut flags = [0u16; 2];
        #[expect(
            unsafe_code,
            reason = "A complete valid surrogate pair and two initialized exclusive output words satisfy GetStringTypeW's per-code-unit buffer contract"
        )]
        // SAFETY: both arrays stay live and classification retains no pointer.
        if unsafe {
            GetStringTypeW(
                CT_CTYPE1,
                wide.as_ptr(),
                wide.len() as i32,
                flags.as_mut_ptr(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok((flags[0] | flags[1]) & mask != 0)
    }
    /// Compare two bounded, nonempty Unicode spans under the captured collation.
    /// No locale is installed and no user-default fallback is selected.
    ///
    /// # Errors
    /// Rejects NUL, invalid UTF-16 or spans above 128 units; native failures retain
    /// their original domain. Named sort data follows the system ICU version.
    pub fn compare(&self, left: &[u16], right: &[u16], strength: Strength) -> io::Result<Ordering> {
        for value in [left, right] {
            if value.is_empty()
                || value.len() > 128
                || value.contains(&0)
                || char::decode_utf16(value.iter().copied()).any(|unit| unit.is_err())
            {
                return Err(io::ErrorKind::InvalidInput.into());
            }
        }
        match &self.collation {
            Some(collation) => collation.compare(left, right, strength),
            None => Ok(left.cmp(right)),
        }
    }
    /// Maximum Unicode-scalar width in the retained collating-element inventory.
    pub fn element_width(&self) -> usize {
        self.collation.as_ref().map_or(1, Collation::width)
    }
    /// Maximum element width for this first scalar, without a native lookup.
    pub fn element_width_for(&self, first: char) -> usize {
        self.collation
            .as_ref()
            .map_or(1, |collation| collation.width_for(first))
    }
    /// Whether a valid bounded span is one character or a native contraction.
    /// Arbitrary Unicode sequences are never assumed to be collating elements.
    pub fn collating_symbol(&self, value: &[u16]) -> io::Result<bool> {
        if value.is_empty() || value.len() > 128 || value.contains(&0) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut count = 0;
        for unit in char::decode_utf16(value.iter().copied()) {
            unit.map_err(|_| io::ErrorKind::InvalidInput)?;
            count += 1;
        }
        Ok(count == 1
            || self
                .collation
                .as_ref()
                .is_some_and(|collation| collation.contains(value)))
    }
}

#[cfg(test)]
mod tests {
    use super::{Collation, Locale, LocaleSnapshot, Strength, nls};
    use std::{cmp::Ordering, io};
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "System ICU sorting fixtures distinguish the selected alternate sort from its base culture without global locale changes"
    )]
    fn alternate_sort_name_keeps_phonebook_primary_weights() -> io::Result<()> {
        let locale = |name: &str| -> io::Result<Locale> {
            Ok(Locale {
                snapshot: LocaleSnapshot::named(b"C")?,
                collation: Some(Collation::open(&nls::resolve_name(
                    &name.encode_utf16().collect::<Vec<_>>(),
                )?)?),
            })
        };
        let phonebook = locale("de-DE_phoneb")?;
        let dictionary = locale("de-DE")?;
        assert_eq!(
            phonebook.compare(&[0x00e4], &[0x61, 0x65], Strength::Primary)?,
            Ordering::Equal
        );
        assert_ne!(
            dictionary.compare(&[0x00e4], &[0x61, 0x65], Strength::Primary)?,
            Ordering::Equal
        );
        Ok(())
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Read-only system ICU fixtures distinguish actual Czech contractions from arbitrary Unicode strings"
    )]
    fn contraction_inventory_owns_boundaries_and_ordering() -> io::Result<()> {
        let locale = Locale {
            snapshot: LocaleSnapshot::named(b"C")?,
            collation: Some(Collation::open(&nls::resolve_name(
                &"cs-CZ".encode_utf16().collect::<Vec<_>>(),
            )?)?),
        };
        let units = |text: &str| text.encode_utf16().collect::<Vec<_>>();
        assert!(locale.collating_symbol(&units("ch"))?);
        assert!(!locale.collating_symbol(&units("cx"))?);
        assert!(locale.element_width() >= 2);
        assert!(locale.element_width_for('c') >= 2);
        assert_eq!(
            locale.compare(&units("h"), &units("ch"), Strength::Ordering)?,
            Ordering::Less
        );
        assert_eq!(
            locale.compare(&units("ch"), &units("i"), Strength::Ordering)?,
            Ordering::Less
        );
        Ok(())
    }
}
