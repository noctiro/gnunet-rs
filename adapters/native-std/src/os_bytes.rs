//! Lossless bytes for local command/path processing, never a wire encoding.
//!
//! Unix retains native bytes. Windows uses UTF-8 plus three-byte encodings of
//! isolated UTF-16 surrogates (canonical WTF-8), constructed through safe wide
//! string APIs. Decoding rejects malformed or noncanonical byte sequences;
//! arbitrary bytes never enter unchecked OsStr constructors. NUL is preserved:
//! each eventual OS/C-string boundary must enforce its own terminator policy.
use std::{
    borrow::Cow,
    ffi::{OsStr, OsString},
    io,
};

/// Borrow the suffix after an ASCII option prefix without encoding or copying
/// a native string. Non-ASCII prefixes are refused; an empty prefix returns the
/// original value. Native code units, including isolated Windows surrogates,
/// remain unchanged. This grants no protocol text or filesystem capability.
#[must_use]
#[expect(
    unsafe_code,
    reason = "The suffix comes from the same native OsStr and is cut only after a complete ASCII prefix, a valid self-synchronizing encoding boundary"
)]
pub fn strip_ascii_prefix<'a>(value: &'a OsStr, prefix: &[u8]) -> Option<&'a OsStr> {
    if !prefix.is_ascii() {
        return None;
    }
    if prefix.is_empty() {
        return Some(value);
    }
    let suffix = value.as_encoded_bytes().strip_prefix(prefix)?;
    // SAFETY: these bytes come from this OsStr in the same process/compilation.
    // The only split is immediately after nonempty ASCII, hence after a valid
    // UTF-8 substring. No external or reconstructed bytes enter this constructor.
    Some(unsafe { OsStr::from_encoded_bytes_unchecked(suffix) })
}

/// Borrow ordinary native bytes; encode isolated Windows UTF-16 surrogates
/// without replacement characters. Valid Unicode is UTF-8 on both platforms.
#[must_use]
pub fn encode(value: &OsStr) -> Cow<'_, [u8]> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Cow::Borrowed(value.as_bytes())
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        if let Some(text) = value.to_str() {
            Cow::Borrowed(text.as_bytes())
        } else {
            Cow::Owned(encode_wide(value.encode_wide()))
        }
    }
}

/// Decode local bytes to a native string. Unix accepts every byte; Windows
/// accepts UTF-8 and canonical isolated-surrogate encodings, preserving code units.
pub fn decode(value: &[u8]) -> io::Result<Cow<'_, OsStr>> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(Cow::Borrowed(OsStr::from_bytes(value)))
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        match std::str::from_utf8(value) {
            Ok(text) => Ok(Cow::Borrowed(OsStr::new(text))),
            Err(_) => Ok(Cow::Owned(OsString::from_wide(&decode_wide(value)?))),
        }
    }
}

/// Decode an owned local byte buffer. Unix transfers its allocation directly.
pub fn decode_owned(value: Vec<u8>) -> io::Result<OsString> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        Ok(OsString::from_vec(value))
    }
    #[cfg(windows)]
    {
        decode(&value).map(Cow::into_owned)
    }
}

#[cfg(any(windows, test))]
fn encode_wide(value: impl IntoIterator<Item = u16>) -> Vec<u8> {
    let mut output = Vec::new();
    for character in char::decode_utf16(value) {
        match character {
            Ok(character) => {
                let mut bytes = [0; 4];
                output.extend_from_slice(character.encode_utf8(&mut bytes).as_bytes());
            }
            Err(error) => {
                let surrogate = error.unpaired_surrogate();
                output.extend_from_slice(&[
                    0xe0 | (surrogate >> 12) as u8,
                    0x80 | ((surrogate >> 6) & 0x3f) as u8,
                    0x80 | (surrogate & 0x3f) as u8,
                ]);
            }
        }
    }
    output
}

#[cfg(any(windows, test))]
fn decode_wide(mut input: &[u8]) -> io::Result<Vec<u16>> {
    let mut output = Vec::new();
    let mut previous_high = false;
    while !input.is_empty() {
        let valid = match std::str::from_utf8(input) {
            Ok(text) => {
                output.extend(text.encode_utf16());
                break;
            }
            Err(error) => error.valid_up_to(),
        };
        if valid != 0 {
            let text = std::str::from_utf8(&input[..valid]).map_err(io::Error::other)?;
            output.extend(text.encode_utf16());
            previous_high = false;
            input = &input[valid..];
        }
        let Some(&[0xed, second @ 0xa0..=0xbf, third @ 0x80..=0xbf]) = input.get(..3) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid local Windows string encoding",
            ));
        };
        let surrogate = 0xd000 | (u16::from(second & 0x3f) << 6) | u16::from(third & 0x3f);
        let high = surrogate < 0xdc00;
        if previous_high && !high {
            // A paired surrogate must use one four-byte scalar encoding. Accepting
            // both spellings would give a native pathname two local byte identities.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "noncanonical local Windows surrogate pair",
            ));
        }
        output.push(surrogate);
        previous_high = high;
        input = &input[3..];
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ascii_option_prefix_keeps_the_original_native_suffix() {
        let value = OsStr::new("--output=雪/result");
        assert_eq!(
            strip_ascii_prefix(value, b"--output="),
            Some(OsStr::new("雪/result"))
        );
        assert_eq!(strip_ascii_prefix(value, b"--missing="), None);
        assert_eq!(strip_ascii_prefix(value, &[0xc3, 0xa9]), None);
        assert_eq!(strip_ascii_prefix(value, b""), Some(value));
    }
    #[cfg(unix)]
    #[test]
    fn ascii_option_prefix_preserves_nonunicode_unix_bytes() {
        use std::os::unix::ffi::OsStrExt;
        let value = OsStr::from_bytes(b"--output=raw-\xff");
        assert_eq!(
            strip_ascii_prefix(value, b"--output=").map(OsStrExt::as_bytes),
            Some(b"raw-\xff".as_slice())
        );
    }
    #[cfg(windows)]
    #[test]
    fn ascii_option_prefix_preserves_isolated_utf16_surrogates() {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        let mut units: Vec<_> = "--output=".encode_utf16().collect();
        units.extend_from_slice(&[0xd800, u16::from(b'\\'), 0xdc00]);
        let value = OsString::from_wide(&units);
        let suffix = strip_ascii_prefix(&value, b"--output=")
            .map(|value| value.encode_wide().collect::<Vec<_>>());
        assert_eq!(suffix, Some(vec![0xd800, u16::from(b'\\'), 0xdc00]));
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Literal UTF-16/native-byte vectors independently assert valid Unicode, isolated surrogates and their canonical spelling"
    )]
    fn windows_code_units_have_one_lossless_local_byte_spelling() -> io::Result<()> {
        let units = [
            0x0043, 0x003a, 0x005c, 0x4e2d, 0xd83d, 0xde80, 0xd800, 0x002f, 0xdc00, 0x0000,
        ];
        let expected = b"C:\\\xe4\xb8\xad\xf0\x9f\x9a\x80\xed\xa0\x80/\xed\xb0\x80\0";
        assert_eq!(encode_wide(units), expected);
        assert_eq!(decode_wide(expected)?, units);
        for invalid in [
            &b"\xff"[..],
            &b"\xc0\xaf"[..],
            &b"\xf4\x90\x80\x80"[..],
            &b"\xed\xa0"[..],
            &b"\xed\xa0\x80\xed\xb0\x80"[..],
        ] {
            assert_eq!(
                decode_wide(invalid).err().map(|e| e.kind()),
                Some(io::ErrorKind::InvalidData)
            );
        }
        Ok(())
    }
    #[cfg(windows)]
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Native wide roundtrip asserts exact original code units rather than lossy display text"
    )]
    fn native_windows_arguments_retain_isolated_surrogates_and_unicode() -> io::Result<()> {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        let units = [0xd800, 0x61, 0xdc00, 0xd83d, 0xde80];
        let original = OsString::from_wide(&units);
        let encoded = encode(&original);
        let decoded = decode(&encoded)?;
        assert_eq!(decoded.encode_wide().collect::<Vec<_>>(), units);
        assert_eq!(decode_owned(encoded.into_owned())?, original);
        assert!(matches!(
            encode(OsStr::new("ordinary Unicode 中")),
            Cow::Borrowed(_)
        ));
        Ok(())
    }
    #[cfg(unix)]
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "All non-UTF-8 Unix bytes remain borrowed and owned decode transfers the original native spelling"
    )]
    fn unix_native_bytes_are_unchanged() -> io::Result<()> {
        use std::os::unix::ffi::OsStrExt;
        let bytes = b"\xff\0\xed\xa0\x80";
        assert!(matches!(encode(OsStr::from_bytes(bytes)), Cow::Borrowed(value) if value == bytes));
        assert_eq!(decode_owned(bytes.to_vec())?.as_bytes(), bytes);
        Ok(())
    }
}
