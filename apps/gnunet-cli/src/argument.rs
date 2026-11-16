//! Command text and wire bytes, separate from native filesystem path encoding.
use std::{error::Error, ffi::OsStr};
/// Unix retains byte arguments. Windows requires Unicode before UTF-8 enters a
/// protocol field; local WTF-8 path preservation is not a network encoding.
pub(super) fn wire_bytes(value: &OsStr) -> Result<&[u8], Box<dyn Error>> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(value.as_bytes())
    }
    #[cfg(not(unix))]
    {
        value
            .to_str()
            .map(str::as_bytes)
            .ok_or_else(|| "wire argument must be Unicode".into())
    }
}
pub(super) fn text(value: &OsStr) -> Result<&str, Box<dyn Error>> {
    std::str::from_utf8(wire_bytes(value)?).map_err(|_| "command requires UTF-8 arguments".into())
}
/// Lossless local path spelling for command output and local persistence only.
/// This is never an encoding for a GNUnet URI, name or other protocol field.
#[cfg(feature = "fs")]
pub(super) fn native_bytes(value: &OsStr) -> std::borrow::Cow<'_, [u8]> {
    gnunet_native::os_bytes::encode(value)
}
#[cfg(test)]
mod tests {
    use super::wire_bytes;
    use std::ffi::{OsStr, OsString};
    #[test]
    fn unicode_names_enter_the_wire_as_utf8() -> Result<(), Box<dyn std::error::Error>> {
        if wire_bytes(OsStr::new("zone-中-λ"))? != "zone-中-λ".as_bytes() {
            return Err("wire name changed its UTF-8 bytes".into());
        }
        Ok(())
    }
    #[cfg(unix)]
    #[test]
    fn unix_byte_names_do_not_require_unicode() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::ffi::OsStringExt;
        let name = OsString::from_vec(vec![b'n', 0xff]);
        if wire_bytes(&name)? != [b'n', 0xff] {
            return Err("Unix byte name was rewritten".into());
        }
        Ok(())
    }
    #[cfg(windows)]
    #[test]
    fn isolated_native_surrogates_never_become_a_private_wire_encoding() {
        use std::os::windows::ffi::OsStringExt;
        assert!(wire_bytes(&OsString::from_wide(&[0xd800])).is_err());
    }
}
